//! The bridge: learns from announcements, repeats them between links, and answers unicast DNS
//! questions from what it has learned (asking the network first when it has to).

use crate::{
    cache::{Cache, acceptable},
    link::{Datagram, Family, Link},
    reflect::{Limiter, Recent},
    rewrite::Mapper,
};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::SOA},
};
use lumen_resolver::BridgeAnswer;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// The same question is not put on the network again within this time.
const ASK_SPACING: Duration = Duration::from_millis(300);
/// Packets repeated per second between links, and the burst allowed.
const REFLECT_RATE: u32 = 200;
const REFLECT_BURST: u32 = 400;
/// Questions put on the network per second on behalf of unicast clients.
const ASK_RATE: u32 = 50;
const ASK_BURST: u32 = 100;
/// TTL of a negative answer and of the synthetic SOA.
const NEGATIVE_TTL: u32 = 30;

#[derive(Clone, Debug)]
pub struct Settings {
    /// Unicast domain that mirrors `.local`. `None` turns the discovery proxy off.
    pub domain: Option<String>,
    pub reflect: bool,
    pub wait: Duration,
    pub ttl_cap: u32,
    pub max_records: usize,
}

pub struct Bridge {
    links: Vec<Arc<dyn Link>>,
    cache: Cache,
    mapper: Option<Mapper>,
    settings: Settings,
    news: Notify,
    asked: Mutex<HashMap<(String, RecordType), Instant>>,
    recent: Mutex<Recent>,
    reflect_limit: Mutex<Limiter>,
    ask_limit: Mutex<Limiter>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Bridge {
    /// # Errors
    /// The domain is not a valid DNS name.
    pub fn new(links: Vec<Arc<dyn Link>>, settings: Settings) -> Result<Arc<Self>, String> {
        let mapper = settings.domain.as_deref().map(Mapper::new).transpose()?;
        let now = Instant::now();
        Ok(Arc::new(Self {
            links,
            cache: Cache::new(settings.max_records),
            mapper,
            settings,
            news: Notify::new(),
            asked: Mutex::default(),
            recent: Mutex::default(),
            reflect_limit: Mutex::new(Limiter::new(REFLECT_RATE, REFLECT_BURST, now)),
            ask_limit: Mutex::new(Limiter::new(ASK_RATE, ASK_BURST, now)),
        }))
    }

    #[must_use]
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Take in one packet: learn from it and, when reflecting, repeat it on the other links.
    pub async fn handle(&self, datagram: Datagram, now: Instant) {
        let Some(link) = self.links.get(datagram.link) else {
            return;
        };
        let source = datagram.source.ip();
        // Anything not from the link is not trusted (RFC 6762 section 11). Packets from this
        // machine's own responder (avahi, for instance) are welcome: ours never loop back,
        // since multicast loopback is off on every socket.
        if !link.on_link(source) {
            return;
        }
        let Ok(message) = Message::from_vec(&datagram.bytes) else {
            return;
        };
        if message.metadata.op_code != OpCode::Query
            || message.metadata.response_code != ResponseCode::NoError
        {
            return;
        }
        if self.settings.reflect
            && datagram.source.port() == 5353
            && lock(&self.recent).first_time(&datagram.bytes, now)
            && lock(&self.reflect_limit).allow(now)
        {
            for (index, other) in self.links.iter().enumerate() {
                if index != datagram.link && other.family() == link.family() {
                    let _ = other.send(&datagram.bytes).await;
                }
            }
        }
        if self.mapper.is_some() && message.metadata.message_type == MessageType::Response {
            let mut news = false;
            for record in message.answers.iter().chain(message.additionals.iter()) {
                if acceptable(&record.name) {
                    news |= self.cache.insert(record, now);
                }
            }
            if news {
                self.news.notify_waiters();
            }
        }
    }

    fn question(name: &Name, rtype: RecordType) -> Option<Vec<u8>> {
        let mut message = Message::query();
        message.metadata.id = 0;
        message.metadata.recursion_desired = false;
        message.add_query(Query::query(name.clone(), rtype));
        message.to_vec().ok()
    }

    async fn send_question(&self, local: &Name, rtype: RecordType) {
        let key = (local.to_lowercase().to_ascii(), rtype);
        let now = Instant::now();
        {
            let mut asked = lock(&self.asked);
            asked.retain(|_, at| now.saturating_duration_since(*at) < ASK_SPACING * 4);
            if asked
                .get(&key)
                .is_some_and(|at| now.saturating_duration_since(*at) < ASK_SPACING)
            {
                return;
            }
            if !lock(&self.ask_limit).allow(now) {
                return;
            }
            asked.insert(key, now);
        }
        let Some(bytes) = Self::question(local, rtype) else {
            return;
        };
        // Multicast loops back to this machine, so our own question comes back as a packet. Mark
        // it as seen so the reflector does not repeat it.
        lock(&self.recent).first_time(&bytes, now);
        for link in &self.links {
            let _ = link.send(&bytes).await;
        }
    }

    /// Ask the network for `local` and wait, up to the configured time, for answers. A question
    /// with a single answer returns as soon as one arrives; a browse (`PTR`) waits for the others.
    async fn ask(&self, local: &Name, rtype: RecordType) {
        let deadline = tokio::time::Instant::now() + self.settings.wait;
        let browse = matches!(rtype, RecordType::PTR | RecordType::ANY);
        self.send_question(local, rtype).await;
        let mut resent = false;
        loop {
            let notified = self.news.notified();
            tokio::pin!(notified);
            // Register interest before looking, so an answer in between is not missed.
            notified.as_mut().enable();
            if !browse && !self.lookup(local, rtype).is_empty() {
                return;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return;
            }
            let halfway = deadline - self.settings.wait / 2;
            let until = if resent {
                deadline
            } else {
                halfway.min(deadline)
            };
            if tokio::time::timeout_at(until, notified).await.is_err() && !resent {
                // One more try halfway through, in case the first was lost.
                resent = true;
                self.send_question(local, rtype).await;
            }
        }
    }

    fn lookup(&self, local: &Name, rtype: RecordType) -> Vec<Record> {
        let now = Instant::now();
        if rtype == RecordType::ANY {
            self.cache.all_for(local, now)
        } else {
            self.cache.get(local, rtype, now)
        }
    }

    fn soa(mapper: &Mapper) -> Record {
        let domain = mapper.domain().clone();
        Record::from_rdata(
            domain.clone(),
            NEGATIVE_TTL,
            RData::SOA(SOA::new(
                domain,
                Name::from_ascii("nobody.invalid.").unwrap_or_default(),
                1,
                3600,
                1200,
                86_400,
                NEGATIVE_TTL,
            )),
        )
    }

    async fn resolve(&self, name: &Name, rtype: RecordType) -> Option<BridgeAnswer> {
        let mapper = self.mapper.as_ref()?;
        if !mapper.handles(name) {
            return None;
        }
        let soa = Self::soa(mapper);
        if mapper.is_apex(name) {
            // The domain itself: a SOA, and nothing else.
            return Some(if matches!(rtype, RecordType::SOA | RecordType::ANY) {
                BridgeAnswer {
                    answers: vec![soa],
                    ..BridgeAnswer::default()
                }
            } else {
                BridgeAnswer {
                    authorities: vec![soa],
                    ..BridgeAnswer::default()
                }
            });
        }
        let local = mapper.to_local(name)?;
        let mut found = self.lookup(&local, rtype);
        if found.is_empty() {
            self.ask(&local, rtype).await;
            found = self.lookup(&local, rtype);
        }
        let cap = self.settings.ttl_cap;
        if found.is_empty() {
            // The name may exist with other record types: then there is just no such record.
            let exists = !self.cache.all_for(&local, Instant::now()).is_empty();
            return Some(BridgeAnswer {
                rcode: if exists {
                    ResponseCode::NoError
                } else {
                    ResponseCode::NXDomain
                },
                authorities: vec![soa],
                ..BridgeAnswer::default()
            });
        }
        let related = self.cache.related(&found, Instant::now());
        Some(BridgeAnswer {
            rcode: ResponseCode::NoError,
            answers: found
                .iter()
                .map(|record| mapper.record_to_domain(record, cap))
                .collect(),
            additionals: related
                .iter()
                .map(|record| mapper.record_to_domain(record, cap))
                .collect(),
            ..BridgeAnswer::default()
        })
    }

    /// How many links speak each family, for logs.
    #[must_use]
    pub fn links(&self) -> (usize, usize) {
        let v4 = self
            .links
            .iter()
            .filter(|l| l.family() == Family::V4)
            .count();
        (v4, self.links.len() - v4)
    }
}

#[async_trait]
impl lumen_resolver::Bridge for Bridge {
    async fn answer(&self, name: &Name, rtype: RecordType) -> Option<BridgeAnswer> {
        self.resolve(name, rtype).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, PTR, SRV, TXT};
    use std::{
        io,
        net::{IpAddr, SocketAddr},
    };

    struct MemoryLink {
        name: String,
        family: Family,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl MemoryLink {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.into(),
                family: Family::V4,
                sent: Mutex::default(),
            })
        }
        fn sent(&self) -> Vec<Vec<u8>> {
            lock(&self.sent).clone()
        }
    }

    #[async_trait]
    impl Link for MemoryLink {
        fn name(&self) -> &str {
            &self.name
        }
        fn family(&self) -> Family {
            self.family
        }
        async fn send(&self, packet: &[u8]) -> io::Result<()> {
            lock(&self.sent).push(packet.to_vec());
            Ok(())
        }
        fn on_link(&self, source: IpAddr) -> bool {
            source.to_string().starts_with("192.168.")
        }
    }

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn response(records: Vec<Record>) -> Vec<u8> {
        let mut message = Message::response(0, OpCode::Query);
        message.metadata.authoritative = true;
        for record in records {
            message.add_answer(record);
        }
        message.to_vec().unwrap()
    }

    fn query_bytes(host: &str) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 0;
        message.add_query(Query::query(name(host), RecordType::A));
        message.to_vec().unwrap()
    }

    fn datagram(link: usize, from: &str, port: u16, bytes: Vec<u8>) -> Datagram {
        Datagram {
            link,
            source: SocketAddr::new(from.parse().unwrap(), port),
            bytes,
        }
    }

    fn settings(domain: Option<&str>, reflect: bool) -> Settings {
        Settings {
            domain: domain.map(str::to_owned),
            reflect,
            wait: Duration::from_millis(400),
            ttl_cap: 120,
            max_records: 1000,
        }
    }

    fn a(host: &str, last: u8) -> Record {
        let mut record = Record::from_rdata(name(host), 120, RData::A(A::new(192, 168, 1, last)));
        record.mdns_cache_flush = true;
        record
    }

    #[tokio::test]
    async fn announcements_are_learned_and_answered_under_the_domain() {
        let link = MemoryLink::new("eth0");
        let bridge =
            Bridge::new(vec![link.clone()], settings(Some("mdns.example"), false)).unwrap();
        bridge
            .handle(
                datagram(
                    0,
                    "192.168.1.50",
                    5353,
                    response(vec![a("printer.local.", 50)]),
                ),
                Instant::now(),
            )
            .await;
        let answer = bridge
            .resolve(&name("Printer.mdns.example."), RecordType::A)
            .await
            .unwrap();
        assert_eq!(answer.rcode, ResponseCode::NoError);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].name, name("printer.mdns.example."));
        assert_eq!(answer.answers[0].data, RData::A(A::new(192, 168, 1, 50)));
        assert!(answer.answers[0].ttl <= 120);
        // Nothing was put on the network: it was already known.
        assert!(link.sent().is_empty());
        // A name outside the domain is not the bridge's to answer.
        assert!(
            bridge
                .resolve(&name("printer.other.example."), RecordType::A)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_unknown_name_asks_the_network_and_picks_up_the_late_answer() {
        let link = MemoryLink::new("eth0");
        let bridge =
            Bridge::new(vec![link.clone()], settings(Some("mdns.example"), false)).unwrap();
        let waiting = {
            let bridge = Arc::clone(&bridge);
            tokio::spawn(async move {
                bridge
                    .resolve(&name("tv.mdns.example."), RecordType::A)
                    .await
            })
        };
        tokio::time::sleep(Duration::from_millis(80)).await;
        // A question for tv.local went out on the link.
        let sent = link.sent();
        let question = Message::from_vec(&sent[0]).unwrap();
        assert_eq!(question.queries[0].name(), &name("tv.local."));
        assert!(!question.metadata.recursion_desired);
        // The device answers; the waiting query returns at once with it.
        bridge
            .handle(
                datagram(0, "192.168.1.60", 5353, response(vec![a("tv.local.", 60)])),
                Instant::now(),
            )
            .await;
        let answer = tokio::time::timeout(Duration::from_millis(200), waiting)
            .await
            .expect("answered before the full wait")
            .unwrap()
            .unwrap();
        assert_eq!(answer.answers[0].data, RData::A(A::new(192, 168, 1, 60)));
    }

    #[tokio::test]
    async fn silence_is_nxdomain_and_a_name_with_other_types_is_nodata() {
        let link = MemoryLink::new("eth0");
        let bridge = Bridge::new(vec![link], settings(Some("mdns.example"), false)).unwrap();
        let none = bridge
            .resolve(&name("ghost.mdns.example."), RecordType::A)
            .await
            .unwrap();
        assert_eq!(none.rcode, ResponseCode::NXDomain);
        assert_eq!(none.authorities.len(), 1, "a SOA for caching");
        bridge
            .handle(
                datagram(
                    0,
                    "192.168.1.50",
                    5353,
                    response(vec![a("printer.local.", 50)]),
                ),
                Instant::now(),
            )
            .await;
        let nodata = bridge
            .resolve(&name("printer.mdns.example."), RecordType::AAAA)
            .await
            .unwrap();
        assert_eq!(nodata.rcode, ResponseCode::NoError);
        assert!(nodata.answers.is_empty() && nodata.authorities.len() == 1);
        // The apex answers a SOA and nothing leaks to the network.
        let apex = bridge
            .resolve(&name("mdns.example."), RecordType::SOA)
            .await
            .unwrap();
        assert_eq!(apex.answers.len(), 1);
    }

    #[tokio::test]
    async fn browsing_returns_every_instance_with_its_service_and_address() {
        let link = MemoryLink::new("eth0");
        let bridge = Bridge::new(vec![link], settings(Some("mdns.example"), false)).unwrap();
        let ptr = |instance: &str| {
            Record::from_rdata(
                name("_http._tcp.local."),
                4500,
                RData::PTR(PTR(name(&format!("{instance}._http._tcp.local.")))),
            )
        };
        let srv = Record::from_rdata(
            name("web._http._tcp.local."),
            120,
            RData::SRV(SRV::new(0, 0, 8080, name("box.local."))),
        );
        let txt = Record::from_rdata(
            name("web._http._tcp.local."),
            4500,
            RData::TXT(TXT::new(vec!["path=/".into()])),
        );
        bridge
            .handle(
                datagram(
                    0,
                    "192.168.1.70",
                    5353,
                    response(vec![ptr("web"), ptr("wiki"), srv, txt, a("box.local.", 70)]),
                ),
                Instant::now(),
            )
            .await;
        let answer = bridge
            .resolve(&name("_http._tcp.mdns.example."), RecordType::PTR)
            .await
            .unwrap();
        assert_eq!(answer.answers.len(), 2);
        let RData::PTR(target) = &answer.answers[0].data else {
            panic!("not a PTR")
        };
        assert!(target.0.to_ascii().ends_with("._http._tcp.mdns.example."));
        let kinds: Vec<RecordType> = answer.additionals.iter().map(Record::record_type).collect();
        assert!(
            kinds.contains(&RecordType::SRV)
                && kinds.contains(&RecordType::TXT)
                && kinds.contains(&RecordType::A),
            "{kinds:?}"
        );
        assert!(
            answer
                .answers
                .iter()
                .chain(&answer.additionals)
                .all(|r| r.ttl <= 120)
        );
    }

    #[tokio::test]
    async fn untrusted_packets_are_ignored() {
        let link = MemoryLink::new("eth0");
        let bridge = Bridge::new(vec![link], settings(Some("mdns.example"), false)).unwrap();
        let now = Instant::now();
        // From off the link, malformed, and a non-local name.
        bridge
            .handle(
                datagram(0, "8.8.8.8", 5353, response(vec![a("evil.local.", 1)])),
                now,
            )
            .await;
        bridge
            .handle(datagram(0, "192.168.1.9", 5353, vec![1, 2, 3]), now)
            .await;
        let mut outside = a("example.com.", 3);
        outside.name = name("example.com.");
        bridge
            .handle(
                datagram(0, "192.168.1.9", 5353, response(vec![outside])),
                now,
            )
            .await;
        assert!(bridge.cache().is_empty());
    }

    #[tokio::test]
    async fn the_reflector_repeats_between_links_once_and_never_to_the_source() {
        let (one, two, three) = (
            MemoryLink::new("eth0"),
            MemoryLink::new("eth1"),
            MemoryLink::new("eth2"),
        );
        let bridge = Bridge::new(
            vec![one.clone(), two.clone(), three.clone()],
            settings(None, true),
        )
        .unwrap();
        let packet = query_bytes("printer.local.");
        let now = Instant::now();
        bridge
            .handle(datagram(0, "192.168.1.50", 5353, packet.clone()), now)
            .await;
        assert!(one.sent().is_empty(), "never back to where it came from");
        assert_eq!(two.sent(), vec![packet.clone()]);
        assert_eq!(three.sent(), vec![packet.clone()]);
        // The same packet again (a loop through another reflector) is not repeated.
        bridge
            .handle(datagram(1, "192.168.1.51", 5353, packet.clone()), now)
            .await;
        assert_eq!(one.sent().len(), 0);
        assert_eq!(three.sent().len(), 1);
        // A packet from another port is a legacy unicast question, not multicast: not repeated.
        bridge
            .handle(
                datagram(0, "192.168.1.50", 40000, query_bytes("other.local.")),
                now,
            )
            .await;
        assert_eq!(two.sent().len(), 1);
        // Without reflection, nothing is repeated.
        let quiet = Bridge::new(
            vec![MemoryLink::new("a"), two.clone()],
            settings(Some("x.example"), false),
        )
        .unwrap();
        quiet
            .handle(
                datagram(0, "192.168.1.50", 5353, query_bytes("z.local.")),
                now,
            )
            .await;
        assert_eq!(two.sent().len(), 1);
    }

    #[tokio::test]
    async fn our_own_question_coming_back_is_not_repeated_by_the_reflector() {
        let (one, two) = (MemoryLink::new("eth0"), MemoryLink::new("eth1"));
        let mut config = settings(Some("mdns.example"), true);
        config.wait = Duration::from_millis(100);
        let bridge = Bridge::new(vec![one.clone(), two.clone()], config).unwrap();
        bridge
            .resolve(&name("tv.mdns.example."), RecordType::A)
            .await;
        let question = one.sent()[0].clone();
        assert_eq!(
            two.sent()[0],
            question,
            "the question went out on both links"
        );
        let before = (one.sent().len(), two.sent().len());
        // The network hands our own question back on the first link.
        bridge
            .handle(datagram(0, "192.168.1.5", 5353, question), Instant::now())
            .await;
        assert_eq!((one.sent().len(), two.sent().len()), before);
    }

    #[tokio::test]
    async fn the_same_question_is_not_asked_over_and_over() {
        let link = MemoryLink::new("eth0");
        let mut config = settings(Some("mdns.example"), false);
        config.wait = Duration::from_millis(150);
        let bridge = Bridge::new(vec![link.clone()], config).unwrap();
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let bridge = Arc::clone(&bridge);
            set.spawn(async move {
                bridge
                    .resolve(&name("quiet.mdns.example."), RecordType::A)
                    .await
            });
        }
        while set.join_next().await.is_some() {}
        assert!(
            link.sent().len() <= 3,
            "20 clients, {} packets",
            link.sent().len()
        );
    }
}

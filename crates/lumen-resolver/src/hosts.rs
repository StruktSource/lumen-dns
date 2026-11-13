//! Names that DHCP hands out. The DHCP server publishes `host.<domain>` with the address it
//! leased, and this store answers `A`, `AAAA` and reverse `PTR` questions for them straight from
//! memory, authoritatively and with short TTLs, so a new device is resolvable at once and an
//! expired lease disappears at once. Names under the domain that nobody holds get an
//! authoritative `NXDOMAIN` instead of leaking to public DNS.

use crate::response_base;
use hickory_server::proto::{
    op::{Message, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, PTR, SOA},
    },
};
use lumen_proto::Query;
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    net::IpAddr,
    sync::RwLock,
};

/// TTL of every answer from here. Short, because leases come and go.
const TTL: u32 = 30;
/// Most published addresses, so a flood of leases cannot grow memory without bound.
pub const MAX_HOSTS: usize = 65_536;

#[derive(Default)]
struct Inner {
    /// Lowercase fully qualified name with a trailing dot, to its addresses.
    forward: HashMap<String, Vec<IpAddr>>,
    /// Reverse owner name to the host name that holds the address.
    reverse: HashMap<String, String>,
}

/// The published DHCP names under one domain.
pub struct Hosts {
    domain: Option<Name>,
    inner: RwLock<Inner>,
}

impl Hosts {
    /// A store for names under `domain` (no trailing dot). `None` publishes nothing.
    #[must_use]
    pub fn new(domain: Option<&str>) -> Self {
        Self {
            domain: domain.and_then(|domain| Name::from_ascii(format!("{domain}.")).ok()),
            inner: RwLock::default(),
        }
    }

    /// The domain, with a trailing dot.
    #[must_use]
    pub fn domain(&self) -> Option<String> {
        self.domain.as_ref().map(Name::to_ascii)
    }

    /// Publish `host` (one label, or labels) under the domain for `address`. Returns the full
    /// name, or `None` when the name is unusable or the store is full.
    pub fn publish(&self, host: &str, address: IpAddr) -> Option<String> {
        let domain = self.domain.as_ref()?;
        let fqdn = Name::from_ascii(format!("{host}."))
            .and_then(|name| name.append_domain(domain))
            .ok()?
            .to_ascii()
            .to_ascii_lowercase();
        let mut inner = self.inner.write().ok()?;
        if inner.reverse.len() >= MAX_HOSTS && !inner.reverse.contains_key(&reverse_name(address)) {
            return None;
        }
        let addresses = inner.forward.entry(fqdn.clone()).or_default();
        if !addresses.contains(&address) {
            addresses.push(address);
        }
        inner.reverse.insert(reverse_name(address), fqdn.clone());
        Some(fqdn)
    }

    /// Stop publishing `address`, and its name when nothing else uses it.
    pub fn withdraw(&self, address: IpAddr) {
        let Ok(mut inner) = self.inner.write() else {
            return;
        };
        if let Some(fqdn) = inner.reverse.remove(&reverse_name(address))
            && let Some(addresses) = inner.forward.get_mut(&fqdn)
        {
            addresses.retain(|existing| *existing != address);
            if addresses.is_empty() {
                inner.forward.remove(&fqdn);
            }
        }
    }

    /// Forget everything. Used before a full rebuild from stored leases.
    pub fn clear(&self) {
        if let Ok(mut inner) = self.inner.write() {
            *inner = Inner::default();
        }
    }

    /// Number of published addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().map_or(0, |inner| inner.reverse.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn soa(domain: &Name) -> Record {
        Record::from_rdata(
            domain.clone(),
            TTL,
            RData::SOA(SOA::new(
                domain.clone(),
                Name::from_ascii("nobody.invalid.").expect("static SOA name"),
                1,
                3600,
                600,
                86_400,
                TTL,
            )),
        )
    }

    /// An authoritative answer when the question is about a name this store owns: a published
    /// host, a reverse name of a published address, or any other name under the domain.
    pub(crate) fn answer(&self, query: &Query) -> Option<Message> {
        let domain = self.domain.as_ref()?;
        let question = query.message.queries.first()?;
        let name = question.name().to_ascii().to_ascii_lowercase();
        let inner = self.inner.read().ok()?;
        let kind = question.query_type();

        if kind == RecordType::PTR {
            let host = inner.reverse.get(&name)?;
            let mut response = response_base(query, true);
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                TTL,
                RData::PTR(PTR(Name::from_ascii(host).ok()?)),
            ));
            return Some(response);
        }
        if !domain.zone_of(question.name()) {
            return None;
        }
        let mut response = response_base(query, true);
        match inner.forward.get(&name) {
            Some(addresses) => {
                let mut any = false;
                for address in addresses {
                    let data = match (kind, address) {
                        (RecordType::A | RecordType::ANY, IpAddr::V4(v4)) => RData::A(A(*v4)),
                        (RecordType::AAAA | RecordType::ANY, IpAddr::V6(v6)) => {
                            RData::AAAA(AAAA(*v6))
                        }
                        _ => continue,
                    };
                    any = true;
                    response.add_answer(Record::from_rdata(question.name().clone(), TTL, data));
                }
                if !any {
                    response.add_authority(Self::soa(domain));
                }
            }
            None if name == domain.to_ascii().to_ascii_lowercase() => {
                // The apex itself: nothing to publish, but it exists.
                response.add_authority(Self::soa(domain));
            }
            None => {
                // Another name below the domain may exist as a parent of a published host.
                let has_child = inner
                    .forward
                    .keys()
                    .any(|host| host.ends_with(&format!(".{name}")));
                if !has_child {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
                response.add_authority(Self::soa(domain));
            }
        }
        Some(response)
    }
}

/// `4.3.2.1.in-addr.arpa.` or the nibble form under `ip6.arpa.`, lowercase.
fn reverse_name(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut out = String::new();
            for byte in v6.octets().iter().rev() {
                let _ = write!(out, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
            }
            out.push_str("ip6.arpa.");
            out
        }
    }
}

/// Names (without the trailing dot) already published, for tests and diagnostics.
impl Hosts {
    #[must_use]
    pub fn names(&self) -> HashSet<String> {
        self.inner
            .read()
            .map(|inner| inner.forward.keys().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::op::Query as DnsQuery;
    use std::str::FromStr;

    fn ask(name: &str, kind: RecordType) -> Query {
        let mut message = Message::query();
        message.add_query(DnsQuery::query(Name::from_str(name).unwrap(), kind));
        Query::parse(&message.to_vec().unwrap()).unwrap()
    }

    #[test]
    fn published_hosts_answer_forward_and_reverse() {
        let hosts = Hosts::new(Some("home.example"));
        let v4: IpAddr = "192.168.1.20".parse().unwrap();
        let v6: IpAddr = "fd00::20".parse().unwrap();
        assert_eq!(hosts.publish("Laptop", v4).unwrap(), "laptop.home.example.");
        hosts.publish("laptop", v6).unwrap();
        let a = hosts
            .answer(&ask("LAPTOP.home.example.", RecordType::A))
            .unwrap();
        assert!(a.metadata.authoritative);
        assert!(matches!(&a.answers[0].data, RData::A(A(ip)) if ip.to_string() == "192.168.1.20"));
        let aaaa = hosts
            .answer(&ask("laptop.home.example.", RecordType::AAAA))
            .unwrap();
        assert!(matches!(&aaaa.answers[0].data, RData::AAAA(_)));
        let ptr = hosts
            .answer(&ask("20.1.168.192.in-addr.arpa.", RecordType::PTR))
            .unwrap();
        assert!(
            matches!(&ptr.answers[0].data, RData::PTR(PTR(name)) if name.to_ascii() == "laptop.home.example.")
        );
        let ptr6 = hosts
            .answer(&ask(&reverse_name(v6), RecordType::PTR))
            .unwrap();
        assert_eq!(ptr6.answers.len(), 1);
    }

    #[test]
    fn unknown_names_under_the_domain_are_nxdomain_and_others_pass_through() {
        let hosts = Hosts::new(Some("home.example"));
        hosts
            .publish("nas", "192.168.1.5".parse().unwrap())
            .unwrap();
        let missing = hosts
            .answer(&ask("ghost.home.example.", RecordType::A))
            .unwrap();
        assert_eq!(missing.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(missing.authorities.len(), 1);
        // A published name with no record of the asked type is NODATA, not NXDOMAIN.
        let nodata = hosts
            .answer(&ask("nas.home.example.", RecordType::AAAA))
            .unwrap();
        assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
        assert!(nodata.answers.is_empty());
        assert!(hosts.answer(&ask("example.com.", RecordType::A)).is_none());
        assert!(
            hosts
                .answer(&ask("9.9.9.9.in-addr.arpa.", RecordType::PTR))
                .is_none()
        );
    }

    #[test]
    fn withdrawing_removes_the_address_and_an_unused_name() {
        let hosts = Hosts::new(Some("home.example"));
        let a: IpAddr = "192.168.1.7".parse().unwrap();
        let b: IpAddr = "fd00::7".parse().unwrap();
        hosts.publish("tv", a).unwrap();
        hosts.publish("tv", b).unwrap();
        hosts.withdraw(a);
        let reply = hosts
            .answer(&ask("tv.home.example.", RecordType::A))
            .unwrap();
        assert!(
            reply.answers.is_empty(),
            "the v4 address is gone, the v6 one stays"
        );
        assert!(
            hosts
                .answer(&ask("tv.home.example.", RecordType::AAAA))
                .unwrap()
                .answers
                .len()
                == 1
        );
        hosts.withdraw(b);
        assert!(hosts.is_empty());
        let reply = hosts
            .answer(&ask("tv.home.example.", RecordType::AAAA))
            .unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn no_domain_means_no_answers() {
        let hosts = Hosts::new(None);
        assert!(hosts.publish("x", "10.0.0.1".parse().unwrap()).is_none());
        assert!(
            hosts
                .answer(&ask("x.home.example.", RecordType::A))
                .is_none()
        );
    }
}

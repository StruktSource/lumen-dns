//! The safety rules around repeating multicast: do not repeat the same packet twice, do not
//! repeat faster than a limit, and only trust packets whose source could be on the link.

use hickory_proto::{
    op::Message,
    rr::{Name, RData},
};
use std::{
    collections::VecDeque,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

/// A packet seen again within this window is a loop or a duplicate, and is not repeated.
const WINDOW: Duration = Duration::from_secs(3);
const MEMORY: usize = 4096;

/// FNV-1a: cheap, and only used to spot repeats.
fn fingerprint(packet: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in packet {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

#[derive(Default)]
pub struct Recent {
    seen: VecDeque<(u64, Instant)>,
}

impl Recent {
    /// True the first time a packet is seen within the window.
    pub fn first_time(&mut self, packet: &[u8], now: Instant) -> bool {
        while self
            .seen
            .front()
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) > WINDOW)
        {
            self.seen.pop_front();
        }
        let print = fingerprint(packet);
        if self.seen.iter().any(|(seen, _)| *seen == print) {
            return false;
        }
        if self.seen.len() >= MEMORY {
            self.seen.pop_front();
        }
        self.seen.push_back((print, now));
        true
    }
}

/// A token bucket: `rate` packets a second with a burst, so a flood cannot be amplified.
pub struct Limiter {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl Limiter {
    #[must_use]
    pub fn new(rate: u32, burst: u32, now: Instant) -> Self {
        Self {
            tokens: f64::from(burst),
            rate: f64::from(rate),
            burst: f64::from(burst),
            last: now,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Which services may be repeated between networks.
///
/// A service type is written like `_airplay._tcp`. Packets that mention no service at all (plain
/// host lookups such as `tv.local` A) always pass, because a client that found a service on
/// another network must still be able to resolve its host. A packet that mentions a service is
/// repeated only if the service is not blocked and, when an allow list exists, is on it.
#[derive(Clone, Debug, Default)]
pub struct ServiceFilter {
    allow: Vec<String>,
    block: Vec<String>,
}

fn service_suffix(service: &str) -> String {
    format!("{}.local.", service.trim_matches('.').to_ascii_lowercase())
}

fn is_service_name(name: &Name) -> bool {
    name.iter().any(|label| label.first() == Some(&b'_'))
}

fn under(name: &Name, suffix: &str) -> bool {
    let text = name.to_ascii().to_ascii_lowercase();
    text == suffix || text.ends_with(&format!(".{suffix}"))
}

impl ServiceFilter {
    #[must_use]
    pub fn new(allow: &[String], block: &[String]) -> Self {
        Self {
            allow: allow.iter().map(|s| service_suffix(s)).collect(),
            block: block.iter().map(|s| service_suffix(s)).collect(),
        }
    }

    /// True for a filter that repeats everything.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.allow.is_empty() && self.block.is_empty()
    }

    #[must_use]
    pub fn permits(&self, message: &Message) -> bool {
        if self.is_open() {
            return true;
        }
        let mut names: Vec<&Name> = message
            .queries
            .iter()
            .map(hickory_proto::op::Query::name)
            .collect();
        for record in message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
        {
            names.push(&record.name);
            if let RData::PTR(target) = &record.data {
                names.push(&target.0);
            }
        }
        for name in names.into_iter().filter(|name| is_service_name(name)) {
            if self.block.iter().any(|suffix| under(name, suffix)) {
                return false;
            }
            if !self.allow.is_empty() && !self.allow.iter().any(|suffix| under(name, suffix)) {
                return false;
            }
        }
        true
    }
}

/// RFC 6762 section 11: a packet whose source is not on the link is ignored.
#[must_use]
pub fn on_link_v4(source: Ipv4Addr, local: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let (source, local, mask) = (u32::from(source), u32::from(local), u32::from(mask));
    source & mask == local & mask
}

#[must_use]
pub fn on_link_v6(source: Ipv6Addr) -> bool {
    source.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_is_repeated_once_per_window_and_the_memory_is_bounded() {
        let mut recent = Recent::default();
        let t0 = Instant::now();
        assert!(recent.first_time(b"query", t0));
        assert!(!recent.first_time(b"query", t0 + Duration::from_secs(1)));
        assert!(recent.first_time(b"other", t0 + Duration::from_secs(1)));
        assert!(
            recent.first_time(b"query", t0 + Duration::from_secs(4)),
            "the window passed"
        );
        for i in 0..10_000u32 {
            recent.first_time(&i.to_be_bytes(), t0 + Duration::from_secs(5));
        }
        assert!(recent.seen.len() <= MEMORY);
    }

    #[test]
    fn the_limiter_allows_a_burst_then_the_rate() {
        let t0 = Instant::now();
        let mut limiter = Limiter::new(10, 5, t0);
        assert_eq!((0..8).filter(|_| limiter.allow(t0)).count(), 5);
        assert!(!limiter.allow(t0 + Duration::from_millis(50)));
        assert!(limiter.allow(t0 + Duration::from_millis(250)));
    }

    #[test]
    fn only_on_link_sources_are_trusted() {
        let (local, mask) = (
            "192.168.1.2".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        );
        assert!(on_link_v4("192.168.1.77".parse().unwrap(), local, mask));
        assert!(!on_link_v4("192.168.2.77".parse().unwrap(), local, mask));
        assert!(!on_link_v4("8.8.8.8".parse().unwrap(), local, mask));
        assert!(on_link_v6("fe80::1".parse().unwrap()));
        assert!(!on_link_v6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn service_filters_allow_block_and_let_plain_host_lookups_through() {
        use hickory_proto::{op::Query, rr::RecordType};
        let ask = |name: &str| {
            let mut message = Message::query();
            message.add_query(Query::query(
                Name::from_ascii(name).unwrap(),
                RecordType::PTR,
            ));
            message
        };
        let open = ServiceFilter::default();
        assert!(open.permits(&ask("_ssh._tcp.local.")));
        let only = ServiceFilter::new(&["_airplay._tcp".into()], &[]);
        assert!(only.permits(&ask("_airplay._tcp.local.")));
        assert!(only.permits(&ask("Living-Room._airplay._tcp.local.")));
        assert!(!only.permits(&ask("_ssh._tcp.local.")));
        assert!(!only.permits(&ask("_services._dns-sd._udp.local.")));
        assert!(only.permits(&ask("tv.local.")), "host lookups pass");
        let blocked = ServiceFilter::new(&[], &["_ssh._tcp".into()]);
        assert!(!blocked.permits(&ask("_ssh._tcp.local.")));
        assert!(blocked.permits(&ask("_ipp._tcp.local.")));
        assert!(
            !ServiceFilter::new(&["_ssh._tcp".into()], &["_ssh._tcp".into()])
                .permits(&ask("_ssh._tcp.local."))
        );
    }
}

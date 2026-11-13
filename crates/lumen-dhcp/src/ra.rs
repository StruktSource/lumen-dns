//! IPv6 Router Advertisements (RFC 4861) with DNS options (RFC 8106) and routes (RFC 4191).
//!
//! Lumen **advertises**; it does not route. With the default router lifetime of zero, hosts learn
//! the prefixes and DNS servers but are told this machine is not a default router.
//!
//! [`Advertisement`] builds the packet and is pure, so every byte can be tested. [`start`] owns
//! the raw `ICMPv6` socket (it needs the same privilege as port 67), sends the unsolicited
//! advertisements on a randomized timer, and answers Router Solicitations.

use lumen_config::{
    AdvertisedPrefix, AdvertisedRoute, Dhcp, RouterAdvertisement, RouterPreference,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{Instant, sleep_until},
};

/// `ICMPv6` types (RFC 4861).
const ROUTER_SOLICITATION: u8 = 133;
const ROUTER_ADVERTISEMENT: u8 = 134;

/// Neighbor Discovery option types.
const OPT_SOURCE_LLADDR: u8 = 1;
const OPT_PREFIX_INFORMATION: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_ROUTE_INFORMATION: u8 = 24;
const OPT_RDNSS: u8 = 25;
const OPT_DNSSL: u8 = 31;

/// Everything one interface advertises, with the defaults filled in.
#[derive(Clone, Debug)]
pub struct Advertisement {
    pub interface: String,
    pub managed: bool,
    pub other_config: bool,
    pub router_lifetime: u16,
    pub preference: RouterPreference,
    pub interval_secs: u32,
    pub mtu: Option<u32>,
    pub prefixes: Vec<AdvertisedPrefix>,
    pub routes: Vec<AdvertisedRoute>,
    pub dns: Vec<Ipv6Addr>,
    pub search: Vec<String>,
    /// The interface's hardware address, so hosts need not ask for it (RFC 4861 section 4.6.1).
    pub mac: Option<[u8; 6]>,
}

impl Advertisement {
    /// Fill in what the configuration leaves out: DNS servers come from the `DHCPv6` scope on the
    /// same interface, and the search domain from `dhcp.domain`.
    #[must_use]
    pub fn resolve(ra: &RouterAdvertisement, dhcp: &Dhcp, mac: Option<[u8; 6]>) -> Self {
        let dns = ra.dns.clone().unwrap_or_else(|| {
            dhcp.scopes6
                .iter()
                .find(|scope| scope.interface.as_deref() == Some(ra.interface.as_str()))
                .map(|scope| scope.dns.clone())
                .unwrap_or_default()
        });
        let search = ra.search.clone().unwrap_or_else(|| {
            dhcp.domain
                .iter()
                .filter(|domain| !domain.is_empty())
                .cloned()
                .collect()
        });
        Self {
            interface: ra.interface.clone(),
            managed: ra.managed,
            other_config: ra.other_config,
            router_lifetime: u16::try_from(ra.router_lifetime_secs).unwrap_or(u16::MAX),
            preference: ra.preference,
            interval_secs: ra.interval_secs,
            mtu: ra.mtu,
            prefixes: ra.prefixes.clone(),
            routes: ra.routes.clone(),
            dns,
            search,
            mac,
        }
    }

    /// The `ICMPv6` message, without the IPv6 header. The kernel fills in the checksum for a raw
    /// `ICMPv6` socket. With `goodbye` the router lifetime is zero, which tells hosts this machine
    /// is no longer a default router (RFC 4861 section 6.2.5).
    #[must_use]
    pub fn packet(&self, goodbye: bool) -> Vec<u8> {
        let lifetime = if goodbye { 0 } else { self.router_lifetime };
        let mut out = vec![ROUTER_ADVERTISEMENT, 0, 0, 0];
        // Current hop limit: unspecified.
        out.push(0);
        let mut flags = 0u8;
        if self.managed {
            flags |= 0x80;
        }
        if self.other_config {
            flags |= 0x40;
        }
        // A router that is not a default router must say "medium" (RFC 4191 section 2.2).
        if lifetime != 0 {
            flags |= preference_bits(self.preference);
        }
        out.push(flags);
        out.extend_from_slice(&lifetime.to_be_bytes());
        // Reachable time and retransmit timer: unspecified.
        out.extend_from_slice(&[0; 8]);

        if let Some(mac) = self.mac {
            out.extend_from_slice(&[OPT_SOURCE_LLADDR, 1]);
            out.extend_from_slice(&mac);
        }
        if let Some(mtu) = self.mtu {
            out.extend_from_slice(&[OPT_MTU, 1, 0, 0]);
            out.extend_from_slice(&mtu.to_be_bytes());
        }
        for item in &self.prefixes {
            out.extend_from_slice(&[OPT_PREFIX_INFORMATION, 4, item.prefix.prefix_len()]);
            let mut flags = 0u8;
            if item.on_link {
                flags |= 0x80;
            }
            if item.autonomous {
                flags |= 0x40;
            }
            out.push(flags);
            out.extend_from_slice(&item.valid_secs.to_be_bytes());
            out.extend_from_slice(&item.preferred_secs.to_be_bytes());
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&item.prefix.network().octets());
        }
        for route in &self.routes {
            let length = route.prefix.prefix_len();
            // The prefix field is 0, 8 or 16 bytes, as the prefix needs (RFC 4191 section 2.3).
            let units: u8 = match length {
                0 => 1,
                1..=64 => 2,
                _ => 3,
            };
            out.extend_from_slice(&[OPT_ROUTE_INFORMATION, units, length]);
            out.push(preference_bits(route.preference));
            out.extend_from_slice(&route.lifetime_secs.to_be_bytes());
            let octets = route.prefix.network().octets();
            out.extend_from_slice(&octets[..usize::from(units - 1) * 8]);
        }
        // Hosts treat a DNS option as valid for this long (RFC 8106 recommends twice the
        // longest interval between advertisements).
        let dns_lifetime = self.interval_secs.saturating_mul(2);
        if !self.dns.is_empty() {
            let units = u8::try_from(1 + 2 * self.dns.len()).unwrap_or(u8::MAX);
            out.extend_from_slice(&[OPT_RDNSS, units, 0, 0]);
            out.extend_from_slice(&dns_lifetime.to_be_bytes());
            for server in &self.dns {
                out.extend_from_slice(&server.octets());
            }
        }
        if !self.search.is_empty() {
            let mut names = Vec::new();
            for name in &self.search {
                for label in name.trim_end_matches('.').split('.') {
                    // A label that does not fit would corrupt the option, so it is left out.
                    let bytes = label.as_bytes();
                    if let Ok(length) = u8::try_from(bytes.len())
                        && (1..=63).contains(&length)
                    {
                        names.push(length);
                        names.extend_from_slice(bytes);
                    }
                }
                names.push(0);
            }
            // The option is a whole number of 8-byte units, padded with zeros.
            while !(names.len() + 8).is_multiple_of(8) {
                names.push(0);
            }
            let units = u8::try_from((names.len() + 8) / 8).unwrap_or(u8::MAX);
            out.extend_from_slice(&[OPT_DNSSL, units, 0, 0]);
            out.extend_from_slice(&dns_lifetime.to_be_bytes());
            out.extend_from_slice(&names);
        }
        out
    }
}

/// The two preference bits of the flags byte (RFC 4191): high 01, medium 00, low 11.
fn preference_bits(preference: RouterPreference) -> u8 {
    match preference {
        RouterPreference::High => 0x08,
        RouterPreference::Medium => 0x00,
        RouterPreference::Low => 0x18,
    }
}

/// True for a Router Solicitation sent by a host on the link. Hosts that are not yet configured
/// send from `::`; the rest from a link-local address. A packet from anywhere else cannot be a
/// solicitation from this link, because routers never forward link-local traffic (the check
/// that RFC 4861 makes with the hop limit).
#[must_use]
pub fn is_solicitation(packet: &[u8], source: Ipv6Addr) -> bool {
    packet.len() >= 8
        && packet[0] == ROUTER_SOLICITATION
        && packet[1] == 0
        && (source.is_unspecified() || (source.segments()[0] & 0xffc0) == 0xfe80)
}

/// All nodes on the link: where unsolicited advertisements go.
const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// All routers on the link: the group solicitations are sent to.
#[cfg(unix)]
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// No two multicast advertisements closer than this (RFC 4861 `MIN_DELAY_BETWEEN_RAS`).
const MIN_GAP: Duration = Duration::from_secs(3);
/// A solicitation is answered after a random wait up to this (`MAX_RA_DELAY_TIME`).
const MAX_ANSWER_DELAY_MS: u64 = 500;
/// The first few advertisements come quickly so a new network settles fast
/// (`MAX_INITIAL_RTR_ADVERTISEMENTS`, `MAX_INITIAL_RTR_ADVERT_INTERVAL`).
const INITIAL_ADVERTISEMENTS: u32 = 3;
const INITIAL_INTERVAL_SECS: u64 = 16;

/// Counters the console shows.
#[derive(Debug, Default)]
pub struct Stats {
    /// Advertisements sent, unsolicited and in answer to a solicitation.
    pub sent: AtomicU64,
    /// Unix seconds of the last one, 0 before the first.
    pub last_sent: AtomicU64,
}

/// An advertisement that withdraws the router when the server stops (RFC 4861 section 6.2.5).
pub struct Goodbye {
    socket: Arc<UdpSocket>,
    packet: Vec<u8>,
    target: SocketAddr,
}

impl Goodbye {
    /// Best effort: one non-blocking send.
    pub fn send(&self) {
        let _ = self.socket.try_send_to(&self.packet, self.target);
    }
}

/// One interface being advertised on.
pub struct Started {
    pub task: JoinHandle<()>,
    pub advertisement: Arc<Advertisement>,
    pub stats: Arc<Stats>,
    /// Present only when this machine advertises itself as a default router.
    pub goodbye: Option<Goodbye>,
}

/// How long to wait before the next unsolicited advertisement. `random` is any 64-bit sample.
///
/// The first few come after 1 to 16 seconds; later ones between a third of the interval (at
/// least 3 seconds) and the whole interval (RFC 4861 section 6.2.4).
#[must_use]
pub fn unsolicited_delay(interval_secs: u32, sent: u32, random: u64) -> Duration {
    let interval = u64::from(interval_secs);
    let (low, high) = if sent < INITIAL_ADVERTISEMENTS {
        (1, INITIAL_INTERVAL_SECS.min(interval))
    } else {
        ((interval / 3).max(3), interval)
    };
    let span_ms = (high.saturating_sub(low)) * 1000 + 1;
    Duration::from_millis(low * 1000 + random % span_ms)
}

fn random_u64() -> u64 {
    use rand_core::{OsRng, RngCore};
    OsRng.next_u64()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The hardware address of an interface, when it has one.
#[cfg(unix)]
fn mac_of(name: &str) -> Option<[u8; 6]> {
    nix::ifaddrs::getifaddrs()
        .ok()?
        .filter(|entry| entry.interface_name == name)
        .find_map(|entry| {
            let mac = entry.address?.as_link_addr()?.addr()?;
            (mac != [0; 6]).then_some(mac)
        })
}

/// A raw `ICMPv6` socket for one interface. It needs the privilege that port 67 needs (root, or
/// `CAP_NET_RAW`).
///
/// The kernel's `ICMPv6` filter cannot be set without `unsafe`, so the socket also receives other
/// `ICMPv6` traffic on the interface; the loop drops everything but solicitations at once.
#[cfg(unix)]
fn raw_socket(name: &str, index: u32) -> io::Result<UdpSocket> {
    let denied = |error: io::Error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "router advertisements on {name} need a raw socket: run as root or grant CAP_NET_RAW"
                ),
            )
        } else {
            error
        }
    };
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).map_err(denied)?;
    // Neighbor Discovery messages are valid only with a hop limit of 255 (RFC 4861 section 6.1).
    socket.set_multicast_hops_v6(255)?;
    socket.set_unicast_hops_v6(255)?;
    socket.set_multicast_if_v6(index)?;
    socket.set_multicast_loop_v6(false)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket.bind_device(Some(name.as_bytes()))?;
    #[cfg(target_os = "macos")]
    socket.bind_device_by_index_v6(std::num::NonZeroU32::new(index))?;
    socket.join_multicast_v6(&ALL_ROUTERS, index)?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Start advertising on one interface.
///
/// # Errors
/// The interface does not exist, or the raw socket cannot be opened (it needs privileges).
#[cfg(unix)]
pub fn start(ra: &RouterAdvertisement, dhcp: &Dhcp, index: u32) -> io::Result<Started> {
    let advertisement = Arc::new(Advertisement::resolve(ra, dhcp, mac_of(&ra.interface)));
    let socket = Arc::new(raw_socket(&ra.interface, index)?);
    let stats = Arc::new(Stats::default());
    let target = SocketAddr::V6(SocketAddrV6::new(ALL_NODES, 0, 0, index));
    let goodbye = (advertisement.router_lifetime != 0).then(|| Goodbye {
        socket: socket.clone(),
        packet: advertisement.packet(true),
        target,
    });
    let task = tokio::spawn(run(
        advertisement.clone(),
        socket,
        index,
        target,
        stats.clone(),
    ));
    Ok(Started {
        task,
        advertisement,
        stats,
        goodbye,
    })
}

/// Router advertisements need a raw `ICMPv6` socket, which this system does not offer here.
///
/// # Errors
/// Always.
#[cfg(not(unix))]
pub fn start(_: &RouterAdvertisement, _: &Dhcp, _: u32) -> io::Result<Started> {
    Err(io::Error::other(
        "router advertisements are available on Linux, macOS and the BSDs",
    ))
}

#[cfg(unix)]
async fn run(
    advertisement: Arc<Advertisement>,
    socket: Arc<UdpSocket>,
    index: u32,
    target: SocketAddr,
    stats: Arc<Stats>,
) {
    let packet = advertisement.packet(false);
    let mut buffer = [0u8; 1500];
    let mut sent_unsolicited = 0u32;
    let mut next = Instant::now();
    let mut pending: Option<Instant> = None;
    let mut last: Option<Instant> = None;
    loop {
        let wake = pending.map_or(next, |due| due.min(next));
        tokio::select! {
            () = sleep_until(wake) => {
                let moment = Instant::now();
                if socket.send_to(&packet, target).await.is_ok() {
                    stats.sent.fetch_add(1, Ordering::Relaxed);
                    stats.last_sent.store(unix_now(), Ordering::Relaxed);
                }
                last = Some(moment);
                pending = None;
                next = moment
                    + unsolicited_delay(advertisement.interval_secs, sent_unsolicited, random_u64());
                sent_unsolicited = sent_unsolicited.saturating_add(1);
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, from)) = received else {
                    // A failing socket must not spin.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                let SocketAddr::V6(from) = from else { continue };
                // On the interface this socket serves, or the system did not say.
                if from.scope_id() != 0 && from.scope_id() != index {
                    continue;
                }
                if !is_solicitation(&buffer[..length], *from.ip()) || pending.is_some() {
                    continue;
                }
                // Many hosts asking at once get one answer: wait a little, and never answer
                // faster than the minimum gap.
                let moment = Instant::now();
                let jitter = Duration::from_millis(random_u64() % (MAX_ANSWER_DELAY_MS + 1));
                let earliest = last.map_or(moment, |at| at + MIN_GAP);
                pending = Some((moment + jitter).max(earliest));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Advertisement {
        Advertisement {
            interface: "eth0".into(),
            managed: false,
            other_config: false,
            router_lifetime: 0,
            preference: RouterPreference::Medium,
            interval_secs: 600,
            mtu: None,
            prefixes: vec![],
            routes: vec![],
            dns: vec![],
            search: vec![],
            mac: None,
        }
    }

    fn prefix(text: &str) -> AdvertisedPrefix {
        AdvertisedPrefix {
            prefix: text.parse().unwrap(),
            on_link: true,
            autonomous: true,
            valid_secs: 86_400,
            preferred_secs: 14_400,
        }
    }

    #[test]
    fn the_header_carries_flags_and_lifetime() {
        let mut ra = base();
        ra.managed = true;
        ra.other_config = true;
        ra.router_lifetime = 1800;
        let packet = ra.packet(false);
        assert_eq!(packet.len(), 16);
        assert_eq!(packet[0], 134);
        assert_eq!(packet[1], 0, "code");
        assert_eq!(packet[2..4], [0, 0], "the kernel fills the checksum");
        assert_eq!(packet[5], 0xc0, "M and O");
        assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 1800);
        // The goodbye message withdraws the router.
        let bye = ra.packet(true);
        assert_eq!(u16::from_be_bytes([bye[6], bye[7]]), 0);
        assert_eq!(bye[5], 0xc0);
    }

    #[test]
    fn a_router_that_is_not_a_default_router_advertises_medium_preference() {
        let mut ra = base();
        ra.preference = RouterPreference::High;
        assert_eq!(ra.packet(false)[5] & 0x18, 0, "lifetime 0 forces medium");
        ra.router_lifetime = 600;
        assert_eq!(ra.packet(false)[5] & 0x18, 0x08, "high");
        ra.preference = RouterPreference::Low;
        assert_eq!(ra.packet(false)[5] & 0x18, 0x18, "low");
        assert_eq!(ra.packet(true)[5] & 0x18, 0, "a goodbye is medium again");
    }

    #[test]
    fn prefix_information_has_flags_lifetimes_and_the_prefix() {
        let mut ra = base();
        ra.prefixes = vec![prefix("2001:db8:1::/64")];
        let packet = ra.packet(false);
        let option = &packet[16..];
        assert_eq!(option.len(), 32);
        assert_eq!(option[..4], [3, 4, 64, 0xc0], "type, 4 units, /64, L and A");
        assert_eq!(u32::from_be_bytes(option[4..8].try_into().unwrap()), 86_400);
        assert_eq!(
            u32::from_be_bytes(option[8..12].try_into().unwrap()),
            14_400
        );
        assert_eq!(option[12..16], [0; 4]);
        assert_eq!(
            Ipv6Addr::from(<[u8; 16]>::try_from(&option[16..32]).unwrap()),
            "2001:db8:1::".parse::<Ipv6Addr>().unwrap()
        );
        // A prefix hosts take addresses from by DHCPv6 only: on-link, not autonomous.
        let mut managed = prefix("2001:db8:2::/64");
        managed.autonomous = false;
        ra.prefixes = vec![managed];
        assert_eq!(ra.packet(false)[16 + 3], 0x80);
    }

    #[test]
    fn the_source_address_and_mtu_options_are_in_their_places() {
        let mut ra = base();
        ra.mac = Some([2, 0, 0, 0, 0, 1]);
        ra.mtu = Some(1500);
        let packet = ra.packet(false);
        assert_eq!(packet[16..24], [1, 1, 2, 0, 0, 0, 0, 1]);
        assert_eq!(packet[24..28], [5, 1, 0, 0]);
        assert_eq!(u32::from_be_bytes(packet[28..32].try_into().unwrap()), 1500);
    }

    #[test]
    fn rdnss_lists_servers_with_twice_the_interval_as_lifetime() {
        let mut ra = base();
        ra.dns = vec![
            "2001:db8::53".parse().unwrap(),
            "2001:db8::54".parse().unwrap(),
        ];
        let packet = ra.packet(false);
        let option = &packet[16..];
        assert_eq!(option[..2], [25, 5], "type 25, 1 + 2 * 2 units");
        assert_eq!(u32::from_be_bytes(option[4..8].try_into().unwrap()), 1200);
        assert_eq!(option.len(), 40);
        assert_eq!(
            option[8..24],
            "2001:db8::53".parse::<Ipv6Addr>().unwrap().octets()
        );
    }

    #[test]
    fn dnssl_encodes_names_as_labels_padded_to_eight_bytes() {
        let mut ra = base();
        ra.search = vec!["home.example".into()];
        let packet = ra.packet(false);
        let option = &packet[16..];
        // 8 bytes of header + [4]home[7]example[0] = 14 bytes, padded to 16.
        assert_eq!(option[0], 31);
        assert_eq!(option[1], 3, "24 bytes is 3 units");
        assert_eq!(option.len(), 24);
        assert_eq!(&option[8..], b"\x04home\x07example\x00\x00\x00");
        assert_eq!(option.len() % 8, 0);
        // A trailing dot makes no difference, and several names share the option.
        ra.search = vec!["a.b.".into(), "c.".into()];
        let packet = ra.packet(false);
        // Exactly 8 bytes of names, so no padding.
        assert_eq!(&packet[16 + 8..], b"\x01a\x01b\x00\x01c\x00");
        assert_eq!(packet[16 + 1], 2);
    }

    #[test]
    fn route_information_uses_the_shortest_prefix_field() {
        let mut ra = base();
        let route = |text: &str, preference| AdvertisedRoute {
            prefix: text.parse().unwrap(),
            preference,
            lifetime_secs: 1800,
        };
        ra.routes = vec![
            route("::/0", RouterPreference::Medium),
            route("fd00:1::/48", RouterPreference::High),
            route("fd00:2:3:4:5::/80", RouterPreference::Low),
        ];
        let packet = ra.packet(false);
        let first = &packet[16..24];
        assert_eq!(
            first[..4],
            [24, 1, 0, 0],
            "a default route has no prefix bytes"
        );
        assert_eq!(u32::from_be_bytes(first[4..8].try_into().unwrap()), 1800);
        let second = &packet[24..40];
        assert_eq!(second[..4], [24, 2, 48, 0x08]);
        assert_eq!(second[8..], [0xfd, 0, 0, 1, 0, 0, 0, 0]);
        let third = &packet[40..64];
        assert_eq!(third[..4], [24, 3, 80, 0x18]);
        assert_eq!(third.len(), 24);
        assert_eq!(packet.len() % 8, 0, "every option is whole units");
    }

    #[test]
    fn missing_dns_and_search_come_from_the_dhcp_settings() {
        let mut dhcp = Dhcp {
            domain: Some("home.example".into()),
            ..Dhcp::default()
        };
        dhcp.scopes6.push(lumen_config::DhcpScope6 {
            interface: Some("eth0".into()),
            prefix: "fd00:1::/64".parse().unwrap(),
            range_start: "fd00:1::100".parse().unwrap(),
            range_end: "fd00:1::1ff".parse().unwrap(),
            dns: vec!["fd00:1::2".parse().unwrap()],
            preferred_secs: 3600,
            valid_secs: 7200,
            reservations: vec![],
            delegation: None,
            reconfigure: false,
        });
        let mut config = RouterAdvertisement {
            interface: "eth0".into(),
            prefixes: vec![],
            managed: true,
            other_config: false,
            router_lifetime_secs: 0,
            preference: RouterPreference::Medium,
            interval_secs: 200,
            mtu: None,
            dns: None,
            search: None,
            routes: vec![],
        };
        let resolved = Advertisement::resolve(&config, &dhcp, None);
        assert_eq!(resolved.dns, vec!["fd00:1::2".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(resolved.search, vec!["home.example".to_owned()]);
        // `[]` means none, even when there is something to inherit.
        config.dns = Some(vec![]);
        config.search = Some(vec![]);
        let none = Advertisement::resolve(&config, &dhcp, None);
        assert!(none.dns.is_empty() && none.search.is_empty());
        // A different interface inherits no DNS servers.
        config.interface = "eth1".into();
        config.dns = None;
        assert!(Advertisement::resolve(&config, &dhcp, None).dns.is_empty());
    }

    #[test]
    fn only_solicitations_from_the_link_are_answered() {
        let solicitation = [133, 0, 0, 0, 0, 0, 0, 0];
        let link: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_solicitation(&solicitation, link));
        assert!(is_solicitation(&solicitation, Ipv6Addr::UNSPECIFIED));
        assert!(!is_solicitation(
            &solicitation,
            "2001:db8::1".parse().unwrap()
        ));
        assert!(
            !is_solicitation(&[134, 0, 0, 0, 0, 0, 0, 0], link),
            "not a solicitation"
        );
        assert!(
            !is_solicitation(&[133, 1, 0, 0, 0, 0, 0, 0], link),
            "bad code"
        );
        assert!(!is_solicitation(&[133, 0, 0, 0], link), "too short");
    }

    #[test]
    fn the_first_advertisements_come_quickly_and_later_ones_spread_over_the_interval() {
        for random in [0, 1, 999, 123_456_789, u64::MAX] {
            let first = unsolicited_delay(600, 0, random);
            assert!(
                (Duration::from_secs(1)..=Duration::from_secs(16)).contains(&first),
                "{first:?}"
            );
            let later = unsolicited_delay(600, 3, random);
            assert!(
                (Duration::from_secs(200)..=Duration::from_secs(600)).contains(&later),
                "{later:?}"
            );
        }
        // A short interval is never exceeded, and the third of it is at least 3 seconds
        // whenever the interval allows.
        for random in [0, 7, u64::MAX] {
            assert!(unsolicited_delay(4, 0, random) <= Duration::from_secs(4));
            let short = unsolicited_delay(4, 5, random);
            assert!((Duration::from_secs(3)..=Duration::from_secs(4)).contains(&short));
        }
        // Different samples give different waits (it is not a constant).
        assert_ne!(
            unsolicited_delay(600, 3, 0),
            unsolicited_delay(600, 3, 50_000)
        );
    }
}

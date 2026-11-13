//! Router Advertisements on a real link.
//!
//! Needs a raw `ICMPv6` socket (root) and two connected interfaces, such as a veth pair:
//!
//! ```text
//! ip link add veth0 type veth peer name veth1
//! ip link set veth0 up; ip link set veth1 up
//! LUMEN_RA_TEST_INTERFACES=veth0,veth1 cargo test -p lumen-dhcp --test ra -- --nocapture
//! ```
//!
//! Without that variable the test says so and passes, so ordinary `cargo test` is unaffected.

#![cfg(unix)]

use lumen_config::{
    AdvertisedPrefix, AdvertisedRoute, Dhcp, RouterAdvertisement, RouterPreference,
};
use lumen_resolver::Hosts;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

/// A host on the far end of the link: a raw `ICMPv6` socket that hears all-nodes traffic.
fn host(index: u32) -> UdpSocket {
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
    socket.set_multicast_hops_v6(255).unwrap();
    socket.set_unicast_hops_v6(255).unwrap();
    socket.set_multicast_if_v6(index).unwrap();
    socket.join_multicast_v6(&ALL_NODES, index).unwrap();
    socket.set_nonblocking(true).unwrap();
    UdpSocket::from_std(socket.into()).unwrap()
}

/// The next Router Advertisement the host hears, with the time it took.
async fn next_advertisement(host: &UdpSocket, wait: Duration) -> Option<(Vec<u8>, Duration)> {
    let started = Instant::now();
    let mut buffer = [0u8; 1500];
    timeout(wait, async {
        loop {
            let (length, _) = host.recv_from(&mut buffer).await.unwrap();
            if length >= 16 && buffer[0] == 134 {
                return buffer[..length].to_vec();
            }
        }
    })
    .await
    .ok()
    .map(|packet| (packet, started.elapsed()))
}

/// The options of an advertisement as `(type, bytes after the two-byte header)`.
fn options(packet: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = &packet[16..];
    while rest.len() >= 2 {
        let length = usize::from(rest[1]) * 8;
        assert!(length >= 8 && length <= rest.len(), "a well-formed option");
        out.push((rest[0], rest[2..length].to_vec()));
        rest = &rest[length..];
    }
    out
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn advertisements_are_sent_solicitations_answered_and_the_router_withdrawn() {
    let Ok(names) = std::env::var("LUMEN_RA_TEST_INTERFACES") else {
        eprintln!("skipped: set LUMEN_RA_TEST_INTERFACES=veth0,veth1 (and run as root) to try it");
        return;
    };
    let (server_name, peer_name) = names.split_once(',').expect("two interface names");
    let peer_index = nix::net::if_::if_nametoindex(peer_name).unwrap();
    let hear = host(peer_index);

    let config = Dhcp {
        enabled: true,
        domain: Some("home.lan".into()),
        router_advertisements: vec![RouterAdvertisement {
            interface: server_name.into(),
            prefixes: vec![AdvertisedPrefix {
                prefix: "2001:db8:77::/64".parse().unwrap(),
                on_link: true,
                autonomous: true,
                valid_secs: 7200,
                preferred_secs: 3600,
            }],
            managed: true,
            other_config: true,
            router_lifetime_secs: 1800,
            preference: RouterPreference::High,
            interval_secs: 4,
            mtu: Some(1400),
            dns: Some(vec!["2001:db8:77::53".parse().unwrap()]),
            search: None,
            routes: vec![AdvertisedRoute {
                prefix: "fd00:77::/48".parse().unwrap(),
                preference: RouterPreference::Low,
                lifetime_secs: 600,
            }],
        }],
        ..Dhcp::default()
    };
    let server = lumen_dhcp::start(&config, Arc::new(Hosts::new(Some("home.lan"))))
        .await
        .unwrap();

    // The first advertisement comes at once, from a link-local address, and says what was set.
    let (packet, took) = next_advertisement(&hear, Duration::from_secs(6))
        .await
        .expect("an unsolicited advertisement");
    eprintln!("first advertisement after {took:?}, {} bytes", packet.len());
    assert_eq!(packet[5] & 0xc0, 0xc0, "M and O");
    assert_eq!(packet[5] & 0x18, 0x08, "high preference");
    assert_eq!(u16::from_be_bytes([packet[6], packet[7]]), 1800);
    let found = options(&packet);
    let kinds: Vec<u8> = found.iter().map(|(kind, _)| *kind).collect();
    for wanted in [3, 5, 24, 25, 31] {
        assert!(kinds.contains(&wanted), "option {wanted} in {kinds:?}");
    }
    let prefix = found.iter().find(|(kind, _)| *kind == 3).unwrap();
    assert_eq!(prefix.1[0], 64);
    assert_eq!(prefix.1[1], 0xc0, "on-link and autonomous");
    assert_eq!(
        Ipv6Addr::from(<[u8; 16]>::try_from(&prefix.1[14..30]).unwrap()),
        "2001:db8:77::".parse::<Ipv6Addr>().unwrap()
    );
    // The search domain came from dhcp.domain.
    let search = found.iter().find(|(kind, _)| *kind == 31).unwrap();
    assert_eq!(&search.1[6..16], b"\x04home\x03lan\x00");
    assert!(search.1[16..].iter().all(|byte| *byte == 0), "padding");

    // More arrive on their own (the interval is 4 seconds), so the timer works.
    next_advertisement(&hear, Duration::from_secs(8))
        .await
        .expect("a second unsolicited advertisement");

    // A host that has just come up asks, and gets an answer well inside the minimum gap plus
    // the random wait (3 s + 0.5 s), if not sooner.
    // Let the quick initial burst finish so the answer is the one under test.
    tokio::time::sleep(Duration::from_secs(4)).await;
    while next_advertisement(&hear, Duration::from_millis(50))
        .await
        .is_some()
    {}
    let target = SocketAddr::V6(SocketAddrV6::new(ALL_ROUTERS, 0, 0, peer_index));
    hear.send_to(&[133, 0, 0, 0, 0, 0, 0, 0], target)
        .await
        .unwrap();
    let (_, waited) = next_advertisement(&hear, Duration::from_secs(5))
        .await
        .expect("an advertisement after the solicitation");
    eprintln!("answered a solicitation after {waited:?}");

    let snapshot = server.handle().snapshot();
    let info = &snapshot.advertisements[0];
    assert_eq!(info.interface, server_name);
    assert!(info.sent >= 3, "sent {}", info.sent);
    assert!(info.last_sent > 0);
    assert_eq!(info.router_lifetime_secs, 1800);
    assert!(info.managed && info.other_config);
    assert_eq!(info.prefixes, ["2001:db8:77::/64"]);

    // For trying it by hand: keep advertising so other tools can look at the link.
    if let Some(seconds) = std::env::var("LUMEN_RA_TEST_HOLD_SECS")
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
    {
        tokio::time::sleep(Duration::from_secs(seconds)).await;
    }

    // Stopping the server withdraws it as a default router: lifetime zero.
    drop(server);
    let mut withdrawn = false;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some((packet, _)) = next_advertisement(&hear, Duration::from_millis(500)).await
            && u16::from_be_bytes([packet[6], packet[7]]) == 0
        {
            withdrawn = true;
            break;
        }
    }
    assert!(withdrawn, "a goodbye advertisement with lifetime 0");
}

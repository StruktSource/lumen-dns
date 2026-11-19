//! Active probes: ICMP echo and TCP connect.
//!
//! ICMP uses the unprivileged "ping" datagram socket (no raw socket, no root needed on macOS, and
//! on Linux when `net.ipv4.ping_group_range` allows the account). When that is not possible the
//! probe reports it, and the caller falls back to TCP probes and the neighbor table.

use crate::health::CheckResult;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

const PAYLOAD: usize = 24;

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0xffff)
}

/// An echo request. `token` identifies our probes among other ICMP on the machine.
fn echo_request(v6: bool, id: u16, seq: u16, token: u64) -> Vec<u8> {
    let mut packet = Vec::with_capacity(8 + PAYLOAD);
    packet.push(if v6 { 128 } else { 8 });
    packet.push(0);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&seq.to_be_bytes());
    packet.extend_from_slice(&token.to_be_bytes());
    packet.resize(8 + PAYLOAD, 0x5a);
    if !v6 {
        // ICMPv6 checksums are filled in by the kernel.
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// If `datagram` is an echo reply carrying our token, its sequence number. The kernel may or may
/// not hand over the IP header (macOS does for IPv4, Linux does not).
fn reply_seq(v6: bool, datagram: &[u8], token: u64) -> Option<u16> {
    let mut icmp = datagram;
    if !v6 && icmp.first().is_some_and(|b| b >> 4 == 4) {
        let header = usize::from(icmp[0] & 0x0f) * 4;
        icmp = icmp.get(header..)?;
    }
    if icmp.len() < 16 || icmp[0] != if v6 { 129 } else { 0 } {
        return None;
    }
    let mut mine = [0u8; 8];
    mine.copy_from_slice(&icmp[8..16]);
    (u64::from_be_bytes(mine) == token).then(|| u16::from_be_bytes([icmp[6], icmp[7]]))
}

fn token() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u8(7);
    hasher.finish()
}

fn open(v6: bool) -> io::Result<UdpSocket> {
    let socket = if v6 {
        Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?
    } else {
        Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?
    };
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Whether this machine lets us send ICMP echo requests without extra privileges.
#[must_use]
pub fn icmp_available(v6: bool) -> bool {
    open(v6).is_ok()
}

/// Send `count` echo requests to `ip` and collect the answers within `wait`.
///
/// # Errors
/// The ICMP socket could not be opened or the address is not reachable at all.
pub async fn ping(ip: IpAddr, count: u8, wait: Duration) -> io::Result<CheckResult> {
    let v6 = ip.is_ipv6();
    let socket = open(v6)?;
    let target = SocketAddr::new(ip, 0);
    let token = token();
    let started = Instant::now();
    let mut sent_at = Vec::new();
    for seq in 0..u16::from(count.max(1)) {
        let packet = echo_request(v6, 0x4c55, seq, token);
        match socket.send_to(&packet, target).await {
            Ok(_) => sent_at.push((seq, Instant::now())),
            // No route to a local address, or a firewall: count it as an unanswered probe.
            Err(e) if sent_at.is_empty() && seq + 1 >= u16::from(count.max(1)) => return Err(e),
            Err(_) => {}
        }
        if seq + 1 < u16::from(count.max(1)) {
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }
    let sent = u8::try_from(sent_at.len()).unwrap_or(u8::MAX);
    let mut answered: Vec<(u16, Duration)> = Vec::new();
    let deadline = started + wait + Duration::from_millis(40 * u64::from(count));
    let mut buffer = [0u8; 1500];
    while answered.len() < sent_at.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let Ok(Ok((length, from))) = timeout(left, socket.recv_from(&mut buffer)).await else {
            break;
        };
        if from.ip() != ip && !same_host(from.ip(), ip) {
            continue;
        }
        if let Some(seq) = reply_seq(v6, &buffer[..length], token)
            && !answered.iter().any(|(s, _)| *s == seq)
            && let Some((_, at)) = sent_at.iter().find(|(s, _)| *s == seq)
        {
            answered.push((seq, at.elapsed()));
        }
    }
    let received = u8::try_from(answered.len()).unwrap_or(u8::MAX);
    let rtt_ms = answered
        .iter()
        .map(|(_, d)| d.as_secs_f64() * 1000.0)
        .fold(None, |best: Option<f64>, ms| {
            Some(best.map_or(ms, |b| b.min(ms)))
        });
    Ok(CheckResult {
        sent: sent.max(1),
        received,
        rtt_ms,
    })
}

/// A link-local IPv6 address may come back without its scope; compare the address only.
fn same_host(a: IpAddr, b: IpAddr) -> bool {
    a == b
}

/// Ping the all-nodes group on an interface and return who answered. This fills the neighbor
/// table with every IPv6 host on the link.
///
/// # Errors
/// The `ICMPv6` socket could not be opened.
pub async fn ping_all_nodes(interface_index: u32, wait: Duration) -> io::Result<Vec<Ipv6Addr>> {
    let socket = open(true)?;
    let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    let target = SocketAddr::V6(SocketAddrV6::new(group, 0, 0, interface_index));
    let token = token();
    socket
        .send_to(&echo_request(true, 0x4c55, 0, token), target)
        .await?;
    let deadline = Instant::now() + wait;
    let mut found = Vec::new();
    let mut buffer = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let Ok(Ok((length, from))) = timeout(left, socket.recv_from(&mut buffer)).await else {
            break;
        };
        if let IpAddr::V6(addr) = from.ip()
            && reply_seq(true, &buffer[..length], token).is_some()
            && !found.contains(&addr)
        {
            found.push(addr);
        }
    }
    Ok(found)
}

/// What a TCP connection attempt showed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tcp {
    /// The port accepted the connection.
    Open(f64),
    /// The host answered with a refusal: it is there, the port is closed.
    Refused(f64),
    /// Nothing came back in time.
    Silent,
}

/// Try a TCP connection and close it at once.
pub async fn tcp(addr: SocketAddr, wait: Duration) -> Tcp {
    let started = Instant::now();
    match timeout(wait, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            // Connecting to a closed port in the ephemeral range can pick the same number as
            // the local port and "connect" to itself (TCP simultaneous open). That is a refusal.
            let itself =
                matches!((stream.local_addr(), stream.peer_addr()), (Ok(a), Ok(b)) if a == b);
            drop(stream);
            if itself {
                Tcp::Refused(ms)
            } else {
                Tcp::Open(ms)
            }
        }
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            Tcp::Refused(started.elapsed().as_secs_f64() * 1000.0)
        }
        _ => Tcp::Silent,
    }
}

/// A check over TCP: `count` connection attempts to one port.
pub async fn tcp_check(addr: SocketAddr, count: u8, wait: Duration) -> CheckResult {
    let mut received = 0u8;
    let mut best: Option<f64> = None;
    for _ in 0..count.max(1) {
        if let Tcp::Open(ms) = tcp(addr, wait).await {
            received += 1;
            best = Some(best.map_or(ms, |b: f64| b.min(ms)));
        }
    }
    CheckResult {
        sent: count.max(1),
        received,
        rtt_ms: best,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_checksum_matches_the_rfc_example() {
        // RFC 1071 section 3 example: the sum of these words is 0xddf2, whose complement is 0x220d.
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        let packet = echo_request(false, 1, 1, 42);
        assert_eq!(
            checksum(&packet),
            0,
            "a packet with its checksum in place sums to zero"
        );
    }

    #[test]
    fn replies_are_recognized_with_or_without_the_ip_header_and_only_with_our_token() {
        let mut reply = echo_request(false, 9, 3, 77);
        reply[0] = 0;
        assert_eq!(reply_seq(false, &reply, 77), Some(3));
        assert_eq!(reply_seq(false, &reply, 78), None, "someone else's ping");
        let mut with_header = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1,
        ];
        with_header.extend_from_slice(&reply);
        assert_eq!(reply_seq(false, &with_header, 77), Some(3));
        let request = echo_request(false, 9, 3, 77);
        assert_eq!(
            reply_seq(false, &request, 77),
            None,
            "a request is not a reply"
        );
        let mut v6 = echo_request(true, 9, 4, 5);
        v6[0] = 129;
        assert_eq!(reply_seq(true, &v6, 5), Some(4));
        assert_eq!(reply_seq(true, &[129, 0, 0], 5), None);
    }

    #[tokio::test]
    async fn pinging_this_machine_works_where_unprivileged_icmp_is_allowed() {
        if !icmp_available(false) {
            return;
        }
        let result = ping("127.0.0.1".parse().unwrap(), 2, Duration::from_millis(800))
            .await
            .unwrap();
        assert_eq!(result.sent, 2);
        assert!(result.received >= 1, "{result:?}");
        assert!(result.rtt_ms.is_some());
    }

    #[tokio::test]
    async fn tcp_probes_tell_open_refused_and_silent_apart() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        assert!(matches!(
            tcp(open, Duration::from_millis(500)).await,
            Tcp::Open(_)
        ));
        let result = tcp_check(open, 2, Duration::from_millis(500)).await;
        assert_eq!((result.sent, result.received), (2, 2));
        drop(listener);
        // Use a fresh port with no established connections waiting in its accept queue. Reusing
        // `open` can still complete one queued handshake after the listener is dropped.
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = closed_listener.local_addr().unwrap();
        drop(closed_listener);
        // A closed port answers with a refusal. (Some systems rate-limit those answers when the
        // machine is busy, so silence is accepted too; an open port is not.)
        assert!(!matches!(
            tcp(closed, Duration::from_millis(500)).await,
            Tcp::Open(_)
        ));
        assert_eq!(
            tcp_check(closed, 1, Duration::from_millis(500))
                .await
                .received,
            0
        );
    }
}

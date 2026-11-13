//! Real sockets: one per interface and family, joined to the mDNS group.

use crate::{
    bridge::{Bridge, Settings},
    link::{Datagram, Family, Link},
    reflect::{on_link_v4, on_link_v6},
};
use async_trait::async_trait;
use lumen_config::Mdns;
use lumen_resolver::Resolver;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};

const GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const PORT: u16 = 5353;

/// What is known about one interface.
#[derive(Clone, Debug, Default)]
struct Iface {
    name: String,
    index: u32,
    v4: Vec<(Ipv4Addr, Ipv4Addr)>,
    v6: Vec<Ipv6Addr>,
}

#[cfg(unix)]
fn interfaces(names: &[String]) -> io::Result<Vec<Iface>> {
    let mut out: Vec<Iface> = Vec::new();
    for name in names {
        let index = nix::net::if_::if_nametoindex(name.as_str())
            .map_err(|error| io::Error::other(format!("interface {name}: {error}")))?;
        out.push(Iface {
            name: name.clone(),
            index,
            ..Iface::default()
        });
    }
    let all = nix::ifaddrs::getifaddrs().map_err(io::Error::other)?;
    for item in all {
        let Some(iface) = out.iter_mut().find(|i| i.name == item.interface_name) else {
            continue;
        };
        if let Some(address) = item.address {
            if let Some(v4) = address.as_sockaddr_in() {
                let mask = item
                    .netmask
                    .and_then(|m| m.as_sockaddr_in().map(nix::sys::socket::SockaddrIn::ip))
                    .unwrap_or(Ipv4Addr::BROADCAST);
                iface.v4.push((v4.ip(), mask));
            } else if let Some(v6) = address.as_sockaddr_in6() {
                iface.v6.push(v6.ip());
            }
        }
    }
    Ok(out)
}

#[cfg(not(unix))]
fn interfaces(_: &[String]) -> io::Result<Vec<Iface>> {
    Err(io::Error::other(
        "the mDNS bridge is supported on Linux and macOS",
    ))
}

struct UdpLink {
    name: String,
    family: Family,
    socket: Arc<UdpSocket>,
    group: SocketAddr,
    iface: Iface,
    /// Testing against fixed addresses: loopback counts as the link.
    test_mode: bool,
}

#[async_trait]
impl Link for UdpLink {
    fn name(&self) -> &str {
        &self.name
    }
    fn family(&self) -> Family {
        self.family
    }
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.socket.send_to(packet, self.group).await.map(|_| ())
    }
    fn on_link(&self, source: IpAddr) -> bool {
        if self.test_mode {
            return source.is_loopback();
        }
        match source {
            IpAddr::V4(source) => self
                .iface
                .v4
                .iter()
                .any(|(local, mask)| on_link_v4(source, *local, *mask)),
            IpAddr::V6(source) => on_link_v6(source),
        }
    }
}

fn socket_v4(iface: &Iface, listen: SocketAddr, join: bool) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if join {
        socket.bind_device(Some(iface.name.as_bytes()))?;
    }
    #[cfg(target_os = "macos")]
    if join {
        socket.bind_device_by_index_v4(std::num::NonZeroU32::new(iface.index))?;
    }
    socket.bind(&listen.into())?;
    if join {
        let local = iface
            .v4
            .first()
            .map(|(address, _)| *address)
            .ok_or_else(|| {
                io::Error::other(format!("interface {} has no IPv4 address", iface.name))
            })?;
        socket.join_multicast_v4(&GROUP_V4, &local)?;
        socket.set_multicast_if_v4(&local)?;
        // Responders on this very machine (avahi) must hear our questions, so loopback stays
        // on; the bridge recognizes its own packets and does not repeat them.
        socket.set_multicast_loop_v4(true)?;
        socket.set_multicast_ttl_v4(255)?;
    }
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn socket_v6(iface: &Iface, listen: SocketAddr, join: bool) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket.bind_device(Some(iface.name.as_bytes()))?;
    #[cfg(target_os = "macos")]
    socket.bind_device_by_index_v6(std::num::NonZeroU32::new(iface.index))?;
    socket.bind(&listen.into())?;
    if join {
        socket.join_multicast_v6(&GROUP_V6, iface.index)?;
        socket.set_multicast_if_v6(iface.index)?;
        socket.set_multicast_loop_v6(true)?;
        socket.set_multicast_hops_v6(255)?;
    }
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// The running bridge. Dropping it stops every task.
pub struct Running {
    pub bridge: Arc<Bridge>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Start the bridge on the configured interfaces and, when a domain is set, hand it to the
/// resolver so unicast questions under that domain reach it.
///
/// # Errors
/// An interface does not exist or has no address, or a socket cannot be opened.
#[allow(clippy::too_many_lines)]
pub async fn start(config: &Mdns, resolver: &Resolver) -> io::Result<Running> {
    let test_mode = config.group4.is_some() || config.group6.is_some();
    let found = if test_mode {
        config
            .interfaces
            .iter()
            .map(|name| Iface {
                name: name.clone(),
                ..Iface::default()
            })
            .collect()
    } else {
        interfaces(&config.interfaces)?
    };
    let (tx, mut rx) = mpsc::channel::<Datagram>(512);
    let mut links: Vec<Arc<dyn Link>> = Vec::new();
    let mut sockets: Vec<Arc<UdpSocket>> = Vec::new();
    for iface in &found {
        // IPv4 (an interface without an address is skipped when it can still use IPv6).
        // Testing: listen on loopback and send to the fixed address (a pretend device).
        let v4_listen = if test_mode {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        } else {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PORT))
        };
        if test_mode || !iface.v4.is_empty() {
            let socket = Arc::new(socket_v4(iface, v4_listen, !test_mode).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("mDNS IPv4 socket on {}: {error}", iface.name),
                )
            })?);
            links.push(Arc::new(UdpLink {
                name: iface.name.clone(),
                family: Family::V4,
                socket: Arc::clone(&socket),
                group: config
                    .group4
                    .unwrap_or(SocketAddr::V4(SocketAddrV4::new(GROUP_V4, PORT))),
                iface: iface.clone(),
                test_mode,
            }));
            sockets.push(socket);
        }
        if config.ipv6 && !iface.v6.is_empty() && !test_mode {
            let listen = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, PORT, 0, 0));
            let socket = Arc::new(socket_v6(iface, listen, true).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("mDNS IPv6 socket on {}: {error}", iface.name),
                )
            })?);
            links.push(Arc::new(UdpLink {
                name: iface.name.clone(),
                family: Family::V6,
                socket: Arc::clone(&socket),
                group: SocketAddr::V6(SocketAddrV6::new(GROUP_V6, PORT, 0, iface.index)),
                iface: iface.clone(),
                test_mode,
            }));
            sockets.push(socket);
        }
    }
    if links.is_empty() {
        return Err(io::Error::other("no mDNS interface has a usable address"));
    }
    let bridge = Bridge::new(
        links,
        Settings {
            domain: config.domain.clone(),
            reflect: config.reflect,
            wait: Duration::from_millis(u64::from(config.wait_ms)),
            ttl_cap: config.ttl_cap_secs,
            max_records: config.max_records as usize,
        },
    )
    .map_err(io::Error::other)?;
    if config.domain.is_some() {
        resolver.set_bridge(bridge.clone());
    }
    let mut tasks = Vec::new();
    for (index, socket) in sockets.into_iter().enumerate() {
        let tx = tx.clone();
        tasks.push(tokio::spawn(async move {
            let mut buffer = vec![0u8; 9000];
            loop {
                let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                };
                // A full queue drops packets: better than growing without bound.
                let _ = tx.try_send(Datagram {
                    link: index,
                    source,
                    bytes: buffer[..length].to_vec(),
                });
            }
        }));
    }
    let engine = bridge.clone();
    tasks.push(tokio::spawn(async move {
        while let Some(datagram) = rx.recv().await {
            engine.handle(datagram, Instant::now()).await;
        }
    }));
    Ok(Running { bridge, tasks })
}

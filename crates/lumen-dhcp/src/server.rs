//! Sockets, storage and DNS publishing around the pure engines.

use crate::{
    store::Store,
    v4::{self, Change, Destination},
    v6::{self, Change6},
};
use dhcproto::{Decodable, Decoder, Encodable};
use lumen_config::Dhcp;
use lumen_resolver::Hosts;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, task::JoinHandle};

/// All `DHCPv6` servers and relay agents on a link (RFC 8415).
const ALL_SERVERS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);
const EXPIRY_INTERVAL: Duration = Duration::from_secs(30);

type Engine4 = Arc<Mutex<v4::Engine>>;
type Engine6 = Arc<Mutex<v6::Engine6>>;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One scope as the console shows it.
#[derive(Clone, Debug)]
pub struct ScopeInfo {
    /// 4 or 6.
    pub family: u8,
    pub interface: Option<String>,
    pub network: String,
    pub range: String,
    pub active: usize,
    pub capacity: u64,
}

/// One bound lease as the console shows it.
#[derive(Clone, Debug)]
pub struct LeaseInfo {
    pub family: u8,
    pub ip: IpAddr,
    /// Hardware address (`aa:bb:..`) for IPv4 clients with no identifier, else the identifier in hex.
    pub client: String,
    pub hostname: Option<String>,
    pub expires: u64,
}

/// A view of the server for status pages. Taking it never blocks packet handling for long.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub scopes: Vec<ScopeInfo>,
    pub leases: Vec<LeaseInfo>,
}

/// The most leases a snapshot lists, so a status page stays small.
pub const SNAPSHOT_LEASES: usize = 2000;

fn hex(bytes: &[u8]) -> String {
    let text: Vec<String> = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    // A six byte hardware address reads better with colons.
    text.join(if bytes.len() == 6 { ":" } else { "" })
}

/// A cheap, clonable view of the engines.
#[derive(Clone)]
pub struct Handle {
    engines4: Vec<Engine4>,
    engines6: Vec<Engine6>,
}

impl Handle {
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let mut out = Snapshot::default();
        for engine in &self.engines4 {
            let engine = locked(engine);
            let scope = engine.scope();
            let bound = engine.bound();
            out.scopes.push(ScopeInfo {
                family: 4,
                interface: scope.interface.clone(),
                network: scope.subnet.to_string(),
                range: format!("{} – {}", scope.range_start, scope.range_end),
                active: bound.len(),
                capacity: u64::from(u32::from(scope.range_end))
                    - u64::from(u32::from(scope.range_start))
                    + 1,
            });
            out.leases.extend(bound.into_iter().map(|lease| LeaseInfo {
                family: 4,
                ip: lease.ip.into(),
                client: hex(&lease.client),
                hostname: lease.hostname,
                expires: lease.expires,
            }));
        }
        for engine in &self.engines6 {
            let engine = locked(engine);
            let scope = engine.scope();
            let bound = engine.bound();
            let capacity = u128::from(scope.range_end) - u128::from(scope.range_start) + 1;
            out.scopes.push(ScopeInfo {
                family: 6,
                interface: Some(scope.interface.clone()),
                network: scope.prefix.to_string(),
                range: format!("{} – {}", scope.range_start, scope.range_end),
                active: bound.len(),
                capacity: u64::try_from(capacity).unwrap_or(u64::MAX),
            });
            out.leases.extend(bound.into_iter().map(|lease| LeaseInfo {
                family: 6,
                ip: lease.ip.into(),
                client: hex(&lease.client),
                hostname: lease.hostname,
                expires: lease.expires,
            }));
        }
        out.leases.truncate(SNAPSHOT_LEASES);
        out
    }
}

/// The running server. Dropping it stops every task.
pub struct Running {
    handle: Handle,
    tasks: Vec<JoinHandle<()>>,
    /// The addresses the sockets are bound to, for tests and logs.
    pub bound4: Vec<SocketAddr>,
    pub bound6: Option<SocketAddr>,
}

impl Running {
    /// A view for status pages that outlives nothing: it only reads the engines.
    #[must_use]
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

struct Shared {
    store: Store,
    hosts: Arc<Hosts>,
}

impl Shared {
    fn publish(&self, hostname: Option<&str>, ip: IpAddr) {
        // A new name for the same address replaces the old one.
        self.hosts.withdraw(ip);
        if let Some(name) = hostname {
            self.hosts.publish(name, ip);
        }
    }

    fn apply4(&self, change: Change) {
        match change {
            Change::Bind(lease) => {
                if let Err(error) = self.store.put4(&lease) {
                    eprintln!("dhcp: cannot save a lease ({error})");
                }
                self.publish(lease.hostname.as_deref(), lease.ip.into());
            }
            Change::End(ip) => self.end(ip.into()),
        }
    }

    fn apply6(&self, change: Change6) {
        match change {
            Change6::Bind(lease) => {
                if let Err(error) = self.store.put6(&lease) {
                    eprintln!("dhcp: cannot save a lease ({error})");
                }
                self.publish(lease.hostname.as_deref(), lease.ip.into());
            }
            Change6::End(ip) => self.end(ip.into()),
        }
    }

    fn end(&self, ip: IpAddr) {
        if let Err(error) = self.store.remove(ip) {
            eprintln!("dhcp: cannot delete a lease ({error})");
        }
        self.hosts.withdraw(ip);
    }
}

#[cfg(unix)]
fn interface_index(name: &str) -> io::Result<u32> {
    nix::net::if_::if_nametoindex(name)
        .map_err(|error| io::Error::other(format!("interface {name}: {error}")))
}

#[cfg(not(unix))]
fn interface_index(name: &str) -> io::Result<u32> {
    Err(io::Error::other(format!(
        "interface {name}: binding to an interface is not supported on this system"
    )))
}

/// A `DHCPv4` socket: broadcast-capable, shared with other servers' ports, and tied to one
/// interface so a request on one network is never answered from another.
fn socket4(listen: SocketAddr, interface: Option<&str>) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    if let Some(name) = interface {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        socket.bind_device(Some(name.as_bytes()))?;
        #[cfg(target_os = "macos")]
        {
            let index = interface_index(name)?;
            socket.bind_device_by_index_v4(std::num::NonZeroU32::new(index))?;
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
        {
            let _ = name;
            return Err(io::Error::other(
                "binding DHCPv4 to an interface is supported on Linux and macOS",
            ));
        }
    }
    socket.bind(&listen.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn socket6(listen: SocketAddr, interfaces: &[u32], join: bool) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    socket.bind(&listen.into())?;
    if join {
        for index in interfaces {
            socket.join_multicast_v6(&ALL_SERVERS_V6, *index)?;
        }
    }
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Where a v4 reply goes. A client that has no address yet sends from 0.0.0.0 and is answered by
/// broadcast; anything that came from a real address (a renewing client, a test) is answered
/// there.
fn target4(destination: Destination, source: SocketAddr, config: &Dhcp) -> Option<SocketAddr> {
    let direct = !source.ip().is_unspecified();
    match destination {
        Destination::Silent => None,
        Destination::Relay(relay) => Some(SocketAddr::new(relay.into(), config.listen4.port())),
        Destination::Unicast(ip) => Some(if direct {
            source
        } else {
            SocketAddr::new(ip.into(), config.client_port4)
        }),
        Destination::Broadcast => Some(if direct {
            source
        } else {
            SocketAddr::new([255, 255, 255, 255].into(), config.client_port4)
        }),
    }
}

async fn serve4(socket: UdpSocket, engine: Engine4, shared: Arc<Shared>, config: Arc<Dhcp>) {
    let mut buffer = [0u8; 1500];
    loop {
        let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
            // A failing socket must not spin.
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(request) = dhcproto::v4::Message::decode(&mut Decoder::new(&buffer[..length]))
        else {
            continue;
        };
        let Some(reply) = locked(&engine).handle(&request, now()) else {
            continue;
        };
        if let Some(change) = reply.change {
            shared.apply4(change);
        }
        let Some(target) = target4(reply.destination, source, &config) else {
            continue;
        };
        if let Ok(bytes) = reply.message.to_vec() {
            let _ = socket.send_to(&bytes, target).await;
        }
    }
}

async fn serve6(socket: UdpSocket, scopes: Vec<(u32, Engine6)>, shared: Arc<Shared>) {
    let mut buffer = [0u8; 1500];
    loop {
        let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(request) = dhcproto::v6::Message::decode(&mut Decoder::new(&buffer[..length]))
        else {
            continue;
        };
        // The link a client is on is the interface its link-local address belongs to. A single
        // scope also serves clients that arrive without one (unicast, or testing).
        let scope_id = match source {
            SocketAddr::V6(address) => address.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        let engine = scopes
            .iter()
            .find(|(index, _)| *index == scope_id)
            .or_else(|| (scopes.len() == 1 && scope_id == 0).then(|| &scopes[0]))
            .map(|(_, engine)| engine);
        let Some(engine) = engine else {
            continue;
        };
        let Some(reply) = locked(engine).handle(&request, now()) else {
            continue;
        };
        for change in reply.changes {
            shared.apply6(change);
        }
        if let Ok(bytes) = reply.message.to_vec() {
            let _ = socket.send_to(&bytes, source).await;
        }
    }
}

async fn expire(engines4: Vec<Engine4>, engines6: Vec<Engine6>, shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(EXPIRY_INTERVAL);
    loop {
        tick.tick().await;
        let moment = now();
        for engine in &engines4 {
            for ip in locked(engine).expire(moment) {
                shared.end(ip.into());
            }
        }
        for engine in &engines6 {
            for ip in locked(engine).expire(moment) {
                shared.end(ip.into());
            }
        }
    }
}

/// A fresh random `DUID` (type 4, UUID) for the server's identity.
fn new_duid() -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    // Mark it as a version 4 UUID.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let mut duid = vec![0, 4];
    duid.extend_from_slice(&bytes);
    duid
}

/// Start the DHCP server for every configured scope.
///
/// Leases are restored from `lease_file` and published to `hosts` before the first packet is
/// read. Returns once the sockets are bound.
///
/// # Errors
/// A socket cannot be bound (port 67 and 547 need privileges), an interface does not exist, or
/// the lease file cannot be opened.
pub async fn start(config: &Dhcp, hosts: Arc<Hosts>) -> io::Result<Running> {
    let store = Store::open(config.lease_file.as_deref()).map_err(io::Error::other)?;
    let moment = now();
    let restored4 = store.load4(moment).map_err(io::Error::other)?;
    let restored6 = store.load6(moment).map_err(io::Error::other)?;
    let duid = store.server_duid(new_duid).map_err(io::Error::other)?;
    let shared = Arc::new(Shared { store, hosts });
    let domain = config.domain.clone().unwrap_or_default();
    let config = Arc::new(config.clone());
    let mut tasks = Vec::new();
    let mut engines4 = Vec::new();
    let mut engines6 = Vec::new();
    let mut bound4 = Vec::new();
    let mut bound6 = None;

    for scope in &config.scopes {
        let mine: Vec<_> = restored4
            .iter()
            .filter(|lease| scope.subnet.contains(&lease.ip))
            .cloned()
            .collect();
        for lease in &mine {
            shared.publish(lease.hostname.as_deref(), lease.ip.into());
        }
        let engine = Arc::new(Mutex::new(v4::Engine::new(scope, &domain, mine, moment)));
        let socket = socket4(config.listen4, scope.interface.as_deref())?;
        bound4.push(socket.local_addr()?);
        tasks.push(tokio::spawn(serve4(
            socket,
            engine.clone(),
            shared.clone(),
            config.clone(),
        )));
        engines4.push(engine);
    }

    if !config.scopes6.is_empty() {
        let mut indexes = Vec::new();
        let mut scopes = Vec::new();
        for scope in &config.scopes6 {
            let index = interface_index(&scope.interface).or_else(|error| {
                // Testing against a fixed address needs no real interface.
                if config.listen6.ip().is_unspecified() {
                    Err(error)
                } else {
                    Ok(0)
                }
            })?;
            let mine: Vec<_> = restored6
                .iter()
                .filter(|lease| scope.prefix.contains(&lease.ip))
                .cloned()
                .collect();
            for lease in &mine {
                shared.publish(lease.hostname.as_deref(), lease.ip.into());
            }
            let engine = Arc::new(Mutex::new(v6::Engine6::new(
                scope,
                duid.clone(),
                mine,
                moment,
            )));
            indexes.push(index);
            scopes.push((index, engine.clone()));
            engines6.push(engine);
        }
        // Multicast is joined only when listening on every address; a fixed address is for
        // tests and relays.
        let socket = socket6(
            config.listen6,
            &indexes,
            config.listen6.ip().is_unspecified(),
        )?;
        bound6 = Some(socket.local_addr()?);
        tasks.push(tokio::spawn(serve6(socket, scopes, shared.clone())));
    }

    let handle = Handle {
        engines4: engines4.clone(),
        engines6: engines6.clone(),
    };
    tasks.push(tokio::spawn(expire(engines4, engines6, shared)));
    Ok(Running {
        handle,
        tasks,
        bound4,
        bound6,
    })
}

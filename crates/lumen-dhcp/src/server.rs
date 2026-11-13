//! Sockets, storage and DNS publishing around the pure engines.

use crate::{
    failover::{self, Failover, Wire},
    relay,
    store::Store,
    v4::{self, Change, Destination},
    v6::{self, Change6},
};
use dhcproto::{Decodable, Decoder, Encodable};
use ipnet::Ipv6Net;
use lumen_config::{Dhcp, DhcpScope, FailoverRole};
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
    /// The address, or the network address of a delegated prefix.
    pub ip: IpAddr,
    /// Set for a delegated prefix: its length.
    pub prefix_len: Option<u8>,
    /// A temporary address (`IA_TA`).
    pub temporary: bool,
    /// The client agreed to be told to renew, so [`Handle::reconfigure`] works for it.
    pub reconfigurable: bool,
    /// Hardware address (`aa:bb:..`) for IPv4 clients with no identifier, else the identifier in hex.
    pub client: String,
    pub hostname: Option<String>,
    pub expires: u64,
}

/// This server's place in a failover pair.
#[derive(Clone, Debug)]
pub struct FailoverInfo {
    pub role: &'static str,
    /// Whether it is answering clients now.
    pub active: bool,
}

/// A view of the server for status pages. Taking it never blocks packet handling for long.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub scopes: Vec<ScopeInfo>,
    pub leases: Vec<LeaseInfo>,
    pub failover: Option<FailoverInfo>,
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
    failover: Option<Arc<Failover>>,
    role: Option<FailoverRole>,
    socket6: Option<Arc<UdpSocket>>,
    client_port6: u16,
}

impl Handle {
    /// Ask the device that holds `ip` to renew now (or, with `info_only`, to ask for its
    /// configuration again), with a signed Reconfigure message (RFC 8415 section 18.4).
    ///
    /// # Errors
    /// The address is not a leased address of a client that agreed to be reconfigured, or the
    /// message could not be sent.
    pub fn reconfigure(&self, ip: IpAddr, info_only: bool) -> Result<(), String> {
        let IpAddr::V6(ip) = ip else {
            return Err("only DHCPv6 clients can be reconfigured".into());
        };
        let socket = self
            .socket6
            .as_ref()
            .ok_or("the DHCPv6 server is not running")?;
        let moment = now();
        for engine in &self.engines6 {
            let engine = locked(engine);
            let Some(client) = engine.reconfigurable_client(ip, moment) else {
                continue;
            };
            let message = engine
                .reconfigure_message(&client, info_only, moment)
                .ok_or("that device did not agree to be reconfigured")?;
            let bytes = message.to_vec().map_err(|error| error.to_string())?;
            return socket
                .try_send_to(&bytes, SocketAddr::new(ip.into(), self.client_port6))
                .map(|_| ())
                .map_err(|error| format!("could not send: {error}"));
        }
        Err("no device that agreed to be reconfigured holds that address".into())
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let mut out = Snapshot::default();
        let moment = now();
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
                prefix_len: None,
                temporary: false,
                reconfigurable: false,
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
                interface: scope.interface.clone(),
                network: scope.prefix.to_string(),
                range: format!("{} – {}", scope.range_start, scope.range_end),
                active: bound.len(),
                capacity: u64::try_from(capacity).unwrap_or(u64::MAX),
            });
            out.leases.extend(bound.into_iter().map(|lease| LeaseInfo {
                family: 6,
                ip: lease.ip.into(),
                prefix_len: None,
                temporary: lease.temporary,
                reconfigurable: engine.reconfigurable_client(lease.ip, moment).is_some(),
                client: hex(&lease.client),
                hostname: lease.hostname,
                expires: lease.expires,
            }));
            out.leases
                .extend(engine.bound_prefixes().into_iter().map(|item| LeaseInfo {
                    family: 6,
                    ip: item.prefix.network().into(),
                    prefix_len: Some(item.prefix.prefix_len()),
                    temporary: false,
                    reconfigurable: false,
                    client: hex(&item.client),
                    hostname: None,
                    expires: item.expires,
                }));
        }
        out.leases.truncate(SNAPSHOT_LEASES);
        out.failover = self
            .failover
            .as_ref()
            .zip(self.role)
            .map(|(link, role)| FailoverInfo {
                role: if role == FailoverRole::Primary {
                    "primary"
                } else {
                    "secondary"
                },
                active: link.active(now()),
            });
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
    failover: Option<Arc<Failover>>,
}

impl Shared {
    fn publish(&self, hostname: Option<&str>, ip: IpAddr) {
        // A new name for the same address replaces the old one.
        self.hosts.withdraw(ip);
        if let Some(name) = hostname {
            self.hosts.publish(name, ip);
        }
    }

    fn tell(&self, wire: Wire) {
        if let Some(link) = &self.failover {
            link.send(wire);
        }
    }

    /// A change made here; `replicate` is false for one that came from the failover partner.
    fn apply4(&self, change: Change, replicate: bool) {
        match change {
            Change::Bind(lease) => {
                if let Err(error) = self.store.put4(&lease) {
                    eprintln!("dhcp: cannot save a lease ({error})");
                }
                self.publish(lease.hostname.as_deref(), lease.ip.into());
                if replicate {
                    self.tell(Wire::Lease4 {
                        ip: lease.ip,
                        client: lease.client,
                        hostname: lease.hostname,
                        expires: lease.expires,
                    });
                }
            }
            Change::End(ip) => {
                self.end(ip.into());
                if replicate {
                    self.tell(Wire::End4 { ip });
                }
            }
        }
    }

    fn apply6(&self, change: Change6, replicate: bool) {
        match change {
            Change6::Bind(lease) => {
                if let Err(error) = self.store.put6(&lease) {
                    eprintln!("dhcp: cannot save a lease ({error})");
                }
                self.publish(lease.hostname.as_deref(), lease.ip.into());
                if replicate {
                    self.tell(Wire::Lease6 {
                        ip: lease.ip,
                        client: lease.client,
                        iaid: lease.iaid,
                        hostname: lease.hostname,
                        expires: lease.expires,
                        temporary: lease.temporary,
                    });
                }
            }
            Change6::End(ip) => {
                self.end(ip.into());
                if replicate {
                    self.tell(Wire::End6 { ip });
                }
            }
            Change6::BindPrefix(item) => {
                if let Err(error) = self.store.put_prefix(&item) {
                    eprintln!("dhcp: cannot save a prefix ({error})");
                }
                if replicate {
                    self.tell(Wire::Prefix {
                        prefix: item.prefix,
                        client: item.client,
                        iaid: item.iaid,
                        expires: item.expires,
                    });
                }
            }
            Change6::ReconfigureKey { client, key } => {
                if let Err(error) = self.store.put_reconf_key(&client, &key) {
                    eprintln!("dhcp: cannot save a reconfigure key ({error})");
                }
            }
            Change6::EndPrefix(prefix) => {
                self.end_prefix(prefix);
                if replicate {
                    self.tell(Wire::EndPrefix { prefix });
                }
            }
        }
    }

    fn end(&self, ip: IpAddr) {
        if let Err(error) = self.store.remove(ip) {
            eprintln!("dhcp: cannot delete a lease ({error})");
        }
        self.hosts.withdraw(ip);
    }

    fn end_prefix(&self, prefix: Ipv6Net) {
        if let Err(error) = self.store.remove_prefix(prefix) {
            eprintln!("dhcp: cannot delete a prefix ({error})");
        }
    }
}

/// The engines of every scope, for the failover link.
struct Engines {
    v4: Vec<Engine4>,
    v6: Vec<Engine6>,
}

impl Engines {
    /// Everything bound now, as failover messages.
    fn snapshot(&self) -> Vec<Wire> {
        let mut out = Vec::new();
        for engine in &self.v4 {
            out.extend(
                locked(engine)
                    .bound()
                    .into_iter()
                    .map(|lease| Wire::Lease4 {
                        ip: lease.ip,
                        client: lease.client,
                        hostname: lease.hostname,
                        expires: lease.expires,
                    }),
            );
        }
        for engine in &self.v6 {
            let engine = locked(engine);
            out.extend(engine.bound().into_iter().map(|lease| Wire::Lease6 {
                ip: lease.ip,
                client: lease.client,
                iaid: lease.iaid,
                hostname: lease.hostname,
                expires: lease.expires,
                temporary: lease.temporary,
            }));
            out.extend(
                engine
                    .bound_prefixes()
                    .into_iter()
                    .map(|item| Wire::Prefix {
                        prefix: item.prefix,
                        client: item.client,
                        iaid: item.iaid,
                        expires: item.expires,
                    }),
            );
        }
        out
    }

    /// Take a change the partner made.
    fn apply(&self, wire: Wire, shared: &Shared) {
        let moment = now();
        match wire {
            Wire::Beat => {}
            Wire::Lease4 {
                ip,
                client,
                hostname,
                expires,
            } => {
                let lease = v4::Lease {
                    ip,
                    client,
                    hostname,
                    expires,
                    offered: false,
                };
                for engine in &self.v4 {
                    if locked(engine).adopt(lease.clone(), moment) {
                        shared.apply4(Change::Bind(lease), false);
                        return;
                    }
                }
            }
            Wire::End4 { ip } => {
                for engine in &self.v4 {
                    if locked(engine).forget(ip) {
                        shared.apply4(Change::End(ip), false);
                    }
                }
            }
            Wire::Lease6 {
                ip,
                client,
                iaid,
                hostname,
                expires,
                temporary,
            } => {
                let lease = v6::Lease6 {
                    ip,
                    client,
                    iaid,
                    hostname,
                    expires,
                    offered: false,
                    temporary,
                };
                for engine in &self.v6 {
                    if locked(engine).adopt(lease.clone(), moment) {
                        shared.apply6(Change6::Bind(lease), false);
                        return;
                    }
                }
            }
            Wire::End6 { ip } => {
                for engine in &self.v6 {
                    locked(engine).forget(ip);
                }
                shared.apply6(Change6::End(ip), false);
            }
            Wire::Prefix {
                prefix,
                client,
                iaid,
                expires,
            } => {
                let item = v6::Delegation6 {
                    prefix,
                    client,
                    iaid,
                    expires,
                    offered: false,
                };
                for engine in &self.v6 {
                    if locked(engine).adopt_prefix(item.clone(), moment) {
                        shared.apply6(Change6::BindPrefix(item), false);
                        return;
                    }
                }
            }
            Wire::EndPrefix { prefix } => {
                for engine in &self.v6 {
                    locked(engine).forget_prefix(prefix);
                }
                shared.apply6(Change6::EndPrefix(prefix), false);
            }
        }
    }
}

#[cfg(unix)]
fn interface_index(name: &str) -> io::Result<u32> {
    nix::net::if_::if_nametoindex(name)
        .map_err(|error| io::Error::other(format!("interface {name}: {error}")))
}

/// On Windows an interface is named by its index (see `netsh interface ipv6 show interfaces`).
#[cfg(not(unix))]
fn interface_index(name: &str) -> io::Result<u32> {
    name.parse().map_err(|_| {
        io::Error::other(format!(
            "interface {name}: on this system give the interface index, such as \"12\""
        ))
    })
}

/// A `DHCPv4` socket: broadcast-capable, shared with other servers' ports, and tied to one
/// network so a request on one is never answered from another.
///
/// Linux binds to the device and macOS to the interface index. Windows binds to the scope's own
/// address, which still receives the broadcasts of its network. Other systems cannot tell
/// networks apart this way, so they serve a single scope and drop requests that are plainly
/// from elsewhere.
fn socket4(listen: SocketAddr, scope: &DhcpScope, scopes: usize) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    socket.set_broadcast(true)?;
    #[allow(unused_mut)]
    let mut address = listen;
    if let Some(name) = scope.interface.as_deref() {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        socket.bind_device(Some(name.as_bytes()))?;
        #[cfg(target_os = "macos")]
        {
            let index = interface_index(name)?;
            socket.bind_device_by_index_v4(std::num::NonZeroU32::new(index))?;
        }
        #[cfg(windows)]
        {
            let _ = name;
            if listen.ip().is_unspecified() {
                address = SocketAddr::new(scope.server_address.into(), listen.port());
            }
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            windows
        )))]
        {
            let _ = name;
            if scopes > 1 {
                return Err(io::Error::other(
                    "this system serves one DHCPv4 scope; use Linux, macOS or Windows for several",
                ));
            }
        }
    }
    let _ = scopes;
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Systems that cannot bind to a device must drop requests that are plainly for another network.
fn plainly_elsewhere(scope: &DhcpScope, request: &dhcproto::v4::Message) -> bool {
    if cfg!(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        windows
    )) {
        return false;
    }
    let near = |ip: std::net::Ipv4Addr| ip.is_unspecified() || scope.subnet.contains(&ip);
    !(near(request.giaddr()) && near(request.ciaddr()))
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
        let moment = now();
        // The standby stays silent while the primary is alive.
        if shared
            .failover
            .as_ref()
            .is_some_and(|link| !link.active(moment))
        {
            continue;
        }
        let Ok(request) = dhcproto::v4::Message::decode(&mut Decoder::new(&buffer[..length]))
        else {
            continue;
        };
        let reply = {
            let mut engine = locked(&engine);
            if plainly_elsewhere(engine.scope(), &request) {
                continue;
            }
            engine.set_reserve(
                shared
                    .failover
                    .as_ref()
                    .and_then(|link| link.reserve(moment)),
            );
            engine.handle(&request, moment)
        };
        let Some(reply) = reply else {
            continue;
        };
        if let Some(change) = reply.change {
            shared.apply4(change, true);
        }
        let Some(target) = target4(reply.destination, source, &config) else {
            continue;
        };
        if let Ok(bytes) = reply.message.to_vec() {
            let _ = socket.send_to(&bytes, target).await;
        }
    }
}

/// One `DHCPv6` network and how to recognize its clients.
struct Scope6 {
    /// The interface index, for clients on the server's own link.
    index: Option<u32>,
    prefix: Ipv6Net,
    engine: Engine6,
}

fn scope_for(scopes: &[Scope6], scope_id: u32, link: Option<Ipv6Addr>) -> Option<&Scope6> {
    if let Some(link) = link {
        return scopes.iter().find(|scope| scope.prefix.contains(&link));
    }
    scopes
        .iter()
        .find(|scope| scope_id != 0 && scope.index == Some(scope_id))
        // A single scope also serves clients that arrive without a link (unicast, or testing).
        .or_else(|| (scopes.len() == 1 && scope_id == 0).then(|| &scopes[0]))
}

async fn serve6(socket: Arc<UdpSocket>, scopes: Vec<Scope6>, shared: Arc<Shared>) {
    let mut buffer = [0u8; 1500];
    loop {
        let Ok((length, source)) = socket.recv_from(&mut buffer).await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let moment = now();
        if shared
            .failover
            .as_ref()
            .is_some_and(|link| !link.active(moment))
        {
            continue;
        }
        let packet = &buffer[..length];
        // A relay agent forwards the client's message inside its own.
        let relayed = if relay::is_relay_forward(packet) {
            match relay::unwrap(packet) {
                Some(relayed) => Some(relayed),
                None => continue,
            }
        } else {
            None
        };
        let inner = relayed
            .as_ref()
            .map_or(packet, |relayed| &relayed.message[..]);
        let Ok(request) = dhcproto::v6::Message::decode(&mut Decoder::new(inner)) else {
            continue;
        };
        // The link a client is on is the interface its link-local address belongs to, or, behind
        // a relay, the link address the relay reports.
        let scope_id = match source {
            SocketAddr::V6(address) => address.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        let link = relayed.as_ref().map(relay::Relayed::link);
        let Some(scope) = scope_for(&scopes, scope_id, link.flatten()).or_else(|| {
            // A relay that reports no link, with a single scope to choose from.
            (relayed.is_some() && scopes.len() == 1).then(|| &scopes[0])
        }) else {
            continue;
        };
        let reply = {
            let mut engine = locked(&scope.engine);
            engine.set_reserve(
                shared
                    .failover
                    .as_ref()
                    .and_then(|link| link.reserve(moment)),
            );
            engine.handle(&request, moment)
        };
        let Some(reply) = reply else {
            continue;
        };
        for change in reply.changes {
            shared.apply6(change, true);
        }
        let Ok(bytes) = reply.message.to_vec() else {
            continue;
        };
        let bytes = match &relayed {
            Some(relayed) => relay::wrap(&relayed.layers, &bytes),
            None => bytes,
        };
        let _ = socket.send_to(&bytes, source).await;
    }
}

async fn expire(engines: Arc<Engines>, shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(EXPIRY_INTERVAL);
    loop {
        tick.tick().await;
        let moment = now();
        for engine in &engines.v4 {
            for ip in locked(engine).expire(moment) {
                shared.end(ip.into());
            }
        }
        for engine in &engines.v6 {
            let mut engine = locked(engine);
            for ip in engine.expire(moment) {
                shared.end(ip.into());
            }
            for prefix in engine.expire_prefixes(moment) {
                shared.end_prefix(prefix);
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
/// A socket cannot be bound (port 67 and 547 need privileges), an interface does not exist, the
/// lease file cannot be opened, or the failover secret cannot be used.
#[allow(clippy::too_many_lines)]
pub async fn start(config: &Dhcp, hosts: Arc<Hosts>) -> io::Result<Running> {
    let store = Store::open(config.lease_file.as_deref()).map_err(io::Error::other)?;
    let moment = now();
    let restored4 = store.load4(moment).map_err(io::Error::other)?;
    let restored6 = store.load6(moment).map_err(io::Error::other)?;
    let restored_prefixes = store.load_prefixes(moment).map_err(io::Error::other)?;
    let restored_keys = store.load_reconf_keys().map_err(io::Error::other)?;
    let duid = store.server_duid(new_duid).map_err(io::Error::other)?;
    let link = config.failover.as_ref().map(Failover::new);
    let shared = Arc::new(Shared {
        store,
        hosts,
        failover: link.clone(),
    });
    let domain = config.domain.clone().unwrap_or_default();
    let config = Arc::new(config.clone());
    let mut tasks = Vec::new();
    let mut engines4 = Vec::new();
    let mut engines6 = Vec::new();
    let mut scopes6 = Vec::new();
    let mut sockets4 = Vec::new();
    let mut bound4 = Vec::new();
    let mut bound6 = None;
    let mut socket6_shared = None;

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
        let socket = socket4(config.listen4, scope, config.scopes.len())?;
        bound4.push(socket.local_addr()?);
        sockets4.push((socket, engine.clone()));
        engines4.push(engine);
    }

    let mut indexes = Vec::new();
    for scope in &config.scopes6 {
        let index = match scope.interface.as_deref() {
            Some(name) => Some(interface_index(name).or_else(|error| {
                // Testing against a fixed address needs no real interface.
                if config.listen6.ip().is_unspecified() {
                    Err(error)
                } else {
                    Ok(0)
                }
            })?),
            None => None,
        };
        let mine: Vec<_> = restored6
            .iter()
            .filter(|lease| scope.prefix.contains(&lease.ip))
            .cloned()
            .collect();
        for lease in &mine {
            shared.publish(lease.hostname.as_deref(), lease.ip.into());
        }
        let mut engine = v6::Engine6::new(scope, duid.clone(), mine, moment);
        engine.restore_prefixes(restored_prefixes.clone(), moment);
        engine.restore_reconf_keys(restored_keys.clone());
        let engine = Arc::new(Mutex::new(engine));
        indexes.extend(index);
        scopes6.push(Scope6 {
            index,
            prefix: scope.prefix,
            engine: engine.clone(),
        });
        engines6.push(engine);
    }

    let engines = Arc::new(Engines {
        v4: engines4.clone(),
        v6: engines6.clone(),
    });
    // The failover link comes up first, so a secondary never answers before it has listened.
    if let (Some(settings), Some(link)) = (config.failover.as_ref(), link.clone()) {
        let (for_snapshot, for_apply, apply_shared) =
            (engines.clone(), engines.clone(), shared.clone());
        tasks.push(
            failover::start(
                settings,
                link,
                Arc::new(move || for_snapshot.snapshot()),
                Arc::new(move |wire| for_apply.apply(wire, &apply_shared)),
            )
            .await?,
        );
    }
    for (socket, engine) in sockets4 {
        tasks.push(tokio::spawn(serve4(
            socket,
            engine,
            shared.clone(),
            config.clone(),
        )));
    }
    if !scopes6.is_empty() {
        // Multicast is joined only when listening on every address; a fixed address is for
        // tests and relays.
        let join = config.listen6.ip().is_unspecified();
        let socket = Arc::new(socket6(config.listen6, &indexes, join)?);
        bound6 = Some(socket.local_addr()?);
        socket6_shared = Some(socket.clone());
        tasks.push(tokio::spawn(serve6(socket, scopes6, shared.clone())));
    }

    let handle = Handle {
        engines4,
        engines6,
        failover: link,
        role: config.failover.as_ref().map(|settings| settings.role),
        socket6: socket6_shared,
        client_port6: config.client_port6,
    };
    tasks.push(tokio::spawn(expire(engines, shared)));
    Ok(Running {
        handle,
        tasks,
        bound4,
        bound6,
    })
}

//! The daemon side: discovery runs, availability checks, and SNMP polling, as background tasks.
//!
//! Everything is bounded: probes in flight, probes per second, scope sizes, and rows read from a
//! device. Nothing outside the configured scopes is ever probed, and the first thing every task
//! does is look at what the administrator allowed.

use crate::{
    data::Target,
    health::{CheckResult, Health},
    model::{CheckMethod, Device, ScanSummary},
    neighbors,
    oui::{Mac, Oui},
    probe,
    scope::{Scopes, mac_from_client},
    snmp::{self, Client, Credentials, UsmUser, mib},
    store::{Merged, Netmon, Observation, Source, now},
};
use async_trait::async_trait;
use lumen_config::{Network, SnmpProfile, SnmpVersion};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::JoinHandle};

/// What the daemon knows that this module may use.
#[async_trait]
pub trait Environment: Send + Sync + 'static {
    /// Addresses handed out by the DHCP server right now.
    fn dhcp_hosts(&self) -> Vec<DhcpHost>;
    /// The name DNS gives an address, if any.
    async fn reverse(&self, ip: IpAddr) -> Option<String>;
}

#[derive(Clone, Debug)]
pub struct DhcpHost {
    pub ip: IpAddr,
    /// The client identifier as hex.
    pub client: String,
    pub hostname: Option<String>,
    /// A configured reservation, whether or not it currently has a live lease.
    pub reserved: bool,
}

/// How to reach a group of devices with SNMP. Secrets come from files and stay in memory.
struct Profile {
    credentials: Credentials,
    port: u16,
    wait: Duration,
    retries: u8,
}

/// Packets per second, enforced by spacing sends.
struct Limiter {
    next: Mutex<Instant>,
    gap: Duration,
}

impl Limiter {
    fn new(per_second: u32) -> Self {
        Self {
            next: Mutex::new(Instant::now()),
            gap: Duration::from_secs_f64(1.0 / f64::from(per_second.max(1))),
        }
    }
    async fn acquire(&self) {
        let slot = {
            let mut next = self
                .next
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let slot = (*next).max(Instant::now());
            *next = slot + self.gap;
            slot
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(slot)).await;
    }
}

/// The FRITZ!Box import: one signed-in client at a time, and what the last run did.
struct Fritz {
    client: tokio::sync::Mutex<crate::fritz::Client>,
    status: Mutex<crate::fritz::Status>,
}

struct Shared {
    fritz: Option<Fritz>,
    cfg: Network,
    scopes: Scopes,
    state: PathBuf,
    env: Arc<dyn Environment>,
    oui: Arc<Oui>,
    profiles: HashMap<String, Profile>,
    limiter: Limiter,
    icmp4: bool,
    icmp6: bool,
    scanning: AtomicBool,
    next_scan: Mutex<Option<i64>>,
    snmp_failures: Mutex<HashMap<i64, u32>>,
}

/// A started module. Dropping it stops every task.
pub struct Running {
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// What the console shows about the daemon side.
#[derive(Clone, Debug, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)] // A status report, one flag per fact.
pub struct EngineStatus {
    pub scanning: bool,
    pub next_scan: Option<i64>,
    pub icmp_v4: bool,
    pub icmp_v6: bool,
    pub scopes: Vec<ScopeStatus>,
    pub snmp_profiles: Vec<String>,
    pub scan_interval_secs: u32,
    pub monitor_enabled: bool,
    pub monitor_interval_secs: u32,
    pub failures_before_offline: u8,
    pub snmp_interval_secs: u32,
    /// The FRITZ!Box import, when it is configured.
    pub fritzbox: Option<crate::fritz::Status>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ScopeStatus {
    pub name: String,
    pub networks: Vec<String>,
    pub excluded: Vec<String>,
    pub interface: Option<String>,
    pub snmp_profile: Option<String>,
}

fn secret(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|_| format!("cannot open {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} must not be readable by group or others (use mode 0600)",
                path.display()
            ));
        }
    }
    let bytes = lumen_config::read_bounded(path, 1024)?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{} is not text", path.display()))?;
    let text = text.trim_end_matches(['\n', '\r']).to_owned();
    if text.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(text.into_bytes())
}

fn load_profile(profile: &SnmpProfile) -> Result<Profile, String> {
    let credentials = match profile.version {
        SnmpVersion::V2c => {
            let path = profile
                .community_file
                .as_ref()
                .ok_or("community_file missing")?;
            Credentials::V2c {
                community: secret(path)?,
            }
        }
        SnmpVersion::V3 => {
            let password = |path: &Option<PathBuf>| -> Result<Option<Vec<u8>>, String> {
                path.as_deref()
                    .map(|p| {
                        let pw = secret(p)?;
                        if pw.len() < 8 {
                            return Err(format!("{} must hold at least 8 characters", p.display()));
                        }
                        Ok(pw)
                    })
                    .transpose()
            };
            let auth = profile
                .auth_protocol
                .zip(password(&profile.auth_password_file)?);
            let privacy = profile
                .privacy_protocol
                .zip(password(&profile.privacy_password_file)?);
            Credentials::V3(UsmUser {
                name: profile.username.clone().ok_or("username missing")?,
                auth,
                privacy,
            })
        }
    };
    Ok(Profile {
        credentials,
        port: profile.port,
        wait: Duration::from_millis(u64::from(profile.timeout_ms)),
        retries: profile.retries,
    })
}

/// Start the module: read the SNMP secrets, make sure the database opens, and launch the tasks.
///
/// # Errors
/// A secret file is unreadable or too open, or the database cannot be opened.
pub fn start(cfg: &Network, state: &Path, env: Arc<dyn Environment>) -> Result<Running, String> {
    Netmon::open(state)?;
    let mut oui = Oui::new();
    if let Some(path) = &cfg.oui_file {
        let bytes = lumen_config::read_bounded(path, 16 << 20)?;
        oui.load(&String::from_utf8_lossy(&bytes));
    }
    let mut profiles = HashMap::new();
    for profile in &cfg.snmp_profiles {
        profiles.insert(
            profile.name.clone(),
            load_profile(profile).map_err(|e| format!("snmp profile {}: {e}", profile.name))?,
        );
    }
    let fritz = if cfg.fritzbox.enabled {
        let fb = &cfg.fritzbox;
        let password = secret(
            fb.password_file
                .as_deref()
                .ok_or("fritzbox password_file missing")?,
        )
        .map_err(|e| format!("fritzbox: {e}"))?;
        Some(Fritz {
            client: tokio::sync::Mutex::new(crate::fritz::Client::new(
                &fb.host,
                fb.port,
                &fb.username,
                password,
            )),
            status: Mutex::new(crate::fritz::Status {
                host: fb.host.clone(),
                interval_secs: fb.interval_secs,
                ..crate::fritz::Status::default()
            }),
        })
    } else {
        None
    };
    let shared = Arc::new(Shared {
        fritz,
        scopes: Scopes::from_config(cfg),
        limiter: Limiter::new(cfg.packets_per_second),
        icmp4: probe::icmp_available(false),
        icmp6: probe::icmp_available(true),
        cfg: cfg.clone(),
        state: state.to_path_buf(),
        env,
        oui: Arc::new(oui),
        profiles,
        scanning: AtomicBool::new(false),
        next_scan: Mutex::new(None),
        snmp_failures: Mutex::new(HashMap::new()),
    });
    let mut tasks = Vec::new();
    for task in [
        Task::Scheduler,
        Task::Monitor,
        Task::Snmp,
        Task::Upkeep,
        Task::Fritz,
    ] {
        if (task == Task::Monitor && !cfg.monitor.enabled)
            || (task == Task::Snmp && shared.profiles.is_empty())
            || (task == Task::Fritz && shared.fritz.is_none())
        {
            continue;
        }
        let shared = Arc::clone(&shared);
        tasks.push(tokio::spawn(async move {
            match task {
                Task::Scheduler => shared.scheduler().await,
                Task::Monitor => shared.monitor().await,
                Task::Snmp => shared.snmp_loop().await,
                Task::Upkeep => shared.upkeep().await,
                Task::Fritz => shared.fritz_loop().await,
            }
        }));
    }
    Ok(Running { shared, tasks })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Task {
    Scheduler,
    Monitor,
    Snmp,
    Upkeep,
    Fritz,
}

/// A cheap handle for asking about, and poking, the running module.
#[derive(Clone)]
pub struct Handle {
    shared: Arc<Shared>,
}

impl Running {
    #[must_use]
    pub fn handle(&self) -> Handle {
        Handle {
            shared: Arc::clone(&self.shared),
        }
    }

    #[must_use]
    pub fn status(&self) -> EngineStatus {
        self.handle().status()
    }

    /// Run discovery as soon as possible.
    ///
    /// # Errors
    /// The database failed.
    pub fn scan_now(&self) -> Result<(), String> {
        self.handle().scan_now()
    }
}

impl Handle {
    #[must_use]
    pub fn status(&self) -> EngineStatus {
        let s = &self.shared;
        EngineStatus {
            scanning: s.scanning.load(Ordering::Relaxed),
            next_scan: *s
                .next_scan
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            icmp_v4: s.icmp4,
            icmp_v6: s.icmp6,
            scopes: s
                .scopes
                .0
                .iter()
                .map(|sc| ScopeStatus {
                    name: sc.name.clone(),
                    networks: sc.networks.iter().map(ToString::to_string).collect(),
                    excluded: sc.exclude.iter().map(ToString::to_string).collect(),
                    interface: sc.interface.clone(),
                    snmp_profile: sc.profile.clone(),
                })
                .collect(),
            snmp_profiles: s.profiles.keys().cloned().collect(),
            scan_interval_secs: s.cfg.scan_interval_secs,
            monitor_enabled: s.cfg.monitor.enabled,
            monitor_interval_secs: s.cfg.monitor.interval_secs,
            failures_before_offline: s.cfg.monitor.failures_before_offline,
            snmp_interval_secs: s.cfg.snmp_interval_secs,
            fritzbox: s.fritz.as_ref().map(|f| {
                f.status
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }),
        }
    }

    /// Run discovery as soon as possible.
    ///
    /// # Errors
    /// The database failed.
    pub fn scan_now(&self) -> Result<(), String> {
        Netmon::open(&self.shared.state)?.request_scan()
    }
}

impl Shared {
    /// Run a database job off the async threads, on its own connection.
    async fn db<T: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Netmon) -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let path = self.state.clone();
        tokio::task::spawn_blocking(move || job(&mut Netmon::open(&path)?))
            .await
            .map_err(|e| e.to_string())?
    }

    // ---- discovery ----

    async fn scheduler(self: Arc<Self>) {
        let interval = u64::from(self.cfg.scan_interval_secs);
        let mut due = (interval > 0).then(|| now() + 10);
        loop {
            *self
                .next_scan
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = due;
            tokio::time::sleep(Duration::from_secs(2)).await;
            let asked = self.db(|nm| nm.take_scan_request()).await.unwrap_or(false);
            if asked || due.is_some_and(|d| now() >= d) {
                self.scan().await;
                due = (interval > 0).then(|| now() + i64::try_from(interval).unwrap_or(3600));
            }
        }
    }

    async fn scan(self: &Arc<Self>) {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return;
        }
        let id = self.db(Netmon::begin_scan).await.unwrap_or(0);
        let mut summary = ScanSummary {
            id,
            ..ScanSummary::default()
        };
        let state = match self.scan_inner(&mut summary).await {
            Ok(()) => "finished",
            Err(error) => {
                summary.detail = error;
                "failed"
            }
        };
        let _ = self.db(move |nm| nm.finish_scan(id, state, &summary)).await;
        self.scanning.store(false, Ordering::SeqCst);
    }

    #[allow(clippy::too_many_lines)]
    async fn scan_inner(self: &Arc<Self>, summary: &mut ScanSummary) -> Result<(), String> {
        let methods = &self.cfg.methods;
        let wait = Duration::from_millis(u64::from(self.cfg.timeout_ms));
        let mut notes: Vec<String> = Vec::new();
        let mut observations: Vec<Observation> = Vec::new();

        // 1. Echo requests: IPv4 hosts one by one, IPv6 links through the all-nodes group.
        if methods.icmp {
            if self.icmp4 {
                let targets = self.scopes.sweep_targets();
                summary.probed += targets.len() as u64;
                let semaphore = Arc::new(Semaphore::new(usize::from(self.cfg.concurrency)));
                let mut set = tokio::task::JoinSet::new();
                for ip in targets {
                    let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                        break;
                    };
                    let shared = Arc::clone(self);
                    set.spawn(async move {
                        shared.limiter.acquire().await;
                        let result = probe::ping(IpAddr::V4(ip), 1, wait).await;
                        drop(permit);
                        (ip, result)
                    });
                    while let Some(done) = set.try_join_next() {
                        collect_ping(done, &mut observations);
                    }
                }
                while let Some(done) = set.join_next().await {
                    collect_ping(done, &mut observations);
                }
            } else {
                notes.push(
                    "ICMP is not available to this account; the neighbor table and DHCP still work"
                        .into(),
                );
            }
            if self.icmp6 {
                for interface in self.scopes.v6_interfaces() {
                    #[cfg(unix)]
                    if let Ok(index) = nix::net::if_::if_nametoindex(interface.as_str()) {
                        self.limiter.acquire().await;
                        summary.probed += 1;
                        if let Ok(found) =
                            probe::ping_all_nodes(index, wait.max(Duration::from_millis(1200)))
                                .await
                        {
                            for addr in found {
                                let ip = IpAddr::V6(addr);
                                if self.scopes.contains(ip) {
                                    let mut o = Observation::new(Source::Icmp);
                                    o.ip = Some(ip);
                                    observations.push(o);
                                }
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    let _ = interface;
                }
            }
        }

        // 2. The neighbor tables, now fuller thanks to the sweep. Learn the hardware address of
        // everything in scope, and the other addresses (such as link-local IPv6) of the same
        // devices.
        if methods.neighbors {
            let table = tokio::task::spawn_blocking(neighbors::collect)
                .await
                .map_err(|e| e.to_string())?;
            let in_scope_macs: HashSet<Mac> = table
                .iter()
                .filter(|n| self.scopes.contains(n.ip))
                .map(|n| n.mac)
                .collect();
            for n in table {
                let wanted = self.scopes.contains(n.ip)
                    || (matches!(n.ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80)
                        && in_scope_macs.contains(&n.mac));
                if wanted {
                    let mut o = Observation::new(Source::Neighbor);
                    o.ip = Some(n.ip);
                    o.mac = Some(n.mac);
                    observations.push(o);
                }
            }
        }

        // 3. DHCP leases.
        if methods.dhcp {
            for lease in self.env.dhcp_hosts() {
                if self.scopes.contains(lease.ip) {
                    let mut o = Observation::new(Source::Dhcp);
                    o.ip = Some(lease.ip);
                    o.mac = mac_from_client(&lease.client);
                    o.dhcp_id = Some(lease.client);
                    o.hostname = lease.hostname;
                    observations.push(o);
                }
            }
        }

        // 4. Merge. Echo and neighbor sightings come first, so a device found by ping gets its
        // hardware address from the neighbor entry rather than becoming two devices.
        let oui = Arc::clone(&self.oui);
        let merged = self
            .db(move |nm| {
                let mut out = Vec::new();
                for o in &observations {
                    if let Some(m) = nm.observe(o, &oui)? {
                        out.push((o.source, m));
                    }
                }
                Ok(out)
            })
            .await?;
        let mut present: HashSet<i64> = HashSet::new();
        let mut alive_ips: Vec<IpAddr> = Vec::new();
        for (source, m) in &merged {
            if source.is_present() {
                present.insert(m.device_id);
            }
            summary.new_devices += u64::from(m.created);
        }
        // Gather what the later steps need from the store.
        let wanted = self
            .db(|nm| {
                Ok(nm
                    .devices(&crate::model::DeviceFilter {
                        include_gone: true,
                        ..Default::default()
                    })?
                    .into_iter()
                    .map(|d| (d.id, d.hostname.is_some(), d.addresses))
                    .collect::<Vec<_>>())
            })
            .await?;
        for (id, _, addresses) in &wanted {
            if present.contains(id) {
                alive_ips.extend(
                    addresses
                        .iter()
                        .filter_map(|a| a.ip.parse::<IpAddr>().ok())
                        .filter(|ip| self.scopes.contains(*ip)),
                );
            }
        }

        // 5. Names for what has none (reverse DNS, a few at a time).
        let mut named = Vec::new();
        if methods.dns {
            let nameless: Vec<IpAddr> = wanted
                .iter()
                .filter(|(id, has, _)| !*has && present.contains(id))
                .filter_map(|(_, _, addrs)| {
                    addrs.iter().find_map(|a| {
                        a.ip.parse::<IpAddr>()
                            .ok()
                            .filter(|ip| self.scopes.contains(*ip))
                    })
                })
                .take(512)
                .collect();
            let semaphore = Arc::new(Semaphore::new(16));
            let mut set = tokio::task::JoinSet::new();
            for ip in nameless {
                let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                    break;
                };
                let shared = Arc::clone(self);
                set.spawn(async move {
                    let name = tokio::time::timeout(Duration::from_secs(3), shared.env.reverse(ip))
                        .await
                        .ok()
                        .flatten();
                    drop(permit);
                    (ip, name)
                });
            }
            while let Some(Ok((ip, name))) = set.join_next().await {
                if let Some(name) = name {
                    let mut o = Observation::new(Source::Dns);
                    o.ip = Some(ip);
                    o.hostname = Some(name);
                    named.push(o);
                }
            }
        }

        // 6. SNMP: ask devices in scopes that have a profile what they are.
        let mut identified = Vec::new();
        if methods.snmp {
            let semaphore = Arc::new(Semaphore::new(16));
            let mut set = tokio::task::JoinSet::new();
            for ip in alive_ips.iter().copied().collect::<HashSet<_>>() {
                let Some(profile) = self.scopes.find(ip).and_then(|s| s.profile.clone()) else {
                    continue;
                };
                let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                    break;
                };
                let shared = Arc::clone(self);
                set.spawn(async move {
                    let sys = shared.identify(ip, &profile).await;
                    drop(permit);
                    (ip, sys)
                });
            }
            while let Some(Ok((ip, sys))) = set.join_next().await {
                if let Some(sys) = sys {
                    let mut o = Observation::new(Source::Snmp);
                    o.ip = Some(ip);
                    o.hostname.clone_from(&sys.name);
                    o.sys = Some(sys);
                    identified.push(o);
                }
            }
        }
        let oui = Arc::clone(&self.oui);
        let extra: Vec<Observation> = named.into_iter().chain(identified).collect();
        let merged_extra = self
            .db(move |nm| {
                let mut out = Vec::new();
                for o in &extra {
                    if let Some(m) = nm.observe(o, &oui)? {
                        out.push((o.source, m));
                    }
                }
                Ok(out)
            })
            .await?;
        for (source, m) in &merged_extra {
            if source.is_present() {
                present.insert(m.device_id);
            }
            summary.new_devices += u64::from(m.created);
        }

        // 6b. What the FRITZ!Box lists (when configured). A failure is a note, not a failed scan.
        if self.fritz.is_some() {
            match self.fritz_import().await {
                Ok(merged) => {
                    for (source, m) in &merged {
                        if source.is_present() {
                            present.insert(m.device_id);
                        }
                        summary.new_devices += u64::from(m.created);
                    }
                }
                Err(error) => notes.push(format!("FRITZ!Box: {error}")),
            }
        }

        // 7. Devices in these networks that were not seen this time.
        summary.seen = present.len() as u64;
        let nets = self.scopes.networks();
        let gone_after = self.cfg.gone_after_scans;
        let gone = self
            .db(move |nm| nm.finish_sweep(&present, &nets, gone_after))
            .await?;
        summary.gone_devices = gone.len() as u64;
        summary.detail = notes.join("; ");
        Ok(())
    }

    // ---- FRITZ!Box ----

    async fn fritz_loop(self: Arc<Self>) {
        let interval = Duration::from_secs(u64::from(self.cfg.fritzbox.interval_secs));
        tokio::time::sleep(Duration::from_secs(15)).await;
        loop {
            // Errors are kept in the status; the next round simply tries again.
            let _ = self.fritz_import().await;
            tokio::time::sleep(interval).await;
        }
    }

    /// Read the box's device list and merge it into the inventory. Only devices with an address
    /// inside a scope are kept, so the box cannot widen what Lumen learns.
    async fn fritz_import(self: &Arc<Self>) -> Result<Vec<(Source, Merged)>, String> {
        let fritz = self.fritz.as_ref().ok_or("the FRITZ!Box import is off")?;
        let result = self.fritz_fetch(fritz).await;
        let mut status = fritz
            .status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match result {
            Ok((info, listed, merged)) => {
                if let Some(info) = info {
                    status.model = Some(info.model).filter(|m| !m.is_empty());
                    status.firmware = Some(info.firmware).filter(|m| !m.is_empty());
                    status.uptime_secs = Some(info.uptime_secs);
                }
                status.last_import = Some(now());
                status.hosts = listed;
                status.imported = merged.len();
                status.error = None;
                Ok(merged)
            }
            Err(error) => {
                status.error = Some(error.clone());
                Err(error)
            }
        }
    }

    async fn fritz_fetch(
        self: &Arc<Self>,
        fritz: &Fritz,
    ) -> Result<(Option<crate::fritz::BoxInfo>, usize, Vec<(Source, Merged)>), String> {
        let (info, hosts) = {
            let mut client = fritz.client.lock().await;
            // The model is nice to have; the host list is the point.
            let info = client.info().await.ok();
            (info, client.hosts().await?)
        };
        let listed = hosts.len();
        let observations: Vec<Observation> = hosts
            .into_iter()
            .filter_map(|host| {
                let ip = host.ip.filter(|ip| self.scopes.contains(*ip))?;
                let mut o = Observation::new(if host.active {
                    Source::Router
                } else {
                    Source::RouterIdle
                });
                o.ip = Some(ip);
                o.mac = host.mac;
                o.label = Some(host.name).filter(|n| !n.is_empty());
                Some(o)
            })
            .collect();
        let oui = Arc::clone(&self.oui);
        let merged = self
            .db(move |nm| {
                let mut out = Vec::new();
                for o in &observations {
                    if let Some(m) = nm.observe(o, &oui)? {
                        out.push((o.source, m));
                    }
                }
                Ok(out)
            })
            .await?;
        Ok((info, listed, merged))
    }

    // ---- SNMP ----

    fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    async fn client(&self, ip: IpAddr, profile: &str) -> Result<Client, snmp::SnmpError> {
        let p = self
            .profile(profile)
            .ok_or_else(|| snmp::SnmpError::Io("unknown SNMP profile".into()))?;
        Client::connect(
            SocketAddr::new(ip, p.port),
            p.credentials.clone(),
            p.wait,
            p.retries,
        )
        .await
    }

    async fn identify(&self, ip: IpAddr, profile: &str) -> Option<crate::model::SysInfo> {
        let mut client = self.client(ip, profile).await.ok()?;
        mib::system(&mut client, now()).await.ok()
    }

    /// The profile for a device: its own, or its scope's.
    fn profile_of(&self, device: &Device) -> Option<String> {
        device
            .snmp_profile
            .clone()
            .filter(|p| self.profiles.contains_key(p))
            .or_else(|| {
                device
                    .addresses
                    .iter()
                    .filter_map(|a| a.ip.parse::<IpAddr>().ok())
                    .find_map(|ip| self.scopes.find(ip).and_then(|s| s.profile.clone()))
            })
    }

    async fn snmp_loop(self: Arc<Self>) {
        let interval = Duration::from_secs(u64::from(self.cfg.snmp_interval_secs));
        let mut last: HashMap<i64, Instant> = HashMap::new();
        let semaphore = Arc::new(Semaphore::new(8));
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let Ok(devices) = self
                .db(|nm| nm.devices(&crate::model::DeviceFilter::default()))
                .await
            else {
                continue;
            };
            for device in devices {
                if last
                    .get(&device.id)
                    .is_some_and(|at| at.elapsed() < interval)
                {
                    continue;
                }
                let Some(profile) = self.profile_of(&device) else {
                    continue;
                };
                if device.addresses.is_empty() {
                    continue;
                }
                let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                    return;
                };
                last.insert(device.id, Instant::now());
                let shared = Arc::clone(&self);
                tokio::spawn(async move {
                    shared.poll(&device, &profile).await;
                    drop(permit);
                });
            }
        }
    }

    /// One poll of one device: facts, resources, interfaces, neighbors and learned addresses.
    #[allow(clippy::too_many_lines)]
    async fn poll(self: &Arc<Self>, device: &Device, profile: &str) {
        let id = device.id;
        let addresses: Vec<IpAddr> = device
            .addresses
            .iter()
            .filter_map(|a| a.ip.parse().ok())
            .collect();
        let mut client = None;
        for ip in &addresses {
            if let Ok(mut c) = self.client(*ip, profile).await
                && mib::system(&mut c, now()).await.is_ok()
            {
                client = Some((*ip, c));
                break;
            }
        }
        let Some((ip, mut client)) = client else {
            let failures = {
                let mut map = self
                    .snmp_failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let n = map.entry(id).or_insert(0);
                *n += 1;
                *n
            };
            if failures == 3 {
                let name = device.name.clone();
                let _ = self
                    .db(move |nm| {
                        nm.log_event(
                            Some(id),
                            "snmp-down",
                            &format!("{name} stopped answering SNMP"),
                        )
                    })
                    .await;
            }
            return;
        };
        let was_down = self
            .snmp_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id)
            .is_some_and(|n| n >= 3);
        if was_down {
            let name = device.name.clone();
            let _ = self
                .db(move |nm| {
                    nm.log_event(Some(id), "snmp-up", &format!("{name} answers SNMP again"))
                })
                .await;
        }
        let Ok(mut sys) = mib::system(&mut client, now()).await else {
            return;
        };
        mib::resources(&mut client, &mut sys).await;
        let interfaces = mib::interfaces(&mut client).await.unwrap_or_default();
        let lldp = mib::lldp(&mut client).await.unwrap_or_default();
        let fdb = mib::forwarding_table(&mut client).await.unwrap_or_default();
        let oui = Arc::clone(&self.oui);
        let scopes = self.scopes.clone();
        let names: HashMap<i64, String> = interfaces
            .iter()
            .map(|i| (i.index, i.name.clone()))
            .collect();
        let _ = self
            .db(move |nm| {
                let mut seen = Observation::new(Source::Snmp);
                seen.ip = Some(ip);
                seen.hostname.clone_from(&sys.name);
                seen.sys = Some(sys);
                nm.observe(&seen, &oui)?;
                nm.record_interfaces(id, &interfaces)?;
                // Neighbors it reports: known devices are linked, unknown ones are added.
                let mut confirmed = Vec::new();
                let mut linked_ports = HashSet::new();
                for n in &lldp {
                    let mut o = Observation::new(Source::Lldp);
                    o.ip = n.address.filter(|a| scopes.contains(*a));
                    o.mac = n.chassis_mac;
                    o.hostname.clone_from(&n.sys_name);
                    let Some(merged) = nm.observe(&o, &oui)? else {
                        continue;
                    };
                    confirmed.push((
                        n.local_port.clone(),
                        merged.device_id,
                        n.remote_port.clone(),
                        None,
                    ));
                    linked_ports.insert(n.local_port.clone());
                }
                nm.replace_reported_links(id, "lldp", &confirmed)?;
                // A port that has learned exactly one known hardware address is probably wired to
                // that device. It is an inference, and shown as one.
                let mut by_port: HashMap<i64, Vec<crate::oui::Mac>> = HashMap::new();
                for entry in &fdb {
                    by_port.entry(entry.if_index).or_default().push(entry.mac);
                }
                let mut inferred = Vec::new();
                for (if_index, macs) in by_port {
                    let port = names
                        .get(&if_index)
                        .cloned()
                        .unwrap_or_else(|| format!("port {if_index}"));
                    if macs.len() != 1 || linked_ports.contains(&port) {
                        continue;
                    }
                    if let Some(other) = nm.find_device(None, Some(&macs[0]))?
                        && other != id
                    {
                        inferred.push((port, other, String::new(), None));
                    }
                }
                nm.replace_reported_links(id, "inferred", &inferred)?;
                Ok(())
            })
            .await;
    }

    // ---- availability ----

    async fn monitor(self: Arc<Self>) {
        let default_interval = i64::from(self.cfg.monitor.interval_secs);
        let semaphore = Arc::new(Semaphore::new(usize::from(self.cfg.concurrency)));
        let mut targets: Vec<Target> = Vec::new();
        let mut refreshed = 0i64;
        // Edits show up quickly on a small network, and a big one is not reread every few seconds.
        let mut refresh_every = 5i64;
        let mut healths: HashMap<i64, Health> = HashMap::new();
        let mut last_check: HashMap<i64, i64> = HashMap::new();
        let mut running: HashSet<i64> = HashSet::new();
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<(i64, Health)>();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            while let Ok((id, health)) = done_rx.try_recv() {
                running.remove(&id);
                healths.insert(id, health);
            }
            let t = now();
            if t - refreshed >= refresh_every
                && let Ok(list) = self.db(|nm| nm.targets()).await
            {
                for target in &list {
                    let id = target.device.id;
                    let every = target
                        .device
                        .monitoring
                        .interval_secs
                        .map_or(default_interval, i64::from)
                        .max(1);
                    // Keep what is known; otherwise spread first checks over one interval so
                    // a restart is not a burst of probes.
                    last_check
                        .entry(id)
                        .or_insert_with(|| match target.last_check {
                            Some(ts) if t - ts < every => ts,
                            _ => t - every + 1 + id % every,
                        });
                    healths.entry(id).or_insert_with(|| target.health.clone());
                }
                refresh_every = if list.len() > 1000 { 30 } else { 5 };
                targets = list;
                refreshed = t;
            }
            for target in &targets {
                let device = &target.device;
                let id = device.id;
                let every = device
                    .monitoring
                    .interval_secs
                    .map_or(default_interval, i64::from);
                if running.contains(&id) || t - last_check.get(&id).copied().unwrap_or(t) < every {
                    continue;
                }
                let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                    break;
                };
                running.insert(id);
                last_check.insert(id, t);
                let shared = Arc::clone(&self);
                let device = device.clone();
                let mut health = healths
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| Health::new(device.status, 0));
                let tx = done_tx.clone();
                tokio::spawn(async move {
                    shared.limiter.acquire().await;
                    let result = shared.check(&device).await;
                    if let Some(result) = result {
                        let change = health.apply(result, &shared.cfg.monitor);
                        let snapshot = health.clone();
                        let _ = shared
                            .db(move |nm| nm.record_check(device.id, result, &snapshot, change))
                            .await;
                    }
                    drop(permit);
                    let _ = tx.send((id, health));
                });
            }
        }
    }

    /// One availability check. `None` when this machine cannot run the check at all (for
    /// example no ICMP), which must never be mistaken for the device being down.
    async fn check(&self, device: &Device) -> Option<CheckResult> {
        let wait = Duration::from_millis(u64::from(self.cfg.timeout_ms));
        let probes = self.cfg.monitor.probes_per_check;
        let addresses: Vec<IpAddr> = device
            .addresses
            .iter()
            .filter_map(|a| a.ip.parse().ok())
            .collect();
        let mut best: Option<CheckResult> = None;
        for ip in addresses {
            let result = match device.monitoring.method {
                CheckMethod::Icmp => {
                    if !(if ip.is_ipv4() { self.icmp4 } else { self.icmp6 }) {
                        continue;
                    }
                    // A send failure (no route, say) is an unanswered check, not a missing one.
                    Some(probe::ping(ip, probes, wait).await.unwrap_or(CheckResult {
                        sent: probes.max(1),
                        received: 0,
                        rtt_ms: None,
                    }))
                }
                CheckMethod::Tcp => {
                    let port = device.monitoring.tcp_port?;
                    Some(probe::tcp_check(SocketAddr::new(ip, port), probes.min(3), wait).await)
                }
                CheckMethod::Snmp => {
                    let profile = self.profile_of(device)?;
                    let started = Instant::now();
                    let answered = match self.client(ip, &profile).await {
                        Ok(mut c) => c
                            .get(&[snmp::ber::Oid::parse("1.3.6.1.2.1.1.3.0")?])
                            .await
                            .is_ok(),
                        Err(_) => false,
                    };
                    Some(CheckResult {
                        sent: 1,
                        received: u8::from(answered),
                        rtt_ms: answered.then(|| started.elapsed().as_secs_f64() * 1000.0),
                    })
                }
            };
            let Some(result) = result else { continue };
            let better = best.is_none_or(|b| result.received > b.received);
            if better {
                best = Some(result);
            }
            if result.received == result.sent && result.sent > 0 {
                break;
            }
        }
        best
    }

    async fn upkeep(self: Arc<Self>) {
        let days = self.cfg.retention_days;
        loop {
            let _ = self.db(move |nm| nm.prune(days)).await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}

#[allow(clippy::needless_pass_by_value)] // Taken straight from the join set.
fn collect_ping(
    done: Result<(std::net::Ipv4Addr, std::io::Result<CheckResult>), tokio::task::JoinError>,
    out: &mut Vec<Observation>,
) {
    if let Ok((ip, Ok(result))) = done
        && result.ok()
    {
        let mut o = Observation::new(Source::Icmp);
        o.ip = Some(IpAddr::V4(ip));
        out.push(o);
    }
}

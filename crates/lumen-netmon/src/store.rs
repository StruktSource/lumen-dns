//! The `SQLite` side of the network module: the device inventory, and how discoveries merge into it.
//!
//! The tables live in the web console's state database next to IPAM's. Everything an
//! administrator typed is kept: discovery only fills in what they left alone.

use crate::{
    model::{
        Counts, Device, DeviceAddress, DeviceFilter, DeviceInput, DeviceMac, Event, ICONS, KINDS,
        MAX_DEVICES, MAX_ROOMS, Monitoring, Room, RoomInput, Status, SysInfo,
    },
    oui::{Mac, Oui, format_mac, is_usable, parse_mac},
};
use ipnet::IpNet;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS nm_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, hostname TEXT, kind TEXT NOT NULL DEFAULT 'unknown', os TEXT, vendor TEXT,
    icon TEXT, description TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
    location_id INTEGER, room_id INTEGER REFERENCES nm_rooms(id) ON DELETE SET NULL,
    manual INTEGER NOT NULL DEFAULT 0, locked TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'unknown', first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    last_ok INTEGER, missed INTEGER NOT NULL DEFAULT 0, gone INTEGER NOT NULL DEFAULT 0,
    fail_streak INTEGER NOT NULL DEFAULT 0,
    mon_enabled INTEGER NOT NULL DEFAULT 1, mon_method TEXT NOT NULL DEFAULT 'icmp',
    mon_port INTEGER, mon_interval INTEGER, snmp_profile TEXT);
CREATE TABLE IF NOT EXISTS nm_addrs (
    ip TEXT PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE,
    source TEXT NOT NULL, last_seen INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS nm_addrs_device ON nm_addrs(device_id);
CREATE TABLE IF NOT EXISTS nm_macs (
    mac TEXT PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE,
    source TEXT NOT NULL, last_seen INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS nm_macs_device ON nm_macs(device_id);
CREATE TABLE IF NOT EXISTS nm_dhcp_ids (
    client TEXT PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE,
    source TEXT NOT NULL, last_seen INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS nm_dhcp_device ON nm_dhcp_ids(device_id);
CREATE TABLE IF NOT EXISTS nm_rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES nm_rooms(id) ON DELETE SET NULL,
    name TEXT NOT NULL COLLATE NOCASE UNIQUE,
    description TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS nm_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    a_device INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE, a_port TEXT NOT NULL DEFAULT '',
    b_device INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE, b_port TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL, confirmed INTEGER NOT NULL, speed_mbps INTEGER, updated INTEGER NOT NULL,
    UNIQUE (a_device, a_port, b_device, b_port));
CREATE TABLE IF NOT EXISTS nm_checks (
    device_id INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE, ts INTEGER NOT NULL,
    ok INTEGER NOT NULL, rtt_us INTEGER, loss REAL NOT NULL);
CREATE INDEX IF NOT EXISTS nm_checks_device ON nm_checks(device_id, ts);
CREATE TABLE IF NOT EXISTS nm_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
    device_id INTEGER REFERENCES nm_devices(id) ON DELETE SET NULL, kind TEXT NOT NULL, detail TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS nm_events_ts ON nm_events(ts);
CREATE TABLE IF NOT EXISTS nm_sys (
    device_id INTEGER PRIMARY KEY REFERENCES nm_devices(id) ON DELETE CASCADE,
    name TEXT, descr TEXT, object_id TEXT, contact TEXT, location TEXT, uptime INTEGER, services INTEGER,
    cpu REAL, mem REAL, temp REAL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nm_ifaces (
    device_id INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE, idx INTEGER NOT NULL,
    name TEXT NOT NULL, alias TEXT NOT NULL DEFAULT '', speed INTEGER, admin_up INTEGER NOT NULL, oper_up INTEGER NOT NULL,
    in_octets INTEGER, out_octets INTEGER, in_bps REAL, out_bps REAL, util REAL,
    in_err INTEGER NOT NULL DEFAULT 0, out_err INTEGER NOT NULL DEFAULT 0,
    in_disc INTEGER NOT NULL DEFAULT 0, out_disc INTEGER NOT NULL DEFAULT 0, ts INTEGER NOT NULL,
    PRIMARY KEY (device_id, idx));
CREATE TABLE IF NOT EXISTS nm_if_hist (
    device_id INTEGER NOT NULL REFERENCES nm_devices(id) ON DELETE CASCADE, idx INTEGER NOT NULL,
    ts INTEGER NOT NULL, in_bps REAL NOT NULL, out_bps REAL NOT NULL);
CREATE INDEX IF NOT EXISTS nm_if_hist_key ON nm_if_hist(device_id, idx, ts);
CREATE TABLE IF NOT EXISTS nm_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT, started INTEGER NOT NULL, finished INTEGER,
    state TEXT NOT NULL, probed INTEGER NOT NULL DEFAULT 0, seen INTEGER NOT NULL DEFAULT 0,
    new_devices INTEGER NOT NULL DEFAULT 0, gone_devices INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS nm_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// Where a fact came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// The ARP or NDP table: the device is on the link, though not necessarily awake.
    Neighbor,
    /// It answered an echo request.
    Icmp,
    /// It accepted a TCP connection.
    Tcp,
    /// A DHCP lease names it.
    Dhcp,
    /// A DNS lookup named it.
    Dns,
    /// It answered SNMP.
    Snmp,
    /// A switch or router reported it as a neighbor (LLDP): it is on the network.
    Lldp,
    /// A router (a FRITZ!Box) lists it, and says it is connected right now.
    Router,
    /// A router lists it, but not as connected.
    RouterIdle,
    /// An administrator typed it.
    Manual,
}

impl Source {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Neighbor => "neighbor",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Dhcp => "dhcp",
            Self::Dns => "dns",
            Self::Snmp => "snmp",
            Self::Lldp => "lldp",
            Self::Router | Self::RouterIdle => "router",
            Self::Manual => "manual",
        }
    }
    /// It answered us just now: the device is awake.
    #[must_use]
    pub fn is_alive(self) -> bool {
        matches!(self, Self::Icmp | Self::Tcp | Self::Snmp)
    }
    /// It shows the device is on the network right now, awake or not.
    #[must_use]
    pub fn is_present(self) -> bool {
        self.is_alive() || matches!(self, Self::Neighbor | Self::Lldp | Self::Router)
    }
}

/// One thing a discovery method found.
#[derive(Clone, Debug)]
pub struct Observation {
    pub ip: Option<IpAddr>,
    pub mac: Option<Mac>,
    pub dhcp_id: Option<String>,
    pub hostname: Option<String>,
    /// A name a person chose for the device elsewhere (the FRITZ!Box device list). It need not be
    /// a host name. It names the device unless an administrator did.
    pub label: Option<String>,
    pub source: Source,
    pub sys: Option<SysInfo>,
}

impl Observation {
    #[must_use]
    pub fn new(source: Source) -> Self {
        Self {
            ip: None,
            mac: None,
            dhcp_id: None,
            hostname: None,
            label: None,
            source,
            sys: None,
        }
    }
}

/// What merging an observation did.
#[derive(Clone, Debug, Default)]
pub struct Merged {
    pub device_id: i64,
    pub created: bool,
    /// The device was marked gone and is back.
    pub returned: bool,
    /// Devices that turned out to be this one and were folded into it.
    pub absorbed: Vec<i64>,
}

pub struct Netmon {
    pub(crate) conn: Connection,
}

#[allow(clippy::needless_pass_by_value)] // Used as `map_err(sql)`.
pub(crate) fn sql(error: rusqlite::Error) -> String {
    format!("the network database failed: {error}")
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn label(field: &str, value: &str, max: usize, required: bool) -> Result<String, String> {
    let value = value.trim();
    if required && value.is_empty() {
        return Err(format!("{field} is required"));
    }
    if value.chars().count() > max || value.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be at most {max} characters, without control characters"
        ));
    }
    Ok(value.to_owned())
}

/// A host name: DNS labels of letters, digits and hyphens (dots allowed), lowercase.
pub(crate) fn clean_hostname(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !value.is_empty()
        && value.len() <= 200
        && value.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !l.starts_with('-')
                && !l.ends_with('-')
        });
    ok.then_some(value)
}

/// The name shown for a host name: its first label (`printer` for `printer.home.lan`).
fn short_name(hostname: &str) -> String {
    hostname.split('.').next().unwrap_or(hostname).to_owned()
}

/// A readable name for a device that announced none: the maker's short name and the last two
/// bytes of its hardware address (`Apple 3fa1`), so two devices of one maker stay apart.
fn generated_name(vendor: &str, mac: &Mac) -> Option<String> {
    let word = vendor
        .split(|c: char| c.is_whitespace() || c == ',')
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .find(|w| !w.is_empty())?;
    let word: String = word.chars().take(20).collect();
    Some(format!("{word} {:02x}{:02x}", mac[4], mac[5]))
}

/// The name is only a stand-in Lumen made up (an address or a maker plus hardware tail), so a
/// better one may replace it. A name an administrator typed is never a placeholder.
fn is_placeholder(device: &Device) -> bool {
    device.addresses.iter().any(|a| a.ip == device.name)
        || device.macs.iter().any(|m| {
            m.mac == device.name
                || parse_mac(&m.mac)
                    .zip(m.vendor.as_deref().or(device.vendor.as_deref()))
                    .and_then(|(mac, vendor)| generated_name(vendor, &mac))
                    .is_some_and(|generated| generated == device.name)
        })
}

/// Guess what a device is from what is known about it. Only a guess: it is never applied over
/// what an administrator chose.
#[must_use]
pub fn guess_kind(
    vendor: Option<&str>,
    hostname: Option<&str>,
    descr: Option<&str>,
    services: Option<u32>,
) -> &'static str {
    let text = format!(
        "{} {} {}",
        vendor.unwrap_or(""),
        hostname.unwrap_or(""),
        descr.unwrap_or("")
    )
    .to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    if has(&[
        "printer",
        "laserjet",
        "officejet",
        "brother ",
        "epson",
        "canon ",
        "xerox",
        "lexmark",
    ]) || hostname.is_some_and(|h| h.starts_with("print"))
    {
        return "printer";
    }
    if has(&[
        "camera",
        "cam-",
        "hikvision",
        "dahua",
        "axis comm",
        "reolink",
        "ipcam",
    ]) {
        return "camera";
    }
    if has(&["access point", "wireless", "-ap", "ap-", "unifi ap", "uap"]) {
        return "access-point";
    }
    if has(&["synology", "qnap", "nas"]) {
        return "nas";
    }
    if has(&[
        "firewall",
        "pfsense",
        "opnsense",
        "fortinet",
        "fortigate",
        "sophos",
    ]) {
        return "firewall";
    }
    if has(&["switch", "catalyst", "procurve", "aruba 2", "-sw", "sw-"]) {
        return "switch";
    }
    if has(&[
        "router",
        "routeros",
        "mikrotik",
        "fritz!box",
        "fritzbox",
        "avm ",
        "edgerouter",
        "gateway",
    ]) {
        return "router";
    }
    if has(&[
        "iphone",
        "android",
        "pixel",
        "galaxy",
        "huawei device",
        "oneplus",
        "xiaomi",
    ]) {
        return "phone";
    }
    if has(&["ipad", "tablet"]) {
        return "tablet";
    }
    if has(&["macbook", "laptop", "thinkpad"]) {
        return "laptop";
    }
    if has(&[
        "samsung electronics",
        "lg electronics",
        "roku",
        "sonos",
        "chromecast",
        "apple tv",
        "tv",
    ]) && has(&["tv", "roku", "chromecast", "sonos"])
    {
        return "tv";
    }
    if has(&[
        "raspberry",
        "espressif",
        "tuya",
        "shelly",
        "philips lighting",
        "signify",
        "ring ",
        "nest ",
    ]) {
        return "iot";
    }
    if has(&[
        "vmware",
        "proxmox",
        "server",
        "srv",
        "xen",
        "qemu",
        "hyper-v",
        "microsoft corporation",
    ]) && !has(&["workstation"])
    {
        return "server";
    }
    // sysServices (RFC 3418): layer 2 (bit 1) and layer 3 (bit 3) mean a switch or a router.
    if let Some(services) = services {
        let l2 = services & 0b10 != 0;
        let l3 = services & 0b100 != 0;
        if l3 {
            return "router";
        }
        if l2 {
            return "switch";
        }
    }
    "unknown"
}

impl Netmon {
    /// Open (or create) the tables inside `path`, which is the console's state file.
    ///
    /// # Errors
    /// The file cannot be opened or its tables created.
    pub fn open(path: &Path) -> Result<Self, String> {
        Self::init(Connection::open(path).map_err(sql)?)
    }

    /// A database in memory, for tests.
    ///
    /// # Errors
    /// Never in practice.
    pub fn open_memory() -> Result<Self, String> {
        Self::init(Connection::open_in_memory().map_err(sql)?)
    }

    fn init(conn: Connection) -> Result<Self, String> {
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(sql)?;
        conn.pragma_update(None, "foreign_keys", true)
            .map_err(sql)?;
        conn.execute_batch(SCHEMA).map_err(sql)?;
        let columns = conn
            .prepare("PRAGMA table_info(nm_devices)")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(sql)?;
        if !columns.iter().any(|column| column == "room_id") {
            conn.execute(
                "ALTER TABLE nm_devices ADD COLUMN room_id INTEGER REFERENCES nm_rooms(id) ON DELETE SET NULL",
                [],
            )
            .map_err(sql)?;
        }
        Ok(Self { conn })
    }

    pub(crate) fn write(&mut self) -> Result<Transaction<'_>, String> {
        self.conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)
    }

    // ---- reading devices ----

    /// The name of every known address, so another part of Lumen can show a device instead of
    /// its IP. Devices that are marked gone still answer, since old lookups mention them.
    ///
    /// # Errors
    /// The database failed.
    pub fn names_by_ip(&self) -> Result<std::collections::HashMap<String, String>, String> {
        let mut stmt = self
            .conn
            .prepare("SELECT a.ip, d.name FROM nm_addrs a JOIN nm_devices d ON d.id = a.device_id")
            .map_err(sql)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(sql)?;
        rows.collect::<Result<_, _>>().map_err(sql)
    }

    /// All devices matching the filter, newest activity first.
    ///
    /// # Errors
    /// The database failed.
    pub fn devices(&self, filter: &DeviceFilter) -> Result<Vec<Device>, String> {
        let mut devices = load_devices(&self.conn, None)?;
        let query = filter.query.trim().to_ascii_lowercase();
        devices.retain(|d| {
            (filter.include_gone || !d.gone)
                && filter.kind.as_deref().is_none_or(|k| d.kind == k)
                && filter
                    .status
                    .as_deref()
                    .is_none_or(|s| d.status.as_str() == s)
                && filter.location_id.is_none_or(|l| d.location_id == Some(l))
                && (query.is_empty() || matches_query(d, &query))
        });
        Ok(devices)
    }

    /// # Errors
    /// The database failed.
    pub fn device(&self, id: i64) -> Result<Option<Device>, String> {
        Ok(load_devices(&self.conn, Some(id))?.into_iter().next())
    }

    /// # Errors
    /// The database failed.
    pub fn counts(&self) -> Result<Counts, String> {
        let mut counts = Counts::default();
        for device in load_devices(&self.conn, None)? {
            if device.gone {
                counts.gone += 1;
                continue;
            }
            counts.total += 1;
            match device.status {
                Status::Online => counts.online += 1,
                Status::Offline => counts.offline += 1,
                Status::Degraded => counts.degraded += 1,
                Status::Unknown => counts.unknown += 1,
            }
            *counts.by_kind.entry(device.kind).or_default() += 1;
        }
        Ok(counts)
    }

    /// All rooms, ordered by name.
    ///
    /// # Errors
    /// The state database could not be read.
    pub fn rooms(&self) -> Result<Vec<Room>, String> {
        let mut statement = self
            .conn
            .prepare("SELECT id, parent_id, name, description FROM nm_rooms ORDER BY name, id")
            .map_err(sql)?;
        statement
            .query_map([], |row| {
                Ok(Room {
                    id: row.get(0)?,
                    parent_id: row.get(1)?,
                    name: row.get(2)?,
                    description: row.get(3)?,
                })
            })
            .map_err(sql)?
            .collect::<Result<_, _>>()
            .map_err(sql)
    }

    /// Add a room or area.
    ///
    /// # Errors
    /// A field or parent is invalid, the room already exists, or the database failed.
    pub fn add_room(&mut self, input: &RoomInput) -> Result<Room, String> {
        let tx = self.write()?;
        if count(&tx, "nm_rooms")? >= MAX_ROOMS {
            return Err("too many rooms".into());
        }
        let name = label("room name", &input.name, 80, true)?;
        let description = label("room description", &input.description, 500, false)?;
        if let Some(parent) = input.parent_id
            && !exists(&tx, "nm_rooms", parent)?
        {
            return Err("no such parent room".into());
        }
        tx.execute(
            "INSERT INTO nm_rooms (parent_id, name, description) VALUES (?1, ?2, ?3)",
            params![input.parent_id, name, description],
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(_, Some(message)) if message.contains("UNIQUE") => {
                "a room with that name already exists".into()
            }
            other => sql(other),
        })?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(sql)?;
        self.rooms()?
            .into_iter()
            .find(|room| room.id == id)
            .ok_or_else(|| "the room disappeared".into())
    }

    /// Change a room or area.
    ///
    /// # Errors
    /// The room or parent is missing, the move makes a cycle, a field is invalid, or the
    /// database failed.
    pub fn update_room(&mut self, id: i64, input: &RoomInput) -> Result<Room, String> {
        let tx = self.write()?;
        if !exists(&tx, "nm_rooms", id)? {
            return Err("no such room".into());
        }
        if input.parent_id == Some(id) {
            return Err("a room cannot contain itself".into());
        }
        if let Some(parent) = input.parent_id
            && !exists(&tx, "nm_rooms", parent)?
        {
            return Err("no such parent room".into());
        }
        let mut parent = input.parent_id;
        for _ in 0..MAX_ROOMS {
            let Some(at) = parent else { break };
            if at == id {
                return Err("a room cannot be moved inside one of its child rooms".into());
            }
            parent = tx
                .query_row(
                    "SELECT parent_id FROM nm_rooms WHERE id = ?1",
                    [at],
                    |row| row.get(0),
                )
                .map_err(sql)?;
        }
        let name = label("room name", &input.name, 80, true)?;
        let description = label("room description", &input.description, 500, false)?;
        tx.execute(
            "UPDATE nm_rooms SET parent_id = ?2, name = ?3, description = ?4 WHERE id = ?1",
            params![id, input.parent_id, name, description],
        )
        .map_err(sql)?;
        tx.commit().map_err(sql)?;
        self.rooms()?
            .into_iter()
            .find(|room| room.id == id)
            .ok_or_else(|| "the room disappeared".into())
    }

    /// Delete a room. Devices become unassigned and child rooms move to the top level.
    ///
    /// # Errors
    /// The state database could not be changed.
    pub fn delete_room(&mut self, id: i64) -> Result<bool, String> {
        let tx = self.write()?;
        tx.execute(
            "UPDATE nm_devices SET room_id = NULL WHERE room_id = ?1",
            [id],
        )
        .map_err(sql)?;
        tx.execute(
            "UPDATE nm_rooms SET parent_id = NULL WHERE parent_id = ?1",
            [id],
        )
        .map_err(sql)?;
        let changed = tx
            .execute("DELETE FROM nm_rooms WHERE id = ?1", [id])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(changed > 0)
    }

    // ---- manual management ----

    /// Register a device by hand.
    ///
    /// # Errors
    /// A field is invalid, an address or MAC already belongs to another device, or the limit is
    /// reached.
    pub fn add_device(&mut self, input: &DeviceInput, oui: &Oui) -> Result<Device, String> {
        let tx = self.write()?;
        let fields = device_fields(input)?;
        if count(&tx, "nm_devices")? >= MAX_DEVICES {
            return Err("too many devices".into());
        }
        let ts = now();
        let ips = parse_addresses(&input.addresses)?;
        let macs = parse_macs(&input.macs)?;
        let dhcp_ids = parse_dhcp_ids(&input.dhcp_ids)?;
        if let Some(room) = input.room_id
            && !exists(&tx, "nm_rooms", room)?
        {
            return Err("no such room".into());
        }
        for ip in &ips {
            if owner_of_ip(&tx, *ip)?.is_some() {
                return Err(format!("{ip} already belongs to another device"));
            }
        }
        for mac in &macs {
            if owner_of_mac(&tx, mac)?.is_some() {
                return Err(format!(
                    "{} already belongs to another device",
                    format_mac(mac)
                ));
            }
        }
        for client in &dhcp_ids {
            if owner_of_dhcp(&tx, client)?.is_some() {
                return Err(format!(
                    "DHCP client {client} already belongs to another device"
                ));
            }
        }
        let monitoring = input.monitoring.clone().unwrap_or_default();
        check_monitoring(&monitoring)?;
        let vendor = macs.iter().find_map(|m| oui.vendor(m));
        let kind = fields.kind.clone().unwrap_or_else(|| {
            guess_kind(vendor.as_deref(), fields.hostname.as_deref(), None, None).to_owned()
        });
        tx.execute(
            "INSERT INTO nm_devices (name, hostname, kind, os, vendor, icon, description, notes, location_id, room_id,
                 manual, locked, first_seen, last_seen, mon_enabled, mon_method, mon_port, mon_interval, snmp_profile)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, '[\"name\",\"kind\"]', ?11, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                fields.name,
                fields.hostname,
                kind,
                fields.os,
                vendor,
                fields.icon,
                fields.description,
                fields.notes,
                input.location_id,
                input.room_id,
                ts,
                i64::from(monitoring.enabled),
                monitoring.method.as_str(),
                monitoring.tcp_port,
                monitoring.interval_secs,
                input.snmp_profile
            ],
        )
        .map_err(sql)?;
        let id = tx.last_insert_rowid();
        for ip in ips {
            attach_ip(&tx, id, ip, "manual", ts)?;
        }
        for mac in macs {
            attach_mac(&tx, id, &mac, "manual", ts)?;
        }
        for client in dhcp_ids {
            attach_dhcp(&tx, id, &client, "manual", ts)?;
        }
        add_event(
            &tx,
            Some(id),
            "new",
            &format!("{} was added by hand", fields.name),
        )?;
        tx.commit().map_err(sql)?;
        self.device(id)?
            .ok_or_else(|| "the device disappeared".into())
    }

    /// Change a device. What is set here is kept: discovery no longer overwrites it.
    ///
    /// # Errors
    /// The device does not exist or a field is invalid.
    pub fn update_device(
        &mut self,
        id: i64,
        input: &DeviceInput,
        oui: &Oui,
    ) -> Result<Device, String> {
        let tx = self.write()?;
        let current = load_devices(&tx, Some(id))?
            .into_iter()
            .next()
            .ok_or("no such device")?;
        let fields = device_fields(input)?;
        let monitoring = input
            .monitoring
            .clone()
            .unwrap_or_else(|| current.monitoring.clone());
        check_monitoring(&monitoring)?;
        if let Some(room) = input.room_id
            && !exists(&tx, "nm_rooms", room)?
        {
            return Err("no such room".into());
        }
        // Only what the administrator actually changed is locked against discovery.
        let mut locked: HashSet<String> = current.locked.iter().cloned().collect();
        if fields.name != current.name {
            locked.insert("name".into());
        }
        if fields.kind.as_deref().is_some_and(|k| k != current.kind) {
            locked.insert("kind".into());
        }
        if fields.hostname.is_some() && fields.hostname != current.hostname {
            locked.insert("hostname".into());
        }
        if fields.os.is_some() && fields.os != current.os {
            locked.insert("os".into());
        }
        if fields.icon.is_some() && fields.icon != current.icon {
            locked.insert("icon".into());
        }
        let mut locked: Vec<String> = locked.into_iter().collect();
        locked.sort();
        let kind = fields.kind.clone().unwrap_or(current.kind.clone());
        tx.execute(
            "UPDATE nm_devices SET name = ?2, hostname = ?3, kind = ?4, os = ?5, icon = ?6, description = ?7,
                 notes = ?8, location_id = ?9, room_id = ?10, locked = ?11, mon_enabled = ?12, mon_method = ?13, mon_port = ?14,
                 mon_interval = ?15, snmp_profile = ?16 WHERE id = ?1",
            params![
                id,
                fields.name,
                fields.hostname.clone().or(current.hostname.clone()),
                kind,
                fields.os.clone().or(current.os.clone()),
                fields.icon.clone().or(current.icon.clone()),
                fields.description,
                fields.notes,
                input.location_id,
                input.room_id,
                serde_json::to_string(&locked).map_err(|e| e.to_string())?,
                i64::from(monitoring.enabled),
                monitoring.method.as_str(),
                monitoring.tcp_port,
                monitoring.interval_secs,
                input.snmp_profile
            ],
        )
        .map_err(sql)?;
        // Addresses and MACs listed here are added; existing ones stay (use the remove calls).
        let ts = now();
        for ip in parse_addresses(&input.addresses)? {
            match owner_of_ip(&tx, ip)? {
                Some(owner) if owner != id => {
                    return Err(format!("{ip} already belongs to another device"));
                }
                Some(_) => {}
                None => attach_ip(&tx, id, ip, "manual", ts)?,
            }
        }
        for mac in parse_macs(&input.macs)? {
            match owner_of_mac(&tx, &mac)? {
                Some(owner) if owner != id => {
                    return Err(format!(
                        "{} already belongs to another device",
                        format_mac(&mac)
                    ));
                }
                Some(_) => {}
                None => {
                    attach_mac(&tx, id, &mac, "manual", ts)?;
                    if let Some(vendor) = oui.vendor(&mac) {
                        tx.execute(
                            "UPDATE nm_devices SET vendor = COALESCE(vendor, ?2) WHERE id = ?1",
                            params![id, vendor],
                        )
                        .map_err(sql)?;
                    }
                }
            }
        }
        for client in parse_dhcp_ids(&input.dhcp_ids)? {
            match owner_of_dhcp(&tx, &client)? {
                Some(owner) if owner != id => {
                    return Err(format!(
                        "DHCP client {client} already belongs to another device"
                    ));
                }
                Some(_) => {}
                None => attach_dhcp(&tx, id, &client, "manual", ts)?,
            }
        }
        tx.commit().map_err(sql)?;
        self.device(id)?
            .ok_or_else(|| "the device disappeared".into())
    }

    /// Remove an address, MAC, or DHCP client ID from a device.
    ///
    /// # Errors
    /// The value is neither an address nor a MAC.
    pub fn detach(&mut self, id: i64, value: &str) -> Result<bool, String> {
        let tx = self.write()?;
        let gone = if let Ok(ip) = value.trim().parse::<IpAddr>() {
            tx.execute(
                "DELETE FROM nm_addrs WHERE ip = ?1 AND device_id = ?2",
                params![ip.to_string(), id],
            )
        } else if let Some(mac) = parse_mac(value) {
            tx.execute(
                "DELETE FROM nm_macs WHERE mac = ?1 AND device_id = ?2",
                params![format_mac(&mac), id],
            )
        } else if parse_dhcp_ids(&[value.to_owned()]).is_ok() {
            let normalized = value.trim().replace([':', '-'], "").to_ascii_lowercase();
            tx.execute(
                "DELETE FROM nm_dhcp_ids WHERE client = ?1 AND device_id = ?2",
                params![normalized, id],
            )
        } else {
            return Err("give an IP address, MAC address, or DHCP client ID".into());
        }
        .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(gone > 0)
    }

    /// Fold `other` into `keep`: its addresses, MACs, links and history move over, and the
    /// settings an administrator made on `keep` stay.
    ///
    /// # Errors
    /// A device does not exist, or they are the same.
    pub fn merge(&mut self, keep: i64, other: i64) -> Result<Device, String> {
        if keep == other {
            return Err("choose two different devices".into());
        }
        let tx = self.write()?;
        for id in [keep, other] {
            if !exists(&tx, "nm_devices", id)? {
                return Err("no such device".into());
            }
        }
        absorb(&tx, keep, other)?;
        add_event(
            &tx,
            Some(keep),
            "merged",
            "two devices were merged into one",
        )?;
        tx.commit().map_err(sql)?;
        self.device(keep)?
            .ok_or_else(|| "the device disappeared".into())
    }

    /// Delete a device and everything recorded about it.
    ///
    /// # Errors
    /// The database failed.
    pub fn delete_device(&mut self, id: i64) -> Result<bool, String> {
        let tx = self.write()?;
        let gone = tx
            .execute("DELETE FROM nm_devices WHERE id = ?1", [id])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(gone > 0)
    }

    // ---- discovery ----

    /// Merge one observation into the inventory: find the device it belongs to (by hardware
    /// address first, then by IP address), create it if it is new, and fill in what is missing
    /// without touching what an administrator set.
    ///
    /// # Errors
    /// The database failed, or the inventory is full.
    #[allow(clippy::too_many_lines)]
    pub fn observe(&mut self, seen: &Observation, oui: &Oui) -> Result<Option<Merged>, String> {
        let mac = seen.mac.filter(is_usable);
        let dhcp_id = seen
            .dhcp_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.replace([':', '-'], "").to_ascii_lowercase());
        if seen.ip.is_none() && mac.is_none() && dhcp_id.is_none() {
            return Ok(None);
        }
        let tx = self.write()?;
        let ts = now();
        let by_mac = match &mac {
            Some(mac) => owner_of_mac(&tx, mac)?,
            None => None,
        };
        let by_ip = match seen.ip {
            Some(ip) => owner_of_ip(&tx, ip)?,
            None => None,
        };
        let by_dhcp = match &dhcp_id {
            Some(client) => owner_of_dhcp(&tx, client)?,
            None => None,
        };
        if let (Some(by_dhcp), Some(by_mac)) = (by_dhcp, by_mac)
            && by_dhcp != by_mac
        {
            return Err("the DHCP client ID and MAC belong to different devices; correct the identity before scanning again".into());
        }
        let by_identity = by_dhcp.or(by_mac);
        let mut merged = Merged::default();
        let id = match (by_identity, by_ip) {
            (Some(a), Some(b)) if a != b => {
                // The device that held this address has hardware addresses of its own: it is a
                // different device and the address simply changed hands (it moves below).
                let other_macs: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM nm_macs WHERE device_id = ?1",
                        [b],
                        |r| r.get(0),
                    )
                    .map_err(sql)?;
                if other_macs > 0 {
                    a
                } else {
                    // Found by address alone before its hardware address was known: one device.
                    let (keep, drop) = pick_survivor(&tx, a, b)?;
                    absorb(&tx, keep, drop)?;
                    merged.absorbed.push(drop);
                    keep
                }
            }
            (Some(id), _) | (None, Some(id)) => id,
            (None, None) => {
                if count(&tx, "nm_devices")? >= MAX_DEVICES {
                    return Err("too many devices".into());
                }
                let hostname = seen.hostname.as_deref().and_then(clean_hostname);
                let vendor = mac.as_ref().and_then(|m| oui.vendor(m));
                let sys = seen.sys.as_ref();
                let kind = guess_kind(
                    vendor.as_deref(),
                    hostname
                        .as_deref()
                        .or(seen.label.as_deref())
                        .or(sys.and_then(|s| s.name.as_deref())),
                    sys.and_then(|s| s.descr.as_deref()),
                    sys.and_then(|s| s.services),
                );
                let label = seen.label.as_deref().and_then(crate::fritz::clean_label);
                let name = label
                    .or_else(|| hostname.as_deref().map(short_name))
                    .or_else(|| sys.and_then(|s| s.name.clone()))
                    .or_else(|| {
                        vendor
                            .as_deref()
                            .zip(mac.as_ref())
                            .and_then(|(v, m)| generated_name(v, m))
                    })
                    .or_else(|| seen.ip.map(|ip| ip.to_string()))
                    .or_else(|| mac.as_ref().map(format_mac))
                    .unwrap_or_else(|| "device".into());
                tx.execute(
                    "INSERT INTO nm_devices (name, hostname, kind, vendor, first_seen, last_seen)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                    params![name, hostname, kind, vendor, ts],
                )
                .map_err(sql)?;
                merged.created = true;
                tx.last_insert_rowid()
            }
        };
        merged.device_id = id;
        if let Some(ip) = seen.ip {
            attach_ip(
                &tx,
                id,
                ip,
                seen.source.as_str(),
                if seen.source.is_present() { ts } else { 0 },
            )?;
        }
        if let Some(mac) = &mac {
            attach_mac(&tx, id, mac, seen.source.as_str(), ts)?;
        }
        if let Some(client) = &dhcp_id {
            attach_dhcp(&tx, id, client, seen.source.as_str(), ts)?;
        }
        let device = load_devices(&tx, Some(id))?
            .into_iter()
            .next()
            .ok_or("device missing")?;
        let locked = |field: &str| device.locked.iter().any(|f| f == field);
        // Fill in what is missing, never over what an administrator set.
        if let Some(hostname) = seen.hostname.as_deref().and_then(clean_hostname)
            && !locked("hostname")
            && device.hostname.as_deref() != Some(hostname.as_str())
        {
            tx.execute(
                "UPDATE nm_devices SET hostname = ?2 WHERE id = ?1",
                params![id, hostname],
            )
            .map_err(sql)?;
            if !locked("name") {
                tx.execute(
                    "UPDATE nm_devices SET name = ?2 WHERE id = ?1",
                    params![id, short_name(&hostname)],
                )
                .map_err(sql)?;
            }
        }
        if let Some(vendor) = mac.as_ref().and_then(|m| oui.vendor(m))
            && device.vendor.is_none()
        {
            tx.execute(
                "UPDATE nm_devices SET vendor = ?2 WHERE id = ?1",
                params![id, vendor],
            )
            .map_err(sql)?;
        }
        // A name someone chose in the router beats any name Lumen made up. Only a name typed here
        // (locked) is stronger.
        if let Some(label) = seen.label.as_deref().and_then(crate::fritz::clean_label)
            && !locked("name")
            && label != device.name
        {
            tx.execute(
                "UPDATE nm_devices SET name = ?2 WHERE id = ?1",
                params![id, label],
            )
            .map_err(sql)?;
        }
        // A device that is still named by an address gets a readable name once its maker is known.
        if !locked("name") && device.hostname.is_none() && is_placeholder(&device) {
            let refreshed = load_devices(&tx, Some(id))?
                .into_iter()
                .next()
                .ok_or("device missing")?;
            let generated = refreshed
                .macs
                .iter()
                .filter(|_| refreshed.hostname.is_none())
                .find_map(|m| {
                    let mac = parse_mac(&m.mac)?;
                    generated_name(refreshed.vendor.as_deref().or(m.vendor.as_deref())?, &mac)
                });
            if let Some(name) = generated
                && name != refreshed.name
            {
                tx.execute(
                    "UPDATE nm_devices SET name = ?2 WHERE id = ?1",
                    params![id, name],
                )
                .map_err(sql)?;
            }
        }
        if let Some(sys) = &seen.sys {
            write_sys(&tx, id, sys)?;
            if !locked("name")
                && device.hostname.is_none()
                && is_placeholder(&device)
                && let Some(name) = sys.name.as_deref().and_then(clean_hostname)
            {
                tx.execute(
                    "UPDATE nm_devices SET name = ?2 WHERE id = ?1",
                    params![id, name],
                )
                .map_err(sql)?;
            }
        }
        if !locked("kind") && device.kind == "unknown" {
            let refreshed = load_devices(&tx, Some(id))?
                .into_iter()
                .next()
                .ok_or("device missing")?;
            let guess = guess_kind(
                refreshed.vendor.as_deref(),
                refreshed.hostname.as_deref(),
                refreshed.sys.as_ref().and_then(|s| s.descr.as_deref()),
                refreshed.sys.as_ref().and_then(|s| s.services),
            );
            if guess != "unknown" {
                tx.execute(
                    "UPDATE nm_devices SET kind = ?2 WHERE id = ?1",
                    params![id, guess],
                )
                .map_err(sql)?;
            }
        }
        if seen.source.is_present() {
            tx.execute(
                "UPDATE nm_devices SET last_seen = ?2, missed = 0 WHERE id = ?1",
                params![id, ts],
            )
            .map_err(sql)?;
            if device.gone {
                tx.execute("UPDATE nm_devices SET gone = 0 WHERE id = ?1", [id])
                    .map_err(sql)?;
                add_event(
                    &tx,
                    Some(id),
                    "returned",
                    &format!("{} is back on the network", device.name),
                )?;
                merged.returned = true;
            }
        }
        if seen.source.is_alive() {
            tx.execute(
                "UPDATE nm_devices SET last_ok = ?2 WHERE id = ?1",
                params![id, ts],
            )
            .map_err(sql)?;
            if device.status == Status::Unknown {
                tx.execute(
                    "UPDATE nm_devices SET status = 'online' WHERE id = ?1",
                    [id],
                )
                .map_err(sql)?;
            } else if device.status == Status::Offline {
                // It answered, so it is not down. Monitoring will confirm on its next check.
                tx.execute(
                    "UPDATE nm_devices SET status = 'online', fail_streak = 0 WHERE id = ?1",
                    [id],
                )
                .map_err(sql)?;
                if !device.gone {
                    add_event(
                        &tx,
                        Some(id),
                        "recovered",
                        &format!("{} answers again", device.name),
                    )?;
                }
            }
        }
        if merged.created {
            let name = load_devices(&tx, Some(id))?
                .into_iter()
                .next()
                .map_or_else(String::new, |d| d.name);
            add_event(&tx, Some(id), "new", &format!("{name} was found"))?;
        }
        tx.commit().map_err(sql)?;
        Ok(Some(merged))
    }

    /// After a full discovery run: a device with an address in the scanned networks that was not
    /// present is a miss, and enough misses in a row make it gone. Devices outside the scanned
    /// networks, and ones that were present, are left alone. Returns the devices newly gone.
    ///
    /// # Errors
    /// The database failed.
    pub fn finish_sweep(
        &mut self,
        present: &HashSet<i64>,
        scanned: &[IpNet],
        gone_after: u8,
    ) -> Result<Vec<i64>, String> {
        let tx = self.write()?;
        let mut newly = Vec::new();
        for device in load_devices(&tx, None)? {
            if device.gone || present.contains(&device.id) {
                continue;
            }
            let in_scope = device
                .addresses
                .iter()
                .filter_map(|a| a.ip.parse::<IpAddr>().ok())
                .any(|ip| scanned.iter().any(|net| net.contains(&ip)));
            if !in_scope {
                continue;
            }
            let missed: i64 = tx
                .query_row(
                    "SELECT missed + 1 FROM nm_devices WHERE id = ?1",
                    [device.id],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if missed >= i64::from(gone_after) {
                tx.execute(
                    "UPDATE nm_devices SET missed = ?2, gone = 1, status = 'offline' WHERE id = ?1",
                    params![device.id, missed],
                )
                .map_err(sql)?;
                add_event(
                    &tx,
                    Some(device.id),
                    "gone",
                    &format!("{} has not been seen for {missed} runs", device.name),
                )?;
                newly.push(device.id);
            } else {
                tx.execute(
                    "UPDATE nm_devices SET missed = ?2 WHERE id = ?1",
                    params![device.id, missed],
                )
                .map_err(sql)?;
            }
        }
        tx.commit().map_err(sql)?;
        Ok(newly)
    }

    /// The device that owns an address or a hardware address, if any.
    ///
    /// # Errors
    /// The database failed.
    pub fn find_device(
        &self,
        ip: Option<IpAddr>,
        mac: Option<&Mac>,
    ) -> Result<Option<i64>, String> {
        if let Some(mac) = mac
            && let Some(id) = owner_of_mac(&self.conn, mac)?
        {
            return Ok(Some(id));
        }
        match ip {
            Some(ip) => owner_of_ip(&self.conn, ip),
            None => Ok(None),
        }
    }

    /// Add a line to the event log.
    ///
    /// # Errors
    /// The database failed.
    pub fn log_event(&self, device: Option<i64>, kind: &str, detail: &str) -> Result<(), String> {
        add_event(&self.conn, device, kind, detail)
    }

    /// Ask the daemon to run discovery now. The request is picked up within a few seconds.
    ///
    /// # Errors
    /// The database failed.
    pub fn request_scan(&self) -> Result<(), String> {
        self.set_meta("scan_request", &now().to_string())
    }

    /// Whether a scan was requested since the last call, clearing the request.
    ///
    /// # Errors
    /// The database failed.
    pub fn take_scan_request(&self) -> Result<bool, String> {
        let had = self.meta("scan_request")?.is_some();
        if had {
            self.conn
                .execute("DELETE FROM nm_meta WHERE key = 'scan_request'", [])
                .map_err(sql)?;
        }
        Ok(had)
    }

    /// The hardware address behind an IP address, when known (for the DHCP and DNS sources).
    ///
    /// # Errors
    /// The database failed.
    pub fn mac_for(&self, ip: IpAddr) -> Result<Option<Mac>, String> {
        let Some(id) = owner_of_ip(&self.conn, ip)? else {
            return Ok(None);
        };
        let text: Option<String> = self
            .conn
            .query_row(
                "SELECT mac FROM nm_macs WHERE device_id = ?1 LIMIT 1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        Ok(text.and_then(|t| parse_mac(&t)))
    }

    /// Recent events, newest first.
    ///
    /// # Errors
    /// The database failed.
    pub fn events(&self, device: Option<i64>, limit: usize) -> Result<Vec<Event>, String> {
        let limit = i64::try_from(limit.clamp(1, 1000)).unwrap_or(1000);
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, ts, device_id, kind, detail FROM nm_events
                 WHERE (?1 IS NULL OR device_id = ?1) ORDER BY id DESC LIMIT ?2",
            )
            .map_err(sql)?;
        statement
            .query_map(params![device, limit], |row| {
                Ok(Event {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    device_id: row.get(2)?,
                    kind: row.get(3)?,
                    detail: row.get(4)?,
                })
            })
            .map_err(sql)?
            .collect::<Result<_, _>>()
            .map_err(sql)
    }

    /// Write a small value that the daemon and the API share.
    ///
    /// # Errors
    /// The database failed.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO nm_meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
                params![key, value],
            )
            .map_err(sql)?;
        Ok(())
    }

    /// # Errors
    /// The database failed.
    pub fn meta(&self, key: &str) -> Result<Option<String>, String> {
        self.conn
            .query_row("SELECT value FROM nm_meta WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(sql)
    }
}

// ---- helpers ----

pub(crate) struct Fields {
    pub name: String,
    pub hostname: Option<String>,
    pub kind: Option<String>,
    pub os: Option<String>,
    pub icon: Option<String>,
    pub description: String,
    pub notes: String,
}

fn device_fields(input: &DeviceInput) -> Result<Fields, String> {
    let name = label("name", &input.name, 64, true)?;
    let hostname = match input
        .hostname
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
    {
        Some(h) => Some(
            clean_hostname(h)
                .ok_or("host name must be DNS labels of letters, digits and hyphens")?,
        ),
        None => None,
    };
    let kind = match input
        .kind
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        Some(k) if KINDS.contains(&k) => Some(k.to_owned()),
        Some(_) => return Err(format!("kind must be one of {}", KINDS.join(", "))),
        None => None,
    };
    let icon = match input
        .icon
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        Some(i) if ICONS.contains(&i) => Some(i.to_owned()),
        Some(_) => return Err(format!("icon must be one of {}", ICONS.join(", "))),
        None => None,
    };
    let os = match input.os.as_deref().map(str::trim).filter(|o| !o.is_empty()) {
        Some(o) => Some(label("os", o, 64, false)?),
        None => None,
    };
    Ok(Fields {
        name,
        hostname,
        kind,
        os,
        icon,
        description: label("description", &input.description, 500, false)?,
        notes: label("notes", &input.notes, 2000, false)?,
    })
}

fn check_monitoring(monitoring: &Monitoring) -> Result<(), String> {
    if monitoring
        .interval_secs
        .is_some_and(|s| !(10..=3600).contains(&s))
    {
        return Err("the check interval must be 10 to 3600 seconds".into());
    }
    if monitoring.method == crate::model::CheckMethod::Tcp
        && monitoring.tcp_port.is_none_or(|p| p == 0)
    {
        return Err("a TCP check needs a port".into());
    }
    Ok(())
}

fn parse_addresses(list: &[String]) -> Result<Vec<IpAddr>, String> {
    if list.len() > 16 {
        return Err("at most 16 addresses per device".into());
    }
    list.iter()
        .map(|a| {
            let ip: IpAddr = a
                .trim()
                .parse()
                .map_err(|_| format!("{a} is not an IP address"))?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(format!("{a} cannot belong to one device"));
            }
            Ok(ip)
        })
        .collect()
}

fn parse_macs(list: &[String]) -> Result<Vec<Mac>, String> {
    if list.len() > 16 {
        return Err("at most 16 hardware addresses per device".into());
    }
    list.iter()
        .map(|m| {
            parse_mac(m)
                .filter(is_usable)
                .ok_or_else(|| format!("{m} is not a usable MAC address"))
        })
        .collect()
}

fn parse_dhcp_ids(list: &[String]) -> Result<Vec<String>, String> {
    if list.len() > 16 {
        return Err("at most 16 DHCP client IDs per device".into());
    }
    list.iter()
        .map(|value| {
            let value = value.trim().replace([':', '-'], "").to_ascii_lowercase();
            if value.is_empty()
                || value.len() > 256
                || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(format!("{value} is not a DHCP client ID"));
            }
            Ok(value)
        })
        .collect()
}

pub(crate) fn count(conn: &Connection, table: &str) -> Result<usize, String> {
    let total: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .map_err(sql)?;
    Ok(usize::try_from(total).unwrap_or(usize::MAX))
}

pub(crate) fn exists(conn: &Connection, table: &str, id: i64) -> Result<bool, String> {
    let found: Option<i64> = conn
        .query_row(&format!("SELECT 1 FROM {table} WHERE id = ?1"), [id], |r| {
            r.get(0)
        })
        .optional()
        .map_err(sql)?;
    Ok(found.is_some())
}

fn owner_of_ip(conn: &Connection, ip: IpAddr) -> Result<Option<i64>, String> {
    conn.query_row(
        "SELECT device_id FROM nm_addrs WHERE ip = ?1",
        [ip.to_string()],
        |r| r.get(0),
    )
    .optional()
    .map_err(sql)
}

fn owner_of_mac(conn: &Connection, mac: &Mac) -> Result<Option<i64>, String> {
    conn.query_row(
        "SELECT device_id FROM nm_macs WHERE mac = ?1",
        [format_mac(mac)],
        |r| r.get(0),
    )
    .optional()
    .map_err(sql)
}

fn owner_of_dhcp(conn: &Connection, client: &str) -> Result<Option<i64>, String> {
    conn.query_row(
        "SELECT device_id FROM nm_dhcp_ids WHERE client = ?1",
        [client],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql)
}

fn attach_ip(
    tx: &Transaction<'_>,
    id: i64,
    ip: IpAddr,
    source: &str,
    seen: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO nm_addrs (ip, device_id, source, last_seen) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(ip) DO UPDATE SET device_id = ?2, last_seen = MAX(last_seen, ?4),
             source = CASE WHEN ?4 > 0 THEN ?3 ELSE source END",
        params![ip.to_string(), id, source, seen],
    )
    .map_err(sql)?;
    Ok(())
}

fn attach_mac(
    tx: &Transaction<'_>,
    id: i64,
    mac: &Mac,
    source: &str,
    seen: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO nm_macs (mac, device_id, source, last_seen) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(mac) DO UPDATE SET device_id = ?2, last_seen = MAX(last_seen, ?4), source = ?3",
        params![format_mac(mac), id, source, seen],
    )
    .map_err(sql)?;
    Ok(())
}

fn attach_dhcp(
    tx: &Transaction<'_>,
    id: i64,
    client: &str,
    source: &str,
    seen: i64,
) -> Result<(), String> {
    tx.execute(
        "INSERT INTO nm_dhcp_ids (client, device_id, source, last_seen) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(client) DO UPDATE SET device_id = ?2, source = ?3, last_seen = MAX(last_seen, ?4)",
        params![client, id, source, seen],
    )
    .map_err(sql)?;
    Ok(())
}

pub(crate) fn add_event(
    conn: &Connection,
    device: Option<i64>,
    kind: &str,
    detail: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO nm_events (ts, device_id, kind, detail) VALUES (?1, ?2, ?3, ?4)",
        params![now(), device, kind, detail],
    )
    .map_err(sql)?;
    Ok(())
}

/// Which of two devices that turned out to be one should stay: one an administrator made or
/// edited wins, then the older.
fn pick_survivor(tx: &Transaction<'_>, a: i64, b: i64) -> Result<(i64, i64), String> {
    let rank = |id: i64| -> Result<(i64, i64), String> {
        tx.query_row(
            "SELECT manual + (locked != '[]'), -first_seen FROM nm_devices WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql)
    };
    Ok(if rank(a)? >= rank(b)? { (a, b) } else { (b, a) })
}

/// Move everything of `drop` to `keep` and delete `drop`.
fn absorb(tx: &Transaction<'_>, keep: i64, drop: i64) -> Result<(), String> {
    tx.execute(
        "UPDATE nm_addrs SET device_id = ?1 WHERE device_id = ?2",
        [keep, drop],
    )
    .map_err(sql)?;
    tx.execute(
        "UPDATE nm_macs SET device_id = ?1 WHERE device_id = ?2",
        [keep, drop],
    )
    .map_err(sql)?;
    tx.execute(
        "UPDATE nm_dhcp_ids SET device_id = ?1 WHERE device_id = ?2",
        [keep, drop],
    )
    .map_err(sql)?;
    tx.execute(
        "UPDATE OR IGNORE nm_links SET a_device = ?1 WHERE a_device = ?2",
        [keep, drop],
    )
    .map_err(sql)?;
    tx.execute(
        "UPDATE OR IGNORE nm_links SET b_device = ?1 WHERE b_device = ?2",
        [keep, drop],
    )
    .map_err(sql)?;
    tx.execute(
        "DELETE FROM nm_links WHERE a_device = b_device OR a_device = ?1 OR b_device = ?1",
        [drop],
    )
    .map_err(sql)?;
    tx.execute(
        "UPDATE nm_checks SET device_id = ?1 WHERE device_id = ?2",
        [keep, drop],
    )
    .map_err(sql)?;
    tx.execute(
        "UPDATE nm_events SET device_id = ?1 WHERE device_id = ?2",
        [keep, drop],
    )
    .map_err(sql)?;
    // Fill the survivor's empty fields from the other one.
    tx.execute(
        "UPDATE nm_devices SET
             hostname = COALESCE(hostname, (SELECT hostname FROM nm_devices WHERE id = ?2)),
             os = COALESCE(os, (SELECT os FROM nm_devices WHERE id = ?2)),
             vendor = COALESCE(vendor, (SELECT vendor FROM nm_devices WHERE id = ?2)),
             first_seen = MIN(first_seen, (SELECT first_seen FROM nm_devices WHERE id = ?2)),
             last_seen = MAX(last_seen, (SELECT last_seen FROM nm_devices WHERE id = ?2)),
             snmp_profile = COALESCE(snmp_profile, (SELECT snmp_profile FROM nm_devices WHERE id = ?2)),
             kind = CASE WHEN kind = 'unknown' THEN (SELECT kind FROM nm_devices WHERE id = ?2) ELSE kind END
         WHERE id = ?1",
        [keep, drop],
    )
    .map_err(sql)?;
    tx.execute("DELETE FROM nm_devices WHERE id = ?1", [drop])
        .map_err(sql)?;
    Ok(())
}

pub(crate) fn write_sys(conn: &Connection, id: i64, sys: &SysInfo) -> Result<(), String> {
    conn.execute(
        "INSERT INTO nm_sys (device_id, name, descr, object_id, contact, location, uptime, services, cpu, mem, temp, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(device_id) DO UPDATE SET
             name = COALESCE(?2, name), descr = COALESCE(?3, descr), object_id = COALESCE(?4, object_id),
             contact = COALESCE(?5, contact), location = COALESCE(?6, location), uptime = COALESCE(?7, uptime),
             services = COALESCE(?8, services), cpu = ?9, mem = ?10, temp = ?11, updated = ?12",
        params![
            id,
            sys.name,
            sys.descr,
            sys.object_id,
            sys.contact,
            sys.location,
            sys.uptime_secs.and_then(|v| i64::try_from(v).ok()),
            sys.services,
            sys.cpu_percent,
            sys.memory_percent,
            sys.temperature_c,
            sys.updated
        ],
    )
    .map_err(sql)?;
    Ok(())
}

fn matches_query(device: &Device, query: &str) -> bool {
    let mut hay = format!(
        "{} {} {} {} {} {}",
        device.name,
        device.hostname.as_deref().unwrap_or(""),
        device.vendor.as_deref().unwrap_or(""),
        device.description,
        device.kind,
        device.os.as_deref().unwrap_or("")
    );
    for a in &device.addresses {
        hay.push(' ');
        hay.push_str(&a.ip);
    }
    for m in &device.macs {
        hay.push(' ');
        hay.push_str(&m.mac);
    }
    hay.to_ascii_lowercase().contains(query)
}

/// Load one device or all of them, with their addresses, MACs and SNMP facts.
pub(crate) fn load_devices(conn: &Connection, only: Option<i64>) -> Result<Vec<Device>, String> {
    let mut addrs: HashMap<i64, Vec<DeviceAddress>> = HashMap::new();
    {
        let mut st = conn
            .prepare("SELECT device_id, ip, source, last_seen FROM nm_addrs ORDER BY ip")
            .map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    DeviceAddress {
                        ip: r.get(1)?,
                        source: r.get(2)?,
                        last_seen: r.get(3)?,
                    },
                ))
            })
            .map_err(sql)?;
        for row in rows {
            let (id, a) = row.map_err(sql)?;
            addrs.entry(id).or_default().push(a);
        }
    }
    let oui = Oui::new();
    let mut macs: HashMap<i64, Vec<DeviceMac>> = HashMap::new();
    {
        let mut st = conn
            .prepare("SELECT device_id, mac, source, last_seen FROM nm_macs ORDER BY mac")
            .map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                let mac: String = r.get(1)?;
                Ok((
                    r.get::<_, i64>(0)?,
                    DeviceMac {
                        vendor: parse_mac(&mac).and_then(|m| oui.vendor(&m)),
                        mac,
                        source: r.get(2)?,
                        last_seen: r.get(3)?,
                    },
                ))
            })
            .map_err(sql)?;
        for row in rows {
            let (id, m) = row.map_err(sql)?;
            macs.entry(id).or_default().push(m);
        }
    }
    let mut sys: HashMap<i64, SysInfo> = HashMap::new();
    {
        let mut st = conn
            .prepare("SELECT device_id, name, descr, object_id, contact, location, uptime, services, cpu, mem, temp, updated FROM nm_sys")
            .map_err(sql)?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    SysInfo {
                        name: r.get(1)?,
                        descr: r.get(2)?,
                        object_id: r.get(3)?,
                        contact: r.get(4)?,
                        location: r.get(5)?,
                        uptime_secs: r
                            .get::<_, Option<i64>>(6)?
                            .and_then(|v| u64::try_from(v).ok()),
                        services: r.get(7)?,
                        cpu_percent: r.get(8)?,
                        memory_percent: r.get(9)?,
                        temperature_c: r.get(10)?,
                        updated: r.get(11)?,
                    },
                ))
            })
            .map_err(sql)?;
        for row in rows {
            let (id, s) = row.map_err(sql)?;
            sys.insert(id, s);
        }
    }
    let mut dhcp: HashMap<i64, Vec<String>> = HashMap::new();
    {
        let mut statement = conn
            .prepare("SELECT device_id, client FROM nm_dhcp_ids ORDER BY client")
            .map_err(sql)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sql)?;
        for row in rows {
            let (id, client) = row.map_err(sql)?;
            dhcp.entry(id).or_default().push(client);
        }
    }
    let mut st = conn
        .prepare(
            "SELECT id, name, hostname, kind, os, vendor, icon, description, notes, location_id, room_id, manual, locked,
                    status, first_seen, last_seen, last_ok, gone, mon_enabled, mon_method, mon_port, mon_interval,
                    snmp_profile FROM nm_devices WHERE (?1 IS NULL OR id = ?1) ORDER BY last_seen DESC, id",
        )
        .map_err(sql)?;
    let rows = st
        .query_map([only], |r| {
            let id: i64 = r.get(0)?;
            let locked: String = r.get(12)?;
            Ok(Device {
                id,
                name: r.get(1)?,
                hostname: r.get(2)?,
                kind: r.get(3)?,
                os: r.get(4)?,
                vendor: r.get(5)?,
                icon: r.get(6)?,
                description: r.get(7)?,
                notes: r.get(8)?,
                location_id: r.get(9)?,
                room_id: r.get(10)?,
                manual: r.get::<_, i64>(11)? != 0,
                locked: serde_json::from_str(&locked).unwrap_or_default(),
                status: Status::parse(&r.get::<_, String>(13)?),
                first_seen: r.get(14)?,
                last_seen: r.get(15)?,
                last_ok: r.get(16)?,
                gone: r.get::<_, i64>(17)? != 0,
                monitoring: Monitoring {
                    enabled: r.get::<_, i64>(18)? != 0,
                    method: crate::model::CheckMethod::parse(&r.get::<_, String>(19)?),
                    tcp_port: r.get(20)?,
                    interval_secs: r.get(21)?,
                },
                snmp_profile: r.get(22)?,
                addresses: Vec::new(),
                macs: Vec::new(),
                dhcp_ids: Vec::new(),
                identity_confidence: String::new(),
                sys: None,
                subnet: None,
                vlan: None,
            })
        })
        .map_err(sql)?;
    let mut out = Vec::new();
    for row in rows {
        let mut d = row.map_err(sql)?;
        d.addresses = addrs.remove(&d.id).unwrap_or_default();
        d.macs = macs.remove(&d.id).unwrap_or_default();
        d.dhcp_ids = dhcp.remove(&d.id).unwrap_or_default();
        d.identity_confidence = if d.manual || d.locked.iter().any(|field| field == "name") {
            "confirmed".to_owned()
        } else if !d.macs.is_empty() || !d.dhcp_ids.is_empty() {
            "probable".to_owned()
        } else {
            "uncertain".to_owned()
        };
        d.sys = sys.remove(&d.id);
        out.push(d);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;

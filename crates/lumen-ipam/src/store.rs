//! The `SQLite` side: tables, validation, and every change as one transaction.

use crate::{
    alloc::{self, block, block_count, from_num, to_num, usable, usable_count},
    model::{
        AddressFilter, AddressInput, AddressRow, AllocateInput, Conflict, LOCATION_KINDS, Leased,
        Location, LocationInput, MAX_ADDRESSES, MAX_LOCATIONS, MAX_METADATA, MAX_SUBNETS,
        MAX_VLANS, Overview, Subnet, SubnetInput, SubnetStats, Vlan, VlanInput,
    },
};
use ipnet::IpNet;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::IpAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ipam_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_id INTEGER REFERENCES ipam_locations(id),
    kind TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS ipam_vlans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vid INTEGER NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    location_id INTEGER REFERENCES ipam_locations(id));
CREATE TABLE IF NOT EXISTS ipam_subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    grp TEXT NOT NULL DEFAULT '', vlan_id INTEGER REFERENCES ipam_vlans(id),
    location_id INTEGER REFERENCES ipam_locations(id), gateway TEXT,
    metadata TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS ipam_addresses (
    ip TEXT PRIMARY KEY, subnet_id INTEGER NOT NULL REFERENCES ipam_subnets(id),
    state TEXT NOT NULL, hostname TEXT, description TEXT NOT NULL DEFAULT '',
    device TEXT NOT NULL DEFAULT '', location_id INTEGER REFERENCES ipam_locations(id),
    dns INTEGER NOT NULL DEFAULT 0, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ipam_addresses_subnet ON ipam_addresses(subnet_id);
CREATE TABLE IF NOT EXISTS ipam_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ipam_leases (ip TEXT PRIMARY KEY, hostname TEXT);
";

/// An IPAM database. Open one per request: opening is cheap and every change is its own
/// transaction.
pub struct Ipam {
    conn: Connection,
}

#[allow(clippy::needless_pass_by_value)] // used as `map_err(sql)`
fn sql(error: rusqlite::Error) -> String {
    format!("the IPAM database failed: {error}")
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn text(field: &str, value: &str, max: usize, required: bool) -> Result<String, String> {
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

/// A DNS host name: letters, digits and hyphens in labels of up to 63 characters.
fn hostname(value: &str) -> Result<String, String> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if value.len() > 200 || !value.split('.').all(label_ok) {
        return Err("host name must be DNS labels of letters, digits and hyphens".into());
    }
    Ok(value)
}

fn parse_net(value: &str) -> Result<IpNet, String> {
    let net: IpNet = value
        .trim()
        .parse()
        .map_err(|_| "cidr must look like 192.168.1.0/24 or 2001:db8::/64".to_owned())?;
    let ok = match net {
        IpNet::V4(v4) => (8..=32).contains(&v4.prefix_len()),
        IpNet::V6(v6) => (16..=128).contains(&v6.prefix_len()),
    };
    if !ok {
        return Err("the prefix length must be 8 to 32 (IPv4) or 16 to 128 (IPv6)".into());
    }
    Ok(net.trunc())
}

fn contains(outer: &IpNet, inner: &IpNet) -> bool {
    outer.prefix_len() < inner.prefix_len() && outer.contains(inner)
}

fn family(ip: IpAddr) -> u8 {
    if ip.is_ipv4() { 4 } else { 6 }
}

impl Ipam {
    /// Open (or create) the tables inside `path`, which may be the console's state file.
    ///
    /// # Errors
    /// The file cannot be opened or its tables created.
    pub fn open(path: &Path) -> Result<Self, String> {
        let conn = Connection::open(path).map_err(sql)?;
        Self::init(conn)
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
        Ok(Self { conn })
    }

    fn write(&mut self) -> Result<Transaction<'_>, String> {
        self.conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql)
    }

    // ---- locations ----

    /// # Errors
    /// The database failed.
    pub fn locations(&self) -> Result<Vec<Location>, String> {
        locations_in(&self.conn)
    }

    /// # Errors
    /// The input is invalid, the parent does not exist, or the limit is reached.
    pub fn add_location(&mut self, input: &LocationInput) -> Result<Location, String> {
        let tx = self.write()?;
        let (kind, name, description) = location_fields(input)?;
        check_parent(&tx, None, input.parent_id)?;
        if count(&tx, "ipam_locations")? >= MAX_LOCATIONS {
            return Err("too many locations".into());
        }
        tx.execute(
            "INSERT INTO ipam_locations (parent_id, kind, name, description) VALUES (?1, ?2, ?3, ?4)",
            params![input.parent_id, kind, name, description],
        )
        .map_err(sql)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(sql)?;
        Ok(Location {
            id,
            parent_id: input.parent_id,
            kind,
            name,
            description,
        })
    }

    /// # Errors
    /// The location does not exist, the input is invalid, or the parent would make a loop.
    pub fn update_location(&mut self, id: i64, input: &LocationInput) -> Result<Location, String> {
        let tx = self.write()?;
        if !exists(&tx, "ipam_locations", id)? {
            return Err("no such location".into());
        }
        let (kind, name, description) = location_fields(input)?;
        check_parent(&tx, Some(id), input.parent_id)?;
        tx.execute(
            "UPDATE ipam_locations SET parent_id = ?2, kind = ?3, name = ?4, description = ?5 WHERE id = ?1",
            params![id, input.parent_id, kind, name, description],
        )
        .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(Location {
            id,
            parent_id: input.parent_id,
            kind,
            name,
            description,
        })
    }

    /// # Errors
    /// The location has children or is still used.
    pub fn delete_location(&mut self, id: i64) -> Result<bool, String> {
        let tx = self.write()?;
        for (table, column, what) in [
            ("ipam_locations", "parent_id", "locations inside it"),
            ("ipam_vlans", "location_id", "VLANs"),
            ("ipam_subnets", "location_id", "subnets"),
            ("ipam_addresses", "location_id", "addresses"),
        ] {
            let used: i64 = tx
                .query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {column} = ?1"),
                    [id],
                    |row| row.get(0),
                )
                .map_err(sql)?;
            if used > 0 {
                return Err(format!(
                    "the location still has {what}; move or remove them first"
                ));
            }
        }
        let gone = tx
            .execute("DELETE FROM ipam_locations WHERE id = ?1", [id])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(gone > 0)
    }

    // ---- VLANs ----

    /// # Errors
    /// The database failed.
    pub fn vlans(&self) -> Result<Vec<Vlan>, String> {
        let mut statement = self
            .conn
            .prepare(
                "SELECT id, vid, name, description, location_id FROM ipam_vlans ORDER BY vid, id",
            )
            .map_err(sql)?;
        statement
            .query_map([], |row| {
                Ok(Vlan {
                    id: row.get(0)?,
                    vid: row.get(1)?,
                    name: row.get(2)?,
                    description: row.get(3)?,
                    location_id: row.get(4)?,
                })
            })
            .map_err(sql)?
            .collect::<Result<_, _>>()
            .map_err(sql)
    }

    fn vlan_fields(
        tx: &Transaction<'_>,
        id: Option<i64>,
        input: &VlanInput,
    ) -> Result<(String, String), String> {
        if !(1..=4094).contains(&input.vid) {
            return Err("the VLAN ID must be 1 to 4094".into());
        }
        let name = text("name", &input.name, 64, true)?;
        let description = text("description", &input.description, 500, false)?;
        if let Some(location) = input.location_id
            && !exists(tx, "ipam_locations", location)?
        {
            return Err("no such location".into());
        }
        let twin: Option<i64> = tx
            .query_row(
                "SELECT id FROM ipam_vlans WHERE vid = ?1 AND IFNULL(location_id, 0) = ?2 AND id != ?3",
                params![input.vid, input.location_id.unwrap_or(0), id.unwrap_or(0)],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql)?;
        if twin.is_some() {
            return Err(format!(
                "VLAN {} already exists in this location",
                input.vid
            ));
        }
        Ok((name, description))
    }

    /// # Errors
    /// The input is invalid, the VLAN ID is taken in that location, or the limit is reached.
    pub fn add_vlan(&mut self, input: &VlanInput) -> Result<Vlan, String> {
        let tx = self.write()?;
        let (name, description) = Self::vlan_fields(&tx, None, input)?;
        if count(&tx, "ipam_vlans")? >= MAX_VLANS {
            return Err("too many VLANs".into());
        }
        tx.execute(
            "INSERT INTO ipam_vlans (vid, name, description, location_id) VALUES (?1, ?2, ?3, ?4)",
            params![input.vid, name, description, input.location_id],
        )
        .map_err(sql)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(sql)?;
        Ok(Vlan {
            id,
            vid: input.vid,
            name,
            description,
            location_id: input.location_id,
        })
    }

    /// # Errors
    /// The VLAN does not exist or the input is invalid.
    pub fn update_vlan(&mut self, id: i64, input: &VlanInput) -> Result<Vlan, String> {
        let tx = self.write()?;
        if !exists(&tx, "ipam_vlans", id)? {
            return Err("no such VLAN".into());
        }
        let (name, description) = Self::vlan_fields(&tx, Some(id), input)?;
        tx.execute(
            "UPDATE ipam_vlans SET vid = ?2, name = ?3, description = ?4, location_id = ?5 WHERE id = ?1",
            params![id, input.vid, name, description, input.location_id],
        )
        .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(Vlan {
            id,
            vid: input.vid,
            name,
            description,
            location_id: input.location_id,
        })
    }

    /// # Errors
    /// Subnets still use the VLAN.
    pub fn delete_vlan(&mut self, id: i64) -> Result<bool, String> {
        let tx = self.write()?;
        let used: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM ipam_subnets WHERE vlan_id = ?1",
                [id],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if used > 0 {
            return Err("subnets still use this VLAN; change them first".into());
        }
        let gone = tx
            .execute("DELETE FROM ipam_vlans WHERE id = ?1", [id])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(gone > 0)
    }

    // ---- subnets ----

    /// All subnets, each with the smallest subnet that contains it.
    ///
    /// # Errors
    /// The database failed.
    pub fn subnets(&self) -> Result<Vec<Subnet>, String> {
        subnets_in(&self.conn)
    }

    fn subnet_fields(
        tx: &Transaction<'_>,
        net: &IpNet,
        input: &SubnetInput,
    ) -> Result<(String, String, String, Option<String>, String), String> {
        let name = text("name", &input.name, 64, true)?;
        let description = text("description", &input.description, 500, false)?;
        let group = text("group", &input.group, 64, false)?;
        if let Some(vlan) = input.vlan_id
            && !exists(tx, "ipam_vlans", vlan)?
        {
            return Err("no such VLAN".into());
        }
        if let Some(location) = input.location_id
            && !exists(tx, "ipam_locations", location)?
        {
            return Err("no such location".into());
        }
        let gateway = match input
            .gateway
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty())
        {
            Some(value) => {
                let ip: IpAddr = value
                    .parse()
                    .map_err(|_| "gateway must be an IP address".to_owned())?;
                let (first, last) = usable(net);
                if !net.contains(&ip) || !(first..=last).contains(&to_num(ip)) {
                    return Err("the gateway must be a usable address inside the subnet".into());
                }
                Some(ip.to_string())
            }
            None => None,
        };
        if input.metadata.len() > MAX_METADATA {
            return Err(format!("at most {MAX_METADATA} metadata entries"));
        }
        let mut metadata = BTreeMap::new();
        for (key, value) in &input.metadata {
            metadata.insert(
                text("metadata key", key, 64, true)?,
                text("metadata value", value, 256, false)?,
            );
        }
        let metadata = serde_json::to_string(&metadata).map_err(|e| e.to_string())?;
        Ok((name, description, group, gateway, metadata))
    }

    /// # Errors
    /// The CIDR is invalid or already managed, a reference does not exist, or the limit is
    /// reached.
    pub fn add_subnet(&mut self, input: &SubnetInput) -> Result<Subnet, String> {
        let net = parse_net(&input.cidr)?;
        let tx = self.write()?;
        let (name, description, group, gateway, metadata) = Self::subnet_fields(&tx, &net, input)?;
        if count(&tx, "ipam_subnets")? >= MAX_SUBNETS {
            return Err("too many subnets".into());
        }
        let cidr = net.to_string();
        let twin: Option<i64> = tx
            .query_row(
                "SELECT id FROM ipam_subnets WHERE cidr = ?1",
                [&cidr],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if twin.is_some() {
            return Err(format!("{cidr} is already managed"));
        }
        tx.execute(
            "INSERT INTO ipam_subnets (cidr, name, description, grp, vlan_id, location_id, gateway, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![cidr, name, description, group, input.vlan_id, input.location_id, gateway, metadata],
        )
        .map_err(sql)?;
        let id = tx.last_insert_rowid();
        // Addresses already recorded inside the new subnet move to it when it is more specific.
        let nets = nets_in(&tx)?;
        let rows: Vec<(String, i64)> = {
            let mut statement = tx
                .prepare("SELECT ip, subnet_id FROM ipam_addresses")
                .map_err(sql)?;
            statement
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(sql)?
                .collect::<Result<_, _>>()
                .map_err(sql)?
        };
        for (ip, owner) in rows {
            let Ok(address) = ip.parse::<IpAddr>() else {
                continue;
            };
            if let Some((best, _)) = subnet_for(&nets, address)
                && best != owner
            {
                tx.execute(
                    "UPDATE ipam_addresses SET subnet_id = ?2 WHERE ip = ?1",
                    params![ip, best],
                )
                .map_err(sql)?;
            }
        }
        tx.commit().map_err(sql)?;
        self.subnets()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| "the subnet disappeared".into())
    }

    /// Change everything except the network itself.
    ///
    /// # Errors
    /// The subnet does not exist, the input is invalid, or the CIDR differs from the stored one.
    pub fn update_subnet(&mut self, id: i64, input: &SubnetInput) -> Result<Subnet, String> {
        let tx = self.write()?;
        let stored: Option<String> = tx
            .query_row("SELECT cidr FROM ipam_subnets WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(sql)?;
        let stored = stored.ok_or("no such subnet")?;
        if !input.cidr.trim().is_empty() && parse_net(&input.cidr)?.to_string() != stored {
            return Err(
                "a subnet keeps its network; delete it and add a new one to change it".into(),
            );
        }
        let net: IpNet = stored
            .parse()
            .map_err(|_| "stored subnet is invalid".to_owned())?;
        let (name, description, group, gateway, metadata) = Self::subnet_fields(&tx, &net, input)?;
        tx.execute(
            "UPDATE ipam_subnets SET name = ?2, description = ?3, grp = ?4, vlan_id = ?5,
                 location_id = ?6, gateway = ?7, metadata = ?8 WHERE id = ?1",
            params![
                id,
                name,
                description,
                group,
                input.vlan_id,
                input.location_id,
                gateway,
                metadata
            ],
        )
        .map_err(sql)?;
        tx.commit().map_err(sql)?;
        self.subnets()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| "the subnet disappeared".into())
    }

    /// # Errors
    /// The subnet still holds addresses or smaller subnets.
    pub fn delete_subnet(&mut self, id: i64) -> Result<bool, String> {
        let tx = self.write()?;
        let used: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM ipam_addresses WHERE subnet_id = ?1",
                [id],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if used > 0 {
            return Err("the subnet still holds addresses; release them first".into());
        }
        let all = subnets_in(&tx)?;
        if all.iter().any(|s| s.parent_id == Some(id)) {
            return Err("the subnet contains smaller subnets; remove or move them first".into());
        }
        let gone = tx
            .execute("DELETE FROM ipam_subnets WHERE id = ?1", [id])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(gone > 0)
    }

    // ---- addresses ----

    fn address_fields(
        tx: &Transaction<'_>,
        ip: IpAddr,
        host: Option<&str>,
        description: &str,
        device: &str,
        location_id: Option<i64>,
        dns: bool,
    ) -> Result<(Option<String>, String, String), String> {
        let host = match host.map(str::trim).filter(|h| !h.is_empty()) {
            Some(value) => Some(hostname(value)?),
            None => None,
        };
        if dns && host.is_none() {
            return Err("DNS publishing needs a host name".into());
        }
        if let Some(location) = location_id
            && !exists(tx, "ipam_locations", location)?
        {
            return Err("no such location".into());
        }
        if let Some(host) = &host {
            // One name cannot have two addresses of the same family here, or DNS would be
            // ambiguous. A and AAAA for one name is fine.
            let others: Vec<String> = {
                let mut statement = tx
                    .prepare("SELECT ip FROM ipam_addresses WHERE hostname = ?1 AND ip != ?2")
                    .map_err(sql)?;
                statement
                    .query_map(params![host, ip.to_string()], |r| r.get(0))
                    .map_err(sql)?
                    .collect::<Result<_, _>>()
                    .map_err(sql)?
            };
            if others
                .iter()
                .filter_map(|o| o.parse::<IpAddr>().ok())
                .any(|o| family(o) == family(ip))
            {
                return Err(format!(
                    "the name {host} already belongs to another address"
                ));
            }
        }
        Ok((
            host,
            text("description", description, 500, false)?,
            text("device", device, 128, false)?,
        ))
    }

    /// Record or change an address by hand: assign it to a device or reserve it. Nothing is
    /// configured on the device.
    ///
    /// # Errors
    /// The address is not in a managed subnet, is not usable, is leased by DHCP, or has an
    /// invalid field.
    pub fn set_address(
        &mut self,
        input: &AddressInput,
        leased: &[Leased],
    ) -> Result<AddressRow, String> {
        let ip: IpAddr = input
            .ip
            .trim()
            .parse()
            .map_err(|_| "ip must be an IP address".to_owned())?;
        let tx = self.write()?;
        let nets = nets_in(&tx)?;
        let (subnet_id, net) =
            subnet_for(&nets, ip).ok_or("the address is not inside any managed subnet")?;
        let (first, last) = usable(&net);
        if !(first..=last).contains(&to_num(ip)) {
            return Err("that is the network or broadcast address of the subnet".into());
        }
        if leased.iter().any(|l| l.ip == ip) {
            return Err("DHCP currently leases this address".into());
        }
        let (host, description, device) = Self::address_fields(
            &tx,
            ip,
            input.hostname.as_deref(),
            &input.description,
            &input.device,
            input.location_id,
            input.dns,
        )?;
        let known: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM ipam_addresses WHERE ip = ?1",
                [ip.to_string()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if known.is_none() && count(&tx, "ipam_addresses")? >= MAX_ADDRESSES {
            return Err("too many addresses".into());
        }
        let row = AddressRow {
            ip: ip.to_string(),
            subnet_id,
            state: input.state.as_str().to_owned(),
            hostname: host,
            description,
            device,
            location_id: input.location_id,
            dns: input.dns,
        };
        upsert(&tx, &row)?;
        tx.commit().map_err(sql)?;
        Ok(row)
    }

    /// Release an address: it becomes available again.
    ///
    /// # Errors
    /// The address is not valid.
    pub fn release(&mut self, ip: &str) -> Result<bool, String> {
        let ip: IpAddr = ip
            .trim()
            .parse()
            .map_err(|_| "ip must be an IP address".to_owned())?;
        let tx = self.write()?;
        let gone = tx
            .execute("DELETE FROM ipam_addresses WHERE ip = ?1", [ip.to_string()])
            .map_err(sql)?;
        bump(&tx)?;
        tx.commit().map_err(sql)?;
        Ok(gone > 0)
    }

    /// Pick a free address in the subnet and record it, atomically: the write lock is taken
    /// before the search, so concurrent requests cannot receive the same address. Skips
    /// addresses that are recorded, leased by DHCP, the gateway, the network and broadcast
    /// addresses, and anything inside a smaller subnet.
    ///
    /// # Errors
    /// The subnet does not exist, has no free address, or a field is invalid.
    pub fn allocate(
        &mut self,
        subnet_id: i64,
        input: &AllocateInput,
        leased: &[Leased],
    ) -> Result<AddressRow, String> {
        let tx = self.write()?;
        let all = subnets_in(&tx)?;
        let subnet = all
            .iter()
            .find(|s| s.id == subnet_id)
            .ok_or("no such subnet")?;
        let net: IpNet = subnet
            .cidr
            .parse()
            .map_err(|_| "stored subnet is invalid".to_owned())?;
        let mut blocked: Vec<(u128, u128)> = Vec::new();
        {
            let mut statement = tx
                .prepare("SELECT ip FROM ipam_addresses WHERE subnet_id = ?1")
                .map_err(sql)?;
            let rows = statement
                .query_map([subnet_id], |r| r.get::<_, String>(0))
                .map_err(sql)?;
            for ip in rows {
                if let Ok(ip) = ip.map_err(sql)?.parse::<IpAddr>() {
                    blocked.push((to_num(ip), to_num(ip)));
                }
            }
        }
        for lease in leased.iter().filter(|l| net.contains(&l.ip)) {
            blocked.push((to_num(lease.ip), to_num(lease.ip)));
        }
        if let Some(gateway) = subnet
            .gateway
            .as_deref()
            .and_then(|g| g.parse::<IpAddr>().ok())
        {
            blocked.push((to_num(gateway), to_num(gateway)));
        }
        for other in &all {
            if let Ok(inner) = other.cidr.parse::<IpNet>()
                && contains(&net, &inner)
            {
                blocked.push(block(&inner));
            }
        }
        let (first, last) = usable(&net);
        let number = alloc::pick(first, last, &blocked, input.strategy)
            .ok_or("the subnet has no free address left")?;
        let ip = from_num(&net, number);
        let (host, description, device) = Self::address_fields(
            &tx,
            ip,
            input.hostname.as_deref(),
            &input.description,
            &input.device,
            input.location_id,
            input.dns,
        )?;
        if count(&tx, "ipam_addresses")? >= MAX_ADDRESSES {
            return Err("too many addresses".into());
        }
        let row = AddressRow {
            ip: ip.to_string(),
            subnet_id,
            state: input.state.as_str().to_owned(),
            hostname: host,
            description,
            device,
            location_id: input.location_id,
            dns: input.dns,
        };
        upsert(&tx, &row)?;
        tx.commit().map_err(sql)?;
        Ok(row)
    }

    /// The address inventory: what IPAM recorded plus what DHCP leases, and, when a single
    /// subnet and the `available` state are asked for, some free addresses. At most `limit`
    /// rows.
    ///
    /// # Errors
    /// The database failed.
    pub fn addresses(
        &self,
        filter: &AddressFilter,
        leased: &[Leased],
        limit: usize,
    ) -> Result<Vec<AddressRow>, String> {
        let nets = nets_in(&self.conn)?;
        let mut rows = stored_addresses(&self.conn)?;
        let recorded: HashSet<String> = rows.iter().map(|r| r.ip.clone()).collect();
        for lease in leased {
            if recorded.contains(&lease.ip.to_string()) {
                continue;
            }
            if let Some((subnet_id, _)) = subnet_for(&nets, lease.ip) {
                rows.push(AddressRow {
                    ip: lease.ip.to_string(),
                    subnet_id,
                    state: "leased".into(),
                    hostname: lease.hostname.clone(),
                    description: String::new(),
                    device: String::new(),
                    location_id: None,
                    dns: false,
                });
            }
        }
        if filter.state.as_deref() == Some("available")
            && let Some(subnet_id) = filter.subnet_id
            && let Some((_, net)) = nets.iter().find(|(id, _)| *id == subnet_id)
        {
            let blocked = blocked_for(&self.conn, subnet_id, net, &rows, &nets)?;
            let (first, last) = usable(net);
            let mut room = limit;
            'fill: for (low, high) in alloc::gaps(first, last, &blocked) {
                let mut at = low;
                while at <= high {
                    if room == 0 {
                        break 'fill;
                    }
                    room -= 1;
                    rows.push(AddressRow {
                        ip: from_num(net, at).to_string(),
                        subnet_id,
                        state: "available".into(),
                        hostname: None,
                        description: String::new(),
                        device: String::new(),
                        location_id: None,
                        dns: false,
                    });
                    at += 1;
                }
            }
        }
        let query = filter.query.trim().to_ascii_lowercase();
        rows.retain(|row| {
            filter.subnet_id.is_none_or(|id| row.subnet_id == id)
                && filter
                    .location_id
                    .is_none_or(|id| row.location_id == Some(id))
                && filter.state.as_deref().is_none_or(|s| row.state == s)
                && (query.is_empty()
                    || [&row.ip, &row.description, &row.device]
                        .iter()
                        .any(|f| f.to_ascii_lowercase().contains(&query))
                    || row.hostname.as_deref().is_some_and(|h| h.contains(&query)))
        });
        rows.sort_by_key(|row| {
            row.ip
                .parse::<IpAddr>()
                .map_or((7, 0), |ip| (family(ip), to_num(ip)))
        });
        rows.truncate(limit);
        Ok(rows)
    }

    /// Every subnet's utilization, and the totals.
    ///
    /// # Errors
    /// The database failed.
    pub fn overview(&self, leased: &[Leased]) -> Result<Overview, String> {
        let subnets = self.subnets()?;
        let rows = stored_addresses(&self.conn)?;
        let nets: Vec<(i64, IpNet)> = subnets
            .iter()
            .filter_map(|s| s.cidr.parse().ok().map(|n| (s.id, n)))
            .collect();
        let recorded: HashSet<&str> = rows.iter().map(|r| r.ip.as_str()).collect();
        let mut counts: HashMap<i64, (u64, u64, u64)> = HashMap::new();
        for row in &rows {
            let entry = counts.entry(row.subnet_id).or_default();
            if row.state == "reserved" {
                entry.1 += 1;
            } else {
                entry.0 += 1;
            }
        }
        for lease in leased {
            if recorded.contains(lease.ip.to_string().as_str()) {
                continue;
            }
            if let Some((id, _)) = subnet_for(&nets, lease.ip) {
                counts.entry(id).or_default().2 += 1;
            }
        }
        // A gateway nobody recorded still occupies its address: count it as reserved.
        for subnet in &subnets {
            if let Some(gateway) = subnet.gateway.as_deref()
                && !recorded.contains(gateway)
                && !leased.iter().any(|l| l.ip.to_string() == gateway)
            {
                counts.entry(subnet.id).or_default().1 += 1;
            }
        }
        let mut stats = Vec::new();
        for subnet in &subnets {
            let Some((_, net)) = nets.iter().find(|(id, _)| *id == subnet.id) else {
                continue;
            };
            let (assigned, reserved, dhcp) = counts.get(&subnet.id).copied().unwrap_or_default();
            let size = usable_count(net);
            let delegated: u128 = subnets
                .iter()
                .filter(|s| s.parent_id == Some(subnet.id))
                .filter_map(|s| s.cidr.parse::<IpNet>().ok())
                .map(|n| block_count(&n))
                .sum();
            let used = u128::from(assigned + reserved + dhcp);
            let room = size.saturating_sub(delegated);
            #[allow(clippy::cast_precision_loss)]
            let percent = if room == 0 {
                0.0
            } else {
                ((used as f64 / room as f64) * 100.0).min(100.0)
            };
            stats.push(SubnetStats {
                subnet_id: subnet.id,
                cidr: subnet.cidr.clone(),
                size: size.to_string(),
                assigned,
                reserved,
                leased: dhcp,
                delegated: delegated.to_string(),
                free: room.saturating_sub(used).to_string(),
                percent_used: (percent * 10.0).round() / 10.0,
            });
        }
        Ok(Overview {
            assigned: stats.iter().map(|s| s.assigned).sum(),
            reserved: stats.iter().map(|s| s.reserved).sum(),
            leased: stats.iter().map(|s| s.leased).sum(),
            vlans: count(&self.conn, "ipam_vlans")?,
            locations: count(&self.conn, "ipam_locations")?,
            subnets: stats,
        })
    }

    /// Records that cannot both be right: an address IPAM holds that DHCP also leases, and a
    /// name IPAM gave to one address that DHCP gave to another.
    ///
    /// # Errors
    /// The database failed.
    pub fn conflicts(&self, leased: &[Leased]) -> Result<Vec<Conflict>, String> {
        let rows = stored_addresses(&self.conn)?;
        let mut found = Vec::new();
        for row in &rows {
            let Ok(ip) = row.ip.parse::<IpAddr>() else {
                continue;
            };
            if leased.iter().any(|l| l.ip == ip) {
                found.push(Conflict {
                    kind: "leased-and-assigned".into(),
                    ip: row.ip.clone(),
                    detail: format!(
                        "IPAM records this address as {}, and DHCP leases it",
                        row.state
                    ),
                });
            }
            if let Some(host) = &row.hostname {
                for lease in leased {
                    let theirs = lease.hostname.as_deref().map(str::to_ascii_lowercase);
                    let first = theirs.as_deref().and_then(|h| h.split('.').next());
                    if lease.ip != ip
                        && lease.ip.is_ipv4() == ip.is_ipv4()
                        && (theirs.as_deref() == Some(host.as_str())
                            || first == Some(host.as_str()))
                    {
                        found.push(Conflict {
                            kind: "name-held-by-dhcp".into(),
                            ip: row.ip.clone(),
                            detail: format!("DHCP gave the name {host} to {}", lease.ip),
                        });
                    }
                }
            }
        }
        Ok(found)
    }

    /// A small value shared between the daemon and the management API.
    ///
    /// # Errors
    /// The database failed.
    pub fn meta(&self, key: &str) -> Result<Option<String>, String> {
        self.conn
            .query_row("SELECT value FROM ipam_meta WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()
            .map_err(sql)
    }

    /// # Errors
    /// The database failed.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO ipam_meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = ?2",
                params![key, value],
            )
            .map_err(sql)?;
        Ok(())
    }

    /// How many times an address was changed. DNS is refreshed when this moves.
    ///
    /// # Errors
    /// The database failed.
    pub fn generation(&self) -> Result<u64, String> {
        Ok(self
            .meta("generation")?
            .and_then(|v| v.parse().ok())
            .unwrap_or(0))
    }

    /// Remember which addresses a DHCP server holds, so callers that cannot ask the server (the
    /// management API) still keep clear of them.
    ///
    /// # Errors
    /// The database failed.
    pub fn replace_leases(&mut self, leased: &[Leased]) -> Result<(), String> {
        let tx = self.write()?;
        tx.execute("DELETE FROM ipam_leases", []).map_err(sql)?;
        for lease in leased {
            tx.execute(
                "INSERT OR REPLACE INTO ipam_leases (ip, hostname) VALUES (?1, ?2)",
                params![lease.ip.to_string(), lease.hostname],
            )
            .map_err(sql)?;
        }
        tx.commit().map_err(sql)
    }

    /// The addresses last reported as leased.
    ///
    /// # Errors
    /// The database failed.
    pub fn leased(&self) -> Result<Vec<Leased>, String> {
        let mut statement = self
            .conn
            .prepare("SELECT ip, hostname FROM ipam_leases")
            .map_err(sql)?;
        let rows: Vec<(String, Option<String>)> = statement
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(sql)?
            .collect::<Result<_, _>>()
            .map_err(sql)?;
        Ok(rows
            .into_iter()
            .filter_map(|(ip, hostname)| {
                Some(Leased {
                    ip: ip.parse().ok()?,
                    hostname,
                })
            })
            .collect())
    }

    /// Names to publish in DNS: every address with a host name and DNS publishing on.
    ///
    /// # Errors
    /// The database failed.
    pub fn dns_entries(&self) -> Result<Vec<(String, IpAddr)>, String> {
        Ok(stored_addresses(&self.conn)?
            .into_iter()
            .filter(|row| row.dns)
            .filter_map(|row| Some((row.hostname?, row.ip.parse().ok()?)))
            .collect())
    }
}

// ---- helpers shared by the methods above ----

fn count(conn: &Connection, table: &str) -> Result<usize, String> {
    let total: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .map_err(sql)?;
    Ok(usize::try_from(total).unwrap_or(usize::MAX))
}

fn exists(conn: &Connection, table: &str, id: i64) -> Result<bool, String> {
    let found: Option<i64> = conn
        .query_row(&format!("SELECT 1 FROM {table} WHERE id = ?1"), [id], |r| {
            r.get(0)
        })
        .optional()
        .map_err(sql)?;
    Ok(found.is_some())
}

fn location_fields(input: &LocationInput) -> Result<(String, String, String), String> {
    if !LOCATION_KINDS.contains(&input.kind.as_str()) {
        return Err(format!("kind must be one of {}", LOCATION_KINDS.join(", ")));
    }
    Ok((
        input.kind.clone(),
        text("name", &input.name, 64, true)?,
        text("description", &input.description, 500, false)?,
    ))
}

/// The parent must exist and must not be the location itself or one of its descendants.
fn check_parent(conn: &Connection, id: Option<i64>, parent: Option<i64>) -> Result<(), String> {
    let Some(mut at) = parent else { return Ok(()) };
    if !exists(conn, "ipam_locations", at)? {
        return Err("no such parent location".into());
    }
    for _ in 0..1000 {
        if Some(at) == id {
            return Err("a location cannot be inside itself".into());
        }
        let up: Option<Option<i64>> = conn
            .query_row(
                "SELECT parent_id FROM ipam_locations WHERE id = ?1",
                [at],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        match up.flatten() {
            Some(next) => at = next,
            None => return Ok(()),
        }
    }
    Err("the location tree is too deep".into())
}

fn locations_in(conn: &Connection) -> Result<Vec<Location>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, parent_id, kind, name, description FROM ipam_locations ORDER BY name, id",
        )
        .map_err(sql)?;
    statement
        .query_map([], |row| {
            Ok(Location {
                id: row.get(0)?,
                parent_id: row.get(1)?,
                kind: row.get(2)?,
                name: row.get(3)?,
                description: row.get(4)?,
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
}

fn nets_in(conn: &Connection) -> Result<Vec<(i64, IpNet)>, String> {
    let mut statement = conn
        .prepare("SELECT id, cidr FROM ipam_subnets")
        .map_err(sql)?;
    let rows: Vec<(i64, String)> = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, cidr)| cidr.parse().ok().map(|n| (id, n)))
        .collect())
}

/// The most specific managed subnet that holds the address.
fn subnet_for(nets: &[(i64, IpNet)], ip: IpAddr) -> Option<(i64, IpNet)> {
    nets.iter()
        .filter(|(_, net)| net.contains(&ip))
        .max_by_key(|(_, net)| net.prefix_len())
        .map(|(id, net)| (*id, *net))
}

fn subnets_in(conn: &Connection) -> Result<Vec<Subnet>, String> {
    let mut statement = conn
        .prepare(
            "SELECT id, cidr, name, description, grp, vlan_id, location_id, gateway, metadata
             FROM ipam_subnets ORDER BY id",
        )
        .map_err(sql)?;
    let mut subnets: Vec<Subnet> = statement
        .query_map([], |row| {
            let metadata: String = row.get(8)?;
            Ok(Subnet {
                id: row.get(0)?,
                cidr: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                group: row.get(4)?,
                vlan_id: row.get(5)?,
                location_id: row.get(6)?,
                gateway: row.get(7)?,
                metadata: serde_json::from_str(&metadata).unwrap_or_default(),
                parent_id: None,
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)?;
    let nets: Vec<Option<IpNet>> = subnets.iter().map(|s| s.cidr.parse().ok()).collect();
    for index in 0..subnets.len() {
        let Some(mine) = nets[index] else { continue };
        subnets[index].parent_id = nets
            .iter()
            .enumerate()
            .filter_map(|(other, net)| net.filter(|n| contains(n, &mine)).map(|n| (other, n)))
            .max_by_key(|(_, n)| n.prefix_len())
            .map(|(other, _)| subnets[other].id);
    }
    subnets.sort_by_key(|s| {
        s.cidr.parse::<IpNet>().map_or((7, 0, 0), |n| {
            (family(n.network()), to_num(n.network()), n.prefix_len())
        })
    });
    Ok(subnets)
}

fn stored_addresses(conn: &Connection) -> Result<Vec<AddressRow>, String> {
    let mut statement = conn
        .prepare(
            "SELECT ip, subnet_id, state, hostname, description, device, location_id, dns
             FROM ipam_addresses",
        )
        .map_err(sql)?;
    statement
        .query_map([], |row| {
            Ok(AddressRow {
                ip: row.get(0)?,
                subnet_id: row.get(1)?,
                state: row.get(2)?,
                hostname: row.get(3)?,
                description: row.get(4)?,
                device: row.get(5)?,
                location_id: row.get(6)?,
                dns: row.get::<_, i64>(7)? != 0,
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
}

/// Counts changes to addresses, so a background task can tell when DNS needs refreshing.
fn bump(conn: &Connection) -> Result<(), String> {
    conn.execute(
        "INSERT INTO ipam_meta (key, value) VALUES ('generation', '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
        [],
    )
    .map_err(sql)?;
    Ok(())
}

fn upsert(tx: &Transaction<'_>, row: &AddressRow) -> Result<(), String> {
    bump(tx)?;
    tx.execute(
        "INSERT INTO ipam_addresses
             (ip, subnet_id, state, hostname, description, device, location_id, dns, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(ip) DO UPDATE SET subnet_id = ?2, state = ?3, hostname = ?4, description = ?5,
             device = ?6, location_id = ?7, dns = ?8, updated = ?9",
        params![
            row.ip,
            row.subnet_id,
            row.state,
            row.hostname,
            row.description,
            row.device,
            row.location_id,
            i64::from(row.dns),
            now()
        ],
    )
    .map_err(sql)?;
    Ok(())
}

/// Ranges that cannot be handed out in a subnet, for listing free addresses.
fn blocked_for(
    conn: &Connection,
    subnet_id: i64,
    net: &IpNet,
    rows: &[AddressRow],
    nets: &[(i64, IpNet)],
) -> Result<Vec<(u128, u128)>, String> {
    let mut blocked: Vec<(u128, u128)> = rows
        .iter()
        .filter_map(|r| r.ip.parse::<IpAddr>().ok())
        .filter(|ip| net.contains(ip))
        .map(|ip| (to_num(ip), to_num(ip)))
        .collect();
    for (_, other) in nets {
        if contains(net, other) {
            blocked.push(block(other));
        }
    }
    let gateway: Option<Option<String>> = conn
        .query_row(
            "SELECT gateway FROM ipam_subnets WHERE id = ?1",
            [subnet_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(gateway) = gateway.flatten().and_then(|g| g.parse::<IpAddr>().ok()) {
        blocked.push((to_num(gateway), to_num(gateway)));
    }
    Ok(blocked)
}

#[cfg(test)]
mod tests;

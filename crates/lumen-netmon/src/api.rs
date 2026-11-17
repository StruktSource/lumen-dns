//! The JSON routes of the network module, shared by the web console and the token-authenticated
//! management API. The caller authenticates, checks the module is on, and checks [`access`].

use crate::{
    model::{Device, DeviceFilter, DeviceInput, Link, LinkInput, Status},
    oui::Oui,
    store::{Netmon, now},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{collections::HashSet, path::Path};

const MAX_LISTED: usize = 5000;

/// What a route needs from the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Access {
    /// Read the inventory.
    Read,
    /// Ask for a discovery run.
    Operate,
    /// Change devices and links.
    Manage,
}

#[must_use]
#[allow(clippy::unnested_or_patterns)] // Flat match arms read best as a route table.
pub fn access(method: &str, parts: &[&str]) -> Option<Access> {
    match (method, parts) {
        ("GET", [] | ["devices" | "links" | "topology" | "events" | "scans" | "locations"])
        | (
            "GET",
            ["devices", _]
            | ["devices", _, "checks" | "interfaces"]
            | ["devices", _, "interfaces", _, "history"],
        ) => Some(Access::Read),
        ("POST", ["scan"]) => Some(Access::Operate),
        ("POST", ["devices" | "links"])
        | ("PUT" | "DELETE", ["devices" | "links", _])
        | ("POST", ["devices", _, "merge" | "ipam"])
        | ("DELETE", ["devices", _, "addresses", _]) => Some(Access::Manage),
        _ => None,
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    /// The path after `network/`, split at `/`.
    pub parts: &'a [&'a str],
    pub query: &'a str,
    pub body: &'a [u8],
    /// The state database, where IPAM keeps subnets, VLANs and locations.
    pub state: &'a Path,
    /// The IPAM module is on, so devices can be recorded there.
    pub ipam_enabled: bool,
    /// What the daemon says about discovery (scopes, intervals, ICMP).
    pub engine: Option<Value>,
}

pub struct Outcome {
    pub status: u16,
    pub body: Value,
    pub audit: Option<(&'static str, String)>,
}

impl Outcome {
    fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            audit: None,
        }
    }
    fn error(status: u16, message: &str) -> Self {
        Self::json(status, json!({ "error": message }))
    }
    fn fail(message: &str) -> Self {
        if message.starts_with("the network database failed")
            || message.starts_with("the IPAM database failed")
        {
            Self::error(500, message)
        } else {
            Self::error(400, message)
        }
    }
    fn of<T: serde::Serialize>(result: Result<T, String>) -> Self {
        match result {
            Ok(v) => Self::json(200, serde_json::to_value(v).unwrap_or(Value::Null)),
            Err(m) => Self::fail(&m),
        }
    }
    fn done<T: serde::Serialize>(
        result: Result<T, String>,
        action: &'static str,
        target: String,
    ) -> Self {
        match result {
            Ok(v) => {
                let mut out = Self::of(Ok(v));
                out.audit = Some((action, target));
                out
            }
            Err(m) => Self::fail(&m),
        }
    }
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status < 300
    }
}

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, Outcome> {
    serde_json::from_slice(body).map_err(|e| Outcome::error(400, &format!("invalid request: {e}")))
}

fn id(text: &str) -> Result<i64, Outcome> {
    text.parse()
        .map_err(|_| Outcome::error(400, "the id must be a number"))
}

fn decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let Some(byte) = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(byte);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).chars().take(100).collect()
}

fn param(query: &str, key: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| decode(v))
        .filter(|v| !v.is_empty())
}

/// Add each device's IPAM subnet and VLAN, when IPAM knows its address.
fn place(devices: &mut [Device], state: &Path) {
    let Ok(ipam) = lumen_ipam::Ipam::open(state) else {
        return;
    };
    for device in devices {
        let found = device
            .addresses
            .iter()
            .filter_map(|a| a.ip.parse().ok())
            .find_map(|ip| ipam.locate(ip).ok().flatten());
        if let Some(p) = found {
            device.subnet = Some(p.cidr);
            device.vlan = p.vlan;
            if device.location_id.is_none() {
                device.location_id = p.location_id;
            }
        }
    }
}

/// How devices are ordered in lists.
fn sort(devices: &mut [Device], key: &str, direction: Option<&str>) {
    // Times default to newest first, everything else to ascending.
    let descending = match direction {
        Some("desc") => true,
        Some("asc") => false,
        _ => !matches!(key, "name" | "status" | "kind" | "ip"),
    };
    match key {
        "name" => devices.sort_by_key(|d| d.name.to_ascii_lowercase()),
        "status" => devices.sort_by_key(|d| match d.status {
            Status::Offline => 0,
            Status::Degraded => 1,
            Status::Unknown => 2,
            Status::Online => 3,
        }),
        "kind" => devices.sort_by(|a, b| (&a.kind, &a.name).cmp(&(&b.kind, &b.name))),
        "ip" => devices.sort_by_key(|d| {
            d.addresses
                .first()
                .and_then(|a| a.ip.parse::<std::net::IpAddr>().ok())
                .map_or((7, 0), |ip| match ip {
                    std::net::IpAddr::V4(v4) => (4, u128::from(u32::from(v4))),
                    std::net::IpAddr::V6(v6) => (6, u128::from(v6)),
                })
        }),
        "first_seen" => devices.sort_by_key(|d| d.first_seen),
        _ => devices.sort_by_key(|d| d.last_seen),
    }
    if descending {
        devices.reverse();
    }
}

fn filter(query: &str) -> (DeviceFilter, Option<String>, Option<String>) {
    let f = DeviceFilter {
        query: param(query, "q").unwrap_or_default(),
        kind: param(query, "kind"),
        status: param(query, "status"),
        location_id: param(query, "location").and_then(|v| v.parse().ok()),
        subnet: param(query, "subnet"),
        include_gone: param(query, "gone").as_deref() == Some("1"),
    };
    (f, param(query, "vlan"), param(query, "sort"))
}

/// The devices a request asks for, with IPAM placement, filtered by subnet and VLAN too.
fn listing(nm: &Netmon, query: &str, state: &Path) -> Result<Vec<Device>, String> {
    let (f, vlan, _) = filter(query);
    let mut devices = nm.devices(&f)?;
    place(&mut devices, state);
    devices.retain(|d| {
        f.subnet
            .as_deref()
            .is_none_or(|s| d.subnet.as_deref() == Some(s))
            && vlan
                .as_deref()
                .is_none_or(|v| d.vlan.as_deref().is_some_and(|dv| dv.contains(v)))
            && f.location_id.is_none_or(|l| d.location_id == Some(l))
    });
    Ok(devices)
}

/// The topology: devices as nodes, links between them. Each link says whether it is confirmed
/// (reported by a device or set by an administrator) or only inferred.
fn topology(nm: &Netmon, query: &str, state: &Path) -> Result<Value, String> {
    let devices = listing(nm, query, state)?;
    let shown: HashSet<i64> = devices.iter().map(|d| d.id).collect();
    let links: Vec<Link> = nm
        .links()?
        .into_iter()
        .filter(|l| shown.contains(&l.a_device) && shown.contains(&l.b_device))
        .collect();
    let mut degree = std::collections::HashMap::<i64, usize>::new();
    for l in &links {
        *degree.entry(l.a_device).or_default() += 1;
        *degree.entry(l.b_device).or_default() += 1;
    }
    let nodes: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "id": d.id, "name": d.name, "kind": d.kind, "icon": d.icon, "status": d.status,
                "ip": d.addresses.first().map(|a| a.ip.clone()), "hostname": d.hostname,
                "vendor": d.vendor, "subnet": d.subnet, "vlan": d.vlan, "location_id": d.location_id,
                "links": degree.get(&d.id).copied().unwrap_or(0),
            })
        })
        .collect();
    let interfaces: std::collections::HashMap<(i64, String), Value> = {
        let mut m = std::collections::HashMap::new();
        for d in &devices {
            for i in nm.interfaces(d.id)? {
                m.insert((d.id, i.name.clone()), json!({ "speed_bps": i.speed_bps, "utilization_percent": i.utilization_percent, "in_bps": i.in_bps, "out_bps": i.out_bps, "oper_up": i.oper_up }));
            }
        }
        m
    };
    let edges: Vec<Value> = links
        .iter()
        .map(|l| {
            json!({
                "id": l.id, "a": l.a_device, "a_port": l.a_port, "b": l.b_device, "b_port": l.b_port,
                "kind": l.kind, "confirmed": l.confirmed, "speed_mbps": l.speed_mbps,
                "a_stats": interfaces.get(&(l.a_device, l.a_port.clone())),
                "b_stats": interfaces.get(&(l.b_device, l.b_port.clone())),
            })
        })
        .collect();
    Ok(json!({ "nodes": nodes, "links": edges }))
}

/// One device with everything recorded about it.
fn detail(nm: &Netmon, device_id: i64, state: &Path) -> Result<Option<Value>, String> {
    let mut devices: Vec<Device> = nm.device(device_id)?.into_iter().collect();
    place(&mut devices, state);
    let Some(device) = devices.pop() else {
        return Ok(None);
    };
    let day = now() - 86_400;
    let week = now() - 7 * 86_400;
    let links: Vec<Link> = nm
        .links()?
        .into_iter()
        .filter(|l| l.a_device == device_id || l.b_device == device_id)
        .collect();
    Ok(Some(json!({
        "device": device,
        "interfaces": nm.interfaces(device_id)?,
        "checks": nm.checks(device_id, day, 200)?,
        "availability_24h": nm.availability(device_id, day)?,
        "availability_7d": nm.availability(device_id, week)?,
        "events": nm.events(Some(device_id), 50)?,
        "links": links,
    })))
}

#[must_use]
pub fn handle(request: &Request<'_>) -> Outcome {
    match run(request) {
        Ok(o) | Err(o) => o,
    }
}

#[allow(clippy::too_many_lines)]
fn run(request: &Request<'_>) -> Result<Outcome, Outcome> {
    let mut nm = Netmon::open(request.state).map_err(|m| Outcome::fail(&m))?;
    let query = request.query;
    let body = request.body;
    let oui = Oui::new();
    Ok(match (request.method, request.parts) {
        ("GET", []) => {
            let counts = nm.counts().map_err(|m| Outcome::fail(&m))?;
            Outcome::json(
                200,
                json!({
                    "counts": counts,
                    "engine": request.engine,
                    "scans": nm.scans(5).map_err(|m| Outcome::fail(&m))?,
                    "events": nm.events(None, 20).map_err(|m| Outcome::fail(&m))?,
                    "ipam": request.ipam_enabled,
                }),
            )
        }
        ("GET", ["devices"]) => {
            let (_, _, key) = filter(query);
            let mut devices = listing(&nm, query, request.state).map_err(|m| Outcome::fail(&m))?;
            sort(
                &mut devices,
                key.as_deref().unwrap_or("last_seen"),
                param(query, "dir").as_deref(),
            );
            let limit = param(query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1000)
                .clamp(1, MAX_LISTED);
            let offset = param(query, "offset")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let total = devices.len();
            let page: Vec<Device> = devices.into_iter().skip(offset).take(limit).collect();
            Outcome::json(200, json!({ "total": total, "devices": page }))
        }
        ("GET", ["devices", raw]) => match detail(&nm, id(raw)?, request.state) {
            Ok(Some(v)) => Outcome::json(200, v),
            Ok(None) => Outcome::error(404, "not found"),
            Err(m) => Outcome::fail(&m),
        },
        ("GET", ["devices", raw, "checks"]) => {
            let since = param(query, "since")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(now() - 86_400);
            let limit = param(query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(500);
            Outcome::of(nm.checks(id(raw)?, since, limit))
        }
        ("GET", ["devices", raw, "interfaces"]) => Outcome::of(nm.interfaces(id(raw)?)),
        ("GET", ["devices", raw, "interfaces", index, "history"]) => {
            let since = param(query, "since")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(now() - 86_400);
            let limit = param(query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(500);
            Outcome::of(nm.interface_history(id(raw)?, id(index)?, since, limit))
        }
        ("GET", ["links"]) => Outcome::of(nm.links()),
        ("GET", ["topology"]) => Outcome::of(topology(&nm, query, request.state)),
        ("GET", ["events"]) => {
            let limit = param(query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100);
            Outcome::of(nm.events(param(query, "device").and_then(|v| v.parse().ok()), limit))
        }
        ("GET", ["scans"]) => Outcome::of(nm.scans(30)),
        ("GET", ["locations"]) => {
            Outcome::of(lumen_ipam::Ipam::open(request.state).and_then(|i| i.locations()))
        }
        ("POST", ["scan"]) => match nm.request_scan() {
            Ok(()) => {
                let mut o = Outcome::json(200, json!({ "requested": true }));
                o.audit = Some(("network.scan", "all scopes".into()));
                o
            }
            Err(m) => Outcome::fail(&m),
        },
        ("POST", ["devices"]) => {
            let input: DeviceInput = parse(body)?;
            Outcome::done(
                nm.add_device(&input, &oui),
                "network.device.add",
                input.name,
            )
        }
        ("PUT", ["devices", raw]) => {
            let (n, input) = (id(raw)?, parse::<DeviceInput>(body)?);
            Outcome::done(
                nm.update_device(n, &input, &oui),
                "network.device.edit",
                input.name,
            )
        }
        ("DELETE", ["devices", raw]) => match nm.delete_device(id(raw)?) {
            Ok(true) => {
                let mut o = Outcome::json(200, json!({ "deleted": true }));
                o.audit = Some(("network.device.delete", (*raw).to_owned()));
                o
            }
            Ok(false) => Outcome::error(404, "not found"),
            Err(m) => Outcome::fail(&m),
        },
        ("POST", ["devices", raw, "merge"]) => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Merge {
                other: i64,
            }
            let (keep, merge) = (id(raw)?, parse::<Merge>(body)?);
            Outcome::done(
                nm.merge(keep, merge.other),
                "network.device.merge",
                format!("{keep}+{}", merge.other),
            )
        }
        ("DELETE", ["devices", raw, "addresses", value]) => {
            let value = decode(value);
            match nm.detach(id(raw)?, &value) {
                Ok(true) => {
                    let mut o = Outcome::json(200, json!({ "deleted": true }));
                    o.audit = Some(("network.device.detach", value));
                    o
                }
                Ok(false) => Outcome::error(404, "not found"),
                Err(m) => Outcome::fail(&m),
            }
        }
        ("POST", ["devices", raw, "ipam"]) => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Record {
                ip: String,
                #[serde(default)]
                dns: bool,
            }
            let (n, record) = (id(raw)?, parse::<Record>(body)?);
            if !request.ipam_enabled {
                return Err(Outcome::error(400, "the IPAM module is off"));
            }
            let device = nm
                .device(n)
                .map_err(|m| Outcome::fail(&m))?
                .ok_or_else(|| Outcome::error(404, "not found"))?;
            if !device.addresses.iter().any(|a| a.ip == record.ip.trim()) {
                return Err(Outcome::error(
                    400,
                    "that address does not belong to this device",
                ));
            }
            let mut ipam = lumen_ipam::Ipam::open(request.state).map_err(|m| Outcome::fail(&m))?;
            let leased = ipam.leased().unwrap_or_default();
            let input = lumen_ipam::AddressInput {
                ip: record.ip,
                state: lumen_ipam::AddressState::Assigned,
                hostname: device.hostname.clone().or_else(|| {
                    // A device name that is already a valid host name.
                    device
                        .name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-')
                        .then(|| device.name.clone())
                }),
                description: device.description.clone(),
                device: device.name.clone(),
                location_id: device.location_id,
                dns: record.dns,
            };
            Outcome::done(
                ipam.set_address(&input, &leased),
                "network.device.ipam",
                device.name,
            )
        }
        ("POST", ["links"]) => {
            let input: LinkInput = parse(body)?;
            Outcome::done(
                nm.add_link(&input),
                "network.link.add",
                format!("{}-{}", input.a_device, input.b_device),
            )
        }
        ("PUT", ["links", raw]) => {
            let (n, input) = (id(raw)?, parse::<LinkInput>(body)?);
            Outcome::done(
                nm.update_link(n, &input),
                "network.link.edit",
                (*raw).to_owned(),
            )
        }
        ("DELETE", ["links", raw]) => match nm.delete_link(id(raw)?) {
            Ok(true) => {
                let mut o = Outcome::json(200, json!({ "deleted": true }));
                o.audit = Some(("network.link.delete", (*raw).to_owned()));
                o
            }
            Ok(false) => Outcome::error(404, "not found"),
            Err(m) => Outcome::fail(&m),
        },
        _ => Outcome::error(404, "not found"),
    })
}

//! The JSON routes of IPAM, shared by the web console and the token-authenticated management
//! API, so both behave the same.
//!
//! The caller authenticates the request, checks the module is on, and checks the role against
//! [`access`]. This module only turns a request into a result.

use crate::{
    AddressFilter, AddressInput, AllocateInput, Ipam, Leased, LocationInput, SubnetInput, VlanInput,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

/// Most rows one address listing returns.
const MAX_LISTED: usize = 2000;

/// What a route needs from the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Access {
    /// Read the inventory.
    Read,
    /// Assign, reserve, allocate and release addresses.
    Address,
    /// Change subnets, VLANs and locations.
    Structure,
}

/// The access a route needs, or `None` when there is no such route.
#[must_use]
pub fn access(method: &str, parts: &[&str]) -> Option<Access> {
    match (method, parts) {
        ("GET", [] | ["locations" | "vlans" | "subnets" | "addresses" | "conflicts"]) => {
            Some(Access::Read)
        }
        ("PUT", ["addresses"])
        | ("POST", ["subnets", _, "allocate"])
        | ("DELETE", ["addresses", _]) => Some(Access::Address),
        ("POST", ["locations" | "vlans" | "subnets"])
        | ("PUT" | "DELETE", ["locations" | "vlans" | "subnets", _]) => Some(Access::Structure),
        _ => None,
    }
}

pub struct Request<'a> {
    pub method: &'a str,
    /// The path after `ipam/`, split at `/`.
    pub parts: &'a [&'a str],
    /// The raw query string, without the `?`.
    pub query: &'a str,
    pub body: &'a [u8],
    /// The addresses a DHCP server holds right now.
    pub leased: &'a [Leased],
    /// Whether a DHCP server is running.
    pub dhcp: bool,
}

pub struct Outcome {
    pub status: u16,
    pub body: Value,
    /// An audit action and target for a change that was made.
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
    /// A refusal is the caller's mistake; a failed database is ours.
    fn fail(message: &str) -> Self {
        if message.starts_with("the IPAM database failed") {
            Self::error(500, message)
        } else {
            Self::error(400, message)
        }
    }
    fn of<T: Serialize>(result: Result<T, String>) -> Self {
        match result {
            Ok(value) => Self::json(200, serde_json::to_value(value).unwrap_or(Value::Null)),
            Err(message) => Self::fail(&message),
        }
    }
    fn changed<T: Serialize>(
        result: Result<T, String>,
        action: &'static str,
        target: impl FnOnce(&T) -> String,
    ) -> Self {
        match result {
            Ok(value) => {
                let target = target(&value);
                let mut out = Self::of(Ok(value));
                out.audit = Some((action, target));
                out
            }
            Err(message) => Self::fail(&message),
        }
    }
    fn deleted(result: Result<bool, String>, action: &'static str, target: &str) -> Self {
        match result {
            Ok(true) => {
                let mut out = Self::json(200, json!({ "deleted": true }));
                out.audit = Some((action, target.to_owned()));
                out
            }
            Ok(false) => Self::error(404, "not found"),
            Err(message) => Self::fail(&message),
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

fn number(text: &str) -> Result<i64, Outcome> {
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

/// Run one request against the inventory. The caller has already allowed it.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn handle(ipam: &mut Ipam, request: &Request<'_>) -> Outcome {
    match run(ipam, request) {
        Ok(outcome) | Err(outcome) => outcome,
    }
}

fn dns_allowed(ipam: &Ipam, wanted: bool) -> Result<(), Outcome> {
    let configured = ipam
        .meta("dns_domain")
        .ok()
        .flatten()
        .is_some_and(|d| !d.is_empty());
    if wanted && !configured {
        return Err(Outcome::error(
            400,
            "DNS publishing needs ipam.dns_domain in the configuration",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run(ipam: &mut Ipam, request: &Request<'_>) -> Result<Outcome, Outcome> {
    let leased = request.leased;
    let body = request.body;
    Ok(match (request.method, request.parts) {
        ("GET", []) => match ipam.overview(leased) {
            Ok(overview) => Outcome::json(
                200,
                json!({
                    "overview": overview,
                    "dhcp": request.dhcp,
                    "dns_domain": ipam.meta("dns_domain").ok().flatten().filter(|d| !d.is_empty()),
                }),
            ),
            Err(message) => Outcome::fail(&message),
        },
        ("GET", ["locations"]) => Outcome::of(ipam.locations()),
        ("POST", ["locations"]) => {
            let input: LocationInput = parse(body)?;
            Outcome::changed(ipam.add_location(&input), "ipam.location.add", |v| {
                v.name.clone()
            })
        }
        ("PUT", ["locations", id]) => {
            let (id, input) = (number(id)?, parse::<LocationInput>(body)?);
            Outcome::changed(
                ipam.update_location(id, &input),
                "ipam.location.edit",
                |v| v.name.clone(),
            )
        }
        ("DELETE", ["locations", id]) => Outcome::deleted(
            ipam.delete_location(number(id)?),
            "ipam.location.delete",
            id,
        ),
        ("GET", ["vlans"]) => Outcome::of(ipam.vlans()),
        ("POST", ["vlans"]) => {
            let input: VlanInput = parse(body)?;
            Outcome::changed(ipam.add_vlan(&input), "ipam.vlan.add", |v| {
                v.vid.to_string()
            })
        }
        ("PUT", ["vlans", id]) => {
            let (id, input) = (number(id)?, parse::<VlanInput>(body)?);
            Outcome::changed(ipam.update_vlan(id, &input), "ipam.vlan.edit", |v| {
                v.vid.to_string()
            })
        }
        ("DELETE", ["vlans", id]) => {
            Outcome::deleted(ipam.delete_vlan(number(id)?), "ipam.vlan.delete", id)
        }
        ("GET", ["subnets"]) => Outcome::of(ipam.subnets()),
        ("POST", ["subnets"]) => {
            let input: SubnetInput = parse(body)?;
            Outcome::changed(ipam.add_subnet(&input), "ipam.subnet.add", |v| {
                v.cidr.clone()
            })
        }
        ("PUT", ["subnets", id]) => {
            let (id, input) = (number(id)?, parse::<SubnetInput>(body)?);
            Outcome::changed(ipam.update_subnet(id, &input), "ipam.subnet.edit", |v| {
                v.cidr.clone()
            })
        }
        ("DELETE", ["subnets", id]) => {
            Outcome::deleted(ipam.delete_subnet(number(id)?), "ipam.subnet.delete", id)
        }
        ("POST", ["subnets", id, "allocate"]) => {
            let (id, input) = (number(id)?, parse::<AllocateInput>(body)?);
            dns_allowed(ipam, input.dns)?;
            Outcome::changed(
                ipam.allocate(id, &input, leased),
                "ipam.address.allocate",
                |v| v.ip.clone(),
            )
        }
        ("GET", ["addresses"]) => {
            let id = |key: &str| param(request.query, key).and_then(|v| v.parse::<i64>().ok());
            let filter = AddressFilter {
                subnet_id: id("subnet"),
                location_id: id("location"),
                state: param(request.query, "state"),
                query: param(request.query, "q").unwrap_or_default(),
            };
            let limit = param(request.query, "limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(500)
                .clamp(1, MAX_LISTED);
            Outcome::of(ipam.addresses(&filter, leased, limit))
        }
        ("PUT", ["addresses"]) => {
            let input: AddressInput = parse(body)?;
            dns_allowed(ipam, input.dns)?;
            Outcome::changed(ipam.set_address(&input, leased), "ipam.address.set", |v| {
                v.ip.clone()
            })
        }
        ("DELETE", ["addresses", ip]) => {
            let ip = decode(ip);
            Outcome::deleted(ipam.release(&ip), "ipam.address.release", &ip)
        }
        ("GET", ["conflicts"]) => Outcome::of(ipam.conflicts(leased)),
        _ => Outcome::error(404, "not found"),
    })
}

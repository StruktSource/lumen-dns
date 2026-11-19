//! The records the network module keeps and the requests it accepts.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_DEVICES: usize = 20_000;
pub const MAX_LINKS: usize = 50_000;
pub const MAX_ROOMS: usize = 1_024;

/// What a device is. Discovery guesses; an administrator can always set it.
pub const KINDS: &[&str] = &[
    "router",
    "switch",
    "access-point",
    "firewall",
    "server",
    "workstation",
    "laptop",
    "phone",
    "tablet",
    "printer",
    "nas",
    "camera",
    "tv",
    "iot",
    "other",
    "unknown",
];

/// Icons the console can draw. A device has one of these or none.
pub const ICONS: &[&str] = &[
    "router", "switch", "wifi", "shield", "server", "desktop", "laptop", "phone", "tablet",
    "printer", "storage", "camera", "tv", "chip", "device",
];

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Unknown,
    Online,
    Degraded,
    Offline,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Online => "online",
            Self::Degraded => "degraded",
            Self::Offline => "offline",
        }
    }
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text {
            "online" => Self::Online,
            "degraded" => Self::Degraded,
            "offline" => Self::Offline,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CheckMethod {
    #[default]
    Icmp,
    Tcp,
    Snmp,
}

impl CheckMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Snmp => "snmp",
        }
    }
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text {
            "tcp" => Self::Tcp,
            "snmp" => Self::Snmp,
            _ => Self::Icmp,
        }
    }
}

/// Settings of one device's availability monitoring.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Monitoring {
    pub enabled: bool,
    pub method: CheckMethod,
    /// The port a `tcp` check connects to.
    pub tcp_port: Option<u16>,
    /// Seconds between checks, or the module default.
    pub interval_secs: Option<u32>,
}

impl Default for Monitoring {
    fn default() -> Self {
        Self {
            enabled: true,
            method: CheckMethod::Icmp,
            tcp_port: None,
            interval_secs: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct DeviceAddress {
    pub ip: String,
    /// Where it was learned: `neighbor`, `icmp`, `dhcp`, `dns`, `snmp`, `manual`.
    pub source: String,
    pub last_seen: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct DeviceMac {
    pub mac: String,
    pub vendor: Option<String>,
    pub source: String,
    pub last_seen: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub hostname: Option<String>,
    pub kind: String,
    pub os: Option<String>,
    pub vendor: Option<String>,
    pub icon: Option<String>,
    pub description: String,
    pub notes: String,
    /// An IPAM location.
    pub location_id: Option<i64>,
    /// A room managed by this module. It does not require IPAM.
    pub room_id: Option<i64>,
    /// Created by an administrator rather than found.
    pub manual: bool,
    /// Fields an administrator set. Discovery never overwrites these.
    pub locked: Vec<String>,
    pub status: Status,
    pub first_seen: i64,
    pub last_seen: i64,
    /// The last time a check or discovery heard from the device.
    pub last_ok: Option<i64>,
    /// Missed discovery runs in a row passed the limit.
    pub gone: bool,
    pub monitoring: Monitoring,
    pub snmp_profile: Option<String>,
    pub addresses: Vec<DeviceAddress>,
    pub macs: Vec<DeviceMac>,
    /// Stable DHCP client identifiers attached to this identity.
    pub dhcp_ids: Vec<String>,
    /// `confirmed`, `probable`, or `uncertain`.
    pub identity_confidence: String,
    /// Facts read over SNMP, when available.
    pub sys: Option<SysInfo>,
    /// The IPAM subnet and VLAN of the first address, when IPAM knows it.
    pub subnet: Option<String>,
    pub vlan: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct SysInfo {
    pub name: Option<String>,
    pub descr: Option<String>,
    pub object_id: Option<String>,
    pub contact: Option<String>,
    pub location: Option<String>,
    pub uptime_secs: Option<u64>,
    /// The `sysServices` bit field (RFC 3418).
    pub services: Option<u32>,
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    pub temperature_c: Option<f64>,
    pub updated: i64,
}

/// What an administrator may set on a device.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInput {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub location_id: Option<i64>,
    #[serde(default)]
    pub room_id: Option<i64>,
    #[serde(default)]
    pub monitoring: Option<Monitoring>,
    #[serde(default)]
    pub snmp_profile: Option<String>,
    /// Addresses (and, when created by hand, MACs) to attach.
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub macs: Vec<String>,
    #[serde(default)]
    pub dhcp_ids: Vec<String>,
}

/// A user-managed room or area. Rooms may be nested.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Room {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomInput {
    #[serde(default)]
    pub parent_id: Option<i64>,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Link {
    pub id: i64,
    pub a_device: i64,
    pub a_port: String,
    pub b_device: i64,
    pub b_port: String,
    /// `lldp`, `snmp`, `manual`, or `inferred`.
    pub kind: String,
    /// Backed by device-reported data or set by an administrator. Inferred links are not.
    pub confirmed: bool,
    pub speed_mbps: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkInput {
    pub a_device: i64,
    #[serde(default)]
    pub a_port: String,
    pub b_device: i64,
    #[serde(default)]
    pub b_port: String,
    #[serde(default)]
    pub speed_mbps: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Event {
    pub id: i64,
    pub ts: i64,
    pub device_id: Option<i64>,
    /// `new`, `online`, `offline`, `degraded`, `recovered`, `gone`, `returned`, `scan`.
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CheckRow {
    pub ts: i64,
    pub ok: bool,
    pub rtt_ms: Option<f64>,
    pub loss_percent: f64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Interface {
    pub device_id: i64,
    pub index: i64,
    pub name: String,
    pub alias: String,
    pub speed_bps: Option<u64>,
    pub admin_up: bool,
    pub oper_up: bool,
    pub in_bps: Option<f64>,
    pub out_bps: Option<f64>,
    pub utilization_percent: Option<f64>,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
    pub ts: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct InterfaceSample {
    pub ts: i64,
    pub in_bps: f64,
    pub out_bps: f64,
}

#[derive(Clone, Debug, Default)]
pub struct DeviceFilter {
    pub query: String,
    pub kind: Option<String>,
    pub status: Option<String>,
    pub location_id: Option<i64>,
    /// An IPAM subnet in CIDR form.
    pub subnet: Option<String>,
    pub include_gone: bool,
}

/// A scan's summary.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct ScanSummary {
    pub id: i64,
    pub started: i64,
    pub finished: Option<i64>,
    pub state: String,
    pub probed: u64,
    pub seen: u64,
    pub new_devices: u64,
    pub gone_devices: u64,
    pub detail: String,
}

/// Counts for the overview.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct Counts {
    pub total: usize,
    pub online: usize,
    pub offline: usize,
    pub degraded: usize,
    pub unknown: usize,
    pub gone: usize,
    pub by_kind: BTreeMap<String, usize>,
}

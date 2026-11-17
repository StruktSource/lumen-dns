//! The records IPAM keeps and the requests it accepts.

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

/// Most of each kind, so a mistake or a script cannot grow the database without bound.
pub const MAX_LOCATIONS: usize = 5_000;
pub const MAX_VLANS: usize = 5_000;
pub const MAX_SUBNETS: usize = 5_000;
pub const MAX_ADDRESSES: usize = 200_000;
pub const MAX_METADATA: usize = 16;

pub const LOCATION_KINDS: &[&str] = &["site", "building", "floor", "room", "rack"];

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Location {
    pub id: i64,
    pub parent_id: Option<i64>,
    pub kind: String,
    pub name: String,
    pub description: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocationInput {
    #[serde(default)]
    pub parent_id: Option<i64>,
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Vlan {
    pub id: i64,
    pub vid: u16,
    pub name: String,
    pub description: String,
    pub location_id: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlanInput {
    pub vid: u16,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub location_id: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Subnet {
    pub id: i64,
    /// Canonical CIDR, such as `192.168.1.0/24` or `2001:db8::/64`.
    pub cidr: String,
    pub name: String,
    pub description: String,
    /// A free-form group name to organize subnets by.
    pub group: String,
    pub vlan_id: Option<i64>,
    pub location_id: Option<i64>,
    pub gateway: Option<String>,
    pub metadata: BTreeMap<String, String>,
    /// The smallest managed subnet that contains this one.
    pub parent_id: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetInput {
    /// Only used when creating: a subnet keeps its network for life.
    #[serde(default)]
    pub cidr: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub vlan_id: Option<i64>,
    #[serde(default)]
    pub location_id: Option<i64>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AddressState {
    /// In use by a device that was given the address by hand.
    Assigned,
    /// Held back so nothing else is given it.
    Reserved,
}

impl AddressState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assigned => "assigned",
            Self::Reserved => "reserved",
        }
    }
}

/// One address in the inventory. `state` is `assigned` or `reserved`; the rows from
/// [`crate::Ipam::addresses`] also use `leased` and `available`.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AddressRow {
    pub ip: String,
    pub subnet_id: i64,
    pub state: String,
    pub hostname: Option<String>,
    pub description: String,
    pub device: String,
    pub location_id: Option<i64>,
    /// Publish `hostname` in DNS (A or AAAA, and PTR).
    pub dns: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressInput {
    pub ip: String,
    pub state: AddressState,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub location_id: Option<i64>,
    #[serde(default)]
    pub dns: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Strategy {
    /// The lowest free address.
    #[default]
    First,
    /// The highest free address.
    Last,
    /// Any free address.
    Random,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocateInput {
    #[serde(default)]
    pub strategy: Strategy,
    #[serde(default = "default_state")]
    pub state: AddressState,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub location_id: Option<i64>,
    #[serde(default)]
    pub dns: bool,
}

fn default_state() -> AddressState {
    AddressState::Assigned
}

/// An address a DHCP server holds right now.
#[derive(Clone, Debug)]
pub struct Leased {
    pub ip: IpAddr,
    pub hostname: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct AddressFilter {
    pub subnet_id: Option<i64>,
    pub location_id: Option<i64>,
    /// `assigned`, `reserved`, `leased`, or `available`.
    pub state: Option<String>,
    /// Matches the address, host name, device and description.
    pub query: String,
}

/// How full one subnet is.
#[derive(Clone, Debug, Serialize)]
pub struct SubnetStats {
    pub subnet_id: i64,
    pub cidr: String,
    /// Usable addresses, as text because an IPv6 network can be larger than any integer.
    pub size: String,
    pub assigned: u64,
    pub reserved: u64,
    pub leased: u64,
    /// Addresses handed to smaller subnets inside this one.
    pub delegated: String,
    pub free: String,
    /// 0 to 100.
    pub percent_used: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Overview {
    pub subnets: Vec<SubnetStats>,
    pub vlans: usize,
    pub locations: usize,
    pub assigned: u64,
    pub reserved: u64,
    pub leased: u64,
}

/// Two records that cannot both be right.
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct Conflict {
    /// `leased-and-assigned` or `name-held-by-dhcp`.
    pub kind: String,
    pub ip: String,
    pub detail: String,
}

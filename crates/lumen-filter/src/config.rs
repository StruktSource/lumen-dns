// SPDX-License-Identifier: Apache-2.0
//! Strict, bounded filtering configuration. All schedules use UTC.

use crate::rules::{Format, Rule, normalize};
use ipnet::IpNet;
use serde::Deserialize;
use std::{collections::HashSet, net::IpAddr, path::PathBuf};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub rules: Rules,
    pub action: Action,
    pub lists: Vec<List>,
    pub profiles: Vec<Profile>,
    pub devices: Vec<Device>,
    pub groups: Vec<Group>,
    pub subnets: Vec<Subnet>,
    pub default_profile: Option<String>,
    /// Explicit opt-in: prints names, client IPs, and decisions to stderr.
    pub decision_log: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub allow: Vec<String>,
    pub block: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    #[default]
    Nxdomain,
    Nodata,
    Address {
        ipv4: Option<std::net::Ipv4Addr>,
        ipv6: Option<std::net::Ipv6Addr>,
    },
    Cname {
        target: String,
    },
    Refused,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct List {
    pub id: String,
    pub format: Format,
    pub path: Option<PathBuf>,
    pub url: Option<String>,
    pub text: Option<String>,
    pub category: Option<String>,
    #[serde(default = "default_refresh")]
    pub refresh_secs: u32,
}
fn default_refresh() -> u32 {
    86400
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub rules: Rules,
    /// Empty means no list restriction. Categories further restrict selection.
    pub lists: Vec<String>,
    pub categories: Vec<String>,
    pub action: Option<Action>,
    /// Empty means always active. Outside these windows only global rules apply.
    pub schedules: Vec<Schedule>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    /// ISO weekdays: Monday=1, Sunday=7. Overnight windows belong to start day.
    pub days: Vec<u8>,
    pub start_minute: u16,
    pub end_minute: u16,
}
impl Schedule {
    #[must_use]
    pub fn active(&self, unix_seconds: u64) -> bool {
        let day = unix_seconds / 86400;
        let weekday = (day + 3) % 7 + 1;
        let minute = (unix_seconds % 86400) / 60;
        let start = u64::from(self.start_minute);
        let end = u64::from(self.end_minute);
        if start < end {
            self.days.iter().any(|d| u64::from(*d) == weekday) && minute >= start && minute < end
        } else {
            (minute >= start && self.days.iter().any(|d| u64::from(*d) == weekday))
                || (minute < end
                    && self
                        .days
                        .iter()
                        .any(|d| u64::from(*d) == (weekday + 5) % 7 + 1))
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub addresses: Vec<IpAddr>,
    pub profile: Option<String>,
    pub group: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub profile: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subnet {
    pub network: IpNet,
    pub profile: String,
}

impl Config {
    /// Validate bounds and references before loading any external list.
    ///
    /// # Errors
    /// Rejects ambiguous policies, unsupported actions, and unbounded input.
    #[allow(clippy::too_many_lines)] // Keep cross-reference validation in one pass.
    pub fn validate(&self) -> Result<(), String> {
        if self.lists.len() > 64
            || self.profiles.len() > 128
            || self.devices.len() > 1024
            || self.groups.len() > 128
            || self.subnets.len() > 256
        {
            return Err("filter configuration exceeds object limits".into());
        }
        let manual_count = self.rules.allow.len()
            + self.rules.block.len()
            + self
                .profiles
                .iter()
                .map(|p| p.rules.allow.len() + p.rules.block.len())
                .sum::<usize>();
        if manual_count > crate::rules::MAX_RULES {
            return Err("all filtering rules together exceed 250000".into());
        }
        let lists = ids(self.lists.iter().map(|l| l.id.as_str()))?;
        let profiles = ids(self.profiles.iter().map(|p| p.id.as_str()))?;
        let groups = ids(self.groups.iter().map(|g| g.id.as_str()))?;
        ids(self.devices.iter().map(|d| d.id.as_str()))?;
        self.action.validate()?;
        validate_rules(&self.rules)?;
        if let Some(id) = &self.default_profile {
            reference(&profiles, id)?;
        }
        for list in &self.lists {
            if usize::from(list.path.is_some())
                + usize::from(list.url.is_some())
                + usize::from(list.text.is_some())
                != 1
            {
                return Err("list needs exactly one of path, url, or text".into());
            }
            if list.refresh_secs != 0 && !(60..=604_800).contains(&list.refresh_secs) {
                return Err("list refresh_secs must be 0 or 60..=604800".into());
            }
            if list
                .text
                .as_ref()
                .is_some_and(|text| text.len() > crate::rules::MAX_LIST_BYTES)
            {
                return Err("inline list too large".into());
            }
            if let Some(category) = &list.category {
                valid_id(category)?;
            }
            if let Some(url) = &list.url {
                crate::fetch::validate_url(url)?;
            }
        }
        let categories: HashSet<&str> = self
            .lists
            .iter()
            .filter_map(|l| l.category.as_deref())
            .collect();
        for profile in &self.profiles {
            validate_rules(&profile.rules)?;
            if let Some(action) = &profile.action {
                action.validate()?;
            }
            if profile.lists.len() > 64
                || profile.categories.len() > 64
                || profile.schedules.len() > 32
            {
                return Err("profile exceeds selection or schedule limits".into());
            }
            for id in &profile.lists {
                reference(&lists, id)?;
            }
            for category in &profile.categories {
                reference(&categories, category)?;
            }
            for schedule in &profile.schedules {
                if schedule.days.is_empty()
                    || schedule.days.len() > 7
                    || schedule.days.iter().any(|day| !(1..=7).contains(day))
                    || schedule.start_minute >= 1440
                    || schedule.end_minute >= 1440
                    || schedule.start_minute == schedule.end_minute
                {
                    return Err("invalid UTC schedule window".into());
                }
            }
        }
        let mut addresses = HashSet::new();
        for device in &self.devices {
            if device.addresses.is_empty()
                || device.addresses.len() > 32
                || (device.profile.is_none() && device.group.is_none())
            {
                return Err("device needs 1..32 addresses and a profile or group".into());
            }
            for address in &device.addresses {
                if address.is_unspecified()
                    || address.is_multicast()
                    || !addresses.insert(address.to_canonical())
                {
                    return Err("invalid or duplicate device IP".into());
                }
            }
            if let Some(id) = &device.profile {
                reference(&profiles, id)?;
            }
            if let Some(id) = &device.group {
                reference(&groups, id)?;
            }
        }
        for group in &self.groups {
            reference(&profiles, &group.profile)?;
        }
        let mut networks = HashSet::new();
        for subnet in &self.subnets {
            reference(&profiles, &subnet.profile)?;
            if !networks.insert(subnet.network.trunc()) {
                return Err("duplicate subnet selector".into());
            }
        }
        Ok(())
    }
}
impl Action {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::Address {
                ipv4: None,
                ipv6: None,
            } => Err("address action needs ipv4 or ipv6".into()),
            Self::Cname { target } => normalize(target).map(|_| ()),
            _ => Ok(()),
        }
    }
}
fn validate_rules(rules: &Rules) -> Result<(), String> {
    if rules.allow.len() + rules.block.len() > 4096 {
        return Err("too many manual rules".into());
    }
    for rule in rules.allow.iter().chain(&rules.block) {
        Rule::parse(rule, false)?;
    }
    Ok(())
}
fn valid_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err("IDs must be 1..64 ASCII letters, digits, underscores, or hyphens".into());
    }
    Ok(())
}
fn ids<'a>(values: impl Iterator<Item = &'a str>) -> Result<HashSet<&'a str>, String> {
    let mut result = HashSet::new();
    for value in values {
        valid_id(value)?;
        if !result.insert(value) {
            return Err("duplicate filter ID".into());
        }
    }
    Ok(result)
}
fn reference(values: &HashSet<&str>, id: &str) -> Result<(), String> {
    if values.contains(id) {
        Ok(())
    } else {
        Err(format!("unknown filter reference: {id}"))
    }
}

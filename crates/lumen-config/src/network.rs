//! Settings for the optional network discovery and monitoring module (`[network]`).
//!
//! Off by default, and it only ever looks at networks listed in `scopes`. SNMP secrets never sit
//! in the configuration: each profile names a file (mode `0600`) that holds the secret.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Most addresses one sweep may probe, summed over all scopes, so a typo cannot flood a network.
pub const MAX_SWEEP_ADDRESSES: u128 = 262_144;
pub const MAX_SCOPES: usize = 32;
pub const MAX_PROFILES: usize = 32;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    pub enabled: bool,
    /// The networks to look at. Nothing outside them is ever probed, learned, or stored.
    pub scopes: Vec<NetworkScope>,
    /// Seconds between automatic discovery runs. `0` means only when an administrator asks.
    pub scan_interval_secs: u32,
    /// Most probes in flight at once (1 to 256).
    pub concurrency: u16,
    /// How long a probe waits for an answer, in milliseconds (100 to 5000).
    pub timeout_ms: u32,
    /// Most probe packets sent per second across all scopes (1 to 2000).
    pub packets_per_second: u32,
    pub methods: DiscoveryMethods,
    /// A device that is missed this many runs in a row is marked as gone (1 to 100).
    pub gone_after_scans: u8,
    /// A vendor list in the IEEE `oui.txt` format, for manufacturer names beyond the built-in
    /// list.
    pub oui_file: Option<PathBuf>,
    /// Days of check, traffic, and event history kept (1 to 365).
    pub retention_days: u16,
    pub monitor: Monitor,
    /// Seconds between SNMP polls of a device (30 to 3600).
    pub snmp_interval_secs: u32,
    pub snmp_profiles: Vec<SnmpProfile>,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            enabled: false,
            scopes: Vec::new(),
            scan_interval_secs: 3600,
            concurrency: 32,
            timeout_ms: 800,
            packets_per_second: 100,
            methods: DiscoveryMethods::default(),
            gone_after_scans: 3,
            oui_file: None,
            retention_days: 30,
            monitor: Monitor::default(),
            snmp_interval_secs: 300,
            snmp_profiles: Vec::new(),
        }
    }
}

/// Which sources discovery uses. All but SNMP are on by default once the module is on.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // One switch per discovery method.
pub struct DiscoveryMethods {
    /// Read this machine's ARP (IPv4) and NDP (IPv6) neighbor tables.
    pub neighbors: bool,
    /// Send ICMP echo requests (IPv4 sweeps; IPv6 scopes ping the all-nodes group).
    pub icmp: bool,
    /// Use the addresses and names of DHCP leases.
    pub dhcp: bool,
    /// Look up host names (reverse DNS) for new addresses.
    pub dns: bool,
    /// Ask devices for details over SNMP (needs `snmp_profiles`).
    pub snmp: bool,
}

impl Default for DiscoveryMethods {
    fn default() -> Self {
        Self {
            neighbors: true,
            icmp: true,
            dhcp: true,
            dns: true,
            snmp: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkScope {
    pub name: String,
    /// IPv4 and IPv6 CIDR ranges. An IPv4 range is swept address by address (at most /16); an
    /// IPv6 range is learned from the neighbor table and an all-nodes ping, never swept.
    pub networks: Vec<IpNet>,
    /// Addresses and ranges that are never probed, learned, or stored.
    #[serde(default)]
    pub exclude: Vec<IpNet>,
    /// The interface this scope is reached through. Needed for IPv6 scopes.
    #[serde(default)]
    pub interface: Option<String>,
    /// The SNMP profile used for devices in this scope.
    #[serde(default)]
    pub snmp_profile: Option<String>,
}

/// Availability checking of registered devices.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Monitor {
    pub enabled: bool,
    /// Seconds between checks of a device (10 to 3600).
    pub interval_secs: u32,
    /// Checks in a row that must fail before a device is offline (1 to 20). One lost packet
    /// never raises an outage.
    pub failures_before_offline: u8,
    /// A device whose recent checks lose at least this share is degraded (1 to 99).
    pub degraded_loss_percent: u8,
    /// Probes of one check, sent together (1 to 10). The check passes if any answers.
    pub probes_per_check: u8,
}

impl Default for Monitor {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60,
            failures_before_offline: 3,
            degraded_loss_percent: 20,
            probes_per_check: 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum SnmpVersion {
    #[serde(rename = "v2c")]
    V2c,
    #[serde(rename = "v3")]
    V3,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SnmpAuth {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SnmpPrivacy {
    Aes128,
}

/// How to talk SNMP to a group of devices. Secrets are read from files.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnmpProfile {
    pub name: String,
    pub version: SnmpVersion,
    /// v2c: file holding the community string (mode 0600).
    #[serde(default)]
    pub community_file: Option<PathBuf>,
    /// v3: the user name.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub auth_protocol: Option<SnmpAuth>,
    /// v3: file holding the authentication password (at least 8 characters, mode 0600).
    #[serde(default)]
    pub auth_password_file: Option<PathBuf>,
    #[serde(default)]
    pub privacy_protocol: Option<SnmpPrivacy>,
    /// v3: file holding the privacy password (at least 8 characters, mode 0600).
    #[serde(default)]
    pub privacy_password_file: Option<PathBuf>,
    #[serde(default = "default_snmp_port")]
    pub port: u16,
    #[serde(default = "default_snmp_timeout")]
    pub timeout_ms: u32,
    #[serde(default = "default_snmp_retries")]
    pub retries: u8,
}

fn default_snmp_port() -> u16 {
    161
}
fn default_snmp_timeout() -> u32 {
    1500
}
fn default_snmp_retries() -> u8 {
    1
}

impl Network {
    /// Addresses an IPv4 sweep would probe, summed over all scopes (excluded ones removed
    /// approximately by subtraction of their size within the scope).
    #[must_use]
    pub fn sweep_size(&self) -> u128 {
        self.scopes
            .iter()
            .flat_map(|scope| scope.networks.iter())
            .filter_map(|net| match net {
                IpNet::V4(v4) => Some(1u128 << (32 - u32::from(v4.prefix_len()))),
                IpNet::V6(_) => None,
            })
            .sum()
    }

    /// # Errors
    /// Says what is wrong with the settings.
    #[allow(clippy::too_many_lines)] // One flat list of independent checks.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        let name_ok = |name: &str| {
            (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b' '))
        };
        if self.scopes.is_empty() || self.scopes.len() > MAX_SCOPES {
            return Err("network needs 1 to 32 scopes: it only looks at networks you list".into());
        }
        let mut seen = std::collections::HashSet::new();
        for scope in &self.scopes {
            if !name_ok(&scope.name) || !seen.insert(scope.name.to_ascii_lowercase()) {
                return Err(
                    "network.scopes need unique names of letters, digits, space, - _ .".into(),
                );
            }
            if scope.networks.is_empty() || scope.networks.len() > 64 || scope.exclude.len() > 256 {
                return Err(format!(
                    "network scope {}: 1 to 64 networks and at most 256 exclusions",
                    scope.name
                ));
            }
            for net in &scope.networks {
                let ok = match net {
                    IpNet::V4(v4) => (16..=32).contains(&v4.prefix_len()),
                    IpNet::V6(v6) => (48..=128).contains(&v6.prefix_len()),
                };
                if !ok {
                    return Err(format!(
                        "network scope {}: {net} must be IPv4 /16 to /32 or IPv6 /48 to /128",
                        scope.name
                    ));
                }
            }
            if scope.networks.iter().any(|n| matches!(n, IpNet::V6(_)))
                && scope.interface.as_deref().is_none_or(str::is_empty)
            {
                return Err(format!(
                    "network scope {}: an IPv6 network needs an interface",
                    scope.name
                ));
            }
            if let Some(interface) = &scope.interface
                && (interface.is_empty()
                    || interface.len() > 15
                    || !interface
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')))
            {
                return Err(format!(
                    "network scope {}: interface is not a valid name",
                    scope.name
                ));
            }
            if let Some(profile) = &scope.snmp_profile
                && !self.snmp_profiles.iter().any(|p| &p.name == profile)
            {
                return Err(format!(
                    "network scope {}: unknown snmp_profile {profile}",
                    scope.name
                ));
            }
        }
        if self.sweep_size() > MAX_SWEEP_ADDRESSES {
            return Err("network scopes would sweep more than 262144 addresses".into());
        }
        if self.scan_interval_secs != 0 && !(60..=86_400).contains(&self.scan_interval_secs) {
            return Err("network.scan_interval_secs must be 0 or 60 to 86400".into());
        }
        if !(1..=256).contains(&self.concurrency)
            || !(100..=5000).contains(&self.timeout_ms)
            || !(1..=2000).contains(&self.packets_per_second)
            || !(1..=100).contains(&self.gone_after_scans)
            || !(1..=365).contains(&self.retention_days)
            || !(30..=3600).contains(&self.snmp_interval_secs)
        {
            return Err("a network limit (concurrency, timeout_ms, packets_per_second, gone_after_scans, retention_days or snmp_interval_secs) is out of range".into());
        }
        let monitor = &self.monitor;
        if !(10..=3600).contains(&monitor.interval_secs)
            || !(1..=20).contains(&monitor.failures_before_offline)
            || !(1..=99).contains(&monitor.degraded_loss_percent)
            || !(1..=10).contains(&monitor.probes_per_check)
        {
            return Err("a network.monitor setting is out of range".into());
        }
        if self.snmp_profiles.len() > MAX_PROFILES {
            return Err("too many network.snmp_profiles".into());
        }
        let mut names = std::collections::HashSet::new();
        for profile in &self.snmp_profiles {
            if !name_ok(&profile.name) || !names.insert(profile.name.to_ascii_lowercase()) {
                return Err("network.snmp_profiles need unique names".into());
            }
            if profile.port == 0
                || !(200..=10_000).contains(&profile.timeout_ms)
                || profile.retries > 5
            {
                return Err(format!(
                    "snmp profile {}: port, timeout_ms or retries is out of range",
                    profile.name
                ));
            }
            match profile.version {
                SnmpVersion::V2c => {
                    if profile.community_file.is_none()
                        || profile.username.is_some()
                        || profile.auth_protocol.is_some()
                        || profile.privacy_protocol.is_some()
                    {
                        return Err(format!(
                            "snmp profile {}: v2c needs community_file and nothing from v3",
                            profile.name
                        ));
                    }
                }
                SnmpVersion::V3 => {
                    let user_ok = profile
                        .username
                        .as_deref()
                        .is_some_and(|u| (1..=32).contains(&u.len()) && u.is_ascii());
                    let auth = profile.auth_protocol.is_some();
                    let priv_ = profile.privacy_protocol.is_some();
                    if !user_ok
                        || profile.community_file.is_some()
                        || (auth != profile.auth_password_file.is_some())
                        || (priv_ != profile.privacy_password_file.is_some())
                        || (priv_ && !auth)
                    {
                        return Err(format!(
                            "snmp profile {}: v3 needs a username, and an auth protocol and password file together; privacy needs auth",
                            profile.name
                        ));
                    }
                }
            }
        }
        if self.methods.snmp && self.snmp_profiles.is_empty() {
            return Err("network.methods.snmp needs at least one snmp profile".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> Network {
        Network {
            enabled: true,
            scopes: vec![NetworkScope {
                name: "Home".into(),
                networks: vec!["192.168.1.0/24".parse().unwrap()],
                exclude: vec!["192.168.1.1/32".parse().unwrap()],
                interface: None,
                snmp_profile: None,
            }],
            ..Network::default()
        }
    }

    #[test]
    fn it_is_off_by_default_and_needs_explicit_scopes() {
        assert!(!Network::default().enabled);
        assert!(Network::default().validate().is_ok());
        assert!(on().validate().is_ok());
        let mut none = on();
        none.scopes.clear();
        assert!(none.validate().is_err());
    }

    #[test]
    fn scopes_and_limits_are_bounded() {
        let mut wide = on();
        wide.scopes[0].networks = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(wide.validate().is_err(), "a /8 cannot be swept");
        let mut sum = on();
        sum.scopes[0].networks = (0..8)
            .map(|i| format!("10.{i}.0.0/16").parse().unwrap())
            .collect();
        assert!(sum.validate().is_err(), "eight /16s are over the total");
        let mut v6 = on();
        v6.scopes[0].networks = vec!["fd00::/64".parse().unwrap()];
        assert!(v6.validate().is_err(), "an IPv6 scope names its interface");
        v6.scopes[0].interface = Some("eth0".into());
        assert!(v6.validate().is_ok());
        for change in [
            |n: &mut Network| n.concurrency = 0,
            |n: &mut Network| n.timeout_ms = 50,
            |n: &mut Network| n.scan_interval_secs = 5,
            |n: &mut Network| n.monitor.failures_before_offline = 0,
            |n: &mut Network| n.monitor.interval_secs = 1,
            |n: &mut Network| n.retention_days = 0,
        ] {
            let mut bad = on();
            change(&mut bad);
            assert!(bad.validate().is_err());
        }
    }

    #[test]
    fn snmp_profiles_need_their_secrets_in_files() {
        let profile = |version, f: fn(&mut SnmpProfile)| {
            let mut p = SnmpProfile {
                name: "core".into(),
                version,
                community_file: None,
                username: None,
                auth_protocol: None,
                auth_password_file: None,
                privacy_protocol: None,
                privacy_password_file: None,
                port: 161,
                timeout_ms: 1500,
                retries: 1,
            };
            f(&mut p);
            p
        };
        let with = |p: SnmpProfile| {
            let mut n = on();
            n.snmp_profiles = vec![p];
            n.validate()
        };
        assert!(with(profile(SnmpVersion::V2c, |p| p.community_file = Some("c".into()))).is_ok());
        assert!(
            with(profile(SnmpVersion::V2c, |_| {})).is_err(),
            "no community file"
        );
        assert!(
            with(profile(SnmpVersion::V3, |p| p.username = Some("lumen".into()))).is_ok(),
            "noAuthNoPriv"
        );
        assert!(
            with(profile(SnmpVersion::V3, |p| {
                p.username = Some("lumen".into());
                p.auth_protocol = Some(SnmpAuth::Sha256);
            }))
            .is_err(),
            "an auth protocol needs its password file"
        );
        assert!(
            with(profile(SnmpVersion::V3, |p| {
                p.username = Some("lumen".into());
                p.privacy_protocol = Some(SnmpPrivacy::Aes128);
                p.privacy_password_file = Some("p".into());
            }))
            .is_err(),
            "privacy needs auth"
        );
        assert!(
            with(profile(SnmpVersion::V3, |p| {
                p.username = Some("lumen".into());
                p.auth_protocol = Some(SnmpAuth::Sha256);
                p.auth_password_file = Some("a".into());
                p.privacy_protocol = Some(SnmpPrivacy::Aes128);
                p.privacy_password_file = Some("p".into());
            }))
            .is_ok()
        );
        let mut missing = on();
        missing.scopes[0].snmp_profile = Some("nope".into());
        assert!(missing.validate().is_err());
        let mut snmp = on();
        snmp.methods.snmp = true;
        assert!(snmp.validate().is_err(), "SNMP discovery needs a profile");
    }
}

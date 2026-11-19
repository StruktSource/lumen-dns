//! The networks discovery is allowed to look at.

use crate::oui::{Mac, is_usable};
use ipnet::IpNet;
use lumen_config::Network;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug)]
pub struct Scope {
    pub name: String,
    pub networks: Vec<IpNet>,
    pub exclude: Vec<IpNet>,
    pub interface: Option<String>,
    pub profile: Option<String>,
}

impl Scope {
    #[must_use]
    pub fn includes(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|n| n.contains(&ip))
            && !self.exclude.iter().any(|n| n.contains(&ip))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Scopes(pub Vec<Scope>);

impl Scopes {
    #[must_use]
    pub fn from_config(config: &Network) -> Self {
        Self(
            config
                .scopes
                .iter()
                .map(|s| Scope {
                    name: s.name.clone(),
                    networks: s.networks.clone(),
                    exclude: s.exclude.clone(),
                    interface: s.interface.clone(),
                    profile: s.snmp_profile.clone(),
                })
                .collect(),
        )
    }

    /// The first scope that covers the address and does not exclude it.
    #[must_use]
    pub fn find(&self, ip: IpAddr) -> Option<&Scope> {
        self.0.iter().find(|s| s.includes(ip))
    }

    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.find(ip).is_some()
    }

    /// Every configured network, for judging which devices a run covered.
    #[must_use]
    pub fn networks(&self) -> Vec<IpNet> {
        self.0.iter().flat_map(|s| s.networks.clone()).collect()
    }

    /// The IPv4 addresses a sweep probes: hosts of every scope network, once each, without
    /// exclusions and without network and broadcast addresses.
    #[must_use]
    pub fn sweep_targets(&self) -> Vec<Ipv4Addr> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for scope in &self.0 {
            for net in &scope.networks {
                let IpNet::V4(net) = net else { continue };
                let hosts: Vec<Ipv4Addr> = if net.prefix_len() >= 31 {
                    (u32::from(net.network())..=u32::from(net.broadcast()))
                        .map(Ipv4Addr::from)
                        .collect()
                } else {
                    net.hosts().collect()
                };
                for ip in hosts {
                    if scope.includes(IpAddr::V4(ip)) && seen.insert(ip) {
                        out.push(ip);
                    }
                }
            }
        }
        out
    }

    /// The interfaces named by IPv6 scopes.
    #[must_use]
    pub fn v6_interfaces(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .0
            .iter()
            .filter(|s| s.networks.iter().any(|n| matches!(n, IpNet::V6(_))))
            .filter_map(|s| s.interface.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

/// The hardware address inside a DHCP client identifier written as hex: six bytes, the same
/// with a leading hardware type (`01`), or a DUID of type LL or LLT for Ethernet.
#[must_use]
pub fn mac_from_client(hex: &str) -> Option<Mac> {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    let tail = match bytes.len() {
        6 => &bytes[..],
        7 if bytes[0] == 1 => &bytes[1..],
        // DUID-LL: type 3, hardware type 1, link-layer address.
        10 if bytes[..4] == [0, 3, 0, 1] => &bytes[4..],
        // DUID-LLT: type 1, hardware type 1, time, link-layer address.
        14 if bytes[..4] == [0, 1, 0, 1] => &bytes[8..],
        _ => return None,
    };
    let mac: Mac = tail.try_into().ok()?;
    is_usable(&mac).then_some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumen_config::NetworkScope;

    fn config() -> Network {
        Network {
            enabled: true,
            scopes: vec![
                NetworkScope {
                    name: "lan".into(),
                    networks: vec![
                        "192.168.1.0/29".parse().unwrap(),
                        "fd00::/64".parse().unwrap(),
                    ],
                    exclude: vec![
                        "192.168.1.2/32".parse().unwrap(),
                        "192.168.1.4/31".parse().unwrap(),
                    ],
                    interface: Some("eth0".into()),
                    snmp_profile: None,
                },
                NetworkScope {
                    name: "p2p".into(),
                    networks: vec![
                        "10.0.0.0/31".parse().unwrap(),
                        "192.168.1.0/30".parse().unwrap(),
                    ],
                    exclude: Vec::new(),
                    interface: None,
                    snmp_profile: None,
                },
            ],
            ..Network::default()
        }
    }

    #[test]
    fn sweeps_cover_hosts_only_once_and_honor_exclusions() {
        let scopes = Scopes::from_config(&config());
        let targets: Vec<String> = scopes
            .sweep_targets()
            .iter()
            .map(ToString::to_string)
            .collect();
        // .1 .3 from the first scope (.2 excluded; .4/.5 excluded; .6 stays), then the /31
        // (both ends are hosts), and .2 comes back through the second scope's /30.
        assert_eq!(
            targets,
            [
                "192.168.1.1",
                "192.168.1.3",
                "192.168.1.6",
                "10.0.0.0",
                "10.0.0.1",
                "192.168.1.2"
            ]
        );
        assert!(scopes.contains("fd00::5".parse().unwrap()));
        assert!(!scopes.contains("192.168.1.4".parse().unwrap()), "excluded");
        assert!(
            !scopes.contains("172.16.0.1".parse().unwrap()),
            "never outside the scopes"
        );
        assert_eq!(
            scopes.find("10.0.0.1".parse().unwrap()).unwrap().name,
            "p2p"
        );
        assert_eq!(scopes.v6_interfaces(), ["eth0"]);
        assert_eq!(scopes.networks().len(), 4);
    }

    #[test]
    fn dhcp_client_identifiers_yield_hardware_addresses() {
        let want = Some([0xb8, 0x27, 0xeb, 0, 0, 1]);
        assert_eq!(mac_from_client("b827eb000001"), want);
        assert_eq!(mac_from_client("01b827eb000001"), want);
        assert_eq!(mac_from_client("00030001b827eb000001"), want);
        assert_eq!(mac_from_client("00010001aabbccddb827eb000001"), want);
        assert_eq!(mac_from_client("000300026060606060"), None, "not Ethernet");
        assert_eq!(mac_from_client("ffffffffffff"), None);
        assert_eq!(mac_from_client("zz"), None);
        assert_eq!(mac_from_client(""), None);
    }
}

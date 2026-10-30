// SPDX-License-Identifier: Apache-2.0
//! Bundled, disabled-by-default upstream resolver metadata.

use crate::{Upstream, UpstreamProtocol};
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

const BUNDLED: &str = include_str!("../../../config/providers/resolvers.toml");

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub catalog_version: u32,
    pub providers: Vec<Provider>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub operator_country: String,
    pub jurisdiction: Jurisdiction,
    pub network_scope: NetworkScope,
    pub filter_variant: FilterVariant,
    pub ecs: bool,
    pub ipv4: Vec<IpAddr>,
    pub ipv6: Vec<IpAddr>,
    pub official_url: String,
    pub privacy_url: Option<String>,
    pub verified_on: String,
    pub transports: Vec<Transport>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transport {
    pub protocol: UpstreamProtocol,
    pub availability: Availability,
    pub test_status: TestStatus,
    pub port: Option<u16>,
    pub server_name: Option<String>,
    pub url: Option<String>,
    #[serde(default)]
    pub bootstrap_ips: Vec<IpAddr>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Supported,
    Unsupported,
    NotDocumented,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Tested,
    NotTested,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Jurisdiction {
    Eu,
    EuropeNonEu,
    OutsideEurope,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScope {
    Regional,
    EuAnycast,
    GlobalAnycast,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FilterVariant {
    Unfiltered,
    Uncensored,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl Catalog {
    /// Parse and validate the source-controlled catalog.
    ///
    /// # Errors
    /// Returns an error when the bundled data does not match the strict schema.
    pub fn bundled() -> Result<Self, String> {
        let catalog: Self = toml::from_str(BUNDLED)
            .map_err(|error| format!("invalid bundled provider catalog at {:?}", error.span()))?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Validate stable IDs, metadata, addresses, and transport endpoints.
    ///
    /// # Errors
    /// Returns an error for inconsistent, unsafe, or duplicate catalog data.
    pub fn validate(&self) -> Result<(), String> {
        if self.catalog_version != 1 {
            return Err("catalog_version must be 1".into());
        }
        let mut ids = HashSet::new();
        for provider in &self.providers {
            if provider.id.is_empty()
                || !provider
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !ids.insert(provider.id.as_str())
            {
                return Err("provider IDs must be unique lowercase slugs".into());
            }
            if provider.name.is_empty() || provider.name.len() > 80 {
                return Err("invalid provider name".into());
            }
            if provider.operator_country.len() != 2
                || !provider
                    .operator_country
                    .bytes()
                    .all(|b| b.is_ascii_uppercase())
            {
                return Err("operator_country must be an ISO alpha-2 code".into());
            }
            if provider.ipv4.iter().any(|ip| !ip.is_ipv4())
                || provider.ipv6.iter().any(|ip| !ip.is_ipv6())
                || provider.ipv4.is_empty() && provider.ipv6.is_empty()
            {
                return Err("provider address family does not match its field".into());
            }
            validate_https_url(&provider.official_url)?;
            if let Some(url) = &provider.privacy_url {
                validate_https_url(url)?;
            }
            if !valid_date(&provider.verified_on) {
                return Err("verified_on must be YYYY-MM-DD".into());
            }
            let mut protocols = HashSet::new();
            for transport in &provider.transports {
                if !protocols.insert(transport.protocol as u8) {
                    return Err("provider transport protocols must be unique".into());
                }
                validate_transport(transport)?;
            }
        }
        Ok(())
    }

    /// Build explicit runtime upstreams for one supported preset transport.
    ///
    /// # Errors
    /// Returns an error for an unknown preset, unavailable transport, or missing family.
    pub fn select(
        &self,
        id: &str,
        protocol: UpstreamProtocol,
        family: AddressFamily,
    ) -> Result<Vec<Upstream>, String> {
        let provider = self
            .providers
            .iter()
            .find(|item| item.id == id)
            .ok_or_else(|| format!("unknown provider preset: {id}"))?;
        let transport = provider
            .transports
            .iter()
            .find(|item| item.protocol == protocol)
            .ok_or_else(|| format!("provider {id} has no {protocol:?} catalog entry"))?;
        if transport.availability != Availability::Supported {
            return Err(format!(
                "provider {id} does not document {protocol:?} support"
            ));
        }
        let addresses = if transport.bootstrap_ips.is_empty() {
            provider
                .ipv4
                .iter()
                .chain(provider.ipv6.iter())
                .copied()
                .collect::<Vec<_>>()
        } else {
            transport.bootstrap_ips.clone()
        };
        let path = if protocol == UpstreamProtocol::Https {
            Some(doh_path(transport)?.to_owned())
        } else {
            None
        };
        let port = transport.port.ok_or("supported transport needs a port")?;
        let selected = addresses
            .into_iter()
            .filter(|ip| match family {
                AddressFamily::Any => true,
                AddressFamily::Ipv4 => ip.is_ipv4(),
                AddressFamily::Ipv6 => ip.is_ipv6(),
            })
            .map(|ip| Upstream {
                address: SocketAddr::new(ip, port),
                protocol,
                server_name: transport.server_name.clone(),
                doh_path: path.clone(),
            })
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(format!(
                "provider {id} has no address for the selected family"
            ));
        }
        Ok(selected)
    }
}

fn validate_transport(transport: &Transport) -> Result<(), String> {
    if transport.availability != Availability::Supported {
        if transport.port.is_some()
            || transport.server_name.is_some()
            || transport.url.is_some()
            || !transport.bootstrap_ips.is_empty()
        {
            return Err("unavailable transports must not contain endpoint data".into());
        }
        return Ok(());
    }
    if transport.port.is_none_or(|port| port == 0) {
        return Err("supported transport needs a port".into());
    }
    let encrypted = matches!(
        transport.protocol,
        UpstreamProtocol::Tls | UpstreamProtocol::Https | UpstreamProtocol::Quic
    );
    if encrypted
        && transport
            .server_name
            .as_ref()
            .is_none_or(|name| name.is_empty() || name.len() > 253)
    {
        return Err("supported encrypted transport needs server_name".into());
    }
    if transport.protocol == UpstreamProtocol::Https {
        doh_path(transport)?;
    } else if transport.url.is_some() {
        return Err("only https transports may contain a URL".into());
    }
    Ok(())
}

fn doh_path(transport: &Transport) -> Result<&str, String> {
    let name = transport
        .server_name
        .as_deref()
        .ok_or("DoH transport needs server_name")?;
    let url = transport
        .url
        .as_deref()
        .ok_or("DoH transport needs a full URL")?;
    let rest = url
        .strip_prefix("https://")
        .ok_or("DoH URL must use https")?;
    let (host, path) = rest.split_once('/').ok_or("DoH URL must contain a path")?;
    if host != name {
        return Err("DoH URL host must equal server_name".into());
    }
    let path = &url[url.len() - path.len() - 1..];
    if path.len() > 1024
        || path.contains(['?', '#'])
        || !path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err("invalid DoH URL path".into());
    }
    Ok(path)
}

fn validate_https_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://")
        || url.len() > 2048
        || url.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err("catalog URLs must be bounded HTTPS URLs".into());
    }
    Ok(())
}

fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 4 || i == 7 || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_catalog_is_valid_and_stable() {
        let catalog = Catalog::bundled().unwrap();
        assert!(catalog.providers.len() >= 10);
        assert!(
            catalog
                .providers
                .iter()
                .any(|provider| provider.id == "dns4eu-unfiltered")
        );
        assert!(catalog.providers.iter().all(|provider| {
            provider
                .transports
                .iter()
                .all(|transport| transport.test_status == TestStatus::NotTested)
        }));
    }

    #[test]
    fn selection_uses_exact_doh_path_and_bootstrap_family() {
        let catalog = Catalog::bundled().unwrap();
        let upstreams = catalog
            .select(
                "controld-uncensored",
                UpstreamProtocol::Https,
                AddressFamily::Ipv6,
            )
            .unwrap();
        assert_eq!(upstreams.len(), 2);
        assert!(
            upstreams
                .iter()
                .all(|upstream| upstream.address.is_ipv6() && upstream.address.port() == 443)
        );
        assert!(
            upstreams
                .iter()
                .all(|upstream| upstream.doh_path.as_deref() == Some("/uncensored"))
        );
        assert!(
            upstreams
                .iter()
                .all(|upstream| upstream.server_name.as_deref() == Some("freedns.controld.com"))
        );
    }

    #[test]
    fn unavailable_and_unknown_selections_fail_closed() {
        let catalog = Catalog::bundled().unwrap();
        assert!(
            catalog
                .select("dns-watch", UpstreamProtocol::Https, AddressFamily::Any)
                .is_err()
        );
        assert!(
            catalog
                .select("missing", UpstreamProtocol::Udp, AddressFamily::Any)
                .is_err()
        );
    }

    #[test]
    fn malformed_catalog_entries_fail_closed() {
        let mut catalog = Catalog::bundled().unwrap();
        catalog.providers[1].id = catalog.providers[0].id.clone();
        assert!(catalog.validate().is_err());

        let mut catalog = Catalog::bundled().unwrap();
        let https = catalog.providers[0]
            .transports
            .iter_mut()
            .find(|transport| transport.protocol == UpstreamProtocol::Https)
            .unwrap();
        https.url = Some("https://wrong.example/dns-query".into());
        assert!(catalog.validate().is_err());

        let mut catalog = Catalog::bundled().unwrap();
        let quic = catalog.providers[0]
            .transports
            .iter_mut()
            .find(|transport| transport.protocol == UpstreamProtocol::Quic)
            .unwrap();
        quic.port = Some(853);
        assert!(catalog.validate().is_err());
    }
}

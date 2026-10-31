// SPDX-License-Identifier: Apache-2.0
//! Versioned startup configuration. Unknown fields and unsafe limits fail closed.

use ipnet::IpNet;
use serde::Deserialize;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

pub mod providers;

/// Startup configuration; relative paths resolve beside the config file.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub listen: Listeners,
    pub resolver: Resolver,
    pub limits: Limits,
    pub filtering: lumen_filter::config::Config,
    pub metrics: Option<SocketAddr>,
    pub management: Management,
}

/// Opt-in local management API. Bearer-token hashes stay in operator config.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Management {
    pub listen: Option<SocketAddr>,
    pub tokens: Vec<ApiToken>,
    pub requests_per_minute: u16,
    pub webhooks: Vec<Webhook>,
}

/// Signed outbound audit-event webhook.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub secret_file: PathBuf,
}

/// One named API principal with a fixed role and SHA-256 token hash.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiToken {
    pub name: String,
    pub role: ApiRole,
    pub sha256: String,
}

/// Management scopes. Higher roles include lower-role actions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApiRole {
    Viewer,
    Operator,
    Admin,
}

impl ApiRole {
    #[must_use]
    pub const fn permits(self, needed: Self) -> bool {
        self.rank() >= needed.rank()
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Viewer => 0,
            Self::Operator => 1,
            Self::Admin => 2,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

impl Default for Management {
    fn default() -> Self {
        Self {
            listen: None,
            tokens: Vec::new(),
            requests_per_minute: 60,
            webhooks: Vec::new(),
        }
    }
}

/// Independently enabled listener addresses. Empty arrays disable a transport.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listeners {
    pub udp: Vec<SocketAddr>,
    pub tcp: Vec<SocketAddr>,
    pub dot: Vec<SocketAddr>,
    pub doh: Vec<SocketAddr>,
    pub doq: Vec<SocketAddr>,
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    pub allow_clients: Vec<IpNet>,
}

impl Default for Listeners {
    fn default() -> Self {
        Self {
            udp: vec!["127.0.0.1:5353".parse().expect("static address")],
            tcp: vec!["127.0.0.1:5353".parse().expect("static address")],
            dot: vec![],
            doh: vec![],
            doq: vec![],
            certificate: None,
            private_key: None,
            allow_clients: vec![
                "127.0.0.0/8".parse().expect("static CIDR"),
                "::1/128".parse().expect("static CIDR"),
            ],
        }
    }
}

/// Resolver mode. Recursive mode only uses a forwarder when fallback is explicit.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Recursive,
    Forward,
}

/// DNSSEC validates by default in both modes.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Resolver {
    pub mode: Mode,
    pub dnssec: bool,
    pub root_hints: Option<PathBuf>,
    pub trust_anchor: Option<PathBuf>,
    pub upstream_ca: Option<PathBuf>,
    pub upstreams: Vec<Upstream>,
    pub providers: Vec<ProviderSelection>,
    #[serde(skip)]
    pub automatic_transport: bool,
    pub cache_entries: u32,
    pub nameserver_cache_entries: u32,
    pub validation_cache_entries: u32,
    pub positive_ttl_secs: u32,
    pub negative_ttl_secs: u32,
    pub recursion_depth: u8,
    pub attempts: u8,
    pub upstream_timeout_ms: u32,
    pub fallback: Fallback,
}

impl Default for Resolver {
    fn default() -> Self {
        Self {
            mode: Mode::Recursive,
            dnssec: true,
            root_hints: None,
            trust_anchor: None,
            upstream_ca: None,
            upstreams: vec![],
            providers: vec![],
            automatic_transport: false,
            cache_entries: 4096,
            nameserver_cache_entries: 256,
            validation_cache_entries: 4096,
            positive_ttl_secs: 86400,
            negative_ttl_secs: 3600,
            recursion_depth: 24,
            attempts: 2,
            upstream_timeout_ms: 2000,
            fallback: Fallback::default(),
        }
    }
}

/// Optional forwarding path used only after an identified recursive timeout.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fallback {
    pub enabled: bool,
    pub recursive_timeout_ms: u32,
    pub timeout_ms: u32,
    pub attempts: u8,
    pub upstreams: Vec<Upstream>,
}

impl Default for Fallback {
    fn default() -> Self {
        Self {
            enabled: false,
            recursive_timeout_ms: 7000,
            timeout_ms: 2000,
            attempts: 1,
            upstreams: vec![],
        }
    }
}

/// Upstream identity is explicit; encrypted connections require a DNS certificate name.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub address: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub server_name: Option<String>,
    /// Optional `DoH` request path. The default is `/dns-query`.
    #[serde(default)]
    pub doh_path: Option<String>,
}

/// One bundled provider selection expanded into explicit runtime upstreams.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSelection {
    pub id: String,
    pub protocol: ProviderProtocol,
    #[serde(default)]
    pub address_family: providers::AddressFamily,
    pub encryption: Option<EncryptionPolicy>,
    pub transport_priority: Option<Vec<EncryptedProtocol>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
    Auto,
}

impl ProviderProtocol {
    fn explicit(self) -> Option<UpstreamProtocol> {
        match self {
            Self::Udp => Some(UpstreamProtocol::Udp),
            Self::Tcp => Some(UpstreamProtocol::Tcp),
            Self::Tls => Some(UpstreamProtocol::Tls),
            Self::Https => Some(UpstreamProtocol::Https),
            Self::Quic => Some(UpstreamProtocol::Quic),
            Self::Auto => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionPolicy {
    Required,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedProtocol {
    Quic,
    Https,
    Tls,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

/// Hard admission and IO bounds. Limits apply across all transports.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_in_flight: u32,
    pub max_connections: u32,
    pub max_clients: u32,
    pub queries_per_second: u32,
    pub query_timeout_ms: u32,
    pub io_timeout_ms: u32,
    pub max_message_bytes: u16,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_in_flight: 128,
            max_connections: 64,
            max_clients: 4096,
            queries_per_second: 100,
            query_timeout_ms: 10000,
            io_timeout_ms: 5000,
            max_message_bytes: 4096,
        }
    }
}

impl Config {
    /// Read at most 64 KiB, resolve paths, and validate before any sockets open.
    ///
    /// # Errors
    /// Returns a safe startup error for unreadable or invalid configuration.
    pub fn load(path: &Path) -> Result<Self, String> {
        let source = read_bounded(path, 65536)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Self::parse(
            std::str::from_utf8(&source).map_err(|_| "config must be UTF-8")?,
            base,
        )
    }

    /// Parse stored TOML using an explicit base for relative paths.
    ///
    /// # Errors
    /// Returns a safe parse or validation error for malformed configuration.
    pub fn parse(source: &str, base: &Path) -> Result<Self, String> {
        if source.len() > 65536 {
            return Err("config source exceeds 65536 bytes".into());
        }
        let mut config: Self = toml::from_str(source)
            .map_err(|error| format!("invalid config at {:?}", error.span()))?;
        for item in [
            &mut config.listen.certificate,
            &mut config.listen.private_key,
            &mut config.resolver.root_hints,
            &mut config.resolver.trust_anchor,
            &mut config.resolver.upstream_ca,
        ]
        .into_iter()
        .flatten()
        {
            if item.is_relative() {
                *item = base.join(&*item);
            }
        }
        for list in &mut config.filtering.lists {
            if let Some(path) = &mut list.path
                && path.is_relative()
            {
                *path = base.join(&*path);
            }
        }
        for webhook in &mut config.management.webhooks {
            if webhook.secret_file.is_relative() {
                webhook.secret_file = base.join(&webhook.secret_file);
            }
        }
        config.expand_provider_selections()?;
        config.validate()?;
        Ok(config)
    }

    fn expand_provider_selections(&mut self) -> Result<(), String> {
        if self.resolver.providers.is_empty() {
            return Ok(());
        }
        if self.resolver.mode != Mode::Forward {
            return Err("provider presets are only available in forward mode".into());
        }
        if !self.resolver.upstreams.is_empty() {
            return Err("provider presets cannot be mixed with custom upstreams".into());
        }
        let catalog = providers::Catalog::bundled()?;
        let automatic = self
            .resolver
            .providers
            .iter()
            .filter(|selection| selection.protocol == ProviderProtocol::Auto)
            .count();
        if automatic != 0 && automatic != self.resolver.providers.len() {
            return Err("automatic and explicit provider transports cannot be mixed".into());
        }
        let mut upstreams = Vec::new();
        for selection in &self.resolver.providers {
            if selection.protocol == ProviderProtocol::Auto {
                if selection.encryption.unwrap_or(EncryptionPolicy::Required)
                    != EncryptionPolicy::Required
                {
                    return Err("automatic provider transport requires encryption".into());
                }
                upstreams.extend(catalog.select_encrypted(
                    &selection.id,
                    selection.address_family,
                    selection.transport_priority.as_deref(),
                )?);
            } else {
                if selection.encryption.is_some() || selection.transport_priority.is_some() {
                    return Err(
                        "encryption and transport_priority are only valid with protocol auto"
                            .into(),
                    );
                }
                upstreams.extend(
                    catalog.select(
                        &selection.id,
                        selection
                            .protocol
                            .explicit()
                            .ok_or("missing explicit protocol")?,
                        selection.address_family,
                    )?,
                );
            }
        }
        if upstreams.len() > 8 {
            return Err("provider presets resolve to more than 8 upstreams".into());
        }
        self.resolver.upstreams = upstreams;
        self.resolver.automatic_transport = automatic != 0;
        Ok(())
    }

    /// Validate schema, transport combinations, ACLs, and bounded resource settings.
    ///
    /// # Errors
    /// Returns a description of an invalid startup setting.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("schema_version must be 1; no implicit migrations".into());
        }
        let sets = [
            &self.listen.udp,
            &self.listen.tcp,
            &self.listen.dot,
            &self.listen.doh,
            &self.listen.doq,
        ];
        let count: usize = sets.iter().map(|set| set.len()).sum();
        if count == 0 || count > 16 {
            return Err("enable between 1 and 16 DNS listeners".into());
        }
        for set in sets {
            for (index, address) in set.iter().enumerate() {
                if address.port() == 0 || set[..index].contains(address) {
                    return Err("listener ports must be nonzero and unique per transport".into());
                }
            }
        }
        if self.listen.allow_clients.is_empty() || self.listen.allow_clients.len() > 128 {
            return Err("allow_clients must contain 1..128 CIDRs".into());
        }
        let encrypted = !self.listen.dot.is_empty()
            || !self.listen.doh.is_empty()
            || !self.listen.doq.is_empty();
        if encrypted && (self.listen.certificate.is_none() || self.listen.private_key.is_none()) {
            return Err("encrypted listeners require certificate and private_key".into());
        }
        if self
            .metrics
            .is_some_and(|address| !address.ip().is_loopback() || address.port() == 0)
        {
            return Err("metrics must bind a nonzero loopback port".into());
        }
        self.validate_management()?;
        self.filtering.validate()?;
        self.validate_resolver()
    }

    fn validate_management(&self) -> Result<(), String> {
        let api = &self.management;
        if api.listen.is_none() {
            if !api.tokens.is_empty() || !api.webhooks.is_empty() {
                return Err("management tokens and webhooks require an enabled listener".into());
            }
            return Ok(());
        }
        let address = api.listen.expect("checked listener");
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err("management API must bind a nonzero loopback port".into());
        }
        if api.tokens.is_empty() || api.tokens.len() > 16 {
            return Err("management API needs 1..16 tokens".into());
        }
        if !(1..=600).contains(&api.requests_per_minute) {
            return Err("management requests_per_minute must be in 1..=600".into());
        }
        if api.webhooks.len() > 8 {
            return Err("at most 8 management webhooks are allowed".into());
        }
        let mut names = std::collections::HashSet::new();
        for token in &api.tokens {
            if !valid_api_name(&token.name)
                || !names.insert(&token.name)
                || token.sha256.len() != 64
                || !token.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err("management tokens need unique names and 64-hex SHA-256 hashes".into());
            }
        }
        let mut webhooks = std::collections::HashSet::new();
        for webhook in &api.webhooks {
            if !valid_api_name(&webhook.id)
                || !webhooks.insert(&webhook.id)
                || webhook.url.len() > 2048
                || !webhook.url.starts_with("https://")
                || webhook.url.contains(['#', '@'])
            {
                return Err("management webhooks need unique IDs and HTTPS URLs without credentials or fragments".into());
            }
        }
        Ok(())
    }

    fn validate_resolver(&self) -> Result<(), String> {
        let r = &self.resolver;
        if r.mode == Mode::Forward && r.upstreams.is_empty() {
            return Err("forward mode needs explicit upstreams".into());
        }
        if r.mode == Mode::Recursive && !r.upstreams.is_empty() {
            return Err("recursive mode rejects unused upstreams".into());
        }
        if r.mode == Mode::Recursive && !r.providers.is_empty() {
            return Err("recursive mode rejects provider presets".into());
        }
        if r.mode == Mode::Forward && r.root_hints.is_some() {
            return Err("root_hints is only used in recursive mode".into());
        }
        if !r.dnssec && r.trust_anchor.is_some() {
            return Err("trust_anchor requires DNSSEC validation".into());
        }
        self.validate_fallback()?;
        if r.upstream_ca.is_some()
            && !r
                .upstreams
                .iter()
                .chain(r.fallback.upstreams.iter())
                .any(|u| {
                    matches!(
                        u.protocol,
                        UpstreamProtocol::Tls | UpstreamProtocol::Https | UpstreamProtocol::Quic
                    )
                })
        {
            return Err("upstream_ca requires encrypted forwarding".into());
        }
        self.validate_upstreams()?;
        for (name, value, maximum) in [
            ("cache_entries", r.cache_entries, 65536),
            ("nameserver_cache_entries", r.nameserver_cache_entries, 4096),
            (
                "validation_cache_entries",
                r.validation_cache_entries,
                65536,
            ),
            ("positive_ttl_secs", r.positive_ttl_secs, 604_800),
            ("negative_ttl_secs", r.negative_ttl_secs, 86400),
            ("recursion_depth", u32::from(r.recursion_depth), 64),
            ("attempts", u32::from(r.attempts), 5),
            ("upstream_timeout_ms", r.upstream_timeout_ms, 30000),
            (
                "fallback.recursive_timeout_ms",
                r.fallback.recursive_timeout_ms,
                60000,
            ),
            ("fallback.timeout_ms", r.fallback.timeout_ms, 30000),
            ("fallback.attempts", u32::from(r.fallback.attempts), 5),
            ("max_in_flight", self.limits.max_in_flight, 4096),
            ("max_connections", self.limits.max_connections, 1024),
            ("max_clients", self.limits.max_clients, 65536),
            ("queries_per_second", self.limits.queries_per_second, 10000),
            ("query_timeout_ms", self.limits.query_timeout_ms, 60000),
            ("io_timeout_ms", self.limits.io_timeout_ms, 30000),
        ] {
            if value == 0 || value > maximum {
                return Err(format!("{name} must be in 1..={maximum}"));
            }
        }
        if self.limits.max_message_bytes < 512 {
            return Err("max_message_bytes must be at least 512".into());
        }
        Ok(())
    }

    fn validate_fallback(&self) -> Result<(), String> {
        let fallback = &self.resolver.fallback;
        if fallback.enabled && self.resolver.mode != Mode::Recursive {
            return Err("fallback is only available in recursive mode".into());
        }
        if fallback.enabled && fallback.upstreams.is_empty() {
            return Err("enabled fallback needs explicit upstreams".into());
        }
        if fallback.upstreams.len() > 8 {
            return Err("at most 8 fallback upstreams are allowed".into());
        }
        if fallback.enabled
            && fallback
                .recursive_timeout_ms
                .saturating_add(fallback.timeout_ms)
                > self.limits.query_timeout_ms
        {
            return Err("fallback budgets must fit within query_timeout_ms".into());
        }
        Ok(())
    }

    fn validate_upstreams(&self) -> Result<(), String> {
        let resolver = &self.resolver;
        if resolver.upstreams.len() > 8 {
            return Err("at most 8 upstreams are allowed".into());
        }
        for upstream in resolver
            .upstreams
            .iter()
            .chain(resolver.fallback.upstreams.iter())
        {
            if upstream.address.port() == 0
                || upstream.address.ip().is_unspecified()
                || upstream.address.ip().is_multicast()
            {
                return Err("invalid upstream address".into());
            }
            let encrypted = matches!(
                upstream.protocol,
                UpstreamProtocol::Tls | UpstreamProtocol::Https | UpstreamProtocol::Quic
            );
            if encrypted
                && upstream
                    .server_name
                    .as_ref()
                    .is_none_or(|name| name.is_empty() || name.len() > 253)
            {
                return Err("encrypted upstream needs server_name".into());
            }
            match &upstream.doh_path {
                Some(_) if upstream.protocol != UpstreamProtocol::Https => {
                    return Err("doh_path is only valid for https upstreams".into());
                }
                Some(path)
                    if path.len() <= 1024
                        && path.starts_with('/')
                        && !path.contains(['?', '#'])
                        && path.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) => {}
                None => {}
                Some(_) => {
                    return Err(
                        "doh_path must be an absolute ASCII path without query or fragment".into(),
                    );
                }
            }
            if self.upstream_points_to_listener(upstream.address) {
                return Err("upstream must not point to a Lumen listener".into());
            }
        }
        Ok(())
    }

    fn upstream_points_to_listener(&self, upstream: SocketAddr) -> bool {
        [
            &self.listen.udp,
            &self.listen.tcp,
            &self.listen.dot,
            &self.listen.doh,
            &self.listen.doq,
        ]
        .into_iter()
        .flatten()
        .any(|listener| {
            listener.port() == upstream.port()
                && (listener.ip() == upstream.ip()
                    || (listener.ip().is_unspecified() && listener.is_ipv4() == upstream.is_ipv4()))
        })
    }
}

fn valid_api_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// Read an operator file without allocating beyond the declared bound.
///
/// # Errors
/// Returns a file access or size error without including file contents.
pub fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| format!("cannot open {}", path.display()))?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read file")?;
    if bytes.len() as u64 > maximum {
        return Err(format!("file exceeds {maximum} bytes"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_unknown_fields_fail_closed() {
        assert!(toml::from_str::<Config>("schema_version = 1\nunknown = true").is_err());
        assert!(
            toml::from_str::<Config>("schema_version = 2")
                .unwrap()
                .validate()
                .is_err()
        );
        assert!(Config::default().validate().is_err());
        assert!(
            toml::from_str::<Config>("schema_version = 1")
                .unwrap()
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn rejects_open_metrics_missing_keys_and_unbounded_work() {
        let mut config: Config = toml::from_str("schema_version = 1").unwrap();
        config.metrics = Some("0.0.0.0:9000".parse().unwrap());
        assert!(config.validate().is_err());
        config.metrics = None;
        config.listen.dot.push("127.0.0.1:8853".parse().unwrap());
        assert!(config.validate().is_err());
        config.listen.dot.clear();
        config.limits.max_connections = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn encrypted_upstreams_need_identity_and_explicit_mode() {
        let mut config: Config = toml::from_str("schema_version = 1").unwrap();
        config.resolver.upstreams.push(Upstream {
            address: "1.1.1.1:853".parse().unwrap(),
            protocol: UpstreamProtocol::Tls,
            server_name: None,
            doh_path: None,
        });
        assert!(config.validate().is_err());
        config.resolver.mode = Mode::Forward;
        assert!(config.validate().is_err());
        config.resolver.upstreams[0].server_name = Some("cloudflare-dns.com".into());
        assert!(config.validate().is_ok());
        config.resolver.upstreams[0].protocol = UpstreamProtocol::Https;
        config.resolver.upstreams[0].address.set_port(443);
        config.resolver.upstreams[0].doh_path = Some("/custom-path".into());
        assert!(config.validate().is_ok());
        config.resolver.upstreams[0].doh_path = Some("https://bad.example/dns-query".into());
        assert!(config.validate().is_err());
        config.resolver.upstreams[0].doh_path = Some("/dns-query?bad=true".into());
        assert!(config.validate().is_err());
        config.resolver.upstreams[0].doh_path = Some("/dns-query".into());
        config.resolver.upstreams[0].protocol = UpstreamProtocol::Tls;
        assert!(config.validate().is_err());
    }

    #[test]
    fn fallback_is_explicit_bounded_and_cannot_loop() {
        let mut config: Config = toml::from_str("schema_version = 1").unwrap();
        config.resolver.fallback.enabled = true;
        assert!(config.validate().is_err());
        config.resolver.fallback.upstreams.push(Upstream {
            address: "1.1.1.1:853".parse().unwrap(),
            protocol: UpstreamProtocol::Tls,
            server_name: Some("cloudflare-dns.com".into()),
            doh_path: None,
        });
        assert!(config.validate().is_ok());
        config.resolver.fallback.recursive_timeout_ms = 9000;
        config.resolver.fallback.timeout_ms = 2000;
        assert!(config.validate().is_err());
        config.resolver.fallback.recursive_timeout_ms = 7000;
        config.resolver.fallback.upstreams[0].address = "127.0.0.1:5353".parse().unwrap();
        assert!(config.validate().is_err());
    }
    #[test]
    fn example_configs_paths_size_limits_and_nested_fields() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for name in [
            "lumen.toml",
            "forward.example.toml",
            "filtering.example.toml",
        ] {
            assert!(Config::load(&root.join("config").join(name)).is_ok());
        }
        assert!(toml::from_str::<Config>("schema_version = 1\n[limits]\nmisspelled = 1").is_err());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "schema_version = 1\n[resolver]\nroot_hints = 'root.hints'",
        )
        .unwrap();
        assert_eq!(
            Config::load(&path).unwrap().resolver.root_hints,
            Some(directory.path().join("root.hints"))
        );
        fs::write(&path, "schema_version = 1\n[[filtering.lists]]\nid = 'local'\nformat = 'domains'\npath = 'block.txt'").unwrap();
        assert_eq!(
            Config::load(&path).unwrap().filtering.lists[0].path,
            Some(directory.path().join("block.txt"))
        );
        fs::write(&path, " ".repeat(65537)).unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn release_default_is_private_and_old_schema_one_still_works() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let config = Config::load(&root.join("config/lumen.toml")).unwrap();
        assert!(config.metrics.is_none());
        assert!(config.management.listen.is_none());
        assert!(config.management.tokens.is_empty());
        assert!(config.management.webhooks.is_empty());
        assert_eq!(config.resolver.mode, Mode::Recursive);
        assert!(config.resolver.dnssec);
        assert!(config.resolver.upstreams.is_empty());
        assert!(!config.resolver.fallback.enabled);
        assert!(config.resolver.fallback.upstreams.is_empty());
        assert!(config.listen.udp.iter().all(|item| item.ip().is_loopback()));
        assert!(config.listen.tcp.iter().all(|item| item.ip().is_loopback()));
        assert!(config.listen.dot.is_empty());
        assert!(config.listen.doh.is_empty());
        assert!(config.listen.doq.is_empty());
        assert!(
            config
                .listen
                .allow_clients
                .iter()
                .all(|network| network.addr().is_loopback())
        );
        assert!(config.filtering.rules.allow.is_empty());
        assert!(config.filtering.rules.block.is_empty());
        assert!(config.filtering.lists.is_empty());
        assert!(config.filtering.profiles.is_empty());
        assert!(config.filtering.devices.is_empty());
        assert!(!config.filtering.decision_log);

        let old: Config =
            toml::from_str("schema_version = 1\n[resolver]\nmode = 'recursive'\ndnssec = true")
                .unwrap();
        assert!(!old.resolver.fallback.enabled);
        assert!(old.validate().is_ok());
    }

    #[test]
    fn provider_presets_expand_during_load_and_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "schema_version = 1\n[resolver]\nmode = 'forward'\n[[resolver.providers]]\nid = 'cloudflare-unfiltered'\nprotocol = 'tls'\naddress_family = 'ipv4'\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.resolver.providers.len(), 1);
        assert!(!config.resolver.upstreams.is_empty());
        assert!(config.resolver.upstreams.iter().all(|upstream| {
            upstream.address.is_ipv4()
                && upstream.address.port() == 853
                && upstream.protocol == UpstreamProtocol::Tls
                && upstream.server_name.as_deref() == Some("one.one.one.one")
        }));

        fs::write(
            &path,
            "schema_version = 1\n[resolver]\nmode = 'forward'\n[[resolver.providers]]\nid = 'missing'\nprotocol = 'tls'\n",
        )
        .unwrap();
        assert!(Config::load(&path).is_err());

        fs::write(
            &path,
            "schema_version = 1\n[resolver]\nmode = 'forward'\n[[resolver.providers]]\nid = 'quad9-unfiltered'\nprotocol = 'auto'\nencryption = 'required'\naddress_family = 'ipv4'\ntransport_priority = ['tls', 'https']\n",
        )
        .unwrap();
        let automatic = Config::load(&path).unwrap();
        assert!(automatic.resolver.automatic_transport);
        assert_eq!(automatic.resolver.upstreams.len(), 4);
        assert!(
            automatic.resolver.upstreams[..2]
                .iter()
                .all(|upstream| upstream.protocol == UpstreamProtocol::Tls)
        );
        assert!(
            automatic.resolver.upstreams[2..]
                .iter()
                .all(|upstream| upstream.protocol == UpstreamProtocol::Https)
        );

        fs::write(
            &path,
            "schema_version = 1\n[resolver]\nmode = 'forward'\n[[resolver.providers]]\nid = 'quad9-unfiltered'\nprotocol = 'auto'\ntransport_priority = ['tls', 'tls']\n",
        )
        .unwrap();
        assert!(Config::load(&path).is_err());

        fs::write(
            &path,
            "schema_version = 1\n[resolver]\nmode = 'forward'\n[[resolver.providers]]\nid = 'cloudflare-unfiltered'\nprotocol = 'tls'\n[[resolver.upstreams]]\naddress = '1.1.1.1:853'\nprotocol = 'tls'\nserver_name = 'cloudflare-dns.com'\n",
        )
        .unwrap();
        assert!(Config::load(&path).is_err());
    }

    #[test]
    fn management_api_is_explicit_local_and_bounded() {
        let base = Path::new("/operator");
        let source = "schema_version = 1\n[management]\nlisten = '127.0.0.1:9080'\nrequests_per_minute = 60\n[[management.tokens]]\nname = 'admin'\nrole = 'admin'\nsha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n[[management.webhooks]]\nid = 'home'\nurl = 'https://home.example/hook'\nsecret_file = 'webhook.key'\n";
        let config = Config::parse(source, base).unwrap();
        assert_eq!(config.management.tokens.len(), 1);
        assert_eq!(
            config.management.webhooks[0].secret_file,
            base.join("webhook.key")
        );

        assert!(Config::parse(&source.replace("127.0.0.1", "0.0.0.0"), base).is_err());
        assert!(
            Config::parse(&source.replace("[[management.tokens]]", "# no token"), base).is_err()
        );
        assert!(Config::parse(&source.replace("https://", "http://"), base).is_err());
    }
}

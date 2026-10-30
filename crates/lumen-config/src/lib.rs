// SPDX-License-Identifier: Apache-2.0
//! Versioned startup configuration. Unknown fields and unsafe limits fail closed.

use ipnet::IpNet;
use serde::Deserialize;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

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
        let mut config: Self =
            toml::from_str(std::str::from_utf8(&source).map_err(|_| "config must be UTF-8")?)
                .map_err(|error| format!("invalid config at {:?}", error.span()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
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
        config.validate()?;
        Ok(config)
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
        self.filtering.validate()?;
        self.validate_resolver()
    }

    fn validate_resolver(&self) -> Result<(), String> {
        let r = &self.resolver;
        if r.mode == Mode::Forward && r.upstreams.is_empty() {
            return Err("forward mode needs explicit upstreams".into());
        }
        if r.mode == Mode::Recursive && !r.upstreams.is_empty() {
            return Err("recursive mode rejects unused upstreams".into());
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
        });
        assert!(config.validate().is_err());
        config.resolver.mode = Mode::Forward;
        assert!(config.validate().is_err());
        config.resolver.upstreams[0].server_name = Some("cloudflare-dns.com".into());
        assert!(config.validate().is_ok());
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
        for name in ["lumen.toml", "forward.toml", "filtering.toml"] {
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
}

// SPDX-License-Identifier: Apache-2.0
//! Versioned startup configuration. Unknown fields and unsafe limits fail closed.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

pub mod providers;

/// Startup configuration; relative paths resolve beside the config file.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub listen: Listeners,
    pub resolver: Resolver,
    pub limits: Limits,
    pub filtering: lumen_filter::config::Config,
    pub metrics: Option<SocketAddr>,
    pub management: Management,
    pub web: Web,
    /// Optional `DNSCrypt` v2 server (UDP and TCP). Off by default.
    pub dnscrypt: DnsCrypt,
    /// Authoritative zones served from operator-managed records.
    pub zones: Vec<Zone>,
    /// Conditional forwarding: names under `domain` go to these resolvers.
    pub forwarders: Vec<Forwarder>,
    /// TSIG keys that authenticate zone updates and transfers.
    pub tsig_keys: Vec<TsigKey>,
}

/// Most authoritative zones, views per zone, and conditional forwarders.
pub const MAX_ZONES: usize = 64;
pub const MAX_ZONE_VIEWS: usize = 8;
pub const MAX_FORWARDERS: usize = 64;
/// Largest zone file or inline zone text.
pub const MAX_ZONE_BYTES: usize = 1_048_576;

/// One authoritative zone. Records come from an RFC 1035 zone file (`file`) or inline `text`.
///
/// `views` give matching clients a different copy of the zone (split-horizon DNS). Clients
/// that match no view get the zone's own `file` or `text`.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Zone {
    pub name: String,
    pub file: Option<PathBuf>,
    pub text: Option<String>,
    pub views: Vec<ZoneView>,
    /// `SQLite` journal that makes the zone dynamic (RFC 2136 updates survive restarts). Needs
    /// `file`, at least one `update_rules` entry, and cannot be combined with `views`.
    pub journal: Option<PathBuf>,
    /// Scoped RFC 2136 update permissions. Without a rule, updates are refused.
    pub update_rules: Vec<UpdateRule>,
    /// Names of `tsig_keys` that may transfer this zone (AXFR and IXFR, over TCP). Empty refuses
    /// every transfer.
    pub transfer_keys: Vec<String>,
}

/// What one TSIG key may change in a dynamic zone.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateRule {
    pub key: String,
    /// Names the key may change: an exact name, or `*.suffix` for any name below `suffix`. Names
    /// are relative to nothing: write them fully, without a trailing dot.
    pub names: Vec<String>,
    /// Record types the key may add or delete, such as `A`, `AAAA`, `TXT`, `CNAME`, `PTR`, `SRV`.
    pub types: Vec<String>,
}

/// A shared TSIG secret. The secret never appears in the config; it is read from `secret_file`
/// (base64 text, at least 16 bytes decoded, a single line).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TsigKey {
    pub name: String,
    pub algorithm: String,
    pub secret_file: Option<PathBuf>,
}

/// Record types a TSIG key may be allowed to change. Structural and DNSSEC types are excluded.
pub const UPDATABLE_TYPES: [&str; 9] = [
    "A", "AAAA", "CNAME", "TXT", "PTR", "SRV", "MX", "CAA", "TLSA",
];
/// Most records one update message may change.
pub const MAX_UPDATE_RECORDS: usize = 64;

/// An alternative copy of a zone for the listed client networks. First match wins.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ZoneView {
    pub clients: Vec<IpNet>,
    pub file: Option<PathBuf>,
    pub text: Option<String>,
}

/// Send one domain (and everything below it) to specific resolvers, such as an internal
/// directory server. Answers are not DNSSEC-validated by Lumen.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Forwarder {
    pub domain: String,
    pub upstreams: Vec<SocketAddr>,
}

/// `DNSCrypt` v2 listener. It answers over both UDP and TCP on each address.
///
/// The long-term Ed25519 provider key is stored in `key_file` (created with mode `0600` on first
/// start if missing). Short-lived resolver keys and certificates rotate automatically in memory.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsCrypt {
    pub enabled: bool,
    pub listen: Vec<SocketAddr>,
    /// Provider name clients query for the certificate, such as `2.dnscrypt-cert.example.net`.
    pub provider_name: String,
    /// 32-byte Ed25519 provider seed, hex encoded. Required when enabled.
    pub key_file: Option<PathBuf>,
    /// Certificate lifetime. Keys rotate at half this age.
    pub cert_hours: u32,
}

impl Default for DnsCrypt {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: vec![],
            provider_name: String::new(),
            key_file: None,
            cert_hours: 24,
        }
    }
}

/// Embedded static UI listeners. Empty address lists disable hosting.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Web {
    pub http: Vec<SocketAddr>,
    pub https: Vec<SocketAddr>,
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    pub max_connections: u16,
    /// Optional external sign-in for the console (`OpenID` Connect). Off by default.
    pub oidc: Oidc,
}

/// Where the console redirects the browser after an external sign-in.
pub const OIDC_CALLBACK_PATH: &str = "/api/login/oidc/callback";

/// External console login through any `OpenID` Connect provider (Authentik, Authelia, Pocket ID,
/// Octelium, Keycloak, and similar). Disabled by default; the built-in login always stays.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Oidc {
    pub enabled: bool,
    /// Text of the sign-in button, for example `Authentik`.
    pub label: String,
    /// Issuer URL. `https://` only, except `http://` on a loopback address.
    pub issuer: String,
    pub client_id: String,
    /// File holding the client secret. Leave unset for a public client (PKCE only).
    pub client_secret_file: Option<PathBuf>,
    /// Optional override. Empty (the default) means Lumen builds the callback address from the
    /// address the browser used to reach the console, so it works with a name, an IP address,
    /// `http` or `https`. Register that address with the provider. Set this only when a reverse
    /// proxy hides the real address; it must then end in [`OIDC_CALLBACK_PATH`].
    pub redirect_url: String,
    /// Extra CA certificates (PEM) for a provider with a private certificate authority.
    pub ca_file: Option<PathBuf>,
    /// Claim used to name a new account.
    pub username_claim: String,
    /// Claim that lists a person's groups.
    pub groups_claim: String,
    /// New accounts of members of this group start as administrators; others start as users.
    pub admin_group: Option<String>,
    /// Keep roles in step with `admin_group` on every sign-in, not only on the first one.
    /// Members become administrators and everyone else a user. The last administrator is never
    /// demoted.
    pub sync_role: bool,
    /// Also end the provider's session when someone signs out of the console after signing in
    /// through it. The provider must allow the console address as a post-logout redirect.
    pub single_logout: bool,
}

impl Default for Oidc {
    fn default() -> Self {
        Self {
            enabled: false,
            label: "Single sign-on".into(),
            issuer: String::new(),
            client_id: String::new(),
            client_secret_file: None,
            redirect_url: String::new(),
            ca_file: None,
            username_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            admin_group: None,
            sync_role: false,
            single_logout: false,
        }
    }
}

/// `https://` URLs, or `http://` only when the host is a loopback address or `localhost`.
#[must_use]
pub fn oidc_url_ok(value: &str) -> bool {
    if value.len() > 2048 || value.bytes().any(|b| b <= 0x20 || b == 0x7f) || value.contains('#') {
        return false;
    }
    if value.starts_with("https://") {
        return true;
    }
    let Some(rest) = value.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?']).next().unwrap_or("");
    let host = host.strip_prefix('[').map_or_else(
        || host.rsplit_once(':').map_or(host, |(name, _)| name),
        |ipv6| ipv6.split(']').next().unwrap_or(""),
    );
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Default for Web {
    fn default() -> Self {
        Self {
            http: Vec::new(),
            https: Vec::new(),
            certificate: None,
            private_key: None,
            max_connections: 64,
            oidc: Oidc::default(),
        }
    }
}

/// Opt-in local management API. Bearer-token hashes stay in operator config.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Management {
    pub listen: Option<SocketAddr>,
    pub tokens: Vec<ApiToken>,
    pub requests_per_minute: u16,
    pub webhooks: Vec<Webhook>,
}

/// Signed outbound audit-event webhook.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Webhook {
    pub id: String,
    pub url: String,
    pub secret_file: PathBuf,
}

/// One named API principal with a fixed role and SHA-256 token hash.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiToken {
    pub name: String,
    pub role: ApiRole,
    pub sha256: String,
}

/// Management scopes. Higher roles include lower-role actions.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listeners {
    pub udp: Vec<SocketAddr>,
    pub tcp: Vec<SocketAddr>,
    pub dot: Vec<SocketAddr>,
    pub doh: Vec<SocketAddr>,
    pub doq: Vec<SocketAddr>,
    /// DNS over HTTP/3 (RFC 9250-style QUIC transport with the `h3` ALPN) at `/dns-query`.
    pub doh3: Vec<SocketAddr>,
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
            doh3: vec![],
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
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Recursive,
    Forward,
}

/// Most bundled providers a forward-mode config may select.
pub const MAX_PROVIDERS: usize = 8;
/// Most custom upstreams, next to any providers.
pub const MAX_CUSTOM_UPSTREAMS: usize = 8;
/// Most endpoints (addresses and transports) all providers and upstreams may expand to.
pub const MAX_FORWARD_ENDPOINTS: usize = 128;

/// How forward mode spreads queries across its providers and upstreams.
///
/// The order of `providers` is their rank. Custom upstreams rank after the providers.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardStrategy {
    /// Ranked fallback: the first provider answers, and the next one is used only when it
    /// fails (connection error or timeout). A DNS answer such as NXDOMAIN is final.
    Failover,
    /// Fastest first: providers are ordered by how quickly they recently answered, so the
    /// fastest takes the query and the others stand by.
    Fastest,
    /// Round-robin: each new query starts at the next provider in turn, spreading queries
    /// evenly. A failing provider is skipped for that query.
    RoundRobin,
    /// Race: every provider gets every query at the same time and the first answer wins.
    /// The fastest possible answer, but all providers see every lookup.
    Race,
}

/// DNSSEC validates by default in both modes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Independent serialized feature switches, not one state.
pub struct Resolver {
    pub mode: Mode,
    pub dnssec: bool,
    pub root_hints: Option<PathBuf>,
    pub trust_anchor: Option<PathBuf>,
    pub upstream_ca: Option<PathBuf>,
    pub upstreams: Vec<Upstream>,
    pub providers: Vec<ProviderSelection>,
    /// How forward mode uses several providers. Unset keeps the older behavior: ranked
    /// fallback for automatic transports, fastest first otherwise.
    pub strategy: Option<ForwardStrategy>,
    #[serde(skip)]
    pub automatic_transport: bool,
    /// Endpoints each provider selection expanded to, in order. They add up to
    /// `provider_upstreams`; every custom upstream after them is a group of one.
    #[serde(skip)]
    pub provider_groups: Vec<usize>,
    /// Leading entries of `upstreams` that came from provider presets.
    #[serde(skip)]
    pub provider_upstreams: usize,
    pub cache_entries: u32,
    pub nameserver_cache_entries: u32,
    pub validation_cache_entries: u32,
    pub positive_ttl_secs: u32,
    pub negative_ttl_secs: u32,
    pub recursion_depth: u8,
    pub attempts: u8,
    pub upstream_timeout_ms: u32,
    /// Serve standards-defined local-only zones without sending them to public DNS.
    pub local_zones: bool,
    /// Export extra fixed-cardinality recursive attempt metrics. No names or addresses.
    pub diagnostics: bool,
    pub fallback: Fallback,
    pub warm: Warm,
    pub prefetch: Prefetch,
    /// Bounded RFC 8767 stale answers. Off by default.
    pub serve_stale: ServeStale,
    /// Optional on-disk DNS response cache. Off by default because names are sensitive.
    pub persistent_cache: PersistentCache,
    /// Start a second recursion for a lookup still unanswered after this many ms; 0 is off.
    pub hedge_ms: u32,
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
            strategy: None,
            automatic_transport: false,
            provider_groups: vec![],
            provider_upstreams: 0,
            cache_entries: 4096,
            nameserver_cache_entries: 1024,
            validation_cache_entries: 4096,
            positive_ttl_secs: 86400,
            negative_ttl_secs: 3600,
            recursion_depth: 24,
            attempts: 2,
            upstream_timeout_ms: 2000,
            local_zones: true,
            diagnostics: false,
            fallback: Fallback::default(),
            warm: Warm::default(),
            prefetch: Prefetch::default(),
            serve_stale: ServeStale::default(),
            persistent_cache: PersistentCache::default(),
            hedge_ms: 0,
        }
    }
}

/// RFC 8767 stale-answer policy. Stale data is returned with a small TTL while one bounded
/// background refresh runs. DNSSEC-authenticated data is never served after expiry.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServeStale {
    pub enabled: bool,
    /// Maximum time an expired answer may remain eligible.
    pub max_age_secs: u32,
    /// TTL placed on a stale response.
    pub answer_ttl_secs: u32,
}

impl Default for ServeStale {
    fn default() -> Self {
        Self {
            enabled: false,
            max_age_secs: 86_400,
            answer_ttl_secs: 30,
        }
    }
}

/// Opt-in persistent DNS response cache. It stores names and answers, but never client data.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PersistentCache {
    pub enabled: bool,
    /// Separate `SQLite` file. Required when enabled.
    pub path: Option<PathBuf>,
    pub max_entries: u32,
    pub max_bytes: u64,
    /// Additional cap on the authoritative TTL written to disk.
    pub max_ttl_secs: u32,
}

impl Default for PersistentCache {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            max_entries: 16_384,
            max_bytes: 64 * 1024 * 1024,
            max_ttl_secs: 604_800,
        }
    }
}

/// Startup priming of root and top-level-zone delegations and DNSSEC keys.
///
/// Queries name only zones listed here, never client data, and run with fixed low
/// concurrency in the background. Disabled by default.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Warm {
    pub enabled: bool,
    /// Zones to prime in addition to the root, without a trailing dot.
    pub zones: Vec<String>,
}

impl Default for Warm {
    fn default() -> Self {
        Self {
            enabled: false,
            zones: [
                "com", "net", "org", "info", "de", "uk", "eu", "nl", "fr", "ch", "io", "us",
            ]
            .map(String::from)
            .to_vec(),
        }
    }
}

/// Bounded refresh of frequently requested names when their cached answer expires.
///
/// Names are held in memory only, never logged or exported. Disabled by default.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Prefetch {
    pub enabled: bool,
    /// Lookups needed within one cache lifetime before the answer is refreshed.
    pub min_hits: u8,
    /// Maximum number of names tracked at once.
    pub max_tracked: u16,
    /// Maximum refreshes running at the same time.
    pub max_concurrent: u8,
    /// Maximum refreshes started in any minute.
    pub budget_per_minute: u16,
}

impl Default for Prefetch {
    fn default() -> Self {
        Self {
            enabled: false,
            min_hits: 2,
            max_tracked: 1024,
            max_concurrent: 4,
            budget_per_minute: 240,
        }
    }
}

/// Optional forwarding path used only after an identified recursive timeout.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSelection {
    pub id: String,
    pub protocol: ProviderProtocol,
    #[serde(default)]
    pub address_family: providers::AddressFamily,
    pub encryption: Option<EncryptionPolicy>,
    pub transport_priority: Option<Vec<EncryptedProtocol>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionPolicy {
    Required,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptedProtocol {
    Quic,
    Https,
    Tls,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    Udp,
    Tcp,
    Tls,
    Https,
    Quic,
}

/// Hard admission and IO bounds. Limits apply across all transports.
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    /// Whether `other` differs from this configuration only inside `[filtering]` (lists,
    /// rules, profiles, devices, schedules). Such a change can go live without restarting
    /// any listener. Anything uncertain answers `false`, which means a full reload.
    #[must_use]
    pub fn same_except_filtering(&self, other: &Self) -> bool {
        let without_filtering = |config: &Self| {
            let mut config = config.clone();
            config.filtering = lumen_filter::config::Config::default();
            toml::to_string(&config).ok()
        };
        match (without_filtering(self), without_filtering(other)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

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
            &mut config.resolver.persistent_cache.path,
            &mut config.dnscrypt.key_file,
            &mut config.web.certificate,
            &mut config.web.private_key,
            &mut config.web.oidc.client_secret_file,
            &mut config.web.oidc.ca_file,
        ]
        .into_iter()
        .flatten()
        {
            if item.is_relative() {
                *item = base.join(&*item);
            }
        }
        for zone in &mut config.zones {
            for path in std::iter::once(&mut zone.file)
                .chain(std::iter::once(&mut zone.journal))
                .chain(zone.views.iter_mut().map(|view| &mut view.file))
                .flatten()
            {
                if path.is_relative() {
                    *path = base.join(&*path);
                }
            }
        }
        for key in &mut config.tsig_keys {
            if let Some(path) = &mut key.secret_file
                && path.is_relative()
            {
                *path = base.join(&*path);
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
        if self.resolver.providers.len() > MAX_PROVIDERS {
            return Err(format!("at most {MAX_PROVIDERS} providers can be selected"));
        }
        let mut seen = std::collections::HashSet::new();
        if !self
            .resolver
            .providers
            .iter()
            .all(|p| seen.insert(p.id.as_str()))
        {
            return Err("a provider can be selected only once".into());
        }
        let mut upstreams = Vec::new();
        let mut groups = Vec::new();
        for selection in &self.resolver.providers {
            let before = upstreams.len();
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
            groups.push(upstreams.len() - before);
        }
        // Custom upstreams follow the provider addresses, so they act as ordered extras.
        let provided = upstreams.len();
        if self.resolver.upstreams.len() > MAX_CUSTOM_UPSTREAMS {
            return Err(format!(
                "at most {MAX_CUSTOM_UPSTREAMS} custom upstreams are allowed"
            ));
        }
        upstreams.append(&mut self.resolver.upstreams);
        if upstreams.len() > MAX_FORWARD_ENDPOINTS {
            return Err(format!(
                "providers and upstreams resolve to more than {MAX_FORWARD_ENDPOINTS} addresses"
            ));
        }
        self.resolver.provider_groups = groups;
        self.resolver.provider_upstreams = provided;
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
            &self.listen.doh3,
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
        self.validate_dnscrypt()?;
        self.validate_zones()?;
        if self.listen.allow_clients.is_empty() || self.listen.allow_clients.len() > 128 {
            return Err("allow_clients must contain 1..128 CIDRs".into());
        }
        let encrypted = !self.listen.dot.is_empty()
            || !self.listen.doh.is_empty()
            || !self.listen.doq.is_empty()
            || !self.listen.doh3.is_empty();
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
        self.validate_web()?;
        self.filtering.validate()?;
        self.validate_resolver()
    }

    fn validate_zones(&self) -> Result<(), String> {
        fn valid_name(name: &str) -> bool {
            (1..=253).contains(&name.len())
                && name.is_ascii()
                && !name.ends_with('.')
                && name.split('.').all(|label| {
                    (1..=63).contains(&label.len())
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
        }
        fn one_source(file: Option<&PathBuf>, text: Option<&String>) -> Result<(), String> {
            match (file, text) {
                (Some(_), None) => Ok(()),
                (None, Some(text)) if text.len() <= MAX_ZONE_BYTES => Ok(()),
                (None, Some(_)) => Err(format!("zone text exceeds {MAX_ZONE_BYTES} bytes")),
                _ => Err("each zone and view needs exactly one of file or text".into()),
            }
        }
        if self.zones.len() > MAX_ZONES || self.forwarders.len() > MAX_FORWARDERS {
            return Err("too many zones or forwarders".into());
        }
        let mut seen = std::collections::HashSet::new();
        for zone in &self.zones {
            if !valid_name(&zone.name) || !seen.insert(zone.name.to_ascii_lowercase()) {
                return Err("zone names must be unique DNS names without a trailing dot".into());
            }
            one_source(zone.file.as_ref(), zone.text.as_ref())?;
            if zone.views.len() > MAX_ZONE_VIEWS {
                return Err(format!("a zone may have at most {MAX_ZONE_VIEWS} views"));
            }
            for view in &zone.views {
                if view.clients.is_empty() || view.clients.len() > 32 {
                    return Err("each view needs 1..=32 client networks".into());
                }
                one_source(view.file.as_ref(), view.text.as_ref())?;
            }
        }
        self.validate_tsig(&valid_name)?;
        for forwarder in &self.forwarders {
            if !valid_name(&forwarder.domain) || !seen.insert(forwarder.domain.to_ascii_lowercase())
            {
                return Err(
                    "forwarder domains must be unique, and different from every zone name".into(),
                );
            }
            if forwarder.upstreams.is_empty()
                || forwarder.upstreams.len() > 8
                || forwarder.upstreams.iter().any(|upstream| {
                    upstream.port() == 0 || self.upstream_points_to_listener(*upstream)
                })
            {
                return Err(
                    "forwarders need 1..=8 upstreams that are not Lumen's own listeners".into(),
                );
            }
        }
        Ok(())
    }

    fn validate_tsig(&self, valid_name: &dyn Fn(&str) -> bool) -> Result<(), String> {
        if self.tsig_keys.len() > 32 {
            return Err("at most 32 tsig_keys".into());
        }
        let mut names = std::collections::HashSet::new();
        for key in &self.tsig_keys {
            if !valid_name(&key.name)
                || !names.insert(key.name.to_ascii_lowercase())
                || !matches!(
                    key.algorithm.as_str(),
                    "hmac-sha256" | "hmac-sha384" | "hmac-sha512"
                )
                || key.secret_file.is_none()
            {
                return Err("tsig_keys need a unique DNS-style name, algorithm hmac-sha256, hmac-sha384, or hmac-sha512, and a secret_file".into());
            }
        }
        for zone in &self.zones {
            let known = |name: &str| names.contains(&name.to_ascii_lowercase());
            if zone.transfer_keys.len() > 8 || !zone.transfer_keys.iter().all(|key| known(key)) {
                return Err("transfer_keys must name at most 8 configured tsig_keys".into());
            }
            if zone.journal.is_some() {
                if zone.file.is_none() || !zone.views.is_empty() || zone.update_rules.is_empty() {
                    return Err("a dynamic zone needs file and update_rules, and no views".into());
                }
            } else if !zone.update_rules.is_empty() {
                return Err("update_rules need a journal".into());
            }
            if zone.update_rules.len() > 16 {
                return Err("a zone may have at most 16 update_rules".into());
            }
            for rule in &zone.update_rules {
                let apex = zone.name.to_ascii_lowercase();
                let in_zone = |name: &str| {
                    let name = name.strip_prefix("*.").unwrap_or(name).to_ascii_lowercase();
                    name == apex || name.ends_with(&format!(".{apex}"))
                };
                if !known(&rule.key)
                    || rule.names.is_empty()
                    || rule.names.len() > 32
                    || !rule.names.iter().all(|name| {
                        valid_name(name.strip_prefix("*.").unwrap_or(name)) && in_zone(name)
                    })
                    || rule.types.is_empty()
                    || !rule
                        .types
                        .iter()
                        .all(|kind| UPDATABLE_TYPES.contains(&kind.to_ascii_uppercase().as_str()))
                {
                    return Err(format!(
                        "update_rules in zone {} need a configured key, names inside the zone, and types from {:?}",
                        zone.name, UPDATABLE_TYPES
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_dnscrypt(&self) -> Result<(), String> {
        let dnscrypt = &self.dnscrypt;
        if !dnscrypt.enabled {
            return Ok(());
        }
        if dnscrypt.listen.is_empty() || dnscrypt.listen.len() > 8 {
            return Err("dnscrypt.listen must contain 1..=8 addresses".into());
        }
        for (index, address) in dnscrypt.listen.iter().enumerate() {
            if address.port() == 0 || dnscrypt.listen[..index].contains(address) {
                return Err("dnscrypt listener ports must be nonzero and unique".into());
            }
        }
        let name = &dnscrypt.provider_name;
        let valid = (4..=253).contains(&name.len())
            && name.is_ascii()
            && !name.ends_with('.')
            && name.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            });
        if !valid || !name.to_ascii_lowercase().starts_with("2.dnscrypt-cert.") {
            return Err(
                "dnscrypt.provider_name must be a DNS name that starts with 2.dnscrypt-cert."
                    .into(),
            );
        }
        if dnscrypt.key_file.is_none() {
            return Err("dnscrypt.key_file is required when enabled".into());
        }
        if !(2..=168).contains(&dnscrypt.cert_hours) {
            return Err("dnscrypt.cert_hours must be in 2..=168".into());
        }
        Ok(())
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

    fn validate_web(&self) -> Result<(), String> {
        let web = &self.web;
        let addresses = web.http.iter().chain(&web.https).collect::<Vec<_>>();
        if addresses.len() > 8 {
            return Err("at most 8 web listeners are allowed".into());
        }
        if !(1..=1024).contains(&web.max_connections) {
            return Err("web max_connections must be in 1..=1024".into());
        }
        for (index, address) in addresses.iter().enumerate() {
            if address.port() == 0
                || addresses[..index]
                    .iter()
                    .any(|other| socket_conflicts(address, other))
            {
                return Err("web listener ports must be nonzero and unique".into());
            }
        }
        if web.https.is_empty() {
            if web.certificate.is_some() || web.private_key.is_some() {
                return Err("web certificate and private_key require HTTPS listeners".into());
            }
        } else if web.certificate.is_none() || web.private_key.is_none() {
            return Err("web HTTPS requires certificate and private_key".into());
        }
        let occupied = self
            .listen
            .tcp
            .iter()
            .chain(&self.listen.dot)
            .chain(&self.listen.doh)
            .chain(self.metrics.iter())
            .chain(self.management.listen.iter());
        if addresses.iter().any(|address| {
            occupied
                .clone()
                .any(|other| socket_conflicts(address, other))
        }) {
            return Err("web listener conflicts with another TCP listener".into());
        }
        self.validate_oidc()
    }

    fn validate_oidc(&self) -> Result<(), String> {
        let oidc = &self.web.oidc;
        let claim_ok = |name: &str| {
            (1..=64).contains(&name.len())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
        };
        if !oidc.enabled {
            return Ok(());
        }
        if self.web.http.is_empty() && self.web.https.is_empty() {
            return Err("web.oidc needs a web listener".into());
        }
        if !oidc_url_ok(&oidc.issuer) {
            return Err("web.oidc.issuer must be an https URL (http only on loopback)".into());
        }
        if !oidc.redirect_url.is_empty()
            && (!oidc_url_ok(&oidc.redirect_url)
                || !oidc.redirect_url.ends_with(OIDC_CALLBACK_PATH))
        {
            return Err(format!(
                "web.oidc.redirect_url, when set, must be an https URL ending in {OIDC_CALLBACK_PATH}"
            ));
        }
        if oidc.client_id.is_empty()
            || oidc.client_id.len() > 256
            || oidc.client_id.chars().any(char::is_control)
        {
            return Err("web.oidc.client_id must be 1..=256 characters".into());
        }
        if oidc.label.trim().is_empty()
            || oidc.label.chars().count() > 40
            || oidc.label.chars().any(char::is_control)
        {
            return Err("web.oidc.label must be 1..=40 characters".into());
        }
        if !claim_ok(&oidc.username_claim) || !claim_ok(&oidc.groups_claim) {
            return Err("web.oidc claim names must be 1..=64 simple characters".into());
        }
        if oidc.admin_group.as_ref().is_some_and(|group| {
            group.is_empty() || group.len() > 256 || group.chars().any(char::is_control)
        }) {
            return Err("web.oidc.admin_group must be 1..=256 characters".into());
        }
        if oidc.sync_role && oidc.admin_group.is_none() {
            return Err("web.oidc.sync_role needs web.oidc.admin_group".into());
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
        self.validate_acceleration()?;
        if r.mode == Mode::Recursive {
            let recursive_budget =
                (u32::from(r.attempts) + u32::from(r.dnssec)).saturating_mul(r.upstream_timeout_ms);
            let available = if r.fallback.enabled {
                r.fallback.recursive_timeout_ms
            } else {
                self.limits.query_timeout_ms
            };
            if recursive_budget > available {
                return Err(
                    "recursive attempts plus DNSSEC recovery must fit the recursive deadline"
                        .into(),
                );
            }
        }
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

    fn validate_acceleration(&self) -> Result<(), String> {
        let (warm, prefetch) = (&self.resolver.warm, &self.resolver.prefetch);
        let hedge = self.resolver.hedge_ms;
        if hedge != 0 && !(100..=5000).contains(&hedge) {
            return Err("hedge_ms must be 0 or in 100..=5000".into());
        }
        if hedge != 0 && self.resolver.mode != Mode::Recursive {
            return Err("hedge_ms is only available in recursive mode".into());
        }
        if (warm.enabled || prefetch.enabled) && self.resolver.mode != Mode::Recursive {
            return Err("warm and prefetch are only available in recursive mode".into());
        }
        if warm.zones.len() > 64 {
            return Err("at most 64 warm zones are allowed".into());
        }
        for zone in &warm.zones {
            let valid = !zone.is_empty()
                && zone.len() <= 253
                && zone.split('.').all(|label| {
                    (1..=63).contains(&label.len())
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                });
            if !valid {
                return Err("warm zones must be ASCII DNS names without a trailing dot".into());
            }
        }
        for (name, value, minimum, maximum) in [
            ("prefetch.min_hits", u32::from(prefetch.min_hits), 1, 100),
            (
                "prefetch.max_tracked",
                u32::from(prefetch.max_tracked),
                16,
                8192,
            ),
            (
                "prefetch.max_concurrent",
                u32::from(prefetch.max_concurrent),
                1,
                16,
            ),
            (
                "prefetch.budget_per_minute",
                u32::from(prefetch.budget_per_minute),
                1,
                6000,
            ),
        ] {
            if value < minimum || value > maximum {
                return Err(format!("{name} must be in {minimum}..={maximum}"));
            }
        }
        let stale = &self.resolver.serve_stale;
        if !(60..=604_800).contains(&stale.max_age_secs) {
            return Err("serve_stale.max_age_secs must be in 60..=604800".into());
        }
        if !(1..=300).contains(&stale.answer_ttl_secs) {
            return Err("serve_stale.answer_ttl_secs must be in 1..=300".into());
        }
        let persistent = &self.resolver.persistent_cache;
        if persistent.enabled && persistent.path.is_none() {
            return Err("persistent_cache.path is required when enabled".into());
        }
        if !(128..=65_536).contains(&persistent.max_entries) {
            return Err("persistent_cache.max_entries must be in 128..=65536".into());
        }
        if !(1_048_576..=1_073_741_824).contains(&persistent.max_bytes) {
            return Err("persistent_cache.max_bytes must be in 1048576..=1073741824".into());
        }
        if !(60..=604_800).contains(&persistent.max_ttl_secs) {
            return Err("persistent_cache.max_ttl_secs must be in 60..=604800".into());
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
        if resolver.upstreams.len() > MAX_FORWARD_ENDPOINTS {
            return Err(format!(
                "at most {MAX_FORWARD_ENDPOINTS} upstream addresses are allowed"
            ));
        }
        if resolver
            .upstreams
            .len()
            .saturating_sub(resolver.provider_upstreams)
            > MAX_CUSTOM_UPSTREAMS
        {
            return Err(format!(
                "at most {MAX_CUSTOM_UPSTREAMS} custom upstreams are allowed"
            ));
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
            &self.listen.doh3,
            &self.dnscrypt.listen,
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

fn socket_conflicts(left: &SocketAddr, right: &SocketAddr) -> bool {
    left.port() == right.port()
        && left.is_ipv4() == right.is_ipv4()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
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

    fn forward_config(strategy: &str, providers: &[&str], custom: usize) -> String {
        use std::fmt::Write;
        let mut text = format!("schema_version = 1\n[resolver]\nmode = \"forward\"\n{strategy}\n");
        for id in providers {
            let _ = write!(
                text,
                "[[resolver.providers]]\nid = \"{id}\"\nprotocol = \"auto\"\n"
            );
        }
        for index in 0..custom {
            let _ = write!(
                text,
                "[[resolver.upstreams]]\naddress = \"192.0.2.{}:853\"\nprotocol = \"tls\"\nserver_name = \"dns.example\"\n",
                index + 1
            );
        }
        text
    }

    #[test]
    fn several_providers_keep_their_rank_groups_and_strategy() {
        let ids = [
            "cloudflare-unfiltered",
            "quad9-unfiltered",
            "dns-sb-unfiltered",
        ];
        let config = Config::parse(
            &forward_config("strategy = \"round_robin\"", &ids, 1),
            Path::new("."),
        )
        .unwrap();
        let resolver = &config.resolver;
        assert_eq!(resolver.strategy, Some(ForwardStrategy::RoundRobin));
        // One group per provider, in the order they were written, then the custom upstream.
        assert_eq!(resolver.provider_groups.len(), 3);
        assert!(resolver.provider_groups.iter().all(|&n| n > 0));
        assert_eq!(
            resolver.provider_groups.iter().sum::<usize>(),
            resolver.provider_upstreams
        );
        assert_eq!(resolver.upstreams.len(), resolver.provider_upstreams + 1);
        // Three providers need far more than the old 8 addresses, and that is now allowed.
        assert!(
            resolver.provider_upstreams > 8,
            "{}",
            resolver.provider_upstreams
        );
        assert!(resolver.automatic_transport);

        for (name, strategy) in [
            ("failover", ForwardStrategy::Failover),
            ("fastest", ForwardStrategy::Fastest),
            ("round_robin", ForwardStrategy::RoundRobin),
            ("race", ForwardStrategy::Race),
        ] {
            let parsed = Config::parse(
                &forward_config(&format!("strategy = \"{name}\""), &ids[..1], 0),
                Path::new("."),
            )
            .unwrap();
            assert_eq!(parsed.resolver.strategy, Some(strategy));
        }
        // Unset keeps the older behavior.
        let legacy = Config::parse(&forward_config("", &ids[..1], 0), Path::new(".")).unwrap();
        assert_eq!(legacy.resolver.strategy, None);
        assert!(
            Config::parse(
                &forward_config("strategy = \"random\"", &ids, 0),
                Path::new(".")
            )
            .is_err()
        );
    }

    #[test]
    fn provider_and_upstream_limits() {
        // The eight bundled providers that offer encrypted transport.
        let encrypted = [
            "dns4eu-unfiltered",
            "ffmuc-unfiltered",
            "libredns-unfiltered",
            "dns-sb-unfiltered",
            "quad9-unfiltered",
            "uncensoreddns-anycast",
            "cloudflare-unfiltered",
            "google-public-dns",
        ];
        // All eight at once are fine, with room to spare under the endpoint cap.
        let eight = Config::parse(&forward_config("", &encrypted, 0), Path::new(".")).unwrap();
        assert_eq!(eight.resolver.provider_groups.len(), 8);
        assert!(eight.resolver.upstreams.len() <= MAX_FORWARD_ENDPOINTS / 2 + 32);
        // A ninth is not, whatever it is.
        let mut nine = encrypted.to_vec();
        nine.push("dns-watch");
        let error = Config::parse(&forward_config("", &nine, 0), Path::new(".")).unwrap_err();
        assert!(error.contains("at most 8 providers"), "{error}");
        // The same provider twice is a mistake, not a way to double its weight.
        let twice = ["quad9-unfiltered", "quad9-unfiltered"];
        assert!(
            Config::parse(&forward_config("", &twice, 0), Path::new("."))
                .unwrap_err()
                .contains("only once")
        );
        // Eight custom upstreams next to providers are fine, nine are not.
        assert!(Config::parse(&forward_config("", &encrypted[..2], 8), Path::new(".")).is_ok());
        let error =
            Config::parse(&forward_config("", &encrypted[..2], 9), Path::new(".")).unwrap_err();
        assert!(error.contains("custom upstreams"), "{error}");
        // Provider selections only work in forward mode.
        assert!(
            Config::parse(
                "schema_version = 1\n[[resolver.providers]]\nid = \"quad9-unfiltered\"\nprotocol = \"auto\"\n",
                Path::new(".")
            )
            .is_err()
        );
    }

    #[test]
    fn only_filtering_changes_can_go_live_without_a_restart() {
        let base = Config::parse("schema_version = 1\n", Path::new(".")).unwrap();
        let with = |extra: &str| {
            Config::parse(&format!("schema_version = 1\n{extra}"), Path::new(".")).unwrap()
        };
        // Lists, rules, profiles and schedules are filtering-only.
        let filtering = with(
            "[filtering]\nrules = { block = [\"ads.example\"] }\n[[filtering.lists]]\nid = \"a\"\nformat = \"domains\"\ntext = \"x.example\"\n",
        );
        assert!(base.same_except_filtering(&filtering));
        assert!(filtering.same_except_filtering(&base));
        assert!(base.same_except_filtering(&base));
        // Anything else needs the listeners to restart.
        for extra in [
            "[resolver]\ncache_entries = 100\n",
            "[listen]\nudp = [\"127.0.0.1:5454\"]\n",
            "[web]\nmax_connections = 10\n",
            "metrics = \"127.0.0.1:9153\"\n",
        ] {
            assert!(!base.same_except_filtering(&with(extra)), "{extra}");
        }
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
    fn warm_and_prefetch_are_off_by_default_and_bounded() {
        let mut config: Config = toml::from_str("schema_version = 1").unwrap();
        assert!(!config.resolver.warm.enabled && !config.resolver.prefetch.enabled);
        assert!(config.resolver.local_zones);
        assert!(!config.resolver.diagnostics);
        assert_eq!(config.resolver.nameserver_cache_entries, 1024);
        config.validate().unwrap();
        let parsed: Config = toml::from_str(
            "schema_version = 1\n[resolver.warm]\nenabled = true\nzones = [\"com\", \"co.uk\"]\n\
             [resolver.prefetch]\nenabled = true\nmin_hits = 3\n",
        )
        .unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed.resolver.prefetch.min_hits, 3);
        config.resolver.warm.enabled = true;
        config.resolver.warm.zones = vec!["bad zone".into()];
        assert!(config.validate().is_err());
        config.resolver.warm.zones = vec!["a.".into()];
        assert!(config.validate().is_err(), "trailing dot is rejected");
        config.resolver.warm.zones = vec!["com".into(); 65];
        assert!(config.validate().is_err());
        config.resolver.warm.zones = vec!["com".into()];
        config.validate().unwrap();
        for bad in [0, 101] {
            config.resolver.prefetch.min_hits = bad;
            assert!(config.validate().is_err());
        }
        config.resolver.prefetch.min_hits = 2;
        for bad in [50, 5001] {
            config.resolver.hedge_ms = bad;
            assert!(config.validate().is_err());
        }
        config.resolver.hedge_ms = 1200;
        config.validate().unwrap();
        config.resolver.hedge_ms = 0;
        config.resolver.prefetch.max_concurrent = 17;
        assert!(config.validate().is_err());
        config.resolver.prefetch.max_concurrent = 4;
        config.resolver.mode = Mode::Forward;
        config.resolver.upstreams.push(Upstream {
            address: "127.0.0.1:5353".parse().unwrap(),
            protocol: UpstreamProtocol::Udp,
            server_name: None,
            doh_path: None,
        });
        assert!(
            config.validate().is_err(),
            "warm and prefetch need recursive mode"
        );
        assert!(
            toml::from_str::<Config>("schema_version = 1\n[resolver.warm]\nbogus = 1").is_err()
        );
        let local: Config = toml::from_str(
            "schema_version = 1\n[resolver]\nlocal_zones = false\ndiagnostics = true\n",
        )
        .unwrap();
        assert!(!local.resolver.local_zones && local.resolver.diagnostics);
        let mut over_budget = Config::default();
        over_budget.resolver.attempts = 5;
        over_budget.resolver.upstream_timeout_ms = 2000;
        assert!(
            over_budget.validate().is_err(),
            "retries leave time for recovery"
        );
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
        assert!(!config.web.http.is_empty());
        assert!(
            config
                .web
                .http
                .iter()
                .all(|address| address.ip().is_loopback())
        );
        assert!(config.web.https.is_empty());
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
        let mixed = Config::load(&path).unwrap();
        assert!(mixed.resolver.provider_upstreams > 0);
        assert_eq!(
            mixed.resolver.upstreams.len(),
            mixed.resolver.provider_upstreams + 1
        );
        assert_eq!(
            mixed.resolver.upstreams.last().unwrap().address.to_string(),
            "1.1.1.1:853"
        );
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

    #[test]
    fn web_listeners_are_bounded_and_do_not_overlap() {
        let config = Config::parse(
            "schema_version = 1\n[web]\nhttp = ['127.0.0.1:8080']\nmax_connections = 32\n",
            Path::new("/operator"),
        )
        .unwrap();
        assert_eq!(config.web.max_connections, 32);
        assert!(config.web.certificate.is_none());

        assert!(
            Config::parse(
                "schema_version = 1\n[web]\nhttp = ['127.0.0.1:5353']\n",
                Path::new("/operator"),
            )
            .is_err()
        );
        assert!(
            Config::parse(
                "schema_version = 1\n[web]\nhttps = ['127.0.0.1:8443']\n",
                Path::new("/operator"),
            )
            .is_err()
        );
    }

    fn oidc_config(extra: &str) -> Result<Config, String> {
        Config::parse(
            &format!(
                "schema_version = 1\n[web]\nhttp = ['127.0.0.1:8080']\n[web.oidc]\nenabled = true\nissuer = 'https://id.example/application/o/lumen/'\nclient_id = 'lumen'\nredirect_url = 'https://dns.example/api/login/oidc/callback'\n{extra}"
            ),
            Path::new("/etc/lumen"),
        )
    }

    #[test]
    fn external_login_is_off_by_default_and_validated_when_on() {
        let default = Config {
            schema_version: 1,
            ..Config::default()
        };
        assert!(!default.web.oidc.enabled);
        default.validate().unwrap();

        let config = oidc_config("client_secret_file = 'secret'\nca_file = '/ca.pem'\n").unwrap();
        config.validate().unwrap();
        // Relative files resolve beside the config file.
        assert_eq!(
            config.web.oidc.client_secret_file.as_deref(),
            Some(Path::new("/etc/lumen/secret"))
        );
        assert_eq!(config.web.oidc.username_claim, "preferred_username");

        for bad in [
            "label = ''\n",
            "username_claim = 'a b'\n",
            "admin_group = ''\n",
            "client_id = ''\n",
            "unknown = 1\n",
        ] {
            let result = oidc_config(bad).and_then(|config| {
                config.validate()?;
                Ok(())
            });
            assert!(result.is_err(), "{bad}");
        }
        let mut config = oidc_config("").unwrap();
        config.web.oidc.issuer = "http://id.example/".into();
        assert!(config.validate().is_err(), "plain http to a remote issuer");
        config.web.oidc.issuer = "http://127.0.0.1:9000/".into();
        config.validate().unwrap();
        config.web.oidc.issuer = "http://localhost.evil.example/".into();
        assert!(config.validate().is_err());
        config.web.oidc.issuer = "https://id.example/".into();
        config.web.oidc.redirect_url = "https://dns.example/somewhere".into();
        assert!(
            config.validate().is_err(),
            "an override needs the callback path"
        );
        config.web.oidc.redirect_url = String::new();
        config.validate().unwrap();
        config.web.oidc.redirect_url = "https://dns.example/api/login/oidc/callback".into();
        config.web.oidc.sync_role = true;
        assert!(config.validate().is_err(), "role sync needs a group");
        config.web.oidc.admin_group = Some("lumen-admins".into());
        config.validate().unwrap();
        config.web.http.clear();
        assert!(config.validate().is_err(), "needs a web listener");
    }

    #[test]
    fn zones_forwarders_and_tsig_rules_are_validated() {
        fn zone(name: &str) -> Zone {
            Zone {
                name: name.into(),
                text: Some("x".into()),
                ..Zone::default()
            }
        }
        let mut config = Config {
            schema_version: 1,
            ..Config::default()
        };
        config.validate().unwrap();
        config.zones = vec![zone("home.example")];
        config.forwarders = vec![Forwarder {
            domain: "corp.example".into(),
            upstreams: vec!["10.0.0.53:53".parse().unwrap()],
        }];
        config.tsig_keys = vec![TsigKey {
            name: "ddns".into(),
            algorithm: "hmac-sha256".into(),
            secret_file: Some("ddns.key".into()),
        }];
        config.validate().unwrap();

        let broken: [fn(&mut Config); 11] = [
            |c| c.zones.push(zone("HOME.example")),
            |c| c.zones.push(zone("bad name")),
            |c| c.zones[0].text = None,
            |c| c.zones[0].file = Some("a.zone".into()),
            |c| c.zones[0].views = vec![ZoneView::default()],
            |c| c.forwarders[0].domain = "home.example".into(),
            |c| c.forwarders[0].upstreams.clear(),
            |c| c.forwarders[0].upstreams = vec!["127.0.0.1:5353".parse().unwrap()],
            |c| c.zones[0].transfer_keys = vec!["unknown".into()],
            |c| c.tsig_keys[0].algorithm = "hmac-md5".into(),
            |c| {
                c.zones[0].update_rules = vec![UpdateRule {
                    key: "ddns".into(),
                    names: vec!["*.home.example".into()],
                    types: vec!["A".into()],
                }];
            },
        ];
        for mutate in broken {
            let mut bad = config.clone();
            mutate(&mut bad);
            assert!(bad.validate().is_err());
        }

        // A dynamic zone needs a journal, a file, no views, and rules that stay inside the zone.
        config.zones[0] = Zone {
            name: "home.example".into(),
            file: Some("home.zone".into()),
            journal: Some("home.journal".into()),
            update_rules: vec![UpdateRule {
                key: "ddns".into(),
                names: vec!["*.home.example".into(), "printer.home.example".into()],
                types: vec!["A".into(), "txt".into()],
            }],
            transfer_keys: vec!["ddns".into()],
            ..Zone::default()
        };
        config.validate().unwrap();
        for mutate in [
            (|c: &mut Config| c.zones[0].update_rules[0].names = vec!["*.other.example".into()])
                as fn(&mut Config),
            |c| c.zones[0].update_rules[0].names = vec!["home.example.evil".into()],
            |c| c.zones[0].update_rules[0].types = vec!["SOA".into()],
            |c| c.zones[0].update_rules[0].types = vec!["NS".into()],
            |c| c.zones[0].update_rules[0].key = "other".into(),
            |c| c.zones[0].update_rules[0].names.clear(),
            |c| c.zones[0].text = Some("x".into()),
        ] {
            let mut bad = config.clone();
            mutate(&mut bad);
            assert!(bad.validate().is_err());
        }
    }

    #[test]
    fn dnscrypt_is_off_by_default_and_validated_when_enabled() {
        assert!(!Config::default().dnscrypt.enabled);
        let source = "schema_version = 1\n[dnscrypt]\nenabled = true\nlisten = ['127.0.0.1:5443']\nprovider_name = '2.dnscrypt-cert.dns.example'\nkey_file = 'provider.key'\n";
        let config = Config::parse(source, Path::new("/var/lib/lumen")).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.dnscrypt.key_file.as_deref(),
            Some(Path::new("/var/lib/lumen/provider.key"))
        );
        for mutate in [
            (|c: &mut Config| c.dnscrypt.listen.clear()) as fn(&mut Config),
            |c| c.dnscrypt.key_file = None,
            |c| c.dnscrypt.provider_name = "dns.example".into(),
            |c| c.dnscrypt.provider_name = "2.dnscrypt-cert.dns.example.".into(),
            |c| c.dnscrypt.cert_hours = 1,
            |c| c.dnscrypt.listen = vec!["127.0.0.1:0".parse().unwrap()],
        ] {
            let mut bad = config.clone();
            mutate(&mut bad);
            assert!(bad.validate().is_err(), "{:?}", bad.dnscrypt);
        }
    }

    #[test]
    fn stale_and_persistent_caches_are_opt_in_bounded_and_path_safe() {
        let default = Config::default();
        assert!(!default.resolver.serve_stale.enabled);
        assert!(!default.resolver.persistent_cache.enabled);

        let config = Config::parse(
            "schema_version = 1\n[resolver.serve_stale]\nenabled = true\nmax_age_secs = 3600\nanswer_ttl_secs = 20\n[resolver.persistent_cache]\nenabled = true\npath = 'dns-cache.sqlite'\nmax_entries = 1024\nmax_bytes = 1048576\nmax_ttl_secs = 3600\n",
            Path::new("/var/lib/lumen"),
        )
        .unwrap();
        assert_eq!(
            config.resolver.persistent_cache.path.as_deref(),
            Some(Path::new("/var/lib/lumen/dns-cache.sqlite"))
        );

        let mut bad = config.clone();
        bad.resolver.persistent_cache.path = None;
        assert!(bad.validate().is_err());
        bad = config.clone();
        bad.resolver.serve_stale.answer_ttl_secs = 0;
        assert!(bad.validate().is_err());
        bad = config;
        bad.resolver.persistent_cache.max_bytes = 1024;
        assert!(bad.validate().is_err());
    }
}

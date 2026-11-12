// SPDX-License-Identifier: Apache-2.0
//! Operator-managed authoritative zones, split-horizon views, and conditional forwarding.
//!
//! Each zone is an in-memory Hickory handler installed in the shared catalog, which routes by
//! the longest matching origin. These names never reach the recursive or forwarding resolver.

use super::{Backend, ResolutionZone, forward, forward_provider};
use async_trait::async_trait;
use hickory_server::{
    dnssec::NxProofKind,
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::ResponseCode,
        rr::{
            LowerName, Name, RecordType, TSigResponseContext, TSigner, rdata::tsig::TsigAlgorithm,
        },
        serialize::txt::Parser,
    },
    resolver::config::ResolverOpts,
    server::{Request, RequestInfo},
    store::in_memory::InMemoryZoneHandler,
    store::sqlite::{SqliteConfig, SqliteZoneHandler},
    zone_handler::{
        AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions,
        Nsec3QueryInfo, UpdateRequest, ZoneHandler, ZoneTransfer, ZoneType,
    },
};
use ipnet::IpNet;
use lumen_config::{Config, Forwarder, TsigKey, Upstream, UpstreamProtocol, Zone, read_bounded};
use std::{net::IpAddr, sync::Arc, time::Duration};

/// Handlers to install, with each origin so callers can skip response caches for them.
pub(crate) struct Built {
    pub handlers: Vec<Arc<dyn ZoneHandler>>,
}

/// Build every configured zone and conditional forwarder.
///
/// With `persist` false (configuration checks), dynamic zones are parsed but no journal is
/// created or opened.
pub(crate) fn build(
    config: &Config,
    options: &ResolverOpts,
    persist: bool,
) -> Result<Built, String> {
    let signers = config
        .tsig_keys
        .iter()
        .map(|key| Ok((key.name.to_ascii_lowercase(), load_signer(key)?)))
        .collect::<Result<std::collections::HashMap<_, _>, String>>()?;
    let mut handlers = Vec::new();
    for zone in &config.zones {
        handlers.push(zone_handler(zone, &signers, persist)?);
    }
    for forwarder in &config.forwarders {
        handlers.push(forwarder_handler(config, forwarder, options)?);
    }
    Ok(Built { handlers })
}

/// Install handlers for the longest-match routing the catalog provides.
pub(crate) fn install(catalog: &mut Catalog, handlers: Vec<Arc<dyn ZoneHandler>>) {
    for handler in handlers {
        catalog.upsert(handler.origin().clone(), vec![handler]);
    }
}

fn read_source(file: Option<&std::path::PathBuf>, text: Option<&String>) -> Result<String, String> {
    match (file, text) {
        (Some(path), None) => {
            let bytes = read_bounded(path, lumen_config::MAX_ZONE_BYTES as u64)?;
            String::from_utf8(bytes).map_err(|_| "zone file must be UTF-8".into())
        }
        (None, Some(text)) => Ok(text.clone()),
        _ => Err("each zone and view needs exactly one of file or text".into()),
    }
}

/// Parse one zone copy. The SOA record and apex NS records must be present.
fn static_zone(name: &str, source: &str) -> Result<Arc<dyn ZoneHandler>, String> {
    let origin =
        Name::from_ascii(format!("{name}.")).map_err(|_| format!("invalid zone name {name}"))?;
    let (_, records) = Parser::new(source.to_owned(), None, Some(origin.clone()))
        .parse()
        .map_err(|_| format!("zone {name} is not valid zone data"))?;
    let handler = InMemoryZoneHandler::<TokioRuntimeProvider>::new(
        origin,
        records,
        ZoneType::Primary,
        AxfrPolicy::Deny,
        None::<NxProofKind>,
    )
    .map_err(|_| format!("zone {name} needs a SOA record at its apex"))?;
    Ok(Arc::new(handler))
}

fn zone_handler(
    zone: &Zone,
    signers: &std::collections::HashMap<String, TSigner>,
    persist: bool,
) -> Result<Arc<dyn ZoneHandler>, String> {
    if zone.journal.is_some() || !zone.transfer_keys.is_empty() {
        return managed_zone(zone, signers, persist);
    }
    let default = static_zone(
        &zone.name,
        &read_source(zone.file.as_ref(), zone.text.as_ref())?,
    )?;
    if zone.views.is_empty() {
        return Ok(default);
    }
    let mut views = Vec::new();
    for view in &zone.views {
        views.push(View {
            clients: view.clients.clone(),
            handler: static_zone(
                &zone.name,
                &read_source(view.file.as_ref(), view.text.as_ref())?,
            )?,
        });
    }
    Ok(Arc::new(ViewZoneHandler { default, views }))
}

/// Read one TSIG secret: a single line of base64, at least 16 bytes once decoded.
fn load_signer(key: &TsigKey) -> Result<TSigner, String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let path = key
        .secret_file
        .as_ref()
        .ok_or("tsig key needs a secret_file")?;
    let text = String::from_utf8(read_bounded(path, 4096)?)
        .map_err(|_| format!("TSIG secret for {} must be base64 text", key.name))?;
    let secret = STANDARD
        .decode(text.trim())
        .ok()
        .filter(|secret| secret.len() >= 16)
        .ok_or_else(|| {
            format!(
                "TSIG secret for {} must be base64 of at least 16 bytes",
                key.name
            )
        })?;
    let algorithm = match key.algorithm.as_str() {
        "hmac-sha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha384" => TsigAlgorithm::HmacSha384,
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        _ => return Err("unsupported TSIG algorithm".into()),
    };
    let name = Name::from_ascii(format!("{}.", key.name))
        .map_err(|_| format!("invalid TSIG key name {}", key.name))?;
    TSigner::new(secret, algorithm, name, 300).map_err(|_| format!("invalid TSIG key {}", key.name))
}

/// One scoped permission: a key may change only these names and types.
struct Rule {
    key: LowerName,
    exact: Vec<LowerName>,
    below: Vec<LowerName>,
    types: Vec<RecordType>,
}

impl Rule {
    fn permits(&self, name: &LowerName, kind: RecordType) -> bool {
        self.types.contains(&kind)
            && (self.exact.contains(name)
                || self
                    .below
                    .iter()
                    .any(|suffix| suffix != name && suffix.zone_of(name)))
    }
}

/// A zone with TSIG-authenticated transfers and, when journaled, scoped RFC 2136 updates.
struct ManagedZone {
    inner: SqliteZoneHandler<TokioRuntimeProvider>,
    rules: Vec<Rule>,
    transfer_keys: Vec<LowerName>,
}

/// Most record sets a dynamic zone may hold, so updates cannot grow memory without bound.
const MAX_RRSETS: usize = 20_000;

fn key_name(name: &str) -> Result<LowerName, String> {
    Name::from_ascii(format!("{name}."))
        .map(LowerName::from)
        .map_err(|_| format!("invalid name {name}"))
}

fn managed_zone(
    zone: &Zone,
    signers: &std::collections::HashMap<String, TSigner>,
    persist: bool,
) -> Result<Arc<dyn ZoneHandler>, String> {
    let origin = Name::from_ascii(format!("{}.", zone.name))
        .map_err(|_| format!("invalid zone name {}", zone.name))?;
    let dynamic = zone.journal.is_some();
    let mut inner = if let (Some(journal), true) = (&zone.journal, persist) {
        let file = zone.file.clone().ok_or("a dynamic zone needs a file")?;
        let config = SqliteConfig {
            zone_path: file,
            journal_path: journal.clone(),
            allow_update: true,
            tsig_keys: Vec::new(),
        };
        let handler = futures_executor::block_on(SqliteZoneHandler::try_from_config(
            origin,
            ZoneType::Primary,
            AxfrPolicy::AllowSigned,
            false,
            None,
            &config,
            None::<NxProofKind>,
        ))?;
        restrict_journal(journal);
        handler
    } else {
        let source = read_source(zone.file.as_ref(), zone.text.as_ref())?;
        let (_, records) = Parser::new(source, None, Some(origin.clone()))
            .parse()
            .map_err(|_| format!("zone {} is not valid zone data", zone.name))?;
        let in_memory = InMemoryZoneHandler::<TokioRuntimeProvider>::new(
            origin,
            records,
            ZoneType::Primary,
            AxfrPolicy::AllowAll, // The wrapper applies its own transfer policy first.
            None::<NxProofKind>,
        )
        .map_err(|_| format!("zone {} needs a SOA record at its apex", zone.name))?;
        SqliteZoneHandler::new(in_memory, AxfrPolicy::AllowSigned, dynamic, false)
    };
    let mut rules = Vec::new();
    let mut used: Vec<&str> = zone.transfer_keys.iter().map(String::as_str).collect();
    for rule in &zone.update_rules {
        used.push(&rule.key);
        let mut exact = Vec::new();
        let mut below = Vec::new();
        for name in &rule.names {
            match name.strip_prefix("*.") {
                Some(suffix) => below.push(key_name(suffix)?),
                None => exact.push(key_name(name)?),
            }
        }
        rules.push(Rule {
            key: key_name(&rule.key)?,
            exact,
            below,
            types: rule
                .types
                .iter()
                .map(|kind| kind.to_ascii_uppercase().parse::<RecordType>())
                .collect::<Result<_, _>>()
                .map_err(|_| "unknown record type in update_rules".to_string())?,
        });
    }
    used.sort_unstable();
    used.dedup();
    let list = used
        .iter()
        .map(|name| {
            signers
                .get(&name.to_ascii_lowercase())
                .cloned()
                .ok_or_else(|| format!("unknown tsig key {name}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    inner.set_tsig_signers(list);
    inner.set_allow_update(dynamic);
    Ok(Arc::new(ManagedZone {
        inner,
        rules,
        transfer_keys: zone
            .transfer_keys
            .iter()
            .map(|name| key_name(name))
            .collect::<Result<_, _>>()?,
    }))
}

/// The journal holds zone data; keep it private to the service account.
fn restrict_journal(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[async_trait]
impl ZoneHandler for ManagedZone {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::AllowSigned
    }
    fn origin(&self) -> &LowerName {
        self.inner.origin()
    }
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.inner.lookup(name, rtype, request_info, options).await
    }
    async fn search(
        &self,
        request: &Request,
        options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        self.inner.search(request, options).await
    }
    async fn nsec_records(
        &self,
        name: &LowerName,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.inner.nsec_records(name, options).await
    }
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.inner.nsec3_records(info, options).await
    }
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
    async fn update(
        &self,
        request: &Request,
        now: u64,
    ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
        // Scope first: a key never gets to touch names or types its rules do not name. The
        // inner handler then verifies the TSIG signature and the RFC 2136 prerequisites.
        let Some(signature) = request.signature() else {
            return (Err(ResponseCode::Refused), None);
        };
        let key = LowerName::from(&signature.name);
        let rules: Vec<&Rule> = self.rules.iter().filter(|rule| rule.key == key).collect();
        let updates = request.updates();
        let allowed = !rules.is_empty()
            && updates.len() <= lumen_config::MAX_UPDATE_RECORDS
            && updates.iter().all(|record| {
                let name = LowerName::from(&record.name);
                rules
                    .iter()
                    .any(|rule| rule.permits(&name, record.record_type()))
            });
        if !allowed {
            return (Err(ResponseCode::Refused), None);
        }
        if self.inner.records().await.len() + updates.len() > MAX_RRSETS {
            return (Err(ResponseCode::Refused), None);
        }
        self.inner.update(request, now).await
    }
    async fn zone_transfer(
        &self,
        request: &Request,
        options: LookupOptions,
        now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<TSigResponseContext>,
    )> {
        let permitted = request.signature().is_some_and(|signature| {
            self.transfer_keys
                .contains(&LowerName::from(&signature.name))
        });
        if !permitted {
            return Some((Err(LookupError::from(ResponseCode::Refused)), None));
        }
        self.inner.zone_transfer(request, options, now).await
    }
}

fn forwarder_handler(
    config: &Config,
    forwarder: &Forwarder,
    options: &ResolverOpts,
) -> Result<Arc<dyn ZoneHandler>, String> {
    let origin = Name::from_ascii(format!("{}.", forwarder.domain))
        .map_err(|_| format!("invalid forwarder domain {}", forwarder.domain))?;
    // Internal resolvers are plain UDP/TCP and not validated; this is explicit in the docs.
    let mut settings = config.resolver.clone();
    settings.automatic_transport = false;
    settings.dnssec = false;
    let upstreams: Vec<Upstream> = forwarder
        .upstreams
        .iter()
        .map(|address| Upstream {
            address: *address,
            protocol: UpstreamProtocol::Udp,
            server_name: None,
            doh_path: None,
        })
        .collect();
    let mut options = options.clone();
    options.validate = false;
    let provider = forward_provider(&settings, &upstreams, options, None)?;
    let penalty = Duration::from_millis(u64::from(settings.upstream_timeout_ms));
    Ok(Arc::new(ResolutionZone {
        origin: origin.into(),
        backend: Backend::Forward(Box::new(forward::ForwardPool::new(
            vec![provider],
            lumen_config::ForwardStrategy::Failover,
            penalty,
        ))),
    }))
}

struct View {
    clients: Vec<IpNet>,
    handler: Arc<dyn ZoneHandler>,
}

/// Picks one zone copy by client address. The first matching view wins, then the default.
struct ViewZoneHandler {
    default: Arc<dyn ZoneHandler>,
    views: Vec<View>,
}

impl ViewZoneHandler {
    fn select(&self, client: IpAddr) -> &Arc<dyn ZoneHandler> {
        let client = match client {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            other @ IpAddr::V4(_) => other,
        };
        self.views
            .iter()
            .find(|view| view.clients.iter().any(|net| net.contains(&client)))
            .map_or(&self.default, |view| &view.handler)
    }
}

#[async_trait]
impl ZoneHandler for ViewZoneHandler {
    fn zone_type(&self) -> ZoneType {
        ZoneType::Primary
    }
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }
    fn origin(&self) -> &LowerName {
        self.default.origin()
    }
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        request_info: Option<&RequestInfo<'_>>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let handler = request_info.map_or(&self.default, |info| self.select(info.src.ip()));
        handler.lookup(name, rtype, request_info, options).await
    }
    async fn search(
        &self,
        request: &Request,
        options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        self.select(request.src().ip())
            .search(request, options)
            .await
    }
    async fn nsec_records(
        &self,
        name: &LowerName,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.default.nsec_records(name, options).await
    }
    async fn nsec3_records(
        &self,
        info: Nsec3QueryInfo<'_>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        self.default.nsec3_records(info, options).await
    }
    async fn zone_transfer(
        &self,
        _request: &Request,
        _options: LookupOptions,
        _now: u64,
    ) -> Option<(
        Result<ZoneTransfer, LookupError>,
        Option<TSigResponseContext>,
    )> {
        // Transfers of split zones would leak one view to another audience.
        Some((Err(LookupError::from(ResponseCode::Refused)), None))
    }
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(origin: &str, address: &str) -> String {
        format!(
            "{origin}. 60 IN SOA ns.{origin}. hostmaster.{origin}. 1 60 60 60 60\n\
             {origin}. 60 IN NS ns.{origin}.\n\
             ns.{origin}. 60 IN A 192.0.2.53\n\
             host.{origin}. 60 IN A {address}\n"
        )
    }

    #[test]
    fn zones_need_soa_and_parse_cleanly() {
        assert!(static_zone("example.test", &text("example.test", "192.0.2.1")).is_ok());
        assert!(static_zone("example.test", "host.example.test. 60 IN A 192.0.2.1\n").is_err());
        assert!(static_zone("example.test", "not a zone").is_err());
    }

    #[test]
    fn views_choose_first_matching_network_then_default() {
        let default = static_zone("example.test", &text("example.test", "192.0.2.1")).unwrap();
        let office = static_zone("example.test", &text("example.test", "192.0.2.2")).unwrap();
        let home = static_zone("example.test", &text("example.test", "192.0.2.3")).unwrap();
        let view = |net: &str, handler: &Arc<dyn ZoneHandler>| View {
            clients: vec![net.parse().unwrap()],
            handler: Arc::clone(handler),
        };
        let mux = ViewZoneHandler {
            default: Arc::clone(&default),
            views: vec![view("10.0.0.0/8", &office), view("192.168.0.0/16", &home)],
        };
        assert!(Arc::ptr_eq(
            mux.select("10.1.2.3".parse().unwrap()),
            &office
        ));
        assert!(Arc::ptr_eq(
            mux.select("::ffff:10.1.2.3".parse().unwrap()),
            &office
        ));
        assert!(Arc::ptr_eq(
            mux.select("192.168.1.2".parse().unwrap()),
            &home
        ));
        assert!(Arc::ptr_eq(
            mux.select("203.0.113.5".parse().unwrap()),
            &default
        ));
        assert_eq!(mux.axfr_policy(), AxfrPolicy::Deny);
    }
}

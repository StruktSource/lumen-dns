// SPDX-License-Identifier: Apache-2.0
//! Operator-managed authoritative zones, split-horizon views, and conditional forwarding.
//!
//! Each zone is an in-memory Hickory handler installed in the shared catalog, which routes by
//! the longest matching origin. These names never reach the recursive or forwarding resolver.

use super::{Backend, ForwardBackend, ResolutionZone, forward, forward_provider};
use async_trait::async_trait;
use hickory_server::{
    dnssec::NxProofKind,
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::ResponseCode,
        rr::{
            LowerName, Name, RData, Record, RecordType, TSigResponseContext, TSigner,
            rdata::tsig::TsigAlgorithm,
        },
        serialize::txt::Parser,
    },
    resolver::config::ResolverOpts,
    server::{Request, RequestInfo},
    store::in_memory::InMemoryZoneHandler,
    store::sqlite::{SqliteConfig, SqliteZoneHandler},
    zone_handler::{
        AuthLookup, AxfrPolicy, AxfrRecords, Catalog, LookupControlFlow, LookupError,
        LookupOptions, LookupRecords, Nsec3QueryInfo, UpdateRequest, ZoneHandler, ZoneTransfer,
        ZoneType,
    },
};
use ipnet::IpNet;
use lumen_config::{
    Config, Forwarder, ManagedRecordData, ManagedZone as ManagedZoneConfig, TsigKey, Upstream,
    UpstreamProtocol, Zone, read_bounded,
};
use std::{fmt::Write, net::IpAddr, sync::Arc, time::Duration};

/// Handlers to install, with each origin so callers can skip response caches for them.
pub(crate) struct Built {
    pub handlers: Vec<Arc<dyn ZoneHandler>>,
    /// Signed zones, which need their signatures renewed on a schedule.
    pub resign: Vec<Arc<InMemoryZoneHandler<TokioRuntimeProvider>>>,
    /// Zones with secondaries to notify at startup.
    pub notify: Vec<(Name, Vec<std::net::SocketAddr>)>,
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
    let mut resign = Vec::new();
    for zone in &config.zones {
        handlers.push(zone_handler(zone, &signers, persist, &mut resign)?);
    }
    for forwarder in &config.forwarders {
        handlers.push(forwarder_handler(config, forwarder, options)?);
    }
    let mut notify = Vec::new();
    for zone in config.zones.iter().filter(|zone| !zone.notify.is_empty()) {
        let origin = Name::from_ascii(format!("{}.", zone.name))
            .map_err(|_| format!("invalid zone name {}", zone.name))?;
        notify.push((origin, zone.notify.clone()));
    }
    Ok(Built {
        handlers,
        resign,
        notify,
    })
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

fn quoted(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Turn a typed console-managed zone into ordinary bounded master-file data. Hickory then uses
/// the same parser and handler as an advanced inline zone.
fn managed_source(name: &str, managed: &ManagedZoneConfig) -> Result<String, String> {
    let ttl = managed.default_ttl;
    let mut source = format!(
        "$ORIGIN {name}.\n@ {ttl} IN SOA ns.{name}. hostmaster.{name}. 1 3600 600 604800 {ttl}\n@ {ttl} IN NS ns.{name}.\n"
    );
    for record in &managed.records {
        let ttl = record.ttl.unwrap_or(ttl);
        write!(&mut source, "{} {ttl} IN ", record.name)
            .map_err(|_| "cannot render managed zone")?;
        match &record.data {
            ManagedRecordData::A { address } => writeln!(&mut source, "A {address}"),
            ManagedRecordData::Aaaa { address } => writeln!(&mut source, "AAAA {address}"),
            ManagedRecordData::Cname { target } => writeln!(&mut source, "CNAME {target}"),
            ManagedRecordData::Txt { value } => {
                writeln!(&mut source, "TXT \"{}\"", quoted(value))
            }
            ManagedRecordData::Ptr { target } => writeln!(&mut source, "PTR {target}"),
            ManagedRecordData::Mx { priority, exchange } => {
                writeln!(&mut source, "MX {priority} {exchange}")
            }
            ManagedRecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => writeln!(&mut source, "SRV {priority} {weight} {port} {target}"),
            ManagedRecordData::Caa { flags, tag, value } => {
                writeln!(&mut source, "CAA {flags} {tag} \"{}\"", quoted(value))
            }
            ManagedRecordData::Tlsa {
                usage,
                selector,
                matching_type,
                certificate_association_data,
            } => writeln!(
                &mut source,
                "TLSA {usage} {selector} {matching_type} {certificate_association_data}"
            ),
        }
        .map_err(|_| "cannot render managed zone")?;
    }
    if source.len() > lumen_config::MAX_ZONE_BYTES {
        return Err(format!(
            "managed zone {name} exceeds {} bytes",
            lumen_config::MAX_ZONE_BYTES
        ));
    }
    Ok(source)
}

fn zone_source(zone: &Zone) -> Result<String, String> {
    match &zone.managed {
        Some(managed) => managed_source(&zone.name, managed),
        None => read_source(zone.file.as_ref(), zone.text.as_ref()),
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

/// A plain zone signed with one combined key (two during a rollover) and `NSEC` or `NSEC3`
/// denial of existence. The caller renews the signatures by calling `secure_zone` again before
/// they expire.
fn signed_zone(
    name: &str,
    source: &str,
    signing: &lumen_config::ZoneSigning,
) -> Result<Arc<InMemoryZoneHandler<TokioRuntimeProvider>>, String> {
    let origin =
        Name::from_ascii(format!("{name}.")).map_err(|_| format!("invalid zone name {name}"))?;
    let (_, records) = Parser::new(source.to_owned(), None, Some(origin.clone()))
        .parse()
        .map_err(|_| format!("zone {name} is not valid zone data"))?;
    let mut handler = InMemoryZoneHandler::<TokioRuntimeProvider>::new(
        origin.clone(),
        records,
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(crate::signing::proof_kind(signing)?),
    )
    .map_err(|_| format!("zone {name} needs a SOA record at its apex"))?;
    for signer in crate::signing::signers(signing, &origin)? {
        handler
            .add_zone_signing_key_mut(signer)
            .map_err(|_| format!("cannot use the signing key for zone {name}"))?;
    }
    handler
        .secure_zone_mut()
        .map_err(|_| format!("cannot sign zone {name}"))?;
    Ok(Arc::new(handler))
}

fn zone_handler(
    zone: &Zone,
    signers: &std::collections::HashMap<String, TSigner>,
    persist: bool,
    resign: &mut Vec<Arc<InMemoryZoneHandler<TokioRuntimeProvider>>>,
) -> Result<Arc<dyn ZoneHandler>, String> {
    if let Some(signing) = &zone.dnssec {
        let handler = signed_zone(&zone.name, &zone_source(zone)?, signing)?;
        resign.push(Arc::clone(&handler));
        return Ok(handler);
    }
    if zone.journal.is_some() || !zone.transfer_keys.is_empty() {
        return managed_zone(zone, signers, persist);
    }
    let default = static_zone(&zone.name, &zone_source(zone)?)?;
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
    notify: Vec<std::net::SocketAddr>,
    /// Recent changes, newest last, so an IXFR client that is only a few serials behind gets the
    /// differences. Kept in memory only: after a restart clients get the whole zone.
    history: std::sync::Mutex<std::collections::VecDeque<Change>>,
    /// Serializes updates so each recorded change matches exactly one update.
    updating: tokio::sync::Mutex<()>,
}

/// What one accepted update changed. SOA records are kept apart from the rest.
struct Change {
    from: u32,
    to: u32,
    old_soa: Record,
    new_soa: Record,
    deleted: Vec<Record>,
    added: Vec<Record>,
}

/// At most this many remembered updates, and this many changed records across all of them. An
/// answer larger than that is not worth building, and the whole zone goes out instead.
const MAX_HISTORY_CHANGES: usize = 32;
const MAX_HISTORY_RECORDS: usize = 500;

fn soa_serial(record: &Record) -> Option<u32> {
    match &record.data {
        RData::SOA(soa) => Some(soa.serial),
        _ => None,
    }
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
        notify: zone.notify.clone(),
        history: std::sync::Mutex::default(),
        updating: tokio::sync::Mutex::default(),
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

impl ManagedZone {
    /// Every record of the zone, without signatures.
    async fn snapshot(&self) -> Vec<Record> {
        let records = self.inner.records().await;
        records
            .values()
            .flat_map(|set| set.records_without_rrsigs().cloned().collect::<Vec<_>>())
            .collect()
    }

    fn remember(&self, before: &[Record], after: &[Record]) {
        let soa = |records: &[Record]| {
            records
                .iter()
                .find(|record| record.record_type() == RecordType::SOA)
                .cloned()
        };
        let (Some(old_soa), Some(new_soa)) = (soa(before), soa(after)) else {
            return;
        };
        let (Some(from), Some(to)) = (soa_serial(&old_soa), soa_serial(&new_soa)) else {
            return;
        };
        let plain = |record: &&Record| record.record_type() != RecordType::SOA;
        let deleted: Vec<Record> = before
            .iter()
            .filter(plain)
            .filter(|record| !after.contains(record))
            .cloned()
            .collect();
        let added: Vec<Record> = after
            .iter()
            .filter(plain)
            .filter(|record| !before.contains(record))
            .cloned()
            .collect();
        let Ok(mut history) = self.history.lock() else {
            return;
        };
        history.push_back(Change {
            from,
            to,
            old_soa,
            new_soa,
            deleted,
            added,
        });
        let total = |history: &std::collections::VecDeque<Change>| {
            history
                .iter()
                .map(|change| change.deleted.len() + change.added.len() + 2)
                .sum::<usize>()
        };
        while history.len() > MAX_HISTORY_CHANGES
            || (history.len() > 1 && total(&history) > MAX_HISTORY_RECORDS)
        {
            history.pop_front();
        }
    }

    /// The differences from `client` to `current` in IXFR order (RFC 1995 section 4): for each
    /// change its old SOA, the deleted records, its new SOA, and the added records. `None` when
    /// the history cannot bridge the gap exactly, which means the whole zone must be sent.
    fn differences(&self, client: u32, current: u32) -> Option<Vec<Record>> {
        let history = self.history.lock().ok()?;
        let start = history.iter().position(|change| change.from == client)?;
        let mut out = Vec::new();
        let mut expected = client;
        for change in history.iter().skip(start) {
            if change.from != expected {
                return None;
            }
            out.push(change.old_soa.clone());
            out.extend(change.deleted.iter().cloned());
            out.push(change.new_soa.clone());
            out.extend(change.added.iter().cloned());
            expected = change.to;
        }
        (expected == current && out.len() <= MAX_HISTORY_RECORDS + 2).then_some(out)
    }
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
        let _turn = self.updating.lock().await;
        let before = self.snapshot().await;
        let result = self.inner.update(request, now).await;
        if matches!(result.0, Ok(true)) {
            self.remember(&before, &self.snapshot().await);
        }
        if matches!(result.0, Ok(true)) && !self.notify.is_empty() {
            let zone: Name = self.inner.origin().into();
            tokio::spawn(crate::notify::send(zone, self.notify.clone()));
        }
        result
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
        let (result, context) = self.inner.zone_transfer(request, options, now).await?;
        let Ok(full) = result else {
            return Some((result, context));
        };
        let is_ixfr = request
            .request_info()
            .is_ok_and(|info| info.query.query_type() == RecordType::IXFR);
        // The client states the serial it has in an SOA record of the authority section.
        let client = request.updates().iter().find_map(soa_serial);
        let current = full.start_soa.iter().find_map(soa_serial);
        let (true, Some(client), Some(current)) = (is_ixfr, client, current) else {
            return Some((Ok(full), context));
        };
        if client == current {
            // Nothing newer: the current SOA alone is the whole answer.
            let answer = ZoneTransfer {
                start_soa: full.start_soa,
                records: AxfrRecords::from_records(Vec::new()),
                end_soa: LookupRecords::Empty,
            };
            return Some((Ok(answer), context));
        }
        match self.differences(client, current) {
            Some(records) => {
                let answer = ZoneTransfer {
                    start_soa: full.start_soa,
                    records: AxfrRecords::from_records(records),
                    end_soa: full.end_soa,
                };
                Some((Ok(answer), context))
            }
            None => Some((Ok(full), context)),
        }
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
        backend: Backend::Forward(Box::new(ForwardBackend::plain(forward::ForwardPool::new(
            vec![provider],
            lumen_config::ForwardStrategy::Failover,
            penalty,
        )))),
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

    #[test]
    fn managed_records_render_as_valid_authoritative_zone_data() {
        let record = |name: &str, data| lumen_config::ManagedRecord {
            name: name.into(),
            ttl: None,
            data,
        };
        let managed = ManagedZoneConfig {
            description: Some("Local names".into()),
            default_ttl: 300,
            records: vec![
                record(
                    "dash",
                    ManagedRecordData::A {
                        address: "192.0.2.10".parse().unwrap(),
                    },
                ),
                record(
                    "dash",
                    ManagedRecordData::Aaaa {
                        address: "2001:db8::10".parse().unwrap(),
                    },
                ),
                record(
                    "alias",
                    ManagedRecordData::Cname {
                        target: "dash".into(),
                    },
                ),
                record(
                    "note",
                    ManagedRecordData::Txt {
                        value: "quoted \"text\" and \\ slash".into(),
                    },
                ),
                record(
                    "10.2.0.192.in-addr",
                    ManagedRecordData::Ptr {
                        target: "dash".into(),
                    },
                ),
                record(
                    "@",
                    ManagedRecordData::Mx {
                        priority: 10,
                        exchange: "mail".into(),
                    },
                ),
                record(
                    "_https._tcp",
                    ManagedRecordData::Srv {
                        priority: 0,
                        weight: 5,
                        port: 443,
                        target: "dash".into(),
                    },
                ),
                record(
                    "@",
                    ManagedRecordData::Caa {
                        flags: 0,
                        tag: "issue".into(),
                        value: "ca.example".into(),
                    },
                ),
                record(
                    "_443._tcp.dash",
                    ManagedRecordData::Tlsa {
                        usage: 3,
                        selector: 1,
                        matching_type: 1,
                        certificate_association_data: "aabb".into(),
                    },
                ),
            ],
        };
        let source = managed_source("home.arpa", &managed).unwrap();
        assert!(source.contains("@ 300 IN SOA ns.home.arpa."));
        assert!(source.contains("@ 300 IN NS ns.home.arpa."));
        assert!(source.contains("TXT \"quoted \\\"text\\\" and \\\\ slash\""));
        assert!(source.contains("TLSA 3 1 1 aabb"));
        assert!(static_zone("home.arpa", &source).is_ok());
    }
}

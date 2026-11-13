// SPDX-License-Identifier: Apache-2.0
//! DNS resolution and validation through Hickory, isolated from client transports.

use accel::Accel;
use async_trait::async_trait;
use cache::ResponseCache;
use hickory_server::{
    dnssec::NxProofKind,
    net::{
        DnsError, NetError,
        runtime::{TokioRuntimeProvider, TokioTime},
        xfer::Protocol,
    },
    proto::{
        dnssec::{DnssecSummary, TrustAnchors},
        op::{Edns, Message, Query as DnsQuery, ResponseCode},
        rr::{
            LowerName, Name, RData, Record, RecordSet, RecordType, TSigResponseContext,
            rdata::{NS, SOA},
        },
        serialize::{binary::BinEncoder, txt::Parser},
    },
    resolver::{
        TtlConfig,
        config::{
            NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts, ServerOrderingStrategy,
        },
        recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions},
    },
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
    store::in_memory::InMemoryZoneHandler,
    zone_handler::{
        AuthLookup, AxfrPolicy, Catalog, DnssecZoneHandler, LookupControlFlow, LookupError,
        LookupOptions, MessageResponse, Nsec3QueryInfo, ZoneHandler, ZoneType,
    },
};
use lumen_config::{Config, ForwardStrategy, Mode, UpstreamProtocol, read_bounded};
use lumen_proto::Query;
use std::{
    fmt::Write,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::time::timeout;

mod accel;
mod cache;
mod challenge;
mod forward;
mod hosts;
mod notify;
mod rollover;
mod signing;
pub use challenge::Challenges;
pub use hosts::Hosts;
pub use signing::zone_key;
mod zones;

pub use hickory_server::net::xfer::Protocol as Transport;

/// Messages that are not ordinary queries but are served by operator zones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneMessage {
    /// RFC 2136 dynamic update (opcode 5).
    Update,
    /// AXFR or IXFR zone transfer request.
    Transfer,
}

/// Classify a raw packet without fully parsing it. Ordinary queries return `None`.
#[must_use]
pub fn zone_message_kind(packet: &[u8]) -> Option<ZoneMessage> {
    if packet.len() < 12 || packet[2] & 0x80 != 0 {
        return None;
    }
    match (packet[2] >> 3) & 0x0f {
        5 => return Some(ZoneMessage::Update),
        0 => {}
        _ => return None,
    }
    if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return None;
    }
    let mut offset = 12;
    loop {
        let length = usize::from(*packet.get(offset)?);
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        offset += length;
    }
    let kind = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
    matches!(kind, 251 | 252).then_some(ZoneMessage::Transfer)
}

/// One shared resolver and cache set for all enabled client transports.
pub struct Resolver {
    catalog: Catalog,
    cache: Option<Arc<ResponseCache>>,
    /// Origins of operator zones and conditional forwarders. They bypass the response caches and
    /// the built-in local-zone answers, because their answers depend on the client and change.
    custom: Vec<LowerName>,
    rollover: Option<rollover::Tracker>,
    signed: Vec<Arc<InMemoryZoneHandler<TokioRuntimeProvider>>>,
    notifications: Vec<(Name, Vec<SocketAddr>)>,
    challenges: Arc<Challenges>,
    hosts: Arc<Hosts>,
    resigners: Resigners,
    metrics: Arc<Metrics>,
    background: Option<Background>,
    local_zones: bool,
}

/// Optional priming and refresh tasks, started explicitly once listeners are bound.
struct Background {
    accel: Arc<Accel>,
    start: Box<dyn Fn() + Send + Sync>,
}

impl Drop for Resolver {
    fn drop(&mut self) {
        if let Some(background) = &self.background {
            background.accel.stop();
        }
    }
}

/// Latency bucket upper bounds in seconds; one extra slot counts everything above.
const LATENCY_BOUNDS: [f64; 10] = [0.001, 0.005, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];

/// Aggregate counters. No query names or client labels are retained.
#[derive(Default)]
pub struct Metrics {
    diagnostics: AtomicBool,
    recursive_attempts: AtomicU64,
    recursive_retries: AtomicU64,
    recursive_timeouts: AtomicU64,
    recursive_failures: AtomicU64,
    forward_insecure_recoveries: AtomicU64,
    attempt_latency: [AtomicU64; 11],
    attempt_latency_sum_micros: AtomicU64,
    attempts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    timeout_triggers: AtomicU64,
    coalesced: AtomicU64,
    hedged: AtomicU64,
    prefetch_refreshes: AtomicU64,
    prefetch_failures: AtomicU64,
    prefetch_skipped: AtomicU64,
    warm_queries: AtomicU64,
    warm_failures: AtomicU64,
    latency: [AtomicU64; 11],
    latency_sum_micros: AtomicU64,
    background_latency: [AtomicU64; 11],
    background_latency_sum_micros: AtomicU64,
    anchor_checks: AtomicU64,
    anchor_changes: AtomicU64,
    anchor_failures: AtomicU64,
    anchor_restart_pending: AtomicBool,
}

impl Metrics {
    fn observe(&self, elapsed: Duration, background: bool) {
        let seconds = elapsed.as_secs_f64();
        let slot = LATENCY_BOUNDS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(LATENCY_BOUNDS.len());
        let (latency, sum) = if background {
            (
                &self.background_latency,
                &self.background_latency_sum_micros,
            )
        } else {
            (&self.latency, &self.latency_sum_micros)
        };
        latency[slot].fetch_add(1, Ordering::Relaxed);
        sum.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    fn observe_attempt(&self, elapsed: Duration) {
        if !self.diagnostics.load(Ordering::Relaxed) {
            return;
        }
        let slot = LATENCY_BOUNDS
            .iter()
            .position(|bound| elapsed.as_secs_f64() <= *bound)
            .unwrap_or(LATENCY_BOUNDS.len());
        self.attempt_latency[slot].fetch_add(1, Ordering::Relaxed);
        self.attempt_latency_sum_micros.fetch_add(
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Stable Prometheus text for recursion latency, sharing, priming, and fallback.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = String::new();
        for (name, help, value) in [
            (
                "fallback_attempts_total",
                "Recursive timeout fallback attempts.",
                &self.attempts,
            ),
            (
                "fallback_successes_total",
                "Fallback responses, including authenticated negative answers.",
                &self.successes,
            ),
            (
                "fallback_failures_total",
                "Fallback attempts without a usable response.",
                &self.failures,
            ),
            (
                "fallback_trigger_recursion_timeout_total",
                "Fallback attempts triggered by an identified recursion timeout.",
                &self.timeout_triggers,
            ),
            (
                "recursive_coalesced_total",
                "Identical in-flight recursive queries that shared one recursion.",
                &self.coalesced,
            ),
            (
                "recursive_hedged_total",
                "Slow recursive lookups that started a second recursion.",
                &self.hedged,
            ),
            (
                "prefetch_refreshes_total",
                "Popular answers refreshed after expiry.",
                &self.prefetch_refreshes,
            ),
            (
                "prefetch_failures_total",
                "Refreshes that did not produce an answer.",
                &self.prefetch_failures,
            ),
            (
                "prefetch_skipped_total",
                "Refreshes skipped because the per-minute budget was spent.",
                &self.prefetch_skipped,
            ),
            (
                "warm_queries_total",
                "Startup priming queries for root and top-level zones.",
                &self.warm_queries,
            ),
            (
                "warm_failures_total",
                "Startup priming queries without an answer.",
                &self.warm_failures,
            ),
            (
                "trust_anchor_checks_total",
                "Root DNSKEY checks for RFC 5011 trust-anchor rollover.",
                &self.anchor_checks,
            ),
            (
                "trust_anchor_changes_total",
                "Checks that changed the set of trusted keys.",
                &self.anchor_changes,
            ),
            (
                "trust_anchor_failures_total",
                "Checks that failed or whose key set no trusted key signed.",
                &self.anchor_failures,
            ),
        ] {
            let _ = writeln!(
                text,
                "# HELP lumen_dns_{name} {help}\n# TYPE lumen_dns_{name} counter\nlumen_dns_{name} {}",
                value.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            text,
            "# HELP lumen_dns_trust_anchor_restart_pending 1 when the trusted keys changed and a restart will load them.\n# TYPE lumen_dns_trust_anchor_restart_pending gauge\nlumen_dns_trust_anchor_restart_pending {}",
            u8::from(self.anchor_restart_pending.load(Ordering::Relaxed))
        );
        self.render_diagnostics(&mut text);
        render_histogram(
            &mut text,
            "lumen_dns_recursive_lookup_duration_seconds",
            "Time to answer a client recursive lookup, including cache hits.",
            &self.latency,
            &self.latency_sum_micros,
        );
        render_histogram(
            &mut text,
            "lumen_dns_recursive_background_duration_seconds",
            "Time to run a recursive startup-prime or expiry-refresh lookup.",
            &self.background_latency,
            &self.background_latency_sum_micros,
        );
        text
    }

    fn render_diagnostics(&self, text: &mut String) {
        if !self.diagnostics.load(Ordering::Relaxed) {
            return;
        }
        for (name, help, value) in [
            (
                "recursive_attempts_total",
                "Bounded recursive walk attempts, without query or server labels.",
                &self.recursive_attempts,
            ),
            (
                "recursive_retries_total",
                "Recursive walks retried after a timeout.",
                &self.recursive_retries,
            ),
            (
                "forward_insecure_recoveries_total",
                "Forward lookups answered without validation because an ancestor zone is provably unsigned.",
                &self.forward_insecure_recoveries,
            ),
            (
                "recursive_attempt_timeouts_total",
                "Recursive walk attempts that reached their Lumen budget.",
                &self.recursive_timeouts,
            ),
            (
                "recursive_attempt_failures_total",
                "Recursive walk attempts that failed without a timeout.",
                &self.recursive_failures,
            ),
        ] {
            let _ = writeln!(
                text,
                "# HELP lumen_dns_{name} {help}\n# TYPE lumen_dns_{name} counter\nlumen_dns_{name} {}",
                value.load(Ordering::Relaxed)
            );
        }
        render_histogram(
            text,
            "lumen_dns_recursive_attempt_duration_seconds",
            "Time spent in each bounded recursive walk attempt.",
            &self.attempt_latency,
            &self.attempt_latency_sum_micros,
        );
    }
}

fn render_histogram(
    text: &mut String,
    name: &str,
    help: &str,
    latency: &[AtomicU64; 11],
    sum_micros: &AtomicU64,
) {
    let _ = writeln!(text, "# HELP {name} {help}\n# TYPE {name} histogram");
    let mut total = 0;
    for (slot, count) in latency.iter().enumerate() {
        total += count.load(Ordering::Relaxed);
        let bound = LATENCY_BOUNDS
            .get(slot)
            .map_or_else(|| "+Inf".to_owned(), ToString::to_string);
        let _ = writeln!(text, "{name}_bucket{{le=\"{bound}\"}} {total}");
    }
    #[allow(clippy::cast_precision_loss)]
    let sum = sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
    let _ = writeln!(text, "{name}_sum {sum}\n{name}_count {total}");
}

const LOCAL_ZONE_TTL: u32 = 10_800;

static EMPTY_LOCAL_ZONES: LazyLock<Vec<Name>> = LazyLock::new(|| {
    let mut zones = vec![
        "10.in-addr.arpa.",
        "168.192.in-addr.arpa.",
        "0.in-addr.arpa.",
        "127.in-addr.arpa.",
        "254.169.in-addr.arpa.",
        "2.0.192.in-addr.arpa.",
        "100.51.198.in-addr.arpa.",
        "113.0.203.in-addr.arpa.",
        "255.255.255.255.in-addr.arpa.",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        "d.f.ip6.arpa.",
        "8.e.f.ip6.arpa.",
        "9.e.f.ip6.arpa.",
        "a.e.f.ip6.arpa.",
        "b.e.f.ip6.arpa.",
        "8.b.d.0.1.0.0.2.ip6.arpa.",
        "service.arpa.",
    ]
    .into_iter()
    .map(|zone| Name::from_ascii(zone).expect("static local zone"))
    .collect::<Vec<_>>();
    zones.extend((16..=31).map(|octet| {
        Name::from_ascii(format!("{octet}.172.in-addr.arpa.")).expect("private reverse zone")
    }));
    zones.extend((64..=127).map(|octet| {
        Name::from_ascii(format!("{octet}.100.in-addr.arpa.")).expect("shared reverse zone")
    }));
    zones
});

static HOME_ARPA: LazyLock<Name> =
    LazyLock::new(|| Name::from_ascii("home.arpa.").expect("static local zone"));
static RESOLVER_ARPA: LazyLock<Name> =
    LazyLock::new(|| Name::from_ascii("resolver.arpa.").expect("static local zone"));
static MDNS_LOCAL: LazyLock<Name> =
    LazyLock::new(|| Name::from_ascii("local.").expect("static local zone"));

/// Answer registered local-only names without leaking them into public recursion.
fn local_zone_response(query: &Query) -> Option<Message> {
    let question = query.message.queries.first()?;
    let name = question.name();
    let dnssec_ok = query
        .message
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);

    // RFC 8375 requires the real parent proof for this one query.
    if HOME_ARPA.zone_of(name)
        && name == &*HOME_ARPA
        && question.query_type() == RecordType::DS
        && dnssec_ok
    {
        return None;
    }

    if RESOLVER_ARPA.zone_of(name) {
        return Some(if name == &*RESOLVER_ARPA {
            empty_zone_response(query, &RESOLVER_ARPA)
        } else {
            local_nodata(query, &RESOLVER_ARPA)
        });
    }
    if MDNS_LOCAL.zone_of(name) {
        // Lumen is not an mDNS bridge. Never send a link-local name to public DNS, and do not
        // claim authority for the multicast namespace.
        let mut response = response_base(query, false);
        response.metadata.response_code = ResponseCode::NXDomain;
        return Some(response);
    }
    if HOME_ARPA.zone_of(name) {
        return Some(empty_zone_response(query, &HOME_ARPA));
    }
    EMPTY_LOCAL_ZONES
        .iter()
        .find(|zone| zone.zone_of(name))
        .map(|zone| empty_zone_response(query, zone))
}

fn response_base(query: &Query, authoritative: bool) -> Message {
    let mut response = Message::response(query.message.metadata.id, query.message.metadata.op_code);
    response.metadata.authoritative = authoritative;
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = query.message.metadata.recursion_desired;
    response.metadata.checking_disabled = query.message.metadata.checking_disabled;
    response.queries.clone_from(&query.message.queries);
    if let Some(request_edns) = &query.message.edns {
        let mut edns = Edns::new();
        edns.set_max_payload(request_edns.max_payload())
            .set_dnssec_ok(request_edns.flags().dnssec_ok);
        response.edns = Some(edns);
    }
    response
}

fn local_soa(zone: &Name) -> Record {
    Record::from_rdata(
        zone.clone(),
        LOCAL_ZONE_TTL,
        RData::SOA(SOA::new(
            zone.clone(),
            Name::from_ascii("nobody.invalid.").expect("static SOA name"),
            1,
            3600,
            1200,
            604_800,
            LOCAL_ZONE_TTL,
        )),
    )
}

fn local_nodata(query: &Query, zone: &Name) -> Message {
    let mut response = response_base(query, true);
    response.add_authority(local_soa(zone));
    response
}

fn empty_zone_response(query: &Query, zone: &Name) -> Message {
    let question = &query.message.queries[0];
    let mut response = response_base(query, true);
    if question.name() != zone {
        response.metadata.response_code = ResponseCode::NXDomain;
        response.add_authority(local_soa(zone));
        return response;
    }
    match question.query_type() {
        RecordType::SOA => response.add_answer(local_soa(zone)),
        RecordType::NS => response.add_answer(Record::from_rdata(
            zone.clone(),
            LOCAL_ZONE_TTL,
            RData::NS(NS(zone.clone())),
        )),
        _ => response.add_authority(local_soa(zone)),
    };
    response
}

/// Signature renewal tasks for signed operator zones. Dropping the resolver stops them.
#[derive(Default)]
struct Resigners(std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>);

impl Resigners {
    fn start(&self, zones: &[Arc<InMemoryZoneHandler<TokioRuntimeProvider>>]) {
        let Ok(mut tasks) = self.0.lock() else {
            return;
        };
        if !tasks.is_empty() {
            return;
        }
        for zone in zones {
            let zone = Arc::clone(zone);
            tasks.push(tokio::spawn(async move {
                // Signatures last days; renewing daily leaves a long margin for failures.
                loop {
                    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                    if DnssecZoneHandler::secure_zone(&*zone).await.is_err() {
                        eprintln!("zone signature renewal failed; keeping current signatures");
                    }
                }
            }));
        }
    }
}

impl Drop for Resigners {
    fn drop(&mut self) {
        if let Ok(tasks) = self.0.lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
}

impl Resolver {
    /// Build the selected mode and trust anchors before opening listeners.
    ///
    /// # Errors
    /// Invalid hints, anchors, TLS settings, or resolver configuration fail startup.
    pub fn new(config: &Config) -> Result<Self, String> {
        Self::build(config, true)
    }

    /// Validate everything [`Self::new`] would load without creating or opening any journal.
    ///
    /// # Errors
    /// The same errors as [`Self::new`].
    pub fn check(config: &Config) -> Result<(), String> {
        Self::build(config, false).map(|_| ())
    }

    fn build(config: &Config, persist: bool) -> Result<Self, String> {
        let settings = &config.resolver;
        let metrics = Arc::new(Metrics::default());
        metrics
            .diagnostics
            .store(settings.diagnostics, Ordering::Relaxed);
        let anchors = settings
            .trust_anchor
            .as_ref()
            .map(|path| {
                let bytes = read_bounded(path, 65536)?;
                let anchors: TrustAnchors = std::str::from_utf8(&bytes)
                    .map_err(|_| "trust anchor must be UTF-8")?
                    .parse()
                    .map_err(|_| "invalid DNSKEY trust anchor")?;
                if anchors.is_empty() {
                    return Err("trust anchor must contain a DNSKEY".into());
                }
                Ok::<_, String>(Arc::new(anchors))
            })
            .transpose()?;
        let (anchors, rollover) = match &settings.trust_anchor_state {
            Some(path) => {
                let (tracker, loaded) = rollover::startup(path, anchors.as_deref(), persist)?;
                (Some(Arc::new(loaded)), Some(tracker))
            }
            None => (anchors, None),
        };
        let mut options = ResolverOpts::default();
        options.validate = settings.dnssec;
        options.cache_size = u64::from(settings.cache_entries);
        options.timeout = Duration::from_millis(u64::from(settings.upstream_timeout_ms));
        options.attempts = usize::from(settings.attempts);
        options.num_concurrent_reqs = 1;
        options.max_active_requests = config.limits.max_in_flight as usize;
        options.use_hosts_file = ResolveHosts::Never;
        options.case_randomization = true;
        options.try_tcp_on_error = true;
        options.edns_payload_len = 1232;
        options.positive_max_ttl = Some(Duration::from_secs(u64::from(settings.positive_ttl_secs)));
        options.negative_max_ttl = Some(Duration::from_secs(u64::from(settings.negative_ttl_secs)));
        let (handler, background) = match settings.mode {
            Mode::Forward => (
                forward_zone(settings, &options, anchors.as_ref(), Arc::clone(&metrics))?,
                None,
            ),
            Mode::Recursive => {
                let (handler, background) =
                    recursive_zone(settings, &options, anchors, Arc::clone(&metrics))?;
                (handler, Some(background))
            }
        };
        let mut catalog = Catalog::new();
        catalog.upsert(Name::root().into(), vec![handler]);
        let built = zones::build(config, &options, persist)?;
        let (custom_handlers, signed, notifications) = (built.handlers, built.resign, built.notify);
        let custom: Vec<LowerName> = custom_handlers
            .iter()
            .map(|handler| handler.origin().clone())
            .collect();
        zones::install(&mut catalog, custom_handlers);
        let cache = ResponseCache::new(settings)?.map(Arc::new);
        Ok(Self {
            catalog,
            cache,
            custom,
            rollover,
            signed,
            notifications,
            challenges: Arc::default(),
            hosts: Arc::new(Hosts::new(config.dhcp.domain.as_deref())),
            resigners: Resigners::default(),
            metrics,
            background,
            local_zones: settings.local_zones,
        })
    }

    /// Begin optional priming and refresh. Call once, after every listener is bound;
    /// dropping the resolver stops them. Does nothing when both are disabled.
    pub fn start_background(&self) {
        self.resigners.start(&self.signed);
        for (zone, targets) in &self.notifications {
            tokio::spawn(notify::send(zone.clone(), targets.clone()));
        }
        if let Some(background) = &self.background {
            (background.start)();
        }
    }

    /// Forget names selected for expiry refresh after filtering policy changes.
    pub fn clear_prefetch(&self) {
        if let Some(background) = &self.background {
            background.accel.clear_prefetch();
        }
    }

    /// The names DHCP leases publish, answered by this resolver.
    #[must_use]
    pub fn hosts(&self) -> Arc<Hosts> {
        Arc::clone(&self.hosts)
    }

    /// Where an ACME client publishes DNS-01 challenge values for this resolver to answer.
    #[must_use]
    pub fn challenges(&self) -> Arc<Challenges> {
        Arc::clone(&self.challenges)
    }

    /// Resolver-owned aggregate metrics.
    #[must_use]
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Resolve a validated query. Caller supplies admission control and deadline.
    ///
    /// # Errors
    /// Returns a non-sensitive error if response serialization fails.
    pub async fn answer(
        self: &Arc<Self>,
        query: &Query,
        peer: SocketAddr,
        protocol: Transport,
        maximum: usize,
    ) -> Result<Vec<u8>, String> {
        if let Some(response) = self.hosts.answer(query) {
            return response
                .to_vec()
                .map_err(|_| "cannot encode host response".into());
        }
        if let Some(response) = self.challenges.answer(query) {
            return response
                .to_vec()
                .map_err(|_| "cannot encode challenge response".into());
        }
        let custom = self.is_custom(query);
        if self.local_zones
            && !custom
            && let Some(response) = local_zone_response(query)
        {
            return response
                .to_vec()
                .map_err(|_| "cannot encode local response".into());
        }
        if !custom
            && let Some(cache) = &self.cache
            && let Some(hit) = cache.lookup(query, maximum)
        {
            if hit.stale && cache.begin_refresh(&hit.key) {
                let (resolver, query, key) = (Arc::clone(self), query.clone(), hit.key.clone());
                tokio::spawn(async move {
                    if let Ok(response) = resolver
                        .answer_uncached(&query, peer, Protocol::Tcp, usize::from(u16::MAX))
                        .await
                        && let Some(cache) = &resolver.cache
                    {
                        cache.store(&query, &response);
                    }
                    if let Some(cache) = &resolver.cache {
                        cache.end_refresh(&key);
                    }
                });
            }
            return Ok(hit.bytes);
        }
        let response = self.answer_uncached(query, peer, protocol, maximum).await?;
        if !custom && let Some(cache) = &self.cache {
            cache.store(query, &response);
        }
        Ok(response)
    }

    /// True when the question falls under an operator zone or conditional forwarder.
    fn is_custom(&self, query: &Query) -> bool {
        query.message.queries.first().is_some_and(|question| {
            let name = LowerName::from(question.name());
            self.custom.iter().any(|origin| origin.zone_of(&name))
        })
    }

    /// Answer an RFC 2136 update or a zone transfer. Always returns a response: operator zones
    /// decide, everything else is `REFUSED`. Transfers are accepted only over plain TCP, and a
    /// transfer that does not fit one 64 KiB message is refused instead of being cut short.
    pub async fn zone_message(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        protocol: Transport,
        kind: ZoneMessage,
    ) -> Vec<u8> {
        let refused = |packet: &[u8]| {
            let mut bytes = lumen_proto::malformed_response(packet);
            bytes[2] = 0x80 | (packet[2] & 0x79);
            bytes[3] = 5;
            bytes
        };
        if kind == ZoneMessage::Transfer && protocol != Protocol::Tcp {
            return refused(packet);
        }
        let Ok(request) = Request::from_bytes(packet.to_vec(), peer, protocol) else {
            return lumen_proto::malformed_response(packet);
        };
        let in_zone = request.request_info().is_ok_and(|info| {
            let name = info.query.name();
            self.custom.iter().any(|origin| origin.zone_of(name))
        });
        if !in_zone {
            return refused(packet);
        }
        let bytes = Arc::new(Mutex::new(Vec::new()));
        self.catalog
            .handle_request::<_, TokioTime>(
                &request,
                Capture {
                    bytes: Arc::clone(&bytes),
                    maximum: usize::from(u16::MAX),
                },
            )
            .await;
        let result = bytes.lock().map(|mut guard| std::mem::take(&mut *guard));
        match result {
            // A set TC bit means the transfer did not fit: fail closed, never send a partial zone.
            Ok(result) if result.len() >= 12 && result[2] & 0x02 == 0 => result,
            _ => {
                let mut bytes = lumen_proto::malformed_response(packet);
                bytes[2] = 0x80 | (packet[2] & 0x79);
                bytes[3] = 2;
                bytes
            }
        }
    }

    /// Return a cached response after the outer query deadline cancelled live resolution.
    #[must_use]
    pub fn cached_answer(&self, query: &Query, maximum: usize) -> Option<Vec<u8>> {
        if self.is_custom(query) {
            return None;
        }
        self.cache
            .as_ref()
            .and_then(|cache| cache.lookup(query, maximum))
            .map(|hit| hit.bytes)
    }

    async fn answer_uncached(
        &self,
        query: &Query,
        peer: SocketAddr,
        protocol: Transport,
        maximum: usize,
    ) -> Result<Vec<u8>, String> {
        let raw = query.message.to_vec().map_err(|_| "cannot encode query")?;
        let request =
            Request::from_bytes(raw, peer, protocol).map_err(|_| "cannot decode request")?;
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let maximum = if protocol == Protocol::Udp {
            maximum
                .min(usize::from(query.message.max_payload()))
                .min(1232)
        } else {
            maximum
        };
        self.catalog
            .handle_request::<_, TokioTime>(
                &request,
                Capture {
                    bytes: Arc::clone(&bytes),
                    maximum,
                },
            )
            .await;
        let result = std::mem::take(&mut *bytes.lock().map_err(|_| "response lock poisoned")?);
        if result.is_empty() {
            return Err("empty resolver response".into());
        }
        Ok(result)
    }
}

fn forward_zone(
    settings: &lumen_config::Resolver,
    options: &ResolverOpts,
    anchors: Option<&Arc<TrustAnchors>>,
    metrics: Arc<Metrics>,
) -> Result<Arc<dyn ZoneHandler>, String> {
    let pool = forward_pool(settings, options, anchors)?;
    // A small second pool without validation, used only below zones already proven unsigned.
    let plain = if settings.dnssec {
        let mut plain_options = options.clone();
        plain_options.validate = false;
        plain_options.cache_size = (plain_options.cache_size / 8).max(64);
        Some(forward_pool(settings, &plain_options, None)?)
    } else {
        None
    };
    Ok(Arc::new(ResolutionZone {
        origin: Name::root().into(),
        backend: Backend::Forward(Box::new(ForwardBackend {
            pool,
            plain,
            budget: Duration::from_millis(u64::from(settings.upstream_timeout_ms)),
            metrics: Some(metrics),
        })),
    }))
}

/// The forwarders of every provider and custom upstream, and how a query picks among them.
fn forward_pool(
    settings: &lumen_config::Resolver,
    options: &ResolverOpts,
    anchors: Option<&Arc<TrustAnchors>>,
) -> Result<forward::ForwardPool<TokioRuntimeProvider>, String> {
    // Without a strategy the older behavior stays: one forwarder over every address.
    let (strategy, groups) = match settings.strategy {
        Some(strategy) => (
            strategy,
            group_sizes(&settings.provider_groups, settings.upstreams.len()),
        ),
        None => (ForwardStrategy::Failover, vec![settings.upstreams.len()]),
    };
    let mut members = Vec::new();
    let mut start = 0;
    for size in groups.iter().copied().filter(|&size| size > 0) {
        let mut member_options = options.clone();
        if groups.len() > 1 {
            // Another provider is the retry, so a silent one costs one timeout, not two.
            member_options.attempts = 1;
        }
        members.push(forward_provider(
            settings,
            &settings.upstreams[start..start + size],
            member_options,
            anchors.cloned(),
        )?);
        start += size;
    }
    let penalty = Duration::from_millis(u64::from(settings.upstream_timeout_ms));
    Ok(forward::ForwardPool::new(members, strategy, penalty))
}

/// Sizes of the groups that `count` upstreams form, one group per provider and then one per
/// custom upstream. `provider_groups` lists the provider groups in rank order.
fn group_sizes(provider_groups: &[usize], count: usize) -> Vec<usize> {
    let mut groups = provider_groups.to_vec();
    let used: usize = groups.iter().sum();
    groups.extend(std::iter::repeat_n(1, count.saturating_sub(used)));
    groups
}

fn forward_provider(
    settings: &lumen_config::Resolver,
    upstreams: &[lumen_config::Upstream],
    options: ResolverOpts,
    anchors: Option<Arc<TrustAnchors>>,
) -> Result<forward::Provider<TokioRuntimeProvider>, String> {
    if !settings.automatic_transport {
        return Ok(forward::Provider::new(
            vec![forward_resolver(settings, upstreams, options, anchors)?],
            None,
        ));
    }
    // Automatic mode is encrypted-only even for callers that bypass config expansion.
    if upstreams.iter().any(|upstream| {
        matches!(
            upstream.protocol,
            UpstreamProtocol::Udp | UpstreamProtocol::Tcp
        )
    }) {
        return Err("automatic transports must be encrypted".into());
    }
    let mut tiers: Vec<Vec<lumen_config::Upstream>> = Vec::new();
    for upstream in upstreams {
        if let Some(tier) = tiers
            .iter_mut()
            .find(|tier| tier[0].protocol == upstream.protocol)
        {
            tier.push(upstream.clone());
        } else {
            tiers.push(vec![upstream.clone()]);
        }
    }
    let budget = options.timeout;
    let mut transports = Vec::new();
    for tier in &tiers {
        let mut tier_options = options.clone();
        // Keep the provider's configured response-cache bound across all its transports.
        tier_options.cache_size /= tiers.len() as u64;
        if tiers.len() > 1 {
            tier_options.attempts = 1;
        }
        transports.push(forward_resolver(
            settings,
            tier,
            tier_options,
            anchors.clone(),
        )?);
    }
    Ok(forward::Provider::new(transports, Some(budget)))
}

fn forward_resolver(
    settings: &lumen_config::Resolver,
    upstreams: &[lumen_config::Upstream],
    mut options: ResolverOpts,
    anchors: Option<Arc<TrustAnchors>>,
) -> Result<hickory_server::resolver::Resolver<TokioRuntimeProvider>, String> {
    if settings.automatic_transport {
        options.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        options.num_concurrent_reqs = 1;
    }
    let servers = upstreams
        .iter()
        .map(|upstream| name_server_config(upstream, settings.automatic_transport))
        .collect();
    let mut builder = hickory_server::resolver::Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], servers),
        TokioRuntimeProvider::default(),
    )
    .with_options(options);
    if let Some(path) = &settings.upstream_ca {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let bytes = read_bounded(path, 1_048_576)?;
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&bytes) {
            roots
                .add(cert.map_err(|_| "invalid upstream CA PEM")?)
                .map_err(|_| "invalid upstream CA certificate")?;
        }
        if roots.is_empty() {
            return Err("upstream_ca has no certificates".into());
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| "invalid TLS versions")?
        .with_root_certificates(roots)
        .with_no_client_auth();
        builder = builder.with_tls_config(tls);
    }
    if let Some(anchors) = anchors {
        builder = builder.with_trust_anchor(anchors);
    }
    builder
        .build()
        .map_err(|_| "cannot build forwarding resolver".into())
}

fn name_server_config(
    upstream: &lumen_config::Upstream,
    trust_negative_responses: bool,
) -> NameServerConfig {
    let name = Arc::from(upstream.server_name.as_deref().unwrap_or(""));
    let mut server = match upstream.protocol {
        UpstreamProtocol::Udp => NameServerConfig::udp_and_tcp(upstream.address.ip()),
        UpstreamProtocol::Tcp => NameServerConfig::tcp(upstream.address.ip()),
        UpstreamProtocol::Tls => NameServerConfig::tls(upstream.address.ip(), name),
        UpstreamProtocol::Https => NameServerConfig::https(
            upstream.address.ip(),
            name,
            upstream.doh_path.as_deref().map(Arc::from),
        ),
        UpstreamProtocol::H3 => NameServerConfig::h3(
            upstream.address.ip(),
            name,
            upstream.doh_path.as_deref().map(Arc::from),
        ),
        UpstreamProtocol::Quic => NameServerConfig::quic(upstream.address.ip(), name),
    };
    server.trust_negative_responses = trust_negative_responses;
    for connection in &mut server.connections {
        connection.port = upstream.address.port();
    }
    server
}

fn recursive_zone(
    settings: &lumen_config::Resolver,
    options: &ResolverOpts,
    anchors: Option<Arc<TrustAnchors>>,
    metrics: Arc<Metrics>,
) -> Result<(Arc<dyn ZoneHandler>, Background), String> {
    let roots = match &settings.root_hints {
        Some(path) => {
            String::from_utf8(read_bounded(path, 65536)?).map_err(|_| "root hints must be UTF-8")?
        }
        None => include_str!("../data/root.hints").to_owned(),
    };
    // Operator overrides are data, never instructions to read other files.
    if roots.contains('$') {
        return Err("root hints directives are not allowed".into());
    }
    let (_, records) = Parser::new(roots, None, Some(Name::root()))
        .parse()
        .map_err(|_| "invalid root hints")?;
    let addresses: Vec<IpAddr> = records
        .values()
        .flat_map(RecordSet::records_without_rrsigs)
        .filter_map(|record| record.data.ip_addr())
        .collect();
    if addresses.is_empty() || addresses.len() > 64 {
        return Err("root hints need 1..64 A/AAAA records".into());
    }
    let mut dnssec = DnssecConfig::default();
    dnssec.trust_anchor.clone_from(&anchors);
    dnssec.nsec3_soft_iteration_limit = Some(100);
    dnssec.nsec3_hard_iteration_limit = Some(500);
    dnssec.validation_cache_size = Some(settings.validation_cache_entries as usize);
    let policy = if settings.dnssec {
        DnssecPolicy::ValidateWithStaticKey(dnssec)
    } else {
        DnssecPolicy::ValidationDisabled
    };
    let build = |policy: DnssecPolicy, divisor: usize| {
        Recursor::new(
            &addresses,
            policy,
            None,
            RecursorOptions {
                ns_cache_size: (settings.nameserver_cache_entries as usize / divisor).max(64),
                response_cache_size: (u64::from(settings.cache_entries) / divisor as u64).max(64),
                recursion_limit: settings.recursion_depth,
                ns_recursion_limit: settings.recursion_depth,
                cache_policy: TtlConfig::from_opts(options),
                case_randomization: true,
                edns_payload_len: 1232,
                ..RecursorOptions::default()
            },
            TokioRuntimeProvider::default(),
        )
        .map_err(|_| "cannot build recursive resolver")
    };
    // A small second recursor without validation, used only below zones already proven unsigned.
    let insecure = if settings.dnssec {
        Some(Arc::new(build(DnssecPolicy::ValidationDisabled, 8)?))
    } else {
        None
    };
    let recursor = Arc::new(build(policy, 1)?);
    let accel = Arc::new(
        Accel::new(Arc::clone(&metrics), settings.prefetch.clone()).with_hedge(settings.hedge_ms),
    );
    let fallback = if settings.fallback.enabled {
        let mut fallback_options = options.clone();
        fallback_options.attempts = usize::from(settings.fallback.attempts);
        fallback_options.timeout = Duration::from_millis(u64::from(settings.fallback.timeout_ms));
        Some(FallbackBackend {
            resolver: Box::new(forward_provider(
                settings,
                &settings.fallback.upstreams,
                fallback_options,
                anchors,
            )?),
            recursive_timeout: Duration::from_millis(u64::from(
                settings.fallback.recursive_timeout_ms,
            )),
            timeout: Duration::from_millis(u64::from(settings.fallback.timeout_ms)),
            metrics,
        })
    } else {
        None
    };
    let start = {
        let (accel, recursor, warm) = (
            Arc::clone(&accel),
            Arc::clone(&recursor),
            settings.warm.clone(),
        );
        Box::new(move || accel.start(&recursor, &warm))
    };
    let zone: Arc<dyn ZoneHandler> = Arc::new(ResolutionZone {
        origin: Name::root().into(),
        backend: Backend::Recursive {
            recursor,
            insecure,
            fallback,
            accel: Arc::clone(&accel),
            policy: RecursivePolicy {
                attempts: settings.attempts,
                attempt_timeout: Duration::from_millis(u64::from(settings.upstream_timeout_ms)),
            },
        },
    });
    Ok((zone, Background { accel, start }))
}

#[derive(Clone)]
struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    maximum: usize,
}

#[async_trait]
impl ResponseHandler for Capture {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
            impl Iterator<Item = &'a Record> + Send + 'a,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        encoder.set_max_size(u16::try_from(self.maximum).unwrap_or(u16::MAX));
        let info = response.destructive_emit(&mut encoder)?;
        *self
            .bytes
            .lock()
            .map_err(|_| io::Error::other("response lock poisoned"))? = bytes;
        Ok(info)
    }
}

enum Backend<P: hickory_server::net::runtime::RuntimeProvider> {
    Recursive {
        recursor: Arc<Recursor<P>>,
        insecure: Option<Arc<Recursor<P>>>,
        fallback: Option<FallbackBackend<P>>,
        accel: Arc<Accel>,
        policy: RecursivePolicy,
    },
    Forward(Box<ForwardBackend<P>>),
}

/// Forward mode: the pool that answers queries and, when local validation is on, a second pool
/// without validation for names below a zone that is provably unsigned.
pub(crate) struct ForwardBackend<P: hickory_server::net::runtime::RuntimeProvider> {
    pub(crate) pool: forward::ForwardPool<P>,
    plain: Option<forward::ForwardPool<P>>,
    /// One budget for the ancestor walk and the retry together.
    budget: Duration,
    metrics: Option<Arc<Metrics>>,
}

impl<P: hickory_server::net::runtime::RuntimeProvider> ForwardBackend<P> {
    /// A forwarder with no recovery, for conditional forwarders.
    pub(crate) fn plain(pool: forward::ForwardPool<P>) -> Self {
        Self {
            pool,
            plain: None,
            budget: Duration::ZERO,
            metrics: None,
        }
    }
}
#[derive(Clone, Copy)]
struct RecursivePolicy {
    attempts: u8,
    attempt_timeout: Duration,
}
#[derive(Clone, Copy)]
struct RecoveryTarget<'a> {
    name: &'a LowerName,
    rtype: RecordType,
    dnssec_ok: bool,
}
struct FallbackBackend<P: hickory_server::net::runtime::RuntimeProvider> {
    resolver: Box<forward::Provider<P>>,
    recursive_timeout: Duration,
    timeout: Duration,
    metrics: Arc<Metrics>,
}
struct ResolutionZone<P: hickory_server::net::runtime::RuntimeProvider> {
    origin: LowerName,
    backend: Backend<P>,
}

#[async_trait]
impl<P: hickory_server::net::runtime::RuntimeProvider> ZoneHandler for ResolutionZone<P> {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }
    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }
    fn can_validate_dnssec(&self) -> bool {
        match &self.backend {
            Backend::Recursive { recursor, .. } => recursor.is_validating(),
            Backend::Forward(backend) => backend.pool.validates(),
        }
    }
    fn origin(&self) -> &LowerName {
        &self.origin
    }
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
    #[allow(clippy::too_many_lines)] // One match over every backend and fallback path.
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _: Option<&RequestInfo<'_>>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let result = match &self.backend {
            Backend::Recursive {
                recursor,
                insecure,
                fallback,
                accel,
                policy,
            } => match fallback {
                Some(fallback) => {
                    let recursive = timeout(
                        fallback.recursive_timeout,
                        recursive_lookup(recursor, accel, name, rtype, options.dnssec_ok, *policy),
                    )
                    .await;
                    match recursive {
                        Ok(Ok(message)) => Ok(AuthLookup::Response(
                            recover_bogus(
                                recursor,
                                insecure.as_deref(),
                                accel,
                                RecoveryTarget {
                                    name,
                                    rtype,
                                    dnssec_ok: options.dnssec_ok,
                                },
                                message,
                                *policy,
                            )
                            .await,
                        )),
                        Ok(Err(error)) if !recursion_timed_out(&error) => {
                            match insecure_retry(
                                recursor,
                                insecure.as_deref(),
                                accel,
                                RecoveryTarget {
                                    name,
                                    rtype,
                                    dnssec_ok: options.dnssec_ok,
                                },
                                Some(&error),
                                *policy,
                            )
                            .await
                            {
                                Some(message) => Ok(AuthLookup::Response(message)),
                                None => Err(LookupError::from(error)),
                            }
                        }
                        Ok(Err(_)) | Err(_) => {
                            fallback.metrics.attempts.fetch_add(1, Ordering::Relaxed);
                            fallback
                                .metrics
                                .timeout_triggers
                                .fetch_add(1, Ordering::Relaxed);
                            match timeout(
                                fallback.timeout,
                                fallback.resolver.lookup(Name::from(name), rtype),
                            )
                            .await
                            {
                                Ok(Ok(lookup)) => {
                                    fallback.metrics.successes.fetch_add(1, Ordering::Relaxed);
                                    Ok(AuthLookup::from(lookup))
                                }
                                Ok(Err(error)) => {
                                    if error.is_no_records_found() {
                                        fallback.metrics.successes.fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        fallback.metrics.failures.fetch_add(1, Ordering::Relaxed);
                                    }
                                    Err(LookupError::from(error))
                                }
                                Err(_) => {
                                    fallback.metrics.failures.fetch_add(1, Ordering::Relaxed);
                                    Err(LookupError::from(NetError::Timeout))
                                }
                            }
                        }
                    }
                }
                None => {
                    match recursive_lookup(recursor, accel, name, rtype, options.dnssec_ok, *policy)
                        .await
                    {
                        Ok(message) => Ok(AuthLookup::Response(
                            recover_bogus(
                                recursor,
                                insecure.as_deref(),
                                accel,
                                RecoveryTarget {
                                    name,
                                    rtype,
                                    dnssec_ok: options.dnssec_ok,
                                },
                                message,
                                *policy,
                            )
                            .await,
                        )),
                        Err(error) => match insecure_retry(
                            recursor,
                            insecure.as_deref(),
                            accel,
                            RecoveryTarget {
                                name,
                                rtype,
                                dnssec_ok: options.dnssec_ok,
                            },
                            Some(&error),
                            *policy,
                        )
                        .await
                        {
                            Some(message) => Ok(AuthLookup::Response(message)),
                            None => Err(LookupError::from(error)),
                        },
                    }
                }
            },
            Backend::Forward(backend) => {
                match backend.pool.lookup(Name::from(name), rtype).await {
                    Ok(lookup) => Ok(AuthLookup::from(lookup)),
                    // A failed validation is final unless a zone above the name is provably
                    // unsigned, which makes validating anything below it meaningless.
                    Err(NetError::Dns(DnsError::DnssecBogus)) => {
                        match forward_insecure_retry(backend, name, rtype).await {
                            Some(lookup) => Ok(AuthLookup::from(lookup)),
                            None => Err(LookupError::from(NetError::Dns(DnsError::DnssecBogus))),
                        }
                    }
                    Err(error) => Err(LookupError::from(error)),
                }
            }
        };
        LookupControlFlow::Continue(result)
    }
    async fn search(
        &self,
        request: &Request,
        options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let result = match request.request_info() {
            Ok(info) => {
                self.lookup(
                    info.query.name(),
                    info.query.query_type(),
                    Some(&info),
                    options,
                )
                .await
            }
            Err(error) => LookupControlFlow::Break(Err(error)),
        };
        (result, None)
    }
    async fn nsec_records(&self, _: &LowerName, _: LookupOptions) -> LookupControlFlow<AuthLookup> {
        unsupported()
    }
    async fn nsec3_records(
        &self,
        _: Nsec3QueryInfo<'_>,
        _: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        unsupported()
    }
}

/// Run a small number of full recursive walks. Only a timeout is retried. Hickory keeps
/// delegation and response caches between attempts, so a retry can reuse completed work while
/// choosing a different authority. DNS answers and DNSSEC failures stay final.
async fn recursive_lookup<P: hickory_server::net::runtime::RuntimeProvider>(
    recursor: &Recursor<P>,
    accel: &Accel,
    name: &LowerName,
    rtype: RecordType,
    dnssec_ok: bool,
    policy: RecursivePolicy,
) -> Result<Message, hickory_server::resolver::recursor::RecursorError> {
    let lookup_started = Instant::now();
    let mut last = hickory_server::resolver::recursor::RecursorError::Timeout;
    let result = 'attempts: {
        for attempt in 0..policy.attempts {
            if attempt > 0 {
                accel
                    .metrics
                    .recursive_retries
                    .fetch_add(1, Ordering::Relaxed);
            }
            accel
                .metrics
                .recursive_attempts
                .fetch_add(1, Ordering::Relaxed);
            let started = Instant::now();
            let result = timeout(
                policy.attempt_timeout,
                accel.resolve_unobserved(recursor, name, rtype, dnssec_ok, false),
            )
            .await;
            accel.metrics.observe_attempt(started.elapsed());
            match result {
                Ok(Ok(message)) => break 'attempts Ok(message),
                Ok(Err(error)) if recursion_timed_out(&error) => {
                    accel
                        .metrics
                        .recursive_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                    last = error;
                }
                Err(_) => {
                    accel
                        .metrics
                        .recursive_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                    last = hickory_server::resolver::recursor::RecursorError::Timeout;
                }
                Ok(Err(error)) => {
                    accel
                        .metrics
                        .recursive_failures
                        .fetch_add(1, Ordering::Relaxed);
                    break 'attempts Err(error);
                }
            }
        }
        break 'attempts Err(last);
    };
    accel.metrics.observe(lookup_started.elapsed(), false);
    result
}

/// Forward mode's counterpart of `insecure_retry`: after a DNSSEC failure, walk the ancestors
/// from the top-level domain down with validating lookups. The first one that validates as
/// provably insecure (a zone with no DS record, proven) means nothing below it can be secure, so
/// the lookup is repeated once without validation. A secure ancestor sends the walk one level
/// down; a bogus or unanswered one ends it, and the failure stands. The walk and the retry share
/// one budget and are cancelled with the query.
async fn forward_insecure_retry<P: hickory_server::net::runtime::RuntimeProvider>(
    backend: &ForwardBackend<P>,
    name: &LowerName,
    rtype: RecordType,
) -> Option<hickory_server::resolver::lookup::Lookup> {
    let plain = backend.plain.as_ref()?;
    let mut chain = Vec::new();
    let mut current = Name::from(name.clone()).base_name();
    while !current.is_root() {
        chain.push(current.clone());
        current = current.base_name();
    }
    chain.reverse(); // from the top-level domain downwards
    let deadline = Instant::now() + backend.budget;
    let remaining = || deadline.saturating_duration_since(Instant::now());
    for ancestor in chain {
        // Which name server answers can vary, so the apex is looked at twice (SOA, then NS).
        let mut verdict = None;
        for probe in [RecordType::SOA, RecordType::NS] {
            let left = remaining();
            if left.is_zero() {
                return None;
            }
            let result = timeout(left, backend.pool.lookup(ancestor.clone(), probe))
                .await
                .ok()?;
            verdict = match &result {
                Ok(lookup) => Some(DnssecSummary::from_records(lookup.answers().iter())),
                Err(NetError::Dns(DnsError::DnssecBogus)) => Some(DnssecSummary::Bogus),
                // Not answered: there is nothing to base a decision on.
                Err(_) => return None,
            };
            if !matches!(verdict, Some(DnssecSummary::Bogus)) {
                break;
            }
        }
        match verdict? {
            DnssecSummary::Insecure => {
                let lookup = timeout(remaining(), plain.lookup(Name::from(name.clone()), rtype))
                    .await
                    .ok()?
                    .ok()?;
                if let Some(metrics) = &backend.metrics {
                    metrics
                        .forward_insecure_recoveries
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Some(lookup);
            }
            DnssecSummary::Secure => {} // a signed zone: look one level down
            DnssecSummary::Bogus => return None,
        }
    }
    None
}

/// Some operators answer DS queries for a child zone from the child itself, which strict
/// validation reads as bogus (Google's `l.google.com` is one). DNSSEC cannot make a name secure
/// below a zone that is provably unsigned, so when an ancestor was validated as insecure the
/// lookup is repeated without validation. Anything below a signed or bogus ancestor still fails.
async fn insecure_retry<P: hickory_server::net::runtime::RuntimeProvider>(
    validating: &Recursor<P>,
    plain: Option<&Recursor<P>>,
    accel: &Accel,
    target: RecoveryTarget<'_>,
    error: Option<&hickory_server::resolver::recursor::RecursorError>,
    policy: RecursivePolicy,
) -> Option<Message> {
    let plain = plain?;
    if error.is_some_and(|e| e.is_no_records_found() || e.is_nx_domain() || recursion_timed_out(e))
    {
        return None;
    }
    let mut chain = Vec::new();
    let mut current = Name::from(target.name.clone()).base_name();
    while !current.is_root() {
        chain.push(current.clone());
        current = current.base_name();
    }
    chain.reverse(); // from the top-level domain downwards
    let deadline = Instant::now() + policy.attempt_timeout;
    for ancestor in chain {
        let ancestor = LowerName::from(ancestor);
        // Which name server answers can vary between attempts, so look at the apex more than once.
        for probe in [RecordType::SOA, RecordType::NS] {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            let result = timeout(
                remaining,
                accel.resolve_unobserved(validating, &ancestor, probe, true, false),
            )
            .await
            .ok()?;
            let Ok(message) = result else { continue };
            match DnssecSummary::from_records(
                message.answers.iter().chain(message.authorities.iter()),
            ) {
                DnssecSummary::Insecure => {
                    let query = DnsQuery::query(Name::from(target.name.clone()), target.rtype);
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    return timeout(
                        remaining,
                        plain.resolve(query, Instant::now(), target.dnssec_ok),
                    )
                    .await
                    .ok()?
                    .ok()
                    .map(|mut message| {
                        message.metadata.authentic_data = false;
                        message
                    });
                }
                DnssecSummary::Secure => break, // a signed zone: look one level down
                DnssecSummary::Bogus => {}
            }
        }
    }
    None
}

/// The recursor returns data it could not validate as an answer whose records are tagged
/// bogus, and the server then answers SERVFAIL. Give such an answer the same second look.
async fn recover_bogus<P: hickory_server::net::runtime::RuntimeProvider>(
    validating: &Recursor<P>,
    plain: Option<&Recursor<P>>,
    accel: &Accel,
    target: RecoveryTarget<'_>,
    message: Message,
    policy: RecursivePolicy,
) -> Message {
    let bogus = matches!(
        DnssecSummary::from_records(message.answers.iter().chain(message.authorities.iter())),
        DnssecSummary::Bogus
    );
    let mut message = if bogus {
        insecure_retry(validating, plain, accel, target, None, policy)
            .await
            .unwrap_or(message)
    } else {
        message
    };
    lowercase_names(&mut message);
    message
}

/// Case randomization protects the upstream exchange; clients must not see the random case.
/// DNSSEC canonical form is lowercase, so signatures stay valid.
fn lowercase_names(message: &mut Message) {
    for record in &mut message.answers {
        record.name = record.name.to_lowercase();
        match &mut record.data {
            RData::CNAME(target) => target.0 = target.0.to_lowercase(),
            RData::HTTPS(https) => https.0.target_name = https.0.target_name.to_lowercase(),
            RData::SVCB(svcb) => svcb.target_name = svcb.target_name.to_lowercase(),
            _ => {}
        }
    }
}

pub(crate) fn recursion_timed_out(
    error: &hickory_server::resolver::recursor::RecursorError,
) -> bool {
    error.is_timeout()
        || matches!(
            error,
            hickory_server::resolver::recursor::RecursorError::Timeout
        )
}

fn unsupported() -> LookupControlFlow<AuthLookup> {
    LookupControlFlow::Continue(Err(LookupError::from(io::Error::other(
        "authoritative proof request is unsupported",
    ))))
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: Apache-2.0
//! DNS resolution and validation through Hickory, isolated from client transports.

use async_trait::async_trait;
use hickory_server::{
    dnssec::NxProofKind,
    net::{
        NetError,
        runtime::{TokioRuntimeProvider, TokioTime},
        xfer::Protocol,
    },
    proto::{
        dnssec::TrustAnchors,
        op::Query as DnsQuery,
        rr::{LowerName, Name, Record, RecordSet, RecordType, TSigResponseContext},
        serialize::{binary::BinEncoder, txt::Parser},
    },
    resolver::{
        TtlConfig,
        config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts},
        recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions},
    },
    server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions,
        MessageResponse, Nsec3QueryInfo, ZoneHandler, ZoneType,
    },
};
use lumen_config::{Config, Mode, UpstreamProtocol, read_bounded};
use lumen_proto::Query;
use std::{
    fmt::Write,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::time::timeout;

pub use hickory_server::net::xfer::Protocol as Transport;

/// One shared resolver and cache set for all enabled client transports.
pub struct Resolver {
    catalog: Catalog,
    metrics: Arc<Metrics>,
}

/// Aggregate fallback counters. No query names or client labels are retained.
#[derive(Default)]
pub struct Metrics {
    attempts: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    timeout_triggers: AtomicU64,
}

impl Metrics {
    /// Stable Prometheus text for the optional recursive fallback path.
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
        ] {
            let _ = writeln!(
                text,
                "# HELP lumen_dns_{name} {help}\n# TYPE lumen_dns_{name} counter\nlumen_dns_{name} {}",
                value.load(Ordering::Relaxed)
            );
        }
        text
    }
}

impl Resolver {
    /// Build the selected mode and trust anchors before opening listeners.
    ///
    /// # Errors
    /// Invalid hints, anchors, TLS settings, or resolver configuration fail startup.
    pub fn new(config: &Config) -> Result<Self, String> {
        let settings = &config.resolver;
        let metrics = Arc::new(Metrics::default());
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
        let handler: Arc<dyn ZoneHandler> = match settings.mode {
            Mode::Forward => forward_zone(settings, options, anchors)?,
            Mode::Recursive => recursive_zone(settings, &options, anchors, Arc::clone(&metrics))?,
        };
        let mut catalog = Catalog::new();
        catalog.upsert(Name::root().into(), vec![handler]);
        Ok(Self { catalog, metrics })
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
        let result = bytes.lock().map_err(|_| "response lock poisoned")?.clone();
        if result.is_empty() {
            return Err("empty resolver response".into());
        }
        Ok(result)
    }
}

fn forward_zone(
    settings: &lumen_config::Resolver,
    options: ResolverOpts,
    anchors: Option<Arc<TrustAnchors>>,
) -> Result<Arc<dyn ZoneHandler>, String> {
    let resolver = forward_resolver(settings, &settings.upstreams, options, anchors)?;
    Ok(Arc::new(ResolutionZone {
        origin: Name::root().into(),
        backend: Backend::Forward(Box::new(resolver)),
    }))
}

fn forward_resolver(
    settings: &lumen_config::Resolver,
    upstreams: &[lumen_config::Upstream],
    options: ResolverOpts,
    anchors: Option<Arc<TrustAnchors>>,
) -> Result<hickory_server::resolver::Resolver<TokioRuntimeProvider>, String> {
    let servers = upstreams.iter().map(name_server_config).collect();
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

fn name_server_config(upstream: &lumen_config::Upstream) -> NameServerConfig {
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
        UpstreamProtocol::Quic => NameServerConfig::quic(upstream.address.ip(), name),
    };
    server.trust_negative_responses = false;
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
) -> Result<Arc<dyn ZoneHandler>, String> {
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
    let recursor = Recursor::new(
        &addresses,
        policy,
        None,
        RecursorOptions {
            ns_cache_size: settings.nameserver_cache_entries as usize,
            response_cache_size: u64::from(settings.cache_entries),
            recursion_limit: settings.recursion_depth,
            ns_recursion_limit: settings.recursion_depth,
            cache_policy: TtlConfig::from_opts(options),
            case_randomization: true,
            edns_payload_len: 1232,
            ..RecursorOptions::default()
        },
        TokioRuntimeProvider::default(),
    )
    .map_err(|_| "cannot build recursive resolver")?;
    let fallback = if settings.fallback.enabled {
        let mut fallback_options = options.clone();
        fallback_options.attempts = usize::from(settings.fallback.attempts);
        fallback_options.timeout = Duration::from_millis(u64::from(settings.fallback.timeout_ms));
        Some(FallbackBackend {
            resolver: Box::new(forward_resolver(
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
    Ok(Arc::new(ResolutionZone {
        origin: Name::root().into(),
        backend: Backend::Recursive {
            recursor: Box::new(recursor),
            fallback,
        },
    }))
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
        recursor: Box<Recursor<P>>,
        fallback: Option<FallbackBackend<P>>,
    },
    Forward(Box<hickory_server::resolver::Resolver<P>>),
}
struct FallbackBackend<P: hickory_server::net::runtime::RuntimeProvider> {
    resolver: Box<hickory_server::resolver::Resolver<P>>,
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
            Backend::Forward(resolver) => resolver.options().validate,
        }
    }
    fn origin(&self) -> &LowerName {
        &self.origin
    }
    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
    async fn lookup(
        &self,
        name: &LowerName,
        rtype: RecordType,
        _: Option<&RequestInfo<'_>>,
        options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        let result = match &self.backend {
            Backend::Recursive { recursor, fallback } => {
                let query = DnsQuery::query(name.into(), rtype);
                match fallback {
                    Some(fallback) => {
                        let recursive = timeout(
                            fallback.recursive_timeout,
                            recursor.resolve(query.clone(), Instant::now(), options.dnssec_ok),
                        )
                        .await;
                        match recursive {
                            Ok(Ok(message)) => Ok(AuthLookup::Response(message)),
                            Ok(Err(error)) if !recursion_timed_out(&error) => {
                                Err(LookupError::from(error))
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
                                            fallback
                                                .metrics
                                                .successes
                                                .fetch_add(1, Ordering::Relaxed);
                                        } else {
                                            fallback
                                                .metrics
                                                .failures
                                                .fetch_add(1, Ordering::Relaxed);
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
                    None => recursor
                        .resolve(query, Instant::now(), options.dnssec_ok)
                        .await
                        .map(AuthLookup::Response)
                        .map_err(LookupError::from),
                }
            }
            Backend::Forward(resolver) => resolver
                .lookup(Name::from(name), rtype)
                .await
                .map(AuthLookup::from)
                .map_err(LookupError::from),
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

fn recursion_timed_out(error: &hickory_server::resolver::recursor::RecursorError) -> bool {
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

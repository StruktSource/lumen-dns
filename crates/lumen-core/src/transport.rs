// SPDX-License-Identifier: Apache-2.0
//! Bounded async listeners. All transports share one query and connection budget.

use super::{Metrics, Service, Transport};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use lumen_config::Config;
use quinn::{Endpoint, crypto::rustls::QuicServerConfig};
use rustls::ServerConfig;
use socket2::{Domain, Protocol, Socket, Type};
use std::sync::atomic::Ordering;
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

/// Bound service. Dropping it aborts all listener and child tasks.
pub struct RunningServer {
    tasks: JoinSet<io::Result<()>>,
    service: Arc<Service>,
    pub endpoints: Vec<(Transport, SocketAddr)>,
    pub metrics: Arc<Metrics>,
    pub web_endpoints: Vec<(bool, SocketAddr)>,
    /// One-time code needed to create the first console account from another machine.
    pub setup_code: Option<String>,
    certificates: Option<Credentials>,
    /// Keeps the DHCP server's sockets open for as long as the service runs.
    _dhcp: Option<lumen_dhcp::Running>,
}

/// Optional managed-mode inputs for the web console.
#[derive(Clone, Debug, Default)]
pub struct ConsoleOptions {
    /// Managed state database. Without it the console API stays disabled.
    pub state: Option<std::path::PathBuf>,
    /// Version string shown by the console.
    pub version: &'static str,
}

impl RunningServer {
    /// Validate all configuration, credentials, and binds before serving requests.
    ///
    /// # Errors
    /// Fails startup if any enabled transport cannot be configured or bound.
    pub async fn start(config: Config) -> io::Result<Self> {
        Self::start_with(config, ConsoleOptions::default()).await
    }

    /// Start with console options: managed state for accounts and the console API.
    ///
    /// # Errors
    /// Same as [`Self::start`], plus an unusable state database.
    pub async fn start_with(config: Config, console: ConsoleOptions) -> io::Result<Self> {
        Self::start_prepared(config, console, None).await
    }

    /// Start, reusing a filter already loaded by [`Self::prepare`]. A reload then does not
    /// download large lists a second time while DNS is down.
    ///
    /// # Errors
    /// Same as [`Self::start_with`].
    #[allow(clippy::too_many_lines)] // Bind all resources before starting workers.
    pub async fn start_prepared(
        config: Config,
        console: ConsoleOptions,
        preloaded: Option<Arc<lumen_filter::Filter>>,
    ) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        config.validate().map_err(io::Error::other)?;
        let resolver = Arc::new(lumen_resolver::Resolver::new(&config).map_err(io::Error::other)?);
        let (tls, cert_not_after) = if config.listen.dot.is_empty()
            && config.listen.doh.is_empty()
            && config.listen.doq.is_empty()
            && config.listen.doh3.is_empty()
        {
            (None, None)
        } else {
            // With ACME, a certificate is obtained first when none exists yet.
            crate::acme::ensure(&config, &resolver.challenges()).await?;
            let (credentials, not_after) = credentials(&config)?;
            (Some(credentials), Some(not_after))
        };
        let filter = match preloaded {
            Some(filter) => filter,
            None => Arc::new(
                lumen_filter::Filter::load(config.filtering.clone())
                    .await
                    .map_err(io::Error::other)?,
            ),
        };
        #[cfg(unix)]
        let mut refresh_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
        #[cfg(unix)]
        let mut rollback_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
        let metrics = Arc::new(Metrics::default());
        let service = Arc::new(Service {
            started: std::time::Instant::now(),
            history_settings: std::sync::Mutex::default(),
            history: std::sync::Mutex::default(),
            unsaved: std::sync::Mutex::default(),
            queries: Arc::new(Semaphore::new(config.limits.max_in_flight as usize)),
            connections: Arc::new(Semaphore::new(config.limits.max_connections as usize)),
            clients: std::sync::Mutex::default(),
            resolver,
            filter: std::sync::RwLock::new(filter),
            config: Arc::new(config),
            metrics: Arc::clone(&metrics),
            dhcp: std::sync::OnceLock::new(),
        });
        if let Some(not_after) = cert_not_after {
            service
                .metrics
                .cert_not_after
                .store(not_after, Ordering::Relaxed);
        }
        let tls_handle = tls.clone();
        let config = &service.config;
        let mut datagrams = Vec::new();
        let mut streams = Vec::new();
        let mut quic = Vec::new();
        let mut endpoints = Vec::new();
        for address in &config.listen.udp {
            let socket = udp_socket(*address)?;
            endpoints.push((Transport::Udp, socket.local_addr()?));
            datagrams.push(socket);
        }
        for (protocol, addresses) in [
            (Transport::Tcp, &config.listen.tcp),
            (Transport::Tls, &config.listen.dot),
            (Transport::Https, &config.listen.doh),
        ] {
            for address in addresses {
                let listener = tcp_listener(*address)?;
                endpoints.push((protocol, listener.local_addr()?));
                let listener_tls = if protocol == Transport::Tcp {
                    None
                } else {
                    Some(tls_config(
                        tls.as_ref()
                            .ok_or_else(|| io::Error::other("missing TLS credentials"))?,
                        if protocol == Transport::Https {
                            b"h2"
                        } else {
                            b"dot"
                        },
                    )?)
                };
                streams.push((protocol, listener, listener_tls));
            }
        }
        for address in &config.listen.doq {
            let endpoint = quic_endpoint(
                *address,
                tls.as_ref()
                    .ok_or_else(|| io::Error::other("missing TLS credentials"))?,
                &config.limits,
                b"doq",
            )?;
            endpoints.push((Transport::Quic, endpoint.local_addr()?));
            quic.push(endpoint);
        }
        let mut h3 = Vec::new();
        for address in &config.listen.doh3 {
            let endpoint = quic_endpoint(
                *address,
                tls.as_ref()
                    .ok_or_else(|| io::Error::other("missing TLS credentials"))?,
                &config.limits,
                b"h3",
            )?;
            endpoints.push((Transport::H3, endpoint.local_addr()?));
            h3.push(endpoint);
        }
        let dnscrypt = if config.dnscrypt.enabled {
            let key_file = config
                .dnscrypt
                .key_file
                .as_deref()
                .ok_or_else(|| io::Error::other("dnscrypt key_file is required"))?;
            Some(Arc::new(crate::dnscrypt::DnsCrypt::load(
                &config.dnscrypt.provider_name,
                key_file,
                config.dnscrypt.cert_hours,
            )?))
        } else {
            None
        };
        let mut dnscrypt_sockets = Vec::new();
        if dnscrypt.is_some() {
            for address in &config.dnscrypt.listen {
                let socket = udp_socket(*address)?;
                let listener = tcp_listener(*address)?;
                endpoints.push((Transport::Udp, socket.local_addr()?));
                endpoints.push((Transport::Tcp, listener.local_addr()?));
                dnscrypt_sockets.push((socket, listener));
            }
        }
        let metrics_listener = config.metrics.map(tcp_listener).transpose()?;
        let console = console.state.map(|state| {
            lumen_web::Console::new(
                state,
                Arc::clone(&service) as Arc<dyn lumen_web::Host>,
                console.version,
            )
        });
        let setup_code = match &console {
            Some(console) => console.prepare().map_err(io::Error::other)?,
            None => None,
        };
        let web = lumen_web::BoundWeb::bind(&config.web, console.map(Arc::new)).await?;
        let web_endpoints = web
            .as_ref()
            .map_or_else(Vec::new, |web| web.endpoints.clone());
        let mut tasks = JoinSet::new();
        for socket in datagrams {
            tasks.spawn(serve_udp(socket, Arc::clone(&service)));
        }
        for (protocol, listener, tls) in streams {
            tasks.spawn(serve_tcp(listener, protocol, tls, Arc::clone(&service)));
        }
        for endpoint in quic {
            tasks.spawn(serve_quic(endpoint, Arc::clone(&service)));
        }
        for endpoint in h3 {
            tasks.spawn(serve_h3(endpoint, Arc::clone(&service)));
        }
        if let Some(dnscrypt) = dnscrypt {
            let public = crate::dnscrypt::to_hex(&dnscrypt.provider_public_key());
            eprintln!(
                "dnscrypt provider={} public_key={public}",
                dnscrypt.provider_name()
            );
            for (socket, listener) in dnscrypt_sockets {
                if let Ok(address) = listener.local_addr() {
                    eprintln!("dnscrypt stamp={}", dnscrypt.stamp(address));
                }
                tasks.spawn(serve_dnscrypt_udp(
                    socket,
                    Arc::clone(&dnscrypt),
                    Arc::clone(&service),
                ));
                tasks.spawn(serve_dnscrypt_tcp(
                    listener,
                    Arc::clone(&dnscrypt),
                    Arc::clone(&service),
                ));
            }
            tasks.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    dnscrypt.rotate_if_due();
                }
            });
        }
        #[cfg(unix)]
        {
            let control = Arc::clone(&service);
            tasks.spawn(async move {
                loop {
                    let result = tokio::select! {
                        _ = refresh_signal.recv() => refresh_filter(&control).await,
                        _ = rollback_signal.recv() => rollback_filter(&control).await,
                    };
                    if result.is_err() {
                        eprintln!("filter control failed; keeping live rules");
                    } else {
                        eprintln!("filter control applied");
                    }
                }
            });
        }
        if let Some(reloader) = tls_handle.clone() {
            let watched = Arc::clone(&service);
            tasks.spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    apply_reload(&reloader, &watched.metrics);
                }
            });
        }
        let refreshing = Arc::clone(&service);
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if refresh_filter_due(&refreshing).await.is_err() {
                    eprintln!("filter refresh failed; keeping previous rules");
                }
            }
        });
        // Every bind succeeded; only now may priming and refresh touch the network.
        service.resolver.start_background();
        if !config.acme.domains.is_empty() && tls.is_some() {
            let acme_config = Arc::clone(config);
            let acme_challenges = service.resolver.challenges();
            tasks.spawn(async move {
                crate::acme::keep_renewed(acme_config, acme_challenges).await;
                Ok(())
            });
        }
        if config.resolver.trust_anchor_state.is_some() {
            let resolver = Arc::clone(&service.resolver);
            tasks.spawn(async move {
                // RFC 5011 asks for a check at least every 15 days. Daily is cheap: one query.
                tokio::time::sleep(Duration::from_secs(60)).await;
                loop {
                    if let Err(error) = resolver.refresh_trust_anchors().await {
                        eprintln!("trust anchor check failed: {error}");
                    }
                    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
                }
            });
        }
        let dhcp = if config.dhcp.enabled {
            let running =
                Box::pin(lumen_dhcp::start(&config.dhcp, service.resolver.hosts())).await?;
            let _ = service.dhcp.set(running.handle());
            Some(running)
        } else {
            None
        };
        if let Some(listener) = metrics_listener {
            tasks.spawn(serve_metrics(listener, Arc::clone(&service)));
        }
        if let Some(web) = web {
            tasks.spawn(web.serve());
        }
        Ok(Self {
            tasks,
            service,
            endpoints,
            metrics,
            web_endpoints,
            setup_code,
            certificates: tls_handle,
            _dhcp: dhcp,
        })
    }

    /// Check the certificate files now instead of waiting for the periodic check. A valid, changed
    /// pair replaces the served one at once. Returns what happened.
    #[must_use]
    pub fn reload_certificates(&self) -> crate::certs::Reload {
        self.certificates
            .as_ref()
            .map_or(crate::certs::Reload::Unchanged, |reloader| {
                apply_reload(reloader, &self.service.metrics)
            })
    }

    /// Check startup credentials without creating any listeners.
    ///
    /// # Errors
    /// Same configuration and credential failures as startup.
    pub async fn check(config: &Config) -> io::Result<()> {
        Self::prepare(config).await.map(|_| ())
    }

    /// Everything [`Self::check`] verifies, returning the loaded filter so the caller can
    /// start without downloading the lists again.
    ///
    /// # Errors
    /// Same configuration and credential failures as startup.
    pub async fn prepare(config: &Config) -> io::Result<Arc<lumen_filter::Filter>> {
        config.validate().map_err(io::Error::other)?;
        lumen_resolver::Resolver::check(config).map_err(io::Error::other)?;
        let filter = Arc::new(
            lumen_filter::Filter::load(config.filtering.clone())
                .await
                .map_err(io::Error::other)?,
        );
        if !config.listen.dot.is_empty()
            || !config.listen.doh.is_empty()
            || !config.listen.doq.is_empty()
            || !config.listen.doh3.is_empty()
        {
            let _ = credentials(config)?;
        }
        lumen_web::BoundWeb::check(&config.web)?;
        Ok(filter)
    }

    /// Wait for a listener failure so background failures cannot go unnoticed.
    ///
    /// # Errors
    /// Returns any listener task error or unexpected listener exit.
    pub async fn wait(&mut self) -> io::Result<()> {
        match self.tasks.join_next().await {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(io::Error::other(error)),
            _ => Err(io::Error::other("DNS listener stopped unexpectedly")),
        }
    }

    /// Stop accepting traffic and cancel outstanding work.
    pub async fn shutdown(&mut self) {
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }

    /// The filter that is live now. It changes when lists or rules are replaced live.
    #[must_use]
    pub fn filter(&self) -> Arc<lumen_filter::Filter> {
        self.service.filter()
    }

    /// Put a new filter live without restarting any listener. Its counters continue from the
    /// old filter's, prefetch candidates chosen under the old rules are dropped, and
    /// downloads of lists it no longer uses are forgotten.
    ///
    /// # Panics
    /// Panics if an internal writer previously poisoned the filter lock.
    pub fn replace_filter(&self, filter: Arc<lumen_filter::Filter>) {
        let old = self.service.filter();
        filter.inherit_metrics(&old);
        filter.retain_downloads();
        *self.service.filter.write().expect("filter lock") = filter;
        self.service.resolver.clear_prefetch();
    }

    /// Refresh filtering rules and discard prefetch candidates selected under old rules.
    ///
    /// # Errors
    /// Returns a source or validation error while keeping the current rules live.
    pub async fn refresh_filter(&self) -> Result<(), String> {
        refresh_filter(&self.service).await
    }

    /// Roll filtering rules back and discard prefetch candidates selected under old rules.
    ///
    /// # Errors
    /// Returns an error when no valid previous generation is available.
    pub async fn rollback_filter(&self) -> Result<(), String> {
        rollback_filter(&self.service).await
    }

    /// Refresh due filtering lists and discard stale prefetch candidates when rules change.
    ///
    /// # Errors
    /// Returns a source or validation error while keeping the current rules live.
    pub async fn refresh_filter_due(&self) -> Result<bool, String> {
        refresh_filter_due(&self.service).await
    }
}

async fn refresh_filter(service: &Service) -> Result<(), String> {
    service.filter().refresh().await?;
    service.resolver.clear_prefetch();
    Ok(())
}

async fn rollback_filter(service: &Service) -> Result<(), String> {
    service.filter().rollback().await?;
    service.resolver.clear_prefetch();
    Ok(())
}

async fn refresh_filter_due(service: &Service) -> Result<bool, String> {
    let changed = service.filter().refresh_due().await?;
    if changed {
        service.resolver.clear_prefetch();
    }
    Ok(changed)
}

type Credentials = Arc<crate::certs::CertReloader>;

/// Load the certificate pair and its expiry. The reloader keeps serving it, and later pairs.
fn credentials(config: &Config) -> io::Result<(Credentials, i64)> {
    let cert = config
        .listen
        .certificate
        .as_ref()
        .ok_or_else(|| io::Error::other("missing certificate"))?;
    let key = config
        .listen
        .private_key
        .as_ref()
        .ok_or_else(|| io::Error::other("missing private key"))?;
    crate::certs::CertReloader::load(cert, key)
}

fn tls_config(keys: &Credentials, alpn: &[u8]) -> io::Result<ServerConfig> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(keys) as Arc<dyn rustls::server::ResolvesServerCert>);
    config.alpn_protocols = vec![alpn.to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
}

fn quic_endpoint(
    address: SocketAddr,
    keys: &Credentials,
    limits: &lumen_config::Limits,
    alpn: &[u8],
) -> io::Result<Endpoint> {
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config(keys, alpn)?).map_err(io::Error::other)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(8_u32.into())
        .max_concurrent_uni_streams(if alpn == b"h3" { 8_u32 } else { 0_u32 }.into())
        .stream_receive_window((u32::from(limits.max_message_bytes) + 2).into())
        .receive_window((8 * (u32::from(limits.max_message_bytes) + 2)).into())
        .send_window(8 * (u64::from(limits.max_message_bytes) + 2))
        .max_idle_timeout(Some(
            Duration::from_millis(u64::from(limits.io_timeout_ms))
                .try_into()
                .map_err(io::Error::other)?,
        ));
    server.transport = Arc::new(transport);
    Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server),
        raw_socket(address, false)?.into(),
        Arc::new(quinn::TokioRuntime),
    )
}

fn raw_socket(address: SocketAddr, tcp: bool) -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::for_address(address),
        if tcp { Type::STREAM } else { Type::DGRAM },
        Some(if tcp { Protocol::TCP } else { Protocol::UDP }),
    )?;
    #[cfg(unix)]
    if tcp {
        socket.set_reuse_address(true)?;
    }
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    if tcp {
        socket.listen(128)?;
    }
    Ok(socket)
}
fn udp_socket(address: SocketAddr) -> io::Result<UdpSocket> {
    UdpSocket::from_std(raw_socket(address, false)?.into())
}
fn tcp_listener(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::from_std(raw_socket(address, true)?.into())
}
fn io_timeout(service: &Service) -> Duration {
    Duration::from_millis(u64::from(service.config.limits.io_timeout_ms))
}

async fn serve_udp(socket: UdpSocket, service: Arc<Service>) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut tasks = JoinSet::new();
    // One extra byte detects truncated oversized datagrams instead of parsing a prefix.
    let mut buffer = vec![0; usize::from(service.config.limits.max_message_bytes) + 1];
    loop {
        let (size, peer) = socket.recv_from(&mut buffer).await?;
        while tasks.try_join_next().is_some() {}
        if tasks.len() >= service.config.limits.max_in_flight as usize {
            service
                .metrics
                .refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        let bytes = buffer[..size].to_vec();
        let socket = Arc::clone(&socket);
        let service = Arc::clone(&service);
        tasks.spawn(async move {
            if let Some(response) = service.answer(&bytes, peer, Transport::Udp).await {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

async fn serve_tcp(
    listener: TcpListener,
    protocol: Transport,
    tls: Option<ServerConfig>,
    service: Arc<Service>,
) -> io::Result<()> {
    let acceptor = tls.map(|config| TlsAcceptor::from(Arc::new(config)));
    let mut tasks = JoinSet::new();
    loop {
        let (stream, peer) = listener.accept().await?;
        while tasks.try_join_next().is_some() {}
        if !service.allowed(peer) {
            continue;
        }
        let Ok(permit) = Arc::clone(&service.connections).try_acquire_owned() else {
            continue;
        };
        let service = Arc::clone(&service);
        let acceptor = acceptor.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Some(acceptor) = acceptor {
                let Ok(Ok(stream)) = timeout(io_timeout(&service), acceptor.accept(stream)).await
                else {
                    return;
                };
                if protocol == Transport::Https {
                    let _ = serve_https(stream, peer, service).await;
                } else {
                    let _ = serve_dns_stream(stream, peer, protocol, &service).await;
                }
            } else {
                let _ = serve_dns_stream(stream, peer, protocol, &service).await;
            }
        });
    }
}

async fn serve_dns_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer: SocketAddr,
    protocol: Transport,
    service: &Service,
) -> io::Result<()> {
    loop {
        let packet = timeout(io_timeout(service), async {
            let length = usize::from(stream.read_u16().await?);
            if !(12..=usize::from(service.config.limits.max_message_bytes)).contains(&length) {
                return Err(io::Error::other("invalid DNS frame length"));
            }
            let mut packet = vec![0; length];
            stream.read_exact(&mut packet).await?;
            Ok(packet)
        })
        .await??;
        if let Some(response) = service.answer(&packet, peer, protocol).await {
            timeout(io_timeout(service), async {
                stream
                    .write_u16(u16::try_from(response.len()).map_err(io::Error::other)?)
                    .await?;
                stream.write_all(&response).await?;
                stream.flush().await
            })
            .await??;
        }
    }
}

async fn serve_https<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: SocketAddr,
    service: Arc<Service>,
) -> io::Result<()> {
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(8)
        .max_header_list_size(2 * u32::from(service.config.limits.max_message_bytes) + 4096)
        .max_send_buffer_size(usize::from(service.config.limits.max_message_bytes));
    let mut connection = timeout(io_timeout(&service), builder.handshake(stream))
        .await?
        .map_err(io::Error::other)?;
    let streams = Arc::new(Semaphore::new(8));
    let mut tasks = JoinSet::new();
    loop {
        let incoming = timeout(
            io_timeout(&service)
                + Duration::from_millis(u64::from(service.config.limits.query_timeout_ms)),
            connection.accept(),
        )
        .await?;
        let Some(incoming) = incoming else {
            return Ok(());
        };
        let (request, mut respond) = incoming.map_err(io::Error::other)?;
        while tasks.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&streams).try_acquire_owned() else {
            respond.send_reset(h2::Reason::REFUSED_STREAM);
            continue;
        };
        let service = Arc::clone(&service);
        tasks.spawn(async move {
            let _permit = permit;
            let deadline = io_timeout(&service)
                + Duration::from_millis(u64::from(service.config.limits.query_timeout_ms));
            let _ = timeout(deadline, async {
                let (status, body) = doh_request(request, peer, &service).await;
                let response = Response::builder()
                    .status(status)
                    .header("content-type", "application/dns-message")
                    .header("cache-control", "no-store")
                    .header("content-length", body.len())
                    .body(())
                    .map_err(io::Error::other)?;
                let mut stream = respond
                    .send_response(response, body.is_empty())
                    .map_err(io::Error::other)?;
                if !body.is_empty() {
                    stream
                        .send_data(Bytes::from(body), true)
                        .map_err(io::Error::other)?;
                }
                Ok::<_, io::Error>(())
            })
            .await;
        });
    }
}

async fn doh_request(
    request: Request<h2::RecvStream>,
    peer: SocketAddr,
    service: &Service,
) -> (StatusCode, Vec<u8>) {
    let maximum = usize::from(service.config.limits.max_message_bytes);
    if request.uri().path() != "/dns-query" {
        return (StatusCode::NOT_FOUND, vec![]);
    }
    let packet = match *request.method() {
        http::Method::GET => {
            if !request.body().is_end_stream() {
                return (StatusCode::BAD_REQUEST, vec![]);
            }
            match doh_get_packet(request.uri().query(), maximum) {
                Ok(packet) => packet,
                Err(status) => return (status, vec![]),
            }
        }
        http::Method::POST => {
            if request
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.eq_ignore_ascii_case("application/dns-message"))
            {
                return (StatusCode::UNSUPPORTED_MEDIA_TYPE, vec![]);
            }
            let mut body = request.into_body();
            let mut packet = Vec::new();
            let read = timeout(io_timeout(service), async {
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
                    if packet.len() + chunk.len() > maximum {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    packet.extend_from_slice(&chunk);
                    body.flow_control()
                        .release_capacity(chunk.len())
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                }
                Ok(())
            })
            .await;
            match read {
                Ok(Ok(())) => packet,
                Ok(Err(status)) => return (status, vec![]),
                Err(_) => return (StatusCode::REQUEST_TIMEOUT, vec![]),
            }
        }
        _ => return (StatusCode::METHOD_NOT_ALLOWED, vec![]),
    };
    doh_finish(service, peer, &packet, Transport::Https).await
}

/// Decode the `dns` parameter of a `DoH` GET request.
fn doh_get_packet(query: Option<&str>, maximum: usize) -> Result<Vec<u8>, StatusCode> {
    let encoded = query
        .and_then(|query| query.strip_prefix("dns="))
        .ok_or(StatusCode::BAD_REQUEST)?;
    if encoded.len() > maximum * 2 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StatusCode::BAD_REQUEST)
}

/// Shared `DoH` tail: bounds-check the DNS message and answer it.
async fn doh_finish(
    service: &Service,
    peer: SocketAddr,
    packet: &[u8],
    transport: Transport,
) -> (StatusCode, Vec<u8>) {
    if packet.len() > usize::from(service.config.limits.max_message_bytes) {
        return (StatusCode::PAYLOAD_TOO_LARGE, vec![]);
    }
    if packet.len() < 12 {
        return (StatusCode::BAD_REQUEST, vec![]);
    }
    service
        .answer(packet, peer, transport)
        .await
        .map_or((StatusCode::FORBIDDEN, vec![]), |answer| {
            (StatusCode::OK, answer)
        })
}

async fn serve_quic(endpoint: Endpoint, service: Arc<Service>) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        while tasks.try_join_next().is_some() {}
        if !service.allowed(incoming.remote_address()) {
            incoming.refuse();
            continue;
        }
        let Ok(permit) = Arc::clone(&service.connections).try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let service = Arc::clone(&service);
        tasks.spawn(async move {
            let _permit = permit;
            let Ok(Ok(connection)) = timeout(io_timeout(&service), incoming).await else {
                return;
            };
            // DoQ uses one query per bidirectional stream; IDs MUST be zero.
            while let Ok(Ok((mut send, mut recv))) =
                timeout(io_timeout(&service), connection.accept_bi()).await
            {
                let maximum = usize::from(service.config.limits.max_message_bytes);
                let Ok(Ok(data)) =
                    timeout(io_timeout(&service), recv.read_to_end(maximum + 2)).await
                else {
                    connection.close(2_u32.into(), b"invalid DNS stream");
                    return;
                };
                if data.len() < 14
                    || usize::from(u16::from_be_bytes([data[0], data[1]])) != data.len() - 2
                    || data[2..4] != [0, 0]
                {
                    connection.close(2_u32.into(), b"invalid DNS frame");
                    return;
                }
                if let Some(response) = service
                    .answer(&data[2..], connection.remote_address(), Transport::Quic)
                    .await
                {
                    let _ = timeout(io_timeout(&service), async {
                        send.write_all(
                            &u16::try_from(response.len())
                                .map_err(io::Error::other)?
                                .to_be_bytes(),
                        )
                        .await
                        .map_err(io::Error::other)?;
                        send.write_all(&response).await.map_err(io::Error::other)?;
                        send.finish().map_err(io::Error::other)
                    })
                    .await;
                }
            }
        });
    }
    Err(io::Error::other("QUIC listener stopped unexpectedly"))
}

async fn serve_h3(endpoint: Endpoint, service: Arc<Service>) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        while tasks.try_join_next().is_some() {}
        if !service.allowed(incoming.remote_address()) {
            incoming.refuse();
            continue;
        }
        let Ok(permit) = Arc::clone(&service.connections).try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let service = Arc::clone(&service);
        tasks.spawn(async move {
            let _permit = permit;
            let Ok(Ok(connection)) = timeout(io_timeout(&service), incoming).await else {
                return;
            };
            let peer = connection.remote_address();
            let _ = serve_h3_connection(connection, peer, service).await;
        });
    }
    Err(io::Error::other("HTTP/3 listener stopped unexpectedly"))
}

async fn serve_h3_connection(
    connection: quinn::Connection,
    peer: SocketAddr,
    service: Arc<Service>,
) -> io::Result<()> {
    let mut builder = h3::server::builder();
    builder.max_field_section_size(2 * u64::from(service.config.limits.max_message_bytes) + 4096);
    let mut h3 = timeout(
        io_timeout(&service),
        builder.build(h3_quinn::Connection::new(connection)),
    )
    .await?
    .map_err(io::Error::other)?;
    let streams = Arc::new(Semaphore::new(8));
    let mut tasks = JoinSet::new();
    loop {
        let accepted = timeout(
            io_timeout(&service)
                + Duration::from_millis(u64::from(service.config.limits.query_timeout_ms)),
            h3.accept(),
        )
        .await?
        .map_err(io::Error::other)?;
        let Some(resolver) = accepted else {
            return Ok(());
        };
        while tasks.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&streams).try_acquire_owned() else {
            continue;
        };
        let service = Arc::clone(&service);
        tasks.spawn(async move {
            let _permit = permit;
            let deadline = io_timeout(&service)
                + Duration::from_millis(u64::from(service.config.limits.query_timeout_ms));
            let _ = timeout(deadline, async {
                let (request, mut stream) =
                    resolver.resolve_request().await.map_err(io::Error::other)?;
                let (status, body) = h3_request(&request, &mut stream, peer, &service).await;
                let response = Response::builder()
                    .status(status)
                    .header("content-type", "application/dns-message")
                    .header("cache-control", "no-store")
                    .header("content-length", body.len())
                    .body(())
                    .map_err(io::Error::other)?;
                stream
                    .send_response(response)
                    .await
                    .map_err(io::Error::other)?;
                if !body.is_empty() {
                    stream
                        .send_data(Bytes::from(body))
                        .await
                        .map_err(io::Error::other)?;
                }
                stream.finish().await.map_err(io::Error::other)
            })
            .await;
        });
    }
}

async fn h3_request<S: h3::quic::BidiStream<Bytes>>(
    request: &Request<()>,
    stream: &mut h3::server::RequestStream<S, Bytes>,
    peer: SocketAddr,
    service: &Service,
) -> (StatusCode, Vec<u8>) {
    use bytes::Buf;
    let maximum = usize::from(service.config.limits.max_message_bytes);
    if request.uri().path() != "/dns-query" {
        return (StatusCode::NOT_FOUND, vec![]);
    }
    let packet = match *request.method() {
        http::Method::GET => match doh_get_packet(request.uri().query(), maximum) {
            Ok(packet) => packet,
            Err(status) => return (status, vec![]),
        },
        http::Method::POST => {
            if request
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_none_or(|value| !value.eq_ignore_ascii_case("application/dns-message"))
            {
                return (StatusCode::UNSUPPORTED_MEDIA_TYPE, vec![]);
            }
            let mut packet = Vec::new();
            let read = timeout(io_timeout(service), async {
                while let Some(mut chunk) = stream
                    .recv_data()
                    .await
                    .map_err(|_| StatusCode::BAD_REQUEST)?
                {
                    if packet.len() + chunk.remaining() > maximum {
                        return Err(StatusCode::PAYLOAD_TOO_LARGE);
                    }
                    packet.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                }
                Ok(())
            })
            .await;
            match read {
                Ok(Ok(())) => packet,
                Ok(Err(status)) => return (status, vec![]),
                Err(_) => return (StatusCode::REQUEST_TIMEOUT, vec![]),
            }
        }
        _ => return (StatusCode::METHOD_NOT_ALLOWED, vec![]),
    };
    doh_finish(service, peer, &packet, Transport::H3).await
}

/// Answer one `DNSCrypt` packet: a plain certificate query, or an encrypted DNS query.
async fn dnscrypt_answer(
    dnscrypt: &crate::dnscrypt::DnsCrypt,
    service: &Service,
    packet: &[u8],
    peer: SocketAddr,
    udp: bool,
) -> Option<Vec<u8>> {
    match dnscrypt.open(packet, udp)? {
        crate::dnscrypt::Packet::Certificate(response) => Some(response),
        crate::dnscrypt::Packet::Query(query) => {
            let protocol = if udp { Transport::Udp } else { Transport::Tcp };
            let response = service.answer(&query.dns, peer, protocol).await?;
            crate::dnscrypt::DnsCrypt::seal(&query, &response, udp)
        }
    }
}

async fn serve_dnscrypt_udp(
    socket: UdpSocket,
    dnscrypt: Arc<crate::dnscrypt::DnsCrypt>,
    service: Arc<Service>,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let mut tasks = JoinSet::new();
    let size = usize::from(service.config.limits.max_message_bytes) + 512;
    let mut buffer = vec![0; size + 1];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        while tasks.try_join_next().is_some() {}
        if length > size
            || tasks.len() >= service.config.limits.max_in_flight as usize
            || !service.allowed(peer)
        {
            continue;
        }
        let bytes = buffer[..length].to_vec();
        let (socket, dnscrypt, service) = (
            Arc::clone(&socket),
            Arc::clone(&dnscrypt),
            Arc::clone(&service),
        );
        tasks.spawn(async move {
            if let Some(response) = dnscrypt_answer(&dnscrypt, &service, &bytes, peer, true).await {
                let _ = socket.send_to(&response, peer).await;
            }
        });
    }
}

async fn serve_dnscrypt_tcp(
    listener: TcpListener,
    dnscrypt: Arc<crate::dnscrypt::DnsCrypt>,
    service: Arc<Service>,
) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        let (mut stream, peer) = listener.accept().await?;
        while tasks.try_join_next().is_some() {}
        if !service.allowed(peer) {
            continue;
        }
        let Ok(permit) = Arc::clone(&service.connections).try_acquire_owned() else {
            continue;
        };
        let (dnscrypt, service) = (Arc::clone(&dnscrypt), Arc::clone(&service));
        tasks.spawn(async move {
            let _permit = permit;
            let maximum = usize::from(service.config.limits.max_message_bytes) + 512;
            loop {
                let Ok(Ok(packet)) = timeout(io_timeout(&service), async {
                    let length = usize::from(stream.read_u16().await?);
                    if !(12..=maximum).contains(&length) {
                        return Err(io::Error::other("invalid DNSCrypt frame length"));
                    }
                    let mut packet = vec![0; length];
                    stream.read_exact(&mut packet).await?;
                    Ok(packet)
                })
                .await
                else {
                    return;
                };
                let Some(response) =
                    dnscrypt_answer(&dnscrypt, &service, &packet, peer, false).await
                else {
                    return;
                };
                let Ok(length) = u16::try_from(response.len()) else {
                    return;
                };
                let sent = timeout(io_timeout(&service), async {
                    stream.write_u16(length).await?;
                    stream.write_all(&response).await?;
                    stream.flush().await
                })
                .await;
                if !matches!(sent, Ok(Ok(()))) {
                    return;
                }
            }
        });
    }
}

async fn serve_metrics(listener: TcpListener, service: Arc<Service>) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        let (mut stream, peer) = listener.accept().await?;
        while tasks.try_join_next().is_some() {}
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = Arc::clone(&service.connections).try_acquire_owned() else {
            continue;
        };
        let service = Arc::clone(&service);
        tasks.spawn(async move {
            let _permit = permit;
            let _ = timeout(io_timeout(&service), async {
                let mut input = Vec::new(); let mut byte = [0];
                while input.len() < 4096 && !input.ends_with(b"\r\n\r\n") { stream.read_exact(&mut byte).await?; input.push(byte[0]); }
                let (status, body) = if !input.ends_with(b"\r\n\r\n") { ("431 Request Header Fields Too Large", String::new()) }
                    else if input.starts_with(b"GET /metrics HTTP/1.") { ("200 OK", service.metrics.render() + &service.resolver.metrics().render() + &service.filter().metrics.render()) }
                    else if input.starts_with(b"GET /healthz HTTP/1.") { ("200 OK", "ok\n".into()) }
                    else { ("404 Not Found", String::new()) };
                let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await
            }).await;
        });
    }
}

/// Poll the certificate files, update the counters, and log without naming any path or key.
fn apply_reload(reloader: &crate::certs::CertReloader, metrics: &Metrics) -> crate::certs::Reload {
    let outcome = reloader.poll();
    match outcome {
        crate::certs::Reload::Replaced(not_after) => {
            metrics.cert_not_after.store(not_after, Ordering::Relaxed);
            metrics.cert_reloads.fetch_add(1, Ordering::Relaxed);
            eprintln!("tls certificate reloaded");
        }
        crate::certs::Reload::Rejected => {
            metrics.cert_reload_failures.fetch_add(1, Ordering::Relaxed);
            eprintln!("tls certificate reload failed; keeping the previous certificate");
        }
        crate::certs::Reload::Unchanged => {}
    }
    outcome
}

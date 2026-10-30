// SPDX-License-Identifier: Apache-2.0
//! Bounded async listeners. All transports share one query and connection budget.

use super::{Metrics, Service, Transport};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use lumen_config::{Config, read_bounded};
use quinn::{Endpoint, crypto::rustls::QuicServerConfig};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use socket2::{Domain, Protocol, Socket, Type};
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
    pub endpoints: Vec<(Transport, SocketAddr)>,
    pub metrics: Arc<Metrics>,
    pub filter: Arc<lumen_filter::Filter>,
}

impl RunningServer {
    /// Validate all configuration, credentials, and binds before serving requests.
    ///
    /// # Errors
    /// Fails startup if any enabled transport cannot be configured or bound.
    #[allow(clippy::too_many_lines)] // Bind all resources before starting workers.
    pub async fn start(config: Config) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        config.validate().map_err(io::Error::other)?;
        let resolver = lumen_resolver::Resolver::new(&config).map_err(io::Error::other)?;
        let tls = if config.listen.dot.is_empty()
            && config.listen.doh.is_empty()
            && config.listen.doq.is_empty()
        {
            None
        } else {
            Some(credentials(&config)?)
        };
        let filter = Arc::new(
            lumen_filter::Filter::load(config.filtering.clone())
                .await
                .map_err(io::Error::other)?,
        );
        #[cfg(unix)]
        let mut refresh_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
        #[cfg(unix)]
        let mut rollback_signal =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())?;
        let metrics = Arc::new(Metrics::default());
        let service = Arc::new(Service {
            queries: Arc::new(Semaphore::new(config.limits.max_in_flight as usize)),
            connections: Arc::new(Semaphore::new(config.limits.max_connections as usize)),
            clients: std::sync::Mutex::default(),
            resolver,
            filter: Arc::clone(&filter),
            config: Arc::new(config),
            metrics: Arc::clone(&metrics),
        });
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
            )?;
            endpoints.push((Transport::Quic, endpoint.local_addr()?));
            quic.push(endpoint);
        }
        let metrics_listener = config.metrics.map(tcp_listener).transpose()?;
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
        #[cfg(unix)]
        {
            let control = Arc::clone(&filter);
            tasks.spawn(async move {
                loop {
                    let result = tokio::select! {
                        _ = refresh_signal.recv() => control.refresh().await,
                        _ = rollback_signal.recv() => control.rollback().await,
                    };
                    if result.is_err() {
                        eprintln!("filter control failed; keeping live rules");
                    } else {
                        eprintln!("filter control applied");
                    }
                }
            });
        }
        let refreshing = Arc::clone(&filter);
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if refreshing.refresh_due().await.is_err() {
                    eprintln!("filter refresh failed; keeping previous rules");
                }
            }
        });
        if let Some(listener) = metrics_listener {
            tasks.spawn(serve_metrics(listener, service));
        }
        Ok(Self {
            tasks,
            endpoints,
            metrics,
            filter,
        })
    }

    /// Check startup credentials without creating any listeners.
    ///
    /// # Errors
    /// Same configuration and credential failures as startup.
    pub async fn check(config: &Config) -> io::Result<()> {
        config.validate().map_err(io::Error::other)?;
        let _ = lumen_resolver::Resolver::new(config).map_err(io::Error::other)?;
        let _ = lumen_filter::Filter::load(config.filtering.clone())
            .await
            .map_err(io::Error::other)?;
        if !config.listen.dot.is_empty()
            || !config.listen.doh.is_empty()
            || !config.listen.doq.is_empty()
        {
            let _ = credentials(config)?;
        }
        Ok(())
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
}

type Credentials = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

fn credentials(config: &Config) -> io::Result<Credentials> {
    let cert = read_bounded(
        config
            .listen
            .certificate
            .as_ref()
            .ok_or_else(|| io::Error::other("missing certificate"))?,
        1_048_576,
    )
    .map_err(io::Error::other)?;
    let key = read_bounded(
        config
            .listen
            .private_key
            .as_ref()
            .ok_or_else(|| io::Error::other("missing private key"))?,
        65536,
    )
    .map_err(io::Error::other)?;
    let cert = CertificateDer::pem_slice_iter(&cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::other("invalid PEM certificate"))?;
    let key = PrivateKeyDer::from_pem_slice(&key)
        .map_err(|_| io::Error::other("invalid PEM private key"))?;
    let keys = (cert, key);
    let _ = tls_config(&keys, b"dot")?;
    Ok(keys)
}

fn tls_config(keys: &Credentials, alpn: &[u8]) -> io::Result<ServerConfig> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(keys.0.clone(), keys.1.clone_key())
            .map_err(|_| io::Error::other("certificate and private key do not match"))?;
    config.alpn_protocols = vec![alpn.to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
}

fn quic_endpoint(
    address: SocketAddr,
    keys: &Credentials,
    limits: &lumen_config::Limits,
) -> io::Result<Endpoint> {
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config(keys, b"doq")?).map_err(io::Error::other)?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(8_u32.into())
        .max_concurrent_uni_streams(0_u32.into())
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
            let Some(encoded) = request
                .uri()
                .query()
                .and_then(|query| query.strip_prefix("dns="))
            else {
                return (StatusCode::BAD_REQUEST, vec![]);
            };
            if encoded.len() > maximum * 2 {
                return (StatusCode::PAYLOAD_TOO_LARGE, vec![]);
            }
            let Ok(packet) = URL_SAFE_NO_PAD.decode(encoded) else {
                return (StatusCode::BAD_REQUEST, vec![]);
            };
            packet
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
    if packet.len() > maximum {
        return (StatusCode::PAYLOAD_TOO_LARGE, vec![]);
    }
    if packet.len() < 12 {
        return (StatusCode::BAD_REQUEST, vec![]);
    }
    service
        .answer(&packet, peer, Transport::Https)
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
                    else if input.starts_with(b"GET /metrics HTTP/1.") { ("200 OK", service.metrics.render() + &service.filter.metrics.render()) }
                    else if input.starts_with(b"GET /healthz HTTP/1.") { ("200 OK", "ok\n".into()) }
                    else { ("404 Not Found", String::new()) };
                let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(response.as_bytes()).await
            }).await;
        });
    }
}

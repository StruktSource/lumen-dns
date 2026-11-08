// SPDX-License-Identifier: Apache-2.0
//! Offline protocol, DNSSEC, cache, and resource-limit regression tests.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_proto::{
    op::{Edns, Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, SOA},
    },
};
use lumen_config::{Config, ForwardStrategy, Mode, Upstream, UpstreamProtocol};
use lumen_core::{ConsoleOptions, RunningServer};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;

/// Picks a port that is free for both TCP and UDP and was not handed out earlier in this
/// process. The servers under test take fixed addresses, so the probe sockets must be dropped
/// before use; checking both protocols and remembering past picks narrows that race, and
/// `encrypted_forwarding_checks_upstream_certificates` additionally retries on `AddrInUse`.
fn address(ip: &str) -> SocketAddr {
    static HANDED_OUT: std::sync::Mutex<Vec<(String, u16)>> = std::sync::Mutex::new(Vec::new());
    loop {
        let listener = std::net::TcpListener::bind(format!("{ip}:0")).unwrap();
        let address = listener.local_addr().unwrap();
        if std::net::UdpSocket::bind(address).is_err() {
            continue;
        }
        let mut handed_out = HANDED_OUT.lock().unwrap();
        if handed_out
            .iter()
            .any(|(i, port)| i == ip && *port == address.port())
        {
            continue;
        }
        handed_out.push((ip.to_string(), address.port()));
        return address;
    }
}

fn query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.id = 1234;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    query.to_vec().unwrap()
}

fn config(upstream: SocketAddr, bind: SocketAddr) -> Config {
    let mut config = Config {
        schema_version: 1,
        ..Config::default()
    };
    config.listen.udp = vec![bind];
    config.listen.tcp = vec![bind];
    config.resolver.mode = Mode::Forward;
    config.resolver.dnssec = false;
    config.resolver.upstreams = vec![Upstream {
        address: upstream,
        protocol: UpstreamProtocol::Udp,
        server_name: None,
        doh_path: None,
    }];
    config
}

#[tokio::test]
async fn release_default_is_private_and_starts() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut config = Config::load(&root.join("config/lumen.toml")).unwrap();
    assert!(config.metrics.is_none());
    assert_eq!(config.resolver.mode, Mode::Recursive);
    assert!(config.resolver.dnssec);
    assert!(config.resolver.upstreams.is_empty());
    assert!(!config.resolver.fallback.enabled);
    assert!(config.filtering.lists.is_empty());
    assert!(config.filtering.rules.allow.is_empty());
    assert!(config.filtering.rules.block.is_empty());
    let bind = address("127.0.0.1");
    let web = address("127.0.0.1");
    config.listen.udp = vec![bind];
    config.listen.tcp = vec![bind];
    config.web.http = vec![web];
    let mut server = RunningServer::start(config).await.unwrap();
    assert_eq!(server.endpoints.len(), 2);
    assert_eq!(server.web_endpoints, [(false, web)]);
    server.shutdown().await;
}

async fn udp(address: SocketAddr, packet: &[u8]) -> Message {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .await
    .unwrap();
    socket.send_to(packet, address).await.unwrap();
    let mut buffer = vec![0; 65535];
    let size = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&buffer[..size]).unwrap()
}

async fn framed<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, packet: &[u8]) -> Message {
    stream
        .write_u16(u16::try_from(packet.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(packet).await.unwrap();
    stream.flush().await.unwrap();
    timeout(Duration::from_secs(3), async {
        let length = usize::from(stream.read_u16().await.unwrap());
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        Message::from_vec(&bytes).unwrap()
    })
    .await
    .unwrap()
}

struct Fixture {
    address: SocketAddr,
    queries: Arc<AtomicUsize>,
    tasks: JoinSet<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

async fn fixture() -> Fixture {
    // The UDP port with the same number as a fresh TCP port can already be taken by another
    // test's socket, so retry with a new TCP port until both protocols bind.
    let (tcp, udp, address) = loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        match UdpSocket::bind(address).await {
            Ok(udp) => break (tcp, udp, address),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) => {}
            Err(error) => panic!("fixture UDP bind failed: {error}"),
        }
    };
    let queries = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    let count = Arc::clone(&queries);
    tasks.spawn(async move {
        let mut buffer = vec![0; 65535];
        loop {
            let (size, peer) = udp.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..size]).unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            if request.queries[0]
                .name()
                .to_ascii()
                .to_lowercase()
                .starts_with("slow.")
            {
                continue;
            }
            let limit = request.max_payload();
            let response = mock_response(request, false);
            let mut bytes = vec![];
            let mut encoder = BinEncoder::new(&mut bytes);
            encoder.set_max_size(limit);
            response.emit(&mut encoder).unwrap();
            udp.send_to(&bytes, peer).await.unwrap();
        }
    });
    let count = Arc::clone(&queries);
    tasks.spawn(async move {
        let mut clients = JoinSet::new();
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let count = Arc::clone(&count);
            clients.spawn(async move {
                loop {
                    let Ok(size) = stream.read_u16().await else {
                        return;
                    };
                    let mut bytes = vec![0; usize::from(size)];
                    if stream.read_exact(&mut bytes).await.is_err() {
                        return;
                    }
                    count.fetch_add(1, Ordering::Relaxed);
                    let request = Message::from_vec(&bytes).unwrap();
                    if request.queries[0]
                        .name()
                        .to_ascii()
                        .to_lowercase()
                        .starts_with("slow.")
                    {
                        // Never answer "slow" names, so a TCP retry cannot rescue them.
                        continue;
                    }
                    let response = mock_response(request, true).to_vec().unwrap();
                    if stream
                        .write_u16(u16::try_from(response.len()).unwrap())
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if stream.write_all(&response).await.is_err() {
                        return;
                    }
                }
            });
            while clients.try_join_next().is_some() {}
        }
    });
    Fixture {
        address,
        queries,
        tasks,
    }
}

fn mock_response(request: Message, tcp: bool) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.queries = request.queries;
    response.edns = request.edns;
    let q = &response.queries[0];
    let name = q.name().clone();
    let text = name.to_ascii().to_lowercase();
    if text.starts_with("tcp.") && !tcp {
        response.metadata.truncation = true;
        return response;
    }
    if text.starts_with("missing.") || text.starts_with("empty.") {
        if text.starts_with("missing.") {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        response.add_authority(Record::from_rdata(
            Name::from_ascii("example.").unwrap(),
            1,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.").unwrap(),
                Name::from_ascii("hostmaster.example.").unwrap(),
                1,
                60,
                60,
                60,
                1,
            )),
        ));
    } else if q.query_type() == RecordType::AAAA {
        response.add_answer(Record::from_rdata(
            name,
            1,
            RData::AAAA(AAAA("2001:db8::42".parse().unwrap())),
        ));
    } else {
        for index in 0..if text.starts_with("large.") { 80 } else { 1 } {
            response.add_answer(Record::from_rdata(
                name.clone(),
                1,
                RData::A(A::new(192, 0, 2, 42 + index)),
            ));
        }
    }
    response
}

#[tokio::test]
async fn udp_tcp_ipv4_ipv6_and_tcp_fallback() {
    let fixture = fixture().await;
    for ip in ["127.0.0.1", "[::1]"] {
        let bind = address(ip);
        let mut server = RunningServer::start(config(fixture.address, bind))
            .await
            .unwrap();
        for kind in [RecordType::A, RecordType::AAAA] {
            let packet = query("ok.example.", kind);
            let reply = udp(bind, &packet).await;
            assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
            assert_eq!(reply.metadata.id, 1234);
            assert!(!reply.answers.is_empty());
            let mut stream = TcpStream::connect(bind).await.unwrap();
            for _ in 0..2 {
                assert!(!framed(&mut stream, &packet).await.answers.is_empty());
            }
        }
        assert!(
            !udp(bind, &query("tcp.example.", RecordType::A))
                .await
                .answers
                .is_empty()
        );
        server.shutdown().await;
    }
}

#[tokio::test]
async fn positive_negative_nodata_cache_and_expiry() {
    let fixture = fixture().await;
    let bind = address("127.0.0.1");
    let mut server = RunningServer::start(config(fixture.address, bind))
        .await
        .unwrap();
    for (name, code) in [
        ("ok.example.", ResponseCode::NoError),
        ("missing.example.", ResponseCode::NXDomain),
        ("empty.example.", ResponseCode::NoError),
    ] {
        let packet = query(name, RecordType::A);
        assert_eq!(udp(bind, &packet).await.metadata.response_code, code);
        let before = fixture.queries.load(Ordering::Relaxed);
        assert_eq!(udp(bind, &packet).await.metadata.response_code, code);
        assert_eq!(
            fixture.queries.load(Ordering::Relaxed),
            before,
            "repeat query should use cache"
        );
    }
    let before = fixture.queries.load(Ordering::Relaxed);
    sleep(Duration::from_millis(1100)).await;
    let _ = udp(bind, &query("ok.example.", RecordType::A)).await;
    let _ = udp(bind, &query("missing.example.", RecordType::A)).await;
    assert!(fixture.queries.load(Ordering::Relaxed) >= before + 2);
    server.shutdown().await;
}

fn certificates() -> (tempfile::TempDir, CertificateDer<'static>) {
    let directory = tempfile::tempdir().unwrap();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(directory.path().join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(
        directory.path().join("key.pem"),
        signing_key.serialize_pem(),
    )
    .unwrap();
    (directory, cert.der().clone())
}

fn client_tls(cert: CertificateDer<'static>, alpn: &[u8]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls
}

async fn doh(
    address: SocketAddr,
    tls: ClientConfig,
    packet: &[u8],
    method: &str,
    path: &str,
    media: &str,
) -> (http::StatusCode, Vec<u8>) {
    let stream = TcpStream::connect(address).await.unwrap();
    let stream = TlsConnector::from(Arc::new(tls))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let (mut client, connection) = h2::client::handshake(stream).await.unwrap();
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let req = http::Request::builder()
        .method(method)
        .uri(format!("https://localhost{path}"))
        .header("content-type", media)
        .body(())
        .unwrap();
    let (response, mut send) = client.send_request(req, packet.is_empty()).unwrap();
    if !packet.is_empty() {
        send.send_data(bytes::Bytes::copy_from_slice(packet), true)
            .unwrap();
    }
    let response = timeout(Duration::from_secs(3), response)
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let mut body = response.into_body();
    let mut bytes = vec![];
    while let Some(chunk) = timeout(Duration::from_secs(3), body.data()).await.unwrap() {
        let chunk = chunk.unwrap();
        bytes.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len()).unwrap();
    }
    driver.abort();
    (status, bytes)
}

#[tokio::test]
async fn encrypted_listeners_ipv4_ipv6_and_doh_contract() {
    let fixture = fixture().await;
    let (directory, cert) = certificates();
    for ip in ["127.0.0.1", "[::1]"] {
        let mut cfg = config(fixture.address, address(ip));
        cfg.listen.udp.clear();
        cfg.listen.tcp.clear();
        let dot = address(ip);
        let doh_addr = address(ip);
        let doq = address(ip);
        cfg.listen.dot = vec![dot];
        cfg.listen.doh = vec![doh_addr];
        cfg.listen.doq = vec![doq];
        cfg.listen.certificate = Some(directory.path().join("cert.pem"));
        cfg.listen.private_key = Some(directory.path().join("key.pem"));
        cfg.filtering.rules.block = vec!["blocked.example".into()];
        let mut server = RunningServer::start(cfg).await.unwrap();
        let packet = query("ok.example.", RecordType::A);
        let stream = TcpStream::connect(dot).await.unwrap();
        let mut stream = TlsConnector::from(Arc::new(client_tls(cert.clone(), b"dot")))
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        assert!(!framed(&mut stream, &packet).await.answers.is_empty());
        let blocked = query("blocked.example.", RecordType::A);
        assert_eq!(
            framed(&mut stream, &blocked).await.metadata.response_code,
            ResponseCode::NXDomain
        );
        let (_, denied) = doh(
            doh_addr,
            client_tls(cert.clone(), b"h2"),
            &blocked,
            "POST",
            "/dns-query",
            "application/dns-message",
        )
        .await;
        assert_eq!(
            Message::from_vec(&denied).unwrap().metadata.response_code,
            ResponseCode::NXDomain
        );
        let (status, body) = doh(
            doh_addr,
            client_tls(cert.clone(), b"h2"),
            &packet,
            "POST",
            "/dns-query",
            "application/dns-message",
        )
        .await;
        assert_eq!(status, http::StatusCode::OK);
        assert!(!Message::from_vec(&body).unwrap().answers.is_empty());
        let path = format!("/dns-query?dns={}", URL_SAFE_NO_PAD.encode(&packet));
        assert_eq!(
            doh(
                doh_addr,
                client_tls(cert.clone(), b"h2"),
                &[],
                "GET",
                &path,
                ""
            )
            .await
            .0,
            http::StatusCode::OK
        );
        assert_eq!(
            doh(
                doh_addr,
                client_tls(cert.clone(), b"h2"),
                &packet,
                "POST",
                "/wrong",
                "application/dns-message"
            )
            .await
            .0,
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            doh(
                doh_addr,
                client_tls(cert.clone(), b"h2"),
                &packet,
                "POST",
                "/dns-query",
                "text/plain"
            )
            .await
            .0,
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        let socket = std::net::UdpSocket::bind(if doq.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        })
        .unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(cert.clone(), b"doq"))
                .unwrap(),
        )));
        let connection = endpoint.connect(doq, "localhost").unwrap().await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let mut packet = packet;
        packet[..2].fill(0);
        send.write_all(&u16::try_from(packet.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        send.write_all(&packet).await.unwrap();
        send.finish().unwrap();
        let data = timeout(Duration::from_secs(3), recv.read_to_end(65537))
            .await
            .unwrap()
            .unwrap();
        assert!(!Message::from_vec(&data[2..]).unwrap().answers.is_empty());
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let mut blocked = blocked;
        blocked[..2].fill(0);
        send.write_all(&u16::try_from(blocked.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        send.write_all(&blocked).await.unwrap();
        send.finish().unwrap();
        let denied = timeout(Duration::from_secs(3), recv.read_to_end(65537))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Message::from_vec(&denied[2..])
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
        assert_eq!(server.filter().metrics.blocked.load(Ordering::Relaxed), 3);
        connection.close(0_u32.into(), b"done");
        endpoint.close(0_u32.into(), b"done");
        server.shutdown().await;
    }
}

#[tokio::test]
async fn malformed_udp_truncation_metrics_and_deadlines() {
    let fixture = fixture().await;
    let bind = address("127.0.0.1");
    let mut cfg = config(fixture.address, bind);
    cfg.limits.query_timeout_ms = 100;
    let metrics = address("127.0.0.1");
    cfg.metrics = Some(metrics);
    let mut server = RunningServer::start(cfg).await.unwrap();
    let mut malformed = query("ok.example.", RecordType::A);
    malformed.push(42);
    assert_eq!(
        udp(bind, &malformed).await.metadata.response_code,
        ResponseCode::FormErr
    );
    let reply = udp(bind, &query("large.example.", RecordType::A)).await;
    assert!(
        reply.metadata.truncation,
        "unexpected large response: {reply:?}"
    );
    assert_eq!(
        udp(bind, &query("slow.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    let mut stream = TcpStream::connect(metrics).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut text = String::new();
    stream.read_to_string(&mut text).await.unwrap();
    assert!(text.contains("lumen_dns_timeouts_total 1"));
    assert!(text.contains("lumen_dns_responses_total 3"));
    assert!(!text.contains("example"));
    assert!(text.contains("lumen_dns_active_queries 0"));
    server.shutdown().await;
}

#[tokio::test]
async fn connection_rate_concurrency_limits_and_shutdown() {
    let fixture = fixture().await;
    let bind = address("127.0.0.1");
    let mut cfg = config(fixture.address, bind);
    cfg.limits.max_connections = 1;
    cfg.limits.max_in_flight = 1;
    cfg.limits.query_timeout_ms = 250;
    cfg.limits.io_timeout_ms = 100;
    cfg.limits.queries_per_second = 3;
    let mut server = RunningServer::start(cfg).await.unwrap();
    let first = TcpStream::connect(bind).await.unwrap();
    sleep(Duration::from_millis(15)).await;
    let mut second = TcpStream::connect(bind).await.unwrap();
    let mut byte = [0];
    assert!(matches!(
        timeout(Duration::from_millis(200), second.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    ));
    drop(first);
    sleep(Duration::from_millis(120)).await;
    let slow = tokio::spawn(async move { udp(bind, &query("slow.example.", RecordType::A)).await });
    sleep(Duration::from_millis(25)).await;
    assert_eq!(
        framed(
            &mut TcpStream::connect(bind).await.unwrap(),
            &query("ok.example.", RecordType::A)
        )
        .await
        .metadata
        .response_code,
        ResponseCode::Refused
    );
    assert_eq!(
        slow.await.unwrap().metadata.response_code,
        ResponseCode::ServFail
    );
    let _ = udp(bind, &query("ok.example.", RecordType::A)).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&query("ok.example.", RecordType::A), bind)
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(50), socket.recv(&mut byte))
            .await
            .is_err()
    );
    server.shutdown().await;
    let mut restarted = RunningServer::start(config(fixture.address, bind))
        .await
        .unwrap();
    restarted.shutdown().await;
}

#[tokio::test]
async fn dnssec_valid_bogus_wrong_anchor_and_signed_denial() {
    use hickory_server::{
        dnssec::NxProofKind,
        proto::{
            dnssec::{Algorithm, DnssecSigner, SigningKey, crypto::EcdsaSigningKey, rdata::DNSKEY},
            serialize::txt::Parser,
        },
        server::Server,
        store::in_memory::InMemoryZoneHandler,
        zone_handler::{AxfrPolicy, Catalog, ZoneType},
    };
    let roots = Name::root();
    let zone = ". 60 IN SOA ns. hostmaster. 1 60 60 60 60\n. 60 IN NS ns.\nns. 60 IN A 127.0.0.1\nvalid.example. 60 IN A 192.0.2.1\nbogus.example. 60 IN A 192.0.2.2\n";
    let (_, records) = Parser::new(zone, None, Some(roots.clone()))
        .parse()
        .unwrap();
    let mut zone: InMemoryZoneHandler = InMemoryZoneHandler::new(
        roots.clone(),
        records,
        ZoneType::Primary,
        AxfrPolicy::Deny,
        Some(NxProofKind::Nsec),
    )
    .unwrap();
    let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
    let key = EcdsaSigningKey::from_pkcs8(&der, Algorithm::ECDSAP256SHA256).unwrap();
    let dnskey = DNSKEY::new(true, true, false, key.to_public_key().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let anchor = directory.path().join("root.key");
    std::fs::write(&anchor, format!(". 60 IN DNSKEY {dnskey}\n")).unwrap();
    zone.add_zone_signing_key_mut(DnssecSigner::new(
        dnskey,
        Box::new(key),
        roots.clone(),
        Duration::from_secs(3600),
    ))
    .unwrap();
    zone.secure_zone_mut().unwrap();
    zone.upsert_mut(
        Record::from_rdata(
            Name::from_ascii("bogus.example.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 99)),
        ),
        1,
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = socket.local_addr().unwrap();
    let mut catalog = Catalog::new();
    catalog.upsert(roots.into(), vec![Arc::new(zone)]);
    let mut authority = Server::new(catalog);
    authority.register_socket(socket);
    let authority = tokio::spawn(async move {
        authority.block_until_done().await.unwrap();
    });
    let bind = address("127.0.0.1");
    let mut cfg = config(upstream, bind);
    cfg.resolver.dnssec = true;
    cfg.resolver.trust_anchor = Some(anchor.clone());
    let mut server = RunningServer::start(cfg.clone()).await.unwrap();
    let mut packet = Message::from_vec(&query("valid.example.", RecordType::A)).unwrap();
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true).set_max_payload(1232);
    packet.set_edns(edns);
    let valid = udp(bind, &packet.to_vec().unwrap()).await;
    assert_eq!(valid.metadata.response_code, ResponseCode::NoError);
    assert!(valid.metadata.authentic_data);
    assert!(!valid.answers.is_empty());
    assert_eq!(
        udp(bind, &query("bogus.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert_eq!(
        udp(bind, &query("absent.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    server.shutdown().await;
    let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
    let key = EcdsaSigningKey::from_pkcs8(&der, Algorithm::ECDSAP256SHA256).unwrap();
    let wrong = DNSKEY::new(true, true, false, key.to_public_key().unwrap());
    std::fs::write(&anchor, format!(". 60 IN DNSKEY {wrong}\n")).unwrap();
    let mut server = RunningServer::start(cfg).await.unwrap();
    assert_eq!(
        udp(bind, &query("valid.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    server.shutdown().await;
    authority.abort();
}

#[tokio::test]
async fn encrypted_forwarding_checks_upstream_certificates() {
    let fixture = fixture().await;
    let (directory, _) = certificates();
    // Free ports are probed by binding and dropping, so another test can win the race.
    // Retry with fresh ports instead of failing on that collision.
    let mut attempt = 0;
    let (mut upstream, tls, https, quic) = loop {
        let mut upstream_cfg = config(fixture.address, address("127.0.0.1"));
        upstream_cfg.listen.udp.clear();
        upstream_cfg.listen.tcp.clear();
        let tls = address("127.0.0.1");
        let https = address("127.0.0.1");
        let quic = address("127.0.0.1");
        upstream_cfg.listen.dot = vec![tls];
        upstream_cfg.listen.doh = vec![https];
        upstream_cfg.listen.doq = vec![quic];
        upstream_cfg.listen.certificate = Some(directory.path().join("cert.pem"));
        upstream_cfg.listen.private_key = Some(directory.path().join("key.pem"));
        match RunningServer::start(upstream_cfg).await {
            Ok(server) => break (server, tls, https, quic),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && attempt < 5 => {
                attempt += 1;
            }
            Err(error) => panic!("upstream failed to start: {error}"),
        }
    };
    for (protocol, address) in [
        (UpstreamProtocol::Tls, tls),
        (UpstreamProtocol::Https, https),
        (UpstreamProtocol::Quic, quic),
    ] {
        let bind = self::address("127.0.0.1");
        let mut cfg = config(address, bind);
        cfg.resolver.upstreams[0].protocol = protocol;
        cfg.resolver.upstreams[0].server_name = Some("localhost".into());
        cfg.resolver.upstream_ca = Some(directory.path().join("cert.pem"));
        let mut server = RunningServer::start(cfg.clone()).await.unwrap();
        assert_eq!(
            udp(bind, &query("ok.example.", RecordType::A))
                .await
                .metadata
                .response_code,
            ResponseCode::NoError,
            "{protocol:?}"
        );
        server.shutdown().await;
        cfg.resolver.upstreams[0].server_name = Some("wrong.example".into());
        cfg.limits.query_timeout_ms = 150;
        let mut server = RunningServer::start(cfg).await.unwrap();
        assert_eq!(
            udp(bind, &query("ok.example.", RecordType::A))
                .await
                .metadata
                .response_code,
            ResponseCode::ServFail
        );
        server.shutdown().await;
    }

    let bind = self::address("127.0.0.1");
    let mut cfg = config(https, bind);
    cfg.resolver.automatic_transport = true;
    cfg.resolver.attempts = 1;
    cfg.resolver.upstream_timeout_ms = 250;
    cfg.resolver.upstream_ca = Some(directory.path().join("cert.pem"));
    // A listener that accepts and immediately drops connections fails the TLS handshake at
    // once on every OS. A closed port does not: Windows keeps retrying the connect.
    let broken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let broken_address = broken.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in broken.incoming() {
            drop(stream);
        }
    });
    cfg.resolver.upstreams = vec![
        Upstream {
            address: broken_address,
            protocol: UpstreamProtocol::Tls,
            server_name: Some("localhost".into()),
            doh_path: None,
        },
        Upstream {
            address: https,
            protocol: UpstreamProtocol::Https,
            server_name: Some("localhost".into()),
            doh_path: Some("/dns-query".into()),
        },
    ];
    let mut server = RunningServer::start(cfg).await.unwrap();
    assert_eq!(
        udp(bind, &query("auto.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NoError,
        "a transport failure should try the next encrypted endpoint"
    );
    server.shutdown().await;

    let bind = self::address("127.0.0.1");
    let mut cfg = config(https, bind);
    cfg.resolver.automatic_transport = true;
    cfg.resolver.upstream_ca = Some(directory.path().join("cert.pem"));
    cfg.resolver.upstreams = vec![
        Upstream {
            address: https,
            protocol: UpstreamProtocol::Https,
            server_name: Some("localhost".into()),
            doh_path: Some("/dns-query".into()),
        },
        Upstream {
            address: tls,
            protocol: UpstreamProtocol::Tls,
            server_name: Some("localhost".into()),
            doh_path: None,
        },
    ];
    let before = fixture.queries.load(Ordering::Relaxed);
    let mut server = RunningServer::start(cfg).await.unwrap();
    assert_eq!(
        udp(bind, &query("missing.auto.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(
        fixture.queries.load(Ordering::Relaxed),
        before + 1,
        "a DNS answer must not trigger transport failover"
    );
    server.shutdown().await;
    upstream.shutdown().await;
}

#[tokio::test]
async fn startup_is_atomic_and_load_stays_bounded() {
    let fixture = fixture().await;
    // Probed ports are free only for an instant. Retry the full atomic-start check with a
    // fresh port if another parallel test wins that race; a real cleanup leak fails every try.
    let mut attempt = 0;
    let (mut server, bind) = loop {
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bind = address("127.0.0.1");
        let mut invalid = config(fixture.address, bind);
        invalid.listen.tcp.push(held.local_addr().unwrap());
        assert!(RunningServer::start(invalid).await.is_err());
        let mut cfg = config(fixture.address, bind);
        cfg.limits.queries_per_second = 1000;
        cfg.limits.max_in_flight = 16;
        match RunningServer::start(cfg).await {
            Ok(server) => break (server, bind),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse && attempt < 5 => {
                attempt += 1;
            }
            Err(error) => panic!("server failed to start after atomic bind check: {error}"),
        }
    };
    for batch in 0..32 {
        let mut tasks = JoinSet::new();
        for index in 0..8 {
            tasks.spawn(async move {
                udp(
                    bind,
                    &query(&format!("load-{batch}-{index}.example."), RecordType::A),
                )
                .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            assert_eq!(
                result.unwrap().metadata.response_code,
                ResponseCode::NoError
            );
        }
        // The counter drops just after the reply is sent, so give the last task a moment.
        for _ in 0..200 {
            if server.metrics.active.load(Ordering::Relaxed) == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(server.metrics.active.load(Ordering::Relaxed), 0);
    }
    assert_eq!(server.metrics.queries.load(Ordering::Relaxed), 256);
    server.shutdown().await;
}

#[tokio::test]
async fn filtering_precedes_shared_cache_updates_and_rollback() {
    use lumen_filter::{
        config::{Device, List, Profile, Rules},
        rules::Format,
    };
    let fixture = fixture().await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("list.txt");
    std::fs::write(&path, "other.example").unwrap();
    let v4 = address("127.0.0.1");
    let v6 = address("[::1]");
    let mut cfg = config(fixture.address, v4);
    cfg.listen.udp.push(v6);
    cfg.listen.tcp.push(v6);
    cfg.filtering.lists = vec![List {
        id: "local".into(),
        format: Format::Domains,
        path: Some(path.clone()),
        text: None,
        url: None,
        category: None,
        refresh_secs: 0,
    }];
    cfg.filtering.profiles = vec![Profile {
        id: "v6".into(),
        rules: Rules {
            block: vec!["ok.example".into()],
            ..Rules::default()
        },
        ..Profile::default()
    }];
    cfg.filtering.devices = vec![Device {
        id: "v6-client".into(),
        addresses: vec!["::1".parse().unwrap()],
        profile: Some("v6".into()),
        group: None,
    }];
    let mut server = RunningServer::start(cfg).await.unwrap();
    let packet = query("ok.example.", RecordType::A);
    assert!(!udp(v4, &packet).await.answers.is_empty());
    let count = fixture.queries.load(Ordering::Relaxed);
    assert_eq!(
        udp(v6, &packet).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    let mut tcp = TcpStream::connect(v6).await.unwrap();
    assert_eq!(
        framed(&mut tcp, &packet).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    assert_eq!(fixture.queries.load(Ordering::Relaxed), count);
    std::fs::write(&path, "ok.example").unwrap();
    server.refresh_filter().await.unwrap();
    let blocked = udp(v4, &packet).await;
    assert_eq!(blocked.metadata.response_code, ResponseCode::NXDomain);
    assert!(!blocked.metadata.authentic_data);
    assert_eq!(fixture.queries.load(Ordering::Relaxed), count);
    std::fs::write(&path, "https://bad.example").unwrap();
    assert!(server.refresh_filter().await.is_err());
    assert_eq!(
        udp(v4, &packet).await.metadata.response_code,
        ResponseCode::NXDomain
    );
    server.rollback_filter().await.unwrap();
    assert!(!udp(v4, &packet).await.answers.is_empty());
    assert_eq!(fixture.queries.load(Ordering::Relaxed), count);
    assert!(!server.refresh_filter_due().await.unwrap());
    server.shutdown().await;
}

#[tokio::test]
async fn bad_filter_source_fails_before_listeners_open() {
    let fixture = fixture().await;
    let bind = address("127.0.0.1");
    let mut cfg = config(fixture.address, bind);
    cfg.filtering.lists.push(lumen_filter::config::List {
        id: "broken".into(),
        format: lumen_filter::rules::Format::Domains,
        text: Some("bad/url".into()),
        path: None,
        url: None,
        category: None,
        refresh_secs: 0,
    });
    assert!(RunningServer::start(cfg).await.is_err());
    let _tcp = TcpListener::bind(bind).await.unwrap();
    let _udp = UdpSocket::bind(bind).await.unwrap();
    assert_eq!(fixture.queries.load(Ordering::Relaxed), 0);
}

/// Saved query history, end to end: a real DNS query reaches the `SQLite` file, anonymously
/// unless an administrator chose full detail, and nothing is saved while history is off.
#[tokio::test]
async fn saved_history_is_opt_in_anonymous_by_choice_and_stops_when_off() {
    use lumen_store::{HistoryDetail, HistoryMode, HistoryPrefs, QueryFilter, Store};

    let fixture = fixture().await;
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state.db");
    let store = Store::open(&state).unwrap();
    let prefs = |mode, detail| HistoryPrefs {
        mode,
        detail,
        retention_days: 7,
    };
    let rows = |store: &Store| {
        store
            .query_log(&QueryFilter {
                limit: 100,
                ..QueryFilter::default()
            })
            .unwrap()
    };
    let wait_for = async |store: &Store, wanted: &dyn Fn(&[lumen_store::StoredQuery]) -> bool| {
        for _ in 0..80 {
            if wanted(&rows(store)) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    };

    // Nothing is recorded by default, even with a console and a state file.
    let bind = address("127.0.0.1");
    let mut cfg = config(fixture.address, bind);
    cfg.web.http = vec![address("127.0.0.1")];
    let mut server = RunningServer::start_with(
        cfg,
        ConsoleOptions {
            state: Some(state.clone()),
            version: "test",
        },
    )
    .await
    .unwrap();
    assert_eq!(
        udp(bind, &query("quiet.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    assert!(
        rows(&store).is_empty(),
        "history is off until it is switched on"
    );
    server.shutdown().await;

    // Saved + anonymous from the first query on: no client address, no device.
    store
        .set_history_prefs(&prefs(HistoryMode::Saved, HistoryDetail::Anonymous))
        .unwrap();
    let mut cfg = config(fixture.address, bind);
    cfg.web.http = vec![address("127.0.0.1")];
    let mut server = RunningServer::start_with(
        cfg,
        ConsoleOptions {
            state: Some(state.clone()),
            version: "test",
        },
    )
    .await
    .unwrap();
    udp(bind, &query("ok.example.", RecordType::A)).await;
    assert!(
        wait_for(&store, &|r| r.iter().any(|q| q.row.domain == "ok.example")).await,
        "saved"
    );
    let saved = rows(&store);
    let row = &saved
        .iter()
        .find(|q| q.row.domain == "ok.example")
        .unwrap()
        .row;
    assert_eq!((row.client.clone(), row.device.clone()), (None, None));
    assert_eq!(
        (row.qtype.as_str(), row.rcode.as_str(), row.blocked),
        ("A", "NOERROR", false)
    );

    // A setting changed behind the daemon's back (as `lumenctl history set` does) is applied
    // within seconds: full detail now records the client address.
    store
        .set_history_prefs(&prefs(HistoryMode::Saved, HistoryDetail::Full))
        .unwrap();
    let mut seen = false;
    for _ in 0..40 {
        udp(bind, &query("full.example.", RecordType::A)).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        seen = rows(&store).iter().any(|q| {
            q.row.domain == "full.example" && q.row.client.as_deref() == Some("127.0.0.1")
        });
        if seen {
            break;
        }
    }
    assert!(seen, "full detail records the client address");

    // Off again: recording stops, and what was saved stays until it expires or is deleted.
    store
        .set_history_prefs(&prefs(HistoryMode::Off, HistoryDetail::Full))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2600)).await;
    let before = rows(&store).len();
    udp(bind, &query("after-off.example.", RecordType::A)).await;
    tokio::time::sleep(std::time::Duration::from_millis(2600)).await;
    let after = rows(&store);
    assert_eq!(after.len(), before);
    assert!(after.iter().all(|q| q.row.domain != "after-off.example"));
    server.shutdown().await;
}

/// Several forwarders, end to end: ranked fallback, even spreading, racing, and skipping a
/// dead provider. Each upstream is a real UDP server that counts what it receives.
#[tokio::test]
async fn forward_strategies_fail_over_spread_race_and_skip_dead_upstreams() {
    let upstreams = [fixture().await, fixture().await, fixture().await];
    let udp_upstream = |address: SocketAddr| Upstream {
        address,
        protocol: UpstreamProtocol::Udp,
        server_name: None,
        doh_path: None,
    };
    let counts = || -> Vec<usize> {
        upstreams
            .iter()
            .map(|u| u.queries.load(Ordering::Relaxed))
            .collect()
    };
    let ask = async |bind: SocketAddr, tag: &str, count: usize| {
        for index in 0..count {
            let reply = udp(
                bind,
                &query(&format!("{tag}-{index}.example."), RecordType::A),
            )
            .await;
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{tag}-{index}"
            );
        }
    };
    let start =
        async |strategy: Option<ForwardStrategy>, upstream_list: Vec<Upstream>, timeout_ms: u32| {
            let bind = address("127.0.0.1");
            let mut cfg = config(upstreams[0].address, bind);
            cfg.resolver.upstreams = upstream_list;
            cfg.resolver.strategy = strategy;
            cfg.resolver.upstream_timeout_ms = timeout_ms;
            (RunningServer::start(cfg).await.unwrap(), bind)
        };
    let live: Vec<Upstream> = upstreams.iter().map(|u| udp_upstream(u.address)).collect();

    // Ranked fallback: the first upstream answers everything and the others stand by.
    let before = counts();
    let (mut server, bind) = start(Some(ForwardStrategy::Failover), live.clone(), 2_000).await;
    ask(bind, "failover", 6).await;
    server.shutdown().await;
    let after = counts();
    assert_eq!(after[0] - before[0], 6);
    assert_eq!((after[1] - before[1], after[2] - before[2]), (0, 0));

    // Round-robin: every upstream starts the same number of queries.
    let before = counts();
    let (mut server, bind) = start(Some(ForwardStrategy::RoundRobin), live.clone(), 2_000).await;
    ask(bind, "robin", 9).await;
    server.shutdown().await;
    let after = counts();
    let shares: Vec<usize> = (0..3).map(|i| after[i] - before[i]).collect();
    assert_eq!(shares, [3, 3, 3], "an even spread");

    // Race: every upstream is asked, and the first answer is used.
    let before = counts();
    let (mut server, bind) = start(Some(ForwardStrategy::Race), live.clone(), 2_000).await;
    ask(bind, "race", 4).await;
    server.shutdown().await;
    let after = counts();
    let shares: Vec<usize> = (0..3).map(|i| after[i] - before[i]).collect();
    assert!(
        shares.iter().all(|&n| n > 0),
        "every upstream sees queries: {shares:?}"
    );
    assert!(
        shares.iter().sum::<usize>() > 4,
        "more than one ask per query: {shares:?}"
    );

    // Fastest first and the older default ask one upstream per query.
    for strategy in [Some(ForwardStrategy::Fastest), None] {
        let before = counts();
        let (mut server, bind) = start(strategy, live.clone(), 2_000).await;
        ask(
            bind,
            if strategy.is_some() {
                "fastest"
            } else {
                "legacy"
            },
            4,
        )
        .await;
        server.shutdown().await;
        let after = counts();
        let total: usize = (0..3).map(|i| after[i] - before[i]).sum();
        assert_eq!(total, 4, "{strategy:?}");
    }

    // A dead first provider is skipped, so ranked fallback and round-robin still answer.
    let dead = address("127.0.0.1");
    for strategy in [
        ForwardStrategy::Failover,
        ForwardStrategy::RoundRobin,
        ForwardStrategy::Race,
    ] {
        let list = vec![udp_upstream(dead), udp_upstream(upstreams[1].address)];
        let before = counts();
        let (mut server, bind) = start(Some(strategy), list, 300).await;
        // The first query may wait for the dead provider once. After that it is left alone,
        // so the rest do not each wait for a timeout.
        ask(bind, &format!("dead-first-{strategy:?}"), 1).await;
        let rest = std::time::Instant::now();
        ask(bind, &format!("dead-then-{strategy:?}"), 3).await;
        assert!(
            rest.elapsed() < Duration::from_millis(500),
            "{strategy:?} kept waiting for the dead provider: {:?}",
            rest.elapsed()
        );
        server.shutdown().await;
        assert!(
            counts()[1] - before[1] >= 4,
            "{strategy:?} reached the live upstream"
        );
    }
}

/// A filtering-only change goes live in the running service: same listeners, no restart.
#[tokio::test]
async fn a_new_filter_goes_live_without_restarting_listeners() {
    use lumen_filter::config::{Config as FilterConfig, Rules};

    let fixture = fixture().await;
    let bind = address("127.0.0.1");
    let mut server = RunningServer::start(config(fixture.address, bind))
        .await
        .unwrap();
    let endpoints = server.endpoints.clone();
    assert_eq!(
        udp(bind, &query("ads.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NoError,
        "allowed before the change"
    );
    assert_eq!(server.filter().metrics.allowed.load(Ordering::Relaxed), 1);

    let blocking = FilterConfig {
        rules: Rules {
            block: vec!["ads.example".into()],
            ..Rules::default()
        },
        ..FilterConfig::default()
    };
    let filter = std::sync::Arc::new(lumen_filter::Filter::load(blocking).await.unwrap());
    server.replace_filter(filter);

    // Blocked at once, on the very same socket.
    assert_eq!(
        udp(bind, &query("ads.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NXDomain,
        "blocked right after the swap"
    );
    assert_eq!(
        server.endpoints, endpoints,
        "the listeners were not touched"
    );
    // The totals carry on instead of starting from zero.
    assert_eq!(server.filter().metrics.allowed.load(Ordering::Relaxed), 1);
    assert_eq!(server.filter().metrics.blocked.load(Ordering::Relaxed), 1);
    server.shutdown().await;
}

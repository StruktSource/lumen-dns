// SPDX-License-Identifier: Apache-2.0
//! Offline protocol, DNSSEC, cache, and resource-limit regression tests.
#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_proto::{
    op::{Edns, Message, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, SOA},
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
    fixture_with_servfail(false).await
}

async fn servfail_fixture() -> Fixture {
    fixture_with_servfail(true).await
}

async fn fixture_with_servfail(servfail: bool) -> Fixture {
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
            let response = mock_response(request, false, servfail);
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
                    let response = mock_response(request, true, servfail).to_vec().unwrap();
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

fn mock_response(request: Message, tcp: bool, servfail: bool) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.queries = request.queries;
    response.edns = request.edns;
    let q = &response.queries[0];
    let name = q.name().clone();
    let text = name.to_ascii().to_lowercase();
    if servfail {
        response.metadata.response_code = ResponseCode::ServFail;
        return response;
    }
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
    } else if text.starts_with("alias.") {
        response.metadata.authentic_data = true;
        response.add_answer(Record::from_rdata(
            name,
            1,
            RData::CNAME(CNAME(Name::from_ascii("tracker.example.").unwrap())),
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
    use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
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
    // Serve the same signed zone over TLS for automatic-transport policy checks.
    let (tls_directory, cert) = certificates();
    let key = PrivateKeyDer::from_pem_file(tls_directory.path().join("key.pem")).unwrap();
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    tls_config.alpn_protocols = vec![b"dot".to_vec()];
    let tls_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_address = tls_listener.local_addr().unwrap();
    authority
        .register_tls_listener_with_tls_config(
            tls_listener,
            Duration::from_secs(2),
            Arc::new(tls_config),
        )
        .unwrap();
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
    // A usable positive or negative answer, and a local DNSSEC failure, must all
    // end the provider lookup without connecting to its next encrypted transport.
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_address = unused.local_addr().unwrap();
    let contacted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&contacted);
    let unused_task = tokio::spawn(async move {
        loop {
            let (stream, _) = unused.accept().await.unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            drop(stream);
        }
    });
    let mut automatic = cfg.clone();
    automatic.resolver.automatic_transport = true;
    automatic.resolver.upstream_ca = Some(tls_directory.path().join("cert.pem"));
    automatic.resolver.upstreams = vec![
        Upstream {
            address: tls_address,
            protocol: UpstreamProtocol::Tls,
            server_name: Some("localhost".into()),
            doh_path: None,
        },
        Upstream {
            address: unused_address,
            protocol: UpstreamProtocol::Https,
            server_name: Some("localhost".into()),
            doh_path: Some("/dns-query".into()),
        },
    ];
    let mut encrypted_server = RunningServer::start(automatic).await.unwrap();
    for (name, expected) in [
        ("valid.example.", ResponseCode::NoError),
        ("absent.example.", ResponseCode::NXDomain),
        ("bogus.example.", ResponseCode::ServFail),
    ] {
        assert_eq!(
            udp(bind, &query(name, RecordType::A))
                .await
                .metadata
                .response_code,
            expected,
            "{name}"
        );
        assert_eq!(
            contacted.load(Ordering::Relaxed),
            0,
            "DNS results are final across transports"
        );
    }
    encrypted_server.shutdown().await;
    unused_task.abort();
    let _ = unused_task.await;
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
    let broken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let broken_address = broken.local_addr().unwrap();
    let broken_task = tokio::spawn(async move {
        loop {
            let (stream, _) = broken.accept().await.unwrap();
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
    // A TCP peer accepts the TLS connection but sends no handshake bytes. This is
    // controlled silence, independent of firewall/OS connect timeout behavior.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_address = silent.local_addr().unwrap();
    let silent_connections = std::sync::Arc::new(AtomicUsize::new(0));
    let seen = std::sync::Arc::clone(&silent_connections);
    let silence = tokio::spawn(async move {
        let mut clients = JoinSet::new();
        loop {
            let (mut stream, _) = silent.accept().await.unwrap();
            let seen = std::sync::Arc::clone(&seen);
            clients.spawn(async move {
                struct Active(std::sync::Arc<AtomicUsize>);
                impl Drop for Active {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                seen.fetch_add(1, Ordering::Relaxed);
                let _active = Active(seen);
                let mut bytes = [0; 4096];
                while matches!(stream.read(&mut bytes).await, Ok(n) if n > 0) {}
            });
            while clients.try_join_next().is_some() {}
        }
    });
    let encrypted = |protocol, address| Upstream {
        address,
        protocol,
        server_name: Some("localhost".into()),
        doh_path: (protocol == UpstreamProtocol::Https).then(|| "/dns-query".into()),
    };
    let bind = self::address("127.0.0.1");
    let mut cfg = config(https, bind);
    cfg.resolver.automatic_transport = true;
    cfg.resolver.attempts = 2;
    cfg.resolver.upstream_timeout_ms = 1_000;
    cfg.resolver.upstream_ca = Some(directory.path().join("cert.pem"));
    cfg.resolver.upstreams = vec![
        encrypted(UpstreamProtocol::Tls, silent_address),
        encrypted(UpstreamProtocol::Https, https),
    ];
    let mut server = RunningServer::start(cfg.clone()).await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        udp(bind, &query("silent-first.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "second transport got time to answer"
    );
    // Concurrent unique queries all share bounded resolver state and finish after silence.
    let mut clients = JoinSet::new();
    for i in 0..12 {
        clients.spawn(async move {
            udp(
                bind,
                &query(&format!("silent-concurrent-{i}.example."), RecordType::A),
            )
            .await
        });
    }
    while let Some(reply) = clients.join_next().await {
        assert_eq!(reply.unwrap().metadata.response_code, ResponseCode::NoError);
    }
    server.shutdown().await;
    timeout(Duration::from_secs(2), async {
        while silent_connections.load(Ordering::Relaxed) != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("timed-out TLS attempts release sockets");

    // Both encrypted transports stay silent: no plaintext query is sent, and the
    // provider expires once, even with attempts=2 and a longer outer query timeout.
    cfg.resolver.upstreams[1] = encrypted(UpstreamProtocol::Https, silent_address);
    cfg.limits.query_timeout_ms = 3_000;
    let before = fixture.queries.load(Ordering::Relaxed);
    let mut server = RunningServer::start(cfg).await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        udp(bind, &query("all-silent.example.", RecordType::A))
            .await
            .metadata
            .response_code,
        ResponseCode::ServFail
    );
    assert!(
        started.elapsed() < Duration::from_millis(1_800),
        "one overall provider deadline"
    );
    assert_eq!(
        fixture.queries.load(Ordering::Relaxed),
        before,
        "no plaintext downgrade"
    );
    // Cancel work while a transport is silent. Shutdown must reap query tasks and sockets.
    let mut clients = JoinSet::new();
    for i in 0..12 {
        clients.spawn(async move {
            udp(bind, &query(&format!("cancel-{i}.example."), RecordType::A)).await
        });
    }
    timeout(Duration::from_secs(2), async {
        while silent_connections.load(Ordering::Relaxed) == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    timeout(Duration::from_secs(2), server.shutdown())
        .await
        .expect("shutdown cancels silent queries");
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    timeout(Duration::from_secs(2), async {
        while silent_connections.load(Ordering::Relaxed) != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("cancelled TLS attempts release sockets");
    silence.abort();
    let _ = silence.await;
    broken_task.abort();
    let _ = broken_task.await;
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
async fn cname_chain_filtering_replaces_validated_answer_and_clears_ad() {
    let fixture = fixture().await;
    let bind = address("127.0.0.1");
    let mut cfg = config(fixture.address, bind);
    cfg.filtering.rules.block = vec!["tracker.example".into()];
    let mut server = RunningServer::start(cfg).await.unwrap();

    let reply = udp(bind, &query("alias.example.", RecordType::A)).await;
    assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
    assert!(!reply.metadata.authentic_data);
    assert!(reply.answers.is_empty());
    assert_eq!(server.filter().metrics.blocked.load(Ordering::Relaxed), 1);
    assert_eq!(server.filter().metrics.allowed.load(Ordering::Relaxed), 0);
    // Hickory follows the CNAME once; policy then replaces the completed chain.
    assert_eq!(fixture.queries.load(Ordering::Relaxed), 2);

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

    // SERVFAIL from an upstream is not useful DNS data and is not a local DNSSEC failure. Try
    // the next provider, then rest the failing one so it cannot add delay to every lookup.
    let servfail = servfail_fixture().await;
    let list = vec![
        udp_upstream(servfail.address),
        udp_upstream(upstreams[1].address),
    ];
    let before_live = upstreams[1].queries.load(Ordering::Relaxed);
    let (mut server, bind) = start(Some(ForwardStrategy::Failover), list, 2_000).await;
    ask(bind, "servfail-first", 1).await;
    let bad_after_first = servfail.queries.load(Ordering::Relaxed);
    ask(bind, "servfail-rested", 3).await;
    assert_eq!(
        servfail.queries.load(Ordering::Relaxed),
        bad_after_first,
        "SERVFAIL provider should rest after the first failure"
    );
    assert_eq!(
        upstreams[1].queries.load(Ordering::Relaxed) - before_live,
        4,
        "the next provider should answer every query"
    );
    server.shutdown().await;
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

type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, bytes::Bytes>;

async fn doh3(
    sender: &mut H3Sender,
    packet: &[u8],
    method: &str,
    path: &str,
    media: &str,
) -> (http::StatusCode, Vec<u8>) {
    use bytes::Buf;
    let request = http::Request::builder()
        .method(method)
        .uri(format!("https://localhost{path}"))
        .header("content-type", media)
        .body(())
        .unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    if !packet.is_empty() {
        stream
            .send_data(bytes::Bytes::copy_from_slice(packet))
            .await
            .unwrap();
    }
    stream.finish().await.unwrap();
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    let mut body = vec![];
    while let Some(mut chunk) = timeout(Duration::from_secs(3), stream.recv_data())
        .await
        .unwrap()
        .unwrap()
    {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (response.status(), body)
}

#[tokio::test]
async fn doh3_listener_answers_get_post_and_rejects_bad_requests() {
    let fixture = fixture().await;
    let (directory, cert) = certificates();
    for ip in ["127.0.0.1", "[::1]"] {
        let mut cfg = config(fixture.address, address(ip));
        cfg.listen.udp.clear();
        cfg.listen.tcp.clear();
        let bind = address(ip);
        cfg.listen.doh3 = vec![bind];
        cfg.listen.certificate = Some(directory.path().join("cert.pem"));
        cfg.listen.private_key = Some(directory.path().join("key.pem"));
        cfg.filtering.rules.block = vec!["blocked.example".into()];
        let mut server = RunningServer::start(cfg).await.unwrap();
        let socket = std::net::UdpSocket::bind(if bind.is_ipv4() {
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
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls(cert.clone(), b"h3"))
                .unwrap(),
        )));
        let connection = endpoint.connect(bind, "localhost").unwrap().await.unwrap();
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let packet = query("ok.example.", RecordType::A);
        let (status, body) = doh3(
            &mut sender,
            &packet,
            "POST",
            "/dns-query",
            "application/dns-message",
        )
        .await;
        assert_eq!(status, http::StatusCode::OK);
        assert!(!Message::from_vec(&body).unwrap().answers.is_empty());
        let path = format!("/dns-query?dns={}", URL_SAFE_NO_PAD.encode(&packet));
        let (status, body) = doh3(&mut sender, &[], "GET", &path, "application/dns-message").await;
        assert_eq!(status, http::StatusCode::OK);
        assert!(!Message::from_vec(&body).unwrap().answers.is_empty());
        let (_, body) = doh3(
            &mut sender,
            &query("blocked.example.", RecordType::A),
            "POST",
            "/dns-query",
            "application/dns-message",
        )
        .await;
        assert_eq!(
            Message::from_vec(&body).unwrap().metadata.response_code,
            ResponseCode::NXDomain
        );
        assert_eq!(
            doh3(&mut sender, &packet, "POST", "/dns-query", "text/plain")
                .await
                .0,
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            doh3(&mut sender, &[], "GET", "/other", "application/dns-message")
                .await
                .0,
            http::StatusCode::NOT_FOUND
        );
        assert_eq!(
            doh3(
                &mut sender,
                &[],
                "PUT",
                "/dns-query",
                "application/dns-message"
            )
            .await
            .0,
            http::StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            doh3(
                &mut sender,
                &[],
                "GET",
                "/dns-query?dns=!!",
                "application/dns-message"
            )
            .await
            .0,
            http::StatusCode::BAD_REQUEST
        );
        driver.abort();
        connection.close(0_u32.into(), b"done");
        endpoint.close(0_u32.into(), b"done");
        server.shutdown().await;
    }
}

/// Minimal independent `DNSCrypt` v2 client for the integration test.
struct CryptClient {
    resolver: crypto_box::PublicKey,
    magic: [u8; 8],
    secret: crypto_box::SecretKey,
    chacha: bool,
}

impl CryptClient {
    fn from_certificate(cert: &[u8], provider: &ed25519_dalek::VerifyingKey, chacha: bool) -> Self {
        use ed25519_dalek::Verifier;
        assert_eq!((cert.len(), &cert[..4]), (124, &b"DNSC"[..]));
        assert_eq!(
            u16::from_be_bytes([cert[4], cert[5]]),
            if chacha { 2 } else { 1 }
        );
        let signature = ed25519_dalek::Signature::from_slice(&cert[8..72]).unwrap();
        provider.verify(&cert[72..], &signature).unwrap();
        let start = u32::from_be_bytes(cert[116..120].try_into().unwrap());
        let end = u32::from_be_bytes(cert[120..124].try_into().unwrap());
        let now = u32::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        assert!(start <= now && now < end);
        Self {
            resolver: crypto_box::PublicKey::from(<[u8; 32]>::try_from(&cert[72..104]).unwrap()),
            magic: cert[104..112].try_into().unwrap(),
            secret: crypto_box::SecretKey::generate(&mut rand_core::OsRng),
            chacha,
        }
    }

    fn encrypt(&self, dns: &[u8]) -> (Vec<u8>, [u8; 12]) {
        use crypto_box::aead::{Aead, generic_array::GenericArray};
        let mut plain = dns.to_vec();
        plain.push(0x80);
        plain.resize(plain.len().div_ceil(64).max(4) * 64, 0);
        let mut nonce = [0_u8; 24];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce[..12]);
        let nonce_ga = GenericArray::from_slice(&nonce);
        let boxed = if self.chacha {
            crypto_box::ChaChaBox::new(&self.resolver, &self.secret)
                .encrypt(nonce_ga, &plain[..])
                .unwrap()
        } else {
            crypto_box::SalsaBox::new(&self.resolver, &self.secret)
                .encrypt(nonce_ga, &plain[..])
                .unwrap()
        };
        let mut packet = self.magic.to_vec();
        packet.extend_from_slice(crypto_box::PublicKey::from(&self.secret).as_bytes());
        packet.extend_from_slice(&nonce[..12]);
        packet.extend_from_slice(&boxed);
        (packet, nonce[..12].try_into().unwrap())
    }

    fn decrypt(&self, packet: &[u8], client_nonce: [u8; 12]) -> Message {
        use crypto_box::aead::{Aead, generic_array::GenericArray};
        assert_eq!(
            &packet[..8],
            &[0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38]
        );
        assert_eq!(packet[8..20], client_nonce);
        let nonce = GenericArray::from_slice(&packet[8..32]);
        let mut plain = if self.chacha {
            crypto_box::ChaChaBox::new(&self.resolver, &self.secret)
                .decrypt(nonce, &packet[32..])
                .unwrap()
        } else {
            crypto_box::SalsaBox::new(&self.resolver, &self.secret)
                .decrypt(nonce, &packet[32..])
                .unwrap()
        };
        while plain.last() == Some(&0) {
            plain.pop();
        }
        assert_eq!(plain.pop(), Some(0x80));
        Message::from_vec(&plain).unwrap()
    }
}

fn certificates_from(response: &[u8]) -> Vec<Vec<u8>> {
    Message::from_vec(response)
        .unwrap()
        .answers
        .iter()
        .map(|record| match &record.data {
            hickory_proto::rr::RData::TXT(txt) => {
                txt.txt_data.iter().flat_map(|part| part.to_vec()).collect()
            }
            _ => panic!("certificate answer is not TXT"),
        })
        .collect()
}

#[tokio::test]
async fn dnscrypt_serves_certificates_and_encrypted_queries_over_udp_and_tcp() {
    let fixture = fixture().await;
    let directory = tempfile::tempdir().unwrap();
    let key_file = directory.path().join("provider.key");
    let bind = address("127.0.0.1");
    let mut cfg = config(fixture.address, address("127.0.0.1"));
    cfg.dnscrypt.enabled = true;
    cfg.dnscrypt.listen = vec![bind];
    cfg.dnscrypt.provider_name = "2.dnscrypt-cert.lumen.test".into();
    cfg.dnscrypt.key_file = Some(key_file.clone());
    cfg.filtering.rules.block = vec!["blocked.example".into()];
    let mut server = RunningServer::start(cfg).await.unwrap();
    let seed: [u8; 32] = std::fs::read_to_string(&key_file)
        .unwrap()
        .trim()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let provider = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = vec![0_u8; 4096];
    // The wrong provider name is dropped silently.
    socket
        .send_to(&query("wrong.lumen.test.", RecordType::TXT), bind)
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(300), socket.recv_from(&mut buffer))
            .await
            .is_err()
    );
    socket
        .send_to(&query("2.dnscrypt-cert.lumen.test.", RecordType::TXT), bind)
        .await
        .unwrap();
    let (size, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let certs = certificates_from(&buffer[..size]);
    assert_eq!(certs.len(), 2);

    for cert in &certs {
        let chacha = u16::from_be_bytes([cert[4], cert[5]]) == 2;
        let client = CryptClient::from_certificate(cert, &provider, chacha);
        // UDP: an answer and a blocked name.
        for (name, code) in [
            ("ok.example.", ResponseCode::NoError),
            ("blocked.example.", ResponseCode::NXDomain),
        ] {
            let (packet, nonce) = client.encrypt(&query(name, RecordType::A));
            socket.send_to(&packet, bind).await.unwrap();
            let (size, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert!(size <= packet.len(), "UDP reply must not exceed the query");
            let message = client.decrypt(&buffer[..size], nonce);
            assert_eq!(message.metadata.response_code, code);
            assert_eq!(!message.answers.is_empty(), code == ResponseCode::NoError);
        }
        // TCP, two queries on one connection, then a forged packet closes it.
        let mut stream = TcpStream::connect(bind).await.unwrap();
        for _ in 0..2 {
            let (packet, nonce) = client.encrypt(&query("ok.example.", RecordType::A));
            stream
                .write_u16(u16::try_from(packet.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&packet).await.unwrap();
            let length = timeout(Duration::from_secs(3), stream.read_u16())
                .await
                .unwrap()
                .unwrap();
            let mut reply = vec![0; usize::from(length)];
            stream.read_exact(&mut reply).await.unwrap();
            assert!(!client.decrypt(&reply, nonce).answers.is_empty());
        }
        let (mut forged, _) = client.encrypt(&query("ok.example.", RecordType::A));
        let last = forged.len() - 1;
        forged[last] ^= 1;
        stream
            .write_u16(u16::try_from(forged.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&forged).await.unwrap();
        assert!(
            timeout(Duration::from_secs(3), stream.read_u16())
                .await
                .unwrap()
                .is_err(),
            "a forged packet must close the stream without a reply"
        );
    }
    server.shutdown().await;
}

fn zone_text(origin: &str, address: &str) -> String {
    format!(
        "{origin}. 60 IN SOA ns.{origin}. hostmaster.{origin}. 1 60 60 60 60\n\
         {origin}. 60 IN NS ns.{origin}.\n\
         ns.{origin}. 60 IN A 192.0.2.53\n\
         host.{origin}. 60 IN A {address}\n\
         _web._tcp.{origin}. 60 IN SRV 0 0 443 host.{origin}.\n"
    )
}

#[tokio::test]
async fn authoritative_zones_views_and_conditional_forwarding() {
    let upstream = fixture().await;
    let corp = fixture().await;
    let bind = address("127.0.0.1");
    let mut cfg = config(upstream.address, bind);
    cfg.zones = vec![
        lumen_config::Zone {
            name: "plain.test".into(),
            text: Some(zone_text("plain.test", "192.0.2.1")),
            ..Default::default()
        },
        lumen_config::Zone {
            name: "split.test".into(),
            text: Some(zone_text("split.test", "203.0.113.1")),
            views: vec![lumen_config::ZoneView {
                clients: vec!["127.0.0.0/8".parse().unwrap()],
                text: Some(zone_text("split.test", "10.0.0.7")),
                ..Default::default()
            }],
            ..Default::default()
        },
        lumen_config::Zone {
            name: "other.test".into(),
            text: Some(zone_text("other.test", "203.0.113.9")),
            views: vec![lumen_config::ZoneView {
                clients: vec!["10.0.0.0/8".parse().unwrap()],
                text: Some(zone_text("other.test", "10.0.0.9")),
                ..Default::default()
            }],
            ..Default::default()
        },
    ];
    cfg.forwarders = vec![lumen_config::Forwarder {
        domain: "corp.example".into(),
        upstreams: vec![corp.address],
    }];
    let mut server = RunningServer::start(cfg).await.unwrap();
    let a_record = |message: &Message| {
        message
            .answers
            .iter()
            .find_map(|record| match &record.data {
                hickory_proto::rr::RData::A(a) => Some(a.0.to_string()),
                _ => None,
            })
            .unwrap()
    };

    let plain = udp(bind, &query("host.plain.test.", RecordType::A)).await;
    assert!(plain.metadata.authoritative);
    assert_eq!(a_record(&plain), "192.0.2.1");
    // The client matches the view, so it gets the view's copy.
    let split = udp(bind, &query("host.split.test.", RecordType::A)).await;
    assert_eq!(a_record(&split), "10.0.0.7");
    // The client matches no view of this zone, so it gets the default copy.
    let other = udp(bind, &query("host.other.test.", RecordType::A)).await;
    assert_eq!(a_record(&other), "203.0.113.9");
    // DNS-SD style records are ordinary authoritative data.
    let srv = udp(bind, &query("_web._tcp.plain.test.", RecordType::SRV)).await;
    assert_eq!(srv.answers.len(), 1);
    // Names missing from a zone are authoritative NXDOMAIN and never leave Lumen.
    let missing = udp(bind, &query("nope.plain.test.", RecordType::A)).await;
    assert_eq!(missing.metadata.response_code, ResponseCode::NXDomain);
    assert!(missing.metadata.authoritative);
    // Zone transfers are refused unless a later policy allows them.
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 0);

    // Conditional forwarding reaches only its own resolver.
    let forwarded = udp(bind, &query("host.corp.example.", RecordType::A)).await;
    assert!(!forwarded.answers.is_empty());
    assert!(corp.queries.load(Ordering::Relaxed) >= 1);
    assert_eq!(upstream.queries.load(Ordering::Relaxed), 0);
    // Everything else still uses the main resolver.
    let main = udp(bind, &query("ok.example.", RecordType::A)).await;
    assert!(!main.answers.is_empty());
    assert!(upstream.queries.load(Ordering::Relaxed) >= 1);
    server.shutdown().await;
}

fn tsig_signer(name: &str, secret: &[u8]) -> hickory_proto::rr::TSigner {
    hickory_proto::rr::TSigner::new(
        secret.to_vec(),
        hickory_proto::rr::rdata::tsig::TsigAlgorithm::HmacSha256,
        Name::from_ascii(format!("{name}.")).unwrap(),
        300,
    )
    .unwrap()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn update_message(
    zone: &str,
    name: &str,
    kind: RecordType,
    data: hickory_proto::rr::RData,
) -> Message {
    let owner = Name::from_ascii(name).unwrap();
    let mut rrset = hickory_proto::rr::RecordSet::new(owner.clone(), kind, 0);
    rrset.insert(Record::from_rdata(owner, 60, data), 0);
    hickory_proto::op::update_message::append(rrset, Name::from_ascii(zone).unwrap(), false, false)
}

async fn signed(
    address: SocketAddr,
    mut message: Message,
    signer: &hickory_proto::rr::TSigner,
    tcp: bool,
) -> Message {
    message.finalize(signer, now_secs()).unwrap();
    let bytes = message.to_vec().unwrap();
    if tcp {
        let mut stream = TcpStream::connect(address).await.unwrap();
        framed(&mut stream, &bytes).await
    } else {
        udp(address, &bytes).await
    }
}

fn base64_secret(secret: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(secret)
}

#[tokio::test]
async fn dynamic_updates_and_zone_transfers_use_scoped_tsig_keys() {
    let upstream = fixture().await;
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| directory.path().join(name);
    let (ddns_secret, xfr_secret) = ([7_u8; 32], [9_u8; 32]);
    std::fs::write(path("ddns.key"), base64_secret(&ddns_secret)).unwrap();
    std::fs::write(path("xfr.key"), base64_secret(&xfr_secret)).unwrap();
    std::fs::write(path("dyn.zone"), zone_text("dyn.test", "192.0.2.1")).unwrap();
    let build = |bind: SocketAddr| {
        let mut cfg = config(upstream.address, bind);
        cfg.tsig_keys = vec![
            lumen_config::TsigKey {
                name: "ddns".into(),
                algorithm: "hmac-sha256".into(),
                secret_file: Some(path("ddns.key")),
            },
            lumen_config::TsigKey {
                name: "xfr".into(),
                algorithm: "hmac-sha256".into(),
                secret_file: Some(path("xfr.key")),
            },
        ];
        cfg.zones = vec![
            lumen_config::Zone {
                name: "dyn.test".into(),
                file: Some(path("dyn.zone")),
                journal: Some(path("dyn.journal")),
                update_rules: vec![lumen_config::UpdateRule {
                    key: "ddns".into(),
                    names: vec!["*.dyn.test".into()],
                    types: vec!["A".into(), "TXT".into()],
                }],
                transfer_keys: vec!["xfr".into()],
                ..Default::default()
            },
            lumen_config::Zone {
                name: "static.test".into(),
                text: Some(zone_text("static.test", "192.0.2.2")),
                transfer_keys: vec!["xfr".into()],
                ..Default::default()
            },
            lumen_config::Zone {
                name: "closed.test".into(),
                text: Some(zone_text("closed.test", "192.0.2.3")),
                ..Default::default()
            },
        ];
        cfg
    };
    let bind = address("127.0.0.1");
    let mut server = RunningServer::start(build(bind)).await.unwrap();
    let (ddns, xfr) = (
        tsig_signer("ddns", &ddns_secret),
        tsig_signer("xfr", &xfr_secret),
    );
    let a = |ip: &str| hickory_proto::rr::RData::A(A(ip.parse().unwrap()));
    let owner = "new.dyn.test.";

    // Unsigned, wrongly signed, and out-of-scope updates change nothing.
    let unsigned = update_message("dyn.test.", owner, RecordType::A, a("192.0.2.77"))
        .to_vec()
        .unwrap();
    assert_eq!(
        udp(bind, &unsigned).await.metadata.response_code,
        ResponseCode::Refused
    );
    let forged = tsig_signer("ddns", &[1_u8; 32]);
    assert_eq!(
        signed(
            bind,
            update_message("dyn.test.", owner, RecordType::A, a("192.0.2.77")),
            &forged,
            false
        )
        .await
        .metadata
        .response_code,
        ResponseCode::NotAuth
    );
    for (message, signer) in [
        // Another key has no update rule.
        (
            update_message("dyn.test.", owner, RecordType::A, a("192.0.2.77")),
            &xfr,
        ),
        // A type the rule does not list.
        (
            update_message(
                "dyn.test.",
                owner,
                RecordType::AAAA,
                hickory_proto::rr::RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
            ),
            &ddns,
        ),
        // The apex is not below `*.dyn.test`.
        (
            update_message("dyn.test.", "dyn.test.", RecordType::A, a("192.0.2.77")),
            &ddns,
        ),
    ] {
        assert_eq!(
            signed(bind, message, signer, false)
                .await
                .metadata
                .response_code,
            ResponseCode::Refused
        );
    }
    // A zone with no journal is not dynamic at all.
    assert_eq!(
        signed(
            bind,
            update_message(
                "closed.test.",
                "x.closed.test.",
                RecordType::A,
                a("192.0.2.77")
            ),
            &ddns,
            false
        )
        .await
        .metadata
        .response_code,
        ResponseCode::NotImp
    );
    let before = udp(bind, &query("new.dyn.test.", RecordType::A)).await;
    assert_eq!(before.metadata.response_code, ResponseCode::NXDomain);

    // A scoped, signed update works over UDP and TCP.
    let ok = signed(
        bind,
        update_message("dyn.test.", owner, RecordType::A, a("192.0.2.77")),
        &ddns,
        false,
    )
    .await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
    let ok = signed(
        bind,
        update_message(
            "dyn.test.",
            "txt.dyn.test.",
            RecordType::TXT,
            hickory_proto::rr::RData::TXT(hickory_proto::rr::rdata::TXT::new(vec!["hello".into()])),
        ),
        &ddns,
        true,
    )
    .await;
    assert_eq!(ok.metadata.response_code, ResponseCode::NoError);
    let after = udp(bind, &query("new.dyn.test.", RecordType::A)).await;
    assert_eq!(after.answers.len(), 1);

    // Transfers: only the transfer key, only over TCP, never unsigned.
    let axfr = |zone: &str| {
        hickory_proto::op::update_message::zone_transfer(Name::from_ascii(zone).unwrap(), None)
    };
    let transfer = signed(bind, axfr("dyn.test."), &xfr, true).await;
    assert_eq!(transfer.metadata.response_code, ResponseCode::NoError);
    let owners: Vec<String> = transfer.answers.iter().map(|r| r.name.to_ascii()).collect();
    assert!(owners.contains(&"new.dyn.test.".to_string()), "{owners:?}");
    assert!(owners.contains(&"txt.dyn.test.".to_string()));
    assert_eq!(
        transfer.answers.first().unwrap().record_type(),
        RecordType::SOA
    );
    assert_eq!(
        transfer.answers.last().unwrap().record_type(),
        RecordType::SOA
    );
    let mut ixfr = axfr("dyn.test.");
    ixfr.queries[0].set_query_type(RecordType::IXFR);
    assert_eq!(
        signed(bind, ixfr, &xfr, true).await.metadata.response_code,
        ResponseCode::NoError
    );
    assert_eq!(
        signed(bind, axfr("static.test."), &xfr, true)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    for (zone, signer) in [
        ("dyn.test.", &ddns),
        ("closed.test.", &xfr),
        ("static.test.", &ddns),
    ] {
        assert_eq!(
            signed(bind, axfr(zone), signer, true)
                .await
                .metadata
                .response_code,
            ResponseCode::Refused,
            "{zone}"
        );
    }
    assert_eq!(
        signed(bind, axfr("dyn.test."), &xfr, false)
            .await
            .metadata
            .response_code,
        ResponseCode::Refused,
        "transfers are TCP only"
    );
    let mut stream = TcpStream::connect(bind).await.unwrap();
    assert_eq!(
        framed(&mut stream, &axfr("dyn.test.").to_vec().unwrap())
            .await
            .metadata
            .response_code,
        ResponseCode::Refused
    );
    server.shutdown().await;

    // The journal keeps the change across a restart, with the file mode kept private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path("dyn.journal"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let bind = address("127.0.0.1");
    let mut server = RunningServer::start(build(bind)).await.unwrap();
    let again = udp(bind, &query("new.dyn.test.", RecordType::A)).await;
    assert_eq!(again.answers.len(), 1);
    // Delete the record again with the same scoped key.
    let mut owner_record = Record::from_rdata(
        Name::from_ascii(owner).unwrap(),
        0,
        hickory_proto::rr::RData::A(A("192.0.2.77".parse().unwrap())),
    );
    owner_record.dns_class = hickory_proto::rr::DNSClass::IN;
    let delete = hickory_proto::op::update_message::delete_rrset(
        owner_record,
        Name::from_ascii("dyn.test.").unwrap(),
        false,
    );
    assert_eq!(
        signed(bind, delete, &ddns, false)
            .await
            .metadata
            .response_code,
        ResponseCode::NoError
    );
    let gone = udp(bind, &query("new.dyn.test.", RecordType::A)).await;
    assert_eq!(gone.metadata.response_code, ResponseCode::NXDomain);
    server.shutdown().await;
}

async fn served_certificate(address: SocketAddr, trusted: &CertificateDer<'static>) -> Vec<u8> {
    let stream = TcpStream::connect(address).await.unwrap();
    let stream = TlsConnector::from(Arc::new(client_tls(trusted.clone(), b"dot")))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    stream.get_ref().1.peer_certificates().unwrap()[0].to_vec()
}

fn write_pair(directory: &std::path::Path) -> CertificateDer<'static> {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(directory.join("cert.pem"), cert.pem()).unwrap();
    std::fs::write(directory.join("key.pem"), signing_key.serialize_pem()).unwrap();
    cert.der().clone()
}

#[tokio::test]
async fn renewed_certificates_replace_the_served_pair_without_a_restart() {
    let upstream = fixture().await;
    let (directory, first) = certificates();
    let bind = address("127.0.0.1");
    let mut cfg = config(upstream.address, bind);
    cfg.listen.udp.clear();
    cfg.listen.tcp.clear();
    let dot = address("127.0.0.1");
    cfg.listen.dot = vec![dot];
    cfg.listen.certificate = Some(directory.path().join("cert.pem"));
    cfg.listen.private_key = Some(directory.path().join("key.pem"));
    let mut server = RunningServer::start(cfg).await.unwrap();
    assert_eq!(served_certificate(dot, &first).await, first.to_vec());
    assert_eq!(server.reload_certificates(), lumen_core::Reload::Unchanged);
    assert!(
        server
            .metrics
            .render()
            .contains("lumen_dns_certificate_not_after_timestamp_seconds")
    );

    // A renewal takes effect for the next connection.
    let second = write_pair(directory.path());
    assert!(matches!(
        server.reload_certificates(),
        lumen_core::Reload::Replaced(not_after) if not_after > 0
    ));
    assert_eq!(served_certificate(dot, &second).await, second.to_vec());

    // A half-written or mismatched pair is rejected and the good pair keeps serving.
    std::fs::write(directory.path().join("cert.pem"), "not a certificate").unwrap();
    assert_eq!(server.reload_certificates(), lumen_core::Reload::Rejected);
    assert_eq!(server.reload_certificates(), lumen_core::Reload::Unchanged);
    assert_eq!(served_certificate(dot, &second).await, second.to_vec());
    std::fs::write(
        directory.path().join("cert.pem"),
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(first.as_ref())
        ),
    )
    .unwrap();
    assert_eq!(server.reload_certificates(), lumen_core::Reload::Rejected);
    assert_eq!(served_certificate(dot, &second).await, second.to_vec());

    // Fixing the files recovers on the next check.
    let third = write_pair(directory.path());
    assert!(matches!(
        server.reload_certificates(),
        lumen_core::Reload::Replaced(_)
    ));
    assert_eq!(served_certificate(dot, &third).await, third.to_vec());
    let metrics = server.metrics.render();
    assert!(metrics.contains("lumen_dns_certificate_reloads_total 2"));
    assert!(metrics.contains("lumen_dns_certificate_reload_failures_total 2"));
    server.shutdown().await;
}

#[tokio::test]
async fn https_records_keep_their_ech_configuration_end_to_end() {
    use hickory_proto::rr::{
        RData,
        rdata::svcb::{SvcParamKey, SvcParamValue},
    };
    let upstream = fixture().await;
    let bind = address("127.0.0.1");
    let mut cfg = config(upstream.address, bind);
    // base64 of the bytes 00 07 fe 0d 01 02 03, a minimal ECHConfigList shape.
    let ech = [0u8, 7, 0xfe, 0x0d, 1, 2, 3];
    let mut text = zone_text("svc.test", "192.0.2.1");
    text.push_str("svc.test. 60 IN HTTPS 1 Pool.SVC.test. alpn=h2,h3 ech=AAf+DQECAw==\n");
    cfg.zones = vec![lumen_config::Zone {
        name: "svc.test".into(),
        text: Some(text),
        ..Default::default()
    }];
    let mut server = RunningServer::start(cfg).await.unwrap();
    // The first answer is built live and the second is repeated, which is where
    // a cache or a name rewrite could alter the record.
    for _ in 0..2 {
        let reply = udp(bind, &query("svc.test.", RecordType::HTTPS)).await;
        assert!(reply.metadata.authoritative);
        let svcb = reply
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RData::HTTPS(value) => Some(&value.0),
                _ => None,
            })
            .expect("HTTPS answer");
        assert_eq!(svcb.target_name.to_ascii(), "pool.svc.test.");
        let has_ech = svcb.svc_params.iter().any(|(key, value)| {
            *key == SvcParamKey::EchConfigList
                && matches!(value, SvcParamValue::EchConfigList(list) if list.0 == ech)
        });
        assert!(has_ech, "ECH configuration was altered: {svcb:?}");
        assert!(
            svcb.svc_params
                .iter()
                .any(|(key, _)| *key == SvcParamKey::Alpn)
        );
    }
    server.shutdown().await;
}

fn dnssec_query(name: &str, kind: RecordType) -> Vec<u8> {
    let mut query = Message::query();
    query.metadata.id = 4321;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(1232);
    query.edns = Some(edns);
    query.to_vec().unwrap()
}

#[tokio::test]
async fn signed_zones_serve_verifiable_signatures_and_proofs_of_absence() {
    use hickory_proto::dnssec::{Verifier, rdata::DNSSECRData};
    use hickory_proto::rr::{DNSClass, RData};
    let upstream = fixture().await;
    let bind = address("127.0.0.1");
    let dir = std::env::temp_dir().join(format!("lumen-signed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let key_file = dir.join("zone.pem");
    let description = lumen_resolver::zone_key(
        &key_file,
        "signed.test",
        lumen_config::SigningAlgorithm::Ed25519,
    )
    .unwrap();
    assert!(description.contains("IN DS "));
    let mut cfg = config(upstream.address, bind);
    cfg.zones = vec![lumen_config::Zone {
        name: "signed.test".into(),
        text: Some(zone_text("signed.test", "192.0.2.1")),
        dnssec: Some(lumen_config::ZoneSigning {
            key_file,
            ..Default::default()
        }),
        ..Default::default()
    }];
    let mut server = RunningServer::start(cfg).await.unwrap();

    // The zone's own DNSKEY, then a signature over the A set that it must verify.
    let keys = udp(bind, &dnssec_query("signed.test.", RecordType::DNSKEY)).await;
    let dnskey = keys
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => Some(key.clone()),
            _ => None,
        })
        .expect("DNSKEY served");
    let reply = udp(bind, &dnssec_query("host.signed.test.", RecordType::A)).await;
    assert!(reply.metadata.authoritative);
    let set: Vec<_> = reply
        .answers
        .iter()
        .filter(|record| record.record_type() == RecordType::A)
        .collect();
    let sig = reply
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => Some(sig.clone()),
            _ => None,
        })
        .expect("RRSIG with the answer");
    assert_eq!(sig.input().key_tag, dnskey.calculate_key_tag().unwrap());
    dnskey
        .verify_rrsig(
            &Name::from_ascii("host.signed.test.").unwrap(),
            DNSClass::IN,
            &sig,
            set.iter().copied(),
        )
        .expect("signature verifies against the zone key");

    // A name that does not exist comes with NSEC and its signature.
    let missing = udp(bind, &dnssec_query("nope.signed.test.", RecordType::A)).await;
    assert_eq!(
        missing.metadata.response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );
    assert!(
        missing
            .authorities
            .iter()
            .any(|r| r.record_type() == RecordType::NSEC)
    );
    assert!(
        missing
            .authorities
            .iter()
            .any(|r| r.record_type() == RecordType::RRSIG)
    );

    // A client that did not ask for DNSSEC data gets none.
    let plain = udp(bind, &query("host.signed.test.", RecordType::A)).await;
    assert!(
        plain
            .answers
            .iter()
            .all(|r| r.record_type() != RecordType::RRSIG)
    );
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

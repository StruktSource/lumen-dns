// SPDX-License-Identifier: Apache-2.0
//! An isolated DNS hierarchy. Port mapping exists only in this test runtime.
#![allow(clippy::too_many_lines)]
use super::*;
use hickory_server::proto::op::Query as DnsQuery;
use hickory_server::resolver::config::ProtocolConfig;
use hickory_server::{
    net::runtime::{DnsUdpSocket, RuntimeProvider, TokioTime},
    proto::{
        op::{Message, ResponseCode},
        rr::{
            RData,
            rdata::{A, NS},
        },
    },
};
use lumen_config::{Prefetch, Upstream, Warm};
use std::time::Instant;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{net::UdpSocket, task::JoinSet, time::timeout};

#[derive(Clone)]
struct TestRuntime {
    inner: TokioRuntimeProvider,
    mapping: Arc<HashMap<IpAddr, SocketAddr>>,
}
struct TestUdp {
    inner: UdpSocket,
    mapping: Arc<HashMap<IpAddr, SocketAddr>>,
}

impl RuntimeProvider for TestRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = TokioTime;
    type Udp = TestUdp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }
    fn connect_tcp(
        &self,
        address: SocketAddr,
        bind: Option<SocketAddr>,
        deadline: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let mapped = self
            .mapping
            .get(&address.ip())
            .copied()
            .expect("all test DNS stays local");
        self.inner.connect_tcp(mapped, bind, deadline)
    }
    fn bind_udp(
        &self,
        local: SocketAddr,
        _: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let mapping = Arc::clone(&self.mapping);
        Box::pin(async move {
            Ok(TestUdp {
                inner: UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, local.port())).await?,
                mapping,
            })
        })
    }
}

#[test]
fn custom_doh_path_reaches_engine_config() {
    let upstream = Upstream {
        address: "76.76.2.11:443".parse().unwrap(),
        protocol: UpstreamProtocol::Https,
        server_name: Some("freedns.controld.com".into()),
        doh_path: Some("/uncensored".into()),
    };
    let server = name_server_config(&upstream, false);
    assert_eq!(server.connections[0].port, 443);
    assert!(matches!(
        &server.connections[0].protocol,
        ProtocolConfig::Https { server_name, path }
            if server_name.as_ref() == "freedns.controld.com" && path.as_ref() == "/uncensored"
    ));
}
#[async_trait]
impl DnsUdpSocket for TestUdp {
    type Time = TokioTime;
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let mut buffer = tokio::io::ReadBuf::new(bytes);
        match self.inner.poll_recv_from(cx, &mut buffer) {
            Poll::Ready(Ok(actual)) => {
                let ip = self
                    .mapping
                    .iter()
                    .find(|(_, address)| **address == actual)
                    .map(|(ip, _)| *ip)
                    .expect("known test server");
                Poll::Ready(Ok((buffer.filled().len(), SocketAddr::new(ip, 53))))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        match self.mapping.get(&target.ip()) {
            Some(mapped) => self.inner.poll_send_to(cx, bytes, *mapped),
            None => Poll::Ready(Err(io::Error::other("unexpected test nameserver"))),
        }
    }
}

fn record(name: &str, data: RData) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), 60, data)
}

fn hierarchy_reply(request: Message, role: usize) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.queries = request.queries;
    response.edns = request.edns;
    let query = &response.queries[0];
    let name = query.name().to_ascii().to_lowercase();
    let (zone, ns, ip) = match role {
        0 => (".", "a.root.", A::new(198, 41, 0, 4)),
        1 => ("test.", "ns.test.", A::new(192, 0, 2, 2)),
        _ => ("example.test.", "ns.example.test.", A::new(192, 0, 2, 3)),
    };
    if name == zone && query.query_type() == RecordType::NS {
        response.metadata.authoritative = true;
        response.add_answer(record(zone, RData::NS(NS(Name::from_ascii(ns).unwrap()))));
        response.add_additional(record(ns, RData::A(ip)));
    } else if role < 2 {
        let (child, ns, ip) = if role == 0 {
            ("test.", "ns.test.", A::new(192, 0, 2, 2))
        } else {
            ("example.test.", "ns.example.test.", A::new(192, 0, 2, 3))
        };
        response.add_authority(record(child, RData::NS(NS(Name::from_ascii(ns).unwrap()))));
        response.add_additional(record(ns, RData::A(ip)));
        // This unrelated glue must never become trusted cache data.
        response.add_additional(record("poison.other.", RData::A(A::new(203, 0, 113, 99))));
    } else if name == "www.example.test." && query.query_type() == RecordType::A {
        response.metadata.authoritative = true;
        response.add_answer(record(&name, RData::A(A::new(203, 0, 113, 42))));
    } else if name == "ns.example.test." {
        response.metadata.authoritative = true;
        response.add_answer(record(&name, RData::A(ip)));
    } else {
        response.metadata.authoritative = true;
        if name != "www.example.test." {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        response.add_authority(record(
            "example.test.",
            RData::SOA(hickory_server::proto::rr::rdata::SOA::new(
                Name::from_ascii("ns.example.test.").unwrap(),
                Name::from_ascii("hostmaster.example.test.").unwrap(),
                1,
                60,
                60,
                60,
                60,
            )),
        ));
    }
    response
}

#[tokio::test]
async fn iterative_delegations_cache_and_depth_limit() {
    let mut tasks = JoinSet::new();
    let mut mapping = HashMap::new();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for (role, ip) in ["198.41.0.4", "192.0.2.2", "192.0.2.3"].iter().enumerate() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        mapping.insert(ip.parse().unwrap(), socket.local_addr().unwrap());
        let hits = Arc::clone(&hits);
        tasks.spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let request = Message::from_vec(&buffer[..size]).unwrap();
                let bytes = hierarchy_reply(request, role).to_vec().unwrap();
                socket.send_to(&bytes, peer).await.unwrap();
            }
        });
    }
    let provider = TestRuntime {
        inner: TokioRuntimeProvider::default(),
        mapping: Arc::new(mapping),
    };
    let options = RecursorOptions {
        deny_server: vec![],
        case_randomization: true,
        recursion_limit: 8,
        ns_recursion_limit: 8,
        response_cache_size: 8,
        ns_cache_size: 8,
        ..RecursorOptions::default()
    };
    let recursor = Recursor::new(
        &["198.41.0.4".parse().unwrap()],
        DnssecPolicy::ValidationDisabled,
        None,
        options.clone(),
        provider.clone(),
    )
    .unwrap();
    let mut catalog = Catalog::new();
    catalog.upsert(
        Name::root().into(),
        vec![Arc::new(ResolutionZone {
            origin: Name::root().into(),
            backend: Backend::Recursive {
                recursor: Arc::new(recursor),
                fallback: None,
                accel: Arc::new(Accel::new(Arc::default(), Prefetch::default())),
            },
        })],
    );
    let resolver = Resolver {
        catalog,
        metrics: Arc::new(Metrics::default()),
        background: None,
    };
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(DnsQuery::query(
        Name::from_ascii("www.example.test.").unwrap(),
        RecordType::A,
    ));
    let query = Query::parse(&request.to_vec().unwrap()).unwrap();
    let response = timeout(
        Duration::from_secs(3),
        resolver.answer(
            &query,
            "127.0.0.1:12345".parse().unwrap(),
            Transport::Udp,
            4096,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let response = Message::from_vec(&response).unwrap();
    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "{response:?}"
    );
    assert!(
        response
            .answers
            .iter()
            .any(|record| record.data == RData::A(A::new(203, 0, 113, 42)))
    );
    assert!(
        response
            .additionals
            .iter()
            .all(|record| record.name != Name::from_ascii("poison.other.").unwrap())
    );
    let before = hits.load(std::sync::atomic::Ordering::Relaxed);
    let _ = resolver
        .answer(
            &query,
            "127.0.0.1:12345".parse().unwrap(),
            Transport::Udp,
            4096,
        )
        .await
        .unwrap();
    assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), before);
    let mut poison_request = Message::query();
    poison_request.metadata.recursion_desired = true;
    poison_request.add_query(DnsQuery::query(
        Name::from_ascii("poison.other.").unwrap(),
        RecordType::A,
    ));
    let poison_query = Query::parse(&poison_request.to_vec().unwrap()).unwrap();
    let poison = timeout(
        Duration::from_secs(3),
        resolver.answer(
            &poison_query,
            "127.0.0.1:12345".parse().unwrap(),
            Transport::Udp,
            4096,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        Message::from_vec(&poison)
            .unwrap()
            .answers
            .iter()
            .all(|record| record.data != RData::A(A::new(203, 0, 113, 99)))
    );
    assert!(hits.load(std::sync::atomic::Ordering::Relaxed) > before);
    let limited = Recursor::new(
        &["198.41.0.4".parse().unwrap()],
        DnssecPolicy::ValidationDisabled,
        None,
        RecursorOptions {
            recursion_limit: 0,
            ns_recursion_limit: 0,
            ..options
        },
        provider,
    )
    .unwrap();
    assert!(
        timeout(
            Duration::from_secs(3),
            limited.resolve(
                DnsQuery::query(
                    Name::from_ascii("www.example.test.").unwrap(),
                    RecordType::A
                ),
                Instant::now(),
                false
            )
        )
        .await
        .unwrap()
        .is_err()
    );
    tasks.abort_all();
}

#[tokio::test]
async fn recursion_timeout_invokes_fallback_once() {
    let recursive_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fallback_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut mapping = HashMap::new();
    mapping.insert(
        "198.41.0.4".parse().unwrap(),
        recursive_socket.local_addr().unwrap(),
    );
    mapping.insert(
        "203.0.113.53".parse().unwrap(),
        fallback_socket.local_addr().unwrap(),
    );
    let provider = TestRuntime {
        inner: TokioRuntimeProvider::default(),
        mapping: Arc::new(mapping),
    };
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let _ = recursive_socket.recv_from(&mut buffer).await.unwrap();
        }
    });
    tasks.spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (size, peer) = fallback_socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..size]).unwrap();
            let mut response = Message::response(request.metadata.id, request.metadata.op_code);
            response.metadata.recursion_available = true;
            response.queries = request.queries;
            let name = response.queries[0].name().clone();
            response.add_answer(record(&name.to_ascii(), RData::A(A::new(203, 0, 113, 77))));
            fallback_socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let recursor = Recursor::new(
        &["198.41.0.4".parse().unwrap()],
        DnssecPolicy::ValidationDisabled,
        None,
        RecursorOptions {
            deny_server: vec![],
            ..RecursorOptions::default()
        },
        provider.clone(),
    )
    .unwrap();
    let server = NameServerConfig::udp_and_tcp("203.0.113.53".parse().unwrap());
    let mut options = ResolverOpts::default();
    options.validate = false;
    options.attempts = 1;
    options.timeout = Duration::from_millis(250);
    options.use_hosts_file = ResolveHosts::Never;
    let forward = hickory_server::resolver::Resolver::builder_with_config(
        ResolverConfig::from_parts(None, vec![], vec![server]),
        provider,
    )
    .with_options(options)
    .build()
    .unwrap();
    let metrics = Arc::new(Metrics::default());
    let mut catalog = Catalog::new();
    catalog.upsert(
        Name::root().into(),
        vec![Arc::new(ResolutionZone {
            origin: Name::root().into(),
            backend: Backend::Recursive {
                recursor: Arc::new(recursor),
                accel: Arc::new(Accel::new(Arc::clone(&metrics), Prefetch::default())),
                fallback: Some(FallbackBackend {
                    resolver: Box::new(forward),
                    recursive_timeout: Duration::from_millis(30),
                    timeout: Duration::from_millis(250),
                    metrics: Arc::clone(&metrics),
                }),
            },
        })],
    );
    let resolver = Resolver {
        catalog,
        metrics: Arc::clone(&metrics),
        background: None,
    };
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(DnsQuery::query(
        Name::from_ascii("fallback.example.").unwrap(),
        RecordType::A,
    ));
    let query = Query::parse(&request.to_vec().unwrap()).unwrap();
    let bytes = timeout(
        Duration::from_secs(1),
        resolver.answer(
            &query,
            "127.0.0.1:12345".parse().unwrap(),
            Transport::Udp,
            4096,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let response = Message::from_vec(&bytes).unwrap();
    assert!(
        response
            .answers
            .iter()
            .any(|answer| answer.data == RData::A(A::new(203, 0, 113, 77)))
    );
    assert_eq!(metrics.attempts.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.successes.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.failures.load(Ordering::Relaxed), 0);
    assert_eq!(metrics.timeout_triggers.load(Ordering::Relaxed), 1);
    tasks.abort_all();
}

#[test]
fn only_timeout_errors_are_fallback_eligible() {
    use hickory_server::resolver::recursor::RecursorError;
    assert!(recursion_timed_out(&RecursorError::Timeout));
    assert!(recursion_timed_out(&RecursorError::Net(NetError::Timeout)));
    assert!(!recursion_timed_out(
        &RecursorError::RecursionLimitExceeded { count: 1 }
    ));
    assert!(!recursion_timed_out(&RecursorError::QueryBudgetExceeded));
}

#[tokio::test]
async fn bundled_roots_and_default_dnssec_build() {
    let config = Config {
        schema_version: 1,
        ..Config::default()
    };
    assert!(Resolver::new(&config).is_ok());
    let hints = include_str!("../data/root.hints");
    assert!(hints.contains("AAAA"));
    assert!(hints.contains("198.41.0.4"));
    assert!(TrustAnchors::default().len() >= 2);
}

/// Local root, `test.`, and `example.test.` servers. `delay` slows every reply.
async fn hierarchy(
    delay: Duration,
) -> (
    JoinSet<()>,
    TestRuntime,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut tasks = JoinSet::new();
    let mut mapping = HashMap::new();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for (role, ip) in ["198.41.0.4", "192.0.2.2", "192.0.2.3"].iter().enumerate() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        mapping.insert(ip.parse().unwrap(), socket.local_addr().unwrap());
        let hits = Arc::clone(&hits);
        tasks.spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let request = Message::from_vec(&buffer[..size]).unwrap();
                let bytes = hierarchy_reply(request, role).to_vec().unwrap();
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = socket.send_to(&bytes, peer).await;
                });
            }
        });
    }
    let provider = TestRuntime {
        inner: TokioRuntimeProvider::default(),
        mapping: Arc::new(mapping),
    };
    (tasks, provider, hits)
}

fn test_recursor(provider: TestRuntime) -> Arc<Recursor<TestRuntime>> {
    Arc::new(
        Recursor::new(
            &["198.41.0.4".parse().unwrap()],
            DnssecPolicy::ValidationDisabled,
            None,
            RecursorOptions {
                deny_server: vec![],
                case_randomization: true,
                recursion_limit: 8,
                ns_recursion_limit: 8,
                response_cache_size: 64,
                ns_cache_size: 64,
                ..RecursorOptions::default()
            },
            provider,
        )
        .unwrap(),
    )
}

fn www_example() -> LowerName {
    LowerName::from(Name::from_ascii("www.example.test.").unwrap())
}

#[tokio::test]
async fn identical_concurrent_queries_share_one_recursion() {
    let (mut single_tasks, provider, single_hits) = hierarchy(Duration::from_millis(40)).await;
    let accel = Accel::new(Arc::default(), Prefetch::default());
    let recursor = test_recursor(provider);
    accel
        .resolve(&recursor, &www_example(), RecordType::A, false, false)
        .await
        .unwrap();
    let one = single_hits.load(std::sync::atomic::Ordering::Relaxed);
    single_tasks.abort_all();

    let (mut tasks, provider, hits) = hierarchy(Duration::from_millis(40)).await;
    let metrics = Arc::new(Metrics::default());
    let accel = Arc::new(Accel::new(Arc::clone(&metrics), Prefetch::default()));
    let recursor = test_recursor(provider);
    let mut jobs = JoinSet::new();
    for _ in 0..24 {
        let (accel, recursor) = (Arc::clone(&accel), Arc::clone(&recursor));
        jobs.spawn(async move {
            accel
                .resolve(&recursor, &www_example(), RecordType::A, false, false)
                .await
                .map(|message| message.answers.len())
        });
    }
    while let Some(result) = jobs.join_next().await {
        assert_eq!(result.unwrap().unwrap(), 1);
    }
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::Relaxed),
        one,
        "24 identical concurrent queries must cost one recursion"
    );
    assert_eq!(metrics.coalesced.load(Ordering::Relaxed), 23);
    assert!(lock_flights_empty(&accel));
    tasks.abort_all();
}

fn lock_flights_empty(accel: &Accel) -> bool {
    accel.flights.lock().unwrap().is_empty()
}

#[tokio::test]
async fn cancelled_leader_does_not_strand_waiters() {
    let (mut tasks, provider, _) = hierarchy(Duration::from_millis(300)).await;
    let accel = Arc::new(Accel::new(Arc::default(), Prefetch::default()));
    let recursor = test_recursor(provider);
    let leader = {
        let (accel, recursor) = (Arc::clone(&accel), Arc::clone(&recursor));
        tokio::spawn(async move {
            let _ = timeout(
                Duration::from_millis(100),
                accel.resolve(&recursor, &www_example(), RecordType::A, false, false),
            )
            .await;
        })
    };
    tokio::time::sleep(Duration::from_millis(30)).await;
    let waiter = timeout(
        Duration::from_secs(8),
        accel.resolve(&recursor, &www_example(), RecordType::A, false, false),
    )
    .await
    .expect("waiter must not hang on an abandoned flight")
    .unwrap();
    assert_eq!(waiter.answers.len(), 1);
    leader.await.unwrap();
    assert!(lock_flights_empty(&accel));
    tasks.abort_all();
}

#[tokio::test]
async fn different_query_types_and_dnssec_flags_do_not_share() {
    let (mut tasks, provider, _) = hierarchy(Duration::from_millis(20)).await;
    let accel = Arc::new(Accel::new(Arc::default(), Prefetch::default()));
    let recursor = test_recursor(provider);
    let name = www_example();
    let a = accel.resolve(&recursor, &name, RecordType::A, false, false);
    let a_do = accel.resolve(&recursor, &name, RecordType::A, true, false);
    let (a, a_do) = tokio::join!(a, a_do);
    assert!(a.is_ok() && a_do.is_ok());
    assert_eq!(accel.metrics.coalesced.load(Ordering::Relaxed), 0);
    tasks.abort_all();
}

fn hot_accel(prefetch: Prefetch) -> Accel {
    Accel::new(Arc::default(), prefetch)
}

fn answer_with_ttl(ttl: u32) -> Message {
    let mut message = Message::query();
    message.add_answer(Record::from_rdata(
        Name::from_ascii("www.example.test.").unwrap(),
        ttl,
        RData::A(A::new(203, 0, 113, 42)),
    ));
    message
}

fn due_now(accel: &Accel, key: &accel::Key) {
    let mut hot = accel.hot.lock().unwrap();
    hot.entries.get_mut(key).unwrap().refresh_at = Some(Instant::now());
}

#[test]
fn refresh_needs_hits_inside_one_cache_window() {
    let accel = hot_accel(Prefetch {
        enabled: true,
        min_hits: 2,
        ..Prefetch::default()
    });
    let key = (www_example(), RecordType::A, false);
    let permits = tokio::sync::Semaphore::new(4);

    accel.touch(&key); // first sighting does not count
    accel.schedule(&key, &answer_with_ttl(60));
    // Lookups served from the same cache entry keep one window and keep counting.
    accel.touch(&key);
    accel.schedule(&key, &answer_with_ttl(59));
    due_now(&accel, &key);
    assert!(accel.due(&permits).is_empty(), "one hit is below min_hits");
    assert!(accel.hot.lock().unwrap().entries.is_empty());

    accel.touch(&key);
    accel.schedule(&key, &answer_with_ttl(60));
    accel.touch(&key);
    accel.touch(&key);
    accel.schedule(&key, &answer_with_ttl(58));
    due_now(&accel, &key);
    assert_eq!(accel.due(&permits), vec![key.clone()]);
    // Launched entries wait for their refreshed answer instead of repeating.
    assert!(accel.due(&permits).is_empty());
}

#[test]
fn refresh_obeys_short_ttl_budget_and_tracking_bounds() {
    let accel = hot_accel(Prefetch {
        enabled: true,
        min_hits: 1,
        max_tracked: 16,
        budget_per_minute: 2,
        ..Prefetch::default()
    });
    let permits = tokio::sync::Semaphore::new(16);
    let name = |n: usize| {
        (
            LowerName::from(Name::from_ascii(format!("n{n}.example.test.")).unwrap()),
            RecordType::A,
            false,
        )
    };
    // Very short answers are never scheduled.
    let short = name(100);
    accel.touch(&short);
    accel.schedule(&short, &answer_with_ttl(5));
    assert!(
        accel.hot.lock().unwrap().entries[&short]
            .refresh_at
            .is_none()
    );

    for n in 0..4 {
        let key = name(n);
        accel.touch(&key);
        accel.schedule(&key, &answer_with_ttl(60));
        accel.touch(&key);
        due_now(&accel, &key);
    }
    assert_eq!(
        accel.due(&permits).len(),
        2,
        "per-minute budget caps starts"
    );
    assert_eq!(accel.metrics.prefetch_skipped.load(Ordering::Relaxed), 2);

    for n in 0..40 {
        accel.touch(&name(1000 + n));
    }
    assert!(accel.hot.lock().unwrap().entries.len() <= 16);
}

#[tokio::test]
async fn disabled_prefetch_tracks_nothing() {
    let accel = hot_accel(Prefetch::default());
    let key = (www_example(), RecordType::A, false);
    accel.touch(&key);
    accel.schedule(&key, &answer_with_ttl(60));
    assert!(accel.hot.lock().unwrap().entries.is_empty());
}

#[tokio::test]
async fn warm_primes_listed_zones_once_and_uses_no_client_data() {
    let (mut tasks, provider, hits) = hierarchy(Duration::ZERO).await;
    let metrics = Arc::new(Metrics::default());
    let accel = Arc::new(Accel::new(Arc::clone(&metrics), Prefetch::default()));
    let recursor = test_recursor(provider);
    let warm = Warm {
        enabled: true,
        zones: vec!["test".into(), "example.test".into()],
    };
    accel.start(&recursor, &warm);
    accel.start(&recursor, &warm); // a second start is ignored
    timeout(Duration::from_secs(8), async {
        while metrics.warm_queries.load(Ordering::Relaxed) < 6 || lock_flights_busy(&accel) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("root plus two zones, NS and DNSKEY each");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(metrics.warm_queries.load(Ordering::Relaxed), 6);
    assert!(hits.load(std::sync::atomic::Ordering::Relaxed) > 0);
    accel.stop();
    tasks.abort_all();
}

fn lock_flights_busy(accel: &Accel) -> bool {
    !lock_flights_empty(accel)
}

#[test]
fn latency_histogram_is_cumulative_and_fixed_cardinality() {
    let metrics = Metrics::default();
    metrics.observe(Duration::from_micros(400));
    metrics.observe(Duration::from_millis(30));
    metrics.observe(Duration::from_secs(9));
    let text = metrics.render();
    let name = "lumen_dns_recursive_lookup_duration_seconds";
    assert!(text.contains(&format!("{name}_bucket{{le=\"0.001\"}} 1\n")));
    assert!(text.contains(&format!("{name}_bucket{{le=\"0.05\"}} 2\n")));
    assert!(text.contains(&format!("{name}_bucket{{le=\"+Inf\"}} 3\n")));
    assert!(text.contains(&format!("{name}_count 3\n")));
    assert_eq!(text.matches("_bucket{").count(), 11);
}

#[tokio::test]
async fn slow_lookup_starts_one_hedge_and_fast_lookup_does_not() {
    let (mut tasks, provider, _) = hierarchy(Duration::from_millis(250)).await;
    let metrics = Arc::new(Metrics::default());
    let accel = Accel::new(Arc::clone(&metrics), Prefetch::default()).with_hedge(100);
    let recursor = test_recursor(provider);
    let name = www_example();
    let answer = accel
        .resolve(&recursor, &name, RecordType::A, false, false)
        .await
        .unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(metrics.hedged.load(Ordering::Relaxed), 1);
    // Cached now: far below the hedge delay, so no second recursion.
    accel
        .resolve(&recursor, &name, RecordType::A, false, false)
        .await
        .unwrap();
    assert_eq!(metrics.hedged.load(Ordering::Relaxed), 1);
    tasks.abort_all();
}

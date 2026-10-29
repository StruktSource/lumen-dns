// SPDX-License-Identifier: Apache-2.0
//! An isolated DNS hierarchy. Port mapping exists only in this test runtime.
#![allow(clippy::too_many_lines)]
use super::*;
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
            backend: Backend::Recursive(Box::new(recursor)),
        })],
    );
    let resolver = Resolver { catalog };
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

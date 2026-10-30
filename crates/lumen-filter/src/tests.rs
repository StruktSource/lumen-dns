// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::unwrap_used, clippy::too_many_lines)]
use super::*;
use config::*;
use rules::*;

fn list(id: &str, text: &str, category: Option<&str>) -> List {
    List {
        id: id.into(),
        text: Some(text.into()),
        path: None,
        url: None,
        format: Format::Domains,
        category: category.map(str::to_owned),
        refresh_secs: 0,
    }
}
fn ip() -> IpAddr {
    "192.0.2.10".parse().unwrap()
}

#[test]
fn domain_normalization_and_strict_parsers() {
    assert_eq!(
        normalize("BÜCHER.Example.").unwrap(),
        "xn--bcher-kva.example"
    );
    assert_eq!(
        Rule::parse("=WWW.Example.", true).unwrap().domain,
        "www.example"
    );
    for value in [
        "",
        ".",
        "foo..com",
        "example.com/path",
        "foo:53",
        "-bad.com",
        "foo$bar",
        "a\\046com",
        "a\nb",
    ] {
        assert!(Rule::parse(value, false).is_err(), "{value}");
    }
    let parsed = parse(
        b"# comment\nEXAMPLE.org.\nexample.org # dup\n=only.example\n",
        Format::Domains,
    )
    .unwrap();
    assert_eq!(parsed.rules.len(), 2);
    assert_eq!(parsed.duplicates, 1);
    assert!(parsed.rules[1].exact);
    assert_eq!(
        parse(
            b"0.0.0.0 a.example b.example # comment\n::1 ipv6.example",
            Format::Hosts
        )
        .unwrap()
        .rules
        .len(),
        3
    );
    assert!(parse(b"192.0.2.1 real.example", Format::Hosts).is_err());
    assert!(parse(b"0.0.0.0", Format::Hosts).is_err());
    let parsed = parse(b"[Adblock Plus 2.0]\n! title\n||ads.example^\n@@||ok.ads.example^\n||ads.example^$script\nexample##.ad\n/regex/", Format::Adblock).unwrap();
    assert_eq!(parsed.rules.len(), 2);
    assert!(parsed.rules[1].allow);
    assert_eq!(parsed.unsupported, 3);
    for bytes in [&b""[..], &b"# empty"[..], &b"\xff"[..]] {
        assert!(parse(bytes, Format::Domains).is_err());
    }
    assert!(parse(&vec![b'a'; MAX_LIST_BYTES + 1], Format::Domains).is_err());
    assert!(parse(&vec![b'a'; 4097], Format::Domains).is_err());
    assert!(parse(b"/unsupported/", Format::Adblock).is_err());
}

#[tokio::test]
async fn precedence_suffix_boundaries_and_decision_evidence() {
    let config = Config {
        rules: Rules {
            allow: vec!["safe.ads.example".into()],
            block: vec!["=exact.example".into()],
        },
        lists: vec![list("ads", "ads.example\ntracking.example", None)],
        ..Config::default()
    };
    let filter = Filter::load(config).await.unwrap();
    let blocked = filter.explain("Sub.ADS.example.", ip(), 0);
    assert!(blocked.blocked);
    assert_eq!(blocked.list.as_deref(), Some("ads"));
    assert_eq!(blocked.rule.as_deref(), Some("ads.example"));
    assert_eq!(blocked.action, Some(Action::Nxdomain));
    assert!(!filter.explain("safe.ads.example", ip(), 0).blocked);
    assert!(!filter.explain("notads.example", ip(), 0).blocked);
    assert!(filter.explain("exact.example", ip(), 0).blocked);
    assert!(!filter.explain("sub.exact.example", ip(), 0).blocked);
    assert_eq!(filter.metrics.blocked.load(Ordering::Relaxed), 0);
    let _ = filter.decide("ads.example", ip(), 0);
    assert_eq!(filter.metrics.blocked.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn device_group_subnet_default_category_and_override() {
    let config = Config {
        rules: Rules {
            allow: vec!["global.example".into()],
            block: vec!["ads.example".into()],
        },
        lists: vec![
            list("adult", "adult.example", Some("adult")),
            list("global", "malware.example", None),
        ],
        profiles: vec![
            Profile {
                id: "family".into(),
                categories: vec!["adult".into()],
                rules: Rules {
                    allow: vec!["ads.example".into()],
                    block: vec!["global.example".into()],
                },
                ..Profile::default()
            },
            Profile {
                id: "work".into(),
                ..Profile::default()
            },
            Profile {
                id: "guest".into(),
                lists: vec!["global".into()],
                ..Profile::default()
            },
        ],
        devices: vec![
            Device {
                id: "phone".into(),
                addresses: vec![ip()],
                profile: None,
                group: Some("kids".into()),
            },
            Device {
                id: "laptop".into(),
                addresses: vec!["192.0.2.11".parse().unwrap()],
                profile: Some("work".into()),
                group: Some("kids".into()),
            },
        ],
        groups: vec![Group {
            id: "kids".into(),
            profile: "family".into(),
        }],
        subnets: vec![
            Subnet {
                network: "192.0.0.0/16".parse().unwrap(),
                profile: "family".into(),
            },
            Subnet {
                network: "192.0.2.0/24".parse().unwrap(),
                profile: "work".into(),
            },
        ],
        default_profile: Some("guest".into()),
        ..Config::default()
    };
    let filter = Filter::load(config).await.unwrap();
    let d = filter.explain("adult.example", ip(), 0);
    assert!(d.blocked);
    assert_eq!(d.device.as_deref(), Some("phone"));
    assert_eq!(d.group.as_deref(), Some("kids"));
    assert_eq!(d.profile.as_deref(), Some("family"));
    assert_eq!(d.category.as_deref(), Some("adult"));
    assert!(!filter.explain("ads.example", ip(), 0).blocked);
    assert!(filter.explain("global.example", ip(), 0).blocked);
    let work = "192.0.2.11".parse().unwrap();
    assert!(!filter.explain("adult.example", work, 0).blocked);
    assert_eq!(
        filter
            .explain("adult.example", "192.0.2.12".parse().unwrap(), 0)
            .profile
            .as_deref(),
        Some("work")
    );
    assert_eq!(
        filter
            .explain("adult.example", "192.0.3.12".parse().unwrap(), 0)
            .profile
            .as_deref(),
        Some("family")
    );
    assert_eq!(
        filter
            .explain("adult.example", "2001:db8::1".parse().unwrap(), 0)
            .profile
            .as_deref(),
        Some("guest")
    );
    assert!(
        filter
            .explain("adult.example", "::ffff:192.0.2.10".parse().unwrap(), 0)
            .blocked
    );
}

#[test]
fn utc_schedules_boundaries_overnight_and_week_wrap() {
    // 1970-01-01 is Thursday. 1970-01-05 is Monday.
    let monday = 4 * 86400;
    let day = Schedule {
        days: vec![1],
        start_minute: 60,
        end_minute: 120,
    };
    assert!(!day.active(monday + 3599));
    assert!(day.active(monday + 3600));
    assert!(!day.active(monday + 7200));
    let night = Schedule {
        days: vec![7],
        start_minute: 1380,
        end_minute: 60,
    };
    assert!(night.active(3 * 86400 + 23 * 3600));
    assert!(night.active(monday));
    assert!(!night.active(monday + 3600));
    assert!(!night.active(monday + 23 * 3600));
}

#[tokio::test]
async fn schedules_disable_profile_not_global_rules() {
    let config = Config {
        rules: Rules {
            block: vec!["global.example".into()],
            ..Rules::default()
        },
        profiles: vec![Profile {
            id: "family".into(),
            rules: Rules {
                block: vec!["game.example".into()],
                ..Rules::default()
            },
            schedules: vec![Schedule {
                days: vec![4],
                start_minute: 60,
                end_minute: 120,
            }],
            ..Profile::default()
        }],
        default_profile: Some("family".into()),
        ..Config::default()
    };
    let filter = Filter::load(config).await.unwrap();
    assert!(!filter.explain("game.example", ip(), 0).blocked);
    assert!(filter.explain("game.example", ip(), 3600).blocked);
    assert!(filter.explain("global.example", ip(), 0).blocked);
}

#[tokio::test]
async fn atomic_refresh_failed_update_and_rollback() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("domains.txt");
    std::fs::write(&path, "old.example").unwrap();
    let mut source = list("local", "", None);
    source.path = Some(path.clone());
    source.text = None;
    let filter = Arc::new(
        Filter::load(Config {
            lists: vec![source],
            ..Config::default()
        })
        .await
        .unwrap(),
    );
    assert!(filter.rollback().await.is_err());
    assert!(!filter.refresh_due().await.unwrap());
    std::fs::write(&path, "new.example").unwrap();
    let reader = Arc::clone(&filter);
    let task = tokio::spawn(async move {
        for _ in 0..1000 {
            let decision = reader.explain("new.example", ip(), 0);
            assert_eq!(decision.blocked, decision.generation == 2);
            tokio::task::yield_now().await;
        }
    });
    filter.refresh().await.unwrap();
    task.await.unwrap();
    assert!(!filter.explain("old.example", ip(), 0).blocked);
    assert!(filter.explain("new.example", ip(), 0).blocked);
    std::fs::write(&path, "bad/url").unwrap();
    assert!(filter.refresh().await.is_err());
    assert!(filter.explain("new.example", ip(), 0).blocked);
    std::fs::write(&path, "").unwrap();
    assert!(filter.refresh().await.is_err());
    assert_eq!(filter.metrics.refresh_failures.load(Ordering::Relaxed), 2);
    filter.rollback().await.unwrap();
    assert!(filter.explain("old.example", ip(), 0).blocked);
    assert!(!filter.explain("new.example", ip(), 0).blocked);
    assert_eq!(filter.explain("old.example", ip(), 0).generation, 1);
}

#[test]
fn source_ssrf_and_schema_guards() {
    for url in [
        "http://example.org/list",
        "file:///tmp/a",
        "https://user:pass@example.org/a",
        "https://example.org:444/a",
        "https://example.org/a#fragment",
    ] {
        assert!(fetch::validate_url(url).is_err());
    }
    assert!(fetch::validate_url("https://example.org/list").is_ok());
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "172.16.1.1",
        "192.168.0.1",
        "100.64.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "224.0.0.1",
        "::1",
        "::ffff:8.8.8.8",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "2002:808:808::1",
    ] {
        assert!(!fetch::public_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "1.1.1.1",
        "8.8.8.8",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(fetch::public_ip(ip.parse().unwrap()));
    }
    assert!(toml::from_str::<Config>("unknown = true").is_err());
    let mut config = Config {
        default_profile: Some("missing".into()),
        ..Config::default()
    };
    assert!(config.validate().is_err());
    config.default_profile = None;
    config.lists = vec![
        list("same", "a.example", None),
        list("same", "b.example", None),
    ];
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn private_https_target_rejected_before_connect() {
    assert!(fetch::download("https://127.0.0.1/list").await.is_err());
    assert!(fetch::download("https://[::1]/list").await.is_err());
}

#[test]
fn block_response_contracts_and_truncation() {
    use lumen_proto::hickory_proto::{
        op::{Message, Query as Question, ResponseCode},
        rr::{Name, RecordType},
    };
    for (kind, action, code, answers) in [
        (RecordType::A, Action::Nxdomain, ResponseCode::NXDomain, 0),
        (RecordType::AAAA, Action::Nodata, ResponseCode::NoError, 0),
        (RecordType::A, Action::Refused, ResponseCode::Refused, 0),
        (
            RecordType::A,
            Action::Address {
                ipv4: Some("0.0.0.0".parse().unwrap()),
                ipv6: None,
            },
            ResponseCode::NoError,
            1,
        ),
        (
            RecordType::AAAA,
            Action::Address {
                ipv4: Some("0.0.0.0".parse().unwrap()),
                ipv6: None,
            },
            ResponseCode::NoError,
            0,
        ),
        (
            RecordType::TXT,
            Action::Cname {
                target: "sink.example".into(),
            },
            ResponseCode::NoError,
            1,
        ),
    ] {
        let mut message = Message::query();
        message.metadata.id = 42;
        message.metadata.recursion_desired = true;
        message.metadata.checking_disabled = true;
        message.add_query(Question::query(
            Name::from_ascii("blocked.example").unwrap(),
            kind,
        ));
        let query = lumen_proto::Query::parse(&message.to_vec().unwrap()).unwrap();
        let reply = Message::from_vec(&response(&query, &action, 4096)).unwrap();
        assert_eq!(reply.metadata.id, 42);
        assert_eq!(reply.metadata.response_code, code);
        assert_eq!(reply.answers.len(), answers);
        assert!(!reply.metadata.authentic_data);
        assert!(reply.metadata.recursion_available);
        assert!(reply.metadata.recursion_desired);
        assert!(reply.metadata.checking_disabled);
        assert!(reply.answers.iter().all(|r| r.ttl == 0));
    }
}

#[tokio::test]
async fn https_import_verifies_tls_and_bounds_responses() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let trusted = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let untrusted = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let cases = [
        (b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nads.example".to_vec(), true, true),
        (b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/secret\r\nContent-Length: 0\r\n\r\n".to_vec(), true, false),
        (b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n".to_vec(), true, false),
        (format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_LIST_BYTES + 1).into_bytes(), true, false),
        (b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".to_vec(), true, false),
        (b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nads.example".to_vec(), false, false),
        ({ let mut response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(); response.extend_from_slice(format!("{:x}\r\n", MAX_LIST_BYTES + 1).as_bytes()); response.extend(vec![b'a'; MAX_LIST_BYTES + 1]); response.extend_from_slice(b"\r\n0\r\n\r\n"); response }, true, false),
    ];
    for (response, trust, success) in cases {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = acceptor.clone();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let mut request = Vec::new();
                let mut byte = [0];
                while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
                    if tls.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                let _ = tls.write_all(&response).await;
                let _ = tls.shutdown().await;
            }
        });
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(if trust {
                trusted.clone()
            } else {
                untrusted.clone()
            })
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .resolve("localhost", address)
            .build()
            .unwrap();
        // Local fixture bypasses only production URL/address admission; TLS stays verified.
        let url =
            reqwest::Url::parse(&format!("https://localhost:{}/list", address.port())).unwrap();
        let result = fetch::read_response(&client, url).await;
        assert_eq!(result.is_ok(), success, "{result:?}");
        if success {
            assert_eq!(
                parse(&result.unwrap(), Format::Domains)
                    .unwrap()
                    .rules
                    .len(),
                1
            );
        }
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
async fn multi_list_transaction_and_due_refresh() {
    let directory = tempfile::tempdir().unwrap();
    let paths = [directory.path().join("a"), directory.path().join("b")];
    let mut lists = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        std::fs::write(path, format!("old{i}.example")).unwrap();
        let mut source = list(&format!("list{i}"), "", None);
        source.path = Some(path.clone());
        source.text = None;
        source.refresh_secs = 60;
        lists.push(source);
    }
    let filter = Filter::load(Config {
        lists,
        ..Config::default()
    })
    .await
    .unwrap();
    std::fs::write(&paths[0], "new.example").unwrap();
    std::fs::write(&paths[1], "bad/url").unwrap();
    assert!(filter.refresh().await.is_err());
    assert!(filter.explain("old0.example", ip(), 0).blocked);
    assert!(!filter.explain("new.example", ip(), 0).blocked);
    std::fs::write(&paths[1], "new.example").unwrap();
    {
        let mut refresh = filter.refresh.lock().await;
        refresh
            .attempted
            .fill(Instant::now().checked_sub(Duration::from_secs(61)).unwrap());
    }
    assert!(filter.refresh_due().await.unwrap());
    assert!(filter.explain("new.example", ip(), 0).blocked);
    filter.rollback().await.unwrap();
    {
        let mut refresh = filter.refresh.lock().await;
        refresh
            .attempted
            .fill(Instant::now().checked_sub(Duration::from_secs(61)).unwrap());
    }
    assert!(!filter.refresh_due().await.unwrap());
    assert!(filter.explain("old0.example", ip(), 0).blocked);
    filter.refresh().await.unwrap();
    assert!(filter.explain("new.example", ip(), 0).blocked);
    assert!(!filter.refresh.lock().await.automatic_paused);
}

#[tokio::test]
async fn unusual_wire_labels_cannot_bypass_suffix_blocks() {
    use lumen_proto::hickory_proto::rr::Name;
    let filter = Filter::load(Config {
        rules: Rules {
            block: vec!["ads.example".into()],
            ..Rules::default()
        },
        ..Config::default()
    })
    .await
    .unwrap();
    for label in [b"*".as_slice(), b"a.b", b"\xff", b"space here", b"-child"] {
        let name = Name::from_labels([label, b"ads", b"example"]).unwrap();
        assert!(filter.explain_dns(&name, ip(), 0).blocked, "{name}");
    }
    let name = Name::from_labels([b"x.ads".as_slice(), b"example"]).unwrap();
    assert!(!filter.explain_dns(&name, ip(), 0).blocked);
}

#[test]
fn long_cname_uses_transport_response_budget() {
    use lumen_proto::hickory_proto::{
        op::{Message, Query as Question},
        rr::{Name, RecordType},
    };
    let long = |c: char| {
        [
            c.to_string().repeat(63),
            c.to_string().repeat(63),
            c.to_string().repeat(63),
            c.to_string().repeat(61),
        ]
        .join(".")
    };
    let mut message = Message::query();
    message.add_query(Question::query(
        Name::from_ascii(long('a')).unwrap(),
        RecordType::A,
    ));
    let query = lumen_proto::Query::parse(&message.to_vec().unwrap()).unwrap();
    let action = Action::Cname { target: long('b') };
    let small = response(&query, &action, 512);
    assert!(small.len() <= 512);
    let small = Message::from_vec(&small).unwrap();
    assert!(small.metadata.truncation);
    assert!(small.answers.is_empty());
    let large = Message::from_vec(&response(&query, &action, 4096)).unwrap();
    assert!(!large.metadata.truncation);
    assert_eq!(large.answers.len(), 1);
}

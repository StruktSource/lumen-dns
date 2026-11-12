//! Certificate issuance against a Pebble test CA. Pebble is not part of the repository, so this
//! test only runs when `LUMEN_PEBBLE_URL` names a running Pebble directory (for example
//! `https://localhost:14000/dir`) and `LUMEN_PEBBLE_CA` the PEM root that signs Pebble's own
//! HTTPS certificate. Its validation port must be 5002 and every name must resolve to 127.0.0.1
//! (`pebble-challtestsrv -defaultIPv4 127.0.0.1` with `pebble -dnsserver`). See
//! `docs/guides/certificates.md`.

use lumen_config::{Config, Mode, Upstream, UpstreamProtocol};
use lumen_core::RunningServer;
use std::{net::SocketAddr, path::PathBuf, time::Duration};

fn free_address() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

#[tokio::test]
async fn pebble_issues_a_certificate_and_the_server_serves_it() {
    let (Ok(directory), Ok(root)) = (
        std::env::var("LUMEN_PEBBLE_URL"),
        std::env::var("LUMEN_PEBBLE_CA"),
    ) else {
        eprintln!("skipped: set LUMEN_PEBBLE_URL and LUMEN_PEBBLE_CA to run against Pebble");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let path = |name: &str| -> PathBuf { dir.path().join(name) };
    let mut config = Config {
        schema_version: 1,
        ..Config::default()
    };
    let dot = free_address();
    config.listen.udp = vec![free_address()];
    config.listen.tcp = vec![free_address()];
    config.listen.dot = vec![dot];
    config.listen.certificate = Some(path("cert.pem"));
    config.listen.private_key = Some(path("key.pem"));
    config.resolver.mode = Mode::Forward;
    config.resolver.dnssec = false;
    config.resolver.upstreams = vec![Upstream {
        address: "127.0.0.1:9".parse().unwrap(),
        protocol: UpstreamProtocol::Udp,
        server_name: None,
        doh_path: None,
    }];
    config.acme.domains = vec!["lumen.test".into()];
    config.acme.directory = Some(directory);
    config.acme.directory_ca = Some(root.into());
    config.acme.terms_agreed = true;
    config.acme.email = Some("ops@lumen.test".into());
    config.acme.account_file = Some(path("account.json"));
    config.acme.challenge_listen = "127.0.0.1:5002".parse().unwrap();

    // No certificate exists, so startup runs the order first.
    let mut server = RunningServer::start(config.clone()).await.unwrap();
    let cert = std::fs::read(path("cert.pem")).unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert).unwrap();
    let parsed = pem.parse_x509().unwrap();
    let names: Vec<String> = parsed
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        names.iter().any(|name| name.contains("lumen.test")),
        "{names:?}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for file in ["key.pem", "account.json"] {
            let mode = std::fs::metadata(path(file)).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{file} must be private");
        }
    }
    server.shutdown().await;

    // The account is reused and a still-valid certificate is left alone.
    let before = std::fs::read(path("cert.pem")).unwrap();
    let mut server = RunningServer::start(config).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read(path("cert.pem")).unwrap(), before);
    server.shutdown().await;
}

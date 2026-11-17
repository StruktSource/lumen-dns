//! The engine end to end on the loopback interface: discovery, naming, and an outage with its
//! recovery, all through the real database.

use async_trait::async_trait;
use lumen_config::{Monitor, Network, NetworkScope};
use lumen_netmon::{
    CheckMethod, DeviceFilter, DhcpHost, Environment, Monitoring, Netmon, Oui, Status, probe,
};
use std::{net::IpAddr, sync::Arc, time::Duration};

struct Env;

#[async_trait]
impl Environment for Env {
    fn dhcp_hosts(&self) -> Vec<DhcpHost> {
        vec![
            DhcpHost {
                ip: "127.0.0.1".parse().unwrap(),
                client: "01b827eb000042".into(),
                hostname: Some("Loopback-Host".into()),
            },
            // Outside the scope: must never be stored.
            DhcpHost {
                ip: "10.99.99.99".parse().unwrap(),
                client: "b827eb000043".into(),
                hostname: Some("elsewhere".into()),
            },
        ]
    }
    async fn reverse(&self, _ip: IpAddr) -> Option<String> {
        Some("reverse.example".into())
    }
}

fn config() -> Network {
    Network {
        enabled: true,
        scopes: vec![NetworkScope {
            name: "loopback".into(),
            networks: vec!["127.0.0.1/32".parse().unwrap()],
            exclude: Vec::new(),
            interface: None,
            snmp_profile: None,
        }],
        scan_interval_secs: 0,
        timeout_ms: 300,
        monitor: Monitor {
            enabled: true,
            interval_secs: 1,
            failures_before_offline: 2,
            degraded_loss_percent: 50,
            probes_per_check: 1,
        },
        ..Network::default()
    }
}

async fn until<T>(what: &str, seconds: u64, mut probe: impl FnMut() -> Option<T>) -> T {
    for _ in 0..seconds * 10 {
        if let Some(found) = probe() {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // One scenario, start to finish.
async fn discovery_names_a_device_and_monitoring_reports_an_outage_and_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let state = directory.path().join("state.db");
    let running = lumen_netmon::start(&config(), &state, Arc::new(Env)).unwrap();
    let status = running.status();
    assert_eq!(status.scopes[0].networks, ["127.0.0.1/32"]);
    running.scan_now().unwrap();

    // Discovery runs: DHCP names it, ICMP (where allowed) shows it is awake, and nothing outside
    // the scope is stored.
    let scan = until("a finished scan", 15, || {
        Netmon::open(&state)
            .unwrap()
            .scans(5)
            .unwrap()
            .into_iter()
            .find(|s| s.state == "finished" || s.state == "failed")
    })
    .await;
    assert_eq!(scan.state, "finished", "{scan:?}");
    let nm = Netmon::open(&state).unwrap();
    let devices = nm.devices(&DeviceFilter::default()).unwrap();
    assert_eq!(devices.len(), 1, "{devices:?}");
    let device = devices[0].clone();
    assert_eq!(device.name, "loopback-host");
    assert_eq!(device.addresses[0].ip, "127.0.0.1");
    assert_eq!(device.macs[0].mac, "b8:27:eb:00:00:42");
    assert_eq!(device.vendor.as_deref(), Some("Raspberry Pi Foundation"));
    assert!(
        devices
            .iter()
            .all(|d| d.addresses.iter().all(|a| a.ip != "10.99.99.99"))
    );
    if probe::icmp_available(false) {
        assert_eq!(device.status, Status::Online);
        assert!(scan.probed >= 1);
    }

    // Monitor it over TCP, so the outage can be staged: open port, closed port, open again.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut nm = Netmon::open(&state).unwrap();
    nm.update_device(
        device.id,
        &lumen_netmon::DeviceInput {
            name: device.name.clone(),
            monitoring: Some(Monitoring {
                enabled: true,
                method: CheckMethod::Tcp,
                tcp_port: Some(port),
                interval_secs: None,
            }),
            ..Default::default()
        },
        &Oui::new(),
    )
    .unwrap();
    drop(nm);
    // The monitor picks the change up within its refresh period; its first check follows.
    let online = until("an online check", 30, || {
        let nm = Netmon::open(&state).unwrap();
        let checks = nm.checks(device.id, 0, 10).unwrap();
        (checks.iter().any(|c| c.ok)).then_some(checks)
    })
    .await;
    assert!(online[0].rtt_ms.is_some());
    assert_eq!(
        Netmon::open(&state)
            .unwrap()
            .device(device.id)
            .unwrap()
            .unwrap()
            .status,
        Status::Online
    );
    assert!(
        Netmon::open(&state)
            .unwrap()
            .device(device.id)
            .unwrap()
            .unwrap()
            .last_ok
            .is_some()
    );

    // The service goes away: after two failed checks in a row the device is offline, once.
    drop(listener);
    until("an offline state", 30, || {
        (Netmon::open(&state)
            .unwrap()
            .device(device.id)
            .unwrap()
            .unwrap()
            .status
            == Status::Offline)
            .then_some(())
    })
    .await;
    let events = Netmon::open(&state)
        .unwrap()
        .events(Some(device.id), 50)
        .unwrap();
    assert_eq!(
        events.iter().filter(|e| e.kind == "offline").count(),
        1,
        "{events:?}"
    );
    let availability = Netmon::open(&state)
        .unwrap()
        .availability(device.id, 0)
        .unwrap()
        .unwrap();
    assert!(availability > 0.0 && availability < 100.0, "{availability}");

    // And it comes back.
    let again = tokio::net::TcpListener::bind(("127.0.0.1", port)).await;
    if again.is_ok() {
        until("a recovery", 30, || {
            let nm = Netmon::open(&state).unwrap();
            nm.events(Some(device.id), 50)
                .unwrap()
                .iter()
                .any(|e| e.kind == "recovered")
                .then_some(())
        })
        .await;
        assert_eq!(
            Netmon::open(&state)
                .unwrap()
                .device(device.id)
                .unwrap()
                .unwrap()
                .status,
            Status::Online
        );
    }
    drop(running);
}

//! The client against a real agent: net-snmp's `snmpd`, when it is installed (the tests quietly
//! pass without it). net-snmp 5.6 offers SHA-1 and AES-128.

use super::*;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
};

struct Agent {
    child: Child,
    port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn snmpd_path() -> Option<PathBuf> {
    [
        "/usr/sbin/snmpd",
        "/usr/local/sbin/snmpd",
        "/opt/homebrew/sbin/snmpd",
        "/sbin/snmpd",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.exists())
}

/// The agent, `None` when `snmpd` is not installed. If it is installed it must start: a silent
/// skip would hide a broken client.
async fn agent() -> Option<Agent> {
    snmpd_path()?;
    Some(
        start_agent()
            .await
            .expect("snmpd is installed but did not start"),
    )
}

async fn start_agent() -> Option<Agent> {
    let program = snmpd_path()?;
    let port = {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
        socket.local_addr().ok()?.port()
    };
    let dir = tempfile::tempdir().ok()?;
    std::fs::create_dir_all(dir.path().join("persist")).ok()?;
    let conf = format!(
        "agentaddress udp:127.0.0.1:{port}\nrocommunity lumentest\n\
         createUser lumenv3 SHA authpassword123 AES privpassword123\nrouser lumenv3 priv\n\
         createUser lumenauth SHA authpassword123\nrouser lumenauth auth\n\
         syslocation Lab\nsyscontact admin@example.invalid\nsysname testagent\n"
    );
    std::fs::write(dir.path().join("snmpd.conf"), conf).ok()?;
    let child = Command::new(program)
        .args(["-f", "-C", "-r", "-Ln", "-c"])
        .arg(dir.path().join("snmpd.conf"))
        .arg("-p")
        .arg(dir.path().join("pid"))
        .env("SNMP_PERSISTENT_DIR", dir.path().join("persist"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let agent = Agent {
        child,
        port,
        _dir: dir,
    };
    // Wait until it answers.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut probe = Client::connect(
            SocketAddr::from(([127, 0, 0, 1], port)),
            Credentials::V2c {
                community: b"lumentest".to_vec(),
            },
            Duration::from_millis(200),
            0,
        )
        .await
        .ok()?;
        if probe
            .get(&[Oid::parse("1.3.6.1.2.1.1.5.0").unwrap()])
            .await
            .is_ok()
        {
            return Some(agent);
        }
    }
    None
}

fn v2c(agent: &Agent, community: &[u8]) -> Credentials {
    let _ = agent;
    Credentials::V2c {
        community: community.to_vec(),
    }
}

fn v3(auth: bool, privacy: bool, user: &str, auth_pw: &str) -> Credentials {
    Credentials::V3(UsmUser {
        name: user.into(),
        auth: auth.then(|| (SnmpAuth::Sha1, auth_pw.as_bytes().to_vec())),
        privacy: privacy.then(|| (SnmpPrivacy::Aes128, b"privpassword123".to_vec())),
    })
}

async fn client(agent: &Agent, credentials: Credentials) -> Client {
    Client::connect(
        SocketAddr::from(([127, 0, 0, 1], agent.port)),
        credentials,
        Duration::from_millis(1500),
        1,
    )
    .await
    .unwrap()
}

fn name() -> Oid {
    Oid::parse("1.3.6.1.2.1.1.5.0").unwrap()
}

#[tokio::test]
async fn v2c_reads_walks_and_reports_missing_objects() {
    let Some(agent) = agent().await else { return };
    let mut c = client(&agent, v2c(&agent, b"lumentest")).await;
    let got = c
        .get(&[name(), Oid::parse("1.3.6.1.2.1.1.99.0").unwrap()])
        .await
        .unwrap();
    assert_eq!(got[0].1.as_text().as_deref(), Some("testagent"));
    assert!(got[1].1.is_missing(), "{:?}", got[1]);
    let sys = mib::system(&mut c, 5).await.unwrap();
    assert_eq!(sys.name.as_deref(), Some("testagent"));
    assert_eq!(sys.location.as_deref(), Some("Lab"));
    assert_eq!(sys.contact.as_deref(), Some("admin@example.invalid"));
    assert!(sys.uptime_secs.is_some() && sys.object_id.is_some());
    // A walk stays under its root and its row limit.
    let root = Oid::parse("1.3.6.1.2.1.1").unwrap();
    let rows = c.walk(&root, 1000).await.unwrap();
    assert!(rows.len() >= 7 && rows.iter().all(|(o, _)| o.starts_with(&root)));
    assert!(rows.windows(2).all(|w| w[0].0 < w[1].0), "in order");
    assert_eq!(c.walk(&root, 3).await.unwrap().len(), 3);
    // Interfaces: this machine has at least a loopback with traffic counters.
    let interfaces = mib::interfaces(&mut c).await.unwrap();
    assert!(!interfaces.is_empty());
    assert!(
        interfaces.iter().any(|i| i.oper_up && !i.name.is_empty()),
        "{interfaces:?}"
    );
    // Resources never fail the poll.
    let mut sys = sys;
    mib::resources(&mut c, &mut sys).await;
    for pct in [sys.cpu_percent, sys.memory_percent].into_iter().flatten() {
        assert!((0.0..=100.0).contains(&pct), "{pct}");
    }
}

#[tokio::test]
async fn v3_authenticated_and_encrypted_requests_work_and_bad_credentials_are_named() {
    let Some(agent) = agent().await else { return };
    // authPriv: SHA-1 and AES-128.
    let mut secure = client(&agent, v3(true, true, "lumenv3", "authpassword123")).await;
    let got = secure.get(&[name()]).await.unwrap();
    assert_eq!(got[0].1.as_text().as_deref(), Some("testagent"));
    // The session reuses what it learned, and a walk works over the encrypted channel.
    let rows = secure
        .walk(&Oid::parse("1.3.6.1.2.1.1").unwrap(), 100)
        .await
        .unwrap();
    assert!(rows.len() >= 7);
    assert!(!mib::interfaces(&mut secure).await.unwrap().is_empty());
    // authNoPriv.
    let mut auth_only = client(&agent, v3(true, false, "lumenauth", "authpassword123")).await;
    assert_eq!(
        auth_only.get(&[name()]).await.unwrap()[0]
            .1
            .as_text()
            .as_deref(),
        Some("testagent")
    );
    // Failures say why.
    let mut wrong_password = client(&agent, v3(true, true, "lumenv3", "not-the-password")).await;
    assert_eq!(
        wrong_password.get(&[name()]).await.unwrap_err(),
        SnmpError::Auth("wrong authentication password")
    );
    let mut wrong_user = client(&agent, v3(true, true, "nobody", "authpassword123")).await;
    assert_eq!(
        wrong_user.get(&[name()]).await.unwrap_err(),
        SnmpError::Auth("unknown user name")
    );
}

#[tokio::test]
async fn a_silent_address_times_out() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut c = Client::connect(
        SocketAddr::from(([127, 0, 0, 1], port)),
        Credentials::V2c {
            community: b"x".to_vec(),
        },
        Duration::from_millis(100),
        1,
    )
    .await
    .unwrap();
    assert_eq!(c.get(&[name()]).await.unwrap_err(), SnmpError::Timeout);
    let mut v3 = Client::connect(
        SocketAddr::from(([127, 0, 0, 1], port)),
        v3(true, true, "u", "authpassword123"),
        Duration::from_millis(100),
        0,
    )
    .await
    .unwrap();
    assert_eq!(v3.get(&[name()]).await.unwrap_err(), SnmpError::Timeout);
    drop(socket);
}

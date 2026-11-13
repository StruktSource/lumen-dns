//! Hot-standby failover between two Lumen DHCP servers.
//!
//! The primary connects to the secondary. Both sides copy every lease change to each other and
//! send a heartbeat every two seconds. The secondary stays silent until it has heard nothing for
//! `takeover_secs`; while it covers for the primary it gives new leases only from the end of each
//! range (see `Engine::set_reserve`). Every frame is authenticated with a shared secret, and a
//! fresh key is derived from two random values for every connection, so frames cannot be forged,
//! replayed, or reflected.

use ipnet::Ipv6Net;
use lumen_config::{DhcpFailover, FailoverRole};
use rand_core::{OsRng, RngCore};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

const BEAT: Duration = Duration::from_secs(2);
const MAX_FRAME: usize = 1 << 20;
const QUEUE: usize = 8192;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// One message between the two servers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "t")]
pub enum Wire {
    Beat,
    Lease4 {
        ip: Ipv4Addr,
        client: Vec<u8>,
        hostname: Option<String>,
        expires: u64,
    },
    End4 {
        ip: Ipv4Addr,
    },
    Lease6 {
        ip: Ipv6Addr,
        client: Vec<u8>,
        iaid: u32,
        hostname: Option<String>,
        expires: u64,
        #[serde(default)]
        temporary: bool,
    },
    End6 {
        ip: Ipv6Addr,
    },
    Prefix {
        prefix: Ipv6Net,
        client: Vec<u8>,
        iaid: u32,
        expires: u64,
    },
    EndPrefix {
        prefix: Ipv6Net,
    },
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// What this server knows about its partner.
pub struct Failover {
    role: FailoverRole,
    takeover: u64,
    reserve: u8,
    last_seen: AtomicU64,
    outgoing: mpsc::Sender<Wire>,
    queue: Mutex<mpsc::Receiver<Wire>>,
}

impl Failover {
    #[must_use]
    pub fn new(config: &DhcpFailover) -> Arc<Self> {
        let (outgoing, queue) = mpsc::channel(QUEUE);
        Arc::new(Self {
            role: config.role,
            takeover: u64::from(config.takeover_secs),
            reserve: config.reserve_percent,
            // A secondary that has just started waits a full takeover period first.
            last_seen: AtomicU64::new(unix_now()),
            outgoing,
            queue: Mutex::new(queue),
        })
    }

    /// Whether this server answers clients now.
    #[must_use]
    pub fn active(&self, now: u64) -> bool {
        match self.role {
            FailoverRole::Primary => true,
            FailoverRole::Secondary => {
                now.saturating_sub(self.last_seen.load(Ordering::Relaxed)) >= self.takeover
            }
        }
    }

    /// The share of each range new leases must come from, while covering for the primary.
    #[must_use]
    pub fn reserve(&self, now: u64) -> Option<u8> {
        (self.role == FailoverRole::Secondary && self.active(now)).then_some(self.reserve)
    }

    /// Tell the partner about a change. Dropped when the queue is full; a reconnect sends
    /// everything again.
    pub fn send(&self, wire: Wire) {
        let _ = self.outgoing.try_send(wire);
    }

    fn heard(&self) {
        self.last_seen.store(unix_now(), Ordering::Relaxed);
    }
}

/// Read the shared secret. It must be at least 16 characters, and on unix private to the owner.
///
/// # Errors
/// The file cannot be read, is too short, or is readable by others.
pub fn read_secret(path: &Path) -> io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(format!(
                "{} must not be readable by others (chmod 600)",
                path.display()
            )));
        }
    }
    let secret = std::fs::read_to_string(path)?.trim().as_bytes().to_vec();
    if secret.len() < 16 {
        return Err(io::Error::other("the failover secret needs 16 characters"));
    }
    Ok(secret)
}

fn tag(secret: &[u8], parts: &[&[u8]]) -> hmac::Tag {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut context = hmac::Context::with_key(&key);
    for part in parts {
        context.update(part);
    }
    context.sign()
}

fn check(secret: &[u8], parts: &[&[u8]], claimed: &[u8]) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut joined = Vec::new();
    for part in parts {
        joined.extend_from_slice(part);
    }
    hmac::verify(&key, &joined, claimed).is_ok()
}

/// The initiator proves it knows the secret, the acceptor does too, and both derive a key.
async fn handshake_out(stream: &mut TcpStream, secret: &[u8]) -> io::Result<hmac::Key> {
    let mut nonce_c = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_c);
    stream.write_all(&nonce_c).await?;
    stream
        .write_all(tag(secret, &[b"c", &nonce_c]).as_ref())
        .await?;
    let mut reply = [0u8; 48];
    stream.read_exact(&mut reply).await?;
    let (nonce_s, proof) = reply.split_at(16);
    if !check(secret, &[b"s", &nonce_c, nonce_s], proof) {
        return Err(io::Error::other(
            "the failover partner does not know the secret",
        ));
    }
    Ok(hmac::Key::new(
        hmac::HMAC_SHA256,
        tag(secret, &[b"k", &nonce_c, nonce_s]).as_ref(),
    ))
}

async fn handshake_in(stream: &mut TcpStream, secret: &[u8]) -> io::Result<hmac::Key> {
    let mut hello = [0u8; 48];
    stream.read_exact(&mut hello).await?;
    let (nonce_c, proof) = hello.split_at(16);
    if !check(secret, &[b"c", nonce_c], proof) {
        return Err(io::Error::other(
            "the failover partner does not know the secret",
        ));
    }
    let mut nonce_s = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_s);
    stream.write_all(&nonce_s).await?;
    stream
        .write_all(tag(secret, &[b"s", nonce_c, &nonce_s]).as_ref())
        .await?;
    Ok(hmac::Key::new(
        hmac::HMAC_SHA256,
        tag(secret, &[b"k", nonce_c, &nonce_s]).as_ref(),
    ))
}

/// What the session needs from the server: everything bound now, and a way to apply a message.
pub type Snapshot = Arc<dyn Fn() -> Vec<Wire> + Send + Sync>;
pub type Apply = Arc<dyn Fn(Wire) + Send + Sync>;

async fn write_frame(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    key: &hmac::Key,
    direction: u8,
    sequence: u64,
    wire: &Wire,
) -> io::Result<()> {
    let payload = serde_json::to_vec(wire).map_err(io::Error::other)?;
    let mut signed = vec![direction];
    signed.extend_from_slice(&sequence.to_be_bytes());
    signed.extend_from_slice(&payload);
    let mac = hmac::sign(key, &signed);
    let length = u32::try_from(payload.len()).map_err(io::Error::other)?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.write_all(mac.as_ref()).await
}

async fn read_frame(
    stream: &mut tokio::net::tcp::OwnedReadHalf,
    key: &hmac::Key,
    direction: u8,
    sequence: u64,
) -> io::Result<Wire> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::other("failover frame too large"));
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await?;
    let mut mac = [0u8; 32];
    stream.read_exact(&mut mac).await?;
    let mut signed = vec![direction];
    signed.extend_from_slice(&sequence.to_be_bytes());
    signed.extend_from_slice(&payload);
    hmac::verify(key, &signed, &mac).map_err(|_| io::Error::other("bad failover signature"))?;
    serde_json::from_slice(&payload).map_err(io::Error::other)
}

/// Run one authenticated connection until it breaks. `outbound` is the direction byte this side
/// signs with (0 for the initiator, 1 for the acceptor).
async fn session(
    stream: TcpStream,
    key: hmac::Key,
    outbound: u8,
    failover: Arc<Failover>,
    snapshot: Snapshot,
    apply: Apply,
) -> io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    let key = Arc::new(key);
    let read_key = Arc::clone(&key);
    let heard = Arc::clone(&failover);
    let reading = tokio::spawn(async move {
        let mut sequence = 0u64;
        loop {
            let wire = read_frame(&mut reader, &read_key, 1 - outbound, sequence).await?;
            sequence += 1;
            heard.heard();
            if wire != Wire::Beat {
                apply(wire);
            }
        }
        #[allow(unreachable_code)]
        io::Result::Ok(())
    });
    let mut queue = failover.queue.lock().await;
    // Whatever queued while disconnected is covered by the full copy sent now.
    while queue.try_recv().is_ok() {}
    let mut sequence = 0u64;
    let result = async {
        for wire in snapshot() {
            write_frame(&mut writer, &key, outbound, sequence, &wire).await?;
            sequence += 1;
        }
        let mut beat = tokio::time::interval(BEAT);
        loop {
            let wire = tokio::select! {
                _ = beat.tick() => Wire::Beat,
                queued = queue.recv() => match queued {
                    Some(wire) => wire,
                    None => return Ok(()),
                },
            };
            write_frame(&mut writer, &key, outbound, sequence, &wire).await?;
            sequence += 1;
        }
    }
    .await;
    reading.abort();
    result
}

/// Start the failover link. The primary connects to the secondary; the secondary accepts.
///
/// # Errors
/// The secret cannot be read, or the secondary cannot bind its address.
pub async fn start(
    config: &DhcpFailover,
    failover: Arc<Failover>,
    snapshot: Snapshot,
    apply: Apply,
) -> io::Result<JoinHandle<()>> {
    let secret = read_secret(&config.secret_file)?;
    match config.role {
        FailoverRole::Primary => {
            let peer = config
                .peer
                .ok_or_else(|| io::Error::other("failover.peer is required for the primary"))?;
            Ok(tokio::spawn(async move {
                loop {
                    let attempt = async {
                        let mut stream =
                            tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(peer))
                                .await
                                .map_err(io::Error::other)??;
                        let key = tokio::time::timeout(
                            HANDSHAKE_TIMEOUT,
                            handshake_out(&mut stream, &secret),
                        )
                        .await
                        .map_err(io::Error::other)??;
                        session(
                            stream,
                            key,
                            0,
                            failover.clone(),
                            snapshot.clone(),
                            apply.clone(),
                        )
                        .await
                    };
                    if let Err(error) = attempt.await {
                        eprintln!("dhcp failover: {error}; retrying");
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }))
        }
        FailoverRole::Secondary => {
            let listen = config
                .listen
                .ok_or_else(|| io::Error::other("failover.listen is required for the secondary"))?;
            let listener = TcpListener::bind(listen).await?;
            Ok(tokio::spawn(async move {
                let mut current: Option<JoinHandle<()>> = None;
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    let authenticated =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake_in(&mut stream, &secret))
                            .await;
                    let Ok(Ok(key)) = authenticated else {
                        continue;
                    };
                    // The newest authenticated connection replaces the old one.
                    if let Some(old) = current.take() {
                        old.abort();
                    }
                    let (failover, snapshot, apply) =
                        (failover.clone(), snapshot.clone(), apply.clone());
                    current = Some(tokio::spawn(async move {
                        if let Err(error) = session(stream, key, 1, failover, snapshot, apply).await
                        {
                            eprintln!("dhcp failover: {error}");
                        }
                    }));
                }
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secondary_waits_out_the_takeover_time_and_covers_with_a_reserve() {
        let config = DhcpFailover {
            role: FailoverRole::Secondary,
            peer: None,
            listen: Some("127.0.0.1:0".parse().unwrap()),
            secret_file: "x".into(),
            takeover_secs: 30,
            reserve_percent: 20,
        };
        let failover = Failover::new(&config);
        let now = unix_now();
        assert!(!failover.active(now), "just started: wait");
        assert_eq!(failover.reserve(now), None);
        assert!(failover.active(now + 31));
        assert_eq!(failover.reserve(now + 31), Some(20));
        failover.heard();
        assert!(!failover.active(unix_now() + 5), "the primary is back");
    }

    #[test]
    fn the_primary_always_answers() {
        let config = DhcpFailover {
            role: FailoverRole::Primary,
            peer: Some("127.0.0.1:1".parse().unwrap()),
            listen: None,
            secret_file: "x".into(),
            takeover_secs: 30,
            reserve_percent: 20,
        };
        let failover = Failover::new(&config);
        assert!(failover.active(0));
        assert_eq!(failover.reserve(1_000_000), None);
    }

    #[test]
    fn a_short_or_shared_secret_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        std::fs::write(&path, "short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(read_secret(&path).is_err());
        std::fs::write(&path, "a long enough shared secret\n").unwrap();
        assert_eq!(read_secret(&path).unwrap(), b"a long enough shared secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_secret(&path).is_err(), "world readable");
        }
    }
}

//! Automatic certificates (ACME, HTTP-01).
//!
//! Lumen asks an ACME certificate authority for the certificate that `listen.certificate` and
//! `listen.private_key` name, answers the CA's HTTP-01 challenge on a port it opens only while
//! an order runs, and writes the result atomically. The running listeners pick the new pair up
//! through certificate reload within 30 seconds, so renewal never restarts anything.

use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use lumen_config::{Acme, AcmeChallenge, Config};
use lumen_resolver::Challenges;
use std::{
    collections::HashMap,
    io,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Semaphore,
    time::timeout,
};

/// One order may take this long before it is abandoned and tried again later.
const ORDER_TIMEOUT: Duration = Duration::from_secs(300);
/// Most challenge connections handled at once.
const MAX_CHALLENGE_CONNECTIONS: usize = 16;

type Tokens = Arc<Mutex<HashMap<String, String>>>;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

fn other(message: impl std::fmt::Display) -> io::Error {
    io::Error::other(message.to_string())
}

/// True when the pair on disk is missing, unusable, or close enough to expiry to renew.
fn due(config: &Config) -> bool {
    let (Some(cert), Some(key)) = (&config.listen.certificate, &config.listen.private_key) else {
        return false;
    };
    match crate::certs::CertReloader::load(cert, key) {
        Ok((_, not_after)) => {
            not_after - now() < i64::from(config.acme.renew_before_days) * 24 * 3600
        }
        Err(_) => true,
    }
}

/// Make sure a certificate exists before listeners start. Fails only when there is none at all.
///
/// # Errors
/// Issuance failed and no usable certificate exists yet.
pub(crate) async fn ensure(config: &Config, challenges: &Arc<Challenges>) -> io::Result<()> {
    if config.acme.domains.is_empty() || !due(config) {
        return Ok(());
    }
    // Before the first certificate Lumen's own listeners cannot start, so DNS-01 needs a small
    // stand-in that answers the challenge name and nothing else.
    let stand_in = if config.acme.challenge == AcmeChallenge::Dns01 {
        Some(StandIn::start(config, challenges).await?)
    } else {
        None
    };
    let result = obtain(config, challenges).await;
    if let Some(stand_in) = stand_in {
        stand_in.stop().await;
    }
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let usable = match (&config.listen.certificate, &config.listen.private_key) {
                (Some(cert), Some(key)) => crate::certs::CertReloader::load(cert, key).is_ok(),
                _ => false,
            };
            if usable {
                eprintln!("certificate renewal failed ({error}); keeping the current one");
                Ok(())
            } else {
                Err(other(format!("cannot obtain a certificate: {error}")))
            }
        }
    }
}

/// Check once a day and renew when the certificate is due. A failed attempt is retried in an
/// hour, so a temporary outage at the CA does not wait a whole day.
pub(crate) async fn keep_renewed(config: Arc<Config>, challenges: Arc<Challenges>) {
    loop {
        let mut wait = Duration::from_secs(24 * 3600);
        if due(&config) {
            if let Err(error) = obtain(&config, &challenges).await {
                eprintln!("certificate renewal failed: {error}");
                wait = Duration::from_secs(3600);
            } else {
                eprintln!("certificate renewed; listeners reload it within 30 seconds");
            }
        }
        tokio::time::sleep(wait).await;
    }
}

async fn account(acme: &Acme) -> io::Result<Account> {
    let builder = match &acme.directory_ca {
        Some(path) => Account::builder_with_root(path),
        None => Account::builder(),
    }
    .map_err(other)?;
    let path = acme
        .account_file
        .as_ref()
        .ok_or_else(|| other("acme.account_file is required"))?;
    if path.exists() {
        let bytes = lumen_config::read_bounded(path, 16384).map_err(other)?;
        let credentials: AccountCredentials =
            serde_json::from_slice(&bytes).map_err(|_| other("acme account file is not valid"))?;
        return builder.from_credentials(credentials).await.map_err(other);
    }
    let contact = acme
        .email
        .as_ref()
        .map(|email| format!("mailto:{email}"))
        .into_iter()
        .collect::<Vec<_>>();
    let contact_refs = contact.iter().map(String::as_str).collect::<Vec<_>>();
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &contact_refs,
                terms_of_service_agreed: acme.terms_agreed,
                only_return_existing: false,
            },
            acme.directory.clone().unwrap_or_default(),
            None,
        )
        .await
        .map_err(other)?;
    let json = serde_json::to_vec(&credentials).map_err(other)?;
    write_private(path, &json)?;
    Ok(account)
}

/// Replace `path` with a new file, mode 0600, through a temporary file in the same directory.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)
}

/// A temporary DNS responder on Lumen's configured UDP and TCP addresses, alive only while the
/// first certificate is ordered. It answers published challenge names and drops everything else.
struct StandIn(Vec<tokio::task::JoinHandle<()>>);

impl StandIn {
    async fn start(config: &Config, challenges: &Arc<Challenges>) -> io::Result<Self> {
        let mut tasks = Vec::new();
        for address in &config.listen.udp {
            let socket = tokio::net::UdpSocket::bind(address).await?;
            let challenges = Arc::clone(challenges);
            tasks.push(tokio::spawn(async move {
                let mut buffer = vec![0u8; 1232];
                while let Ok((size, from)) = socket.recv_from(&mut buffer).await {
                    if let Some(reply) = challenges.answer_packet(&buffer[..size]) {
                        let _ = socket.send_to(&reply, from).await;
                    }
                }
            }));
        }
        for address in &config.listen.tcp {
            let listener = TcpListener::bind(address).await?;
            let challenges = Arc::clone(challenges);
            tasks.push(tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let challenges = Arc::clone(&challenges);
                    tokio::spawn(async move {
                        let work = async {
                            let mut length = [0u8; 2];
                            stream.read_exact(&mut length).await?;
                            let mut packet =
                                vec![0u8; usize::from(u16::from_be_bytes(length)).min(1232)];
                            stream.read_exact(&mut packet).await?;
                            if let Some(reply) = challenges.answer_packet(&packet) {
                                let size = u16::try_from(reply.len()).unwrap_or(0).to_be_bytes();
                                stream.write_all(&size).await?;
                                stream.write_all(&reply).await?;
                            }
                            io::Result::Ok(())
                        };
                        let _ = timeout(Duration::from_secs(5), work).await;
                    });
                }
            }));
        }
        Ok(Self(tasks))
    }

    /// Stop answering and give the sockets back before the real listeners bind them.
    async fn stop(self) {
        for task in &self.0 {
            task.abort();
        }
        for task in self.0 {
            let _ = task.await;
        }
    }
}

/// Answer `GET /.well-known/acme-challenge/<token>` with the key authorization, and nothing else.
async fn serve_challenges(listener: TcpListener, tokens: Tokens) {
    let limit = Arc::new(Semaphore::new(MAX_CHALLENGE_CONNECTIONS));
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            continue;
        };
        let tokens = Arc::clone(&tokens);
        tokio::spawn(async move {
            let _permit = permit;
            let mut buffer = [0u8; 2048];
            let read = timeout(Duration::from_secs(5), stream.read(&mut buffer)).await;
            let Ok(Ok(size)) = read else {
                return;
            };
            let request = String::from_utf8_lossy(&buffer[..size]);
            let line = request.lines().next().unwrap_or_default();
            let body = line
                .strip_prefix("GET /.well-known/acme-challenge/")
                .and_then(|rest| rest.split_whitespace().next())
                .filter(|token| {
                    token
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                })
                .and_then(|token| tokens.lock().ok()?.get(token).cloned());
            let response = match body {
                Some(body) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
            };
            let _ = timeout(
                Duration::from_secs(5),
                stream.write_all(response.as_bytes()),
            )
            .await;
        });
    }
}

/// Run one order and write the new certificate and key.
async fn obtain(config: &Config, challenges: &Arc<Challenges>) -> io::Result<()> {
    let acme = &config.acme;
    let (Some(cert_path), Some(key_path)) =
        (&config.listen.certificate, &config.listen.private_key)
    else {
        return Err(other("certificate and key paths are required"));
    };
    let tokens: Tokens = Arc::default();
    // Only HTTP-01 needs a listener of its own. DNS-01 is answered by the resolver.
    let server = if acme.challenge == AcmeChallenge::Http01 {
        let listener = TcpListener::bind(acme.challenge_listen)
            .await
            .map_err(|error| {
                other(format!(
                    "cannot listen for challenges on {}: {error}",
                    acme.challenge_listen
                ))
            })?;
        Some(tokio::spawn(serve_challenges(
            listener,
            Arc::clone(&tokens),
        )))
    } else {
        None
    };
    let result = timeout(ORDER_TIMEOUT, run_order(acme, &tokens, challenges)).await;
    if let Some(server) = server {
        server.abort();
    }
    challenges.clear();
    let (chain, key) = result.map_err(|_| other("the order timed out"))??;
    // Key first: a certificate without its key would make the pair mismatched while it waits.
    write_private(key_path, key.as_bytes())?;
    write_private(cert_path, chain.as_bytes())
}

async fn run_order(
    acme: &Acme,
    tokens: &Tokens,
    challenges: &Challenges,
) -> io::Result<(String, String)> {
    let account = account(acme).await?;
    let identifiers: Vec<Identifier> = acme
        .domains
        .iter()
        .map(|name| Identifier::Dns(name.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(other)?;
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authorization = result.map_err(other)?;
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            _ => return Err(other("the CA refused an authorization")),
        }
        if acme.challenge == AcmeChallenge::Dns01 {
            let mut challenge = authorization
                .challenge(ChallengeType::Dns01)
                .ok_or_else(|| other("the CA offers no DNS-01 challenge"))?;
            // The identifier is the name without any wildcard label.
            challenges.publish(
                &challenge.identifier().to_string(),
                &challenge.key_authorization().dns_value(),
            );
            challenge.set_ready().await.map_err(other)?;
            continue;
        }
        let mut challenge = authorization
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| other("the CA offers no HTTP-01 challenge"))?;
        let value = challenge.key_authorization().as_str().to_owned();
        tokens
            .lock()
            .map_err(|_| other("challenge state poisoned"))?
            .insert(challenge.token.clone(), value);
        challenge.set_ready().await.map_err(other)?;
    }
    let status = order
        .poll_ready(&RetryPolicy::default())
        .await
        .map_err(other)?;
    if status != OrderStatus::Ready {
        return Err(other(format!("the order ended as {status:?}")));
    }
    let key = order.finalize().await.map_err(other)?;
    let chain = order
        .poll_certificate(&RetryPolicy::default())
        .await
        .map_err(other)?;
    Ok((chain, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn certificate(days: i64, dir: &Path) -> Config {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["lumen.test".into()]).unwrap();
        let now = ::time::OffsetDateTime::now_utc();
        params.not_before = now - ::time::Duration::days(1);
        params.not_after = now + ::time::Duration::days(days);
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
        let mut config = Config::default();
        config.listen.certificate = Some(dir.join("cert.pem"));
        config.listen.private_key = Some(dir.join("key.pem"));
        config
    }

    #[test]
    fn a_certificate_is_due_when_missing_or_close_to_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.listen.certificate = Some(dir.path().join("cert.pem"));
        config.listen.private_key = Some(dir.path().join("key.pem"));
        assert!(due(&config), "no files yet");
        let config = certificate(10, dir.path());
        assert!(due(&config), "10 days left, renew at 30");
        let config = certificate(80, dir.path());
        assert!(!due(&config), "80 days left");
        let mut early = certificate(80, dir.path());
        early.acme.renew_before_days = 60;
        assert!(!due(&early));
        early.acme.renew_before_days = 30;
        let soon = certificate(31, dir.path());
        assert!(!due(&soon));
        let soon = certificate(29, dir.path());
        assert!(due(&soon));
    }

    async fn ask(address: std::net::SocketAddr, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        reply
    }

    #[tokio::test]
    async fn the_challenge_server_answers_only_known_tokens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tokens: Tokens = Arc::default();
        tokens
            .lock()
            .unwrap()
            .insert("abc-DEF_123".into(), "abc-DEF_123.thumbprint".into());
        let server = tokio::spawn(serve_challenges(listener, tokens));
        let ok = ask(
            address,
            "GET /.well-known/acme-challenge/abc-DEF_123 HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(ok.starts_with("HTTP/1.1 200 OK"), "{ok}");
        assert!(ok.ends_with("abc-DEF_123.thumbprint"));
        for request in [
            "GET /.well-known/acme-challenge/unknown HTTP/1.1\r\n\r\n",
            "GET /.well-known/acme-challenge/../../etc/passwd HTTP/1.1\r\n\r\n",
            "GET / HTTP/1.1\r\n\r\n",
            "POST /.well-known/acme-challenge/abc-DEF_123 HTTP/1.1\r\n\r\n",
            "garbage",
        ] {
            let reply = ask(address, request).await;
            assert!(reply.starts_with("HTTP/1.1 404"), "{request}: {reply}");
        }
        server.abort();
    }
}

//! Bounded, loopback-only authenticated management API.

use lumen_config::{ApiRole, Management, Webhook, read_bounded};
use lumen_filter::config::Device;
use lumen_store::{Command, Store};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

pub const FIRST_API_VERSION: &str = "v1";
const MAX_HEADERS: usize = 16_384;
const MAX_BODY: usize = 65_536;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Active API listener. Drop aborts all API work.
pub struct RunningApi {
    task: JoinHandle<io::Result<()>>,
    pub address: SocketAddr,
}

impl RunningApi {
    /// Validate token hashes, webhook URLs, and webhook secret files without binding.
    ///
    /// # Errors
    /// Returns invalid or unreadable management configuration.
    pub fn check(config: &Management) -> io::Result<()> {
        validate_hashes(config)?;
        load_webhooks(&config.webhooks)?;
        Ok(())
    }

    /// Bind and start the opt-in management listener.
    ///
    /// # Errors
    /// Returns bind, state, or token configuration errors.
    pub async fn start(
        config: Management,
        state_path: impl AsRef<Path>,
    ) -> io::Result<Option<Self>> {
        let Some(address) = config.listen else {
            return Ok(None);
        };
        Self::check(&config)?;
        let webhook_targets = load_webhooks(&config.webhooks)?;
        let webhook_sender = if webhook_targets.is_empty() {
            None
        } else {
            let (sender, receiver) = mpsc::channel(128);
            tokio::spawn(deliver_webhooks(webhook_targets, receiver));
            Some(sender)
        };
        let listener = TcpListener::bind(address).await?;
        let address = listener.local_addr()?;
        let state = Arc::new(ApiState {
            state_path: state_path.as_ref().to_owned(),
            tokens: config
                .tokens
                .into_iter()
                .map(|token| {
                    Ok(Token {
                        name: token.name,
                        role: token.role,
                        hash: decode_hash(&token.sha256)?,
                    })
                })
                .collect::<io::Result<Vec<_>>>()?,
            requests_per_minute: config.requests_per_minute,
            rates: Mutex::new(HashMap::new()),
            webhook_sender,
        });
        Store::open(&state.state_path).map_err(io::Error::other)?;
        let task = tokio::spawn(serve(listener, state));
        Ok(Some(Self { task, address }))
    }

    /// Wait for unexpected listener exit.
    ///
    /// # Errors
    /// Returns listener and task failures.
    pub async fn wait(&mut self) -> io::Result<()> {
        (&mut self.task).await.map_err(io::Error::other)?
    }

    /// Stop listener and in-flight requests.
    pub async fn shutdown(&mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

struct Token {
    name: String,
    role: ApiRole,
    hash: [u8; 32],
}
struct RateBucket {
    start: Instant,
    count: u16,
}
struct ApiState {
    state_path: PathBuf,
    tokens: Vec<Token>,
    requests_per_minute: u16,
    rates: Mutex<HashMap<String, RateBucket>>,
    webhook_sender: Option<mpsc::Sender<WebhookEvent>>,
}
#[derive(Clone)]
struct WebhookTarget {
    id: String,
    url: reqwest::Url,
    secret: Vec<u8>,
}
struct WebhookEvent {
    created_at: u64,
    actor: String,
    role: String,
    action: String,
    target: String,
    outcome: String,
}
struct Principal<'a> {
    name: &'a str,
    role: ApiRole,
}
struct Request {
    method: String,
    path: String,
    authorization: Option<String>,
    content_type: Option<String>,
    body: Vec<u8>,
}
struct Response {
    status: &'static str,
    body: Vec<u8>,
}

async fn serve(listener: TcpListener, state: Arc<ApiState>) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        let (stream, peer) = listener.accept().await?;
        while tasks.try_join_next().is_some() {}
        if !peer.ip().is_loopback() || tasks.len() >= 32 {
            continue;
        }
        let state = Arc::clone(&state);
        tasks.spawn(async move {
            let _ = timeout(IO_TIMEOUT, handle(stream, peer, &state)).await;
        });
    }
}

async fn handle(mut stream: TcpStream, peer: SocketAddr, state: &ApiState) -> io::Result<()> {
    let request = match read_request(&mut stream).await {
        Ok(request) => request,
        Err(response) => return write_response(&mut stream, response).await,
    };
    write_response(&mut stream, dispatch(&request, peer, state)).await
}

fn dispatch(request: &Request, peer: SocketAddr, state: &ApiState) -> Response {
    let principal = match authenticate(request, state) {
        Ok(principal) => principal,
        Err(status) => {
            audit(
                state,
                "unknown",
                "none",
                "authenticate",
                &request.path,
                "denied",
                peer,
            );
            return error(status, "authentication failed");
        }
    };
    if !rate_allowed(state, principal.name) {
        audit_principal(state, &principal, request, "rate_limited", peer);
        return error("429 Too Many Requests", "request rate exceeded");
    }
    let Some(needed) = required_role(&request.method, &request.path) else {
        audit_principal(state, &principal, request, "not_found", peer);
        return error("404 Not Found", "route not found");
    };
    if !principal.role.permits(needed) {
        audit_principal(state, &principal, request, "denied", peer);
        return error("403 Forbidden", "role does not permit this action");
    }
    let result = route(request, state);
    let outcome = if result.status.starts_with('2') {
        "accepted"
    } else {
        "rejected"
    };
    audit_principal(state, &principal, request, outcome, peer);
    result
}

fn required_role(method: &str, path: &str) -> Option<ApiRole> {
    match (method, path) {
        ("GET", "/v1/status" | "/v1/devices") => Some(ApiRole::Viewer),
        ("GET", path) if path == "/v1/audit" || path.starts_with("/v1/audit?") => {
            Some(ApiRole::Admin)
        }
        ("POST", "/v1/filter/refresh" | "/v1/filter/rollback") => Some(ApiRole::Operator),
        ("POST", "/v1/reload" | "/v1/shutdown" | "/v1/config") | ("PUT", "/v1/devices") => {
            Some(ApiRole::Admin)
        }
        ("DELETE", path) if path.starts_with("/v1/devices/") => Some(ApiRole::Admin),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn route(request: &Request, state: &ApiState) -> Response {
    let Ok(mut store) = Store::open(&state.state_path) else {
        return error("503 Service Unavailable", "state unavailable");
    };
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/status") => match store.status() {
            Ok((status, last_error)) => json_response(
                "200 OK",
                json!({"status": status.unwrap_or_else(|| "unknown".into()), "last_error": last_error}),
            ),
            Err(_) => error("503 Service Unavailable", "state unavailable"),
        },
        ("GET", "/v1/devices") => match store.devices() {
            Ok(devices) => json_response(
                "200 OK",
                Value::Array(devices.into_iter().map(device_json).collect()),
            ),
            Err(_) => error("503 Service Unavailable", "state unavailable"),
        },
        ("GET", path) if path == "/v1/audit" || path.starts_with("/v1/audit?") => {
            let Some(limit) = query_limit(path) else {
                return error("400 Bad Request", "invalid audit limit");
            };
            match store.audit_events(limit) {
                Ok(events) => json_response("200 OK", Value::Array(events.into_iter().map(|event| json!({"id": event.id, "created_at": event.created_at, "actor": event.actor, "role": event.role, "action": event.action, "target": event.target, "outcome": event.outcome, "peer": event.peer})).collect())),
                Err(_) => error("400 Bad Request", "invalid audit limit"),
            }
        }
        ("PUT", "/v1/devices") => {
            if !is_json(request) {
                return error("415 Unsupported Media Type", "use application/json");
            }
            match serde_json::from_slice::<Device>(&request.body)
                .map_err(|_| "invalid device".to_owned())
                .and_then(|device| {
                    store.set_device(&device)?;
                    store.enqueue(Command::Reload)?;
                    Ok(device.id)
                }) {
                Ok(id) => json_response("202 Accepted", json!({"device": id, "reload": "queued"})),
                Err(_) => error("400 Bad Request", "invalid device"),
            }
        }
        ("DELETE", path) if path.starts_with("/v1/devices/") => {
            let id = &path[12..];
            match store.remove_device(id) {
                Ok(true) => match store.enqueue(Command::Reload) {
                    Ok(command) => json_response("202 Accepted", json!({"command": command})),
                    Err(_) => error("503 Service Unavailable", "control queue unavailable"),
                },
                Ok(false) => error("404 Not Found", "device not found"),
                Err(_) => error("400 Bad Request", "invalid device id"),
            }
        }
        ("POST", "/v1/filter/refresh") => queue(&store, Command::FilterRefresh),
        ("POST", "/v1/filter/rollback") => queue(&store, Command::FilterRollback),
        ("POST", "/v1/reload") => queue(&store, Command::Reload),
        ("POST", "/v1/shutdown") => queue(&store, Command::Shutdown),
        ("POST", "/v1/config") => {
            if request.content_type.as_deref() != Some("application/toml") {
                return error("415 Unsupported Media Type", "use application/toml");
            }
            let Ok(source) = std::str::from_utf8(&request.body) else {
                return error("400 Bad Request", "config must be UTF-8");
            };
            let base_dir = match store.config() {
                Ok(Some(config)) => PathBuf::from(config.base_dir),
                _ => return error("503 Service Unavailable", "active config unavailable"),
            };
            match lumen_config::Config::parse(source, &base_dir)
                .and_then(|_| store.stage_config(source, &base_dir))
                .and_then(|revision| {
                    store.enqueue(Command::ConfigReload(revision))?;
                    Ok(revision)
                }) {
                Ok(revision) => json_response(
                    "202 Accepted",
                    json!({"revision": revision, "reload": "queued"}),
                ),
                Err(_) => error("400 Bad Request", "invalid config"),
            }
        }
        _ => error("404 Not Found", "route not found"),
    }
}

fn queue(store: &Store, command: Command) -> Response {
    match store.enqueue(command) {
        Ok(id) => json_response("202 Accepted", json!({"command": id})),
        Err(_) => error("503 Service Unavailable", "control queue unavailable"),
    }
}

fn authenticate<'a>(request: &Request, state: &'a ApiState) -> Result<Principal<'a>, &'static str> {
    let header = request.authorization.as_deref().ok_or("401 Unauthorized")?;
    let secret = header.strip_prefix("Bearer ").ok_or("401 Unauthorized")?;
    if !(32..=256).contains(&secret.len()) || !secret.is_ascii() {
        return Err("401 Unauthorized");
    }
    let digest: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    let mut matched = None;
    for token in &state.tokens {
        if bool::from(digest.ct_eq(&token.hash)) {
            matched = Some(Principal {
                name: &token.name,
                role: token.role,
            });
        }
    }
    matched.ok_or("401 Unauthorized")
}

fn rate_allowed(state: &ApiState, actor: &str) -> bool {
    let now = Instant::now();
    let mut rates = state.rates.lock().expect("API rate lock");
    let bucket = rates.entry(actor.to_owned()).or_insert(RateBucket {
        start: now,
        count: 0,
    });
    if now.duration_since(bucket.start) >= Duration::from_secs(60) {
        bucket.start = now;
        bucket.count = 0;
    }
    if bucket.count >= state.requests_per_minute {
        return false;
    }
    bucket.count += 1;
    true
}

async fn read_request(stream: &mut TcpStream) -> Result<Request, Response> {
    let mut input = Vec::new();
    let mut byte = [0_u8];
    while input.len() < MAX_HEADERS && !input.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|_| error("400 Bad Request", "incomplete request"))?;
        input.push(byte[0]);
    }
    if !input.ends_with(b"\r\n\r\n") {
        return Err(error(
            "431 Request Header Fields Too Large",
            "headers too large",
        ));
    }
    let text = std::str::from_utf8(&input)
        .map_err(|_| error("400 Bad Request", "headers must be UTF-8"))?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let first = lines
        .next()
        .ok_or_else(|| error("400 Bad Request", "missing request line"))?;
    let parts = first.split(' ').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[2] != "HTTP/1.1"
        || !matches!(parts[0], "GET" | "POST" | "PUT" | "DELETE")
    {
        return Err(error("400 Bad Request", "invalid request line"));
    }
    if !parts[1].starts_with('/')
        || parts[1].len() > 256
        || !parts[1].bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(error("400 Bad Request", "invalid request target"));
    }
    let mut authorization = None;
    let mut content_type = None;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| error("400 Bad Request", "invalid header"))?;
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "authorization" if authorization.is_none() => authorization = Some(value.to_owned()),
            "content-type" if content_type.is_none() => {
                content_type = Some(
                    value
                        .split(';')
                        .next()
                        .unwrap_or(value)
                        .trim()
                        .to_ascii_lowercase(),
                );
            }
            "content-length" if content_length.is_none() => {
                content_length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| error("400 Bad Request", "invalid content length"))?,
                );
            }
            "authorization" | "content-type" | "content-length" => {
                return Err(error("400 Bad Request", "duplicate security header"));
            }
            "transfer-encoding" => {
                return Err(error("400 Bad Request", "chunked bodies unsupported"));
            }
            _ => {}
        }
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_BODY {
        return Err(error("413 Payload Too Large", "body too large"));
    }
    let mut body = vec![0; content_length];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|_| error("400 Bad Request", "incomplete body"))?;
    Ok(Request {
        method: parts[0].to_owned(),
        path: parts[1].to_owned(),
        authorization,
        content_type,
        body,
    })
}

async fn write_response(stream: &mut TcpStream, response: Response) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response.body).await
}

#[allow(clippy::needless_pass_by_value)]
fn json_response(status: &'static str, value: Value) -> Response {
    Response {
        status,
        body: serde_json::to_vec(&value).expect("JSON value serializes"),
    }
}
fn error(status: &'static str, message: &'static str) -> Response {
    json_response(status, json!({"error": message}))
}
fn device_json(device: Device) -> Value {
    json!({"id": device.id, "addresses": device.addresses.into_iter().map(|address| address.to_string()).collect::<Vec<_>>(), "profile": device.profile, "group": device.group})
}
fn is_json(request: &Request) -> bool {
    request.content_type.as_deref() == Some("application/json")
}
fn query_limit(path: &str) -> Option<u16> {
    match path.split_once('?') {
        None => Some(100),
        Some((_, query)) => query
            .strip_prefix("limit=")?
            .parse()
            .ok()
            .filter(|limit| (1..=1000).contains(limit)),
    }
}

fn audit_principal(
    state: &ApiState,
    principal: &Principal<'_>,
    request: &Request,
    outcome: &str,
    peer: SocketAddr,
) {
    audit(
        state,
        principal.name,
        principal.role.as_str(),
        &request.method.to_ascii_lowercase(),
        &request.path,
        outcome,
        peer,
    );
}

fn audit(
    state: &ApiState,
    actor: &str,
    role: &str,
    action: &str,
    target: &str,
    outcome: &str,
    peer: SocketAddr,
) {
    if let Ok(mut store) = Store::open(&state.state_path) {
        let _ = store.append_audit(actor, role, action, target, outcome, &peer.ip().to_string());
    }
    if let Some(sender) = &state.webhook_sender {
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = sender.try_send(WebhookEvent {
            created_at,
            actor: actor.to_owned(),
            role: role.to_owned(),
            action: action.to_owned(),
            target: target.to_owned(),
            outcome: outcome.to_owned(),
        });
    }
}

fn load_webhooks(config: &[Webhook]) -> io::Result<Vec<WebhookTarget>> {
    config
        .iter()
        .map(|webhook| {
            let url = reqwest::Url::parse(&webhook.url)
                .map_err(|_| io::Error::other("invalid webhook URL"))?;
            if url.scheme() != "https"
                || url.port_or_known_default() != Some(443)
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(io::Error::other("webhook requires HTTPS port 443"));
            }
            let secret = read_bounded(&webhook.secret_file, 4096).map_err(io::Error::other)?;
            let secret = secret.strip_suffix(b"\n").unwrap_or(&secret);
            let secret = secret.strip_suffix(b"\r").unwrap_or(secret).to_vec();
            if !(32..=256).contains(&secret.len()) {
                return Err(io::Error::other(
                    "webhook secret must contain 32..=256 bytes",
                ));
            }
            Ok(WebhookTarget {
                id: webhook.id.clone(),
                url,
                secret,
            })
        })
        .collect()
}

async fn deliver_webhooks(targets: Vec<WebhookTarget>, mut receiver: mpsc::Receiver<WebhookEvent>) {
    let roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<rustls::RootCertStore>();
    let Ok(tls) = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map(|builder| builder.with_root_certificates(roots).with_no_client_auth()) else {
        return;
    };
    let Ok(client) = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(true)
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(5))
        .build()
    else {
        return;
    };
    while let Some(event) = receiver.recv().await {
        let body = serde_json::to_vec(&json!({
            "version": 1,
            "event": "audit",
            "created_at": event.created_at,
            "actor": event.actor,
            "role": event.role,
            "action": event.action,
            "target": event.target,
            "outcome": event.outcome,
        }))
        .expect("webhook JSON serializes");
        for target in &targets {
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &target.secret);
            let signature = hex(ring::hmac::sign(&key, &body).as_ref());
            let _ = client
                .post(target.url.clone())
                .header("Content-Type", "application/json")
                .header("X-Lumen-Event", "audit")
                .header("X-Lumen-Webhook", &target.id)
                .header("X-Lumen-Signature", format!("sha256={signature}"))
                .body(body.clone())
                .send()
                .await;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_hashes(config: &Management) -> io::Result<()> {
    for token in &config.tokens {
        decode_hash(&token.sha256)?;
    }
    Ok(())
}
fn decode_hash(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(io::Error::other("invalid API token hash"));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(io::Error::other)?;
        bytes[index] =
            u8::from_str_radix(text, 16).map_err(|_| io::Error::other("invalid API token hash"))?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumen_config::{ApiToken, Management};
    use tempfile::tempdir;

    fn state() -> (tempfile::TempDir, ApiState) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.db");
        Store::open(&path).unwrap();
        let secret = "01234567890123456789012345678901";
        let hash: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
        (
            dir,
            ApiState {
                state_path: path,
                tokens: vec![Token {
                    name: "admin".into(),
                    role: ApiRole::Admin,
                    hash,
                }],
                requests_per_minute: 2,
                rates: Mutex::new(HashMap::new()),
                webhook_sender: None,
            },
        )
    }

    #[test]
    fn authenticates_and_scopes_routes() {
        let (_dir, state) = state();
        let request = Request {
            method: "GET".into(),
            path: "/v1/status".into(),
            authorization: Some("Bearer 01234567890123456789012345678901".into()),
            content_type: None,
            body: Vec::new(),
        };
        let principal = authenticate(&request, &state).unwrap();
        assert_eq!(principal.name, "admin");
        assert!(
            principal
                .role
                .permits(required_role("POST", "/v1/shutdown").unwrap())
        );
        assert!(required_role("GET", "/v1/missing").is_none());
    }

    #[test]
    fn rejects_bad_hash_and_bounds_rate() {
        let (_dir, state) = state();
        assert!(decode_hash("bad").is_err());
        assert!(rate_allowed(&state, "admin"));
        assert!(rate_allowed(&state, "admin"));
        assert!(!rate_allowed(&state, "admin"));
        let config = Management {
            listen: Some("127.0.0.1:9000".parse().unwrap()),
            tokens: vec![ApiToken {
                name: "admin".into(),
                role: ApiRole::Admin,
                sha256: "00".repeat(32),
            }],
            requests_per_minute: 60,
            webhooks: Vec::new(),
        };
        assert!(validate_hashes(&config).is_ok());
    }

    #[tokio::test]
    async fn serves_authenticated_status_and_audits_denials() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.db");
        let store = Store::open(&path).unwrap();
        store.set_status("running", None).unwrap();
        let secret = "01234567890123456789012345678901";
        let hash = hex(&Sha256::digest(secret.as_bytes()));
        let config = Management {
            listen: Some("127.0.0.1:0".parse().unwrap()),
            tokens: vec![ApiToken {
                name: "viewer".into(),
                role: ApiRole::Viewer,
                sha256: hash,
            }],
            requests_per_minute: 60,
            webhooks: Vec::new(),
        };
        let mut api = RunningApi::start(config, &path).await.unwrap().unwrap();

        let mut stream = TcpStream::connect(api.address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /v1/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {secret}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"status\":\"running\""));

        let mut denied = TcpStream::connect(api.address).await.unwrap();
        denied
            .write_all(b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        denied.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 401 Unauthorized"));

        api.shutdown().await;
        assert_eq!(
            Store::open(&path).unwrap().audit_events(10).unwrap().len(),
            2
        );
    }

    #[test]
    fn webhook_secrets_and_signatures_are_bounded() {
        let directory = tempdir().unwrap();
        let secret = directory.path().join("webhook.key");
        std::fs::write(&secret, b"01234567890123456789012345678901\n").unwrap();
        let targets = load_webhooks(&[Webhook {
            id: "home".into(),
            url: "https://home.example/hook".into(),
            secret_file: secret.clone(),
        }])
        .unwrap();
        assert_eq!(targets[0].secret.len(), 32);
        assert_eq!(hex(&[0, 255]), "00ff");
        std::fs::write(secret, b"short").unwrap();
        assert!(
            load_webhooks(&[Webhook {
                id: "home".into(),
                url: "https://home.example/hook".into(),
                secret_file: directory.path().join("webhook.key"),
            }])
            .is_err()
        );
    }
}

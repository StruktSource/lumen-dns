// SPDX-License-Identifier: Apache-2.0
//! Embedded, bounded console hosting over HTTP/1.1, HTTP/2, and TLS.
//!
//! The UI is a set of static files compiled into the binary. `/api/*` is the
//! session-authenticated console API (see [`Console`]).

mod console;
mod host;
pub use console::Console;
pub use host::{Counters, Explained, Host, ListInfo, QueryRecord};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue},
    service::service_fn,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use lumen_config::{Web, read_bounded};
use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

struct Asset {
    path: &'static str,
    content_type: &'static str,
    body: &'static [u8],
}

macro_rules! asset {
    ($path:literal, $type:expr, $file:literal) => {
        Asset {
            path: $path,
            content_type: $type,
            body: include_bytes!(concat!("../../../web/", $file)),
        }
    };
}

const HTML: &str = "text/html; charset=utf-8";
const CSS: &str = "text/css; charset=utf-8";
const JS: &str = "text/javascript; charset=utf-8";

const ASSETS: &[Asset] = &[
    asset!("/", HTML, "index.html"),
    asset!("/index.html", HTML, "index.html"),
    asset!("/assets/app.css", CSS, "app.css"),
    asset!("/assets/js/core.js", JS, "js/core.js"),
    asset!("/assets/js/api.js", JS, "js/api.js"),
    asset!("/assets/js/view-login.js", JS, "js/view-login.js"),
    asset!("/assets/js/view-overview.js", JS, "js/view-overview.js"),
    asset!("/assets/js/view-activity.js", JS, "js/view-activity.js"),
    asset!("/assets/js/view-devices.js", JS, "js/view-devices.js"),
    asset!("/assets/js/view-filtering.js", JS, "js/view-filtering.js"),
    asset!("/assets/js/view-dns.js", JS, "js/view-dns.js"),
    asset!("/assets/js/view-access.js", JS, "js/view-access.js"),
    asset!("/assets/js/view-system.js", JS, "js/view-system.js"),
    asset!("/assets/js/view-account.js", JS, "js/view-account.js"),
    asset!("/assets/js/app.js", JS, "js/app.js"),
];

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
/// No inline script or style, no third-party origin, no framing.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Pre-bound web listeners. Bind all sockets before any request is served.
pub struct BoundWeb {
    listeners: Vec<(TcpListener, Option<TlsAcceptor>)>,
    connections: Arc<Semaphore>,
    console: Option<Arc<Console>>,
    pub endpoints: Vec<(bool, std::net::SocketAddr)>,
}

impl BoundWeb {
    /// Validate credentials and bind all configured web sockets.
    ///
    /// # Errors
    /// Returns invalid TLS material or socket bind errors.
    pub async fn bind(config: &Web, console: Option<Arc<Console>>) -> io::Result<Option<Self>> {
        if config.http.is_empty() && config.https.is_empty() {
            return Ok(None);
        }
        let tls = if config.https.is_empty() {
            None
        } else {
            Some(TlsAcceptor::from(Arc::new(tls_config(config)?)))
        };
        let mut listeners = Vec::with_capacity(config.http.len() + config.https.len());
        let mut endpoints = Vec::with_capacity(config.http.len() + config.https.len());
        for address in &config.http {
            let listener = TcpListener::bind(address).await?;
            endpoints.push((false, listener.local_addr()?));
            listeners.push((listener, None));
        }
        for address in &config.https {
            let listener = TcpListener::bind(address).await?;
            endpoints.push((true, listener.local_addr()?));
            listeners.push((listener, tls.clone()));
        }
        Ok(Some(Self {
            listeners,
            connections: Arc::new(Semaphore::new(usize::from(config.max_connections))),
            console,
            endpoints,
        }))
    }

    /// Validate HTTPS credentials without binding sockets.
    ///
    /// # Errors
    /// Returns invalid, unreadable, or mismatched TLS material.
    pub fn check(config: &Web) -> io::Result<()> {
        if !config.https.is_empty() {
            let _ = tls_config(config)?;
        }
        Ok(())
    }

    /// Serve until a listener exits unexpectedly.
    ///
    /// # Errors
    /// Returns listener and task failures.
    pub async fn serve(self) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        if let Some(console) = &self.console {
            let console = Arc::clone(console);
            tasks.spawn(async move { console.run_sampler().await });
        }
        for (listener, tls) in self.listeners {
            tasks.spawn(serve_listener(
                listener,
                tls,
                Arc::clone(&self.connections),
                self.console.clone(),
            ));
        }
        match tasks.join_next().await {
            Some(Ok(Err(error))) => Err(error),
            Some(Err(error)) => Err(io::Error::other(error)),
            _ => Err(io::Error::other("web listener stopped unexpectedly")),
        }
    }
}

async fn serve_listener(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    connections: Arc<Semaphore>,
    console: Option<Arc<Console>>,
) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        let (stream, peer) = listener.accept().await?;
        while tasks.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            continue;
        };
        let console = console.clone();
        if let Some(tls) = tls.clone() {
            tasks.spawn(async move {
                if let Ok(Ok(stream)) = timeout(CONNECTION_TIMEOUT, tls.accept(stream)).await {
                    serve_tls(stream, permit, console, peer).await;
                }
            });
        } else {
            tasks.spawn(serve_tcp(stream, permit, console, peer));
        }
    }
}

async fn serve_tcp(
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    console: Option<Arc<Console>>,
    peer: SocketAddr,
) {
    let builder = Builder::new(TokioExecutor::new());
    let service = service_fn(move |request| respond(request, console.clone(), peer, false));
    let _ = timeout(
        CONNECTION_TIMEOUT,
        builder.serve_connection(TokioIo::new(stream), service),
    )
    .await;
}

async fn serve_tls(
    stream: TlsStream<TcpStream>,
    _permit: OwnedSemaphorePermit,
    console: Option<Arc<Console>>,
    peer: SocketAddr,
) {
    let builder = Builder::new(TokioExecutor::new());
    let service = service_fn(move |request| respond(request, console.clone(), peer, true));
    let _ = timeout(
        CONNECTION_TIMEOUT,
        builder.serve_connection(TokioIo::new(stream), service),
    )
    .await;
}

async fn respond(
    request: Request<Incoming>,
    console: Option<Arc<Console>>,
    peer: SocketAddr,
    tls: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path();
    if path == "/api" || path.starts_with("/api/") {
        let mut response = match console {
            None => api_disabled(),
            Some(console) => {
                let body = match timeout(
                    BODY_TIMEOUT,
                    Limited::new(body, console::MAX_BODY).collect(),
                )
                .await
                {
                    Ok(Ok(collected)) => collected.to_bytes(),
                    _ => {
                        return Ok(secure(
                            error_response(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                "request body too large or too slow",
                            ),
                            true,
                        ));
                    }
                };
                let request = console::Request {
                    method: parts.method.clone(),
                    path: path.to_owned(),
                    query: parts.uri.query().unwrap_or("").to_owned(),
                    headers: parts.headers.clone(),
                    body,
                    peer,
                    tls,
                };
                // SQLite and password hashing block; keep them off the async executor.
                match tokio::task::spawn_blocking(move || console.handle(&request)).await {
                    Ok(response) => response,
                    Err(_) => {
                        error_response(StatusCode::INTERNAL_SERVER_ERROR, "console task failed")
                    }
                }
            }
        };
        let headers = response.headers_mut();
        headers.insert("cache-control", HeaderValue::from_static("no-store"));
        return Ok(secure(response, true));
    }
    Ok(secure(static_response(&parts.method, path), false))
}

fn api_disabled() -> Response<Full<Bytes>> {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "The console needs managed mode: start Lumen with --state FILE.",
    )
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(format!(
        "{{\"error\":{}}}",
        serde_json::Value::String(message.to_owned())
    ))));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

fn secure(mut response: Response<Full<Bytes>>, api: bool) -> Response<Full<Bytes>> {
    let headers = response.headers_mut();
    if !api {
        headers
            .entry("cache-control")
            .or_insert(HeaderValue::from_static("no-cache"));
    }
    headers.insert("content-security-policy", HeaderValue::from_static(CSP));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    response
}

fn static_response(method: &Method, path: &str) -> Response<Full<Bytes>> {
    let head = method == Method::HEAD;
    let allowed = method == Method::GET || head;
    let (status, content_type, source): (StatusCode, &str, &[u8]) = if allowed {
        if path == "/healthz" {
            (StatusCode::OK, "text/plain; charset=utf-8", b"ok\n")
        } else if let Some(asset) = ASSETS.iter().find(|asset| asset.path == path) {
            (StatusCode::OK, asset.content_type, asset.body)
        } else {
            (StatusCode::NOT_FOUND, "text/plain; charset=utf-8", b"")
        }
    } else {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            b"",
        )
    };
    let body = if head || status != StatusCode::OK {
        Bytes::new()
    } else {
        Bytes::from_static(source)
    };
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    if head {
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&source.len().to_string()).expect("content length header"),
        );
    }
    response
}

fn tls_config(config: &Web) -> io::Result<ServerConfig> {
    let cert = read_bounded(
        config
            .certificate
            .as_ref()
            .ok_or_else(|| io::Error::other("web HTTPS needs certificate"))?,
        1_048_576,
    )
    .map_err(io::Error::other)?;
    let key = read_bounded(
        config
            .private_key
            .as_ref()
            .ok_or_else(|| io::Error::other("web HTTPS needs private_key"))?,
        65_536,
    )
    .map_err(io::Error::other)?;
    let certificates = CertificateDer::pem_slice_iter(&cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::other("invalid web PEM certificate"))?;
    let private_key = PrivateKeyDer::from_pem_slice(&key)
        .map_err(|_| io::Error::other("invalid web PEM private key"))?;
    let mut tls =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)
            .map_err(|_| io::Error::other("web certificate and private key do not match"))?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tls.max_early_data_size = 0;
    Ok(tls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn index() -> &'static [u8] {
        ASSETS.iter().find(|a| a.path == "/").unwrap().body
    }

    #[test]
    fn routes_are_exact_and_headers_strict() {
        let page = secure(static_response(&Method::GET, "/"), false);
        assert_eq!(page.status(), StatusCode::OK);
        assert_eq!(page.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
        let csp = page.headers()["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("script-src 'self'") && csp.contains("default-src 'none'"));
        assert!(
            !csp.contains("unsafe-inline") && !csp.contains("unsafe-eval") && !csp.contains("http")
        );
        assert_eq!(page.headers()["x-frame-options"], "DENY");
        for path in [
            "/missing",
            "/assets/../index.html",
            "/assets/js/",
            "/assets/js/core.js/x",
            "/api",
        ] {
            assert_eq!(
                static_response(&Method::GET, path).status(),
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        assert_eq!(
            static_response(&Method::POST, "/").status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            static_response(&Method::HEAD, "/").headers()[CONTENT_LENGTH],
            index().len().to_string()
        );
        assert_eq!(
            static_response(&Method::GET, "/healthz").status(),
            StatusCode::OK
        );
        assert!(index().starts_with(b"<!doctype html>"));
    }

    #[test]
    fn every_asset_is_served_and_the_page_loads_only_embedded_files() {
        let html = String::from_utf8_lossy(index()).into_owned();
        for asset in ASSETS {
            assert!(!asset.body.is_empty(), "{}", asset.path);
            assert_eq!(
                static_response(&Method::GET, asset.path).status(),
                StatusCode::OK
            );
        }
        // Every script and stylesheet the page references exists, and nothing external is loaded.
        for reference in html
            .split(['"', '\''])
            .filter(|part| part.starts_with("/assets/"))
        {
            assert!(
                ASSETS.iter().any(|a| a.path == reference),
                "{reference} is referenced but not embedded"
            );
        }
        let without_namespace = html.replace("http://www.w3.org/2000/svg", "");
        assert!(!without_namespace.contains("http://") && !without_namespace.contains("https://"));
        for asset in ASSETS.iter().filter(|a| {
            std::path::Path::new(a.path)
                .extension()
                .is_some_and(|e| e == "js")
        }) {
            let source = String::from_utf8_lossy(asset.body);
            assert!(
                !source.contains("eval(") && !source.contains("new Function"),
                "{}",
                asset.path
            );
        }
    }

    async fn get(address: SocketAddr, path: &str, extra: &str) -> String {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}Connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).into_owned()
    }

    fn config() -> Web {
        Web {
            http: vec!["127.0.0.1:0".parse().unwrap()],
            https: Vec::new(),
            certificate: None,
            private_key: None,
            max_connections: 4,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_ui_over_http_and_refuses_api_without_managed_mode() {
        let web = BoundWeb::bind(&config(), None).await.unwrap().unwrap();
        let address = web.endpoints[0].1;
        let task = tokio::spawn(web.serve());
        let page = get(address, "/", "").await;
        assert!(page.starts_with("HTTP/1.1 200 OK"));
        assert!(page.to_ascii_lowercase().contains("x-frame-options: deny"));
        assert!(page.contains("/assets/js/app.js"));
        let script = get(address, "/assets/js/app.js", "").await;
        assert!(script.contains("content-type: text/javascript"));
        let api = get(address, "/api/state", "").await;
        assert!(api.starts_with("HTTP/1.1 503"), "{api}");
        assert!(api.contains("managed mode"));
        assert!(api.to_ascii_lowercase().contains("cache-control: no-store"));
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_works_over_a_socket_with_cookies_and_blocking_work_off_the_executor() {
        struct Host0;
        impl Host for Host0 {
            fn counters(&self) -> Counters {
                Counters::default()
            }
            fn lists(&self) -> Vec<ListInfo> {
                Vec::new()
            }
            fn explain(&self, _: &str, _: std::net::IpAddr, _: u64) -> Explained {
                unreachable!()
            }
            fn uptime_secs(&self) -> u64 {
                1
            }
            fn history_enabled(&self) -> bool {
                false
            }
            fn set_history(&self, _: bool) {}
            fn history(&self, _: usize) -> Vec<QueryRecord> {
                Vec::new()
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.db");
        let mut store = lumen_store::Store::open(&state).unwrap();
        store
            .set_config("schema_version = 1\n", directory.path())
            .unwrap();
        let record =
            lumen_store::password::hash_with_iterations("correct horse battery", 1_000).unwrap();
        store.create_first_admin("admin", &record).unwrap();
        drop(store);
        let console = Arc::new(Console::new(state, Arc::new(Host0), "t"));
        let web = BoundWeb::bind(&config(), Some(console))
            .await
            .unwrap()
            .unwrap();
        let address = web.endpoints[0].1;
        let task = tokio::spawn(web.serve());
        let mut stream = TcpStream::connect(address).await.unwrap();
        let body = r#"{"username":"admin","password":"correct horse battery"}"#;
        stream
            .write_all(format!("POST /api/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("set-cookie: lumen_session=")
                && lower.contains("httponly")
                && lower.contains("samesite=strict")
        );
        assert!(
            !lower.contains("; secure"),
            "plain HTTP must not claim Secure"
        );
        assert!(lower.contains("cache-control: no-store"));
        task.abort();
    }

    #[test]
    fn direct_https_uses_tls13_and_h2_alpn() {
        let directory = tempfile::tempdir().unwrap();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(directory.path().join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(
            directory.path().join("key.pem"),
            signing_key.serialize_pem(),
        )
        .unwrap();
        let config = Web {
            http: Vec::new(),
            https: vec!["127.0.0.1:8443".parse().unwrap()],
            certificate: Some(directory.path().join("cert.pem")),
            private_key: Some(directory.path().join("key.pem")),
            max_connections: 4,
        };
        let tls = tls_config(&config).unwrap();
        assert_eq!(tls.alpn_protocols, [b"h2".to_vec(), b"http/1.1".to_vec()]);
        assert_eq!(tls.max_early_data_size, 0);
    }
}

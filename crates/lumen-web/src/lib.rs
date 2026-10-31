// SPDX-License-Identifier: Apache-2.0
//! Embedded, bounded static UI hosting over HTTP/1.1, HTTP/2, and TLS.

use bytes::Bytes;
use http_body_util::Full;
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
use std::{io, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const INDEX: &[u8] = include_bytes!("../../../web/index.html");
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Pre-bound web listeners. Bind all sockets before any request is served.
pub struct BoundWeb {
    listeners: Vec<(TcpListener, Option<TlsAcceptor>)>,
    connections: Arc<Semaphore>,
    pub endpoints: Vec<(bool, std::net::SocketAddr)>,
}

impl BoundWeb {
    /// Validate credentials and bind all configured web sockets.
    ///
    /// # Errors
    /// Returns invalid TLS material or socket bind errors.
    pub async fn bind(config: &Web) -> io::Result<Option<Self>> {
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
        for (listener, tls) in self.listeners {
            tasks.spawn(serve_listener(listener, tls, Arc::clone(&self.connections)));
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
) -> io::Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        let (stream, _) = listener.accept().await?;
        while tasks.try_join_next().is_some() {}
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            continue;
        };
        if let Some(tls) = tls.clone() {
            tasks.spawn(async move {
                if let Ok(Ok(stream)) = timeout(CONNECTION_TIMEOUT, tls.accept(stream)).await {
                    serve_tls(stream, permit).await;
                }
            });
        } else {
            tasks.spawn(serve_tcp(stream, permit));
        }
    }
}

async fn serve_tcp(stream: TcpStream, _permit: OwnedSemaphorePermit) {
    let builder = Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection(TokioIo::new(stream), service_fn(response));
    let _ = timeout(CONNECTION_TIMEOUT, connection).await;
}

async fn serve_tls(stream: TlsStream<TcpStream>, _permit: OwnedSemaphorePermit) {
    let builder = Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection(TokioIo::new(stream), service_fn(response));
    let _ = timeout(CONNECTION_TIMEOUT, connection).await;
}

async fn response(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    Ok(static_response(request.method(), request.uri().path()))
}

fn static_response(method: &Method, path: &str) -> Response<Full<Bytes>> {
    let head = method == Method::HEAD;
    let allowed = method == Method::GET || head;
    let (status, content_type, source) = if allowed {
        match path {
            "/" | "/index.html" => (StatusCode::OK, "text/html; charset=utf-8", INDEX),
            "/healthz" => (StatusCode::OK, "text/plain; charset=utf-8", &b"ok\n"[..]),
            _ => (StatusCode::NOT_FOUND, "text/plain; charset=utf-8", &[][..]),
        }
    } else {
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            &[][..],
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
    headers.insert("cache-control", HeaderValue::from_static("no-cache"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
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

    #[test]
    fn shell_routes_and_headers_are_strict() {
        let index = static_response(&Method::GET, "/");
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(index.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(
            index.headers()["content-security-policy"],
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        );
        assert_eq!(
            static_response(&Method::GET, "/missing").status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            static_response(&Method::POST, "/").status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            static_response(&Method::HEAD, "/").headers()[CONTENT_LENGTH],
            INDEX.len().to_string()
        );
        assert!(INDEX.starts_with(b"<!doctype html>"));
        assert!(INDEX.len() < 16_384);
    }

    #[tokio::test]
    async fn serves_embedded_shell_over_http() {
        let config = Web {
            http: vec!["127.0.0.1:0".parse().unwrap()],
            https: Vec::new(),
            certificate: None,
            private_key: None,
            max_connections: 4,
        };
        let web = BoundWeb::bind(&config).await.unwrap().unwrap();
        let address = web.endpoints[0].1;
        let task = tokio::spawn(web.serve());
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert!(response.windows(INDEX.len()).any(|window| window == INDEX));
        assert!(
            String::from_utf8_lossy(&response)
                .to_ascii_lowercase()
                .contains("x-frame-options: deny")
        );
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

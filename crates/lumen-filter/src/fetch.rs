// SPDX-License-Identifier: Apache-2.0
//! HTTPS-only downloads with DNS pinning, no redirects/proxies, and hard bounds.

use crate::rules::MAX_LIST_BYTES;
use reqwest::{Client, Url};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub(crate) fn validate_url(source: &str) -> Result<Url, String> {
    if source.len() > 2048 {
        return Err("list URL too long".into());
    }
    let url = Url::parse(source).map_err(|_| "invalid list URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err("list URLs require HTTPS port 443 without credentials or fragments".into());
    }
    Ok(url)
}

// Conservative public-unicast allowlist. Special, private, mapped, transition,
// multicast, loopback, documentation, benchmarking, and metadata targets denied.
pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127 | 224..=255)
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000 == 0x2000)
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

pub(crate) async fn download(source: &str) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let url = validate_url(source)?;
        let host = url
            .host_str()
            .ok_or("missing list host")?
            .trim_matches(['[', ']']);
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, 443))
            .await
            .map_err(|_| "list host lookup failed")?
            .take(33)
            .collect();
        if addresses.is_empty()
            || addresses.len() > 32
            || addresses.iter().any(|a| !public_ip(a.ip()))
        {
            return Err("list host must resolve only to public unicast addresses".into());
        }
        let roots = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
            .collect::<rustls::RootCertStore>();
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| "TLS setup failed")?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(true)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(25))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|_| "list client setup failed")?;
        read_response(&client, url).await
    })
    .await
    .map_err(|_| "list download deadline exceeded")?
}

pub(crate) async fn read_response(client: &Client, url: Url) -> Result<Vec<u8>, String> {
    let mut response = client
        .get(url)
        .header("Accept", "text/plain")
        .send()
        .await
        .map_err(|_| "list HTTPS request failed")?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("list requires HTTP 200; redirects rejected".into());
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_LIST_BYTES as u64)
    {
        return Err("list response exceeds 8 MiB".into());
    }
    if response
        .headers()
        .get("content-encoding")
        .is_some_and(|value| value != "identity")
    {
        return Err("compressed lists are not supported".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "list body read failed")?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_LIST_BYTES {
            return Err("list body exceeds 8 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

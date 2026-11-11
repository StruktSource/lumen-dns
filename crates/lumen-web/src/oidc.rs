// SPDX-License-Identifier: Apache-2.0
//! External console sign-in through `OpenID` Connect: authorization code flow with PKCE.
//!
//! Lumen is the relying party. It discovers the provider, sends the browser to it, and
//! exchanges the returned code directly with the provider's token endpoint over TLS. That
//! direct, TLS-protected exchange is what lets the ID token's claims be trusted without
//! checking its signature (`OpenID` Connect Core 3.1.3.7, step 6), so Lumen needs no JWT or JWKS
//! code. Everything it does validate is checked: issuer, audience, expiry, and the nonce.
//!
//! Provider tokens are never stored. Only the stable `(issuer, subject)` pair is kept.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use lumen_config::{Oidc, oidc_url_ok, read_bounded};
use lumen_store::password;
use reqwest::{Client, Url};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// A sign-in must be finished within this time of starting.
pub(crate) const FLOW_SECS: u64 = 600;
const MAX_PENDING: usize = 256;
const DISCOVERY_SECS: u64 = 3600;
const MAX_RESPONSE: usize = 64 * 1024;
/// Allowed clock difference between Lumen and the provider.
const SKEW_SECS: u64 = 120;

/// What a successful sign-in proved about a person.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub issuer: String,
    pub subject: String,
    pub username: Option<String>,
    pub groups: Vec<String>,
}

struct Provider {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    /// Send the client secret in the form body instead of a Basic header.
    secret_in_body: bool,
    /// Where to send the browser to end the provider's own session, when it offers one.
    end_session_endpoint: Option<String>,
}

struct Pending {
    verifier: String,
    nonce: String,
    at: Instant,
    /// Set when a signed-in person is linking their existing account instead of signing in.
    link: Option<i64>,
}

/// Discovery cache and the sign-ins that are waiting for their browser to come back.
#[derive(Default)]
pub(crate) struct Flows {
    provider: Mutex<Option<(Instant, Arc<Provider>)>>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl Flows {
    /// Start a sign-in, or with `link` the linking of that account. Returns the provider URL to
    /// send the browser to and the state value that the flow cookie must carry.
    pub(crate) fn begin(
        &self,
        config: &Oidc,
        link: Option<i64>,
    ) -> Result<(String, String), String> {
        let provider = self.provider(config)?;
        let state = password::random_hex(16)?;
        let nonce = password::random_hex(16)?;
        let verifier = password::random_hex(32)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut url = Url::parse(&provider.authorization_endpoint)
            .map_err(|_| "invalid authorization endpoint")?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", &config.redirect_url)
            .append_pair("scope", "openid profile email groups")
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        let mut pending = self.pending.lock().expect("oidc pending");
        pending.retain(|_, flow| flow.at.elapsed().as_secs() < FLOW_SECS);
        while pending.len() >= MAX_PENDING {
            let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, flow)| flow.at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            pending.remove(&oldest);
        }
        pending.insert(
            state.clone(),
            Pending {
                verifier,
                nonce,
                at: Instant::now(),
                link,
            },
        );
        Ok((url.into(), state))
    }

    /// Finish a sign-in for `state` with the code the provider returned. A state works once.
    /// The second value is the account being linked, for a linking flow.
    pub(crate) fn finish(
        &self,
        config: &Oidc,
        state: &str,
        code: &str,
    ) -> Result<(Identity, Option<i64>), String> {
        let flow = self
            .pending
            .lock()
            .expect("oidc pending")
            .remove(state)
            .filter(|flow| flow.at.elapsed().as_secs() < FLOW_SECS)
            .ok_or("sign-in expired or unknown")?;
        if code.is_empty() || code.len() > 2048 {
            return Err("invalid authorization code".into());
        }
        let provider = self.provider(config)?;
        let token = block(exchange(config, &provider, code, &flow.verifier))?;
        let id_token = token
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or("provider sent no ID token")?;
        let claims = payload(id_token)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        check_claims(&claims, config, &provider.issuer, &flow.nonce, now)
            .map(|identity| (identity, flow.link))
    }

    /// The provider's logout address for a person who signed in through it, if it has one.
    /// Best effort: `None` means signing out of the console is all that happens.
    pub(crate) fn logout_url(&self, config: &Oidc) -> Option<String> {
        let provider = self.provider(config).ok()?;
        let mut url = Url::parse(provider.end_session_endpoint.as_deref()?).ok()?;
        let back = Url::parse(&config.redirect_url)
            .ok()?
            .origin()
            .ascii_serialization()
            + "/";
        url.query_pairs_mut()
            .append_pair("client_id", &config.client_id)
            .append_pair("post_logout_redirect_uri", &back);
        Some(url.into())
    }

    fn provider(&self, config: &Oidc) -> Result<Arc<Provider>, String> {
        if let Some((at, provider)) = &*self.provider.lock().expect("oidc provider")
            && at.elapsed().as_secs() < DISCOVERY_SECS
            && same_issuer(&provider.issuer, &config.issuer)
        {
            return Ok(Arc::clone(provider));
        }
        let provider = Arc::new(block(discover(config))?);
        *self.provider.lock().expect("oidc provider") =
            Some((Instant::now(), Arc::clone(&provider)));
        Ok(provider)
    }
}

/// Run a future from a blocking thread (or a test thread with no runtime).
fn block<F: Future>(future: F) -> F::Output {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle.block_on(future),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("oidc runtime")
            .block_on(future),
    }
}

/// Issuers match exactly, except that one trailing slash more or less is tolerated.
fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

fn client(config: &Oidc) -> Result<Client, String> {
    let mut roots = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<rustls::RootCertStore>();
    if let Some(path) = &config.ca_file {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let bytes = read_bounded(path, 1_048_576)?;
        for certificate in CertificateDer::pem_slice_iter(&bytes) {
            roots
                .add(certificate.map_err(|_| "invalid web.oidc.ca_file PEM")?)
                .map_err(|_| "invalid web.oidc.ca_file certificate")?;
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "TLS setup failed")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Client::builder()
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "sign-in client setup failed".into())
}

/// Read a response body of at most [`MAX_RESPONSE`] bytes.
async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "provider response failed")?
    {
        if bytes.len() + chunk.len() > MAX_RESPONSE {
            return Err("provider response is too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn discover(config: &Oidc) -> Result<Provider, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        config.issuer.trim_end_matches('/')
    );
    let response = client(config)?
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|_| "provider discovery failed")?;
    if !response.status().is_success() {
        return Err("provider discovery was refused".into());
    }
    let document: Value = serde_json::from_slice(&read_limited(response).await?)
        .map_err(|_| "provider discovery is not JSON")?;
    let field = |name: &str| {
        document
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let issuer = field("issuer").ok_or("provider discovery has no issuer")?;
    if !same_issuer(&issuer, &config.issuer) {
        return Err("provider issuer does not match web.oidc.issuer".into());
    }
    let authorization_endpoint =
        field("authorization_endpoint").ok_or("no authorization endpoint")?;
    let token_endpoint = field("token_endpoint").ok_or("no token endpoint")?;
    if !oidc_url_ok(&authorization_endpoint) || !oidc_url_ok(&token_endpoint) {
        return Err("provider endpoints must use https".into());
    }
    let methods: Vec<&str> = document
        .get("token_endpoint_auth_methods_supported")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let end_session_endpoint = field("end_session_endpoint").filter(|url| oidc_url_ok(url));
    Ok(Provider {
        issuer,
        authorization_endpoint,
        token_endpoint,
        end_session_endpoint,
        secret_in_body: methods.contains(&"client_secret_post")
            && !methods.contains(&"client_secret_basic"),
    })
}

fn encoded(value: &str) -> String {
    let mut url = Url::parse("https://x.invalid/").expect("static URL");
    url.query_pairs_mut().append_pair("v", value);
    url.query()
        .unwrap_or("v=")
        .trim_start_matches("v=")
        .to_owned()
}

async fn exchange(
    config: &Oidc,
    provider: &Provider,
    code: &str,
    verifier: &str,
) -> Result<Value, String> {
    let secret = match &config.client_secret_file {
        Some(path) => Some(
            String::from_utf8(read_bounded(path, 4096)?)
                .map_err(|_| "client secret must be UTF-8")?
                .trim()
                .to_owned(),
        ),
        None => None,
    };
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        encoded(code),
        encoded(&config.redirect_url),
        encoded(&config.client_id),
        encoded(verifier)
    );
    let mut request = client(config)?
        .post(&provider.token_endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded");
    if let Some(secret) = secret.filter(|secret| !secret.is_empty()) {
        if provider.secret_in_body {
            form.push_str("&client_secret=");
            form.push_str(&encoded(&secret));
        } else {
            request = request.basic_auth(encoded(&config.client_id), Some(encoded(&secret)));
        }
    }
    let response = request
        .body(form)
        .send()
        .await
        .map_err(|_| "token request failed")?;
    let success = response.status().is_success();
    let body = read_limited(response).await?;
    if !success {
        return Err("provider refused the authorization code".into());
    }
    serde_json::from_slice(&body).map_err(|_| "token response is not JSON".into())
}

/// The claims of a JWT. The signature is not checked; see the module documentation.
fn payload(token: &str) -> Result<Value, String> {
    let mut parts = token.split('.');
    let (Some(_), Some(claims), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("malformed ID token".into());
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(claims.trim_end_matches('='))
        .map_err(|_| "malformed ID token")?;
    serde_json::from_slice(&bytes).map_err(|_| "malformed ID token".into())
}

fn check_claims(
    claims: &Value,
    config: &Oidc,
    issuer: &str,
    nonce: &str,
    now: u64,
) -> Result<Identity, String> {
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if !text("iss").is_some_and(|value| same_issuer(value, issuer)) {
        return Err("ID token issuer is wrong".into());
    }
    let audience_ok = match claims.get("aud") {
        Some(Value::String(one)) => one == &config.client_id,
        Some(Value::Array(list)) => {
            list.iter().any(|v| v.as_str() == Some(&config.client_id))
                && (list.len() == 1 || text("azp") == Some(&config.client_id))
        }
        _ => false,
    };
    if !audience_ok {
        return Err("ID token is for another client".into());
    }
    let expires = claims
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or("ID token has no expiry")?;
    if expires.saturating_add(SKEW_SECS) < now {
        return Err("ID token expired".into());
    }
    if claims
        .get("iat")
        .and_then(Value::as_u64)
        .is_some_and(|issued| issued > now + SKEW_SECS)
    {
        return Err("ID token is from the future".into());
    }
    if text("nonce") != Some(nonce) {
        return Err("ID token nonce is wrong".into());
    }
    let subject = text("sub")
        .filter(|s| !s.is_empty())
        .ok_or("ID token has no subject")?;
    let groups = match claims.get(&config.groups_claim) {
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(Value::as_str)
            .take(256)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(one)) => vec![one.clone()],
        _ => Vec::new(),
    };
    Ok(Identity {
        issuer: issuer.to_owned(),
        subject: subject.to_owned(),
        username: text(&config.username_claim).map(str::to_owned),
        groups,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    pub(crate) fn config(issuer: &str) -> Oidc {
        Oidc {
            enabled: true,
            issuer: issuer.into(),
            client_id: "lumen".into(),
            redirect_url: "http://127.0.0.1:1/api/login/oidc/callback".into(),
            ..Oidc::default()
        }
    }

    fn token(claims: &Value) -> String {
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}"),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    #[test]
    fn claims_must_match_issuer_audience_expiry_and_nonce() {
        let config = config("https://id.example/");
        let good = json!({
            "iss": "https://id.example", "aud": "lumen", "exp": 2000, "iat": 1000,
            "nonce": "n1", "sub": "abc", "preferred_username": "Anna", "groups": ["lumen-admins", 7]
        });
        let who = check_claims(&good, &config, "https://id.example/", "n1", 1500).unwrap();
        assert_eq!(who.subject, "abc");
        assert_eq!(who.username.as_deref(), Some("Anna"));
        assert_eq!(who.groups, ["lumen-admins"]);

        let bad = |change: Value| {
            let mut claims = good.clone();
            for (key, value) in change.as_object().unwrap() {
                if value.is_null() {
                    claims.as_object_mut().unwrap().remove(key);
                } else {
                    claims[key] = value.clone();
                }
            }
            check_claims(&claims, &config, "https://id.example/", "n1", 1500).is_err()
        };
        assert!(bad(json!({"iss": "https://evil.example"})));
        assert!(bad(json!({"aud": "someone-else"})));
        assert!(bad(json!({"aud": ["lumen", "other"]})), "azp is needed");
        assert!(!bad(json!({"aud": ["lumen", "other"], "azp": "lumen"})));
        assert!(bad(json!({"exp": 1000})), "expired beyond the skew");
        assert!(!bad(json!({"exp": 1400})), "inside the skew");
        assert!(bad(json!({"exp": null})));
        assert!(bad(json!({"iat": 5000})));
        assert!(bad(json!({"nonce": "other"})));
        assert!(bad(json!({"nonce": null})));
        assert!(bad(json!({"sub": null})));
        assert!(bad(json!({"sub": ""})));
    }

    #[test]
    fn id_token_payload_is_bounded_to_three_parts() {
        assert_eq!(payload(&token(&json!({"sub": "x"}))).unwrap()["sub"], "x");
        assert!(payload("only.two").is_err());
        assert!(payload("a.b.c.d").is_err());
        assert!(payload("a.!!!.c").is_err());
    }

    /// A provider on loopback that answers discovery and the token request.
    pub(crate) struct Provider {
        pub base: String,
        pub nonce: Arc<Mutex<String>>,
        pub requests: Arc<Mutex<Vec<String>>>,
    }

    pub(crate) fn mock_provider(subject: &'static str, audience: &'static str) -> Provider {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let nonce = Arc::new(Mutex::new(String::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (served_base, served_nonce, served) =
            (base.clone(), Arc::clone(&nonce), Arc::clone(&requests));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut buffer = vec![0; 8192];
                let size = stream.read(&mut buffer).unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..size]).into_owned();
                served.lock().unwrap().push(request.clone());
                let body = if request.starts_with("GET /.well-known/openid-configuration") {
                    json!({
                        "issuer": served_base,
                        "authorization_endpoint": format!("{served_base}/authorize"),
                        "token_endpoint": format!("{served_base}/token"),
                        "end_session_endpoint": format!("{served_base}/logout"),
                    })
                } else if request.starts_with("POST /token") {
                    let claims = json!({
                        "iss": served_base, "aud": audience,
                        "exp": u64::MAX / 2, "nonce": served_nonce.lock().unwrap().clone(),
                        "sub": subject, "preferred_username": "Anna", "groups": ["lumen-admins"],
                    });
                    json!({"id_token": token(&claims), "access_token": "unused"})
                } else {
                    json!({})
                }
                .to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Provider {
            base,
            nonce,
            requests,
        }
    }

    pub(crate) fn nonce_of(url: &str) -> String {
        Url::parse(url)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "nonce")
            .unwrap()
            .1
            .into_owned()
    }

    #[test]
    fn full_flow_uses_pkce_validates_the_token_and_works_once() {
        let provider = mock_provider("subject-1", "lumen");
        let config = config(&provider.base);
        let flows = Flows::default();
        let (url, state) = flows.begin(&config, None).unwrap();
        let parsed = Url::parse(&url).unwrap();
        assert_eq!(parsed.path(), "/authorize");
        let query: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], "lumen");
        assert_eq!(query["state"], state);
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(query["code_challenge"].len(), 43);
        *provider.nonce.lock().unwrap() = nonce_of(&url);

        let (who, link) = flows.finish(&config, &state, "the-code").unwrap();
        assert_eq!(link, None);
        assert_eq!(who.subject, "subject-1");
        assert_eq!(who.groups, ["lumen-admins"]);
        let token_request = provider
            .requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.starts_with("POST /token"))
            .cloned()
            .unwrap();
        assert!(token_request.contains("code=the-code"));
        assert!(token_request.contains("code_verifier="));
        // The same state cannot be replayed, and an unknown one is refused.
        assert!(flows.finish(&config, &state, "the-code").is_err());
        assert!(flows.finish(&config, "unknown", "c").is_err());
    }

    #[test]
    fn a_linking_flow_carries_its_account_and_logout_names_the_client() {
        let provider = mock_provider("subject-9", "lumen");
        let config = config(&provider.base);
        let flows = Flows::default();
        let (url, state) = flows.begin(&config, Some(42)).unwrap();
        *provider.nonce.lock().unwrap() = nonce_of(&url);
        let (who, link) = flows.finish(&config, &state, "code").unwrap();
        assert_eq!((who.subject.as_str(), link), ("subject-9", Some(42)));

        let logout = Url::parse(&flows.logout_url(&config).unwrap()).unwrap();
        assert_eq!(logout.path(), "/logout");
        let query: HashMap<_, _> = logout.query_pairs().into_owned().collect();
        assert_eq!(query["client_id"], "lumen");
        assert_eq!(query["post_logout_redirect_uri"], "http://127.0.0.1:1/");
    }

    #[test]
    fn a_token_for_another_client_or_a_wrong_issuer_is_refused() {
        let provider = mock_provider("subject-1", "someone-else");
        let config = config(&provider.base);
        let flows = Flows::default();
        let (url, state) = flows.begin(&config, None).unwrap();
        *provider.nonce.lock().unwrap() = nonce_of(&url);
        assert!(flows.finish(&config, &state, "code").is_err());

        // Discovery for a different issuer than configured fails closed.
        let provider = mock_provider("subject-1", "lumen");
        let mut config = self::config(&provider.base);
        config.issuer = "http://127.0.0.1:9/".into();
        assert!(Flows::default().begin(&config, None).is_err());
    }

    #[test]
    fn waiting_sign_ins_are_bounded() {
        let provider = mock_provider("s", "lumen");
        let config = config(&provider.base);
        let flows = Flows::default();
        for _ in 0..MAX_PENDING + 20 {
            flows.begin(&config, None).unwrap();
        }
        assert_eq!(flows.pending.lock().unwrap().len(), MAX_PENDING);
    }
}

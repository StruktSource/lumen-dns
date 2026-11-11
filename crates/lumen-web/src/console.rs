// SPDX-License-Identifier: Apache-2.0
//! Session-authenticated JSON API behind the embedded console. Accounts, sessions,
//! settings and control all live in the managed `SQLite` state; DNS data comes from
//! the daemon through [`Host`].
#![allow(clippy::unused_self)] // Handlers live on `Console` so each route reads as one method.

use crate::host::{Counters, HistoryDetail, HistoryMode, HistorySettings, Host};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    HeaderMap, Method, Response, StatusCode,
    header::{CONTENT_TYPE, COOKIE, HOST, HeaderValue, ORIGIN, SET_COOKIE},
};
use lumen_config::{Config, providers::Catalog};
use lumen_filter::config::Device;
use lumen_store::{
    Command, HistoryPrefs, MAX_RETENTION_DAYS, QUERY_LOG_MAX_ROWS, QueryFilter, QueryRow, Role,
    Session, Store, password, totp,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(crate) type Reply = Response<Full<Bytes>>;

const COOKIE_NAME: &str = "lumen_session";
/// Carries the sign-in state through the provider's redirect. `Lax`, because the provider's
/// redirect back is a cross-site navigation that a `Strict` cookie would not survive.
const OIDC_COOKIE: &str = "lumen_oidc";
/// Marks a console session that came from the provider, for single logout.
const SSO_COOKIE: &str = "lumen_sso";
const MAX_SESSION_SECS: u64 = 12 * 3600;
const DEFAULT_IDLE_MINUTES: u64 = 30;
const SERIES_POINTS: usize = 60;
/// Console languages. The first is the default. The web console carries the translations.
pub(crate) const LANGUAGES: [&str; 5] = ["en", "de", "it", "es", "nl"];
/// How often lookups waiting in memory are written to the database.
const HISTORY_FLUSH_SECS: u64 = 2;
/// How often saved lookups past their retention are deleted (in flush ticks).
const HISTORY_PRUNE_TICKS: u64 = 300;
const BODY_LIMIT: usize = 256 * 1024;

/// One minute of traffic.
#[derive(Clone, Copy)]
struct Point {
    unix: u64,
    queries: u64,
    blocked: u64,
}

#[derive(Default)]
struct Throttle {
    entries: HashMap<String, (u32, u32, Instant)>,
}

impl Throttle {
    /// Seconds left on a lock for any of the keys.
    fn locked(&self, keys: &[String]) -> Option<u64> {
        let now = Instant::now();
        keys.iter()
            .filter_map(|key| self.entries.get(key))
            .filter(|(_, _, until)| *until > now)
            .map(|(_, _, until)| until.duration_since(now).as_secs() + 1)
            .max()
    }

    fn fail(&mut self, keys: &[String]) {
        if self.entries.len() > 4096 {
            let now = Instant::now();
            self.entries.retain(|_, (_, _, until)| *until > now);
            if self.entries.len() > 4096 {
                self.entries.clear();
            }
        }
        for key in keys {
            let entry = self
                .entries
                .entry(key.clone())
                .or_insert((0, 0, Instant::now()));
            entry.0 += 1;
            // Many people can share one address (proxy, NAT); a single name is held to 5.
            let limit = if key.starts_with("i:") { 25 } else { 5 };
            if entry.0 >= limit {
                entry.0 = 0;
                entry.1 = (entry.1 + 1).min(5);
                entry.2 = Instant::now() + Duration::from_secs(30 << (entry.1 - 1));
            }
        }
    }

    fn clear(&mut self, keys: &[String]) {
        for key in keys {
            self.entries.remove(key);
        }
    }
}

/// Console state shared by every web connection.
pub struct Console {
    state: PathBuf,
    host: Arc<dyn Host>,
    version: &'static str,
    throttle: Mutex<Throttle>,
    series: Mutex<VecDeque<Point>>,
    last: Mutex<Option<(Instant, Counters)>>,
    challenges: Mutex<HashMap<String, Challenge>>,
    oidc: crate::oidc::Flows,
}

/// A password was accepted; the second step is still owed.
struct Challenge {
    name: String,
    peer: IpAddr,
    at: Instant,
    tries: u32,
}

const CHALLENGE_SECS: u64 = 300;

/// One API request with owned data, so it can move to a blocking thread.
pub(crate) struct Request {
    pub method: Method,
    pub path: String,
    pub query: String,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub peer: SocketAddr,
    pub tls: bool,
}

/// Constant-time equality for secrets.
fn same(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn reply(status: StatusCode, body: &Value) -> Reply {
    let mut response = Response::new(Full::new(Bytes::from(body.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

/// Read external-login settings from JSON, as sent by the setup wizard and the settings page.
/// Empty text means "not set", so the defaults apply.
fn oidc_from_json(item: &Value, enabled: bool) -> lumen_config::Oidc {
    let get = |key: &str| {
        text(item, key)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let flag = |key: &str| item.get(key).and_then(Value::as_bool).unwrap_or(false);
    let defaults = lumen_config::Oidc::default();
    lumen_config::Oidc {
        enabled,
        label: get("label").unwrap_or(defaults.label),
        issuer: get("issuer").unwrap_or_default(),
        client_id: get("client_id").unwrap_or_default(),
        redirect_url: get("redirect_url").unwrap_or_default(),
        client_secret_file: get("client_secret_file").map(PathBuf::from),
        ca_file: get("ca_file").map(PathBuf::from),
        username_claim: get("username_claim").unwrap_or(defaults.username_claim),
        groups_claim: get("groups_claim").unwrap_or(defaults.groups_claim),
        admin_group: get("admin_group"),
        sync_role: flag("sync_role"),
        single_logout: flag("single_logout"),
    }
}

/// Check `oidc` against the stored configuration exactly as a configuration change would be.
fn check_oidc(store: &Store, oidc: &lumen_config::Oidc) -> Result<(), String> {
    let mut config = match store.config()? {
        Some(stored) => Config::parse(&stored.source, Path::new(&stored.base_dir))?,
        None => Config {
            schema_version: 1,
            ..Config::default()
        },
    };
    config.web.oidc = oidc.clone();
    config.validate()
}

/// The external-login choice of the setup wizard, checked against the stored configuration
/// exactly as a configuration change would be. `None` when the wizard did not ask for it.
fn setup_oidc(store: &Store, body: &Value) -> Result<Option<lumen_config::Oidc>, String> {
    let Some(item) = body.get("oidc").filter(|value| value.is_object()) else {
        return Ok(None);
    };
    let oidc = oidc_from_json(item, true);
    check_oidc(store, &oidc)?;
    Ok(Some(oidc))
}

/// `scheme://host[:port]` as the browser addressed this console, for building the callback
/// address. The host comes from the `Host` header, which must look like a name, an IPv4 address,
/// or a bracketed IPv6 address with an optional port. A proxy that ends TLS says so with
/// `X-Forwarded-Proto`. A wrong value cannot redirect anyone anywhere: the provider only
/// accepts callback addresses that were registered with it.
fn public_origin(request: &Request) -> Option<String> {
    let host = request.headers.get(HOST)?.to_str().ok()?;
    if host.is_empty()
        || host.len() > 255
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return None;
    }
    let https = request.tls
        || request
            .headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("https"));
    Some(format!("{}://{host}", if https { "https" } else { "http" }))
}

/// A 302 to a fixed or provider-supplied location. Never built from request input.
fn redirect(location: &str) -> Reply {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::FOUND;
    if let Ok(value) = HeaderValue::from_str(location) {
        response
            .headers_mut()
            .insert(hyper::header::LOCATION, value);
    }
    response
}

fn clear_oidc_cookie(tls: bool) -> HeaderValue {
    let secure = if tls { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "{OIDC_COOKIE}=; Path=/api/login/oidc; HttpOnly; SameSite=Lax; Max-Age=0{secure}"
    ))
    .expect("static cookie")
}

/// Decode `%XX` and `+` in a query value without the length cut of [`percent_decode`], so long
/// authorization codes survive. Invalid escapes are kept as they are.
fn decode_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 3 <= bytes.len() => {
                let hex = value.get(i + 1..i + 3);
                if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(byte);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn error(status: StatusCode, message: &str) -> Reply {
    reply(status, &json!({ "error": message }))
}

fn bad(message: &str) -> Reply {
    error(StatusCode::BAD_REQUEST, message)
}

fn unavailable() -> Reply {
    error(StatusCode::SERVICE_UNAVAILABLE, "state unavailable")
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn audit_safe(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(60)
        .collect();
    if cleaned.is_empty() {
        "unknown".into()
    } else {
        cleaned
    }
}

impl Console {
    /// Console bound to a managed state file.
    #[must_use]
    pub fn new(state: PathBuf, host: Arc<dyn Host>, version: &'static str) -> Self {
        Self {
            state,
            host,
            version,
            throttle: Mutex::default(),
            series: Mutex::default(),
            last: Mutex::default(),
            challenges: Mutex::default(),
            oidc: crate::oidc::Flows::default(),
        }
    }

    /// Restore saved settings into the daemon and, on first run, create the setup code.
    ///
    /// # Errors
    /// Returns an error when the state database cannot be used.
    pub fn prepare(&self) -> Result<Option<String>, String> {
        let store = Store::open(&self.state)?;
        self.host
            .set_history(runtime_settings(store.history_prefs()));
        if store.user_count()? == 0 {
            if let Some(code) = store.setting("setup_code")? {
                return Ok(Some(code));
            }
            let raw = password::random_hex(4)?.to_uppercase();
            let code = format!("{}-{}", &raw[..4], &raw[4..]);
            store.set_setting("setup_code", &code)?;
            return Ok(Some(code));
        }
        store.clear_setting("setup_code")?;
        Ok(None)
    }

    /// Sample counters once a minute for the traffic chart.
    ///
    /// # Errors
    /// Never returns an error today; the signature matches the other web tasks.
    ///
    /// # Panics
    /// Panics if a lock was poisoned by an earlier panic.
    pub async fn run_sampler(self: Arc<Self>) -> std::io::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut previous = self.host.counters();
        tick.tick().await;
        loop {
            tick.tick().await;
            let current = self.host.counters();
            let point = Point {
                unix: now(),
                queries: current.queries.saturating_sub(previous.queries),
                blocked: current.blocked.saturating_sub(previous.blocked),
            };
            {
                let mut series = self.series.lock().expect("series lock");
                if series.len() >= SERIES_POINTS {
                    series.pop_front();
                }
                series.push_back(point);
            }
            previous = current;
            if let Ok(store) = Store::open(&self.state) {
                let _ = store.purge_sessions(24 * 3600, MAX_SESSION_SECS);
            }
        }
    }

    /// Write saved-mode lookups to the database in small batches and delete expired ones.
    ///
    /// # Errors
    /// Never returns an error today; the signature matches the other web tasks.
    pub async fn run_history_writer(self: Arc<Self>) -> std::io::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(HISTORY_FLUSH_SECS));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut count = 0_u64;
        loop {
            tick.tick().await;
            let prune = count.is_multiple_of(HISTORY_PRUNE_TICKS);
            count = count.wrapping_add(1);
            let console = Arc::clone(&self);
            // Database work stays off the async executor threads.
            let _ = tokio::task::spawn_blocking(move || console.flush_history(prune)).await;
        }
    }

    /// One writer step: pick up setting changes made by `lumenctl`, save waiting lookups,
    /// and optionally delete lookups older than the retention period.
    pub(crate) fn flush_history(&self, prune: bool) -> Result<(), String> {
        let mut store = Store::open(&self.state)?;
        let prefs = store.history_prefs();
        let settings = runtime_settings(prefs);
        if settings != self.host.history_settings() {
            self.host.set_history(settings);
        }
        let records = self.host.take_unsaved_history();
        if !records.is_empty() {
            let rows: Vec<QueryRow> = records.into_iter().map(record_row).collect();
            store.insert_queries(&rows)?;
        }
        if prune {
            let cutoff = now()
                .saturating_mul(1000)
                .saturating_sub(u64::from(prefs.retention_days) * 86_400_000);
            store.prune_query_log(cutoff, QUERY_LOG_MAX_ROWS)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)] // One route table, public routes first.
    pub(crate) fn handle(&self, request: &Request) -> Reply {
        let Ok(mut store) = Store::open(&self.state) else {
            return unavailable();
        };
        let mutating = !matches!(request.method, Method::GET | Method::HEAD);
        if mutating && !origin_ok(&request.headers) {
            return error(StatusCode::FORBIDDEN, "cross-origin request refused");
        }
        let path = request.path.trim_end_matches('/').to_owned();
        let parts: Vec<&str> = path.trim_start_matches("/api/").split('/').collect();
        let method = request.method.clone();
        // Public routes.
        match (method.as_str(), parts.as_slice()) {
            ("GET", ["state"]) => return self.public_state(&store, request),
            ("POST", ["setup"]) => return self.setup(&mut store, request),
            ("POST", ["setup", "code"]) => return self.setup_code(&store, request),
            ("POST", ["login"]) => return self.login(&mut store, request),
            ("POST", ["login", "2fa"]) => return self.login_second_step(&mut store, request),
            ("GET", ["login", "oidc"]) => return self.oidc_begin(request),
            ("GET", ["login", "oidc", "callback"]) => {
                return self.oidc_callback(&mut store, request);
            }
            _ => {}
        }
        let Some((token_hash, session)) = self.session(&store, request) else {
            return error(StatusCode::UNAUTHORIZED, "sign in required");
        };
        if mutating {
            let sent = request
                .headers
                .get("x-lumen-csrf")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !same(sent, &session.csrf) {
                return error(StatusCode::FORBIDDEN, "missing or wrong CSRF token");
            }
        }
        let admin = session.user.role == Role::Admin;
        let ctx = Ctx {
            request,
            session: &session,
            token_hash: &token_hash,
        };
        // Routes for every signed-in account.
        match (method.as_str(), parts.as_slice()) {
            ("GET", ["me"]) => return reply(StatusCode::OK, &me_json(&session)),
            ("POST", ["logout"]) => return self.logout(&mut store, &ctx),
            ("POST", ["me", "password"]) => return self.change_own_password(&mut store, &ctx),
            ("GET", ["me", "oidc"]) => return self.oidc_state(&store, &ctx),
            ("POST", ["me", "oidc", "link"]) => return self.oidc_link_start(&store, &ctx),
            ("DELETE", ["me", "oidc"]) => return self.oidc_unlink(&mut store, &ctx),
            ("POST", ["me", "2fa", "setup"]) => return self.totp_setup(&mut store, &ctx),
            ("POST", ["me", "2fa", "enable"]) => return self.totp_enable(&mut store, &ctx),
            ("POST", ["me", "2fa", "disable"]) => return self.totp_disable(&mut store, &ctx),
            ("GET", ["status"]) => return self.status(&store),
            ("GET", ["series"]) => return self.series_json(),
            ("GET", ["devices"]) => return devices_json(&store),
            ("GET", ["history"]) => return self.history(&store, request),
            ("GET", ["settings"]) => return settings_json(&store),
            ("GET", ["modules"]) => return modules_json(&store),
            _ => {}
        }
        if !admin {
            return error(StatusCode::FORBIDDEN, "administrators only");
        }
        match (method.as_str(), parts.as_slice()) {
            ("GET", ["users"]) => users_json(&store),
            ("POST", ["users"]) => self.add_user(&mut store, &ctx),
            ("PATCH", ["users", name]) => self.set_role(&mut store, &ctx, name),
            ("POST", ["users", name, "password"]) => self.reset_password(&mut store, &ctx, name),
            ("POST", ["users", name, "2fa", "reset"]) => self.totp_reset(&mut store, &ctx, name),
            ("DELETE", ["users", name]) => self.remove_user(&mut store, &ctx, name),
            ("PUT", ["devices"]) => self.put_device(&mut store, &ctx),
            ("DELETE", ["devices", id]) => self.delete_device(&mut store, &ctx, id),
            ("GET", ["config"]) => config_json(&store),
            ("POST", ["config", "preview"]) => preview_config(&store, request),
            ("PUT", ["config"]) => self.put_config(&mut store, &ctx),
            ("GET", ["config", "history"]) => config_history(&store),
            ("POST", ["config", "restore"]) => self.restore_config(&mut store, &ctx),
            ("GET", ["providers"]) => providers_json(),
            ("POST", ["explain"]) => self.explain(request),
            ("POST", ["filter", "refresh"]) => self.control(
                &mut store,
                &ctx,
                Command::FilterRefresh,
                "filter.refresh",
                "all lists",
            ),
            ("POST", ["filter", "rollback"]) => self.control(
                &mut store,
                &ctx,
                Command::FilterRollback,
                "filter.rollback",
                "previous generation",
            ),
            ("POST", ["reload"]) => {
                self.control(&mut store, &ctx, Command::Reload, "reload", "daemon")
            }
            ("POST", ["shutdown"]) => {
                self.control(&mut store, &ctx, Command::Shutdown, "shutdown", "daemon")
            }
            ("POST", ["activity", "cancel"]) => self.cancel_activity(&mut store, &ctx),
            ("GET", ["audit"]) => audit_json(&store, &request.query),
            ("PUT", ["oidc"]) => self.put_oidc(&mut store, &ctx),
            ("POST", ["oidc", "test"]) => self.test_oidc(&store, &ctx),
            ("PUT", ["settings"]) => self.put_settings(&mut store, &ctx),
            ("PUT", ["modules"]) => self.put_module(&mut store, &ctx),
            ("PUT", ["history"]) => self.put_history(&mut store, &ctx),
            ("DELETE", ["history"]) => self.clear_history(&mut store, &ctx),
            _ => error(StatusCode::NOT_FOUND, "route not found"),
        }
    }

    // ----- sessions -----

    fn idle_secs(store: &Store) -> u64 {
        store
            .setting("session_idle_minutes")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|m| (5..=1440).contains(m))
            .unwrap_or(DEFAULT_IDLE_MINUTES)
            * 60
    }

    fn session(&self, store: &Store, request: &Request) -> Option<(String, Session)> {
        let token = cookie(&request.headers, COOKIE_NAME)?;
        if token.len() != 64 {
            return None;
        }
        let hash = password::sha256_hex(token);
        let session = store
            .session(&hash, Self::idle_secs(store), MAX_SESSION_SECS)
            .ok()??;
        Some((hash, session))
    }

    fn start_session(
        &self,
        store: &Store,
        user: &lumen_store::User,
        peer: &SocketAddr,
        tls: bool,
    ) -> Result<(String, String), String> {
        let token = password::random_hex(32)?;
        let csrf = password::random_hex(16)?;
        store.create_session(
            user.id,
            &password::sha256_hex(&token),
            &csrf,
            &peer.ip().to_string(),
        )?;
        let secure = if tls { "; Secure" } else { "" };
        Ok((
            format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict{secure}"),
            csrf,
        ))
    }

    fn audit(
        store: &mut Store,
        actor: &str,
        role: &str,
        action: &str,
        target: &str,
        ok: bool,
        peer: &SocketAddr,
    ) {
        let _ = store.append_audit(
            &audit_safe(actor),
            role,
            action,
            &audit_safe(target),
            if ok { "accepted" } else { "rejected" },
            &peer.ip().to_string(),
        );
    }

    fn actor(store: &mut Store, ctx: &Ctx<'_>, action: &str, target: &str) {
        Self::audit(
            store,
            &ctx.session.user.name,
            ctx.session.user.role.as_str(),
            action,
            target,
            true,
            &ctx.request.peer,
        );
    }

    // ----- public -----

    fn public_state(&self, store: &Store, request: &Request) -> Reply {
        let setup = store.user_count().is_ok_and(|n| n == 0);
        let signed_in = self.session(store, request).map(|(_, s)| me_json(&s));
        reply(
            StatusCode::OK,
            &json!({
                "version": self.version,
                "setup_needed": setup,
                "setup_code_required": setup && !request.peer.ip().to_canonical().is_loopback(),
                "language": language(store),
                "languages": LANGUAGES,
                "oidc": self.host.oidc().map(|oidc| json!({ "label": oidc.label })),
                "user": signed_in,
            }),
        )
    }

    /// Shared by the code page and the final setup call: throttle, first-run check, code check.
    #[allow(clippy::result_large_err)] // The error is the ready-made HTTP reply.
    fn check_setup_code(
        &self,
        store: &Store,
        request: &Request,
        body: &Value,
    ) -> Result<(), Reply> {
        let key = vec![format!("setup:{}", request.peer.ip())];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&key) {
            return Err(error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("too many attempts, wait {wait} s"),
            ));
        }
        if store.user_count().unwrap_or(1) != 0 {
            return Err(error(StatusCode::CONFLICT, "setup is already complete"));
        }
        if !request.peer.ip().to_canonical().is_loopback() {
            let expected = store
                .setting("setup_code")
                .ok()
                .flatten()
                .unwrap_or_default();
            let given = text(body, "code").unwrap_or("").trim().to_uppercase();
            if expected.is_empty() || !same(&given, &expected) {
                self.throttle.lock().expect("throttle").fail(&key);
                return Err(error(
                    StatusCode::FORBIDDEN,
                    "wrong setup code. It is printed in the daemon log when Lumen starts",
                ));
            }
        }
        Ok(())
    }

    /// Lets the console check the setup code on its own page before asking for an account.
    fn setup_code(&self, store: &Store, request: &Request) -> Reply {
        if !json_content(&request.headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "use application/json");
        }
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return bad("invalid JSON");
        };
        match self.check_setup_code(store, request, &body) {
            Ok(()) => reply(StatusCode::OK, &json!({ "ok": true })),
            Err(reply) => reply,
        }
    }

    fn setup(&self, store: &mut Store, request: &Request) -> Reply {
        if !json_content(&request.headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "use application/json");
        }
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return bad("invalid JSON");
        };
        if let Err(reply) = self.check_setup_code(store, request, &body) {
            return reply;
        }
        let name = text(&body, "username").unwrap_or("").trim().to_lowercase();
        let pw = text(&body, "password").unwrap_or("");
        if let Err(message) = password::check_policy(pw, &name) {
            return bad(&message);
        }
        // Checked before the account exists, so a typo in the provider settings can be fixed.
        let sso = match setup_oidc(store, &body) {
            Ok(sso) => sso,
            Err(message) => return bad(&message),
        };
        let Ok(record) = password::hash(pw) else {
            return unavailable();
        };
        let user = match store.create_first_admin(&name, &record) {
            Ok(user) => user,
            Err(message) => return bad(&message),
        };
        // Optional first-run choices. Failures here never undo the account.
        if let Err(message) = self.apply_setup_choices(store, &body, sso.as_ref(), &name) {
            let _ = message;
        }
        if let Some(code) = text(&body, "language").filter(|c| LANGUAGES.contains(c)) {
            let _ = store.set_setting("language", code);
        }
        let _ = store.clear_setting("setup_code");
        Self::audit(
            store,
            &name,
            "admin",
            "setup.complete",
            &name,
            true,
            &request.peer,
        );
        self.signed_in_reply(store, &user, request)
    }

    /// Apply resolution mode and allowed networks chosen during setup.
    fn apply_setup_choices(
        &self,
        store: &mut Store,
        body: &Value,
        sso: Option<&lumen_config::Oidc>,
        actor: &str,
    ) -> Result<(), String> {
        let mode = text(body, "mode");
        let networks = body.get("allow_clients").and_then(Value::as_array);
        if mode.is_none() && networks.is_none() && sso.is_none() {
            return Ok(());
        }
        let stored = store.config()?.ok_or("no active config")?;
        let mut table: toml::Table =
            toml::from_str(&stored.source).map_err(|_| "unreadable config")?;
        if let Some(mode @ ("recursive" | "forward")) = mode {
            let resolver = table
                .entry("resolver")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .ok_or("bad resolver table")?;
            resolver.insert("mode".into(), toml::Value::String(mode.into()));
            if mode == "forward" {
                // Warm-up, prefetch, fallback and hedging are recursive-only. The stock config
                // enables warm-up, so leaving it on would make the forward config invalid.
                resolver.remove("hedge_ms");
                for key in ["warm", "prefetch", "fallback"] {
                    if let Some(toml::Value::Table(section)) = resolver.get_mut(key) {
                        section.insert("enabled".into(), toml::Value::Boolean(false));
                    }
                }
            }
            if mode == "forward"
                && !resolver.contains_key("providers")
                && !resolver.contains_key("upstreams")
            {
                let mut provider = toml::Table::new();
                provider.insert("id".into(), toml::Value::String("quad9-unfiltered".into()));
                provider.insert("protocol".into(), toml::Value::String("auto".into()));
                resolver.insert(
                    "providers".into(),
                    toml::Value::Array(vec![toml::Value::Table(provider)]),
                );
            }
        }
        if let Some(networks) = networks {
            let list: Vec<toml::Value> = networks
                .iter()
                .filter_map(Value::as_str)
                .map(|n| toml::Value::String(n.to_owned()))
                .collect();
            if !list.is_empty() {
                let mut all = vec![
                    toml::Value::String("127.0.0.0/8".into()),
                    toml::Value::String("::1/128".into()),
                ];
                all.extend(list);
                let listen = table
                    .entry("listen")
                    .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                    .as_table_mut()
                    .ok_or("bad listen table")?;
                listen.insert("allow_clients".into(), toml::Value::Array(all));
            }
        }
        if let Some(sso) = sso {
            let web = table
                .entry("web")
                .or_insert_with(|| toml::Value::Table(toml::Table::new()))
                .as_table_mut()
                .ok_or("bad web table")?;
            web.insert(
                "oidc".into(),
                toml::Value::try_from(sso).map_err(|_| "cannot write external login")?,
            );
        }
        let source = toml::to_string(&table).map_err(|_| "cannot write config")?;
        Config::parse(&source, Path::new(&stored.base_dir))?;
        let revision = store.stage_config_by(&source, Path::new(&stored.base_dir), actor)?;
        store.enqueue(Command::ConfigReload(revision))?;
        Ok(())
    }

    fn login(&self, store: &mut Store, request: &Request) -> Reply {
        if !json_content(&request.headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "use application/json");
        }
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return bad("invalid JSON");
        };
        let name = text(&body, "username").unwrap_or("").trim().to_lowercase();
        let pw = text(&body, "password").unwrap_or("");
        let keys = vec![format!("u:{name}"), format!("i:{}", request.peer.ip())];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&keys) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many attempts. Try again in {wait} s."),
            );
        }
        let found = store.user_with_record(&name).ok().flatten();
        let verified = match &found {
            Some((_, record)) if password::verify(pw, record) => true,
            Some(_) => false,
            None => {
                password::verify_dummy(pw);
                false
            }
        };
        let Some((user, _)) = found.filter(|_| verified) else {
            self.throttle.lock().expect("throttle").fail(&keys);
            Self::audit(
                store,
                &name,
                "-",
                "session.start",
                &name,
                false,
                &request.peer,
            );
            return error(StatusCode::UNAUTHORIZED, "Incorrect username or password.");
        };
        if user.totp_enabled {
            // Password accepted; the code is still owed. The lock keys stay armed.
            let Ok(token) = password::random_hex(16) else {
                return unavailable();
            };
            let mut challenges = self.challenges.lock().expect("challenges");
            challenges.retain(|_, c| c.at.elapsed().as_secs() < CHALLENGE_SECS);
            if challenges.len() >= 256 {
                challenges.clear();
            }
            challenges.insert(
                token.clone(),
                Challenge {
                    name: user.name.clone(),
                    peer: request.peer.ip(),
                    at: Instant::now(),
                    tries: 0,
                },
            );
            return reply(
                StatusCode::OK,
                &json!({ "needs_2fa": true, "challenge": token }),
            );
        }
        self.throttle.lock().expect("throttle").clear(&keys);
        let _ = store.record_login(user.id);
        Self::audit(
            store,
            &user.name,
            user.role.as_str(),
            "session.start",
            "console",
            true,
            &request.peer,
        );
        self.signed_in_reply(store, &user, request)
    }

    /// Check a 6-digit code (once per time step) or a single-use recovery code.
    fn code_ok(store: &mut Store, name: &str, code: &str) -> Result<Option<&'static str>, ()> {
        let code = code.trim();
        if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) {
            let Ok(Some((secret, _))) = store.totp_secret(name) else {
                return Ok(None);
            };
            return match totp::verify(&secret, code, now()) {
                Some(step) if store.claim_totp_step(name, step).map_err(|_| ())? => {
                    Ok(Some("authenticator code"))
                }
                _ => Ok(None),
            };
        }
        let hash = password::sha256_hex(&totp::clean_recovery(code));
        Ok(store
            .use_recovery_code(name, &hash)
            .map_err(|_| ())?
            .then_some("recovery code"))
    }

    fn login_second_step(&self, store: &mut Store, request: &Request) -> Reply {
        if !json_content(&request.headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "use application/json");
        }
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return bad("invalid JSON");
        };
        let token = text(&body, "challenge").unwrap_or("").to_owned();
        let code = text(&body, "code").unwrap_or("").to_owned();
        let name = {
            let mut challenges = self.challenges.lock().expect("challenges");
            match challenges.get_mut(&token) {
                Some(c)
                    if c.at.elapsed().as_secs() < CHALLENGE_SECS && c.peer == request.peer.ip() =>
                {
                    c.tries += 1;
                    if c.tries > 5 {
                        challenges.remove(&token);
                        return error(
                            StatusCode::UNAUTHORIZED,
                            "Too many wrong codes. Sign in again.",
                        );
                    }
                    c.name.clone()
                }
                _ => {
                    challenges.remove(&token);
                    return error(
                        StatusCode::UNAUTHORIZED,
                        "That sign-in expired. Enter your password again.",
                    );
                }
            }
        };
        let keys = vec![format!("u:{name}"), format!("i:{}", request.peer.ip())];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&keys) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many attempts. Try again in {wait} s."),
            );
        }
        let Ok(method) = Self::code_ok(store, &name, &code) else {
            return unavailable();
        };
        let Some(method) = method else {
            self.throttle.lock().expect("throttle").fail(&keys);
            Self::audit(
                store,
                &name,
                "-",
                "session.start",
                "wrong 2fa code",
                false,
                &request.peer,
            );
            return error(StatusCode::UNAUTHORIZED, "That code is not correct.");
        };
        self.challenges.lock().expect("challenges").remove(&token);
        self.throttle.lock().expect("throttle").clear(&keys);
        let Some((user, _)) = store.user_with_record(&name).ok().flatten() else {
            return error(StatusCode::UNAUTHORIZED, "Sign in again.");
        };
        let _ = store.record_login(user.id);
        Self::audit(
            store,
            &user.name,
            user.role.as_str(),
            "session.start",
            method,
            true,
            &request.peer,
        );
        self.signed_in_reply(store, &user, request)
    }

    fn totp_setup(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let name = &ctx.session.user.name;
        if ctx.session.user.totp_enabled {
            return error(StatusCode::CONFLICT, "Two-step verification is already on.");
        }
        let key = vec![format!("p:{name}")];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&key) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many attempts. Try again in {wait} s."),
            );
        }
        let record = store.user_with_record(name).ok().flatten().map(|(_, r)| r);
        if !record
            .as_deref()
            .is_some_and(|r| password::verify(text(&body, "password").unwrap_or(""), r))
        {
            self.throttle.lock().expect("throttle").fail(&key);
            return error(StatusCode::FORBIDDEN, "Your password is not correct.");
        }
        let Ok(secret) = totp::generate_secret() else {
            return unavailable();
        };
        if store.set_totp_pending(name, &secret).is_err() {
            return unavailable();
        }
        reply(
            StatusCode::OK,
            &json!({ "secret": secret, "uri": totp::uri(&secret, name, "Lumen") }),
        )
    }

    fn totp_enable(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let name = &ctx.session.user.name;
        let Ok(Some(secret)) = store.totp_pending(name) else {
            return bad("Start setup first.");
        };
        let Some(step) = totp::verify(&secret, text(&body, "code").unwrap_or(""), now()) else {
            return bad(
                "That code is not correct. Check that your phone's clock is right, then try the next code.",
            );
        };
        let Ok(codes) = totp::recovery_codes() else {
            return unavailable();
        };
        let hashes: Vec<String> = codes.iter().map(|c| password::sha256_hex(c)).collect();
        if store.enable_totp(name, step, &hashes).is_err() {
            return unavailable();
        }
        Self::actor(store, ctx, "user.2fa-enable", name);
        reply(StatusCode::OK, &json!({ "recovery_codes": codes }))
    }

    fn totp_disable(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let name = &ctx.session.user.name;
        let key = vec![format!("p:{name}")];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&key) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many attempts. Try again in {wait} s."),
            );
        }
        let record = store.user_with_record(name).ok().flatten().map(|(_, r)| r);
        let password_ok = record
            .as_deref()
            .is_some_and(|r| password::verify(text(&body, "password").unwrap_or(""), r));
        let code_ok = password_ok
            && matches!(
                Self::code_ok(store, name, text(&body, "code").unwrap_or("")),
                Ok(Some(_))
            );
        if !code_ok {
            self.throttle.lock().expect("throttle").fail(&key);
            return error(
                StatusCode::FORBIDDEN,
                "Your password or code is not correct.",
            );
        }
        if store.disable_totp(name).is_err() {
            return unavailable();
        }
        Self::actor(store, ctx, "user.2fa-disable", name);
        reply(StatusCode::OK, &json!({ "ok": true }))
    }

    fn totp_reset(&self, store: &mut Store, ctx: &Ctx<'_>, name: &str) -> Reply {
        let Some((user, _)) = store.user_with_record(name).ok().flatten() else {
            return error(StatusCode::NOT_FOUND, "unknown user");
        };
        if store.disable_totp(name).is_err() || store.delete_user_sessions(user.id, None).is_err() {
            return unavailable();
        }
        Self::actor(store, ctx, "user.2fa-reset", name);
        reply(StatusCode::OK, &json!({ "ok": true }))
    }

    fn signed_in_reply(&self, store: &Store, user: &lumen_store::User, request: &Request) -> Reply {
        let Ok((cookie, csrf)) = self.start_session(store, user, &request.peer, request.tls) else {
            return unavailable();
        };
        let mut response = reply(
            StatusCode::OK,
            &json!({ "user": user_json(user), "csrf": csrf }),
        );
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(SET_COOKIE, value);
        }
        response
    }

    // ----- external sign-in (OpenID Connect) -----

    /// Where a failed external sign-in lands: the login page with a short, generic notice.
    fn oidc_failed(&self, tls: bool) -> Reply {
        let mut response = redirect("/?sso=failed#/login");
        response
            .headers_mut()
            .append(SET_COOKIE, clear_oidc_cookie(tls));
        response
    }

    #[allow(clippy::result_large_err)] // The error is the ready-made HTTP reply.
    /// Shared start of a sign-in or a linking flow. `Err(Some(reply))` is a ready answer for a
    /// throttled address; `Err(None)` means the provider could not be reached.
    fn oidc_start(
        &self,
        request: &Request,
        config: &lumen_config::Oidc,
        link: Option<i64>,
    ) -> Result<(String, HeaderValue), Option<Reply>> {
        let keys = vec![format!("i:{}", request.peer.ip())];
        if self
            .throttle
            .lock()
            .expect("throttle")
            .locked(&keys)
            .is_some()
        {
            return Err(Some(error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Try again soon.",
            )));
        }
        // Every start counts toward the address limit; a successful sign-in clears it.
        self.throttle.lock().expect("throttle").fail(&keys);
        let origin = public_origin(request).ok_or(None)?;
        let redirect = crate::oidc::callback_for(config, &origin);
        let (url, state) = self.oidc.begin(config, link, &redirect).map_err(|_| None)?;
        let secure = if request.tls { "; Secure" } else { "" };
        let cookie = HeaderValue::from_str(&format!(
            "{OIDC_COOKIE}={state}; Path=/api/login/oidc; HttpOnly; SameSite=Lax; Max-Age={}{secure}",
            crate::oidc::FLOW_SECS
        ))
        .map_err(|_| None)?;
        Ok((url, cookie))
    }

    fn oidc_begin(&self, request: &Request) -> Reply {
        let Some(config) = self.host.oidc() else {
            return error(StatusCode::NOT_FOUND, "external sign-in is off");
        };
        match self.oidc_start(request, &config, None) {
            Ok((url, cookie)) => {
                let mut response = redirect(&url);
                response.headers_mut().insert(SET_COOKIE, cookie);
                response
            }
            Err(Some(reply)) => reply,
            Err(None) => self.oidc_failed(request.tls),
        }
    }

    /// What the account page shows about external sign-in for the signed-in person.
    fn oidc_state(&self, store: &Store, ctx: &Ctx<'_>) -> Reply {
        let config = self.host.oidc();
        reply(
            StatusCode::OK,
            &json!({
                "available": config.is_some(),
                "label": config.as_ref().map(|c| c.label.clone()),
                "linked": store.oidc_linked(ctx.session.user.id).unwrap_or(false),
            }),
        )
    }

    /// A signed-in person starts linking their own account to a provider identity.
    fn oidc_link_start(&self, store: &Store, ctx: &Ctx<'_>) -> Reply {
        let Some(config) = self.host.oidc() else {
            return error(StatusCode::NOT_FOUND, "external sign-in is off");
        };
        if store.oidc_linked(ctx.session.user.id).unwrap_or(true) {
            return error(StatusCode::CONFLICT, "This account is already linked.");
        }
        match self.oidc_start(ctx.request, &config, Some(ctx.session.user.id)) {
            Ok((url, cookie)) => {
                let mut response = reply(StatusCode::OK, &json!({ "url": url }));
                response.headers_mut().insert(SET_COOKIE, cookie);
                response
            }
            Err(Some(reply)) => reply,
            Err(None) => error(
                StatusCode::BAD_GATEWAY,
                "The sign-in provider did not answer.",
            ),
        }
    }

    /// Remove the link again. It needs the account's own password, so an account that was
    /// created by the provider (and has no known password) cannot cut itself off.
    fn oidc_unlink(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let name = &ctx.session.user.name;
        let key = vec![format!("p:{name}")];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&key) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many attempts. Try again in {wait} s."),
            );
        }
        let verified = store
            .user_with_record(name)
            .ok()
            .flatten()
            .is_some_and(|(_, record)| {
                password::verify(text(&body, "password").unwrap_or(""), &record)
            });
        if !verified {
            self.throttle.lock().expect("throttle").fail(&key);
            return error(StatusCode::FORBIDDEN, "Your password is not correct.");
        }
        self.throttle.lock().expect("throttle").clear(&key);
        match store.oidc_unlink(ctx.session.user.id) {
            Ok(removed) => {
                if removed {
                    Self::actor(store, ctx, "user.oidc-unlink", name);
                }
                reply(StatusCode::OK, &json!({ "ok": true }))
            }
            Err(_) => unavailable(),
        }
    }

    /// Where a finished linking flow lands: the account page with a short notice.
    fn oidc_link_done(&self, ok: bool, tls: bool) -> Reply {
        let mut response = redirect(if ok {
            "/?sso=linked#/account"
        } else {
            "/?sso=link-failed#/account"
        });
        response
            .headers_mut()
            .append(SET_COOKIE, clear_oidc_cookie(tls));
        response
    }

    #[allow(clippy::too_many_lines)] // One linear sign-in: check, map, sync role, start session.
    fn oidc_callback(&self, store: &mut Store, request: &Request) -> Reply {
        let Some(config) = self.host.oidc() else {
            return error(StatusCode::NOT_FOUND, "external sign-in is off");
        };
        let keys = vec![format!("i:{}", request.peer.ip())];
        if self
            .throttle
            .lock()
            .expect("throttle")
            .locked(&keys)
            .is_some()
        {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Try again soon.",
            );
        }
        let param = |name: &str| {
            request.query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == name).then(|| decode_component(value))
            })
        };
        // The browser must be the one that started the sign-in.
        let state = param("state").unwrap_or_default();
        let bound = cookie(&request.headers, OIDC_COOKIE).is_some_and(|c| same(c, &state));
        let outcome = if !bound {
            Err("sign-in was not started in this browser".to_owned())
        } else if let Some(code) = param("code").filter(|_| param("error").is_none()) {
            self.oidc.finish(&config, &state, &code)
        } else {
            Err("provider returned an error".to_owned())
        };
        let (identity, link) = match outcome {
            Ok(done) => done,
            Err(reason) => {
                Self::audit(
                    store,
                    "-",
                    "-",
                    "session.start",
                    &format!("sso: {reason}"),
                    false,
                    &request.peer,
                );
                return self.oidc_failed(request.tls);
            }
        };
        if let Some(user_id) = link {
            // Linking: the person was signed in when they started, and this browser is the one
            // that started it. The identity and the account must both be free.
            let account = store
                .users()
                .ok()
                .and_then(|users| users.into_iter().find(|user| user.id == user_id));
            let linked = match &account {
                Some(_) => store.oidc_link(user_id, &identity.issuer, &identity.subject),
                None => Err("account no longer exists".into()),
            };
            let (name, role) = account
                .as_ref()
                .map_or(("-", "-"), |user| (user.name.as_str(), user.role.as_str()));
            Self::audit(
                store,
                name,
                role,
                "user.oidc-link",
                &config.label,
                linked.is_ok(),
                &request.peer,
            );
            return self.oidc_link_done(linked.is_ok(), request.tls);
        }
        let role = if config
            .admin_group
            .as_ref()
            .is_some_and(|group| identity.groups.contains(group))
        {
            Role::Admin
        } else {
            Role::User
        };
        let Ok((mut user, _created)) = store.oidc_user(
            &identity.issuer,
            &identity.subject,
            identity.username.as_deref(),
            role,
        ) else {
            return self.oidc_failed(request.tls);
        };
        // With role sync the group decides on every sign-in. The last administrator stays one.
        if config.sync_role && user.role != role {
            let changed = store.set_role(&user.name, role).is_ok();
            Self::audit(
                store,
                &user.name,
                role.as_str(),
                "user.role",
                "sso group",
                changed,
                &request.peer,
            );
            if changed {
                user.role = role;
            }
        }
        self.throttle.lock().expect("throttle").clear(&keys);
        let _ = store.record_login(user.id);
        Self::audit(
            store,
            &user.name,
            user.role.as_str(),
            "session.start",
            "sso",
            true,
            &request.peer,
        );
        let Ok((session_cookie, _csrf)) =
            self.start_session(store, &user, &request.peer, request.tls)
        else {
            return unavailable();
        };
        let mut response = redirect("/");
        if let Ok(value) = HeaderValue::from_str(&session_cookie) {
            response.headers_mut().append(SET_COOKIE, value);
        }
        if config.single_logout {
            // Remembers that this session came from the provider, so sign-out can end it there.
            let secure = if request.tls { "; Secure" } else { "" };
            if let Ok(value) = HeaderValue::from_str(&format!(
                "{SSO_COOKIE}=1; Path=/; HttpOnly; SameSite=Strict{secure}"
            )) {
                response.headers_mut().append(SET_COOKIE, value);
            }
        }
        response
            .headers_mut()
            .append(SET_COOKIE, clear_oidc_cookie(request.tls));
        response
    }

    fn logout(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let _ = store.delete_session(ctx.token_hash);
        Self::actor(store, ctx, "session.end", "console");
        let secure = if ctx.request.tls { "; Secure" } else { "" };
        let mut body = json!({ "ok": true });
        let mut clear = vec![format!(
            "{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
        )];
        if cookie(&ctx.request.headers, SSO_COOKIE).is_some() {
            clear.push(format!(
                "{SSO_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
            ));
            // Signed in through the provider: also end the session there, when it can.
            if let Some(url) = self
                .host
                .oidc()
                .filter(|config| config.single_logout)
                .and_then(|config| {
                    let origin = public_origin(ctx.request)?;
                    self.oidc.logout_url(&config, &origin)
                })
            {
                body["redirect"] = Value::String(url);
            }
        }
        let mut response = reply(StatusCode::OK, &body);
        for value in clear {
            if let Ok(value) = HeaderValue::from_str(&value) {
                response.headers_mut().append(SET_COOKIE, value);
            }
        }
        response
    }

    fn change_own_password(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let name = &ctx.session.user.name;
        let key = vec![format!("p:{name}")];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&key) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Too many attempts. Try again in {wait} s."),
            );
        }
        let current = text(&body, "current").unwrap_or("");
        let next = text(&body, "password").unwrap_or("");
        let record = store.user_with_record(name).ok().flatten().map(|(_, r)| r);
        if !record
            .as_deref()
            .is_some_and(|r| password::verify(current, r))
        {
            self.throttle.lock().expect("throttle").fail(&key);
            return error(
                StatusCode::FORBIDDEN,
                "Your current password is not correct.",
            );
        }
        if current == next {
            return bad("Choose a password you are not using now.");
        }
        if let Err(message) = password::check_policy(next, name) {
            return bad(&message);
        }
        let Ok(new_record) = password::hash(next) else {
            return unavailable();
        };
        if store.set_password(name, &new_record, false).is_err() {
            return unavailable();
        }
        Self::actor(store, ctx, "user.password", name);
        let mut user = ctx.session.user.clone();
        user.must_change = false;
        self.signed_in_reply(store, &user, ctx.request)
    }

    // ----- users -----

    fn add_user(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let name = text(&body, "name").unwrap_or("").trim().to_lowercase();
        let Ok(role) = Role::parse(text(&body, "role").unwrap_or("user")) else {
            return bad("role must be admin or user");
        };
        let pw = text(&body, "password").unwrap_or("");
        if let Err(message) = password::check_policy(pw, &name) {
            return bad(&message);
        }
        let Ok(record) = password::hash(pw) else {
            return unavailable();
        };
        match store.create_user(&name, role, &record, true) {
            Ok(user) => {
                Self::actor(store, ctx, "user.add", &name);
                reply(StatusCode::CREATED, &user_json(&user))
            }
            Err(message) => bad(&message),
        }
    }

    fn set_role(&self, store: &mut Store, ctx: &Ctx<'_>, name: &str) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let Ok(role) = Role::parse(text(&body, "role").unwrap_or("")) else {
            return bad("role must be admin or user");
        };
        match store.set_role(name, role) {
            Ok(()) => {
                Self::actor(
                    store,
                    ctx,
                    "user.role",
                    &format!("{name} -> {}", role.as_str()),
                );
                reply(StatusCode::OK, &json!({ "ok": true }))
            }
            Err(message) => bad(&message),
        }
    }

    fn reset_password(&self, store: &mut Store, ctx: &Ctx<'_>, name: &str) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let pw = text(&body, "password").unwrap_or("");
        if let Err(message) = password::check_policy(pw, name) {
            return bad(&message);
        }
        let Ok(record) = password::hash(pw) else {
            return unavailable();
        };
        match store.set_password(name, &record, true) {
            Ok(true) => {
                Self::actor(store, ctx, "user.reset-password", name);
                reply(StatusCode::OK, &json!({ "ok": true }))
            }
            Ok(false) => error(StatusCode::NOT_FOUND, "unknown user"),
            Err(_) => unavailable(),
        }
    }

    fn remove_user(&self, store: &mut Store, ctx: &Ctx<'_>, name: &str) -> Reply {
        if name == ctx.session.user.name {
            return bad("You cannot delete your own account.");
        }
        match store.delete_user(name) {
            Ok(true) => {
                Self::actor(store, ctx, "user.remove", name);
                reply(StatusCode::OK, &json!({ "ok": true }))
            }
            Ok(false) => error(StatusCode::NOT_FOUND, "unknown user"),
            Err(message) => bad(&message),
        }
    }

    // ----- status -----

    fn status(&self, store: &Store) -> Reply {
        let c = self.host.counters();
        let (state, last_error) = store.status().unwrap_or((None, None));
        let lists: Vec<Value> = self
            .host
            .lists()
            .into_iter()
            .map(|l| json!({ "id": l.id, "rules": l.rules, "unsupported": l.unsupported, "duplicates": l.duplicates }))
            .collect();
        *self.last.lock().expect("last lock") = Some((Instant::now(), c.clone()));
        reply(
            StatusCode::OK,
            &json!({
                "version": self.version,
                "uptime_secs": self.host.uptime_secs(),
                "daemon": state.unwrap_or_else(|| "unknown".into()),
                "last_error": last_error,
                "revision": store.config().ok().flatten().map(|c| c.revision),
                "pending_revision": store.staged_config().ok().flatten().map(|c| c.revision),
                "history_enabled": self.host.history_settings().mode != HistoryMode::Off,
                "history_mode": self.host.history_settings().mode.as_str(),
                "rss_bytes": rss_bytes(),
                "activity": activity_json(),
                "counters": {
                    "queries": c.queries, "responses": c.responses, "malformed": c.malformed,
                    "refused": c.refused, "timeouts": c.timeouts, "failures": c.failures,
                    "active": c.active,
                    "transports": { "udp": c.transports[0], "tcp": c.transports[1], "tls": c.transports[2], "https": c.transports[3], "quic": c.transports[4], "other": c.transports[5] },
                    "latency": c.latency,
                    "rcodes": { "noerror": c.rcodes[0], "nxdomain": c.rcodes[1], "servfail": c.rcodes[2], "refused": c.rcodes[3], "other": c.rcodes[4] },
                },
                "filter": {
                    "generation": c.filter_generation, "blocked": c.blocked, "allowed": c.allowed,
                    "refresh_successes": c.refresh_successes, "refresh_failures": c.refresh_failures,
                    "rollbacks": c.rollbacks, "lists": lists,
                },
            }),
        )
    }

    fn series_json(&self) -> Reply {
        let points: Vec<Value> = self
            .series
            .lock()
            .expect("series lock")
            .iter()
            .map(|p| json!({ "t": p.unix, "queries": p.queries, "blocked": p.blocked }))
            .collect();
        reply(
            StatusCode::OK,
            &json!({ "interval_secs": 60, "points": points }),
        )
    }

    #[allow(clippy::cast_precision_loss)] // Microseconds to milliseconds for display only.
    fn history(&self, store: &Store, request: &Request) -> Reply {
        let prefs = store.history_prefs();
        let settings = runtime_settings(prefs);
        let saved = store.query_log_summary().unwrap_or_default();
        let limit = query_param(&request.query, "limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(200)
            .clamp(1, 1000);
        let search = query_param(&request.query, "search")
            .map(percent_decode)
            .filter(|v| !v.is_empty());
        let blocked = match query_param(&request.query, "filter") {
            Some("blocked") => Some(true),
            Some("allowed") => Some(false),
            _ => None,
        };
        let before = query_param(&request.query, "before").and_then(|v| v.parse::<i64>().ok());
        let mut next_before = None;
        let items: Vec<Value> = if settings.mode == HistoryMode::Memory {
            let needle = search.as_deref().map(str::to_lowercase);
            self.host
                .history(1000)
                .into_iter()
                .filter(|r| blocked.is_none_or(|b| b == r.blocked))
                .filter(|r| {
                    needle.as_deref().is_none_or(|n| {
                        let hay = format!(
                            "{} {} {}",
                            r.domain,
                            r.device.as_deref().unwrap_or(""),
                            r.client.map(|c| c.to_string()).unwrap_or_default()
                        );
                        hay.to_lowercase().contains(n)
                    })
                })
                .take(limit)
                .map(|r| {
                    json!({
                        "t": r.unix_ms, "domain": r.domain, "type": r.qtype,
                        "client": r.client.map(|c| c.to_string()), "device": r.device,
                        "blocked": r.blocked, "rcode": r.rcode, "ms": (r.micros as f64) / 1000.0,
                    })
                })
                .collect()
        } else if saved.rows > 0 {
            // Saved lookups stay visible (and deletable) even after the mode is switched off.
            let page = u16::try_from(limit).unwrap_or(1000);
            let Ok(rows) = store.query_log(&QueryFilter {
                search: search.as_deref(),
                blocked,
                before_id: before,
                limit: page,
            }) else {
                return unavailable();
            };
            if rows.len() == usize::from(page) {
                next_before = rows.last().map(|r| r.id);
            }
            rows.into_iter()
                .map(|r| {
                    json!({
                        "id": r.id, "t": r.row.t, "domain": r.row.domain, "type": r.row.qtype,
                        "client": r.row.client, "device": r.row.device, "blocked": r.row.blocked,
                        "rcode": r.row.rcode, "ms": (r.row.micros as f64) / 1000.0,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        reply(
            StatusCode::OK,
            &json!({
                "enabled": settings.mode != HistoryMode::Off,
                "mode": settings.mode.as_str(),
                "detail": settings.detail.as_str(),
                "retention_days": prefs.retention_days,
                "max_rows": QUERY_LOG_MAX_ROWS,
                "saved": { "rows": saved.rows, "oldest": saved.oldest_ms, "newest": saved.newest_ms },
                "items": items,
                "next_before": next_before,
            }),
        )
    }

    fn put_history(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let current = store.history_prefs();
        // `{"enabled": bool}` is the older on/off form. It means memory mode or off.
        let mode = if let Some(on) = body.get("enabled").and_then(Value::as_bool) {
            if on {
                HistoryMode::Memory
            } else {
                HistoryMode::Off
            }
        } else if let Some(value) = body.get("mode") {
            match value.as_str().and_then(HistoryMode::parse) {
                Some(mode) => mode,
                None => return bad("mode must be off, memory or saved"),
            }
        } else {
            return bad("mode must be off, memory or saved");
        };
        let detail = match body.get("detail") {
            None => current.detail,
            Some(value) => match value.as_str().and_then(HistoryDetail::parse) {
                Some(detail) => detail,
                None => return bad("detail must be anonymous or full"),
            },
        };
        let days = match body.get("retention_days") {
            None => current.retention_days,
            Some(value) => match value
                .as_u64()
                .and_then(|d| u32::try_from(d).ok())
                .filter(|d| (1..=MAX_RETENTION_DAYS).contains(d))
            {
                Some(days) => days,
                None => return bad("retention_days must be 1-90"),
            },
        };
        let prefs = HistoryPrefs {
            mode,
            detail,
            retention_days: days,
        };
        if store.set_history_prefs(&prefs).is_err() {
            return unavailable();
        }
        let settings = runtime_settings(prefs);
        self.host.set_history(settings);
        Self::actor(
            store,
            ctx,
            "history.update",
            &format!(
                "mode {} detail {} days {days}",
                mode.as_str(),
                detail.as_str()
            ),
        );
        reply(
            StatusCode::OK,
            &json!({
                "enabled": mode != HistoryMode::Off, "mode": mode.as_str(),
                "detail": detail.as_str(), "retention_days": days,
            }),
        )
    }

    /// Switch one optional module on or off. Modules are off until an administrator turns them on.
    fn put_module(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let Some(id) = body.get("id").and_then(Value::as_str) else {
            return bad("id is required");
        };
        let Some(&id) = MODULES.iter().find(|m| **m == id) else {
            return bad("unknown module");
        };
        let Some(on) = body.get("enabled").and_then(Value::as_bool) else {
            return bad("enabled must be true or false");
        };
        let mut enabled = enabled_modules(store);
        enabled.retain(|m| *m != id);
        if on {
            enabled.push(id);
        }
        if store.set_setting("modules", &enabled.join(",")).is_err() {
            return unavailable();
        }
        Self::actor(
            store,
            ctx,
            "module.update",
            &format!("{id} {}", if on { "on" } else { "off" }),
        );
        modules_json(store)
    }

    fn clear_history(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(removed) = store.clear_query_log() else {
            return unavailable();
        };
        // Lookups already waiting to be saved are saved history too.
        let _ = self.host.take_unsaved_history();
        Self::actor(store, ctx, "history.clear", &format!("{removed} rows"));
        reply(StatusCode::OK, &json!({ "removed": removed }))
    }

    fn put_settings(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let idle = body.get("session_idle_minutes");
        let language = body.get("language");
        let reload = body.get("overview_reload_secs");
        if idle.is_none() && language.is_none() && reload.is_none() {
            return bad("nothing to change");
        }
        // How often every console reloads the Overview. 0 means never.
        let reload_secs = match reload {
            None => None,
            Some(value) => match value.as_u64().filter(|s| OVERVIEW_RELOAD_STEPS.contains(s)) {
                Some(secs) => Some(secs),
                None => return bad("overview_reload_secs must be 0, 1, 2, 5, 10, 30 or 60"),
            },
        };
        let minutes = match idle {
            None => None,
            Some(value) => match value.as_u64().filter(|m| (5..=1440).contains(m)) {
                Some(minutes) => Some(minutes),
                None => return bad("session_idle_minutes must be 5-1440"),
            },
        };
        // `null` goes back to "automatic": each browser then uses its own language.
        let clear_language = language.is_some_and(Value::is_null);
        let code = match language {
            None => None,
            Some(value) if value.is_null() => None,
            Some(value) => match value.as_str().filter(|c| LANGUAGES.contains(c)) {
                Some(code) => Some(code),
                None => return bad("language is not available"),
            },
        };
        if let Some(secs) = reload_secs {
            if store
                .set_setting("overview_reload_secs", &secs.to_string())
                .is_err()
            {
                return unavailable();
            }
            Self::actor(
                store,
                ctx,
                "settings.update",
                &format!("overview reload {secs} s"),
            );
        }
        if let Some(minutes) = minutes {
            if store
                .set_setting("session_idle_minutes", &minutes.to_string())
                .is_err()
            {
                return unavailable();
            }
            Self::actor(
                store,
                ctx,
                "settings.update",
                &format!("idle {minutes} min"),
            );
        }
        if let Some(code) = code {
            if store.set_setting("language", code).is_err() {
                return unavailable();
            }
            Self::actor(store, ctx, "settings.update", &format!("language {code}"));
        } else if clear_language {
            if store.clear_setting("language").is_err() {
                return unavailable();
            }
            Self::actor(store, ctx, "settings.update", "language automatic");
        }
        settings_json(store)
    }

    /// Stop the downloads of the change that is being applied. Nothing changes: the previous
    /// settings and lists stay live.
    fn cancel_activity(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let cancelled = lumen_filter::activity::request_cancel();
        if cancelled {
            Self::actor(store, ctx, "apply.cancel", "block lists");
        }
        reply(StatusCode::OK, &json!({ "cancelled": cancelled }))
    }

    // ----- devices -----

    fn put_device(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let id = text(&body, "id").unwrap_or("").to_owned();
        let addresses: Result<Vec<IpAddr>, _> =
            body.get("addresses").and_then(Value::as_array).map_or_else(
                || Ok(Vec::new()),
                |list| {
                    list.iter()
                        .map(|v| v.as_str().unwrap_or("").parse::<IpAddr>())
                        .collect()
                },
            );
        let Ok(addresses) = addresses else {
            return bad("every address must be a valid IP address");
        };
        let nonempty = |key: &str| {
            text(&body, key)
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        let device = Device {
            id: id.clone(),
            addresses,
            profile: nonempty("profile"),
            group: nonempty("group"),
        };
        if let Some(message) = device_references(store, &device) {
            return bad(&message);
        }
        if let Err(message) = store.set_device(&device) {
            let _ = message;
            return bad(
                "invalid device: use an ID of letters, digits, dash or underscore, at least one address, and a profile or group",
            );
        }
        if store.enqueue(Command::Reload).is_err() {
            return unavailable();
        }
        Self::actor(store, ctx, "device.set", &id);
        reply(
            StatusCode::ACCEPTED,
            &json!({ "device": id, "reload": "queued" }),
        )
    }

    fn delete_device(&self, store: &mut Store, ctx: &Ctx<'_>, id: &str) -> Reply {
        match store.remove_device(id) {
            Ok(true) => {
                let _ = store.enqueue(Command::Reload);
                Self::actor(store, ctx, "device.remove", id);
                reply(StatusCode::ACCEPTED, &json!({ "reload": "queued" }))
            }
            Ok(false) => error(StatusCode::NOT_FOUND, "device not found"),
            Err(_) => bad("invalid device id"),
        }
    }

    // ----- config -----

    fn put_config(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let source = match config_source(store, &ctx.request.body) {
            Ok(source) => source,
            Err(response) => return response,
        };
        let Ok(Some(stored)) = store.config() else {
            return unavailable();
        };
        let staged =
            store.stage_config_by(&source, Path::new(&stored.base_dir), &ctx.session.user.name);
        match staged.and_then(|revision| {
            store
                .enqueue(Command::ConfigReload(revision))
                .map(|_| revision)
        }) {
            Ok(revision) => {
                Self::actor(store, ctx, "config.apply", &format!("revision {revision}"));
                reply(
                    StatusCode::ACCEPTED,
                    &json!({ "revision": revision, "reload": "queued" }),
                )
            }
            Err(_) => unavailable(),
        }
    }

    /// Save the external-login settings into the stored configuration and apply them, like any
    /// other configuration change. Turning it off keeps the other fields for next time.
    fn put_oidc(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let enabled = body
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let oidc = oidc_from_json(&body, enabled);
        if let Err(message) = check_oidc(store, &oidc) {
            return bad(&message);
        }
        let Ok(Some(stored)) = store.config() else {
            return unavailable();
        };
        let Ok(mut table) = toml::from_str::<toml::Table>(&stored.source) else {
            return unavailable();
        };
        let Some(web) = table
            .entry("web")
            .or_insert_with(|| toml::Value::Table(toml::Table::new()))
            .as_table_mut()
        else {
            return unavailable();
        };
        let Ok(value) = toml::Value::try_from(&oidc) else {
            return unavailable();
        };
        web.insert("oidc".into(), value);
        let Ok(source) = toml::to_string(&table) else {
            return unavailable();
        };
        if let Err(message) = Config::parse(&source, Path::new(&stored.base_dir)) {
            return bad(&message);
        }
        let staged =
            store.stage_config_by(&source, Path::new(&stored.base_dir), &ctx.session.user.name);
        match staged.and_then(|revision| {
            store
                .enqueue(Command::ConfigReload(revision))
                .map(|_| revision)
        }) {
            Ok(revision) => {
                Self::actor(store, ctx, "sso.update", if enabled { "on" } else { "off" });
                reply(
                    StatusCode::ACCEPTED,
                    &json!({ "revision": revision, "reload": "queued" }),
                )
            }
            Err(_) => unavailable(),
        }
    }

    /// Ask the provider whether these settings can work, without saving or signing anyone in.
    fn test_oidc(&self, store: &Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let oidc = oidc_from_json(&body, true);
        if let Err(message) = check_oidc(store, &oidc) {
            return reply(StatusCode::OK, &json!({ "ok": false, "error": message }));
        }
        match crate::oidc::check(&oidc) {
            Ok(found) => reply(
                StatusCode::OK,
                &json!({ "ok": true, "issuer": found.issuer, "logout": found.logout }),
            ),
            Err(message) => reply(StatusCode::OK, &json!({ "ok": false, "error": message })),
        }
    }

    fn restore_config(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let Some(revision) = body.get("revision").and_then(Value::as_u64) else {
            return bad("revision required");
        };
        let Ok(history) = store.config_history(100) else {
            return unavailable();
        };
        let Some(old) = history.into_iter().find(|r| r.revision == revision) else {
            return error(StatusCode::NOT_FOUND, "that revision is no longer kept");
        };
        let Ok(Some(stored)) = store.config() else {
            return unavailable();
        };
        if Config::parse(&old.source, Path::new(&stored.base_dir)).is_err() {
            return bad("that revision no longer parses with this version of Lumen");
        }
        let staged = store.stage_config_by(
            &old.source,
            Path::new(&stored.base_dir),
            &ctx.session.user.name,
        );
        match staged.and_then(|next| store.enqueue(Command::ConfigReload(next)).map(|_| next)) {
            Ok(next) => {
                Self::actor(
                    store,
                    ctx,
                    "config.restore",
                    &format!("revision {revision} as {next}"),
                );
                reply(
                    StatusCode::ACCEPTED,
                    &json!({ "revision": next, "reload": "queued" }),
                )
            }
            Err(_) => unavailable(),
        }
    }

    fn control(
        &self,
        store: &mut Store,
        ctx: &Ctx<'_>,
        command: Command,
        action: &str,
        target: &str,
    ) -> Reply {
        match store.enqueue(command) {
            Ok(_) => {
                Self::actor(store, ctx, action, target);
                reply(StatusCode::ACCEPTED, &json!({ "queued": true }))
            }
            Err(message) => error(StatusCode::SERVICE_UNAVAILABLE, &message),
        }
    }

    fn explain(&self, request: &Request) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return bad("invalid JSON");
        };
        let domain = text(&body, "domain").unwrap_or("").trim();
        let Ok(client) = text(&body, "client").unwrap_or("").trim().parse::<IpAddr>() else {
            return bad("client must be an IP address");
        };
        if domain.is_empty() || domain.len() > 253 {
            return bad("enter a domain name");
        }
        // Monday 1970-01-05 is unix day 4; the weekday maths in the filter is relative to it.
        let seconds = match (
            body.get("day").and_then(Value::as_u64),
            body.get("minute").and_then(Value::as_u64),
        ) {
            (Some(day @ 1..=7), Some(minute @ 0..=1439)) => (3 + day) * 86_400 + minute * 60,
            _ => now(),
        };
        let d = self.host.explain(domain, client, seconds);
        reply(
            StatusCode::OK,
            &json!({
                "blocked": d.blocked, "rule": d.rule, "list": d.list, "category": d.category,
                "profile": d.profile, "device": d.device, "group": d.group, "generation": d.generation,
            }),
        )
    }
}

struct Ctx<'a> {
    request: &'a Request,
    session: &'a Session,
    token_hash: &'a str,
}

// ----- helpers -----

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value)
}

fn json_content(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
}

/// A browser sends `Origin` on cross-site and same-site POSTs; it must match `Host`.
fn origin_ok(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let host = headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    origin
        .split_once("://")
        .is_some_and(|(_, authority)| authority == host)
}

fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// Decode `%XX` and `+` in a query-string value. Invalid escapes are kept as typed.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(byte);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).chars().take(100).collect()
}

/// The daemon-side half of the stored history choices.
const fn runtime_settings(prefs: HistoryPrefs) -> HistorySettings {
    HistorySettings {
        mode: prefs.mode,
        detail: prefs.detail,
    }
}

fn record_row(record: crate::host::QueryRecord) -> QueryRow {
    QueryRow {
        t: record.unix_ms,
        domain: record.domain,
        qtype: record.qtype,
        client: record.client.map(|c| c.to_string()),
        device: record.device,
        blocked: record.blocked,
        rcode: record.rcode.to_owned(),
        micros: record.micros,
    }
}

fn user_json(user: &lumen_store::User) -> Value {
    json!({
        "name": user.name, "role": user.role.as_str(), "must_change": user.must_change,
        "created_at": user.created_at, "last_login": user.last_login,
        "totp_enabled": user.totp_enabled,
    })
}

fn me_json(session: &Session) -> Value {
    json!({ "user": user_json(&session.user), "csrf": session.csrf })
}

fn users_json(store: &Store) -> Reply {
    match store.users() {
        Ok(users) => reply(
            StatusCode::OK,
            &Value::Array(
                users
                    .iter()
                    .map(|user| {
                        let mut json = user_json(user);
                        // Tied to a provider identity, so people can see who signs in that way.
                        json["sso"] = Value::Bool(store.oidc_linked(user.id).unwrap_or(false));
                        json
                    })
                    .collect(),
            ),
        ),
        Err(_) => unavailable(),
    }
}

fn devices_json(store: &Store) -> Reply {
    match store.devices() {
        Ok(devices) => reply(
            StatusCode::OK,
            &Value::Array(
                devices
                    .into_iter()
                    .map(|d| json!({
                        "id": d.id,
                        "addresses": d.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "profile": d.profile, "group": d.group,
                    }))
                    .collect(),
            ),
        ),
        Err(_) => unavailable(),
    }
}

/// The console language an administrator chose as the default. `None` until one is chosen,
/// so each browser can then use its own language.
fn language(store: &Store) -> Option<String> {
    store
        .setting("language")
        .ok()
        .flatten()
        .filter(|code| LANGUAGES.contains(&code.as_str()))
}

/// Optional features an administrator can switch on. Every module is off by default.
const MODULES: &[&str] = &["traffic-map"];

/// The enabled modules, in catalog order. Unknown names in storage are ignored.
fn enabled_modules(store: &Store) -> Vec<&'static str> {
    let saved = store.setting("modules").ok().flatten().unwrap_or_default();
    MODULES
        .iter()
        .copied()
        .filter(|m| saved.split(',').any(|s| s == *m))
        .collect()
}

fn modules_json(store: &Store) -> Reply {
    reply(
        StatusCode::OK,
        &json!({
            "available": MODULES,
            "enabled": enabled_modules(store),
        }),
    )
}

/// The seconds between Overview reloads the console offers. 0 turns it off.
const OVERVIEW_RELOAD_STEPS: [u64; 7] = [1, 2, 5, 10, 30, 60, 0];

fn overview_reload_secs(store: &Store) -> u64 {
    store
        .setting("overview_reload_secs")
        .ok()
        .flatten()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| OVERVIEW_RELOAD_STEPS.contains(s))
        .unwrap_or(10)
}

fn settings_json(store: &Store) -> Reply {
    reply(
        StatusCode::OK,
        &json!({
            "session_idle_minutes": Console::idle_secs(store) / 60,
            "overview_reload_secs": overview_reload_secs(store),
            "language": language(store),
            "languages": LANGUAGES,
        }),
    )
}

fn audit_json(store: &Store, query: &str) -> Reply {
    let limit = query_param(query, "limit")
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(200)
        .clamp(1, 1000);
    match store.audit_events(limit) {
        Ok(events) => reply(
            StatusCode::OK,
            &Value::Array(
                events
                    .into_iter()
                    .map(|e| json!({
                        "id": e.id, "t": e.created_at, "actor": e.actor, "role": e.role,
                        "action": e.action, "target": e.target, "outcome": e.outcome, "peer": e.peer,
                    }))
                    .collect(),
            ),
        ),
        Err(_) => unavailable(),
    }
}

fn config_json(store: &Store) -> Reply {
    let Ok(Some(stored)) = store.config() else {
        return unavailable();
    };
    // Effective values: whatever the file omits takes the daemon's own default.
    let Ok(effective) = Config::parse(&stored.source, Path::new(&stored.base_dir)) else {
        return unavailable();
    };
    let Ok(mut config) = serde_json::to_value(&effective) else {
        return unavailable();
    };
    // Provider presets expand into upstream addresses; the form edits the presets and
    // only the custom extras, so hide the derived entries.
    if effective.resolver.provider_upstreams > 0
        && let Some(upstreams) = config
            .pointer_mut("/resolver/upstreams")
            .and_then(Value::as_array_mut)
    {
        upstreams.drain(..effective.resolver.provider_upstreams.min(upstreams.len()));
    }
    if let Some(filtering) = config.get_mut("filtering").and_then(Value::as_object_mut) {
        filtering.remove("devices");
    }
    reply(
        StatusCode::OK,
        &json!({
            "revision": stored.revision,
            "pending_revision": store.staged_config().ok().flatten().map(|c| c.revision),
            "config": config,
        }),
    )
}

fn config_history(store: &Store) -> Reply {
    match store.config_history(20) {
        Ok(items) => reply(
            StatusCode::OK,
            &Value::Array(
                items
                    .into_iter()
                    .map(|r| json!({ "revision": r.revision, "t": r.applied_at, "actor": r.actor, "toml": r.source }))
                    .collect(),
            ),
        ),
        Err(_) => unavailable(),
    }
}

/// Convert JSON from the console to TOML, dropping nulls, and validate it.
#[allow(clippy::result_large_err)] // The error is the ready-made HTTP reply.
fn config_source(store: &Store, body: &[u8]) -> Result<String, Reply> {
    let Ok(request) = serde_json::from_slice::<Value>(body) else {
        return Err(bad("invalid JSON"));
    };
    let Some(config) = request.get("config").and_then(Value::as_object) else {
        return Err(bad("config object required"));
    };
    let mut config = Value::Object(config.clone());
    if let Ok(defaults) = serde_json::to_value(Config::default()) {
        prune_defaults(&mut config, &defaults);
    }
    let Some(toml::Value::Table(mut table)) = json_to_toml(&config) else {
        return Err(bad("config must be an object"));
    };
    // Recursive mode takes no forwarding upstreams; drop leftovers from forward mode.
    if let Some(toml::Value::Table(resolver)) = table.get_mut("resolver")
        && resolver.get("mode").and_then(toml::Value::as_str) == Some("recursive")
    {
        resolver.remove("providers");
        resolver.remove("upstreams");
    }
    table.insert("schema_version".into(), toml::Value::Integer(1));
    if let Some(toml::Value::Table(filtering)) = table.get_mut("filtering") {
        filtering.remove("devices");
    }
    let source = toml::to_string(&table).map_err(|_| bad("config cannot be written as TOML"))?;
    let Ok(Some(stored)) = store.config() else {
        return Err(unavailable());
    };
    Config::parse(&source, Path::new(&stored.base_dir)).map_err(|message| {
        if message.starts_with("invalid config") {
            bad("The configuration has a setting Lumen does not recognise, or a value of the wrong type.")
        } else {
            bad(&message)
        }
    })?;
    Ok(source)
}

fn preview_config(store: &Store, request: &Request) -> Reply {
    match config_source(store, &request.body) {
        Ok(source) => reply(StatusCode::OK, &json!({ "toml": source })),
        Err(response) => response,
    }
}

/// Drop every object member equal to its default so saved TOML stays small and readable.
fn prune_defaults(value: &mut Value, default: &Value) {
    let (Value::Object(map), Value::Object(defaults)) = (&mut *value, default) else {
        return;
    };
    let keys: Vec<String> = map.keys().cloned().collect();
    for key in keys {
        let Some(default_item) = defaults.get(&key) else {
            continue;
        };
        if map.get(&key) == Some(default_item) {
            map.remove(&key);
        } else if let Some(item) = map.get_mut(&key) {
            prune_defaults(item, default_item);
            if matches!(item, Value::Object(inner) if inner.is_empty()) {
                map.remove(&key);
            }
        }
    }
}

fn json_to_toml(value: &Value) -> Option<toml::Value> {
    Some(match value {
        Value::Null => return None,
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::Number(n) => n
            .as_i64()
            .map(toml::Value::Integer)
            .or_else(|| n.as_f64().map(toml::Value::Float))?,
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Array(items) => toml::Value::Array(items.iter().filter_map(json_to_toml).collect()),
        Value::Object(map) => {
            let mut table = toml::Table::new();
            for (key, item) in map {
                if let Some(converted) = json_to_toml(item) {
                    table.insert(key.clone(), converted);
                }
            }
            toml::Value::Table(table)
        }
    })
}

/// A device may only name profiles and groups that exist in the active config.
fn device_references(store: &Store, device: &Device) -> Option<String> {
    let stored = store.config().ok().flatten()?;
    let config = Config::parse(&stored.source, Path::new(&stored.base_dir)).ok()?;
    let filtering = &config.filtering;
    if let Some(profile) = &device.profile
        && !filtering.profiles.iter().any(|p| &p.id == profile)
    {
        return Some(format!(
            "Profile “{profile}” does not exist. Create it under Filtering first."
        ));
    }
    if let Some(group) = &device.group
        && !filtering.groups.iter().any(|g| &g.id == group)
    {
        return Some(format!(
            "Group “{group}” does not exist. Create it under Filtering first."
        ));
    }
    None
}

fn snake(debug: &str) -> String {
    let mut out = String::new();
    for (index, ch) in debug.chars().enumerate() {
        if ch.is_uppercase() && index > 0 {
            out.push('_');
        }
        out.extend(ch.to_lowercase());
    }
    out
}

/// Live download and apply progress for the console's activity bar.
fn activity_json() -> Value {
    let (job, lists) = lumen_filter::activity::snapshot();
    json!({
        "phase": job.phase, "message": job.message, "since": job.since,
        "cancellable": matches!(job.phase, "checking" | "downloading"),
        "lists": lists.into_iter().map(|l| json!({
            "id": l.id, "state": l.state, "bytes": l.bytes, "total": l.total, "rules": l.rules, "error": l.error,
        })).collect::<Vec<_>>(),
    })
}

fn providers_json() -> Reply {
    let Ok(catalog) = Catalog::bundled() else {
        return unavailable();
    };
    let items: Vec<Value> = catalog
        .providers
        .iter()
        .map(|p| {
            let supported = |t: &&lumen_config::providers::Transport| {
                snake(&format!("{:?}", t.availability)) == "supported"
            };
            let transports: Vec<String> = p
                .transports
                .iter()
                .filter(supported)
                .map(|t| snake(&format!("{:?}", t.protocol)))
                .collect();
            // Addresses each transport would add, by family, so the console can
            // keep a selection within the 8-upstream limit.
            let endpoints: serde_json::Map<String, Value> = p
                .transports
                .iter()
                .filter(supported)
                .map(|t| {
                    let ips: Vec<IpAddr> = if t.bootstrap_ips.is_empty() {
                        p.ipv4.iter().chain(p.ipv6.iter()).copied().collect()
                    } else {
                        t.bootstrap_ips.clone()
                    };
                    let v4 = ips.iter().filter(|ip| ip.is_ipv4()).count();
                    (
                        snake(&format!("{:?}", t.protocol)),
                        json!({ "ipv4": v4, "ipv6": ips.len() - v4 }),
                    )
                })
                .collect();
            json!({
                "id": p.id, "name": p.name, "country": p.operator_country,
                "scope": snake(&format!("{:?}", p.network_scope)),
                "filter": snake(&format!("{:?}", p.filter_variant)),
                "transports": transports, "endpoints": endpoints,
            })
        })
        .collect();
    reply(StatusCode::OK, &Value::Array(items))
}

/// Resident memory where the platform exposes it without extra dependencies.
fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

pub(crate) const MAX_BODY: usize = BODY_LIMIT;

#[cfg(test)]
#[allow(clippy::too_many_lines)] // Scenario tests read top to bottom.
mod tests {
    use super::*;
    use crate::host::{Explained, ListInfo, QueryRecord};
    use lumen_store::password::hash_with_iterations;

    /// A host whose history behaves like the daemon's: settings, a recent list, a save queue.
    #[derive(Default)]
    struct Stub {
        settings: Mutex<HistorySettings>,
        recent: Mutex<Vec<QueryRecord>>,
        unsaved: Mutex<Vec<QueryRecord>>,
        oidc: Mutex<Option<lumen_config::Oidc>>,
    }
    impl Host for Stub {
        fn oidc(&self) -> Option<lumen_config::Oidc> {
            self.oidc.lock().unwrap().clone()
        }
        fn counters(&self) -> Counters {
            Counters {
                queries: 7,
                blocked: 2,
                allowed: 5,
                ..Counters::default()
            }
        }
        fn lists(&self) -> Vec<ListInfo> {
            vec![ListInfo {
                id: "ads".into(),
                rules: 3,
                unsupported: 0,
                duplicates: 0,
            }]
        }
        fn explain(&self, domain: &str, _: IpAddr, _: u64) -> Explained {
            Explained {
                blocked: domain == "ads.example",
                rule: None,
                list: None,
                category: None,
                profile: None,
                device: None,
                group: None,
                generation: 1,
            }
        }
        fn uptime_secs(&self) -> u64 {
            5
        }
        fn history_settings(&self) -> HistorySettings {
            *self.settings.lock().unwrap()
        }
        fn set_history(&self, settings: HistorySettings) {
            *self.settings.lock().unwrap() = settings;
            if settings.mode != HistoryMode::Saved {
                self.unsaved.lock().unwrap().clear();
            }
        }
        fn history(&self, limit: usize) -> Vec<QueryRecord> {
            self.recent
                .lock()
                .unwrap()
                .iter()
                .take(limit)
                .cloned()
                .collect()
        }
        fn take_unsaved_history(&self) -> Vec<QueryRecord> {
            std::mem::take(&mut *self.unsaved.lock().unwrap())
        }
    }

    const CONFIG: &str = "schema_version = 1\n[filtering]\ndefault_profile = \"standard\"\n[[filtering.profiles]]\nid = \"standard\"\n";

    struct Fixture {
        console: Console,
        host: Arc<Stub>,
        _directory: tempfile::TempDir,
        state: PathBuf,
    }

    fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.db");
        let mut store = Store::open(&state).unwrap();
        store.set_config(CONFIG, directory.path()).unwrap();
        let cheap = |pw: &str| hash_with_iterations(pw, 1_000).unwrap();
        store
            .create_first_admin("admin", &cheap("correct horse battery"))
            .unwrap();
        store
            .create_user("anna", Role::User, &cheap("anna passphrase 123"), false)
            .unwrap();
        let host = Arc::new(Stub::default());
        Fixture {
            console: Console::new(state.clone(), host.clone(), "test"),
            host,
            _directory: directory,
            state,
        }
    }

    fn peer(ip: &str) -> SocketAddr {
        format!("{ip}:40000").parse().unwrap()
    }

    fn call(
        f: &Fixture,
        method: Method,
        path: &str,
        session: Option<(&str, &str)>,
        body: &str,
        from: &str,
    ) -> Reply {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(HOST, HeaderValue::from_static("lumen.test"));
        if let Some((cookie, csrf)) = session {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&format!("{COOKIE_NAME}={cookie}")).unwrap(),
            );
            headers.insert("x-lumen-csrf", HeaderValue::from_str(csrf).unwrap());
        }
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        f.console.handle(&Request {
            method,
            path: path.into(),
            query: query.into(),
            headers,
            body: Bytes::from(body.to_owned()),
            peer: peer(from),
            tls: false,
        })
    }

    fn body(reply: Reply) -> (StatusCode, Value) {
        use http_body_util::BodyExt;
        let status = reply.status();
        let bytes = futures_block(reply.into_body().collect())
            .expect("body")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    fn futures_block<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    /// Sign in and return (cookie token, csrf).
    fn sign_in(f: &Fixture, user: &str, password: &str) -> (String, String) {
        let reply = call(
            f,
            Method::POST,
            "/api/login",
            None,
            &json!({"username": user, "password": password}).to_string(),
            "127.0.0.1",
        );
        let cookie = reply
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let (status, json) = body(reply);
        assert_eq!(status, StatusCode::OK, "{json}");
        assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
        let token = cookie
            .trim_start_matches("lumen_session=")
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        (token, json["csrf"].as_str().unwrap().to_owned())
    }

    #[test]
    fn external_sign_in_is_off_by_default_bound_to_the_browser_and_single_use() {
        use crate::oidc::tests::{config as oidc_config, mock_provider, nonce_of};
        let f = fixture();
        let go = |path: &str, cookie: Option<&str>, from: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_static("lumen.test"));
            if let Some(cookie) = cookie {
                headers.insert(COOKIE, HeaderValue::from_str(cookie).unwrap());
            }
            let (path, query) = path.split_once('?').unwrap_or((path, ""));
            f.console.handle(&Request {
                method: Method::GET,
                path: path.into(),
                query: query.into(),
                headers,
                body: Bytes::new(),
                peer: peer(from),
                tls: false,
            })
        };
        let cookies = |reply: &Reply| -> Vec<String> {
            reply
                .headers()
                .get_all(SET_COOKIE)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect()
        };
        let location = |reply: &Reply| {
            reply.headers()[hyper::header::LOCATION]
                .to_str()
                .unwrap()
                .to_owned()
        };

        // Off: no route, nothing advertised.
        assert_eq!(
            go("/api/login/oidc", None, "127.0.0.1").status(),
            StatusCode::NOT_FOUND
        );
        let (_, state) = body(call(&f, Method::GET, "/api/state", None, "", "127.0.0.1"));
        assert!(state["oidc"].is_null());

        let provider = mock_provider("subject-7", "lumen");
        let mut config = oidc_config(&provider.base);
        config.label = "Authentik".into();
        config.admin_group = Some("lumen-admins".into());
        *f.host.oidc.lock().unwrap() = Some(config);
        let (_, state) = body(call(&f, Method::GET, "/api/state", None, "", "127.0.0.1"));
        assert_eq!(state["oidc"]["label"], "Authentik");

        // Start: a redirect to the provider plus a Lax, HttpOnly flow cookie.
        let started = go("/api/login/oidc", None, "127.0.0.1");
        assert_eq!(started.status(), StatusCode::FOUND);
        let url = location(&started);
        assert!(
            url.starts_with(&format!("{}/authorize?", provider.base)),
            "{url}"
        );
        let flow_cookie = cookies(&started).remove(0);
        assert!(flow_cookie.contains("HttpOnly") && flow_cookie.contains("SameSite=Lax"));
        assert!(!flow_cookie.contains("Strict"));
        let pair = flow_cookie.split(';').next().unwrap().to_owned();
        let state_value = pair.trim_start_matches("lumen_oidc=").to_owned();
        *provider.nonce.lock().unwrap() = nonce_of(&url);

        // Without the cookie, or with a different browser's state, nothing signs in.
        for (cookie, from) in [(None, "127.0.0.1"), (Some("lumen_oidc=other"), "127.0.0.1")] {
            let failed = go(
                &format!("/api/login/oidc/callback?code=abc&state={state_value}"),
                cookie,
                from,
            );
            assert_eq!(failed.status(), StatusCode::FOUND);
            assert_eq!(location(&failed), "/?sso=failed#/login");
            assert!(
                cookies(&failed)
                    .iter()
                    .all(|c| !c.starts_with("lumen_session=") || c.contains("Max-Age=0"))
            );
        }
        // A provider error is refused as well.
        let refused = go(
            &format!("/api/login/oidc/callback?error=access_denied&state={state_value}"),
            Some(&pair),
            "127.0.0.1",
        );
        assert_eq!(location(&refused), "/?sso=failed#/login");

        // The flow state was spent by none of the failures above, except the error one above
        // only checks it; start again for the real sign-in.
        let started = go("/api/login/oidc", None, "127.0.0.1");
        let url = location(&started);
        *provider.nonce.lock().unwrap() = nonce_of(&url);
        let pair = cookies(&started)
            .remove(0)
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let state_value = pair.trim_start_matches("lumen_oidc=").to_owned();
        let done = go(
            &format!("/api/login/oidc/callback?code=the-code&state={state_value}"),
            Some(&pair),
            "127.0.0.1",
        );
        assert_eq!(done.status(), StatusCode::FOUND);
        assert_eq!(location(&done), "/");
        let set = cookies(&done);
        let session = set
            .iter()
            .find(|c| c.starts_with("lumen_session="))
            .expect("session cookie");
        assert!(session.contains("HttpOnly") && session.contains("SameSite=Strict"));
        assert!(
            set.iter()
                .any(|c| c.starts_with("lumen_oidc=;") && c.contains("Max-Age=0"))
        );
        let token = session
            .trim_start_matches("lumen_session=")
            .split(';')
            .next()
            .unwrap();

        // The session works, the group made this first login an administrator, and the console
        // hands the page its CSRF token through /api/state.
        let (status, state) = body(go(
            "/api/state",
            Some(&format!("lumen_session={token}")),
            "127.0.0.1",
        ));
        assert_eq!(status, StatusCode::OK);
        let name = state["user"]["user"]["name"].as_str().unwrap();
        assert!(
            name.starts_with("anna-"),
            "{name}: the local anna is not taken over"
        );
        assert_eq!(state["user"]["user"]["role"], "admin");
        assert!(
            state["user"]["csrf"]
                .as_str()
                .is_some_and(|c| !c.is_empty())
        );

        // Replaying the callback fails: the state was single use.
        let replay = go(
            &format!("/api/login/oidc/callback?code=the-code&state={state_value}"),
            Some(&pair),
            "127.0.0.1",
        );
        assert_eq!(location(&replay), "/?sso=failed#/login");

        // The local account "anna" was never linked: the SSO person is a separate account.
        let store = Store::open(&f.state).unwrap();
        let users = store.users().unwrap();
        assert_eq!(
            users.iter().filter(|u| u.name.starts_with("anna")).count(),
            2
        );
        assert!(store.user_with_record("anna").unwrap().unwrap().0.role == Role::User);
    }

    fn oidc_get(f: &Fixture, path: &str, cookie: &str) -> Reply {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("lumen.test"));
        if !cookie.is_empty() {
            headers.insert(COOKIE, HeaderValue::from_str(cookie).unwrap());
        }
        let (path, query) = path.split_once('?').unwrap_or((path, ""));
        f.console.handle(&Request {
            method: Method::GET,
            path: path.into(),
            query: query.into(),
            headers,
            body: Bytes::new(),
            peer: peer("127.0.0.1"),
            tls: false,
        })
    }

    fn csrf_of(f: &Fixture, cookie: &str) -> String {
        let token = cookie
            .split("lumen_session=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let hash = password::sha256_hex(token);
        Store::open(&f.state)
            .unwrap()
            .session(&hash, 1800, 43200)
            .unwrap()
            .unwrap()
            .csrf
    }

    fn set_cookies(reply: &Reply) -> Vec<String> {
        reply
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    fn pair(cookie: &str) -> String {
        cookie.split(';').next().unwrap().to_owned()
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One story: link, sign in, sync roles, sign out, unlink.
    fn external_login_links_accounts_syncs_roles_and_signs_out_of_the_provider() {
        use crate::oidc::tests::{config as oidc_config, mock_provider, nonce_of};
        let f = fixture();
        let provider = mock_provider("subject-7", "lumen");
        let mut config = oidc_config(&provider.base);
        config.admin_group = Some("lumen-admins".into());
        config.sync_role = true;
        config.single_logout = true;
        *f.host.oidc.lock().unwrap() = Some(config.clone());

        // A local person links their own account. Only a signed-in person with the CSRF token can.
        let (token, csrf) = sign_in(&f, "anna", "anna passphrase 123");
        let session = Some((token.as_str(), csrf.as_str()));
        let (_, mine) = body(call(
            &f,
            Method::GET,
            "/api/me/oidc",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(
            (mine["available"].as_bool(), mine["linked"].as_bool()),
            (Some(true), Some(false))
        );
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/me/oidc/link",
                Some((token.as_str(), "wrong")),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        let started = call(
            &f,
            Method::POST,
            "/api/me/oidc/link",
            session,
            "",
            "127.0.0.1",
        );
        let flow = pair(&set_cookies(&started)[0]);
        let (status, started) = body(started);
        assert_eq!(status, StatusCode::OK);
        *provider.nonce.lock().unwrap() = nonce_of(started["url"].as_str().unwrap());
        let state = flow.trim_start_matches("lumen_oidc=");
        // The provider's redirect carries no session cookie (it is SameSite=Strict), only the flow.
        let done = oidc_get(
            &f,
            &format!("/api/login/oidc/callback?code=c&state={state}"),
            &flow,
        );
        assert_eq!(
            done.headers()[hyper::header::LOCATION],
            "/?sso=linked#/account"
        );
        assert!(
            set_cookies(&done)
                .iter()
                .all(|c| !c.starts_with("lumen_session="))
        );
        let (_, mine) = body(call(
            &f,
            Method::GET,
            "/api/me/oidc",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(mine["linked"], true);
        // A second link attempt is refused, and nobody else can claim the same identity.
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/me/oidc/link",
                session,
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::CONFLICT
        );
        let (other_token, other_csrf) = sign_in(&f, "admin", "correct horse battery");
        let other = call(
            &f,
            Method::POST,
            "/api/me/oidc/link",
            Some((other_token.as_str(), other_csrf.as_str())),
            "",
            "127.0.0.1",
        );
        let flow = pair(&set_cookies(&other)[0]);
        let (_, other) = body(other);
        *provider.nonce.lock().unwrap() = nonce_of(other["url"].as_str().unwrap());
        let refused = oidc_get(
            &f,
            &format!(
                "/api/login/oidc/callback?code=c&state={}",
                flow.trim_start_matches("lumen_oidc=")
            ),
            &flow,
        );
        assert_eq!(
            refused.headers()[hyper::header::LOCATION],
            "/?sso=link-failed#/account"
        );

        // Signing in through the provider now reaches the existing local account, and the
        // group promotes it (role sync).
        let sso = |f: &Fixture| {
            let started = oidc_get(f, "/api/login/oidc", "");
            let flow = pair(&set_cookies(&started)[0]);
            let url = started.headers()[hyper::header::LOCATION]
                .to_str()
                .unwrap()
                .to_owned();
            *provider.nonce.lock().unwrap() = nonce_of(&url);
            let state = flow.trim_start_matches("lumen_oidc=").to_owned();
            oidc_get(
                f,
                &format!("/api/login/oidc/callback?code=c&state={state}"),
                &flow,
            )
        };
        let role_of = |f: &Fixture, name: &str| {
            Store::open(&f.state)
                .unwrap()
                .user_with_record(name)
                .unwrap()
                .unwrap()
                .0
                .role
        };
        assert_eq!(role_of(&f, "anna"), Role::User);
        let signed = sso(&f);
        assert_eq!(signed.headers()[hyper::header::LOCATION], "/");
        let cookies = set_cookies(&signed);
        assert_eq!(
            role_of(&f, "anna"),
            Role::Admin,
            "group membership promotes"
        );
        assert_eq!(
            Store::open(&f.state).unwrap().users().unwrap().len(),
            2,
            "no new account"
        );
        let session_cookie = cookies
            .iter()
            .find(|c| c.starts_with("lumen_session="))
            .unwrap();
        let marker = cookies
            .iter()
            .find(|c| c.starts_with("lumen_sso=1"))
            .expect("sso marker");
        assert!(marker.contains("HttpOnly") && marker.contains("SameSite=Strict"));

        // Single logout: with the marker the answer names the provider's logout page.
        let out = |cookie: String| {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_static("lumen.test"));
            headers.insert(COOKIE, HeaderValue::from_str(&cookie).unwrap());
            headers.insert(
                "x-lumen-csrf",
                HeaderValue::from_str(&csrf_of(&f, &cookie)).unwrap(),
            );
            f.console.handle(&Request {
                method: Method::POST,
                path: "/api/logout".into(),
                query: String::new(),
                headers,
                body: Bytes::new(),
                peer: peer("127.0.0.1"),
                tls: false,
            })
        };
        let token = pair(session_cookie);
        let reply = out(format!("{token}; {}", pair(marker)));
        assert!(
            set_cookies(&reply)
                .iter()
                .any(|c| c.starts_with("lumen_sso=;") && c.contains("Max-Age=0"))
        );
        let (_, reply) = body(reply);
        let target = reply["redirect"].as_str().expect("provider logout address");
        assert!(
            target.starts_with(&format!("{}/logout?", provider.base)),
            "{target}"
        );
        assert!(target.contains("client_id=lumen"));
        // A password sign-in has no marker, so signing out stays inside the console.
        let (token, _) = sign_in(&f, "anna", "anna passphrase 123");
        let (_, reply) = body(out(format!("lumen_session={token}")));
        assert!(reply.get("redirect").is_none());

        // Role sync also demotes when the group is gone, but never the last administrator.
        let mut changed = config.clone();
        changed.admin_group = Some("other-group".into());
        *f.host.oidc.lock().unwrap() = Some(changed);
        sso(&f);
        assert_eq!(role_of(&f, "anna"), Role::User, "no longer in the group");
        Store::open(&f.state)
            .unwrap()
            .set_role("anna", Role::Admin)
            .unwrap();
        Store::open(&f.state)
            .unwrap()
            .set_role("admin", Role::User)
            .unwrap();
        let kept = sso(&f);
        assert_eq!(
            kept.headers()[hyper::header::LOCATION],
            "/",
            "still signs in"
        );
        assert_eq!(
            role_of(&f, "anna"),
            Role::Admin,
            "the last administrator stays"
        );

        // Without role sync a later sign-in leaves the role alone.
        let mut plain = config;
        plain.sync_role = false;
        *f.host.oidc.lock().unwrap() = Some(plain);
        Store::open(&f.state)
            .unwrap()
            .set_role("admin", Role::Admin)
            .unwrap();
        Store::open(&f.state)
            .unwrap()
            .set_role("anna", Role::User)
            .unwrap();
        sso(&f);
        assert_eq!(role_of(&f, "anna"), Role::User);

        // Unlinking needs the account's own password.
        let (token, csrf) = sign_in(&f, "anna", "anna passphrase 123");
        let session = Some((token.as_str(), csrf.as_str()));
        let wrong = call(
            &f,
            Method::DELETE,
            "/api/me/oidc",
            session,
            r#"{"password":"nope nope nope"}"#,
            "127.0.0.1",
        );
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
        let right = call(
            &f,
            Method::DELETE,
            "/api/me/oidc",
            session,
            r#"{"password":"anna passphrase 123"}"#,
            "127.0.0.1",
        );
        assert_eq!(right.status(), StatusCode::OK);
        let (_, mine) = body(call(
            &f,
            Method::GET,
            "/api/me/oidc",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(mine["linked"], false);
        let audit = Store::open(&f.state).unwrap().audit_events(100).unwrap();
        assert!(
            audit
                .iter()
                .any(|e| e.action == "user.oidc-link" && e.outcome == "accepted")
        );
        assert!(
            audit
                .iter()
                .any(|e| e.action == "user.oidc-link" && e.outcome == "rejected")
        );
        assert!(audit.iter().any(|e| e.action == "user.oidc-unlink"));
    }

    #[test]
    fn administrators_save_and_check_external_login_from_the_console() {
        use crate::oidc::tests::mock_provider;
        let f = fixture();
        let provider = mock_provider("s", "lumen");
        // The console tests' config has no web listener; add one so the settings can be valid.
        {
            let mut store = Store::open(&f.state).unwrap();
            store
                .set_config(
                    "schema_version = 1\n[web]\nhttp = ['127.0.0.1:8080']\n",
                    f.state.parent().unwrap(),
                )
                .unwrap();
        }
        let (admin, admin_csrf) = sign_in(&f, "admin", "correct horse battery");
        let (user, user_csrf) = sign_in(&f, "anna", "anna passphrase 123");
        let settings = |enabled: bool, issuer: &str| {
            json!({
                "enabled": enabled, "label": "Authentik", "issuer": issuer, "client_id": "lumen",
                "redirect_url": "http://127.0.0.1:8080/api/login/oidc/callback",
                "admin_group": "lumen-admins", "sync_role": true, "single_logout": true
            })
            .to_string()
        };
        let put = |who: (&str, &str), body: String| {
            call(&f, Method::PUT, "/api/oidc", Some(who), &body, "127.0.0.1")
        };
        // People who are not administrators cannot read or change it.
        assert_eq!(
            put((&user, &user_csrf), settings(true, &provider.base)).status(),
            StatusCode::FORBIDDEN
        );
        let who = (admin.as_str(), admin_csrf.as_str());

        // The provider check is answered in the body, and never saves anything.
        let (status, checked) = body(call(
            &f,
            Method::POST,
            "/api/oidc/test",
            Some(who),
            &settings(true, &provider.base),
            "127.0.0.1",
        ));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            (checked["ok"].as_bool(), checked["logout"].as_bool()),
            (Some(true), Some(true))
        );
        let (_, failed) = body(call(
            &f,
            Method::POST,
            "/api/oidc/test",
            Some(who),
            &settings(true, "https://id.example/"),
            "127.0.0.1",
        ));
        assert_eq!(failed["ok"], false);
        let (_, invalid) = body(call(
            &f,
            Method::POST,
            "/api/oidc/test",
            Some(who),
            &settings(true, "http://remote.example/"),
            "127.0.0.1",
        ));
        assert!(
            invalid["error"].as_str().unwrap().contains("issuer"),
            "{invalid}"
        );
        assert!(
            Store::open(&f.state)
                .unwrap()
                .staged_config()
                .unwrap()
                .is_none()
        );

        // Invalid settings are refused; valid ones are staged as a new revision and queued.
        assert_eq!(
            put(who, settings(true, "http://remote.example/")).status(),
            StatusCode::BAD_REQUEST
        );
        let (status, saved) = body(put(who, settings(true, &provider.base)));
        assert_eq!(status, StatusCode::ACCEPTED, "{saved}");
        let staged = Store::open(&f.state)
            .unwrap()
            .staged_config()
            .unwrap()
            .unwrap();
        assert_eq!(staged.revision, saved["revision"].as_u64().unwrap());
        let config = Config::parse(&staged.source, Path::new("/etc/lumen")).unwrap();
        assert!(
            config.web.oidc.enabled && config.web.oidc.sync_role && config.web.oidc.single_logout
        );
        assert_eq!(config.web.oidc.label, "Authentik");
        assert_eq!(config.web.http.len(), 1, "the rest of the config is kept");
        let audit = Store::open(&f.state).unwrap().audit_events(50).unwrap();
        assert!(
            audit
                .iter()
                .any(|e| e.action == "sso.update" && e.target == "on")
        );

        // Turning it off is always allowed and keeps the other fields.
        let (status, _) = body(put(who, settings(false, "")));
        assert_eq!(status, StatusCode::ACCEPTED);

        // The people list says who is tied to a provider identity.
        let mut store = Store::open(&f.state).unwrap();
        let anna = store.user_with_record("anna").unwrap().unwrap().0;
        store
            .oidc_link(anna.id, "https://id.example/", "x")
            .unwrap();
        let (_, users) = body(call(
            &f,
            Method::GET,
            "/api/users",
            Some(who),
            "",
            "127.0.0.1",
        ));
        let flag = |name: &str| {
            users
                .as_array()
                .unwrap()
                .iter()
                .find(|u| u["name"] == name)
                .unwrap()["sso"]
                .as_bool()
        };
        assert_eq!((flag("anna"), flag("admin")), (Some(true), Some(false)));
    }

    #[test]
    fn the_callback_address_follows_how_people_reach_the_console() {
        use crate::oidc::tests::{config as oidc_config, mock_provider};
        let f = fixture();
        let provider = mock_provider("s", "lumen");
        let mut config = oidc_config(&provider.base);
        config.redirect_url = String::new();
        *f.host.oidc.lock().unwrap() = Some(config.clone());
        let start = |host: &str, proto: Option<&str>| {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_str(host).unwrap());
            if let Some(proto) = proto {
                headers.insert("x-forwarded-proto", HeaderValue::from_str(proto).unwrap());
            }
            f.console.handle(&Request {
                method: Method::GET,
                path: "/api/login/oidc".into(),
                query: String::new(),
                headers,
                body: Bytes::new(),
                peer: peer("127.0.0.1"),
                tls: false,
            })
        };
        let redirect_uri = |reply: &Reply| {
            let location = reply.headers()[hyper::header::LOCATION]
                .to_str()
                .unwrap()
                .to_owned();
            reqwest::Url::parse(&location)
                .ok()?
                .query_pairs()
                .find(|(key, _)| key == "redirect_uri")
                .map(|(_, value)| value.into_owned())
        };
        for (host, proto, expected) in [
            (
                "lumen.dns.orb.local",
                Some("https"),
                "https://lumen.dns.orb.local/api/login/oidc/callback",
            ),
            (
                "192.168.1.2:8080",
                None,
                "http://192.168.1.2:8080/api/login/oidc/callback",
            ),
            (
                "[fd00::2]:8080",
                None,
                "http://[fd00::2]:8080/api/login/oidc/callback",
            ),
            (
                "dns.home.example",
                Some("HTTPS"),
                "https://dns.home.example/api/login/oidc/callback",
            ),
            (
                "dns.home.example",
                Some("gopher"),
                "http://dns.home.example/api/login/oidc/callback",
            ),
        ] {
            assert_eq!(
                redirect_uri(&start(host, proto)).as_deref(),
                Some(expected),
                "{host}"
            );
        }
        // A Host header that is not a plain name or address starts nothing.
        for host in ["evil.example/x", "a b", "user@evil.example", "x?y=1"] {
            let reply = start(host, None);
            assert_eq!(
                reply.headers()[hyper::header::LOCATION],
                "/?sso=failed#/login",
                "{host}"
            );
        }
        // An override from the configuration wins, for a proxy that hides the real address.
        config.redirect_url = "https://dns.example/api/login/oidc/callback".into();
        *f.host.oidc.lock().unwrap() = Some(config);
        assert_eq!(
            redirect_uri(&start("192.168.1.2:8080", None)).as_deref(),
            Some("https://dns.example/api/login/oidc/callback")
        );
    }

    #[test]
    fn login_is_generic_gated_and_throttled() {
        let f = fixture();
        let wrong = |f: &Fixture, who: &str| {
            body(call(
                f,
                Method::POST,
                "/api/login",
                None,
                &json!({"username": who, "password": "wrong password!"}).to_string(),
                "127.0.0.1",
            ))
        };
        let (status, json) = wrong(&f, "admin");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "Incorrect username or password.");
        assert_eq!(
            wrong(&f, "nobody").1["error"],
            "Incorrect username or password."
        );
        for _ in 0..3 {
            wrong(&f, "admin");
        }
        // Fifth failure for the name locks it, even with the right password.
        wrong(&f, "admin");
        let (status, json) = body(call(
            &f,
            Method::POST,
            "/api/login",
            None,
            &json!({"username": "admin", "password": "correct horse battery"}).to_string(),
            "127.0.0.1",
        ));
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{json}");
        // Another name from the same address still works.
        sign_in(&f, "anna", "anna passphrase 123");
        // Login without a JSON content type is refused.
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("lumen.test"));
        let reply = f.console.handle(&Request {
            method: Method::POST,
            path: "/api/login".into(),
            query: String::new(),
            headers,
            body: Bytes::from("{}"),
            peer: peer("127.0.0.1"),
            tls: false,
        });
        assert_eq!(reply.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn mutations_need_csrf_and_same_origin_and_roles() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        assert_eq!(
            call(&f, Method::GET, "/api/status", None, "", "127.0.0.1").status(),
            StatusCode::UNAUTHORIZED
        );
        let (status, json) = body(call(
            &f,
            Method::GET,
            "/api/status",
            Some((&cookie, &csrf)),
            "",
            "127.0.0.1",
        ));
        assert_eq!(
            (status, json["counters"]["queries"].as_u64()),
            (StatusCode::OK, Some(7))
        );
        assert_eq!(json["filter"]["lists"][0]["rules"], 3);
        // No CSRF header.
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/reload",
                Some((&cookie, "wrong")),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/reload",
                Some((&cookie, &csrf)),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::ACCEPTED
        );
        // Cross-origin POST is refused even with a valid token.
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(HOST, HeaderValue::from_static("lumen.test"));
        headers.insert(ORIGIN, HeaderValue::from_static("http://evil.example"));
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{COOKIE_NAME}={cookie}")).unwrap(),
        );
        headers.insert("x-lumen-csrf", HeaderValue::from_str(&csrf).unwrap());
        let reply = f.console.handle(&Request {
            method: Method::POST,
            path: "/api/reload".into(),
            query: String::new(),
            headers,
            body: Bytes::new(),
            peer: peer("127.0.0.1"),
            tls: false,
        });
        assert_eq!(reply.status(), StatusCode::FORBIDDEN);
        // A standard user reads status and devices but nothing else.
        let (user_cookie, user_csrf) = sign_in(&f, "anna", "anna passphrase 123");
        let user = |m: Method, p: &str| {
            call(
                &f,
                m,
                p,
                Some((&user_cookie, &user_csrf)),
                "{}",
                "127.0.0.1",
            )
            .status()
        };
        assert_eq!(user(Method::GET, "/api/status"), StatusCode::OK);
        assert_eq!(user(Method::GET, "/api/devices"), StatusCode::OK);
        for path in ["/api/users", "/api/config", "/api/audit", "/api/providers"] {
            assert_eq!(user(Method::GET, path), StatusCode::FORBIDDEN, "{path}");
        }
        for (method, path) in [
            (Method::POST, "/api/reload"),
            (Method::PUT, "/api/devices"),
            (Method::PUT, "/api/config"),
            (Method::POST, "/api/shutdown"),
            (Method::POST, "/api/filter/refresh"),
        ] {
            assert_eq!(user(method, path), StatusCode::FORBIDDEN, "{path}");
        }
        // Sign out ends the session.
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/logout",
                Some((&cookie, &csrf)),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &f,
                Method::GET,
                "/api/me",
                Some((&cookie, &csrf)),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn setup_forward_choice_survives_the_stock_recursive_only_settings() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.db");
        let mut store = Store::open(&state).unwrap();
        // The shipped config turns zone warm-up on, which forward mode rejects.
        store
            .set_config(
                "schema_version = 1\n[resolver]\nmode = \"recursive\"\n[resolver.warm]\nenabled = true\nzones = [\"com\"]\n",
                directory.path(),
            )
            .unwrap();
        let host = Arc::new(Stub::default());
        let console = Console::new(state.clone(), host.clone(), "test");
        let f = Fixture {
            console,
            host,
            _directory: directory,
            state,
        };
        let (status, json) = body(call(
            &f,
            Method::POST,
            "/api/setup",
            None,
            &json!({"username": "owner", "password": "correct horse battery", "mode": "forward"})
                .to_string(),
            "127.0.0.1",
        ));
        assert_eq!(status, StatusCode::OK, "{json}");
        let staged = Store::open(&f.state).unwrap().staged_config().unwrap();
        let source = staged.expect("forward config staged").source;
        assert!(source.contains("mode = \"forward\""), "{source}");
        assert!(source.contains("quad9-unfiltered"), "{source}");
        assert!(!source.contains("enabled = true"), "{source}");
    }

    #[test]
    fn setup_can_turn_on_external_login_and_checks_it_before_making_the_account() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.db");
        Store::open(&state)
            .unwrap()
            .set_config(
                "schema_version = 1\n[web]\nhttp = ['127.0.0.1:8080']\n",
                directory.path(),
            )
            .unwrap();
        let host = Arc::new(Stub::default());
        let f = Fixture {
            console: Console::new(state.clone(), host.clone(), "test"),
            host,
            _directory: directory,
            state,
        };
        let setup = |oidc: Value| {
            body(call(
                &f,
                Method::POST,
                "/api/setup",
                None,
                &json!({"username": "owner", "password": "correct horse battery", "oidc": oidc})
                    .to_string(),
                "127.0.0.1",
            ))
        };
        // A bad provider setting is refused and no account is created, so it can be fixed.
        for bad in [
            json!({"issuer": "http://remote.example/", "client_id": "lumen", "redirect_url": "https://dns.example/api/login/oidc/callback"}),
            json!({"issuer": "https://id.example/", "client_id": "", "redirect_url": "https://dns.example/api/login/oidc/callback"}),
            json!({"issuer": "https://id.example/", "client_id": "lumen", "redirect_url": "https://dns.example/elsewhere"}),
            json!({"issuer": "https://id.example/", "client_id": "lumen", "redirect_url": "https://dns.example/api/login/oidc/callback", "sync_role": true}),
        ] {
            let (status, json) = setup(bad.clone());
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad} {json}");
            assert_eq!(Store::open(&f.state).unwrap().user_count().unwrap(), 0);
        }
        let (status, json) = setup(json!({
            "label": "Authentik", "issuer": "https://id.example/application/o/lumen/",
            "client_id": "lumen", "redirect_url": "https://dns.example/api/login/oidc/callback",
            "admin_group": "lumen-admins", "sync_role": true, "single_logout": true
        }));
        assert_eq!(status, StatusCode::OK, "{json}");
        let staged = Store::open(&f.state).unwrap().staged_config().unwrap();
        let source = staged.expect("external login staged").source;
        let config = Config::parse(&source, Path::new("/etc/lumen")).unwrap();
        config.validate().unwrap();
        let oidc = config.web.oidc;
        assert!(oidc.enabled && oidc.sync_role && oidc.single_logout);
        assert_eq!(oidc.label, "Authentik");
        assert_eq!(oidc.admin_group.as_deref(), Some("lumen-admins"));
        assert_eq!(config.web.http.len(), 1, "other web settings are kept");
    }

    #[test]
    fn setup_runs_once_and_needs_the_code_off_machine() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.db");
        let mut store = Store::open(&state).unwrap();
        store.set_config(CONFIG, directory.path()).unwrap();
        let host = Arc::new(Stub::default());
        let f = Fixture {
            console: Console::new(state.clone(), host.clone(), "test"),
            host,
            _directory: directory,
            state,
        };
        let code = f.console.prepare().unwrap().expect("setup code");
        assert_eq!(code.len(), 9);
        assert_eq!(
            f.console.prepare().unwrap().as_deref(),
            Some(code.as_str()),
            "code is stable until setup"
        );
        let (_, state_json) = body(call(&f, Method::GET, "/api/state", None, "", "192.168.1.9"));
        assert_eq!(
            (
                state_json["setup_needed"].clone(),
                state_json["setup_code_required"].clone()
            ),
            (json!(true), json!(true))
        );
        let attempt = |from: &str, code: &str, pw: &str| {
            body(call(
                &f,
                Method::POST,
                "/api/setup",
                None,
                &json!({"code": code, "username": "Owner", "password": pw, "language": "it"})
                    .to_string(),
                from,
            ))
        };
        let check = |from: &str, code: &str| {
            body(call(
                &f,
                Method::POST,
                "/api/setup/code",
                None,
                &json!({ "code": code }).to_string(),
                from,
            ))
            .0
        };
        assert_eq!(check("192.168.1.9", "WRONG-CODE"), StatusCode::FORBIDDEN);
        assert_eq!(check("192.168.1.9", &code.to_lowercase()), StatusCode::OK);
        assert_eq!(
            check("127.0.0.1", ""),
            StatusCode::OK,
            "loopback needs no code"
        );
        assert_eq!(
            attempt("192.168.1.9", "WRONG-CODE", "correct horse battery").0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            attempt("127.0.0.1", "", "short").0,
            StatusCode::BAD_REQUEST,
            "policy applies on loopback too"
        );
        let (status, json) = attempt("192.168.1.9", &code.to_lowercase(), "correct horse battery");
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["user"]["name"], "owner");
        assert_eq!(json["user"]["role"], "admin");
        assert_eq!(
            Store::open(&f.state)
                .unwrap()
                .setting("language")
                .unwrap()
                .as_deref(),
            Some("it"),
            "the language chosen in the wizard is kept"
        );
        assert_eq!(
            attempt("127.0.0.1", "", "another passphrase!").0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            check("127.0.0.1", ""),
            StatusCode::CONFLICT,
            "closed after setup"
        );
        assert!(f.console.prepare().unwrap().is_none());
        assert!(
            Store::open(&f.state)
                .unwrap()
                .setting("setup_code")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn several_providers_keep_their_rank_and_strategy_through_the_form() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let get = || {
            body(call(
                &f,
                Method::GET,
                "/api/config",
                session,
                "",
                "127.0.0.1",
            ))
            .1
        };
        let put = |config: &Value| {
            body(call(
                &f,
                Method::PUT,
                "/api/config",
                session,
                &json!({"config": config}).to_string(),
                "127.0.0.1",
            ))
        };
        let provider = |id: &str| {
            json!({"id": id, "protocol": "auto", "address_family": "any", "encryption": null,
                   "transport_priority": ["quic", "https", "tls"]})
        };
        let ids = [
            "quad9-unfiltered",
            "cloudflare-unfiltered",
            "dns4eu-unfiltered",
        ];
        let mut config = get()["config"].clone();
        assert!(
            config["resolver"]["strategy"].is_null(),
            "no strategy until chosen"
        );
        config["resolver"]["mode"] = json!("forward");
        config["resolver"]["strategy"] = json!("race");
        config["resolver"]["providers"] =
            json!(ids.iter().map(|id| provider(id)).collect::<Vec<_>>());
        let (status, staged) = put(&config);
        assert_eq!(status, StatusCode::ACCEPTED, "{staged}");
        let revision = staged["revision"].as_u64().unwrap();
        let mut store = Store::open(&f.state).unwrap();
        let source = store.staged_config().unwrap().unwrap().source;
        assert!(source.contains("strategy = \"race\""), "{source}");
        let positions: Vec<usize> = ids.iter().map(|id| source.find(id).expect(id)).collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "rank order is kept: {source}"
        );
        assert!(store.promote_staged_config(revision).unwrap());

        // Read back: rank and strategy survive, and the derived addresses stay hidden.
        let after = get()["config"].clone();
        assert_eq!(after["resolver"]["strategy"], "race");
        let back: Vec<&str> = after["resolver"]["providers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap())
            .collect();
        assert_eq!(back, ids);
        assert!(
            after["resolver"]["upstreams"]
                .as_array()
                .unwrap()
                .is_empty()
        );

        // A ninth provider, a repeat, and an unknown strategy are refused.
        let mut nine = after.clone();
        let all = [
            "ffmuc-unfiltered",
            "libredns-unfiltered",
            "dns-sb-unfiltered",
            "uncensoreddns-anycast",
            "google-public-dns",
        ];
        let mut list: Vec<Value> = ids
            .iter()
            .chain(all.iter())
            .map(|id| provider(id))
            .collect();
        nine["resolver"]["providers"] = json!(list.clone());
        assert_eq!(put(&nine).0, StatusCode::ACCEPTED, "eight are fine");
        list.push(provider("adguard-unfiltered"));
        nine["resolver"]["providers"] = json!(list);
        assert_eq!(put(&nine).0, StatusCode::BAD_REQUEST, "nine are not");
        let mut twice = after.clone();
        twice["resolver"]["providers"] = json!([provider(ids[0]), provider(ids[0])]);
        assert_eq!(put(&twice).0, StatusCode::BAD_REQUEST);
        let mut odd = after;
        odd["resolver"]["strategy"] = json!("random");
        assert_eq!(put(&odd).0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn config_round_trips_with_defaults_and_validation() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let (status, json) = body(call(
            &f,
            Method::GET,
            "/api/config",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(status, StatusCode::OK);
        let mut config = json["config"].clone();
        assert_eq!(
            config["resolver"]["cache_entries"], 4096,
            "daemon defaults are filled in"
        );
        assert_eq!(config["filtering"]["default_profile"], "standard");
        assert!(config["filtering"].get("devices").is_none());
        // Unchanged config previews as the compact original: no default noise.
        let (_, preview) = body(call(
            &f,
            Method::POST,
            "/api/config/preview",
            session,
            &json!({"config": config}).to_string(),
            "127.0.0.1",
        ));
        let toml = preview["toml"].as_str().unwrap();
        assert!(
            !toml.contains("cache_entries") && !toml.contains("[limits]"),
            "{toml}"
        );
        config["resolver"]["cache_entries"] = json!(8192);
        let (status, preview) = body(call(
            &f,
            Method::PUT,
            "/api/config",
            session,
            &json!({"config": config}).to_string(),
            "127.0.0.1",
        ));
        assert_eq!(status, StatusCode::ACCEPTED, "{preview}");
        let revision = preview["revision"].as_u64().unwrap();
        let mut store = Store::open(&f.state).unwrap();
        let staged = store.staged_config().unwrap().unwrap();
        assert_eq!(staged.revision, revision);
        assert!(staged.source.contains("cache_entries = 8192"));
        assert!(
            matches!(store.next_command().unwrap(), Some((_, Command::ConfigReload(r))) if r == revision)
        );
        assert!(store.promote_staged_config(revision).unwrap());
        // Out-of-range, unknown, and non-object input is refused without staging anything.
        config["resolver"]["cache_entries"] = json!(0);
        assert_eq!(
            call(
                &f,
                Method::PUT,
                "/api/config",
                session,
                &json!({"config": config}).to_string(),
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &f,
                Method::PUT,
                "/api/config",
                session,
                &json!({"config": {"bogus": 1}}).to_string(),
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &f,
                Method::PUT,
                "/api/config",
                session,
                &json!({"config": 5}).to_string(),
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(store.staged_config().unwrap().is_none());
        // Restore an earlier revision.
        let (_, history) = body(call(
            &f,
            Method::GET,
            "/api/config/history",
            session,
            "",
            "127.0.0.1",
        ));
        let first = history.as_array().unwrap().last().unwrap()["revision"]
            .as_u64()
            .unwrap();
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/config/restore",
                session,
                &json!({"revision": first}).to_string(),
                "127.0.0.1"
            )
            .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/config/restore",
                session,
                &json!({"revision": 9999}).to_string(),
                "127.0.0.1"
            )
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn devices_users_and_passwords() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let put = |payload: Value| {
            call(
                &f,
                Method::PUT,
                "/api/devices",
                session,
                &payload.to_string(),
                "127.0.0.1",
            )
            .status()
        };
        assert_eq!(
            put(json!({"id": "tv", "addresses": ["192.168.1.40"], "profile": "standard"})),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            put(json!({"id": "tv", "addresses": ["192.168.1.40"], "profile": "missing"})),
            StatusCode::BAD_REQUEST,
            "unknown profile"
        );
        assert_eq!(
            put(json!({"id": "tv2", "addresses": ["not-an-ip"], "profile": "standard"})),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            put(json!({"id": "tv3", "addresses": ["192.168.1.41"]})),
            StatusCode::BAD_REQUEST,
            "needs a profile or group"
        );
        let (_, devices) = body(call(
            &f,
            Method::GET,
            "/api/devices",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(devices.as_array().unwrap().len(), 1);
        assert_eq!(
            call(
                &f,
                Method::DELETE,
                "/api/devices/tv",
                session,
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            call(
                &f,
                Method::DELETE,
                "/api/devices/tv",
                session,
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::NOT_FOUND
        );
        // The last administrator and your own account are protected.
        assert_eq!(
            call(
                &f,
                Method::DELETE,
                "/api/users/admin",
                session,
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &f,
                Method::PATCH,
                "/api/users/admin",
                session,
                r#"{"role":"user"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &f,
                Method::PATCH,
                "/api/users/anna",
                session,
                r#"{"role":"admin"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &f,
                Method::PATCH,
                "/api/users/anna",
                session,
                r#"{"role":"user"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::OK
        );
        // Weak and duplicate accounts are refused.
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/users",
                session,
                r#"{"name":"bob","role":"user","password":"short"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/users",
                session,
                r#"{"name":"anna","role":"user","password":"another long passphrase"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        // Resetting a password ends that account's sessions and forces a change.
        let (user_cookie, user_csrf) = sign_in(&f, "anna", "anna passphrase 123");
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/users/anna/password",
                session,
                r#"{"password":"a brand new passphrase"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &f,
                Method::GET,
                "/api/me",
                Some((&user_cookie, &user_csrf)),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let (token, csrf) = sign_in(&f, "anna", "a brand new passphrase");
        let (_, me) = body(call(
            &f,
            Method::GET,
            "/api/me",
            Some((&token, &csrf)),
            "",
            "127.0.0.1",
        ));
        assert_eq!(me["user"]["must_change"], true);
        // Changing your own password needs the current one and ends other sessions.
        let change = |current: &str, new: &str| {
            call(
                &f,
                Method::POST,
                "/api/me/password",
                Some((&token, &csrf)),
                &json!({"current": current, "password": new}).to_string(),
                "127.0.0.1",
            )
        };
        assert_eq!(
            change("wrong current", "yet another passphrase").status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            change("a brand new passphrase", "short").status(),
            StatusCode::BAD_REQUEST
        );
        let reply = change("a brand new passphrase", "yet another passphrase");
        assert_eq!(reply.status(), StatusCode::OK);
        assert!(
            reply.headers().get(SET_COOKIE).is_some(),
            "a fresh session replaces the old one"
        );
        assert_eq!(
            call(
                &f,
                Method::GET,
                "/api/me",
                Some((&token, &csrf)),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::UNAUTHORIZED
        );
        // Every one of these actions is in the audit log, without secrets.
        let (_, audit) = body(call(
            &f,
            Method::GET,
            "/api/audit",
            session,
            "",
            "127.0.0.1",
        ));
        let text = audit.to_string();
        assert!(
            text.contains("device.set")
                && text.contains("user.reset-password")
                && text.contains("user.password")
        );
        assert!(!text.contains("passphrase") && !text.contains("csrf"));
    }

    #[test]
    fn overview_reload_interval_is_saved_for_everyone() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let get = || {
            body(call(
                &f,
                Method::GET,
                "/api/settings",
                session,
                "",
                "127.0.0.1",
            ))
            .1
        };
        assert_eq!(get()["overview_reload_secs"], 10);
        let put = |payload: &str| {
            call(
                &f,
                Method::PUT,
                "/api/settings",
                session,
                payload,
                "127.0.0.1",
            )
        };
        assert_eq!(
            put(r#"{"overview_reload_secs":3}"#).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            put(r#"{"overview_reload_secs":"5"}"#).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            body(put(r#"{"overview_reload_secs":30}"#)).1["overview_reload_secs"],
            30
        );
        assert_eq!(get()["overview_reload_secs"], 30);
        assert_eq!(
            body(put(r#"{"overview_reload_secs":0}"#)).1["overview_reload_secs"],
            0
        );
        assert_eq!(get()["overview_reload_secs"], 0);
    }

    #[test]
    fn modules_are_off_until_an_administrator_turns_them_on() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let get = || {
            body(call(
                &f,
                Method::GET,
                "/api/modules",
                session,
                "",
                "127.0.0.1",
            ))
            .1
        };
        assert_eq!(get()["enabled"], json!([]));
        assert_eq!(get()["available"], json!(["traffic-map"]));
        let put = |payload: &str| {
            call(
                &f,
                Method::PUT,
                "/api/modules",
                session,
                payload,
                "127.0.0.1",
            )
        };
        assert_eq!(
            put(r#"{"id":"nope","enabled":true}"#).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            put(r#"{"id":"traffic-map"}"#).status(),
            StatusCode::BAD_REQUEST
        );
        let (_, on) = body(put(r#"{"id":"traffic-map","enabled":true}"#));
        assert_eq!(on["enabled"], json!(["traffic-map"]));
        assert_eq!(get()["enabled"], json!(["traffic-map"]));
        let (_, off) = body(put(r#"{"id":"traffic-map","enabled":false}"#));
        assert_eq!(off["enabled"], json!([]));
    }

    #[test]
    fn explain_providers_and_history_settings() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let (_, json) = body(call(
            &f,
            Method::POST,
            "/api/explain",
            session,
            r#"{"domain":"ads.example","client":"192.168.1.5"}"#,
            "127.0.0.1",
        ));
        assert_eq!(json["blocked"], true);
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/explain",
                session,
                r#"{"domain":"","client":"192.168.1.5"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/explain",
                session,
                r#"{"domain":"a.example","client":"nope"}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        let (_, providers) = body(call(
            &f,
            Method::GET,
            "/api/providers",
            session,
            "",
            "127.0.0.1",
        ));
        assert!(
            providers
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == "quad9-unfiltered")
        );
        assert_eq!(
            call(
                &f,
                Method::PUT,
                "/api/settings",
                session,
                r#"{"session_idle_minutes":2}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::BAD_REQUEST
        );
        let (_, settings) = body(call(
            &f,
            Method::PUT,
            "/api/settings",
            session,
            r#"{"session_idle_minutes":60}"#,
            "127.0.0.1",
        ));
        assert_eq!(settings["session_idle_minutes"], 60);
        assert!(
            settings["language"].is_null(),
            "no default until an administrator chooses"
        );
        for bad in [
            r"{}",
            r#"{"language":"xx"}"#,
            r#"{"language":7}"#,
            r#"{"language":"de","session_idle_minutes":1}"#,
        ] {
            assert_eq!(
                call(&f, Method::PUT, "/api/settings", session, bad, "127.0.0.1").status(),
                StatusCode::BAD_REQUEST,
                "{bad}"
            );
        }
        let (_, german) = body(call(
            &f,
            Method::PUT,
            "/api/settings",
            session,
            r#"{"language":"de"}"#,
            "127.0.0.1",
        ));
        assert_eq!(
            (
                german["language"].clone(),
                german["session_idle_minutes"].clone()
            ),
            ("de".into(), 60.into())
        );
        // Going back to automatic removes the default again.
        let (_, automatic) = body(call(
            &f,
            Method::PUT,
            "/api/settings",
            session,
            r#"{"language":null}"#,
            "127.0.0.1",
        ));
        assert!(automatic["language"].is_null());
        call(
            &f,
            Method::PUT,
            "/api/settings",
            session,
            r#"{"language":"de"}"#,
            "127.0.0.1",
        );
        // The default language is public, so the sign-in page can use it.
        let (_, public) = body(call(&f, Method::GET, "/api/state", None, "", "127.0.0.1"));
        assert_eq!(public["language"], "de");
        assert_eq!(public["languages"], json!(["en", "de", "it", "es", "nl"]));
        assert_eq!(
            call(
                &f,
                Method::PUT,
                "/api/history",
                session,
                r#"{"enabled":true}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            Store::open(&f.state)
                .unwrap()
                .setting("history_mode")
                .unwrap()
                .as_deref(),
            Some("memory")
        );
        assert_eq!(f.host.history_settings().mode, HistoryMode::Memory);
        assert_eq!(
            call(&f, Method::GET, "/api/nope", session, "", "127.0.0.1").status(),
            StatusCode::NOT_FOUND
        );
    }

    fn record(t: u64, domain: &str, blocked: bool, full: bool) -> QueryRecord {
        QueryRecord {
            unix_ms: t,
            domain: domain.into(),
            qtype: "A".into(),
            client: full.then(|| "192.168.1.5".parse().unwrap()),
            device: full.then(|| "tablet".to_owned()),
            blocked,
            rcode: if blocked { "NXDOMAIN" } else { "NOERROR" },
            micros: 2500,
        }
    }

    #[test]
    fn saved_history_modes_search_paging_retention_and_clearing() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let get = |path: &str| body(call(&f, Method::GET, path, session, "", "127.0.0.1")).1;
        let put = |payload: &str| {
            call(
                &f,
                Method::PUT,
                "/api/history",
                session,
                payload,
                "127.0.0.1",
            )
        };

        // Off by default: nothing is recorded or listed, and the defaults are privacy-first.
        let off = get("/api/history");
        assert_eq!(
            (off["enabled"].clone(), off["mode"].clone()),
            (false.into(), "off".into())
        );
        assert_eq!(off["retention_days"], 7);
        assert_eq!(off["items"].as_array().unwrap().len(), 0);

        // Bad input is refused before anything is stored.
        for bad in [
            r#"{"mode":"forever"}"#,
            r#"{"mode":"saved","detail":"everything"}"#,
            r#"{"mode":"saved","retention_days":0}"#,
            r#"{"mode":"saved","retention_days":91}"#,
            r#"{"detail":"anonymous"}"#,
            "not json",
        ] {
            assert_eq!(put(bad).status(), StatusCode::BAD_REQUEST, "{bad}");
        }
        assert_eq!(f.host.history_settings().mode, HistoryMode::Off);

        // Saved + anonymous with a 3 day retention.
        assert_eq!(
            put(r#"{"mode":"saved","detail":"anonymous","retention_days":3}"#).status(),
            StatusCode::OK
        );
        assert_eq!(
            f.host.history_settings(),
            HistorySettings {
                mode: HistoryMode::Saved,
                detail: HistoryDetail::Anonymous
            }
        );
        let now_ms = now() * 1000;
        f.host.unsaved.lock().unwrap().extend([
            record(now_ms - 10 * 86_400_000, "ancient.example", false, false),
            record(now_ms - 2_000, "news.example", false, false),
            record(now_ms - 1_000, "ads.example", true, false),
            record(now_ms, "Shop.example", false, true),
        ]);
        // The writer step saves the queue once, and the retention prune drops the old row.
        f.console.flush_history(true).unwrap();
        assert!(f.host.unsaved.lock().unwrap().is_empty());
        f.console.flush_history(true).unwrap();
        let listed = get("/api/history?limit=10");
        assert_eq!(listed["saved"]["rows"], 3);
        let items = listed["items"].as_array().unwrap();
        assert_eq!(items[0]["domain"], "Shop.example");
        assert_eq!(items[0]["device"], "tablet");
        assert!(
            items[1]["client"].is_null(),
            "anonymous rows keep no client"
        );

        // Filter, search (URL-decoded) and paging.
        let blocked = get("/api/history?filter=blocked");
        assert_eq!(blocked["items"].as_array().unwrap().len(), 1);
        let found = get("/api/history?search=SHOP%2Eexample");
        assert_eq!(found["items"][0]["domain"], "Shop.example");
        assert_eq!(
            get("/api/history?search=nothing%20here")["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let page = get("/api/history?limit=2");
        assert_eq!(page["items"].as_array().unwrap().len(), 2);
        let next = get(&format!(
            "/api/history?limit=2&before={}",
            page["next_before"]
        ));
        assert_eq!(next["items"].as_array().unwrap().len(), 1);
        assert!(next["next_before"].is_null());

        // Turning history off stops recording but keeps what is saved, which can still be seen.
        assert_eq!(put(r#"{"mode":"off"}"#).status(), StatusCode::OK);
        assert_eq!(f.host.history_settings().mode, HistoryMode::Off);
        let after_off = get("/api/history");
        assert_eq!(
            (
                after_off["enabled"].clone(),
                after_off["saved"]["rows"].clone()
            ),
            (false.into(), 3.into())
        );
        assert_eq!(after_off["detail"], "anonymous");
        assert_eq!(after_off["retention_days"], 3);

        // Only administrators change or delete history; nothing is deleted by a refusal.
        let (user_cookie, user_csrf) = sign_in(&f, "anna", "anna passphrase 123");
        let user = Some((user_cookie.as_str(), user_csrf.as_str()));
        for method in [Method::PUT, Method::DELETE] {
            assert_eq!(
                call(
                    &f,
                    method,
                    "/api/history",
                    user,
                    r#"{"mode":"saved"}"#,
                    "127.0.0.1"
                )
                .status(),
                StatusCode::FORBIDDEN
            );
        }
        assert_eq!(get("/api/history")["saved"]["rows"], 3);

        // Clearing deletes saved rows and anything still waiting to be saved. It is audited.
        f.host
            .unsaved
            .lock()
            .unwrap()
            .push(record(now_ms, "late.example", false, false));
        let cleared = body(call(
            &f,
            Method::DELETE,
            "/api/history",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(
            (cleared.0, cleared.1["removed"].clone()),
            (StatusCode::OK, 3.into())
        );
        assert!(f.host.unsaved.lock().unwrap().is_empty());
        assert_eq!(get("/api/history")["saved"]["rows"], 0);
        let audit = Store::open(&f.state).unwrap().audit_events(50).unwrap();
        for action in ["history.update", "history.clear"] {
            assert!(audit.iter().any(|e| e.action == action), "{action}");
        }
        assert!(
            audit.iter().all(|e| !e.target.contains("example")),
            "no domains in the audit log"
        );
    }

    #[test]
    fn memory_history_filters_in_memory_and_cli_setting_changes_are_picked_up() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let now_ms = now() * 1000;
        f.host.recent.lock().unwrap().extend([
            record(now_ms, "ads.example", true, true),
            record(now_ms - 1, "news.example", false, true),
        ]);
        // The older on/off flag keeps working: it means memory mode.
        Store::open(&f.state)
            .unwrap()
            .set_setting("history", "1")
            .unwrap();
        f.console.prepare().unwrap();
        assert_eq!(f.host.history_settings().mode, HistoryMode::Memory);
        let (_, listed) = body(call(
            &f,
            Method::GET,
            "/api/history?filter=blocked",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(listed["mode"], "memory");
        assert_eq!(listed["items"].as_array().unwrap().len(), 1);
        assert_eq!(listed["items"][0]["device"], "tablet");
        let (_, searched) = body(call(
            &f,
            Method::GET,
            "/api/history?search=tablet",
            session,
            "",
            "127.0.0.1",
        ));
        assert_eq!(searched["items"].as_array().unwrap().len(), 2);

        // `lumenctl history set` writes the settings; the writer step applies them to the daemon.
        let store = Store::open(&f.state).unwrap();
        store.set_setting("history_mode", "saved").unwrap();
        store.set_setting("history_detail", "anonymous").unwrap();
        drop(store);
        f.console.flush_history(false).unwrap();
        assert_eq!(
            f.host.history_settings(),
            HistorySettings {
                mode: HistoryMode::Saved,
                detail: HistoryDetail::Anonymous
            }
        );
        // A new mode wins over the older flag even after it is switched off again.
        assert_eq!(
            call(
                &f,
                Method::PUT,
                "/api/history",
                session,
                r#"{"enabled":false}"#,
                "127.0.0.1"
            )
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            Store::open(&f.state).unwrap().setting("history").unwrap(),
            None
        );
        f.console.prepare().unwrap();
        assert_eq!(f.host.history_settings().mode, HistoryMode::Off);
    }

    #[test]
    fn cancelling_needs_an_administrator_and_does_nothing_when_idle() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let admin = Some((cookie.as_str(), csrf.as_str()));
        let (status, idle) = body(call(
            &f,
            Method::POST,
            "/api/activity/cancel",
            admin,
            "{}",
            "127.0.0.1",
        ));
        assert_eq!(
            (status, idle["cancelled"].clone()),
            (StatusCode::OK, false.into())
        );
        let (_, state) = body(call(&f, Method::GET, "/api/status", admin, "", "127.0.0.1"));
        assert_eq!(state["activity"]["cancellable"], false);
        let (user_cookie, user_csrf) = sign_in(&f, "anna", "anna passphrase 123");
        let user = Some((user_cookie.as_str(), user_csrf.as_str()));
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/activity/cancel",
                user,
                "{}",
                "127.0.0.1"
            )
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/activity/cancel",
                None,
                "{}",
                "127.0.0.1"
            )
            .status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn two_step_sign_in_enrolment_replay_recovery_and_reset() {
        let f = fixture();
        let (cookie, csrf) = sign_in(&f, "admin", "correct horse battery");
        let session = Some((cookie.as_str(), csrf.as_str()));
        let post = |path: &str, payload: Value| {
            body(call(
                &f,
                Method::POST,
                path,
                session,
                &payload.to_string(),
                "127.0.0.1",
            ))
        };
        // Wrong password cannot start enrolment; right password returns a secret and URI.
        assert_eq!(
            post("/api/me/2fa/setup", json!({"password": "nope nope nope"})).0,
            StatusCode::FORBIDDEN
        );
        let (status, setup) = post(
            "/api/me/2fa/setup",
            json!({"password": "correct horse battery"}),
        );
        assert_eq!(status, StatusCode::OK);
        let secret = setup["secret"].as_str().unwrap().to_owned();
        assert!(
            setup["uri"]
                .as_str()
                .unwrap()
                .contains(&format!("secret={secret}"))
        );
        // Enabling needs a valid current code.
        assert_eq!(
            post("/api/me/2fa/enable", json!({"code": "000000"})).0,
            StatusCode::BAD_REQUEST
        );
        let code =
            |offset: u64| totp::code_for_step(&secret, totp::step_at(now()) + offset).unwrap();
        let (status, enabled) = post("/api/me/2fa/enable", json!({"code": code(0)}));
        assert_eq!(status, StatusCode::OK, "{enabled}");
        let recovery: Vec<String> = enabled["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(recovery.len(), 10);
        assert_eq!(
            post(
                "/api/me/2fa/setup",
                json!({"password": "correct horse battery"})
            )
            .0,
            StatusCode::CONFLICT
        );
        // Password alone no longer signs in: a challenge is returned and no cookie is set.
        let reply = call(
            &f,
            Method::POST,
            "/api/login",
            None,
            &json!({"username": "admin", "password": "correct horse battery"}).to_string(),
            "127.0.0.1",
        );
        assert!(reply.headers().get(SET_COOKIE).is_none());
        let (_, step_one) = body(reply);
        assert_eq!(step_one["needs_2fa"], true);
        let challenge = step_one["challenge"].as_str().unwrap().to_owned();
        let second = |challenge: &str, code: &str, from: &str| {
            call(
                &f,
                Method::POST,
                "/api/login/2fa",
                None,
                &json!({"challenge": challenge, "code": code}).to_string(),
                from,
            )
        };
        // The code used during enrolment cannot be replayed, a wrong one is refused,
        // and a challenge cannot be used from another address.
        assert_eq!(
            second(&challenge, &code(0), "127.0.0.1").status(),
            StatusCode::UNAUTHORIZED,
            "enrolment code is spent"
        );
        assert_eq!(
            second(&challenge, "123456", "127.0.0.1").status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            second(&challenge, &code(1), "10.9.9.9").status(),
            StatusCode::UNAUTHORIZED,
            "wrong address"
        );
        let (_, again) = body(call(
            &f,
            Method::POST,
            "/api/login",
            None,
            &json!({"username": "admin", "password": "correct horse battery"}).to_string(),
            "127.0.0.1",
        ));
        let challenge = again["challenge"].as_str().unwrap().to_owned();
        let ok = second(&challenge, &code(1), "127.0.0.1");
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(ok.headers().get(SET_COOKIE).is_some());
        assert_eq!(
            second(&challenge, &code(1), "127.0.0.1").status(),
            StatusCode::UNAUTHORIZED,
            "challenge is single use"
        );
        // A recovery code works exactly once.
        let (_, third) = body(call(
            &f,
            Method::POST,
            "/api/login",
            None,
            &json!({"username": "admin", "password": "correct horse battery"}).to_string(),
            "127.0.0.1",
        ));
        let challenge = third["challenge"].as_str().unwrap().to_owned();
        assert_eq!(
            second(&challenge, &recovery[0].to_uppercase(), "127.0.0.1").status(),
            StatusCode::OK
        );
        let (_, fourth) = body(call(
            &f,
            Method::POST,
            "/api/login",
            None,
            &json!({"username": "admin", "password": "correct horse battery"}).to_string(),
            "127.0.0.1",
        ));
        assert_eq!(
            second(
                fourth["challenge"].as_str().unwrap(),
                &recovery[0],
                "127.0.0.1"
            )
            .status(),
            StatusCode::UNAUTHORIZED,
            "recovery code is spent"
        );
        // Disabling needs password and a code.
        assert_eq!(
            post(
                "/api/me/2fa/disable",
                json!({"password": "correct horse battery", "code": "111111"})
            )
            .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                "/api/me/2fa/disable",
                json!({"password": "correct horse battery", "code": recovery[1]})
            )
            .0,
            StatusCode::OK
        );
        let (_, plain) = body(call(
            &f,
            Method::POST,
            "/api/login",
            None,
            &json!({"username": "admin", "password": "correct horse battery"}).to_string(),
            "127.0.0.1",
        ));
        assert!(plain.get("needs_2fa").is_none() && plain["user"]["totp_enabled"] == false);
        // An administrator can clear a lost device.
        let (token, user_csrf) = sign_in(&f, "anna", "anna passphrase 123");
        let store = Store::open(&f.state).unwrap();
        store.set_totp_pending("anna", &secret).unwrap();
        store.enable_totp("anna", 1, &[]).unwrap();
        assert!(
            store
                .user_with_record("anna")
                .unwrap()
                .unwrap()
                .0
                .totp_enabled
        );
        assert_eq!(
            call(
                &f,
                Method::POST,
                "/api/users/anna/2fa/reset",
                session,
                "{}",
                "127.0.0.1"
            )
            .status(),
            StatusCode::OK
        );
        assert!(
            !store
                .user_with_record("anna")
                .unwrap()
                .unwrap()
                .0
                .totp_enabled
        );
        assert_eq!(
            call(
                &f,
                Method::GET,
                "/api/me",
                Some((&token, &user_csrf)),
                "",
                "127.0.0.1"
            )
            .status(),
            StatusCode::UNAUTHORIZED,
            "reset ends their sessions"
        );
        // Audit never contains codes or secrets.
        let (_, audit) = body(call(
            &f,
            Method::GET,
            "/api/audit?limit=100",
            session,
            "",
            "127.0.0.1",
        ));
        let text = audit.to_string();
        assert!(
            text.contains("user.2fa-enable")
                && text.contains("user.2fa-disable")
                && text.contains("user.2fa-reset")
        );
        assert!(!text.contains(&secret) && !text.contains(&recovery[0]));
    }
}

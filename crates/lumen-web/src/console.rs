// SPDX-License-Identifier: Apache-2.0
//! Session-authenticated JSON API behind the embedded console. Accounts, sessions,
//! settings and control all live in the managed `SQLite` state; DNS data comes from
//! the daemon through [`Host`].
#![allow(clippy::unused_self)] // Handlers live on `Console` so each route reads as one method.

use crate::host::{Counters, Host};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    HeaderMap, Method, Response, StatusCode,
    header::{CONTENT_TYPE, COOKIE, HOST, HeaderValue, ORIGIN, SET_COOKIE},
};
use lumen_config::{Config, providers::Catalog};
use lumen_filter::config::Device;
use lumen_store::{Command, Role, Session, Store, password, totp};
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
const MAX_SESSION_SECS: u64 = 12 * 3600;
const DEFAULT_IDLE_MINUTES: u64 = 30;
const SERIES_POINTS: usize = 60;
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
        }
    }

    /// Restore saved settings into the daemon and, on first run, create the setup code.
    ///
    /// # Errors
    /// Returns an error when the state database cannot be used.
    pub fn prepare(&self) -> Result<Option<String>, String> {
        let store = Store::open(&self.state)?;
        self.host
            .set_history(store.setting("history")?.as_deref() == Some("1"));
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
            ("POST", ["login"]) => return self.login(&mut store, request),
            ("POST", ["login", "2fa"]) => return self.login_second_step(&mut store, request),
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
            ("POST", ["me", "2fa", "setup"]) => return self.totp_setup(&mut store, &ctx),
            ("POST", ["me", "2fa", "enable"]) => return self.totp_enable(&mut store, &ctx),
            ("POST", ["me", "2fa", "disable"]) => return self.totp_disable(&mut store, &ctx),
            ("GET", ["status"]) => return self.status(&store),
            ("GET", ["series"]) => return self.series_json(),
            ("GET", ["devices"]) => return devices_json(&store),
            ("GET", ["history"]) => return self.history(request),
            ("GET", ["settings"]) => return settings_json(&store),
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
            ("GET", ["audit"]) => audit_json(&store, &request.query),
            ("PUT", ["settings"]) => self.put_settings(&mut store, &ctx),
            ("PUT", ["history"]) => self.put_history(&mut store, &ctx),
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
                "user": signed_in,
            }),
        )
    }

    fn setup(&self, store: &mut Store, request: &Request) -> Reply {
        if !json_content(&request.headers) {
            return error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "use application/json");
        }
        let Ok(body) = serde_json::from_slice::<Value>(&request.body) else {
            return bad("invalid JSON");
        };
        let key = vec![format!("setup:{}", request.peer.ip())];
        if let Some(wait) = self.throttle.lock().expect("throttle").locked(&key) {
            return error(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("too many attempts, wait {wait} s"),
            );
        }
        if store.user_count().unwrap_or(1) != 0 {
            return error(StatusCode::CONFLICT, "setup is already complete");
        }
        if !request.peer.ip().to_canonical().is_loopback() {
            let expected = store
                .setting("setup_code")
                .ok()
                .flatten()
                .unwrap_or_default();
            let given = text(&body, "code").unwrap_or("").trim().to_uppercase();
            if expected.is_empty() || !same(&given, &expected) {
                self.throttle.lock().expect("throttle").fail(&key);
                return error(
                    StatusCode::FORBIDDEN,
                    "wrong setup code. It is printed in the daemon log when Lumen starts",
                );
            }
        }
        let name = text(&body, "username").unwrap_or("").trim().to_lowercase();
        let pw = text(&body, "password").unwrap_or("");
        if let Err(message) = password::check_policy(pw, &name) {
            return bad(&message);
        }
        let Ok(record) = password::hash(pw) else {
            return unavailable();
        };
        let user = match store.create_first_admin(&name, &record) {
            Ok(user) => user,
            Err(message) => return bad(&message),
        };
        // Optional first-run choices. Failures here never undo the account.
        if let Err(message) = self.apply_setup_choices(store, &body, &name) {
            let _ = message;
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
        actor: &str,
    ) -> Result<(), String> {
        let mode = text(body, "mode");
        let networks = body.get("allow_clients").and_then(Value::as_array);
        if mode.is_none() && networks.is_none() {
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

    fn logout(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let _ = store.delete_session(ctx.token_hash);
        Self::actor(store, ctx, "session.end", "console");
        let mut response = reply(StatusCode::OK, &json!({ "ok": true }));
        let secure = if ctx.request.tls { "; Secure" } else { "" };
        if let Ok(value) = HeaderValue::from_str(&format!(
            "{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}"
        )) {
            response.headers_mut().insert(SET_COOKIE, value);
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
                "history_enabled": self.host.history_enabled(),
                "rss_bytes": rss_bytes(),
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
    fn history(&self, request: &Request) -> Reply {
        if !self.host.history_enabled() {
            return reply(StatusCode::OK, &json!({ "enabled": false, "items": [] }));
        }
        let limit = query_param(&request.query, "limit")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(200)
            .clamp(1, 1000);
        let items: Vec<Value> = self
            .host
            .history(limit)
            .into_iter()
            .map(|r| {
                json!({
                    "t": r.unix_ms, "domain": r.domain, "type": r.qtype, "client": r.client.to_string(),
                    "device": r.device, "blocked": r.blocked, "rcode": r.rcode, "ms": (r.micros as f64) / 1000.0,
                })
            })
            .collect();
        reply(StatusCode::OK, &json!({ "enabled": true, "items": items }))
    }

    fn put_history(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let Some(on) = body.get("enabled").and_then(Value::as_bool) else {
            return bad("enabled must be true or false");
        };
        self.host.set_history(on);
        if store
            .set_setting("history", if on { "1" } else { "0" })
            .is_err()
        {
            return unavailable();
        }
        Self::actor(
            store,
            ctx,
            if on {
                "history.enable"
            } else {
                "history.disable"
            },
            "console",
        );
        reply(StatusCode::OK, &json!({ "enabled": on }))
    }

    fn put_settings(&self, store: &mut Store, ctx: &Ctx<'_>) -> Reply {
        let Ok(body) = serde_json::from_slice::<Value>(&ctx.request.body) else {
            return bad("invalid JSON");
        };
        let Some(minutes) = body
            .get("session_idle_minutes")
            .and_then(Value::as_u64)
            .filter(|m| (5..=1440).contains(m))
        else {
            return bad("session_idle_minutes must be 5-1440");
        };
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
        settings_json(store)
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
            &Value::Array(users.iter().map(user_json).collect()),
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

fn settings_json(store: &Store) -> Reply {
    reply(
        StatusCode::OK,
        &json!({ "session_idle_minutes": Console::idle_secs(store) / 60 }),
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

    struct Stub;
    impl Host for Stub {
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
        fn history_enabled(&self) -> bool {
            false
        }
        fn set_history(&self, _: bool) {}
        fn history(&self, _: usize) -> Vec<QueryRecord> {
            Vec::new()
        }
    }

    const CONFIG: &str = "schema_version = 1\n[filtering]\ndefault_profile = \"standard\"\n[[filtering.profiles]]\nid = \"standard\"\n";

    struct Fixture {
        console: Console,
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
        Fixture {
            console: Console::new(state.clone(), Arc::new(Stub), "test"),
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
    fn setup_runs_once_and_needs_the_code_off_machine() {
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state.db");
        let mut store = Store::open(&state).unwrap();
        store.set_config(CONFIG, directory.path()).unwrap();
        let f = Fixture {
            console: Console::new(state.clone(), Arc::new(Stub), "test"),
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
                &json!({"code": code, "username": "Owner", "password": pw}).to_string(),
                from,
            ))
        };
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
            attempt("127.0.0.1", "", "another passphrase!").0,
            StatusCode::CONFLICT
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
                .setting("history")
                .unwrap()
                .as_deref(),
            Some("1")
        );
        assert_eq!(
            call(&f, Method::GET, "/api/nope", session, "", "127.0.0.1").status(),
            StatusCode::NOT_FOUND
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

// SPDX-License-Identifier: Apache-2.0
//! Service lifecycle, resource admission, and aggregate metrics.

mod transport;
pub use lumen_resolver::Transport;
pub use transport::{ConsoleOptions, RunningServer};

use lumen_config::Config;
use lumen_proto::{Query, Rcode, is_response, malformed_response};
use lumen_resolver::Resolver;
use std::fmt::Write;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, time::timeout};

/// Public product name.
pub const PRODUCT_NAME: &str = "Lumen";

/// Aggregate counters. No query names, client labels, or query history.
#[derive(Default)]
pub struct Metrics {
    pub queries: AtomicU64,
    pub responses: AtomicU64,
    pub malformed: AtomicU64,
    pub refused: AtomicU64,
    pub timeouts: AtomicU64,
    pub failures: AtomicU64,
    pub active: AtomicU64,
    transports: [AtomicU64; 6],
    latency_buckets: [AtomicU64; 8],
    latency_micros: AtomicU64,
    rcodes: [AtomicU64; 5],
}

impl Metrics {
    /// Stable Prometheus text exposition. All labels have bounded cardinality.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = String::new();
        for (name, help, value) in [
            (
                "queries_total",
                "DNS packets admitted to the query path.",
                &self.queries,
            ),
            (
                "responses_total",
                "DNS responses produced.",
                &self.responses,
            ),
            (
                "malformed_total",
                "Malformed DNS requests.",
                &self.malformed,
            ),
            (
                "refused_total",
                "Requests refused by ACL, rate, or concurrency limits.",
                &self.refused,
            ),
            (
                "timeouts_total",
                "Queries reaching the resolution deadline.",
                &self.timeouts,
            ),
            (
                "failures_total",
                "SERVFAIL responses produced.",
                &self.failures,
            ),
            ("active_queries", "Current resolver queries.", &self.active),
        ] {
            let kind = if name == "active_queries" {
                "gauge"
            } else {
                "counter"
            };
            let _ = writeln!(
                text,
                "# HELP lumen_dns_{name} {help}\n# TYPE lumen_dns_{name} {kind}\nlumen_dns_{name} {}",
                value.load(Ordering::Relaxed)
            );
        }
        text.push_str("# HELP lumen_dns_transport_queries_total Admitted DNS queries by bounded transport.\n# TYPE lumen_dns_transport_queries_total counter\n");
        for (name, value) in [
            ("udp", &self.transports[0]),
            ("tcp", &self.transports[1]),
            ("tls", &self.transports[2]),
            ("https", &self.transports[3]),
            ("quic", &self.transports[4]),
            ("other", &self.transports[5]),
        ] {
            let _ = writeln!(
                text,
                "lumen_dns_transport_queries_total{{transport=\"{name}\"}} {}",
                value.load(Ordering::Relaxed)
            );
        }
        text.push_str("# HELP lumen_dns_query_duration_seconds End-to-end admitted DNS query time.\n# TYPE lumen_dns_query_duration_seconds histogram\n");
        let bounds = [0.001_f64, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0];
        let mut cumulative = 0_u64;
        for (index, bound) in bounds.into_iter().enumerate() {
            cumulative =
                cumulative.saturating_add(self.latency_buckets[index].load(Ordering::Relaxed));
            let _ = writeln!(
                text,
                "lumen_dns_query_duration_seconds_bucket{{le=\"{bound}\"}} {cumulative}"
            );
        }
        cumulative = cumulative.saturating_add(self.latency_buckets[7].load(Ordering::Relaxed));
        let micros = self.latency_micros.load(Ordering::Relaxed);
        let _ = writeln!(
            text,
            "lumen_dns_query_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}\nlumen_dns_query_duration_seconds_sum {}.{:06}\nlumen_dns_query_duration_seconds_count {cumulative}",
            micros / 1_000_000,
            micros % 1_000_000
        );
        text
    }

    fn observe(&self, protocol: Transport, started: Instant) {
        let transport = match protocol {
            Transport::Udp => 0,
            Transport::Tcp => 1,
            Transport::Tls => 2,
            Transport::Https => 3,
            Transport::Quic => 4,
            _ => 5,
        };
        self.transports[transport].fetch_add(1, Ordering::Relaxed);
        let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.latency_micros.fetch_add(micros, Ordering::Relaxed);
        let bucket = [
            1_000_u64, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000,
        ]
        .into_iter()
        .position(|bound| micros <= bound)
        .unwrap_or(7);
        self.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }
}

struct Bucket {
    start: Instant,
    count: u32,
}

#[derive(Default)]
struct ClientRates {
    entries: HashMap<IpAddr, Bucket>,
    last_sweep: Option<Instant>,
}

impl ClientRates {
    fn allow(&mut self, ip: IpAddr, now: Instant, limits: &lumen_config::Limits) -> bool {
        let window = Duration::from_secs(1);
        if !self.entries.contains_key(&ip) && self.entries.len() >= limits.max_clients as usize {
            // A flood of new IPs must not force a full table scan per packet.
            if self
                .last_sweep
                .is_none_or(|last| now.duration_since(last) >= window)
            {
                self.entries
                    .retain(|_, bucket| now.duration_since(bucket.start) < window);
                self.last_sweep = Some(now);
            }
            if self.entries.len() >= limits.max_clients as usize {
                return false;
            }
        }
        let bucket = self.entries.entry(ip).or_insert(Bucket {
            start: now,
            count: 0,
        });
        if now.duration_since(bucket.start) >= window {
            bucket.start = now;
            bucket.count = 0;
        }
        if bucket.count >= limits.queries_per_second {
            return false;
        }
        bucket.count += 1;
        true
    }
}

/// Most recent queries kept in memory while history is enabled. Never persisted.
const HISTORY_LIMIT: usize = 1000;

struct Service {
    started: Instant,
    history_on: std::sync::atomic::AtomicBool,
    history: Mutex<std::collections::VecDeque<lumen_web::QueryRecord>>,
    config: Arc<Config>,
    resolver: Resolver,
    filter: Arc<lumen_filter::Filter>,
    queries: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    clients: Mutex<ClientRates>,
    metrics: Arc<Metrics>,
}

impl Service {
    fn allowed(&self, peer: SocketAddr) -> bool {
        let ip = peer.ip().to_canonical();
        self.config
            .listen
            .allow_clients
            .iter()
            .any(|network| network.contains(&ip))
    }

    fn rate_allowed(&self, ip: IpAddr) -> bool {
        self.clients.lock().expect("client rate lock").allow(
            ip,
            Instant::now(),
            &self.config.limits,
        )
    }

    async fn answer(
        &self,
        packet: &[u8],
        peer: SocketAddr,
        protocol: Transport,
    ) -> Option<Vec<u8>> {
        if packet.len() < 12 || is_response(packet) {
            return None;
        }
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        if !self.allowed(peer) || !self.rate_allowed(peer.ip().to_canonical()) {
            self.metrics.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if packet.len() > usize::from(self.config.limits.max_message_bytes) {
            self.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            return Some(self.record_response(malformed_response(packet), protocol, started));
        }
        let Ok(query) = Query::parse(packet) else {
            self.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            return Some(self.record_response(malformed_response(packet), protocol, started));
        };
        let Ok(_permit) = self.queries.try_acquire() else {
            self.metrics.refused.fetch_add(1, Ordering::Relaxed);
            return Some(self.record_response(query.response(Rcode::Refused), protocol, started));
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let decision = self.filter.decide_dns(
            query.message.queries[0].name(),
            peer.ip().to_canonical(),
            now,
        );
        if self.config.filtering.decision_log {
            let name = query.message.queries[0].name().to_ascii();
            eprintln!(
                "filter client={} domain={name:?} {decision}",
                peer.ip().to_canonical()
            );
        }
        if let Some(action) = &decision.action {
            let maximum = usize::from(self.config.limits.max_message_bytes);
            let maximum = if protocol == Transport::Udp {
                maximum.min(usize::from(query.message.max_payload().max(512)))
            } else {
                maximum
            };
            let response = lumen_filter::response(&query, action, maximum);
            self.log_query(&query, peer, true, &response, started);
            return Some(self.record_response(response, protocol, started));
        }
        self.metrics.active.fetch_add(1, Ordering::Relaxed);
        let _active = ActiveQuery(&self.metrics.active);
        let result = timeout(
            Duration::from_millis(u64::from(self.config.limits.query_timeout_ms)),
            self.resolver.answer(
                &query,
                peer,
                protocol,
                usize::from(self.config.limits.max_message_bytes),
            ),
        )
        .await;
        let response = match result {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => query.response(Rcode::ServFail),
            Err(_) => {
                self.metrics.timeouts.fetch_add(1, Ordering::Relaxed);
                query.response(Rcode::ServFail)
            }
        };
        self.log_query(&query, peer, false, &response, started);
        Some(self.record_response(response, protocol, started))
    }

    fn record_response(&self, response: Vec<u8>, protocol: Transport, started: Instant) -> Vec<u8> {
        self.metrics.responses.fetch_add(1, Ordering::Relaxed);
        self.metrics.observe(protocol, started);
        let rcode = response.get(3).map_or(0, |byte| byte & 15);
        if rcode == 2 {
            self.metrics.failures.fetch_add(1, Ordering::Relaxed);
        }
        self.metrics.rcodes[match rcode {
            0 => 0,
            3 => 1,
            2 => 2,
            5 => 3,
            _ => 4,
        }]
        .fetch_add(1, Ordering::Relaxed);
        response
    }

    fn log_query(
        &self,
        query: &Query,
        peer: SocketAddr,
        blocked: bool,
        response: &[u8],
        started: Instant,
    ) {
        if !self.history_on.load(Ordering::Relaxed) {
            return;
        }
        let client = peer.ip().to_canonical();
        let question = &query.message.queries[0];
        let record = lumen_web::QueryRecord {
            unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            domain: question.name().to_ascii().trim_end_matches('.').to_owned(),
            qtype: question.query_type().to_string(),
            client,
            device: self.filter.device_of(client),
            blocked,
            rcode: match response.get(3).map_or(0, |byte| byte & 15) {
                0 => "NOERROR",
                2 => "SERVFAIL",
                3 => "NXDOMAIN",
                5 => "REFUSED",
                _ => "OTHER",
            },
            micros: u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        };
        let mut log = self.history.lock().expect("history lock");
        if log.len() >= HISTORY_LIMIT {
            log.pop_back();
        }
        log.push_front(record);
    }
}

struct ActiveQuery<'a>(&'a AtomicU64);
impl Drop for ActiveQuery<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl lumen_web::Host for Service {
    fn counters(&self) -> lumen_web::Counters {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        let m = &self.metrics;
        let (generation, _) = self.filter.status();
        lumen_web::Counters {
            queries: load(&m.queries),
            responses: load(&m.responses),
            malformed: load(&m.malformed),
            refused: load(&m.refused),
            timeouts: load(&m.timeouts),
            failures: load(&m.failures),
            active: load(&m.active),
            transports: std::array::from_fn(|i| load(&m.transports[i])),
            latency: std::array::from_fn(|i| load(&m.latency_buckets[i])),
            rcodes: std::array::from_fn(|i| load(&m.rcodes[i])),
            blocked: load(&self.filter.metrics.blocked),
            allowed: load(&self.filter.metrics.allowed),
            refresh_successes: load(&self.filter.metrics.refresh_successes),
            refresh_failures: load(&self.filter.metrics.refresh_failures),
            rollbacks: load(&self.filter.metrics.rollbacks),
            filter_generation: generation,
        }
    }

    fn lists(&self) -> Vec<lumen_web::ListInfo> {
        self.filter
            .status()
            .1
            .into_iter()
            .map(|list| lumen_web::ListInfo {
                id: list.id,
                rules: list.rules,
                unsupported: list.unsupported,
                duplicates: list.duplicates,
            })
            .collect()
    }

    fn explain(&self, domain: &str, client: IpAddr, unix_seconds: u64) -> lumen_web::Explained {
        let decision = self.filter.explain(domain, client, unix_seconds);
        lumen_web::Explained {
            blocked: decision.blocked,
            rule: decision.rule,
            list: decision.list,
            category: decision.category,
            profile: decision.profile,
            device: decision.device,
            group: decision.group,
            generation: decision.generation,
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    fn history_enabled(&self) -> bool {
        self.history_on.load(Ordering::Relaxed)
    }

    fn set_history(&self, enabled: bool) {
        self.history_on.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.history.lock().expect("history lock").clear();
        }
    }

    fn history(&self, limit: usize) -> Vec<lumen_web::QueryRecord> {
        self.history
            .lock()
            .expect("history lock")
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn client_table_bounds_sweeps_and_window_reset() {
        let mut rates = ClientRates::default();
        let now = Instant::now();
        let limits = lumen_config::Limits {
            max_clients: 1,
            queries_per_second: 2,
            ..lumen_config::Limits::default()
        };
        let first = "127.0.0.1".parse().unwrap();
        let second = "127.0.0.2".parse().unwrap();
        assert!(rates.allow(first, now, &limits));
        assert!(rates.allow(first, now, &limits));
        assert!(!rates.allow(first, now, &limits));
        assert!(!rates.allow(second, now, &limits));
        assert!(!rates.allow(second, now + Duration::from_millis(500), &limits));
        assert_eq!(rates.last_sweep, Some(now));
        assert_eq!(rates.entries.len(), 1);
        assert!(rates.allow(second, now + Duration::from_secs(1), &limits));
        assert_eq!(rates.entries.len(), 1);
        assert!(rates.allow(second, now + Duration::from_secs(2), &limits));
    }

    #[test]
    fn extended_metrics_have_bounded_transport_and_latency_series() {
        let metrics = Metrics::default();
        metrics.observe(Transport::Udp, Instant::now());
        let text = metrics.render();
        assert!(text.contains("lumen_dns_transport_queries_total{transport=\"udp\"} 1"));
        assert!(text.contains("lumen_dns_query_duration_seconds_count 1"));
        assert!(!text.contains("client="));
        assert!(!text.contains("domain="));
    }
}

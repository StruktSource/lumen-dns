// SPDX-License-Identifier: Apache-2.0
//! Service lifecycle, resource admission, and aggregate metrics.

mod transport;
pub use lumen_resolver::Transport;
pub use transport::RunningServer;

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
        text
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

struct Service {
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
        if !self.allowed(peer) || !self.rate_allowed(peer.ip().to_canonical()) {
            self.metrics.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        if packet.len() > usize::from(self.config.limits.max_message_bytes) {
            self.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            return Some(self.record_response(malformed_response(packet)));
        }
        let Ok(query) = Query::parse(packet) else {
            self.metrics.malformed.fetch_add(1, Ordering::Relaxed);
            return Some(self.record_response(malformed_response(packet)));
        };
        let Ok(_permit) = self.queries.try_acquire() else {
            self.metrics.refused.fetch_add(1, Ordering::Relaxed);
            return Some(self.record_response(query.response(Rcode::Refused)));
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
            return Some(self.record_response(lumen_filter::response(&query, action, maximum)));
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
        Some(self.record_response(response))
    }

    fn record_response(&self, response: Vec<u8>) -> Vec<u8> {
        self.metrics.responses.fetch_add(1, Ordering::Relaxed);
        if response.get(3).is_some_and(|byte| byte & 15 == 2) {
            self.metrics.failures.fetch_add(1, Ordering::Relaxed);
        }
        response
    }
}

struct ActiveQuery<'a>(&'a AtomicU64);
impl Drop for ActiveQuery<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
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
}

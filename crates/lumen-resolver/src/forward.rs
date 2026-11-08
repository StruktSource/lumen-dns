// SPDX-License-Identifier: Apache-2.0
//! Forward mode with several providers.
//!
//! Every provider (and every custom upstream) gets its own forwarder with its own timeout.
//! Lumen, not the forwarding library, then decides which provider answers a query:
//!
//! - **Ranked fallback** asks the providers in their written order, and the next one only
//!   after the previous failed. A provider that never answers costs one timeout.
//! - **Fastest first** orders providers by how quickly they recently answered.
//! - **Round-robin** starts each query at the next provider in turn.
//! - **Race** asks every provider at once and takes the first answer.
//!
//! Only connection errors and timeouts move on to another provider. A DNS answer, including
//! NXDOMAIN, SERVFAIL and a DNSSEC failure, is final: asking a second provider for a
//! different answer would let it override a validation result.

use hickory_server::{
    net::{NetError, runtime::RuntimeProvider},
    proto::rr::{Name, RecordType},
    resolver::{Resolver, lookup::Lookup},
};
use lumen_config::ForwardStrategy;
use std::{
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};

/// How long a provider that just failed is skipped before it is tried again.
const REST_AFTER_FAILURE: Duration = Duration::from_secs(10);

/// One provider's forwarder and how fast it has been answering.
struct Member<P: RuntimeProvider> {
    resolver: Resolver<P>,
    /// Recent response time in microseconds. Zero until the first answer.
    speed: AtomicU64,
    /// Milliseconds since the pool started until which the provider is left alone. Zero
    /// means it is in use.
    resting_until: AtomicU64,
}

impl<P: RuntimeProvider> Member<P> {
    /// Blend a new response time into the running figure.
    fn answered(&self, took: Duration) {
        let micros = u64::try_from(took.as_micros()).unwrap_or(u64::MAX);
        let old = self.speed.load(Ordering::Relaxed);
        let blended = if old == 0 {
            micros
        } else {
            (old * 7 + micros) / 8
        };
        self.speed.store(blended.max(1), Ordering::Relaxed);
        self.resting_until.store(0, Ordering::Relaxed);
    }

    /// A failed provider goes to the back of the line for fastest-first, and is left alone
    /// for a short while so every query does not wait for it again.
    fn failed(&self, penalty: Duration, now_ms: u64) {
        let micros = u64::try_from(penalty.as_micros()).unwrap_or(u64::MAX);
        self.speed.fetch_max(micros.max(1), Ordering::Relaxed);
        let rest = u64::try_from(REST_AFTER_FAILURE.as_millis()).unwrap_or(u64::MAX);
        self.resting_until
            .store(now_ms.saturating_add(rest), Ordering::Relaxed);
    }
}

pub(crate) struct ForwardPool<P: RuntimeProvider> {
    members: Vec<Member<P>>,
    strategy: ForwardStrategy,
    next: AtomicUsize,
    penalty: Duration,
    started: Instant,
}

/// Errors that say the provider could not be reached or did not answer in time, as opposed
/// to a DNS answer. Only these move on to the next provider.
fn try_next_provider(error: &NetError) -> bool {
    matches!(
        error,
        NetError::Timeout
            | NetError::NoConnections
            | NetError::Io(_)
            | NetError::Busy
            | NetError::H2(_)
            | NetError::QuinnConnect(_)
            | NetError::QuinnConnection(_)
            | NetError::QuinnWriteError(_)
            | NetError::QuinnReadError(_)
            | NetError::QuinnStreamError(_)
            | NetError::QuinnUnknownStreamError
            | NetError::RustlsError(_)
            | NetError::QueryCaseMismatch
            | NetError::Truncated
    )
}

/// The order in which `count` providers are tried for one query.
///
/// `start` is the round-robin counter and `speeds` the recent response times (zero means
/// not measured yet, which sorts first so every provider gets measured).
pub(crate) fn order_for(
    strategy: ForwardStrategy,
    count: usize,
    start: usize,
    speeds: &[u64],
) -> Vec<usize> {
    match strategy {
        ForwardStrategy::Failover | ForwardStrategy::Race => (0..count).collect(),
        ForwardStrategy::RoundRobin => (0..count).map(|i| (start + i) % count.max(1)).collect(),
        ForwardStrategy::Fastest => {
            let mut order: Vec<usize> = (0..count).collect();
            order.sort_by_key(|&i| (speeds.get(i).copied().unwrap_or(0), i));
            order
        }
    }
}

impl<P: RuntimeProvider> ForwardPool<P> {
    pub(crate) fn new(
        resolvers: Vec<Resolver<P>>,
        strategy: ForwardStrategy,
        penalty: Duration,
    ) -> Self {
        Self {
            members: resolvers
                .into_iter()
                .map(|resolver| Member {
                    resolver,
                    speed: AtomicU64::new(0),
                    resting_until: AtomicU64::new(0),
                })
                .collect(),
            strategy,
            next: AtomicUsize::new(0),
            penalty,
            started: Instant::now(),
        }
    }

    /// Whether answers are validated with DNSSEC (the same for every provider).
    pub(crate) fn validates(&self) -> bool {
        self.members
            .first()
            .is_some_and(|member| member.resolver.options().validate)
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(crate) async fn lookup(&self, name: Name, rtype: RecordType) -> Result<Lookup, NetError> {
        if self.strategy == ForwardStrategy::Race && self.members.len() > 1 {
            return self.race(name, rtype).await;
        }
        let speeds: Vec<u64> = self
            .members
            .iter()
            .map(|member| member.speed.load(Ordering::Relaxed))
            .collect();
        let start = if self.strategy == ForwardStrategy::RoundRobin {
            self.next.fetch_add(1, Ordering::Relaxed)
        } else {
            0
        };
        let mut order = order_for(self.strategy, self.members.len(), start, &speeds);
        // Providers that just failed are the last resort, not the first thing every query
        // waits for. They are still tried if nothing else answers.
        let now = self.now_ms();
        order.sort_by_key(|&i| self.members[i].resting_until.load(Ordering::Relaxed) > now);
        let mut last = NetError::NoConnections;
        for index in order {
            let member = &self.members[index];
            let started = Instant::now();
            match member.resolver.lookup(name.clone(), rtype).await {
                Ok(lookup) => {
                    member.answered(started.elapsed());
                    self.let_others_recover(index);
                    return Ok(lookup);
                }
                Err(error) if try_next_provider(&error) => {
                    member.failed(self.penalty, self.now_ms());
                    last = error;
                }
                Err(error) => {
                    member.answered(started.elapsed());
                    return Err(error);
                }
            }
        }
        Err(last)
    }

    /// Ask every provider at once. The first answer wins and the rest are cancelled.
    async fn race(&self, name: Name, rtype: RecordType) -> Result<Lookup, NetError> {
        let mut asks = tokio::task::JoinSet::new();
        for (index, member) in self.members.iter().enumerate() {
            let resolver = member.resolver.clone();
            let name = name.clone();
            asks.spawn(async move {
                let started = Instant::now();
                let result = resolver.lookup(name, rtype).await;
                (index, started.elapsed(), result)
            });
        }
        let mut last = NetError::NoConnections;
        while let Some(done) = asks.join_next().await {
            let Ok((index, took, result)) = done else {
                continue;
            };
            let member = &self.members[index];
            match result {
                Ok(lookup) => {
                    member.answered(took);
                    return Ok(lookup);
                }
                Err(error) if try_next_provider(&error) => {
                    member.failed(self.penalty, self.now_ms());
                    last = error;
                }
                Err(error) => {
                    member.answered(took);
                    return Err(error);
                }
            }
        }
        Err(last)
    }

    /// Providers not chosen drift slowly back toward being tried, so one slow spell does not
    /// banish a provider for good.
    fn let_others_recover(&self, chosen: usize) {
        for (index, member) in self.members.iter().enumerate() {
            if index != chosen {
                let old = member.speed.load(Ordering::Relaxed);
                member.speed.store(old - old / 100, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ForwardStrategy::{Failover, Fastest, Race, RoundRobin};

    #[test]
    fn providers_are_ordered_by_strategy() {
        // Ranked fallback and race keep the written order.
        assert_eq!(order_for(Failover, 3, 7, &[9, 1, 5]), [0, 1, 2]);
        assert_eq!(order_for(Race, 3, 7, &[9, 1, 5]), [0, 1, 2]);
        // Round-robin starts one provider later each time and still lists them all.
        assert_eq!(order_for(RoundRobin, 3, 0, &[]), [0, 1, 2]);
        assert_eq!(order_for(RoundRobin, 3, 1, &[]), [1, 2, 0]);
        assert_eq!(order_for(RoundRobin, 3, 5, &[]), [2, 0, 1]);
        // Fastest first sorts by response time. A provider not yet measured goes first.
        assert_eq!(order_for(Fastest, 3, 0, &[900, 100, 500]), [1, 2, 0]);
        assert_eq!(order_for(Fastest, 3, 0, &[900, 0, 500]), [1, 2, 0]);
        assert_eq!(order_for(Fastest, 3, 0, &[]), [0, 1, 2]);
        // Equal speeds keep their rank, and nothing breaks with no providers.
        assert_eq!(order_for(Fastest, 3, 0, &[7, 7, 7]), [0, 1, 2]);
        assert!(order_for(RoundRobin, 0, 4, &[]).is_empty());
    }

    #[test]
    fn only_unreachable_providers_move_on_never_dns_answers() {
        use hickory_server::net::DnsError;
        assert!(try_next_provider(&NetError::Timeout));
        assert!(try_next_provider(&NetError::NoConnections));
        assert!(try_next_provider(&NetError::Io(std::sync::Arc::new(
            std::io::Error::other("refused")
        ))));
        // A DNS answer, even a negative one, ends the lookup.
        let nxdomain = NetError::from(DnsError::ResponseCode(
            hickory_server::proto::op::ResponseCode::NXDomain,
        ));
        assert!(!try_next_provider(&nxdomain));
        let servfail = NetError::from(DnsError::ResponseCode(
            hickory_server::proto::op::ResponseCode::ServFail,
        ));
        assert!(!try_next_provider(&servfail));
    }
}

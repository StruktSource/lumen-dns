// SPDX-License-Identifier: Apache-2.0
//! Bounded request coalescing, startup priming, and expiry-time refresh for recursion.
//!
//! None of this changes what is resolved or validated. Every answer still comes from the
//! shared Hickory recursor and its DNSSEC validation. Coalescing only lets identical
//! in-flight queries share one recursion; warming and refresh only issue ordinary recursive
//! queries earlier than a client would. Query names stay in memory, are bounded, and are
//! never logged or exported.

use crate::{Metrics, recursion_timed_out};
use hickory_server::{
    net::runtime::RuntimeProvider,
    proto::{
        op::{Message, Query as DnsQuery},
        rr::{LowerName, Name, RecordType},
    },
    resolver::recursor::{Recursor, RecursorError},
};
use lumen_config::{Prefetch, Warm};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};

/// Distinct identical-query groups that may be in flight at once.
const MAX_FLIGHTS: usize = 4096;
/// Answers that expire sooner than this are not worth refreshing.
const MIN_REFRESH_TTL_SECS: u64 = 10;
/// Refresh starts slightly after expiry so the cache entry is certainly stale.
const REFRESH_DELAY: Duration = Duration::from_millis(250);
/// One recursion for priming or refresh may not run longer than this.
const BACKGROUND_DEADLINE: Duration = Duration::from_secs(10);
/// Tracked names unseen for this long are forgotten.
const MAX_IDLE: Duration = Duration::from_secs(3600);
/// Priming never runs more than this many recursions at once.
const WARM_CONCURRENCY: usize = 2;

pub(crate) type Key = (LowerName, RecordType, bool);

/// Result shared with identical queries that waited on one recursion.
#[derive(Clone)]
pub(crate) enum Outcome {
    Answer(Box<Message>),
    /// Negative answers are cached by the recursor, so waiters read them from there.
    Retry,
    Timeout,
    Failed,
}

enum Role {
    Leader(watch::Sender<Option<Outcome>>),
    Follower(watch::Receiver<Option<Outcome>>),
    Alone,
}

pub(crate) struct Entry {
    pub(crate) hits: u32,
    pub(crate) last_seen: Instant,
    pub(crate) refresh_at: Option<Instant>,
}

#[derive(Default)]
pub(crate) struct Hot {
    pub(crate) entries: HashMap<Key, Entry>,
    window_start: Option<Instant>,
    started: u32,
}

pub(crate) struct Accel {
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) flights: Mutex<HashMap<Key, watch::Receiver<Option<Outcome>>>>,
    pub(crate) hot: Mutex<Hot>,
    prefetch: Prefetch,
    hedge: Option<Duration>,
    started: AtomicBool,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Removes a flight even when its leader is cancelled by a caller deadline.
struct FlightGuard<'a> {
    accel: &'a Accel,
    key: &'a Key,
}

impl Drop for FlightGuard<'_> {
    fn drop(&mut self) {
        lock(&self.accel.flights).remove(self.key);
    }
}

impl Accel {
    pub(crate) fn new(metrics: Arc<Metrics>, prefetch: Prefetch) -> Self {
        Self {
            metrics,
            flights: Mutex::default(),
            hot: Mutex::default(),
            prefetch,
            hedge: None,
            started: AtomicBool::new(false),
            tasks: Mutex::default(),
        }
    }

    /// Start a second recursion for lookups still unanswered after `milliseconds`.
    #[must_use]
    pub(crate) fn with_hedge(mut self, milliseconds: u32) -> Self {
        self.hedge = (milliseconds != 0).then(|| Duration::from_millis(u64::from(milliseconds)));
        self
    }

    /// Resolve through the recursor, sharing the work with identical in-flight queries.
    pub(crate) async fn resolve<P: RuntimeProvider>(
        &self,
        recursor: &Recursor<P>,
        name: &LowerName,
        rtype: RecordType,
        dnssec_ok: bool,
        background: bool,
    ) -> Result<Message, RecursorError> {
        let started = Instant::now();
        let key: Key = (name.clone(), rtype, dnssec_ok);
        if !background {
            self.touch(&key);
        }
        let result = self.coalesced(recursor, &key).await;
        self.metrics.observe(started.elapsed());
        result
    }

    async fn coalesced<P: RuntimeProvider>(
        &self,
        recursor: &Recursor<P>,
        key: &Key,
    ) -> Result<Message, RecursorError> {
        for _ in 0..3 {
            let role = {
                let mut flights = lock(&self.flights);
                if let Some(receiver) = flights.get(key) {
                    Role::Follower(receiver.clone())
                } else if flights.len() >= MAX_FLIGHTS {
                    Role::Alone
                } else {
                    let (sender, receiver) = watch::channel(None);
                    flights.insert(key.clone(), receiver);
                    Role::Leader(sender)
                }
            };
            match role {
                Role::Alone => break,
                Role::Leader(sender) => {
                    let guard = FlightGuard { accel: self, key };
                    let result = self.run(recursor, key).await;
                    if let Ok(message) = &result {
                        self.schedule(key, message);
                    }
                    // New arrivals now start their own flight and hit the cache.
                    drop(guard);
                    if sender.receiver_count() > 0 {
                        let _ = sender.send(Some(match &result {
                            Ok(message) => Outcome::Answer(Box::new(message.clone())),
                            Err(RecursorError::Negative(_)) => Outcome::Retry,
                            Err(error) if recursion_timed_out(error) => Outcome::Timeout,
                            Err(_) => Outcome::Failed,
                        }));
                    }
                    return result;
                }
                Role::Follower(mut receiver) => {
                    // A closed channel means the leader was cancelled: try again.
                    let outcome = match receiver.wait_for(Option::is_some).await {
                        Ok(shared) => (*shared).clone(),
                        Err(_) => continue,
                    };
                    self.metrics.coalesced.fetch_add(1, Ordering::Relaxed);
                    return match outcome {
                        Some(Outcome::Answer(message)) => Ok(*message),
                        Some(Outcome::Timeout) => Err(RecursorError::Timeout),
                        Some(Outcome::Failed) => {
                            Err(RecursorError::Message("shared recursion failed"))
                        }
                        Some(Outcome::Retry) | None => self.run(recursor, key).await,
                    };
                }
            }
        }
        self.run(recursor, key).await
    }

    /// One recursion, plus a single hedge when it is slow. Authoritative servers that
    /// do not answer cost a full per-attempt timeout each; a second recursion started
    /// later often reaches a different, responsive server. First usable answer wins.
    async fn run<P: RuntimeProvider>(
        &self,
        recursor: &Recursor<P>,
        key: &Key,
    ) -> Result<Message, RecursorError> {
        let Some(delay) = self.hedge else {
            return Self::attempt(recursor, key).await;
        };
        let first = Self::attempt(recursor, key);
        tokio::pin!(first);
        tokio::select! {
            result = &mut first => return result,
            () = sleep(delay) => {}
        }
        self.metrics.hedged.fetch_add(1, Ordering::Relaxed);
        let second = Self::attempt(recursor, key);
        tokio::pin!(second);
        tokio::select! {
            result = &mut first => settle(result, second).await,
            result = &mut second => settle(result, first).await,
        }
    }

    async fn attempt<P: RuntimeProvider>(
        recursor: &Recursor<P>,
        key: &Key,
    ) -> Result<Message, RecursorError> {
        let query = DnsQuery::query(Name::from(key.0.clone()), key.1);
        recursor.resolve(query, Instant::now(), key.2).await
    }

    pub(crate) fn touch(&self, key: &Key) {
        if !self.prefetch.enabled {
            return;
        }
        let now = Instant::now();
        let mut hot = lock(&self.hot);
        if let Some(entry) = hot.entries.get_mut(key) {
            entry.hits = entry.hits.saturating_add(1);
            entry.last_seen = now;
            return;
        }
        if hot.entries.len() >= usize::from(self.prefetch.max_tracked) {
            let oldest = hot
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                hot.entries.remove(&oldest);
            }
        }
        hot.entries.insert(
            key.clone(),
            Entry {
                hits: 0,
                last_seen: now,
                refresh_at: None,
            },
        );
    }

    /// Record when a tracked answer expires. Lookups served from the same cache entry
    /// land on the same expiry and keep their hit count; a new fill starts a new window.
    pub(crate) fn schedule(&self, key: &Key, message: &Message) {
        if !self.prefetch.enabled {
            return;
        }
        let ttl = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .map(|record| u64::from(record.ttl))
            .min();
        let Some(ttl) = ttl.filter(|ttl| *ttl >= MIN_REFRESH_TTL_SECS) else {
            return;
        };
        let expiry = Instant::now() + Duration::from_secs(ttl) + REFRESH_DELAY;
        let mut hot = lock(&self.hot);
        let Some(entry) = hot.entries.get_mut(key) else {
            return;
        };
        let same_fill = entry.refresh_at.is_some_and(|previous| {
            let delta = if previous > expiry {
                previous - expiry
            } else {
                expiry - previous
            };
            delta <= Duration::from_secs(2)
        });
        if !same_fill {
            entry.hits = 0;
            entry.refresh_at = Some(expiry);
        }
    }

    /// Start priming and refresh once, after listeners are bound.
    pub(crate) fn start<P: RuntimeProvider>(
        self: &Arc<Self>,
        recursor: &Arc<Recursor<P>>,
        warm: &Warm,
    ) {
        if self.started.swap(true, Ordering::AcqRel)
            || tokio::runtime::Handle::try_current().is_err()
        {
            return;
        }
        let mut tasks = lock(&self.tasks);
        if warm.enabled {
            tasks.push(tokio::spawn(
                Arc::clone(self).warm(Arc::clone(recursor), warm.zones.clone()),
            ));
        }
        if self.prefetch.enabled {
            tasks.push(tokio::spawn(
                Arc::clone(self).refresh_loop(Arc::clone(recursor)),
            ));
        }
    }

    pub(crate) fn stop(&self) {
        for task in lock(&self.tasks).drain(..) {
            task.abort();
        }
    }

    async fn warm<P: RuntimeProvider>(
        self: Arc<Self>,
        recursor: Arc<Recursor<P>>,
        zones: Vec<String>,
    ) {
        let permits = Arc::new(Semaphore::new(WARM_CONCURRENCY));
        let mut jobs = JoinSet::new();
        let names = std::iter::once(Name::root()).chain(
            zones
                .iter()
                .filter_map(|zone| Name::from_str(&format!("{zone}.")).ok()),
        );
        for name in names {
            for rtype in [RecordType::NS, RecordType::DNSKEY] {
                let (accel, recursor, permits) = (
                    Arc::clone(&self),
                    Arc::clone(&recursor),
                    Arc::clone(&permits),
                );
                let name = LowerName::from(&name);
                jobs.spawn(async move {
                    let Ok(_permit) = permits.acquire_owned().await else {
                        return;
                    };
                    accel.metrics.warm_queries.fetch_add(1, Ordering::Relaxed);
                    let result = timeout(
                        BACKGROUND_DEADLINE,
                        accel.resolve(&recursor, &name, rtype, true, true),
                    )
                    .await;
                    if !matches!(result, Ok(Ok(_))) {
                        accel.metrics.warm_failures.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        }
        while jobs.join_next().await.is_some() {}
    }

    async fn refresh_loop<P: RuntimeProvider>(self: Arc<Self>, recursor: Arc<Recursor<P>>) {
        let permits = Arc::new(Semaphore::new(usize::from(self.prefetch.max_concurrent)));
        loop {
            sleep(Duration::from_secs(1)).await;
            for key in self.due(&permits) {
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    self.forget(&key);
                    continue;
                };
                let (accel, recursor) = (Arc::clone(&self), Arc::clone(&recursor));
                tokio::spawn(async move {
                    let result = timeout(
                        BACKGROUND_DEADLINE,
                        accel.resolve(&recursor, &key.0, key.1, key.2, true),
                    )
                    .await;
                    drop(permit);
                    if matches!(result, Ok(Ok(_))) {
                        accel
                            .metrics
                            .prefetch_refreshes
                            .fetch_add(1, Ordering::Relaxed);
                    } else {
                        accel
                            .metrics
                            .prefetch_failures
                            .fetch_add(1, Ordering::Relaxed);
                        accel.forget(&key);
                    }
                });
            }
        }
    }

    fn forget(&self, key: &Key) {
        lock(&self.hot).entries.remove(key);
    }

    /// Entries whose answer has expired and was popular enough to refresh now.
    pub(crate) fn due(&self, permits: &Semaphore) -> Vec<Key> {
        let now = Instant::now();
        let mut hot = lock(&self.hot);
        if hot
            .window_start
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(60))
        {
            hot.window_start = Some(now);
            hot.started = 0;
        }
        let budget = u32::from(self.prefetch.budget_per_minute);
        let min_hits = u32::from(self.prefetch.min_hits);
        let mut available = permits.available_permits();
        let mut due = Vec::new();
        let mut started = hot.started;
        hot.entries.retain(|key, entry| {
            if now.duration_since(entry.last_seen) > MAX_IDLE {
                return false;
            }
            if entry.refresh_at.is_none_or(|at| at > now) {
                return true;
            }
            if entry.hits < min_hits {
                return false;
            }
            if started >= budget {
                self.metrics
                    .prefetch_skipped
                    .fetch_add(1, Ordering::Relaxed);
                return false;
            }
            if available == 0 {
                // Keep it; a permit may free up on the next tick.
                return true;
            }
            available -= 1;
            started += 1;
            entry.refresh_at = None;
            entry.hits = 0;
            due.push(key.clone());
            true
        });
        hot.started = started;
        due
    }
}

/// Keep a definitive answer (including a negative one); after a transient failure,
/// let the other recursion finish and prefer its answer.
async fn settle(
    finished: Result<Message, RecursorError>,
    other: impl std::future::Future<Output = Result<Message, RecursorError>>,
) -> Result<Message, RecursorError> {
    match finished {
        Ok(message) => Ok(message),
        Err(RecursorError::Negative(data)) => Err(RecursorError::Negative(data)),
        Err(error) => other.await.or(Err(error)),
    }
}

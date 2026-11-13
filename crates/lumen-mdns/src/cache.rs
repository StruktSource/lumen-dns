//! What devices announced, kept until their TTL runs out. Bounded, and never holds anything but
//! records under `.local` (plus reverse names), so a hostile packet cannot park other data here.

use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Longest a record is kept, whatever its TTL says.
const MAX_KEEP: Duration = Duration::from_secs(4500);
/// A cache-flush record replaces older ones, but not ones that arrived in the same moment (a
/// device announces its whole set at once).
const FLUSH_GRACE: Duration = Duration::from_secs(1);

struct Entry {
    record: Record,
    learned: Instant,
    expires: Instant,
}

#[derive(Default)]
struct Inner {
    sets: HashMap<(String, RecordType), Vec<Entry>>,
    count: usize,
}

pub struct Cache {
    inner: Mutex<Inner>,
    max: usize,
}

fn key(name: &Name, rtype: RecordType) -> (String, RecordType) {
    (name.to_lowercase().to_ascii(), rtype)
}

impl Cache {
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            inner: Mutex::default(),
            max,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Remember a record. TTL 0 is a goodbye and removes it. Returns true when this was new
    /// information (a record that was not there, or a refresh that changes nothing returns
    /// false), so waiters are only woken for news.
    pub fn insert(&self, record: &Record, now: Instant) -> bool {
        let name_key = key(&record.name, record.record_type());
        let mut inner = self.lock();
        if record.ttl == 0 {
            let removed = inner.sets.get_mut(&name_key).is_some_and(|set| {
                let before = set.len();
                set.retain(|entry| entry.record.data != record.data);
                set.len() != before
            });
            if removed {
                inner.count -= 1;
            }
            return false;
        }
        let mut stored = record.clone();
        let flush = stored.mdns_cache_flush;
        stored.mdns_cache_flush = false;
        let expires = now + Duration::from_secs(u64::from(record.ttl)).min(MAX_KEEP);
        let mut fresh = true;
        {
            let set = inner.sets.entry(name_key.clone()).or_default();
            if flush {
                let before = set.len();
                set.retain(|entry| {
                    now.saturating_duration_since(entry.learned) < FLUSH_GRACE
                        || entry.record.data == stored.data
                });
                let dropped = before - set.len();
                inner.count -= dropped;
            }
        }
        let set = inner.sets.entry(name_key).or_default();
        if let Some(entry) = set
            .iter_mut()
            .find(|entry| entry.record.data == stored.data)
        {
            entry.record = stored;
            entry.expires = expires;
            entry.learned = now;
            fresh = false;
        } else {
            set.push(Entry {
                record: stored,
                learned: now,
                expires,
            });
            inner.count += 1;
        }
        if inner.count > self.max {
            Self::evict(&mut inner, now, self.max);
        }
        fresh
    }

    /// Drop what has expired, and if the cache is still over its limit, the records closest to
    /// expiring, down to nine tenths of it so this does not run on every insert.
    fn evict(inner: &mut Inner, now: Instant, max: usize) {
        inner.sets.retain(|_, set| {
            set.retain(|entry| entry.expires > now);
            !set.is_empty()
        });
        inner.count = inner.sets.values().map(Vec::len).sum();
        if inner.count <= max {
            return;
        }
        let target = max - max / 10;
        let mut expiries: Vec<Instant> = inner
            .sets
            .values()
            .flat_map(|set| set.iter().map(|entry| entry.expires))
            .collect();
        expiries.sort_unstable();
        let cutoff = expiries[inner.count - target - 1];
        inner.sets.retain(|_, set| {
            set.retain(|entry| entry.expires > cutoff);
            !set.is_empty()
        });
        inner.count = inner.sets.values().map(Vec::len).sum();
    }

    /// The live records for a name and type, with TTLs counted down.
    #[must_use]
    pub fn get(&self, name: &Name, rtype: RecordType, now: Instant) -> Vec<Record> {
        let inner = self.lock();
        inner
            .sets
            .get(&key(name, rtype))
            .map(|set| {
                set.iter()
                    .filter(|entry| entry.expires > now)
                    .map(|entry| {
                        let mut record = entry.record.clone();
                        record.ttl = u32::try_from(
                            entry
                                .expires
                                .saturating_duration_since(now)
                                .as_secs()
                                .max(1),
                        )
                        .unwrap_or(u32::MAX);
                        record
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Every live record of a name, whatever its type.
    #[must_use]
    pub fn all_for(&self, name: &Name, now: Instant) -> Vec<Record> {
        let wanted = name.to_lowercase().to_ascii();
        let inner = self.lock();
        inner
            .sets
            .iter()
            .filter(|((owner, _), _)| *owner == wanted)
            .flat_map(|(_, set)| set.iter())
            .filter(|entry| entry.expires > now)
            .map(|entry| entry.record.clone())
            .collect()
    }

    /// The addresses, services, and text records that belong to the instances a PTR names:
    /// handy as additional records so a client needs fewer round trips.
    #[must_use]
    pub fn related(&self, answers: &[Record], now: Instant) -> Vec<Record> {
        let mut out = Vec::new();
        for record in answers {
            match &record.data {
                RData::PTR(ptr) => {
                    for kind in [RecordType::SRV, RecordType::TXT] {
                        out.extend(self.get(&ptr.0, kind, now));
                    }
                    for srv in self.get(&ptr.0, RecordType::SRV, now) {
                        if let RData::SRV(srv) = &srv.data {
                            for kind in [RecordType::A, RecordType::AAAA] {
                                out.extend(self.get(&srv.target, kind, now));
                            }
                        }
                    }
                }
                RData::SRV(srv) => {
                    for kind in [RecordType::A, RecordType::AAAA] {
                        out.extend(self.get(&srv.target, kind, now));
                    }
                }
                _ => {}
            }
        }
        out
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().count
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// True for names the cache accepts: below `.local`, or the reverse zones mDNS also uses.
#[must_use]
pub fn acceptable(name: &Name) -> bool {
    let text = name.to_lowercase().to_ascii();
    text == "local."
        || text.ends_with(".local.")
        || text.ends_with(".in-addr.arpa.")
        || text.ends_with(".ip6.arpa.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, PTR, SRV};

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }
    fn a(host: &str, last: u8, ttl: u32) -> Record {
        Record::from_rdata(name(host), ttl, RData::A(A::new(192, 0, 2, last)))
    }

    #[test]
    fn records_live_for_their_ttl_and_goodbyes_remove_them() {
        let cache = Cache::new(100);
        let t0 = Instant::now();
        assert!(cache.insert(&a("tv.local.", 5, 120), t0));
        assert!(
            !cache.insert(&a("TV.local.", 5, 120), t0),
            "a refresh is not news"
        );
        assert_eq!(cache.get(&name("tv.local."), RecordType::A, t0).len(), 1);
        let later = t0 + Duration::from_secs(100);
        assert_eq!(
            cache.get(&name("tv.local."), RecordType::A, later)[0].ttl,
            20
        );
        assert!(
            cache
                .get(
                    &name("tv.local."),
                    RecordType::A,
                    t0 + Duration::from_secs(121)
                )
                .is_empty()
        );
        cache.insert(&a("tv.local.", 5, 0), t0);
        assert!(cache.get(&name("tv.local."), RecordType::A, t0).is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn a_cache_flush_replaces_older_records_but_not_the_same_announcement() {
        let cache = Cache::new(100);
        let t0 = Instant::now();
        cache.insert(&a("tv.local.", 5, 120), t0);
        let mut moved = a("tv.local.", 6, 120);
        moved.mdns_cache_flush = true;
        // Within the grace period the old address stays (a device sends its set at once).
        cache.insert(&moved, t0 + Duration::from_millis(300));
        assert_eq!(cache.get(&name("tv.local."), RecordType::A, t0).len(), 2);
        // Later, a flush leaves only the new address.
        let mut again = a("tv.local.", 7, 120);
        again.mdns_cache_flush = true;
        cache.insert(&again, t0 + Duration::from_secs(5));
        let left = cache.get(
            &name("tv.local."),
            RecordType::A,
            t0 + Duration::from_secs(5),
        );
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].data, RData::A(A::new(192, 0, 2, 7)));
    }

    #[test]
    fn the_cache_is_bounded_and_prefers_dropping_what_is_stale() {
        let cache = Cache::new(64);
        let t0 = Instant::now();
        for i in 0..64u8 {
            cache.insert(&a(&format!("h{i}.local."), i, 10), t0);
        }
        // A new record after the old ones expired makes room by dropping them.
        cache.insert(&a("fresh.local.", 1, 100), t0 + Duration::from_secs(50));
        assert_eq!(cache.len(), 1);
        for i in 0..200u8 {
            cache.insert(
                &a(&format!("n{i}.local."), i, 4000),
                t0 + Duration::from_secs(60),
            );
        }
        assert!(cache.len() <= 64, "{}", cache.len());
    }

    #[test]
    fn related_records_follow_a_service_instance() {
        let cache = Cache::new(100);
        let t0 = Instant::now();
        let ptr = Record::from_rdata(
            name("_http._tcp.local."),
            120,
            RData::PTR(PTR(name("web._http._tcp.local."))),
        );
        cache.insert(
            &Record::from_rdata(
                name("web._http._tcp.local."),
                120,
                RData::SRV(SRV::new(0, 0, 80, name("host.local."))),
            ),
            t0,
        );
        cache.insert(&a("host.local.", 9, 120), t0);
        let related = cache.related(&[ptr], t0);
        let kinds: Vec<RecordType> = related.iter().map(Record::record_type).collect();
        assert!(
            kinds.contains(&RecordType::SRV) && kinds.contains(&RecordType::A),
            "{kinds:?}"
        );
    }

    #[test]
    fn only_local_and_reverse_names_are_acceptable() {
        assert!(acceptable(&name("printer.local.")));
        assert!(acceptable(&name("5.2.0.192.in-addr.arpa.")));
        assert!(!acceptable(&name("example.com.")));
        assert!(!acceptable(&name("local.example.com.")));
    }
}

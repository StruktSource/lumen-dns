// SPDX-License-Identifier: Apache-2.0
//! In-memory copies of downloaded lists.
//!
//! A reload (for example after changing the resolver) builds a new filter. Without this
//! cache it would download every list again. With it, only lists that are new, changed, or
//! due for their own refresh are fetched. Nothing is written to disk, and the cache is lost
//! on restart. Cancelled or failed applies keep what they already downloaded.

use crate::rules::{Format, ParsedList};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// More than the 64 lists a config may hold, so a few removed lists never block new ones.
const MAX_ENTRIES: usize = 128;

type Key = (String, Format);

#[derive(Clone)]
pub(crate) struct Cached {
    pub list: Arc<ParsedList>,
    /// When the list was downloaded, so refresh timing continues across reloads.
    pub fetched: Instant,
}

static CACHE: Mutex<Option<HashMap<Key, Cached>>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut HashMap<Key, Cached>) -> R) -> R {
    let mut guard = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
}

/// A cached download of `url`, unless it is older than `max_age`.
pub(crate) fn get(url: &str, format: Format, max_age: Option<Duration>) -> Option<Cached> {
    with(|cache| {
        cache
            .get(&(url.to_owned(), format))
            .filter(|entry| max_age.is_none_or(|age| entry.fetched.elapsed() < age))
            .cloned()
    })
}

/// Remember a fresh download. Returns the time it is recorded under.
pub(crate) fn put(url: &str, format: Format, list: Arc<ParsedList>) -> Instant {
    let fetched = Instant::now();
    with(|cache| {
        if cache.len() >= MAX_ENTRIES
            && let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.fetched)
                .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
        cache.insert((url.to_owned(), format), Cached { list, fetched });
    });
    fetched
}

/// Forget every download except the ones in `keep`.
pub(crate) fn retain(keep: &[(String, Format)]) {
    with(|cache| cache.retain(|key, _| keep.contains(key)));
}

// SPDX-License-Identifier: Apache-2.0
//! Bounded Lumen-owned DNS response cache for serve-stale and opt-in persistence.

use hickory_server::proto::{
    op::{Message, ResponseCode},
    rr::RData,
};
use lumen_config::Resolver as Settings;
use lumen_proto::Query;
use rusqlite::{Connection, params};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError, mpsc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

const MEMORY_BYTES_WITHOUT_DISK: u64 = 64 * 1024 * 1024;
const WRITE_QUEUE: usize = 1024;

#[derive(Clone)]
struct Entry {
    response: Vec<u8>,
    stored: u64,
    fresh_until: u64,
    stale_until: u64,
    last_used: u64,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    refreshing: HashSet<String>,
    bytes: u64,
    clock: u64,
}

enum Write {
    Put { key: String, entry: Entry },
    Delete(String),
}

/// Result of a lookup in the Lumen-owned cache.
pub(crate) struct Hit {
    pub(crate) bytes: Vec<u8>,
    pub(crate) stale: bool,
    pub(crate) key: String,
}

/// Memory cache plus an optional blocking persistence worker.
pub(crate) struct ResponseCache {
    state: Mutex<State>,
    max_entries: usize,
    max_bytes: u64,
    stale_enabled: bool,
    stale_age: u64,
    stale_ttl: u32,
    persistent_ttl: Option<u64>,
    writer: Option<mpsc::SyncSender<Write>>,
}

impl ResponseCache {
    pub(crate) fn new(settings: &Settings) -> Result<Option<Self>, String> {
        if !settings.serve_stale.enabled && !settings.persistent_cache.enabled {
            return Ok(None);
        }
        let persistent = &settings.persistent_cache;
        let max_entries = if persistent.enabled {
            persistent.max_entries as usize
        } else {
            settings.cache_entries as usize
        };
        let max_bytes = if persistent.enabled {
            persistent.max_bytes
        } else {
            MEMORY_BYTES_WITHOUT_DISK
        };
        let (entries, writer) = if persistent.enabled {
            let path = persistent
                .path
                .as_deref()
                .ok_or("persistent cache path is missing")?;
            let (connection, entries) = open(path, max_entries, max_bytes)?;
            let (sender, receiver) = mpsc::sync_channel(WRITE_QUEUE);
            let disk_entries = persistent.max_entries;
            let disk_bytes = persistent.max_bytes;
            thread::Builder::new()
                .name("lumen-dns-cache".into())
                .spawn(move || writer_loop(connection, receiver, disk_entries, disk_bytes))
                .map_err(|_| "cannot start persistent cache writer")?;
            (entries, Some(sender))
        } else {
            (HashMap::new(), None)
        };
        let bytes = entries
            .values()
            .map(|entry| entry.response.len() as u64)
            .sum();
        Ok(Some(Self {
            state: Mutex::new(State {
                entries,
                bytes,
                ..State::default()
            }),
            max_entries,
            max_bytes,
            stale_enabled: settings.serve_stale.enabled,
            stale_age: u64::from(settings.serve_stale.max_age_secs),
            stale_ttl: settings.serve_stale.answer_ttl_secs,
            persistent_ttl: persistent
                .enabled
                .then_some(u64::from(persistent.max_ttl_secs)),
            writer,
        }))
    }

    pub(crate) fn lookup(&self, query: &Query, maximum: usize) -> Option<Hit> {
        let key = key(query);
        let now = unix_time();
        let (entry, stale) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.clock = state.clock.saturating_add(1);
            let clock = state.clock;
            let entry = state.entries.get_mut(&key)?;
            entry.last_used = clock;
            if now <= entry.fresh_until {
                (entry.clone(), false)
            } else if self.stale_enabled && now <= entry.stale_until {
                let message = Message::from_vec(&entry.response).ok()?;
                // Serving authenticated data after its TTL can outlive its signatures. Fail closed.
                if message.metadata.authentic_data {
                    return None;
                }
                (entry.clone(), true)
            } else {
                let removed = state.entries.remove(&key)?;
                state.bytes = state.bytes.saturating_sub(removed.response.len() as u64);
                self.write(Write::Delete(key));
                return None;
            }
        };
        render(&entry, query, maximum, stale, self.stale_ttl).map(|bytes| Hit { bytes, stale, key })
    }

    pub(crate) fn store(&self, query: &Query, bytes: &[u8]) {
        let Ok(message) = Message::from_vec(bytes) else {
            return;
        };
        let Some(ttl) = cache_ttl(&message) else {
            return;
        };
        let ttl = self.persistent_ttl.map_or(ttl, |cap| ttl.min(cap));
        if ttl == 0 {
            return;
        }
        let now = unix_time();
        let fresh_until = now.saturating_add(ttl);
        let stale_until = if self.stale_enabled && !message.metadata.authentic_data {
            fresh_until.saturating_add(self.stale_age)
        } else {
            fresh_until
        };
        let key = key(query);
        let mut response = bytes.to_vec();
        // Transaction IDs are per request and never belong in persistent data.
        response[0..2].fill(0);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.clock = state.clock.saturating_add(1);
        let entry = Entry {
            response,
            stored: now,
            fresh_until,
            stale_until,
            last_used: state.clock,
        };
        if entry.response.len() as u64 > self.max_bytes {
            return;
        }
        if let Some(old) = state.entries.insert(key.clone(), entry.clone()) {
            state.bytes = state.bytes.saturating_sub(old.response.len() as u64);
        }
        state.bytes = state.bytes.saturating_add(entry.response.len() as u64);
        while state.entries.len() > self.max_entries || state.bytes > self.max_bytes {
            let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, item)| item.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(old) = state.entries.remove(&oldest) {
                state.bytes = state.bytes.saturating_sub(old.response.len() as u64);
                self.write(Write::Delete(oldest));
            }
        }
        drop(state);
        self.write(Write::Put { key, entry });
    }

    pub(crate) fn begin_refresh(&self, key: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .refreshing
            .insert(key.to_owned())
    }

    pub(crate) fn end_refresh(&self, key: &str) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .refreshing
            .remove(key);
    }

    fn write(&self, command: Write) {
        if let Some(writer) = &self.writer {
            let _ = writer.try_send(command);
        }
    }
}

fn key(query: &Query) -> String {
    let question = &query.message.queries[0];
    let dnssec_ok = query
        .message
        .edns
        .as_ref()
        .is_some_and(|edns| edns.flags().dnssec_ok);
    format!(
        "{}|{:?}|{:?}|{}|{}",
        question.name().to_ascii().to_ascii_lowercase(),
        question.query_type(),
        question.query_class(),
        dnssec_ok,
        query.message.metadata.checking_disabled
    )
}

fn cache_ttl(message: &Message) -> Option<u64> {
    if message.metadata.truncation || message.signature.is_some() {
        return None;
    }
    if !matches!(
        message.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return None;
    }
    if !message.answers.is_empty() {
        return message
            .answers
            .iter()
            .map(|record| u64::from(record.ttl))
            .min();
    }
    message.authorities.iter().find_map(|record| {
        if let RData::SOA(soa) = &record.data {
            Some(u64::from(record.ttl.min(soa.minimum)))
        } else {
            None
        }
    })
}

fn render(
    entry: &Entry,
    query: &Query,
    maximum: usize,
    stale: bool,
    stale_ttl: u32,
) -> Option<Vec<u8>> {
    let mut message = Message::from_vec(&entry.response).ok()?;
    message.metadata.id = query.message.metadata.id;
    message.queries.clone_from(&query.message.queries);
    let age = u32::try_from(unix_time().saturating_sub(entry.stored)).unwrap_or(u32::MAX);
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        record.ttl = if stale {
            stale_ttl
        } else {
            record.ttl.saturating_sub(age)
        };
    }
    if stale {
        message.metadata.authentic_data = false;
    }
    let bytes = message.to_vec().ok()?;
    if bytes.len() <= maximum {
        return Some(bytes);
    }
    let mut truncated = message.truncate();
    truncated.metadata.id = query.message.metadata.id;
    truncated
        .to_vec()
        .ok()
        .filter(|bytes| bytes.len() <= maximum)
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn open(
    path: &Path,
    max_entries: usize,
    max_bytes: u64,
) -> Result<(Connection, HashMap<String, Entry>), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|_| "cannot create persistent cache directory")?;
    }
    match open_once(path, max_entries, max_bytes) {
        Ok(result) => Ok(result),
        Err(_) if path.exists() => {
            let damaged = damaged_path(path);
            fs::rename(path, &damaged).map_err(|_| "cannot move corrupt persistent cache")?;
            open_once(path, max_entries, max_bytes)
        }
        Err(error) => Err(error),
    }
}

fn open_once(
    path: &Path,
    max_entries: usize,
    max_bytes: u64,
) -> Result<(Connection, HashMap<String, Entry>), String> {
    let connection = Connection::open(path).map_err(|_| "cannot open persistent cache")?;
    connection
        .busy_timeout(std::time::Duration::from_secs(2))
        .map_err(|_| "cannot configure persistent cache")?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS responses (
                key TEXT PRIMARY KEY,
                response BLOB NOT NULL,
                stored INTEGER NOT NULL,
                fresh_until INTEGER NOT NULL,
                stale_until INTEGER NOT NULL,
                touched INTEGER NOT NULL
             );
             PRAGMA user_version = 1;",
        )
        .map_err(|_| "cannot migrate persistent cache")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot restrict persistent cache permissions")?;
    }
    let now = unix_time();
    connection
        .execute("DELETE FROM responses WHERE stale_until < ?1", [now])
        .map_err(|_| "cannot prune persistent cache")?;
    let mut entries = HashMap::new();
    let mut bytes = 0_u64;
    {
        let mut statement = connection
            .prepare(
                "SELECT key, response, stored, fresh_until, stale_until, touched
                 FROM responses ORDER BY touched DESC LIMIT ?1",
            )
            .map_err(|_| "cannot read persistent cache")?;
        let rows = statement
            .query_map([max_entries as u64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    Entry {
                        response: row.get(1)?,
                        stored: row.get(2)?,
                        fresh_until: row.get(3)?,
                        stale_until: row.get(4)?,
                        last_used: row.get(5)?,
                    },
                ))
            })
            .map_err(|_| "cannot read persistent cache")?;
        for row in rows {
            let (key, entry) = row.map_err(|_| "cannot decode persistent cache")?;
            let size = entry.response.len() as u64;
            if bytes.saturating_add(size) <= max_bytes && Message::from_vec(&entry.response).is_ok()
            {
                bytes += size;
                entries.insert(key, entry);
            }
        }
    }
    Ok((connection, entries))
}

#[allow(clippy::needless_pass_by_value)] // the writer thread owns both ends
fn writer_loop(
    connection: Connection,
    receiver: mpsc::Receiver<Write>,
    max_entries: u32,
    max_bytes: u64,
) {
    while let Ok(command) = receiver.recv() {
        match command {
            Write::Put { key, entry } => {
                let _ = connection.execute(
                    "INSERT INTO responses(key,response,stored,fresh_until,stale_until,touched)
                     VALUES(?1,?2,?3,?4,?5,?6)
                     ON CONFLICT(key) DO UPDATE SET response=excluded.response,
                     stored=excluded.stored,fresh_until=excluded.fresh_until,
                     stale_until=excluded.stale_until,touched=excluded.touched",
                    params![
                        key,
                        entry.response,
                        entry.stored,
                        entry.fresh_until,
                        entry.stale_until,
                        entry.last_used
                    ],
                );
                let _ = connection.execute(
                    "DELETE FROM responses WHERE key NOT IN
                     (SELECT key FROM responses ORDER BY touched DESC LIMIT ?1)",
                    [max_entries],
                );
                loop {
                    let total: u64 = connection
                        .query_row(
                            "SELECT COALESCE(SUM(length(response)),0) FROM responses",
                            [],
                            |row| row.get(0),
                        )
                        .unwrap_or(0);
                    if total <= max_bytes {
                        break;
                    }
                    if connection
                        .execute(
                            "DELETE FROM responses WHERE key =
                             (SELECT key FROM responses ORDER BY touched ASC LIMIT 1)",
                            [],
                        )
                        .unwrap_or(0)
                        == 0
                    {
                        break;
                    }
                }
            }
            Write::Delete(key) => {
                let _ = connection.execute("DELETE FROM responses WHERE key=?1", [key]);
            }
        }
    }
}

fn damaged_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".corrupt-{}", unix_time()));
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::{
        op::{Message, MessageType, OpCode},
        rr::{Name, Record, RecordType, rdata::A},
    };

    fn query(id: u16) -> Query {
        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.add_query(hickory_server::proto::op::Query::query(
            Name::from_ascii("cache.example.").unwrap(),
            RecordType::A,
        ));
        Query { message }
    }

    fn answer(id: u16, ttl: u32) -> Vec<u8> {
        let mut message = Message::response(id, OpCode::Query);
        message.add_query(query(id).message.queries[0].clone());
        message.add_answer(Record::from_rdata(
            Name::from_ascii("cache.example.").unwrap(),
            ttl,
            hickory_server::proto::rr::RData::A(A::new(192, 0, 2, 1)),
        ));
        message.to_vec().unwrap()
    }

    #[test]
    fn cache_rewrites_ids_and_is_off_by_default() {
        let settings = Settings::default();
        assert!(ResponseCache::new(&settings).unwrap().is_none());
        let mut settings = settings;
        settings.serve_stale.enabled = true;
        let cache = ResponseCache::new(&settings).unwrap().unwrap();
        cache.store(&query(1), &answer(1, 60));
        let hit = cache.lookup(&query(7), 4096).unwrap();
        assert!(!hit.stale);
        assert_eq!(Message::from_vec(&hit.bytes).unwrap().metadata.id, 7);
    }

    #[test]
    fn servfail_and_zero_ttl_are_not_cached() {
        let mut settings = Settings::default();
        settings.serve_stale.enabled = true;
        let cache = ResponseCache::new(&settings).unwrap().unwrap();
        cache.store(&query(1), &answer(1, 0));
        assert!(cache.lookup(&query(1), 4096).is_none());
        let mut failed = Message::response(1, OpCode::Query);
        failed.metadata.response_code = ResponseCode::ServFail;
        cache.store(&query(1), &failed.to_vec().unwrap());
        assert!(cache.lookup(&query(1), 4096).is_none());
    }

    #[test]
    fn stale_answer_has_small_ttl_and_clears_ad() {
        let mut settings = Settings::default();
        settings.serve_stale.enabled = true;
        settings.serve_stale.answer_ttl_secs = 17;
        let cache = ResponseCache::new(&settings).unwrap().unwrap();
        let now = unix_time();
        let key = key(&query(1));
        let response = answer(0, 60);
        {
            let mut state = cache.state.lock().unwrap();
            state.bytes = response.len() as u64;
            state.entries.insert(
                key,
                Entry {
                    response,
                    stored: now.saturating_sub(61),
                    fresh_until: now.saturating_sub(1),
                    stale_until: now + 60,
                    last_used: 0,
                },
            );
        }
        let hit = cache.lookup(&query(9), 4096).unwrap();
        assert!(hit.stale);
        let message = Message::from_vec(&hit.bytes).unwrap();
        assert_eq!(message.answers[0].ttl, 17);
        assert!(!message.metadata.authentic_data);
    }

    #[test]
    fn corrupt_persistent_database_is_moved_aside() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("dns-cache.sqlite");
        fs::write(&path, b"not sqlite").unwrap();
        let mut settings = Settings::default();
        settings.persistent_cache.enabled = true;
        settings.persistent_cache.path = Some(path.clone());
        let cache = ResponseCache::new(&settings).unwrap();
        assert!(cache.is_some());
        assert!(path.is_file());
        assert!(
            fs::read_dir(directory.path())
                .unwrap()
                .flatten()
                .any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("dns-cache.sqlite.corrupt-")
                })
        );
    }
}

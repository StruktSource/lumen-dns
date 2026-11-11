// SPDX-License-Identifier: Apache-2.0
//! Bounded memory and disk copies of downloaded lists.
//!
//! Reloads reuse parsed lists in memory. Managed mode also keeps raw responses beside state, so
//! restarts can reuse fresh data and stale data can be revalidated without downloading it again.

use crate::rules::{Format, ParsedList};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_ENTRIES: usize = 128;
const MAX_DISK_BYTES: u64 = 512 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 4096;
const MAGIC: &[u8] = b"LUMEN-LIST-1\n";

type Key = (String, Format);

#[derive(Clone)]
pub(crate) struct Cached {
    pub list: Arc<ParsedList>,
    pub fetched: Instant,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Validators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
pub(crate) struct DiskHit {
    pub bytes: Vec<u8>,
    pub validators: Validators,
    pub fresh: bool,
    pub fetched: Instant,
}

#[derive(Deserialize, Serialize)]
struct DiskHeader {
    fetched: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

static CACHE: Mutex<Option<HashMap<Key, Cached>>> = Mutex::new(None);
static DISK: Mutex<Option<PathBuf>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut HashMap<Key, Cached>) -> R) -> R {
    let mut guard = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(guard.get_or_insert_with(HashMap::new))
}

pub(crate) fn get(url: &str, format: Format, max_age: Option<Duration>) -> Option<Cached> {
    with(|cache| {
        cache
            .get(&(url.to_owned(), format))
            .filter(|entry| max_age.is_none_or(|age| entry.fetched.elapsed() < age))
            .cloned()
    })
}

pub(crate) fn put(url: &str, format: Format, list: Arc<ParsedList>, fetched: Instant) -> Instant {
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

pub(crate) fn retain(keep: &[(String, Format)]) {
    with(|cache| cache.retain(|key, _| keep.contains(key)));
}

pub(crate) fn configure_disk(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|_| "cannot create filter download cache")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot restrict filter download cache permissions")?;
    }
    *DISK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(path.to_owned());
    Ok(())
}

fn disk_path(url: &str, format: Format) -> Option<PathBuf> {
    let directory = DISK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()?;
    let mut hash = Sha256::new();
    hash.update(match format {
        Format::Domains => b"domains:".as_slice(),
        Format::Hosts => b"hosts:".as_slice(),
        Format::Adblock => b"adblock:".as_slice(),
    });
    hash.update(url.as_bytes());
    let name = hash
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        });
    Some(directory.join(format!("{name}.cache")))
}

fn clean_validator(value: Option<String>) -> Option<String> {
    value.filter(|value| value.len() <= 512 && !value.chars().any(char::is_control))
}

pub(crate) fn disk_get(url: &str, format: Format, max_age: Option<Duration>) -> Option<DiskHit> {
    let path = disk_path(url, format)?;
    let metadata = fs::metadata(&path).ok()?;
    if metadata.len() > (crate::rules::MAX_LIST_BYTES + MAX_HEADER_BYTES) as u64 {
        let _ = fs::remove_file(path);
        return None;
    }
    let mut file = File::open(&path).ok()?;
    let mut magic = vec![0; MAGIC.len()];
    file.read_exact(&mut magic).ok()?;
    if magic != MAGIC {
        let _ = fs::remove_file(path);
        return None;
    }
    let mut length = [0; 4];
    file.read_exact(&mut length).ok()?;
    let header_len = u32::from_be_bytes(length) as usize;
    if header_len > MAX_HEADER_BYTES {
        let _ = fs::remove_file(path);
        return None;
    }
    let mut header = vec![0; header_len];
    file.read_exact(&mut header).ok()?;
    let header: DiskHeader = serde_json::from_slice(&header).ok()?;
    let mut bytes = Vec::new();
    file.take((crate::rules::MAX_LIST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > crate::rules::MAX_LIST_BYTES {
        let _ = fs::remove_file(path);
        return None;
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let age = Duration::from_secs(now.saturating_sub(header.fetched));
    Some(DiskHit {
        bytes,
        validators: Validators {
            etag: clean_validator(header.etag),
            last_modified: clean_validator(header.last_modified),
        },
        fresh: max_age.is_none_or(|limit| age < limit),
        fetched: Instant::now().checked_sub(age).unwrap_or_else(Instant::now),
    })
}

pub(crate) fn disk_put(
    url: &str,
    format: Format,
    bytes: &[u8],
    validators: Validators,
) -> Result<(), String> {
    if bytes.len() > crate::rules::MAX_LIST_BYTES {
        return Err("filter list exceeds the disk cache limit".into());
    }
    let Some(path) = disk_path(url, format) else {
        return Ok(());
    };
    let header = DiskHeader {
        fetched: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch")?
            .as_secs(),
        etag: clean_validator(validators.etag),
        last_modified: clean_validator(validators.last_modified),
    };
    let header = serde_json::to_vec(&header).map_err(|_| "cannot encode filter cache header")?;
    let header_len = u32::try_from(header.len())
        .map_err(|_| "filter cache header is too large")?
        .to_be_bytes();
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = File::create(&temporary).map_err(|_| "cannot write filter download cache")?;
    file.write_all(MAGIC)
        .and_then(|()| file.write_all(&header_len))
        .and_then(|()| file.write_all(&header))
        .and_then(|()| file.write_all(bytes))
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot write filter download cache")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|_| "cannot restrict filter download cache file")?;
    }
    if fs::rename(&temporary, &path).is_err() {
        let _ = fs::remove_file(&path);
        fs::rename(&temporary, &path).map_err(|_| "cannot replace filter download cache")?;
    }
    prune(path.parent().unwrap_or_else(|| Path::new(".")));
    Ok(())
}

fn prune(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    let mut files = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = entry.metadata().ok()?;
            (path.extension().is_some_and(|ext| ext == "cache") && metadata.is_file())
                .then(|| (path, metadata.len(), metadata.modified().ok()))
        })
        .collect::<Vec<_>>();
    files.sort_by_key(|(_, _, modified)| *modified);
    let mut bytes = files.iter().map(|(_, bytes, _)| *bytes).sum::<u64>();
    let mut count = files.len();
    for (path, size, _) in files {
        if count <= MAX_ENTRIES && bytes <= MAX_DISK_BYTES {
            break;
        }
        if fs::remove_file(path).is_ok() {
            count -= 1;
            bytes = bytes.saturating_sub(size);
        }
    }
}

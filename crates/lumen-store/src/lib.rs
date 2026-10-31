// SPDX-License-Identifier: Apache-2.0
//! Versioned local `SQLite` state for configuration, devices, and daemon control.

use lumen_filter::config::Device;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    net::IpAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const SCHEMA_VERSION: i64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredConfig {
    pub source: String,
    pub base_dir: String,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Reload,
    ConfigReload(u64),
    FilterRefresh,
    FilterRollback,
    Shutdown,
}

impl Command {
    fn as_str(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::ConfigReload(_) => "config_reload",
            Self::FilterRefresh => "filter_refresh",
            Self::FilterRollback => "filter_rollback",
            Self::Shutdown => "shutdown",
        }
    }

    fn payload(self) -> Option<u64> {
        match self {
            Self::ConfigReload(revision) => Some(revision),
            _ => None,
        }
    }

    fn parse(value: &str, payload: Option<u64>) -> Result<Self, String> {
        match value {
            "reload" => Ok(Self::Reload),
            "config_reload" => Ok(Self::ConfigReload(
                payload.ok_or("config reload command needs a revision")?,
            )),
            "filter_refresh" => Ok(Self::FilterRefresh),
            "filter_rollback" => Ok(Self::FilterRollback),
            "shutdown" => Ok(Self::Shutdown),
            _ => Err("invalid stored control command".into()),
        }
    }
}

pub struct Store {
    connection: Connection,
}

impl Store {
    /// Open state and apply every pending migration in one transaction.
    ///
    /// # Errors
    /// Returns an error for an unreadable database or failed migration.
    pub fn open(path: &Path) -> Result<Self, String> {
        let connection = Connection::open(path).map_err(database_error)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| "cannot restrict state database permissions".to_owned())?;
        }
        connection
            .busy_timeout(std::time::Duration::from_secs(2))
            .map_err(database_error)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<(), String> {
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(database_error)?;
        if version > SCHEMA_VERSION {
            return Err(format!(
                "state schema {version} is newer than supported schema {SCHEMA_VERSION}"
            ));
        }
        let transaction = self.connection.transaction().map_err(database_error)?;
        if version < 1 {
            transaction
                .execute_batch(
                    "CREATE TABLE config (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    source TEXT NOT NULL,
                    base_dir TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                PRAGMA user_version = 1;",
                )
                .map_err(database_error)?;
        }
        if version < 2 {
            transaction
                .execute_batch(
                    "CREATE TABLE devices (
                    id TEXT PRIMARY KEY,
                    addresses TEXT NOT NULL,
                    profile TEXT,
                    group_id TEXT
                );
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE pending_config (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    source TEXT NOT NULL,
                    base_dir TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    payload INTEGER
                );
                PRAGMA user_version = 2;",
                )
                .map_err(database_error)?;
        }
        transaction.commit().map_err(database_error)
    }

    /// Read active stored configuration.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn config(&self) -> Result<Option<StoredConfig>, String> {
        self.connection
            .query_row(
                "SELECT source, base_dir, revision FROM config WHERE singleton = 1",
                [],
                |row| {
                    Ok(StoredConfig {
                        source: row.get(0)?,
                        base_dir: row.get(1)?,
                        revision: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    /// Store a new configuration revision.
    ///
    /// # Errors
    /// Returns an error when the revision cannot be written.
    pub fn set_config(&mut self, source: &str, base_dir: &Path) -> Result<u64, String> {
        validate_config_record(source, base_dir)?;
        let transaction = self.connection.transaction().map_err(database_error)?;
        let current: Option<u64> = transaction
            .query_row(
                "SELECT revision FROM config WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let revision = current
            .unwrap_or(0)
            .checked_add(1)
            .ok_or("config revision overflow")?;
        transaction.execute(
            "INSERT INTO config(singleton, source, base_dir, revision, updated_at)
             VALUES(1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET source=excluded.source,
             base_dir=excluded.base_dir, revision=excluded.revision, updated_at=excluded.updated_at",
            params![source, base_dir.to_string_lossy(), revision, now()?],
        ).map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(revision)
    }

    /// Stage a configuration revision until the daemon accepts it.
    ///
    /// # Errors
    /// Returns an error when the candidate cannot be written.
    pub fn stage_config(&mut self, source: &str, base_dir: &Path) -> Result<u64, String> {
        validate_config_record(source, base_dir)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let current: Option<u64> = transaction
            .query_row(
                "SELECT revision FROM config WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let staged: Option<u64> = transaction
            .query_row(
                "SELECT revision FROM pending_config WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let current = current.unwrap_or(0);
        let staged = staged.unwrap_or(0);
        let revision = current
            .max(staged)
            .checked_add(1)
            .ok_or("config revision overflow")?;
        transaction.execute(
            "INSERT INTO pending_config(singleton, source, base_dir, revision, updated_at)
             VALUES(1, ?1, ?2, ?3, ?4)
             ON CONFLICT(singleton) DO UPDATE SET source=excluded.source,
             base_dir=excluded.base_dir, revision=excluded.revision, updated_at=excluded.updated_at",
            params![source, base_dir.to_string_lossy(), revision, now()?],
        ).map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(revision)
    }

    /// Read a staged configuration revision.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn staged_config(&self) -> Result<Option<StoredConfig>, String> {
        self.connection
            .query_row(
                "SELECT source, base_dir, revision FROM pending_config WHERE singleton = 1",
                [],
                |row| {
                    Ok(StoredConfig {
                        source: row.get(0)?,
                        base_dir: row.get(1)?,
                        revision: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(database_error)
    }

    /// Promote the staged revision to active configuration.
    ///
    /// # Errors
    /// Returns an error when the transaction fails. A stale revision returns false.
    pub fn promote_staged_config(&mut self, revision: u64) -> Result<bool, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let changed = transaction.execute(
            "INSERT INTO config(singleton, source, base_dir, revision, updated_at)
             SELECT 1, source, base_dir, revision, updated_at FROM pending_config
             WHERE singleton = 1 AND revision = ?1
             ON CONFLICT(singleton) DO UPDATE SET source=excluded.source,
             base_dir=excluded.base_dir, revision=excluded.revision, updated_at=excluded.updated_at",
            [revision],
        ).map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM pending_config WHERE singleton = 1 AND revision = ?1",
                [revision],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(changed != 0)
    }

    /// Drop a rejected staged revision.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn discard_staged_config(&self, revision: u64) -> Result<(), String> {
        self.connection
            .execute(
                "DELETE FROM pending_config WHERE singleton = 1 AND revision = ?1",
                [revision],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// Seed persistent devices once from startup configuration.
    ///
    /// # Errors
    /// Returns an error when a device or transaction is invalid.
    pub fn initialize_devices(&mut self, devices: &[Device]) -> Result<(), String> {
        if self.metadata("devices_initialized")?.is_some() {
            return Ok(());
        }
        let transaction = self.connection.transaction().map_err(database_error)?;
        for device in devices {
            write_device(&transaction, device)?;
        }
        transaction
            .execute(
                "INSERT INTO metadata(key, value) VALUES('devices_initialized', '1')",
                [],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)
    }

    /// Read all persistent devices in stable ID order.
    ///
    /// # Errors
    /// Returns an error for invalid stored data or database access failure.
    pub fn devices(&self) -> Result<Vec<Device>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT id, addresses, profile, group_id FROM devices ORDER BY id")
            .map_err(database_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get(2)?,
                    row.get(3)?,
                ))
            })
            .map_err(database_error)?;
        let mut devices = Vec::new();
        for row in rows {
            let (id, addresses, profile, group) = row.map_err(database_error)?;
            let addresses = addresses
                .lines()
                .map(|value| {
                    value
                        .parse::<IpAddr>()
                        .map_err(|_| "invalid stored device address".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            devices.push(Device {
                id,
                addresses,
                profile,
                group,
            });
        }
        Ok(devices)
    }

    /// Insert or replace one persistent device.
    ///
    /// # Errors
    /// Returns an error for an invalid device or database access failure.
    pub fn set_device(&self, device: &Device) -> Result<(), String> {
        write_device(&self.connection, device)
    }

    /// Remove a device, returning whether it existed.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn remove_device(&self, id: &str) -> Result<bool, String> {
        Ok(self
            .connection
            .execute("DELETE FROM devices WHERE id = ?1", [id])
            .map_err(database_error)?
            != 0)
    }

    /// Queue a local daemon control command.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn enqueue(&self, command: Command) -> Result<i64, String> {
        let pending: u32 = self
            .connection
            .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
            .map_err(database_error)?;
        if pending >= 1024 {
            return Err("too many pending control commands".into());
        }
        self.connection
            .execute(
                "INSERT INTO commands(kind, created_at, payload) VALUES(?1, ?2, ?3)",
                params![command.as_str(), now()?, command.payload()],
            )
            .map_err(database_error)?;
        Ok(self.connection.last_insert_rowid())
    }

    /// Atomically consume the oldest pending command.
    ///
    /// # Errors
    /// Returns an error for invalid stored commands or database access failure.
    pub fn next_command(&mut self) -> Result<Option<(i64, Command)>, String> {
        let transaction = self.connection.transaction().map_err(database_error)?;
        let pending: Option<(i64, String, Option<u64>)> = transaction
            .query_row(
                "SELECT id, kind, payload FROM commands ORDER BY id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(database_error)?;
        let Some((id, kind, payload)) = pending else {
            transaction.commit().map_err(database_error)?;
            return Ok(None);
        };
        transaction
            .execute("DELETE FROM commands WHERE id = ?1", [id])
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(Some((id, Command::parse(&kind, payload)?)))
    }

    /// Update daemon status and its last control error.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn set_status(&self, status: &str, error: Option<&str>) -> Result<(), String> {
        self.set_metadata("daemon_status", status)?;
        self.set_metadata("daemon_error", error.unwrap_or(""))
    }

    /// Read daemon status and its last control error.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn status(&self) -> Result<(Option<String>, Option<String>), String> {
        let status = self.metadata("daemon_status")?;
        let error = self
            .metadata("daemon_error")?
            .filter(|value| !value.is_empty());
        Ok((status, error))
    }

    fn metadata(&self, key: &str) -> Result<Option<String>, String> {
        self.connection
            .query_row("SELECT value FROM metadata WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()
            .map_err(database_error)
    }

    fn set_metadata(&self, key: &str, value: &str) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO metadata(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![key, value],
            )
            .map_err(database_error)?;
        Ok(())
    }
}

fn write_device(connection: &Connection, device: &Device) -> Result<(), String> {
    if !valid_id(&device.id)
        || device.addresses.is_empty()
        || device.addresses.len() > 32
        || (device.profile.is_none() && device.group.is_none())
        || device.profile.as_deref().is_some_and(|id| !valid_id(id))
        || device.group.as_deref().is_some_and(|id| !valid_id(id))
    {
        return Err("invalid persistent device".into());
    }
    let mut unique = std::collections::HashSet::new();
    if device.addresses.iter().any(|address| {
        address.is_unspecified() || address.is_multicast() || !unique.insert(address.to_canonical())
    }) {
        return Err("invalid persistent device address".into());
    }
    let addresses = device
        .addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    connection
        .execute(
            "INSERT INTO devices(id, addresses, profile, group_id) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET addresses=excluded.addresses,
         profile=excluded.profile, group_id=excluded.group_id",
            params![device.id, addresses, device.profile, device.group],
        )
        .map_err(database_error)?;
    Ok(())
}

fn validate_config_record(source: &str, base_dir: &Path) -> Result<(), String> {
    if source.len() > 65536 || base_dir.as_os_str().len() > 4096 {
        return Err("stored config exceeds size limits".into());
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| "system clock is before Unix epoch".into())
}

#[allow(clippy::needless_pass_by_value)] // `map_err` passes the owned error.
fn database_error(error: rusqlite::Error) -> String {
    format!("state database error: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_preserve_config_and_devices_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        let legacy = Connection::open(&path).unwrap();
        legacy
            .execute_batch(
                "CREATE TABLE config (singleton INTEGER PRIMARY KEY, source TEXT NOT NULL,
             base_dir TEXT NOT NULL, revision INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             INSERT INTO config VALUES(1, 'schema_version = 1', '/tmp', 4, 0);
             PRAGMA user_version = 1;",
            )
            .unwrap();
        drop(legacy);

        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.config().unwrap().unwrap().revision, 4);
        assert_eq!(
            store
                .stage_config("schema_version = 1\n", Path::new("/new"))
                .unwrap(),
            5
        );
        assert_eq!(store.config().unwrap().unwrap().revision, 4);
        assert!(store.promote_staged_config(5).unwrap());
        assert_eq!(store.config().unwrap().unwrap().revision, 5);
        assert!(store.staged_config().unwrap().is_none());
        assert_eq!(
            store
                .stage_config("schema_version = 1\n", Path::new("/six"))
                .unwrap(),
            6
        );
        assert_eq!(
            store
                .stage_config("schema_version = 1\n", Path::new("/seven"))
                .unwrap(),
            7
        );
        store.discard_staged_config(6).unwrap();
        assert!(!store.promote_staged_config(6).unwrap());
        assert_eq!(store.staged_config().unwrap().unwrap().revision, 7);
        assert!(store.promote_staged_config(7).unwrap());
        let device = Device {
            id: "phone".into(),
            addresses: vec!["192.0.2.4".parse().unwrap(), "2001:db8::4".parse().unwrap()],
            profile: Some("family".into()),
            group: None,
        };
        store
            .initialize_devices(std::slice::from_ref(&device))
            .unwrap();
        assert_eq!(store.devices().unwrap()[0].addresses, device.addresses);
        store.enqueue(Command::Reload).unwrap();
        assert_eq!(store.next_command().unwrap().unwrap().1, Command::Reload);
        store.enqueue(Command::ConfigReload(6)).unwrap();
        assert_eq!(
            store.next_command().unwrap().unwrap().1,
            Command::ConfigReload(6)
        );
        assert!(store.next_command().unwrap().is_none());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

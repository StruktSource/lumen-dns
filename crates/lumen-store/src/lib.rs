// SPDX-License-Identifier: Apache-2.0
//! Versioned local `SQLite` state for configuration, devices, accounts, and daemon control.

pub mod password;
pub mod totp;

use lumen_filter::config::Device;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    net::IpAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const SCHEMA_VERSION: i64 = 7;

/// Hard cap on saved query history rows, whatever the retention says.
pub const QUERY_LOG_MAX_ROWS: u64 = 500_000;
/// Saved lookups are kept this many days unless an administrator chooses otherwise.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;
/// The longest retention an administrator can choose.
pub const MAX_RETENTION_DAYS: u32 = 90;

/// Opt-in saved query history. Empty and unused unless an administrator turns it on.
const MIGRATION_6: &str = "CREATE TABLE query_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    t INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    qtype TEXT NOT NULL,
                    client TEXT,
                    device TEXT,
                    blocked INTEGER NOT NULL,
                    rcode TEXT NOT NULL,
                    micros INTEGER NOT NULL
                );
                CREATE INDEX query_log_t ON query_log(t);
                PRAGMA user_version = 6;";

/// Stable OIDC subjects map to ordinary local accounts. Provider tokens are never stored.
const MIGRATION_7: &str = "CREATE TABLE oidc_identities (
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (issuer, subject),
                    UNIQUE (user_id)
                );
                CREATE INDEX oidc_identities_user ON oidc_identities(user_id);
                PRAGMA user_version = 7;";

/// Two-step verification (TOTP secret, replay guard, hashed recovery codes).
const MIGRATION_5: &str = "ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN totp_pending TEXT;
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN recovery TEXT NOT NULL DEFAULT '';
PRAGMA user_version = 5;";

/// Console accounts, sessions and applied-config history.
const MIGRATION_4: &str = "CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                    password TEXT NOT NULL,
                    must_change INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    last_login INTEGER
                );
                CREATE TABLE sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    csrf TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    peer TEXT NOT NULL
                );
                CREATE INDEX sessions_user ON sessions(user_id);
                CREATE TABLE config_history (
                    revision INTEGER PRIMARY KEY,
                    source TEXT NOT NULL,
                    applied_at INTEGER NOT NULL,
                    actor TEXT NOT NULL
                );
                ALTER TABLE pending_config ADD COLUMN actor TEXT NOT NULL DEFAULT '';
                INSERT INTO config_history(revision, source, applied_at, actor)
                    SELECT revision, source, updated_at, '' FROM config WHERE singleton = 1;
                PRAGMA user_version = 4;";

/// Durable management action without secrets or request bodies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: i64,
    pub created_at: u64,
    pub actor: String,
    pub role: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub peer: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredConfig {
    pub source: String,
    pub base_dir: String,
    pub revision: u64,
}

/// Console account role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }

    /// # Errors
    /// Rejects any value other than `admin` or `user`.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "admin" => Ok(Self::Admin),
            "user" => Ok(Self::User),
            _ => Err("role must be admin or user".into()),
        }
    }
}

/// Console account without its password record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub role: Role,
    pub must_change: bool,
    pub created_at: u64,
    pub last_login: Option<u64>,
    pub totp_enabled: bool,
}

/// A validated, unexpired browser session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub user: User,
    pub csrf: String,
}

/// One applied configuration revision, newest first in listings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigRevision {
    pub revision: u64,
    pub source: String,
    pub applied_at: u64,
    pub actor: String,
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

/// What the daemon remembers about lookups. Off by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HistoryMode {
    /// Nothing is recorded. Only aggregate counters exist.
    #[default]
    Off,
    /// The last 1,000 lookups, in memory only. Never written to disk.
    Memory,
    /// Lookups are saved to the state database until the retention period ends.
    Saved,
}

impl HistoryMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Memory => "memory",
            Self::Saved => "saved",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "off" => Some(Self::Off),
            "memory" => Some(Self::Memory),
            "saved" => Some(Self::Saved),
            _ => None,
        }
    }
}

/// How much about the person behind a lookup is recorded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HistoryDetail {
    /// Domain, type, result and timing only. No client address or device.
    Anonymous,
    /// Also the client address and the device name.
    #[default]
    Full,
}

impl HistoryDetail {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Full => "full",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "anonymous" => Some(Self::Anonymous),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// Saved history choices: what to record, how detailed, and for how long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryPrefs {
    pub mode: HistoryMode,
    pub detail: HistoryDetail,
    /// How long saved lookups are kept, 1 to [`MAX_RETENTION_DAYS`].
    pub retention_days: u32,
}

impl Default for HistoryPrefs {
    fn default() -> Self {
        Self {
            mode: HistoryMode::Off,
            detail: HistoryDetail::Full,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

/// One saved lookup. `client` and `device` are `None` in anonymous mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryRow {
    /// Unix time in milliseconds.
    pub t: u64,
    pub domain: String,
    pub qtype: String,
    pub client: Option<String>,
    pub device: Option<String>,
    pub blocked: bool,
    pub rcode: String,
    pub micros: u64,
}

/// A saved lookup with its row ID, used to page through history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredQuery {
    pub id: i64,
    pub row: QueryRow,
}

/// Which saved lookups to return. Newest first.
#[derive(Clone, Debug, Default)]
pub struct QueryFilter<'a> {
    /// Case-insensitive text found in the domain, device or client address.
    pub search: Option<&'a str>,
    pub blocked: Option<bool>,
    /// Only rows older than this ID, for paging.
    pub before_id: Option<i64>,
    pub limit: u16,
}

/// Size of the saved query history.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueryLogSummary {
    pub rows: u64,
    pub oldest_ms: Option<u64>,
    pub newest_ms: Option<u64>,
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
        if version < 3 {
            transaction
                .execute_batch(
                    "CREATE TABLE audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    peer TEXT NOT NULL
                );
                CREATE INDEX audit_events_created_at ON audit_events(created_at);
                PRAGMA user_version = 3;",
                )
                .map_err(database_error)?;
        }
        if version < 4 {
            transaction
                .execute_batch(MIGRATION_4)
                .map_err(database_error)?;
        }
        if version < 5 {
            transaction
                .execute_batch(MIGRATION_5)
                .map_err(database_error)?;
        }
        if version < 6 {
            transaction
                .execute_batch(MIGRATION_6)
                .map_err(database_error)?;
        }
        if version < 7 {
            transaction
                .execute_batch(MIGRATION_7)
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
        record_history(&transaction, revision, source, "")?;
        transaction.commit().map_err(database_error)?;
        Ok(revision)
    }

    /// Stage a configuration revision until the daemon accepts it.
    ///
    /// # Errors
    /// Returns an error when the candidate cannot be written.
    pub fn stage_config(&mut self, source: &str, base_dir: &Path) -> Result<u64, String> {
        self.stage_config_by(source, base_dir, "")
    }

    /// Stage a revision and remember who proposed it.
    ///
    /// # Errors
    /// Returns an error when the candidate cannot be written.
    pub fn stage_config_by(
        &mut self,
        source: &str,
        base_dir: &Path,
        actor: &str,
    ) -> Result<u64, String> {
        validate_config_record(source, base_dir)?;
        if !valid_audit_field(actor, 64) && !actor.is_empty() {
            return Err("invalid actor".into());
        }
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
            "INSERT INTO pending_config(singleton, source, base_dir, revision, updated_at, actor)
             VALUES(1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET source=excluded.source,
             base_dir=excluded.base_dir, revision=excluded.revision, updated_at=excluded.updated_at,
             actor=excluded.actor",
            params![source, base_dir.to_string_lossy(), revision, now()?, actor],
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
        let proposer: Option<(String, String)> = transaction
            .query_row(
                "SELECT source, actor FROM pending_config WHERE singleton = 1 AND revision = ?1",
                [revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(database_error)?;
        if let Some((source, actor)) = &proposer {
            record_history(&transaction, revision, source, actor)?;
        }
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

    /// Append one bounded management audit event.
    ///
    /// # Errors
    /// Returns an error for invalid fields or failed database access.
    pub fn append_audit(
        &mut self,
        actor: &str,
        role: &str,
        action: &str,
        target: &str,
        outcome: &str,
        peer: &str,
    ) -> Result<i64, String> {
        if !valid_audit_field(actor, 64)
            || !valid_audit_field(role, 16)
            || !valid_audit_field(action, 64)
            || !valid_audit_field(target, 256)
            || !valid_audit_field(outcome, 32)
            || !valid_audit_field(peer, 64)
        {
            return Err("invalid audit event".into());
        }
        let transaction = self.connection.transaction().map_err(database_error)?;
        transaction
            .execute(
                "INSERT INTO audit_events(created_at, actor, role, action, target, outcome, peer)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![now()?, actor, role, action, target, outcome, peer],
            )
            .map_err(database_error)?;
        let id = transaction.last_insert_rowid();
        transaction
            .execute(
                "DELETE FROM audit_events WHERE id NOT IN
                 (SELECT id FROM audit_events ORDER BY id DESC LIMIT 10000)",
                [],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(id)
    }

    /// Read newest audit events first with a hard result cap.
    ///
    /// # Errors
    /// Returns an error for invalid limits or failed database access.
    pub fn audit_events(&self, limit: u16) -> Result<Vec<AuditEvent>, String> {
        if !(1..=1000).contains(&limit) {
            return Err("audit limit must be in 1..=1000".into());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, created_at, actor, role, action, target, outcome, peer
                 FROM audit_events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([limit], |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    actor: row.get(2)?,
                    role: row.get(3)?,
                    action: row.get(4)?,
                    target: row.get(5)?,
                    outcome: row.get(6)?,
                    peer: row.get(7)?,
                })
            })
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
    }

    /// Read a console setting. Settings never collide with internal metadata.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn setting(&self, key: &str) -> Result<Option<String>, String> {
        self.metadata(&format!("setting:{key}"))
    }

    /// Write a console setting.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.set_metadata(&format!("setting:{key}"), value)
    }

    /// Remove a console setting.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn clear_setting(&self, key: &str) -> Result<(), String> {
        self.connection
            .execute(
                "DELETE FROM metadata WHERE key = ?1",
                [format!("setting:{key}")],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// Save a batch of lookups in one transaction.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn insert_queries(&mut self, rows: &[QueryRow]) -> Result<(), String> {
        if rows.is_empty() {
            return Ok(());
        }
        let transaction = self.connection.transaction().map_err(database_error)?;
        {
            let mut statement = transaction
                .prepare_cached(
                    "INSERT INTO query_log(t, domain, qtype, client, device, blocked, rcode, micros)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                )
                .map_err(database_error)?;
            for row in rows {
                statement
                    .execute(params![
                        row.t,
                        row.domain,
                        row.qtype,
                        row.client,
                        row.device,
                        row.blocked,
                        row.rcode,
                        row.micros
                    ])
                    .map_err(database_error)?;
            }
        }
        transaction.commit().map_err(database_error)
    }

    /// Read saved lookups, newest first.
    ///
    /// # Errors
    /// Returns an error when `limit` is not 1-1000 or database access fails.
    pub fn query_log(&self, filter: &QueryFilter<'_>) -> Result<Vec<StoredQuery>, String> {
        if !(1..=1000).contains(&filter.limit) {
            return Err("limit must be 1-1000".into());
        }
        let search = filter.search.map(str::to_lowercase).unwrap_or_default();
        let blocked: Option<i64> = filter.blocked.map(i64::from);
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT id, t, domain, qtype, client, device, blocked, rcode, micros
                 FROM query_log
                 WHERE (?1 = '' OR instr(lower(domain || ' ' || ifnull(device, '') || ' ' || ifnull(client, '')), ?1) > 0)
                   AND (?2 IS NULL OR blocked = ?2)
                   AND (?3 IS NULL OR id < ?3)
                 ORDER BY id DESC LIMIT ?4",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map(
                params![search, blocked, filter.before_id, filter.limit],
                |row| {
                    Ok(StoredQuery {
                        id: row.get(0)?,
                        row: QueryRow {
                            t: row.get(1)?,
                            domain: row.get(2)?,
                            qtype: row.get(3)?,
                            client: row.get(4)?,
                            device: row.get(5)?,
                            blocked: row.get(6)?,
                            rcode: row.get(7)?,
                            micros: row.get(8)?,
                        },
                    })
                },
            )
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
    }

    /// How many lookups are saved and how far back they go.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn query_log_summary(&self) -> Result<QueryLogSummary, String> {
        self.connection
            .query_row(
                "SELECT count(*), min(t), max(t) FROM query_log",
                [],
                |row| {
                    Ok(QueryLogSummary {
                        rows: row.get(0)?,
                        oldest_ms: row.get(1)?,
                        newest_ms: row.get(2)?,
                    })
                },
            )
            .map_err(database_error)
    }

    /// Delete lookups older than `cutoff_ms`, then the oldest rows beyond `max_rows`.
    /// Returns how many rows were removed.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn prune_query_log(&self, cutoff_ms: u64, max_rows: u64) -> Result<u64, String> {
        let by_age = self
            .connection
            .execute("DELETE FROM query_log WHERE t < ?1", [cutoff_ms])
            .map_err(database_error)?;
        let by_size = self
            .connection
            .execute(
                "DELETE FROM query_log WHERE id <= (SELECT id FROM query_log ORDER BY id DESC LIMIT 1 OFFSET ?1)",
                [max_rows],
            )
            .map_err(database_error)?;
        Ok((by_age + by_size) as u64)
    }

    /// Delete every saved lookup. Returns how many rows were removed.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn clear_query_log(&self) -> Result<u64, String> {
        let removed = self
            .connection
            .execute("DELETE FROM query_log", [])
            .map_err(database_error)?;
        Ok(removed as u64)
    }

    /// The history choices. The older `history` flag means memory mode until a mode is chosen.
    /// Unreadable or out-of-range values fall back to the private defaults.
    #[must_use]
    pub fn history_prefs(&self) -> HistoryPrefs {
        let get = |key: &str| self.setting(key).ok().flatten();
        let mode = get("history_mode")
            .as_deref()
            .and_then(HistoryMode::parse)
            .unwrap_or_else(|| {
                if get("history").as_deref() == Some("1") {
                    HistoryMode::Memory
                } else {
                    HistoryMode::Off
                }
            });
        let detail = get("history_detail")
            .as_deref()
            .and_then(HistoryDetail::parse)
            .unwrap_or_default();
        let retention_days = get("history_days")
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|days| (1..=MAX_RETENTION_DAYS).contains(days))
            .unwrap_or(DEFAULT_RETENTION_DAYS);
        HistoryPrefs {
            mode,
            detail,
            retention_days,
        }
    }

    /// Save the history choices.
    ///
    /// # Errors
    /// Rejects a retention outside 1-90 days or a failed database write.
    pub fn set_history_prefs(&self, prefs: &HistoryPrefs) -> Result<(), String> {
        if !(1..=MAX_RETENTION_DAYS).contains(&prefs.retention_days) {
            return Err(format!("retention must be 1-{MAX_RETENTION_DAYS} days"));
        }
        self.set_setting("history_mode", prefs.mode.as_str())?;
        self.set_setting("history_detail", prefs.detail.as_str())?;
        self.set_setting("history_days", &prefs.retention_days.to_string())?;
        // The older flag must not bring a switched-off history back.
        self.clear_setting("history")
    }

    /// Applied configuration revisions, newest first.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn config_history(&self, limit: u16) -> Result<Vec<ConfigRevision>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT revision, source, applied_at, actor FROM config_history
                 ORDER BY revision DESC LIMIT ?1",
            )
            .map_err(database_error)?;
        let rows = statement
            .query_map([limit.clamp(1, 100)], |row| {
                Ok(ConfigRevision {
                    revision: row.get(0)?,
                    source: row.get(1)?,
                    applied_at: row.get(2)?,
                    actor: row.get(3)?,
                })
            })
            .map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
    }

    /// Number of console accounts.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn user_count(&self) -> Result<u64, String> {
        self.connection
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(database_error)
    }

    /// Create the first administrator. Fails once any account exists.
    ///
    /// # Errors
    /// Returns an error when an account exists or the name is invalid.
    pub fn create_first_admin(&mut self, name: &str, record: &str) -> Result<User, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let count: u64 = transaction
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .map_err(database_error)?;
        if count != 0 {
            return Err("setup is already complete".into());
        }
        let user = insert_user(&transaction, name, Role::Admin, record, false)?;
        transaction.commit().map_err(database_error)?;
        Ok(user)
    }

    /// Create an account with a stored password record.
    ///
    /// # Errors
    /// Returns an error for an invalid or duplicate name.
    pub fn create_user(
        &mut self,
        name: &str,
        role: Role,
        record: &str,
        must_change: bool,
    ) -> Result<User, String> {
        let transaction = self.connection.transaction().map_err(database_error)?;
        let user = insert_user(&transaction, name, role, record, must_change)?;
        transaction.commit().map_err(database_error)?;
        Ok(user)
    }

    /// All accounts in name order.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn users(&self) -> Result<Vec<User>, String> {
        let mut statement = self
            .connection
            .prepare(&format!("{USER_COLUMNS} ORDER BY name"))
            .map_err(database_error)?;
        let rows = statement.query_map([], read_user).map_err(database_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(database_error)
    }

    /// An account and its stored password record.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn user_with_record(&self, name: &str) -> Result<Option<(User, String)>, String> {
        self.connection
            .query_row(
                "SELECT id, name, role, must_change, created_at, last_login, totp_enabled, password
                 FROM users WHERE name = ?1",
                [name],
                |row| Ok((read_user(row)?, row.get::<_, String>(7)?)),
            )
            .optional()
            .map_err(database_error)
    }

    /// Find a stable `OIDC` identity or create a local account for its first login with `role`.
    /// The role is not changed on later logins, and existing local usernames are never linked
    /// implicitly.
    ///
    /// # Errors
    /// Returns an error for invalid claims, password hashing, or database access.
    pub fn oidc_user(
        &mut self,
        issuer: &str,
        subject: &str,
        preferred_name: Option<&str>,
        role: Role,
    ) -> Result<(User, bool), String> {
        if issuer.is_empty()
            || issuer.len() > 2048
            || subject.is_empty()
            || subject.len() > 512
            || issuer.chars().any(char::is_control)
            || subject.chars().any(char::is_control)
        {
            return Err("invalid OIDC identity claims".into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let existing = transaction
            .query_row(
                &format!(
                    "{USER_COLUMNS} WHERE id = (SELECT user_id FROM oidc_identities
                     WHERE issuer = ?1 AND subject = ?2)"
                ),
                params![issuer, subject],
                read_user,
            )
            .optional()
            .map_err(database_error)?;
        if let Some(user) = existing {
            transaction.commit().map_err(database_error)?;
            return Ok((user, false));
        }
        let name = available_oidc_name(&transaction, preferred_name, issuer, subject)?;
        let record = password::hash(&password::random_hex(32)?)?;
        let user = insert_user(&transaction, &name, role, &record, false)?;
        transaction
            .execute(
                "INSERT INTO oidc_identities(issuer, subject, user_id, created_at)
                 VALUES(?1, ?2, ?3, ?4)",
                params![issuer, subject, user.id, now()?],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok((user, true))
    }

    /// Change a role. The last administrator cannot be demoted.
    ///
    /// # Errors
    /// Returns an error for an unknown account or when no administrator would remain.
    pub fn set_role(&mut self, name: &str, role: Role) -> Result<(), String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if role != Role::Admin && last_admin(&transaction, name)? {
            return Err("there must be at least one administrator".into());
        }
        let changed = transaction
            .execute(
                "UPDATE users SET role = ?1 WHERE name = ?2",
                params![role.as_str(), name],
            )
            .map_err(database_error)?;
        if changed == 0 {
            return Err("unknown user".into());
        }
        transaction.commit().map_err(database_error)
    }

    /// Replace a password record and end all of that account's sessions.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn set_password(
        &mut self,
        name: &str,
        record: &str,
        must_change: bool,
    ) -> Result<bool, String> {
        let transaction = self.connection.transaction().map_err(database_error)?;
        let changed = transaction
            .execute(
                "UPDATE users SET password = ?1, must_change = ?2 WHERE name = ?3",
                params![record, must_change, name],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE name = ?1)",
                [name],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(changed != 0)
    }

    /// Delete an account and its sessions. The last administrator is protected.
    ///
    /// # Errors
    /// Returns an error when no administrator would remain.
    pub fn delete_user(&mut self, name: &str) -> Result<bool, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        if last_admin(&transaction, name)? {
            return Err("there must be at least one administrator".into());
        }
        transaction
            .execute(
                "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE name = ?1)",
                [name],
            )
            .map_err(database_error)?;
        transaction
            .execute(
                "DELETE FROM oidc_identities WHERE user_id = (SELECT id FROM users WHERE name = ?1)",
                [name],
            )
            .map_err(database_error)?;
        let changed = transaction
            .execute("DELETE FROM users WHERE name = ?1", [name])
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(changed != 0)
    }

    /// Begin enrolment: remember a secret that is not active until a code proves it.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn set_totp_pending(&self, name: &str, secret: &str) -> Result<(), String> {
        self.connection
            .execute(
                "UPDATE users SET totp_pending = ?1 WHERE name = ?2",
                params![secret, name],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// The secret awaiting confirmation, if any.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn totp_pending(&self, name: &str) -> Result<Option<String>, String> {
        Ok(self
            .connection
            .query_row(
                "SELECT totp_pending FROM users WHERE name = ?1",
                [name],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(database_error)?
            .flatten())
    }

    /// Turn two-step verification on with the confirmed secret and hashed recovery codes.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn enable_totp(
        &self,
        name: &str,
        step: u64,
        recovery_hashes: &[String],
    ) -> Result<(), String> {
        self.connection
            .execute(
                "UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_enabled = 1,
                 totp_last_step = ?1, recovery = ?2 WHERE name = ?3 AND totp_pending IS NOT NULL",
                params![step, recovery_hashes.join("\n"), name],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// Turn two-step verification off and forget its secrets.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn disable_totp(&self, name: &str) -> Result<bool, String> {
        let changed = self
            .connection
            .execute(
                "UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_enabled = 0,
                 totp_last_step = 0, recovery = '' WHERE name = ?1",
                [name],
            )
            .map_err(database_error)?;
        Ok(changed != 0)
    }

    /// The active secret and the last accepted time step.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn totp_secret(&self, name: &str) -> Result<Option<(String, u64)>, String> {
        Ok(self
            .connection
            .query_row(
                "SELECT totp_secret, totp_last_step FROM users WHERE name = ?1 AND totp_enabled = 1",
                [name],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()
            .map_err(database_error)?
            .and_then(|(secret, step)| secret.map(|s| (s, step))))
    }

    /// Accept a time step once. A code cannot be used twice.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn claim_totp_step(&self, name: &str, step: u64) -> Result<bool, String> {
        let changed = self
            .connection
            .execute(
                "UPDATE users SET totp_last_step = ?1 WHERE name = ?2 AND totp_last_step < ?1",
                params![step, name],
            )
            .map_err(database_error)?;
        Ok(changed != 0)
    }

    /// Spend one recovery code (by its hash). Returns whether it matched.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn use_recovery_code(&mut self, name: &str, hash: &str) -> Result<bool, String> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(database_error)?;
        let stored: Option<String> = transaction
            .query_row(
                "SELECT recovery FROM users WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        let Some(stored) = stored else {
            return Ok(false);
        };
        let mut codes: Vec<&str> = stored.lines().filter(|l| !l.is_empty()).collect();
        let Some(position) = codes.iter().position(|code| *code == hash) else {
            return Ok(false);
        };
        codes.remove(position);
        transaction
            .execute(
                "UPDATE users SET recovery = ?1 WHERE name = ?2",
                params![codes.join("\n"), name],
            )
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(true)
    }

    /// How many recovery codes remain.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn recovery_remaining(&self, name: &str) -> Result<usize, String> {
        let stored: Option<String> = self
            .connection
            .query_row(
                "SELECT recovery FROM users WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(database_error)?;
        Ok(stored.map_or(0, |text| text.lines().filter(|l| !l.is_empty()).count()))
    }

    /// Remember a successful sign-in.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn record_login(&self, id: i64) -> Result<(), String> {
        self.connection
            .execute(
                "UPDATE users SET last_login = ?1 WHERE id = ?2",
                params![now()?, id],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// Store a new session by the hash of its secret.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn create_session(
        &self,
        user_id: i64,
        token_hash: &str,
        csrf: &str,
        peer: &str,
    ) -> Result<(), String> {
        let now = now()?;
        self.connection
            .execute(
                "INSERT INTO sessions(token_hash, user_id, csrf, created_at, last_seen, peer)
                 VALUES(?1, ?2, ?3, ?4, ?4, ?5)",
                params![token_hash, user_id, csrf, now, peer],
            )
            .map_err(database_error)?;
        self.connection
            .execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND token_hash NOT IN
                 (SELECT token_hash FROM sessions WHERE user_id = ?1 ORDER BY last_seen DESC LIMIT 20)",
                [user_id],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// Look up a live session. Expired sessions are deleted.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn session(
        &self,
        token_hash: &str,
        idle_secs: u64,
        max_secs: u64,
    ) -> Result<Option<Session>, String> {
        let now = now()?;
        let found: Option<(User, String, u64, u64)> = self
            .connection
            .query_row(
                "SELECT u.id, u.name, u.role, u.must_change, u.created_at, u.last_login,
                        u.totp_enabled, s.csrf, s.created_at, s.last_seen
                 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1",
                [token_hash],
                |row| {
                    Ok((
                        read_user(row)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, u64>(8)?,
                        row.get::<_, u64>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(database_error)?;
        let Some((user, csrf, created, seen)) = found else {
            return Ok(None);
        };
        if now.saturating_sub(seen) > idle_secs || now.saturating_sub(created) > max_secs {
            self.delete_session(token_hash)?;
            return Ok(None);
        }
        if now.saturating_sub(seen) >= 15 {
            self.connection
                .execute(
                    "UPDATE sessions SET last_seen = ?1 WHERE token_hash = ?2",
                    params![now, token_hash],
                )
                .map_err(database_error)?;
        }
        Ok(Some(Session { user, csrf }))
    }

    /// End one session.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn delete_session(&self, token_hash: &str) -> Result<(), String> {
        self.connection
            .execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])
            .map_err(database_error)?;
        Ok(())
    }

    /// End every session of an account except an optional one to keep.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn delete_user_sessions(&self, user_id: i64, keep: Option<&str>) -> Result<(), String> {
        self.connection
            .execute(
                "DELETE FROM sessions WHERE user_id = ?1 AND token_hash <> ?2",
                params![user_id, keep.unwrap_or("")],
            )
            .map_err(database_error)?;
        Ok(())
    }

    /// Delete sessions past their idle or absolute lifetime.
    ///
    /// # Errors
    /// Returns an error when database access fails.
    pub fn purge_sessions(&self, idle_secs: u64, max_secs: u64) -> Result<(), String> {
        let now = now()?;
        self.connection
            .execute(
                "DELETE FROM sessions WHERE ?1 - last_seen > ?2 OR ?1 - created_at > ?3",
                params![now, idle_secs, max_secs],
            )
            .map_err(database_error)?;
        Ok(())
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

const USER_COLUMNS: &str =
    "SELECT id, name, role, must_change, created_at, last_login, totp_enabled FROM users";

fn read_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let role: String = row.get(2)?;
    Ok(User {
        id: row.get(0)?,
        name: row.get(1)?,
        role: Role::parse(&role).map_err(|_| rusqlite::Error::InvalidQuery)?,
        must_change: row.get::<_, i64>(3)? != 0,
        created_at: row.get(4)?,
        last_login: row.get(5)?,
        totp_enabled: row.get::<_, i64>(6)? != 0,
    })
}

fn valid_username(name: &str) -> bool {
    let mut chars = name.chars();
    (3..=32).contains(&name.len())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn available_oidc_name(
    connection: &Connection,
    preferred: Option<&str>,
    issuer: &str,
    subject: &str,
) -> Result<String, String> {
    let candidate = preferred
        .unwrap_or("oidc-user")
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    let candidate = candidate.trim_matches(['.', '_', '-']);
    let mut base = if candidate
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase())
    {
        candidate.to_owned()
    } else {
        format!("oidc-{candidate}")
    };
    base.truncate(32);
    if valid_username(&base) && !username_exists(connection, &base)? {
        return Ok(base);
    }
    let suffix = password::sha256_hex(&format!("{issuer}\0{subject}"));
    base.truncate(23);
    while base.ends_with(['.', '_', '-']) {
        base.pop();
    }
    if base.len() < 3 || !base.starts_with(|c: char| c.is_ascii_lowercase()) {
        base = "oidc-user".into();
    }
    let candidate = format!("{base}-{}", &suffix[..8]);
    if username_exists(connection, &candidate)? {
        return Err("OIDC username collision".into());
    }
    Ok(candidate)
}

fn username_exists(connection: &Connection, name: &str) -> Result<bool, String> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE name = ?1)",
            [name],
            |row| row.get(0),
        )
        .map_err(database_error)
}

fn insert_user(
    connection: &Connection,
    name: &str,
    role: Role,
    record: &str,
    must_change: bool,
) -> Result<User, String> {
    if !valid_username(name) {
        return Err("username must be 3-32 lowercase letters, digits, dot, dash or underscore, starting with a letter".into());
    }
    if !record.starts_with("pbkdf2-sha256$") {
        return Err("invalid password record".into());
    }
    let created = now()?;
    connection
        .execute(
            "INSERT INTO users(name, role, password, must_change, created_at) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![name, role.as_str(), record, must_change, created],
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(failure, _)
                if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                "that username is taken".to_owned()
            }
            other => database_error(other),
        })?;
    Ok(User {
        id: connection.last_insert_rowid(),
        name: name.to_owned(),
        role,
        must_change,
        created_at: created,
        last_login: None,
        totp_enabled: false,
    })
}

/// True when removing or demoting `name` would leave no administrator.
fn last_admin(connection: &Connection, name: &str) -> Result<bool, String> {
    let admins: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'",
            [],
            |row| row.get(0),
        )
        .map_err(database_error)?;
    let is_admin: bool = connection
        .query_row(
            "SELECT role = 'admin' FROM users WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?
        .unwrap_or(false);
    Ok(is_admin && admins <= 1)
}

fn record_history(
    connection: &Connection,
    revision: u64,
    source: &str,
    actor: &str,
) -> Result<(), String> {
    connection
        .execute(
            "INSERT OR REPLACE INTO config_history(revision, source, applied_at, actor)
             VALUES(?1, ?2, ?3, ?4)",
            params![revision, source, now()?, actor],
        )
        .map_err(database_error)?;
    connection
        .execute(
            "DELETE FROM config_history WHERE revision NOT IN
             (SELECT revision FROM config_history ORDER BY revision DESC LIMIT 50)",
            [],
        )
        .map_err(database_error)?;
    Ok(())
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

fn valid_audit_field(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
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
        store
            .append_audit(
                "admin",
                "admin",
                "post",
                "/v1/reload",
                "accepted",
                "127.0.0.1",
            )
            .unwrap();
        let audit = store.audit_events(10).unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].target, "/v1/reload");
        assert!(store.audit_events(0).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn accounts_sessions_and_history() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.user_count().unwrap(), 0);
        let record = "pbkdf2-sha256$1$aa$bb";
        let admin = store.create_first_admin("admin", record).unwrap();
        assert_eq!(admin.role, Role::Admin);
        assert!(store.create_first_admin("other", record).is_err());
        assert!(
            store
                .create_user("Bad Name", Role::User, record, false)
                .is_err()
        );
        let anna = store.create_user("anna", Role::User, record, true).unwrap();
        assert!(anna.must_change);
        assert!(
            store
                .create_user("anna", Role::User, record, false)
                .unwrap_err()
                .contains("taken")
        );
        assert_eq!(store.users().unwrap().len(), 2);
        assert!(
            store
                .set_role("admin", Role::User)
                .unwrap_err()
                .contains("administrator")
        );
        assert!(
            store
                .delete_user("admin")
                .unwrap_err()
                .contains("administrator")
        );
        store.set_role("anna", Role::Admin).unwrap();
        store.set_role("admin", Role::User).unwrap();
        store.set_role("admin", Role::Admin).unwrap();

        store
            .create_session(anna.id, "hash-a", "csrf-a", "127.0.0.1")
            .unwrap();
        let session = store.session("hash-a", 60, 3600).unwrap().unwrap();
        assert_eq!(
            (session.user.name.as_str(), session.csrf.as_str()),
            ("anna", "csrf-a")
        );
        assert!(store.session("missing", 60, 3600).unwrap().is_none());
        store
            .set_password("anna", "pbkdf2-sha256$1$cc$dd", false)
            .unwrap();
        assert!(store.session("hash-a", 60, 3600).unwrap().is_none());
        assert_eq!(
            store.user_with_record("anna").unwrap().unwrap().1,
            "pbkdf2-sha256$1$cc$dd"
        );
        assert!(store.delete_user("anna").unwrap());
        assert!(store.user_with_record("anna").unwrap().is_none());

        store.set_setting("session_idle_minutes", "45").unwrap();
        assert_eq!(
            store.setting("session_idle_minutes").unwrap().as_deref(),
            Some("45")
        );
        assert_eq!(store.setting("daemon_status").unwrap(), None);
        store.clear_setting("session_idle_minutes").unwrap();
        assert_eq!(store.setting("session_idle_minutes").unwrap(), None);

        store
            .set_config("schema_version = 1\n", directory.path())
            .unwrap();
        let staged = store
            .stage_config_by("schema_version = 1\n# second\n", directory.path(), "admin")
            .unwrap();
        assert!(store.promote_staged_config(staged).unwrap());
        let history = store.config_history(10).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(
            (history[0].revision, history[0].actor.as_str()),
            (staged, "admin")
        );
    }

    #[test]
    fn schema_three_upgrades_to_four() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        {
            let connection = Connection::open(&path).unwrap();
            connection.execute_batch(
                "CREATE TABLE config (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), source TEXT NOT NULL, base_dir TEXT NOT NULL, revision INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 CREATE TABLE devices (id TEXT PRIMARY KEY, addresses TEXT NOT NULL, profile TEXT, group_id TEXT);
                 CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE pending_config (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), source TEXT NOT NULL, base_dir TEXT NOT NULL, revision INTEGER NOT NULL, updated_at INTEGER NOT NULL);
                 CREATE TABLE commands (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, created_at INTEGER NOT NULL, payload INTEGER);
                 CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, actor TEXT NOT NULL, role TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL, peer TEXT NOT NULL);
                 INSERT INTO config VALUES(1, 'schema_version = 1', '/tmp', 7, 1000);
                 PRAGMA user_version = 3;",
            ).unwrap();
        }
        let store = Store::open(&path).unwrap();
        assert_eq!(store.config().unwrap().unwrap().revision, 7);
        assert_eq!(store.config_history(5).unwrap()[0].revision, 7);
        assert_eq!(store.user_count().unwrap(), 0);
    }

    fn row(t: u64, domain: &str, blocked: bool, client: Option<&str>) -> QueryRow {
        QueryRow {
            t,
            domain: domain.into(),
            qtype: "A".into(),
            client: client.map(Into::into),
            device: client.map(|_| "tablet".to_owned()),
            blocked,
            rcode: if blocked { "NXDOMAIN" } else { "NOERROR" }.into(),
            micros: 1500,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Scenario test reads top to bottom.
    fn query_log_saves_filters_pages_prunes_and_clears() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.db")).unwrap();
        assert_eq!(
            store.query_log_summary().unwrap(),
            QueryLogSummary::default()
        );
        store
            .insert_queries(&[
                row(1_000, "old.example", false, None),
                row(2_000, "ads.example", true, Some("192.0.2.10")),
                row(3_000, "News.Example", false, Some("192.0.2.11")),
            ])
            .unwrap();
        store.insert_queries(&[]).unwrap();
        let summary = store.query_log_summary().unwrap();
        assert_eq!(
            (summary.rows, summary.oldest_ms, summary.newest_ms),
            (3, Some(1_000), Some(3_000))
        );

        let all = store
            .query_log(&QueryFilter {
                limit: 10,
                ..QueryFilter::default()
            })
            .unwrap();
        let domains: Vec<_> = all.iter().map(|q| q.row.domain.as_str()).collect();
        assert_eq!(domains, ["News.Example", "ads.example", "old.example"]);
        // Anonymous rows keep no client or device.
        assert_eq!(all[2].row.client, None);
        assert_eq!(all[2].row.device, None);

        let blocked = store
            .query_log(&QueryFilter {
                blocked: Some(true),
                limit: 10,
                ..QueryFilter::default()
            })
            .unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].row.domain, "ads.example");

        // Case-insensitive search across domain, device and client.
        for needle in ["NEWS", "tablet", "192.0.2.11"] {
            let found = store
                .query_log(&QueryFilter {
                    search: Some(needle),
                    limit: 10,
                    ..QueryFilter::default()
                })
                .unwrap();
            assert!(
                found.iter().any(|q| q.row.domain == "News.Example"),
                "{needle}"
            );
        }
        // LIKE wildcards are literal text, not patterns.
        assert!(
            store
                .query_log(&QueryFilter {
                    search: Some("%"),
                    limit: 10,
                    ..QueryFilter::default()
                })
                .unwrap()
                .is_empty()
        );

        // Paging: next page starts after the last ID of the first.
        let first = store
            .query_log(&QueryFilter {
                limit: 2,
                ..QueryFilter::default()
            })
            .unwrap();
        let next = store
            .query_log(&QueryFilter {
                limit: 2,
                before_id: Some(first[1].id),
                ..QueryFilter::default()
            })
            .unwrap();
        assert_eq!((first.len(), next.len()), (2, 1));
        assert_eq!(next[0].row.domain, "old.example");
        assert!(
            store
                .query_log(&QueryFilter {
                    limit: 0,
                    ..QueryFilter::default()
                })
                .is_err()
        );
        assert!(
            store
                .query_log(&QueryFilter {
                    limit: 1001,
                    ..QueryFilter::default()
                })
                .is_err()
        );

        // Retention by age, then the row cap keeps only the newest rows.
        assert_eq!(store.prune_query_log(1_500, 100).unwrap(), 1);
        assert_eq!(store.prune_query_log(0, 1).unwrap(), 1);
        let left = store
            .query_log(&QueryFilter {
                limit: 10,
                ..QueryFilter::default()
            })
            .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].row.domain, "News.Example");

        assert_eq!(store.clear_query_log().unwrap(), 1);
        assert_eq!(store.query_log_summary().unwrap().rows, 0);
    }

    #[test]
    fn external_identities_map_to_separate_accounts_and_go_with_the_account() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(&directory.path().join("state.db")).unwrap();
        store
            .create_first_admin("admin", "pbkdf2-sha256$1$aa$bb")
            .unwrap();
        let issuer = "https://id.example/";
        let (external, created) = store
            .oidc_user(issuer, "stable-subject", Some("admin"), Role::User)
            .unwrap();
        assert!(created);
        assert_eq!(external.role, Role::User);
        assert_ne!(
            external.name, "admin",
            "OIDC must not claim a local account"
        );
        assert!(valid_username(&external.name));
        let (same, created) = store
            .oidc_user(issuer, "stable-subject", Some("renamed"), Role::Admin)
            .unwrap();
        assert!(!created);
        assert_eq!(same.id, external.id);
        assert_eq!(
            same.role,
            Role::User,
            "a later login never changes the role"
        );
        // Another subject with the same wanted name gets its own account, and odd names are cleaned.
        let (other, _) = store
            .oidc_user(issuer, "second", Some("Admin"), Role::Admin)
            .unwrap();
        assert_ne!(other.id, external.id);
        assert_eq!(other.role, Role::Admin);
        let (odd, _) = store
            .oidc_user(issuer, "third", Some("  ../Zoë Müller!! "), Role::User)
            .unwrap();
        assert!(valid_username(&odd.name), "{}", odd.name);
        let (nameless, _) = store.oidc_user(issuer, "fourth", None, Role::User).unwrap();
        assert!(valid_username(&nameless.name));
        for (issuer, subject) in [("", "s"), (issuer, ""), (issuer, "bad\nsubject")] {
            assert!(
                store
                    .oidc_user(issuer, subject, Some("x"), Role::User)
                    .is_err()
            );
        }
        // The identity is removed with its account, so a new login starts fresh.
        assert!(store.delete_user(&external.name).unwrap());
        let (again, created) = store
            .oidc_user(issuer, "stable-subject", Some("admin"), Role::User)
            .unwrap();
        assert!(created);
        assert_ne!(again.id, external.id);
    }

    #[test]
    fn schema_five_upgrades_to_six_without_touching_settings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.db");
        {
            let store = Store::open(&path).unwrap();
            store.set_setting("history", "1").unwrap();
        }
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TABLE query_log; DROP TABLE oidc_identities; PRAGMA user_version = 5;",
            )
            .unwrap();
        drop(connection);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.setting("history").unwrap().as_deref(), Some("1"));
        assert_eq!(
            store.history_prefs().mode,
            HistoryMode::Memory,
            "older flag"
        );
        assert_eq!(store.query_log_summary().unwrap().rows, 0);
        let version: i64 = Connection::open(&path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn history_prefs_default_private_validate_and_replace_the_older_flag() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(&directory.path().join("state.db")).unwrap();
        assert_eq!(store.history_prefs(), HistoryPrefs::default());
        assert_eq!(store.history_prefs().mode, HistoryMode::Off);
        assert_eq!(store.history_prefs().retention_days, 7);

        store.set_setting("history", "1").unwrap();
        assert_eq!(store.history_prefs().mode, HistoryMode::Memory);

        let saved = HistoryPrefs {
            mode: HistoryMode::Saved,
            detail: HistoryDetail::Anonymous,
            retention_days: 30,
        };
        store.set_history_prefs(&saved).unwrap();
        assert_eq!(store.history_prefs(), saved);
        assert_eq!(store.setting("history").unwrap(), None);
        store
            .set_history_prefs(&HistoryPrefs {
                mode: HistoryMode::Off,
                ..saved
            })
            .unwrap();
        assert_eq!(
            store.history_prefs().mode,
            HistoryMode::Off,
            "flag stays gone"
        );

        for days in [0, 91, u32::MAX] {
            assert!(
                store
                    .set_history_prefs(&HistoryPrefs {
                        retention_days: days,
                        ..saved
                    })
                    .is_err()
            );
        }
        // Garbage in the database falls back to the private defaults.
        store.set_setting("history_mode", "forever").unwrap();
        store.set_setting("history_detail", "x").unwrap();
        store.set_setting("history_days", "9999").unwrap();
        assert_eq!(store.history_prefs(), HistoryPrefs::default());
    }
}

// SPDX-License-Identifier: Apache-2.0
//! Versioned local `SQLite` state for configuration, devices, accounts, and daemon control.

pub mod password;

use lumen_filter::config::Device;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    net::IpAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const SCHEMA_VERSION: i64 = 4;

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
                "SELECT id, name, role, must_change, created_at, last_login, password
                 FROM users WHERE name = ?1",
                [name],
                |row| Ok((read_user(row)?, row.get::<_, String>(6)?)),
            )
            .optional()
            .map_err(database_error)
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
        let changed = transaction
            .execute("DELETE FROM users WHERE name = ?1", [name])
            .map_err(database_error)?;
        transaction.commit().map_err(database_error)?;
        Ok(changed != 0)
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
                        s.csrf, s.created_at, s.last_seen
                 FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?1",
                [token_hash],
                |row| {
                    Ok((
                        read_user(row)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, u64>(7)?,
                        row.get::<_, u64>(8)?,
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

const USER_COLUMNS: &str = "SELECT id, name, role, must_change, created_at, last_login FROM users";

fn read_user(row: &rusqlite::Row<'_>) -> rusqlite::Result<User> {
    let role: String = row.get(2)?;
    Ok(User {
        id: row.get(0)?,
        name: row.get(1)?,
        role: Role::parse(&role).map_err(|_| rusqlite::Error::InvalidQuery)?,
        must_change: row.get::<_, i64>(3)? != 0,
        created_at: row.get(4)?,
        last_login: row.get(5)?,
    })
}

fn valid_username(name: &str) -> bool {
    let mut chars = name.chars();
    (3..=32).contains(&name.len())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
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
}

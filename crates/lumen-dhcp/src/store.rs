//! Lease storage in `SQLite`, so leases and the server's `DUID` survive a restart.

use crate::{
    v4::Lease,
    v6::{Delegation6, Lease6},
};
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Mutex,
};

/// A lease database. Calls are short single-row statements.
pub struct Store {
    connection: Mutex<Connection>,
}

fn clamp_secs(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Store {
    /// Open (or create) the database. `None` keeps leases in memory only.
    ///
    /// # Errors
    /// The file cannot be opened or its tables created.
    pub fn open(path: Option<&Path>) -> rusqlite::Result<Self> {
        let connection = match path {
            Some(path) => {
                let connection = Connection::open(path)?;
                restrict(path);
                connection.pragma_update(None, "journal_mode", "WAL")?;
                connection.pragma_update(None, "synchronous", "NORMAL")?;
                connection
            }
            None => Connection::open_in_memory()?,
        };
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS leases4 (
                 ip TEXT PRIMARY KEY, client BLOB NOT NULL, hostname TEXT, expires INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS leases6 (
                 ip TEXT PRIMARY KEY, client BLOB NOT NULL, iaid INTEGER NOT NULL,
                 hostname TEXT, expires INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS prefixes6 (
                 prefix TEXT PRIMARY KEY, client BLOB NOT NULL, iaid INTEGER NOT NULL,
                 expires INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS reconf_keys (client BLOB PRIMARY KEY, key BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);",
        )?;
        // Databases made before temporary addresses existed have no such column.
        let has_column = connection
            .prepare("SELECT 1 FROM pragma_table_info('leases6') WHERE name = 'temporary'")?
            .exists([])?;
        if !has_column {
            connection.execute(
                "ALTER TABLE leases6 ADD COLUMN temporary INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave the database inconsistent.
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The server's `DUID` for `DHCPv6`, created from `fresh` on first use and then kept.
    ///
    /// # Errors
    /// The database cannot be read or written.
    pub fn server_duid(&self, fresh: impl FnOnce() -> Vec<u8>) -> rusqlite::Result<Vec<u8>> {
        let connection = self.connection();
        let existing: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM meta WHERE key = 'server_duid'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(duid) = existing {
            return Ok(duid);
        }
        let duid = fresh();
        connection.execute(
            "INSERT INTO meta (key, value) VALUES ('server_duid', ?1)",
            params![duid],
        )?;
        Ok(duid)
    }

    /// Live `DHCPv4` leases.
    ///
    /// # Errors
    /// The database cannot be read.
    pub fn load4(&self, now: u64) -> rusqlite::Result<Vec<Lease>> {
        let connection = self.connection();
        let mut statement = connection
            .prepare("SELECT ip, client, hostname, expires FROM leases4 WHERE expires > ?1")?;
        let rows = statement.query_map(params![clamp_secs(now)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ip, client, hostname, expires) = row?;
            if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                out.push(Lease {
                    ip,
                    client,
                    hostname,
                    expires: u64::try_from(expires).unwrap_or(0),
                    offered: false,
                });
            }
        }
        Ok(out)
    }

    /// Live `DHCPv6` leases.
    ///
    /// # Errors
    /// The database cannot be read.
    pub fn load6(&self, now: u64) -> rusqlite::Result<Vec<Lease6>> {
        let connection = self.connection();
        let mut statement = connection.prepare(
            "SELECT ip, client, iaid, hostname, expires, temporary FROM leases6 WHERE expires > ?1",
        )?;
        let rows = statement.query_map(params![clamp_secs(now)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, bool>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (ip, client, iaid, hostname, expires, temporary) = row?;
            if let Ok(ip) = ip.parse::<Ipv6Addr>() {
                out.push(Lease6 {
                    ip,
                    client,
                    iaid,
                    hostname,
                    expires: u64::try_from(expires).unwrap_or(0),
                    offered: false,
                    temporary,
                });
            }
        }
        Ok(out)
    }

    /// The keys of clients that agreed to be reconfigured.
    ///
    /// # Errors
    /// The database cannot be read.
    pub fn load_reconf_keys(&self) -> rusqlite::Result<Vec<(Vec<u8>, [u8; 16])>> {
        let connection = self.connection();
        let mut statement = connection.prepare("SELECT client, key FROM reconf_keys")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (client, key) = row?;
            if let Ok(key) = <[u8; 16]>::try_from(key.as_slice()) {
                out.push((client, key));
            }
        }
        Ok(out)
    }

    /// Keep the Reconfigure key of a client.
    ///
    /// # Errors
    /// The database cannot be written.
    pub fn put_reconf_key(&self, client: &[u8], key: &[u8; 16]) -> rusqlite::Result<()> {
        self.connection().execute(
            "INSERT OR REPLACE INTO reconf_keys (client, key) VALUES (?1, ?2)",
            params![client, key.as_slice()],
        )?;
        Ok(())
    }

    /// Live delegated prefixes.
    ///
    /// # Errors
    /// The database cannot be read.
    pub fn load_prefixes(&self, now: u64) -> rusqlite::Result<Vec<Delegation6>> {
        let connection = self.connection();
        let mut statement = connection
            .prepare("SELECT prefix, client, iaid, expires FROM prefixes6 WHERE expires > ?1")?;
        let rows = statement.query_map(params![clamp_secs(now)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (prefix, client, iaid, expires) = row?;
            if let Ok(prefix) = prefix.parse() {
                out.push(Delegation6 {
                    prefix,
                    client,
                    iaid,
                    expires: u64::try_from(expires).unwrap_or(0),
                    offered: false,
                });
            }
        }
        Ok(out)
    }

    /// Save or replace a delegated prefix.
    ///
    /// # Errors
    /// The database cannot be written.
    pub fn put_prefix(&self, item: &Delegation6) -> rusqlite::Result<()> {
        self.connection().execute(
            "INSERT OR REPLACE INTO prefixes6 (prefix, client, iaid, expires) VALUES (?1, ?2, ?3, ?4)",
            params![
                item.prefix.to_string(),
                item.client,
                item.iaid,
                clamp_secs(item.expires)
            ],
        )?;
        Ok(())
    }

    /// Remove a delegated prefix.
    ///
    /// # Errors
    /// The database cannot be written.
    pub fn remove_prefix(&self, prefix: ipnet::Ipv6Net) -> rusqlite::Result<()> {
        self.connection().execute(
            "DELETE FROM prefixes6 WHERE prefix = ?1",
            params![prefix.to_string()],
        )?;
        Ok(())
    }

    /// Save or replace a `DHCPv4` lease.
    ///
    /// # Errors
    /// The database cannot be written.
    pub fn put4(&self, lease: &Lease) -> rusqlite::Result<()> {
        self.connection().execute(
            "INSERT OR REPLACE INTO leases4 (ip, client, hostname, expires) VALUES (?1, ?2, ?3, ?4)",
            params![
                lease.ip.to_string(),
                lease.client,
                lease.hostname,
                clamp_secs(lease.expires)
            ],
        )?;
        Ok(())
    }

    /// Save or replace a `DHCPv6` lease.
    ///
    /// # Errors
    /// The database cannot be written.
    pub fn put6(&self, lease: &Lease6) -> rusqlite::Result<()> {
        self.connection().execute(
            "INSERT OR REPLACE INTO leases6 (ip, client, iaid, hostname, expires, temporary)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                lease.ip.to_string(),
                lease.client,
                lease.iaid,
                lease.hostname,
                clamp_secs(lease.expires),
                lease.temporary
            ],
        )?;
        Ok(())
    }

    /// Remove the lease of an address.
    ///
    /// # Errors
    /// The database cannot be written.
    pub fn remove(&self, ip: std::net::IpAddr) -> rusqlite::Result<()> {
        let (table, key) = match ip {
            std::net::IpAddr::V4(ip) => ("leases4", ip.to_string()),
            std::net::IpAddr::V6(ip) => ("leases6", ip.to_string()),
        };
        self.connection()
            .execute(&format!("DELETE FROM {table} WHERE ip = ?1"), params![key])?;
        Ok(())
    }
}

#[cfg(unix)]
fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_and_the_server_duid_survive_a_reopen_and_expired_rows_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.db");
        let store = Store::open(Some(&path)).unwrap();
        let v4 = Lease {
            ip: "192.168.1.50".parse().unwrap(),
            client: vec![1, 2, 3],
            hostname: Some("laptop".into()),
            expires: 1000,
            offered: false,
        };
        let v6 = Lease6 {
            ip: "fd00::5".parse().unwrap(),
            client: vec![9],
            iaid: 4,
            hostname: None,
            expires: 1000,
            offered: false,
            temporary: true,
        };
        store.put4(&v4).unwrap();
        store.put6(&v6).unwrap();
        let first = store.server_duid(|| vec![7, 7]).unwrap();
        drop(store);

        let store = Store::open(Some(&path)).unwrap();
        assert_eq!(store.load4(10).unwrap(), vec![v4.clone()]);
        assert_eq!(store.load6(10).unwrap(), vec![v6]);
        assert!(store.load4(1000).unwrap().is_empty());
        // The DUID is kept, not regenerated.
        assert_eq!(store.server_duid(|| vec![1]).unwrap(), first);
        let prefix = Delegation6 {
            prefix: "2001:db8:100:4200::/56".parse().unwrap(),
            client: vec![5],
            iaid: 2,
            expires: 1000,
            offered: false,
        };
        store.put_prefix(&prefix).unwrap();
        assert_eq!(store.load_prefixes(10).unwrap(), vec![prefix.clone()]);
        store.remove_prefix(prefix.prefix).unwrap();
        assert!(store.load_prefixes(10).unwrap().is_empty());
        store.remove(v4.ip.into()).unwrap();
        assert!(store.load4(10).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_database_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.db");
        let _store = Store::open(Some(&path)).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

//! Checks, links, interface counters, scans, and the events they cause.

use crate::{
    health::{CheckResult, Health, Transition},
    model::{
        CheckRow, Device, Event, Interface, InterfaceSample, Link, LinkInput, MAX_LINKS,
        ScanSummary, Status,
    },
    store::{Netmon, add_event, count, exists, load_devices, now, sql},
};
use rusqlite::{OptionalExtension, params};

/// A counter reading of one interface, before rates are worked out.
#[derive(Clone, Debug, Default)]
pub struct IfReading {
    pub index: i64,
    pub name: String,
    pub alias: String,
    pub speed_bps: Option<u64>,
    pub admin_up: bool,
    pub oper_up: bool,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_errors: u64,
    pub out_errors: u64,
    pub in_discards: u64,
    pub out_discards: u64,
    /// 32 or 64: how wide the octet counters are, for wrap-around.
    pub counter_bits: u8,
}

/// Bits per second between two counter readings. A counter that went down by wrapping is
/// handled; one that went down because the device restarted is not a rate and gives `None`.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn octet_rate(previous: u64, current: u64, secs: f64, bits: u8) -> Option<f64> {
    if secs <= 0.0 {
        return None;
    }
    let delta = if current >= previous {
        current - previous
    } else if bits == 32 && u32::try_from(previous).is_ok() {
        // The 32-bit counter wrapped once.
        (u64::from(u32::MAX) - previous) + current + 1
    } else {
        return None;
    };
    Some(delta as f64 * 8.0 / secs)
}

/// A device that is due a check.
#[derive(Clone, Debug)]
pub struct Target {
    pub device: Device,
    pub health: Health,
    pub last_check: Option<i64>,
}

impl Netmon {
    // ---- availability ----

    /// Store one check, the new state, and an event when the state changed.
    ///
    /// # Errors
    /// The database failed.
    pub fn record_check(
        &mut self,
        device_id: i64,
        result: CheckResult,
        health: &Health,
        change: Option<Transition>,
    ) -> Result<(), String> {
        let tx = self.write()?;
        let ts = now();
        tx.execute(
            "INSERT INTO nm_checks (device_id, ts, ok, rtt_us, loss) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device_id,
                ts,
                i64::from(result.ok()),
                result.rtt_ms.map(|ms| (ms * 1000.0).round() as i64),
                result.loss_percent()
            ],
        )
        .map_err(sql)?;
        tx.execute(
            "UPDATE nm_devices SET status = ?2, fail_streak = ?3,
                 last_ok = CASE WHEN ?4 THEN ?5 ELSE last_ok END,
                 last_seen = CASE WHEN ?4 THEN ?5 ELSE last_seen END,
                 gone = CASE WHEN ?4 THEN 0 ELSE gone END,
                 missed = CASE WHEN ?4 THEN 0 ELSE missed END
             WHERE id = ?1",
            params![
                device_id,
                health.status.as_str(),
                health.fail_streak,
                result.ok(),
                ts
            ],
        )
        .map_err(sql)?;
        if let Some(change) = change {
            let name: String = tx
                .query_row(
                    "SELECT name FROM nm_devices WHERE id = ?1",
                    [device_id],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            let detail = match change {
                Transition::Offline => format!("{name} stopped answering"),
                Transition::Recovered => format!("{name} answers again"),
                Transition::Degraded => format!("{name} is losing packets"),
                Transition::Healthy => format!("{name} is no longer losing packets"),
            };
            add_event(&tx, Some(device_id), change.event(), &detail)?;
        }
        tx.commit().map_err(sql)
    }

    /// The devices that should be checked, with their remembered state and last check time.
    ///
    /// # Errors
    /// The database failed.
    pub fn targets(&self) -> Result<Vec<Target>, String> {
        let mut last: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
        {
            let mut st = self
                .conn
                .prepare("SELECT device_id, MAX(ts) FROM nm_checks GROUP BY device_id")
                .map_err(sql)?;
            let rows = st
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))
                .map_err(sql)?;
            for row in rows {
                let (id, ts) = row.map_err(sql)?;
                last.insert(id, ts);
            }
        }
        let streaks: std::collections::HashMap<i64, i64> = {
            let mut st = self
                .conn
                .prepare("SELECT id, fail_streak FROM nm_devices")
                .map_err(sql)?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(sql)?
                .collect::<Result<_, _>>()
                .map_err(sql)?
        };
        Ok(load_devices(&self.conn, None)?
            .into_iter()
            .filter(|d| d.monitoring.enabled && !d.addresses.is_empty())
            .map(|d| Target {
                health: Health::new(
                    d.status,
                    u32::try_from(streaks.get(&d.id).copied().unwrap_or(0)).unwrap_or(0),
                ),
                last_check: last.get(&d.id).copied(),
                device: d,
            })
            .collect())
    }

    /// Recent checks of a device, newest first.
    ///
    /// # Errors
    /// The database failed.
    pub fn checks(
        &self,
        device_id: i64,
        since: i64,
        limit: usize,
    ) -> Result<Vec<CheckRow>, String> {
        let limit = i64::try_from(limit.clamp(1, 5000)).unwrap_or(5000);
        let mut st = self
            .conn
            .prepare(
                "SELECT ts, ok, rtt_us, loss FROM nm_checks WHERE device_id = ?1 AND ts >= ?2
                 ORDER BY ts DESC LIMIT ?3",
            )
            .map_err(sql)?;
        st.query_map(params![device_id, since, limit], |r| {
            Ok(CheckRow {
                ts: r.get(0)?,
                ok: r.get::<_, i64>(1)? != 0,
                rtt_ms: r.get::<_, Option<i64>>(2)?.map(|us| us as f64 / 1000.0),
                loss_percent: r.get(3)?,
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
    }

    /// The share of checks since `since` that were answered, or `None` with no checks.
    ///
    /// # Errors
    /// The database failed.
    pub fn availability(&self, device_id: i64, since: i64) -> Result<Option<f64>, String> {
        self.conn
            .query_row(
                "SELECT AVG(ok) * 100.0 FROM nm_checks WHERE device_id = ?1 AND ts >= ?2",
                params![device_id, since],
                |r| r.get(0),
            )
            .map_err(sql)
    }

    // ---- links ----

    /// # Errors
    /// The database failed.
    pub fn links(&self) -> Result<Vec<Link>, String> {
        let mut st = self
            .conn
            .prepare("SELECT id, a_device, a_port, b_device, b_port, kind, confirmed, speed_mbps FROM nm_links ORDER BY id")
            .map_err(sql)?;
        st.query_map([], |r| {
            Ok(Link {
                id: r.get(0)?,
                a_device: r.get(1)?,
                a_port: r.get(2)?,
                b_device: r.get(3)?,
                b_port: r.get(4)?,
                kind: r.get(5)?,
                confirmed: r.get::<_, i64>(6)? != 0,
                speed_mbps: r
                    .get::<_, Option<i64>>(7)?
                    .and_then(|v| u64::try_from(v).ok()),
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
    }

    fn link_checks(
        tx: &rusqlite::Transaction<'_>,
        input: &LinkInput,
    ) -> Result<(String, String), String> {
        if input.a_device == input.b_device {
            return Err("a device cannot be linked to itself".into());
        }
        for id in [input.a_device, input.b_device] {
            if !exists(tx, "nm_devices", id)? {
                return Err("no such device".into());
            }
        }
        let port = |p: &str| -> Result<String, String> {
            let p = p.trim();
            if p.chars().count() > 64 || p.chars().any(char::is_control) {
                return Err("a port name is at most 64 characters".into());
            }
            Ok(p.to_owned())
        };
        if input.speed_mbps.is_some_and(|s| s == 0 || s > 1_000_000) {
            return Err("the link speed must be 1 to 1000000 Mb/s".into());
        }
        Ok((port(&input.a_port)?, port(&input.b_port)?))
    }

    /// Record a connection an administrator knows about. It is shown as confirmed.
    ///
    /// # Errors
    /// A device does not exist, or the link is invalid or already there.
    pub fn add_link(&mut self, input: &LinkInput) -> Result<Link, String> {
        let tx = self.write()?;
        let (a_port, b_port) = Self::link_checks(&tx, input)?;
        if count(&tx, "nm_links")? >= MAX_LINKS {
            return Err("too many links".into());
        }
        // The same connection written the other way round is the same connection.
        let twin: Option<i64> = tx
            .query_row(
                "SELECT id FROM nm_links WHERE (a_device = ?1 AND a_port = ?2 AND b_device = ?3 AND b_port = ?4)
                    OR (a_device = ?3 AND a_port = ?4 AND b_device = ?1 AND b_port = ?2)",
                params![input.a_device, a_port, input.b_device, b_port],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if twin.is_some() {
            return Err("that link already exists".into());
        }
        tx.execute(
            "INSERT INTO nm_links (a_device, a_port, b_device, b_port, kind, confirmed, speed_mbps, updated)
             VALUES (?1, ?2, ?3, ?4, 'manual', 1, ?5, ?6)",
            params![input.a_device, a_port, input.b_device, b_port, input.speed_mbps, now()],
        )
        .map_err(sql)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(sql)?;
        self.links()?
            .into_iter()
            .find(|l| l.id == id)
            .ok_or_else(|| "the link disappeared".into())
    }

    /// Correct a link: its ports or speed. A corrected link becomes a manual, confirmed one.
    ///
    /// # Errors
    /// The link does not exist or the input is invalid.
    pub fn update_link(&mut self, id: i64, input: &LinkInput) -> Result<Link, String> {
        let tx = self.write()?;
        if !exists(&tx, "nm_links", id)? {
            return Err("no such link".into());
        }
        let (a_port, b_port) = Self::link_checks(&tx, input)?;
        tx.execute(
            "UPDATE nm_links SET a_device = ?2, a_port = ?3, b_device = ?4, b_port = ?5, speed_mbps = ?6,
                 kind = 'manual', confirmed = 1, updated = ?7 WHERE id = ?1",
            params![id, input.a_device, a_port, input.b_device, b_port, input.speed_mbps, now()],
        )
        .map_err(|e| {
            if e.to_string().contains("UNIQUE") {
                "that link already exists".to_owned()
            } else {
                sql(e)
            }
        })?;
        tx.commit().map_err(sql)?;
        self.links()?
            .into_iter()
            .find(|l| l.id == id)
            .ok_or_else(|| "the link disappeared".into())
    }

    /// # Errors
    /// The database failed.
    pub fn delete_link(&mut self, id: i64) -> Result<bool, String> {
        let tx = self.write()?;
        let gone = tx
            .execute("DELETE FROM nm_links WHERE id = ?1", [id])
            .map_err(sql)?;
        tx.commit().map_err(sql)?;
        Ok(gone > 0)
    }

    /// Replace the links a device reported itself (`lldp`, `snmp`), or inferred, with a fresh
    /// set. Links an administrator made are never touched. `confirmed` is true for what a device
    /// reported and false for an inference.
    ///
    /// # Errors
    /// The database failed.
    pub fn replace_reported_links(
        &mut self,
        device_id: i64,
        kind: &str,
        found: &[(String, i64, String, Option<u64>)],
    ) -> Result<(), String> {
        let confirmed = kind != "inferred";
        let tx = self.write()?;
        tx.execute(
            "DELETE FROM nm_links WHERE kind = ?2 AND (a_device = ?1)",
            params![device_id, kind],
        )
        .map_err(sql)?;
        for (local_port, remote, remote_port, speed) in found {
            if *remote == device_id || !exists(&tx, "nm_devices", *remote)? {
                continue;
            }
            // Already known the other way round, or by an administrator: keep that one.
            let known: Option<i64> = tx
                .query_row(
                    "SELECT id FROM nm_links WHERE (a_device = ?1 AND a_port = ?2 AND b_device = ?3 AND b_port = ?4)
                        OR (a_device = ?3 AND a_port = ?4 AND b_device = ?1 AND b_port = ?2)",
                    params![device_id, local_port, remote, remote_port],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql)?;
            if known.is_some() {
                continue;
            }
            if count(&tx, "nm_links")? >= MAX_LINKS {
                break;
            }
            tx.execute(
                "INSERT INTO nm_links (a_device, a_port, b_device, b_port, kind, confirmed, speed_mbps, updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![device_id, local_port, remote, remote_port, kind, i64::from(confirmed), speed.and_then(|s| i64::try_from(s).ok()), now()],
            )
            .map_err(sql)?;
        }
        tx.commit().map_err(sql)
    }

    // ---- interfaces ----

    /// Store a poll of a device's interfaces, working out rates from the previous reading.
    ///
    /// # Errors
    /// The database failed.
    pub fn record_interfaces(
        &mut self,
        device_id: i64,
        readings: &[IfReading],
    ) -> Result<(), String> {
        let tx = self.write()?;
        let ts = now();
        for r in readings.iter().take(1024) {
            let previous: Option<(Option<i64>, Option<i64>, i64)> = tx
                .query_row(
                    "SELECT in_octets, out_octets, ts FROM nm_ifaces WHERE device_id = ?1 AND idx = ?2",
                    params![device_id, r.index],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(sql)?;
            #[allow(clippy::cast_precision_loss)]
            let (in_bps, out_bps) = match previous {
                Some((Some(pin), Some(pout), pts)) => {
                    let secs = (ts - pts) as f64;
                    (
                        octet_rate(
                            u64::try_from(pin).unwrap_or(0),
                            r.in_octets,
                            secs,
                            r.counter_bits,
                        ),
                        octet_rate(
                            u64::try_from(pout).unwrap_or(0),
                            r.out_octets,
                            secs,
                            r.counter_bits,
                        ),
                    )
                }
                _ => (None, None),
            };
            #[allow(clippy::cast_precision_loss)]
            let util = match (in_bps, out_bps, r.speed_bps) {
                (Some(i), Some(o), Some(speed)) if speed > 0 => {
                    Some((i.max(o) / speed as f64 * 100.0).min(100.0))
                }
                _ => None,
            };
            tx.execute(
                "INSERT INTO nm_ifaces (device_id, idx, name, alias, speed, admin_up, oper_up, in_octets, out_octets,
                     in_bps, out_bps, util, in_err, out_err, in_disc, out_disc, ts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                 ON CONFLICT(device_id, idx) DO UPDATE SET name = ?3, alias = ?4, speed = ?5, admin_up = ?6, oper_up = ?7,
                     in_octets = ?8, out_octets = ?9, in_bps = ?10, out_bps = ?11, util = ?12, in_err = ?13,
                     out_err = ?14, in_disc = ?15, out_disc = ?16, ts = ?17",
                params![
                    device_id,
                    r.index,
                    r.name,
                    r.alias,
                    r.speed_bps.and_then(|v| i64::try_from(v).ok()),
                    i64::from(r.admin_up),
                    i64::from(r.oper_up),
                    i64::try_from(r.in_octets).unwrap_or(i64::MAX),
                    i64::try_from(r.out_octets).unwrap_or(i64::MAX),
                    in_bps,
                    out_bps,
                    util,
                    i64::try_from(r.in_errors).unwrap_or(i64::MAX),
                    i64::try_from(r.out_errors).unwrap_or(i64::MAX),
                    i64::try_from(r.in_discards).unwrap_or(i64::MAX),
                    i64::try_from(r.out_discards).unwrap_or(i64::MAX),
                    ts
                ],
            )
            .map_err(sql)?;
            if let (Some(i), Some(o)) = (in_bps, out_bps) {
                tx.execute(
                    "INSERT INTO nm_if_hist (device_id, idx, ts, in_bps, out_bps) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![device_id, r.index, ts, i, o],
                )
                .map_err(sql)?;
            }
        }
        // Interfaces that vanished from the device.
        let keep: Vec<i64> = readings.iter().map(|r| r.index).collect();
        let existing: Vec<i64> = {
            let mut st = tx
                .prepare("SELECT idx FROM nm_ifaces WHERE device_id = ?1")
                .map_err(sql)?;
            st.query_map([device_id], |r| r.get(0))
                .map_err(sql)?
                .collect::<Result<_, _>>()
                .map_err(sql)?
        };
        for idx in existing.into_iter().filter(|i| !keep.contains(i)) {
            tx.execute(
                "DELETE FROM nm_ifaces WHERE device_id = ?1 AND idx = ?2",
                params![device_id, idx],
            )
            .map_err(sql)?;
        }
        tx.commit().map_err(sql)
    }

    /// The interfaces of a device as last polled.
    ///
    /// # Errors
    /// The database failed.
    pub fn interfaces(&self, device_id: i64) -> Result<Vec<Interface>, String> {
        let mut st = self
            .conn
            .prepare(
                "SELECT device_id, idx, name, alias, speed, admin_up, oper_up, in_bps, out_bps, util,
                        in_err, out_err, in_disc, out_disc, ts FROM nm_ifaces WHERE device_id = ?1 ORDER BY idx",
            )
            .map_err(sql)?;
        st.query_map([device_id], |r| {
            let u = |i: usize| -> rusqlite::Result<u64> {
                Ok(u64::try_from(r.get::<_, i64>(i)?).unwrap_or(0))
            };
            Ok(Interface {
                device_id: r.get(0)?,
                index: r.get(1)?,
                name: r.get(2)?,
                alias: r.get(3)?,
                speed_bps: r
                    .get::<_, Option<i64>>(4)?
                    .and_then(|v| u64::try_from(v).ok()),
                admin_up: r.get::<_, i64>(5)? != 0,
                oper_up: r.get::<_, i64>(6)? != 0,
                in_bps: r.get(7)?,
                out_bps: r.get(8)?,
                utilization_percent: r.get(9)?,
                in_errors: u(10)?,
                out_errors: u(11)?,
                in_discards: u(12)?,
                out_discards: u(13)?,
                ts: r.get(14)?,
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
    }

    /// Traffic rate history of one interface, oldest first.
    ///
    /// # Errors
    /// The database failed.
    pub fn interface_history(
        &self,
        device_id: i64,
        index: i64,
        since: i64,
        limit: usize,
    ) -> Result<Vec<InterfaceSample>, String> {
        let limit = i64::try_from(limit.clamp(1, 5000)).unwrap_or(5000);
        let mut st = self
            .conn
            .prepare(
                "SELECT ts, in_bps, out_bps FROM (
                     SELECT ts, in_bps, out_bps FROM nm_if_hist WHERE device_id = ?1 AND idx = ?2 AND ts >= ?3
                     ORDER BY ts DESC LIMIT ?4) ORDER BY ts",
            )
            .map_err(sql)?;
        st.query_map(params![device_id, index, since, limit], |r| {
            Ok(InterfaceSample {
                ts: r.get(0)?,
                in_bps: r.get(1)?,
                out_bps: r.get(2)?,
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
    }

    // ---- scans ----

    /// # Errors
    /// The database failed.
    pub fn begin_scan(&mut self) -> Result<i64, String> {
        let tx = self.write()?;
        tx.execute(
            "INSERT INTO nm_scans (started, state) VALUES (?1, 'running')",
            [now()],
        )
        .map_err(sql)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(sql)?;
        Ok(id)
    }

    /// # Errors
    /// The database failed.
    pub fn finish_scan(
        &mut self,
        id: i64,
        state: &str,
        summary: &ScanSummary,
    ) -> Result<(), String> {
        let tx = self.write()?;
        tx.execute(
            "UPDATE nm_scans SET finished = ?2, state = ?3, probed = ?4, seen = ?5, new_devices = ?6,
                 gone_devices = ?7, detail = ?8 WHERE id = ?1",
            params![
                id,
                now(),
                state,
                i64::try_from(summary.probed).unwrap_or(i64::MAX),
                i64::try_from(summary.seen).unwrap_or(i64::MAX),
                i64::try_from(summary.new_devices).unwrap_or(i64::MAX),
                i64::try_from(summary.gone_devices).unwrap_or(i64::MAX),
                summary.detail
            ],
        )
        .map_err(sql)?;
        add_event(
            &tx,
            None,
            "scan",
            &format!(
                "discovery {state}: {} seen, {} new",
                summary.seen, summary.new_devices
            ),
        )?;
        tx.commit().map_err(sql)
    }

    /// Recent discovery runs, newest first.
    ///
    /// # Errors
    /// The database failed.
    pub fn scans(&self, limit: usize) -> Result<Vec<ScanSummary>, String> {
        let limit = i64::try_from(limit.clamp(1, 100)).unwrap_or(100);
        let mut st = self
            .conn
            .prepare(
                "SELECT id, started, finished, state, probed, seen, new_devices, gone_devices, detail
                 FROM nm_scans ORDER BY id DESC LIMIT ?1",
            )
            .map_err(sql)?;
        st.query_map([limit], |r| {
            let u = |i: usize| -> rusqlite::Result<u64> {
                Ok(u64::try_from(r.get::<_, i64>(i)?).unwrap_or(0))
            };
            Ok(ScanSummary {
                id: r.get(0)?,
                started: r.get(1)?,
                finished: r.get(2)?,
                state: r.get(3)?,
                probed: u(4)?,
                seen: u(5)?,
                new_devices: u(6)?,
                gone_devices: u(7)?,
                detail: r.get(8)?,
            })
        })
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)
    }

    // ---- upkeep ----

    /// Delete history older than the retention. Returns rows removed.
    ///
    /// # Errors
    /// The database failed.
    pub fn prune(&mut self, retention_days: u16) -> Result<usize, String> {
        let cutoff = now() - i64::from(retention_days) * 86_400;
        let tx = self.write()?;
        let mut removed = 0;
        for sql_text in [
            "DELETE FROM nm_checks WHERE ts < ?1",
            "DELETE FROM nm_if_hist WHERE ts < ?1",
            "DELETE FROM nm_events WHERE ts < ?1",
            "DELETE FROM nm_scans WHERE started < ?1",
        ] {
            removed += tx.execute(sql_text, [cutoff]).map_err(sql)?;
        }
        tx.commit().map_err(sql)?;
        Ok(removed)
    }

    /// Whether the device exists and what its state is, for the engine.
    ///
    /// # Errors
    /// The database failed.
    pub fn status_of(&self, id: i64) -> Result<Option<Status>, String> {
        let text: Option<String> = self
            .conn
            .query_row("SELECT status FROM nm_devices WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()
            .map_err(sql)?;
        Ok(text.map(|t| Status::parse(&t)))
    }

    /// Recent events for the API, with the device name in the detail already.
    ///
    /// # Errors
    /// The database failed.
    pub fn recent_events(&self, limit: usize) -> Result<Vec<Event>, String> {
        self.events(None, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_rates_handle_wraps_and_resets() {
        assert_eq!(octet_rate(1000, 2000, 10.0, 64), Some(800.0));
        // A 32-bit counter that wrapped once.
        let rate = octet_rate(u64::from(u32::MAX) - 99, 100, 1.0, 32).unwrap();
        assert!((rate - 200.0 * 8.0).abs() < 1e-9, "{rate}");
        // A 64-bit counter that went down, or a reboot, is not a rate.
        assert_eq!(octet_rate(5000, 10, 10.0, 64), None);
        assert_eq!(octet_rate(10, 20, 0.0, 64), None);
    }
}

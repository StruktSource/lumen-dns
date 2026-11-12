//! RFC 5011 trust-anchor tracking: the state of every key seen at a zone's apex.
//!
//! This is the pure part. It knows nothing about the network or the clock: the caller hands in
//! the keys it saw and the time. A key that appears is not trusted until it has been seen,
//! without interruption, for the add hold-down. A revoked key stays listed for the remove
//! hold-down and is never trusted again. Only an apex key set that a currently trusted key signed
//! may change anything, and the caller states that with `validated`.

#![allow(dead_code)] // Wired in by the updater step; remove then.

use std::fmt::Write as _;

/// Seconds a new key must stay visible before it is trusted (30 days, RFC 5011 section 2.3).
pub const ADD_HOLD_DOWN: u64 = 30 * 24 * 3600;
/// Seconds a revoked key stays listed before it is forgotten (30 days).
pub const REMOVE_HOLD_DOWN: u64 = 30 * 24 * 3600;
/// At most this many keys are tracked or read back from a state file.
pub const MAX_KEYS: usize = 32;
/// Largest public key accepted, in bytes.
pub const MAX_KEY_BYTES: usize = 1024;

/// What the apex key set currently says about a key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Seen {
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    /// The REVOKE flag is set and the key signed itself, checked by the caller.
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// Seen for the first time at the second value.
    AddPending(u64),
    Valid,
    /// Trusted, but absent from the latest key set since the second value.
    Missing(u64),
    /// Revoked at the second value. Not trusted.
    Revoked(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tracked {
    pub algorithm: u8,
    pub public_key: Vec<u8>,
    pub state: State,
}

impl Tracked {
    fn trusted(&self) -> bool {
        matches!(self.state, State::Valid | State::Missing(_))
    }
}

/// The tracked keys of one zone.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Anchors {
    keys: Vec<Tracked>,
}

impl Anchors {
    /// Start from keys that are trusted without waiting, such as the configured anchors.
    pub fn seeded(keys: impl IntoIterator<Item = (u8, Vec<u8>)>) -> Self {
        let mut anchors = Self::default();
        for (algorithm, public_key) in keys.into_iter().take(MAX_KEYS) {
            anchors.keys.push(Tracked {
                algorithm,
                public_key,
                state: State::Valid,
            });
        }
        anchors
    }

    pub fn tracked(&self) -> &[Tracked] {
        &self.keys
    }

    /// Keys that count as trust anchors right now.
    pub fn trusted(&self) -> Vec<(u8, Vec<u8>)> {
        self.keys
            .iter()
            .filter(|key| key.trusted())
            .map(|key| (key.algorithm, key.public_key.clone()))
            .collect()
    }

    /// Apply one observation of the apex key set. Returns true when the trusted set changed.
    ///
    /// Nothing changes unless `validated` is true, meaning a currently trusted key signed the
    /// set. An empty set is also ignored: a failed or truncated fetch must not look like every
    /// key vanishing.
    pub fn observe(&mut self, now: u64, seen: &[Seen], validated: bool) -> bool {
        if !validated || seen.is_empty() {
            return false;
        }
        let before = self.trusted();
        // Walk the keys already tracked.
        let mut kept = Vec::with_capacity(self.keys.len());
        for mut key in std::mem::take(&mut self.keys) {
            let hit = seen
                .iter()
                .find(|s| s.algorithm == key.algorithm && s.public_key == key.public_key);
            let next = match (key.state, hit) {
                (State::AddPending(_), None) => None,
                (State::AddPending(_), Some(s)) if s.revoked => None,
                (State::AddPending(first), Some(_)) => {
                    Some(if now.saturating_sub(first) >= ADD_HOLD_DOWN {
                        State::Valid
                    } else {
                        State::AddPending(first)
                    })
                }
                (State::Valid | State::Missing(_), Some(s)) if s.revoked => {
                    Some(State::Revoked(now))
                }
                (State::Valid | State::Missing(_), Some(_)) => Some(State::Valid),
                (State::Valid, None) => Some(State::Missing(now)),
                (State::Missing(since), None) => Some(State::Missing(since)),
                (State::Revoked(since), _) => {
                    (now.saturating_sub(since) < REMOVE_HOLD_DOWN).then_some(State::Revoked(since))
                }
            };
            if let Some(state) = next {
                key.state = state;
                kept.push(key);
            }
        }
        self.keys = kept;
        // Keys not tracked yet start their hold-down. A key that arrives revoked is ignored.
        for s in seen.iter().filter(|s| !s.revoked) {
            let known = self
                .keys
                .iter()
                .any(|key| key.algorithm == s.algorithm && key.public_key == s.public_key);
            if !known && self.keys.len() < MAX_KEYS && s.public_key.len() <= MAX_KEY_BYTES {
                self.keys.push(Tracked {
                    algorithm: s.algorithm,
                    public_key: s.public_key.clone(),
                    state: State::AddPending(now),
                });
            }
        }
        self.trusted() != before
    }

    /// One line per key: `state algorithm seconds hexkey`. Meant for a small private file.
    pub fn to_text(&self) -> String {
        let mut out = String::from("# Lumen trust-anchor state (RFC 5011). Edit nothing here.\n");
        for key in &self.keys {
            let (name, at) = match key.state {
                State::AddPending(at) => ("addpend", at),
                State::Valid => ("valid", 0),
                State::Missing(at) => ("missing", at),
                State::Revoked(at) => ("revoked", at),
            };
            let _ = write!(out, "{name} {} {at} ", key.algorithm);
            for byte in &key.public_key {
                let _ = write!(out, "{byte:02x}");
            }
            out.push('\n');
        }
        out
    }

    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut keys = Vec::new();
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if keys.len() >= MAX_KEYS {
                return Err("too many trust anchor keys".into());
            }
            let mut parts = line.split_whitespace();
            let (Some(name), Some(algorithm), Some(at), Some(hex), None) = (
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
                parts.next(),
            ) else {
                return Err("malformed trust anchor state line".into());
            };
            let algorithm: u8 = algorithm.parse().map_err(|_| "bad algorithm")?;
            let at: u64 = at.parse().map_err(|_| "bad time")?;
            let state = match name {
                "addpend" => State::AddPending(at),
                "valid" => State::Valid,
                "missing" => State::Missing(at),
                "revoked" => State::Revoked(at),
                _ => return Err("unknown trust anchor state".into()),
            };
            if hex.len() % 2 != 0 || hex.len() > MAX_KEY_BYTES * 2 || hex.is_empty() {
                return Err("bad key".into());
            }
            let public_key = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "bad key")?;
            keys.push(Tracked {
                algorithm,
                public_key,
                state,
            });
        }
        Ok(Self { keys })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600;

    fn seen(id: u8, revoked: bool) -> Seen {
        Seen {
            algorithm: 8,
            public_key: vec![id; 4],
            revoked,
        }
    }

    fn trusted_ids(anchors: &Anchors) -> Vec<u8> {
        anchors.trusted().iter().map(|(_, key)| key[0]).collect()
    }

    #[test]
    fn a_new_key_is_trusted_only_after_the_full_hold_down() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4])]);
        let both = [seen(1, false), seen(2, false)];
        assert!(!anchors.observe(0, &both, true));
        assert_eq!(trusted_ids(&anchors), [1]);
        assert!(!anchors.observe(29 * DAY, &both, true));
        assert_eq!(trusted_ids(&anchors), [1]);
        assert!(anchors.observe(30 * DAY, &both, true));
        assert_eq!(trusted_ids(&anchors), [1, 2]);
    }

    #[test]
    fn a_key_that_disappears_during_hold_down_starts_over() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4])]);
        anchors.observe(0, &[seen(1, false), seen(2, false)], true);
        anchors.observe(10 * DAY, &[seen(1, false)], true);
        anchors.observe(31 * DAY, &[seen(1, false), seen(2, false)], true);
        assert_eq!(trusted_ids(&anchors), [1]);
        assert!(anchors.observe(61 * DAY, &[seen(1, false), seen(2, false)], true));
        assert_eq!(trusted_ids(&anchors), [1, 2]);
    }

    #[test]
    fn an_unvalidated_or_empty_answer_changes_nothing() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4])]);
        let before = anchors.clone();
        assert!(!anchors.observe(0, &[seen(9, false)], false));
        assert!(!anchors.observe(0, &[], true));
        assert_eq!(anchors, before);
    }

    #[test]
    fn a_revoked_key_is_dropped_at_once_and_forgotten_after_the_hold_down() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4]), (8, vec![2; 4])]);
        assert!(anchors.observe(0, &[seen(1, true), seen(2, false)], true));
        assert_eq!(trusted_ids(&anchors), [2]);
        assert_eq!(anchors.tracked().len(), 2);
        anchors.observe(29 * DAY, &[seen(2, false)], true);
        assert_eq!(anchors.tracked().len(), 2);
        anchors.observe(30 * DAY, &[seen(2, false)], true);
        assert_eq!(anchors.tracked().len(), 1);
        // A revoked key can never come back, even if it is published again unrevoked.
        anchors.observe(31 * DAY, &[seen(1, false), seen(2, false)], true);
        assert_eq!(trusted_ids(&anchors), [2]);
    }

    #[test]
    fn a_missing_trusted_key_stays_trusted_and_recovers() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4]), (8, vec![2; 4])]);
        assert!(!anchors.observe(0, &[seen(2, false)], true));
        assert_eq!(trusted_ids(&anchors), [1, 2]);
        anchors.observe(90 * DAY, &[seen(1, false), seen(2, false)], true);
        assert!(matches!(anchors.tracked()[0].state, State::Valid));
    }

    #[test]
    fn a_full_rollover_ends_with_only_the_new_key() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4])]);
        anchors.observe(0, &[seen(1, false), seen(2, false)], true);
        anchors.observe(30 * DAY, &[seen(1, false), seen(2, false)], true);
        anchors.observe(31 * DAY, &[seen(1, true), seen(2, false)], true);
        assert_eq!(trusted_ids(&anchors), [2]);
        anchors.observe(62 * DAY, &[seen(2, false)], true);
        assert_eq!(anchors.tracked().len(), 1);
    }

    #[test]
    fn a_key_that_first_appears_revoked_is_ignored() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4])]);
        anchors.observe(0, &[seen(1, false), seen(3, true)], true);
        assert_eq!(anchors.tracked().len(), 1);
    }

    #[test]
    fn state_round_trips_and_bad_files_are_refused() {
        let mut anchors = Anchors::seeded([(8, vec![1; 4])]);
        anchors.observe(5, &[seen(1, false), seen(2, false)], true);
        anchors.observe(6, &[seen(2, false)], true);
        let text = anchors.to_text();
        assert_eq!(Anchors::from_text(&text).unwrap(), anchors);
        for bad in [
            "valid 8 0 zz",
            "valid 8 0 abc",
            "nope 8 0 aa",
            "valid 8 0",
            "valid 8 0 aa extra",
            "valid 300 0 aa",
        ] {
            assert!(Anchors::from_text(bad).is_err(), "{bad}");
        }
        let many = "valid 8 0 aa\n".repeat(MAX_KEYS + 1);
        assert!(Anchors::from_text(&many).is_err());
    }
}

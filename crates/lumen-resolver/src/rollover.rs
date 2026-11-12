//! RFC 5011 trust-anchor tracking: the state of every key seen at a zone's apex.
//!
//! This is the pure part. It knows nothing about the network or the clock: the caller hands in
//! the keys it saw and the time. A key that appears is not trusted until it has been seen,
//! without interruption, for the add hold-down. A revoked key stays listed for the remove
//! hold-down and is never trusted again. Only an apex key set that a currently trusted key signed
//! may change anything, and the caller states that with `validated`.

#![allow(dead_code)] // Wired in by the updater step; remove then.

use hickory_server::proto::{
    dnssec::{
        PublicKey, Verifier,
        rdata::{DNSKEY, DNSSECRData, RRSIG},
    },
    rr::{DNSClass, Name, RData, Record, RecordType},
};
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

/// Read an apex DNSKEY answer the way RFC 5011 asks, at the unix time `now`.
///
/// Returns the key-signing keys that are present, and whether a key from `trusted` signed the
/// set with a signature that is valid now. A revoked key counts as revoked only if it signed
/// the set itself; otherwise it is left out, so a forged REVOKE bit cannot remove anything.
pub fn evaluate(
    trusted: &[(u8, Vec<u8>)],
    owner: &Name,
    records: &[Record],
    now: u32,
) -> (Vec<Seen>, bool) {
    let keys: Vec<(&DNSKEY, &Record)> = records
        .iter()
        .filter(|record| record.name == *owner)
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(key))
                if key.secure_entry_point() && key.zone_key() =>
            {
                Some((key, record))
            }
            _ => None,
        })
        .collect();
    let set: Vec<&Record> = records
        .iter()
        .filter(|record| record.name == *owner && record.record_type() == RecordType::DNSKEY)
        .collect();
    let signatures: Vec<&RRSIG> = records
        .iter()
        .filter(|record| record.name == *owner)
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig))
                if sig.input().type_covered == RecordType::DNSKEY =>
            {
                Some(sig)
            }
            _ => None,
        })
        .collect();
    let signed_by = |key: &DNSKEY| {
        let Ok(tag) = key.calculate_key_tag() else {
            return false;
        };
        signatures.iter().any(|sig| {
            let input = sig.input();
            let fresh = now.wrapping_sub(input.sig_inception.get()).cast_signed() >= 0
                && input.sig_expiration.get().wrapping_sub(now).cast_signed() >= 0;
            fresh
                && input.key_tag == tag
                && input.signer_name == *owner
                && key
                    .verify_rrsig(owner, DNSClass::IN, sig, set.iter().copied())
                    .is_ok()
        })
    };
    let identity = |key: &DNSKEY| {
        (
            u8::from(key.algorithm()),
            key.public_key().public_bytes().to_vec(),
        )
    };
    let validated = keys
        .iter()
        .any(|(key, _)| !key.revoke() && trusted.contains(&identity(key)) && signed_by(key));
    let mut seen = Vec::new();
    for (key, _) in &keys {
        let (algorithm, public_key) = identity(key);
        if key.revoke() {
            if signed_by(key) {
                seen.push(Seen {
                    algorithm,
                    public_key,
                    revoked: true,
                });
            }
        } else {
            seen.push(Seen {
                algorithm,
                public_key,
                revoked: false,
            });
        }
    }
    (seen, validated)
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

    mod signed {
        use super::super::*;
        use hickory_server::proto::dnssec::{
            Algorithm, DnssecSigner, SigningKey, crypto::EcdsaSigningKey,
        };
        use hickory_server::proto::rr::RecordSet;
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::time::Duration;
        use time::OffsetDateTime;

        const NOW: u32 = 1_800_000_000;

        struct Key(Vec<u8>);

        impl Key {
            fn new() -> Self {
                let der = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
                Self(der.secret_pkcs8_der().to_vec())
            }

            fn pair(&self) -> EcdsaSigningKey {
                EcdsaSigningKey::from_pkcs8(
                    &PrivatePkcs8KeyDer::from(self.0.clone()),
                    Algorithm::ECDSAP256SHA256,
                )
                .unwrap()
            }

            fn dnskey(&self, revoke: bool) -> DNSKEY {
                DNSKEY::new(true, true, revoke, self.pair().to_public_key().unwrap())
            }

            fn identity(&self) -> (u8, Vec<u8>) {
                let public = self.pair().to_public_key().unwrap();
                (u8::from(public.algorithm()), public.public_bytes().to_vec())
            }
        }

        /// A root DNSKEY answer. `keys` are (key, revoked). `signers` are (key, revoked, start
        /// of a one hour validity, in unix seconds).
        fn answer(keys: &[(&Key, bool)], signers: &[(&Key, bool, u32)]) -> Vec<Record> {
            let owner = Name::root();
            let mut set = RecordSet::new(owner.clone(), RecordType::DNSKEY, 1);
            for (key, revoke) in keys {
                set.insert(
                    Record::from_rdata(
                        owner.clone(),
                        3600,
                        RData::DNSSEC(DNSSECRData::DNSKEY(key.dnskey(*revoke))),
                    ),
                    1,
                );
            }
            let mut out: Vec<Record> = set.records_without_rrsigs().cloned().collect();
            for (key, revoke, from) in signers {
                let signer = DnssecSigner::new(
                    key.dnskey(*revoke),
                    Box::new(key.pair()),
                    owner.clone(),
                    Duration::from_secs(3600),
                );
                let start = OffsetDateTime::from_unix_timestamp(i64::from(*from)).unwrap();
                let sig = RRSIG::from_rrset(&set, DNSClass::IN, start, &signer).unwrap();
                out.push(Record::from_rdata(
                    owner.clone(),
                    3600,
                    RData::DNSSEC(DNSSECRData::RRSIG(sig)),
                ));
            }
            out
        }

        fn run(trusted: &[&Key], records: &[Record]) -> (Vec<Seen>, bool) {
            let trusted: Vec<_> = trusted.iter().map(|key| key.identity()).collect();
            evaluate(&trusted, &Name::root(), records, NOW)
        }

        #[test]
        fn a_set_signed_by_a_trusted_key_is_validated_and_lists_every_key() {
            let (old, new) = (Key::new(), Key::new());
            let records = answer(&[(&old, false), (&new, false)], &[(&old, false, NOW - 60)]);
            let (seen, validated) = run(&[&old], &records);
            assert!(validated);
            assert_eq!(seen.len(), 2);
            assert!(seen.iter().all(|key| !key.revoked));
        }

        #[test]
        fn a_set_signed_only_by_an_unknown_key_is_not_validated() {
            let (trusted, stranger) = (Key::new(), Key::new());
            let records = answer(
                &[(&trusted, false), (&stranger, false)],
                &[(&stranger, false, NOW - 60)],
            );
            assert!(!run(&[&trusted], &records).1);
        }

        #[test]
        fn expired_and_not_yet_valid_signatures_are_refused() {
            let key = Key::new();
            for start in [NOW - 7200, NOW + 600] {
                let records = answer(&[(&key, false)], &[(&key, false, start)]);
                assert!(!run(&[&key], &records).1, "start {start}");
            }
        }

        #[test]
        fn a_tampered_key_set_fails_the_signature() {
            let (key, other) = (Key::new(), Key::new());
            let mut records = answer(&[(&key, false)], &[(&key, false, NOW - 60)]);
            let extra = answer(&[(&other, false)], &[]);
            records.extend(extra);
            assert!(!run(&[&key], &records).1);
        }

        #[test]
        fn a_revoke_bit_counts_only_when_the_key_signed_itself() {
            let (old, new) = (Key::new(), Key::new());
            // Revoked and self-signed, with the new key vouching for the set too.
            let records = answer(
                &[(&old, true), (&new, false)],
                &[(&old, true, NOW - 60), (&new, false, NOW - 60)],
            );
            let (seen, validated) = run(&[&old, &new], &records);
            assert!(validated);
            assert!(
                seen.iter()
                    .any(|key| key.revoked && key.public_key == old.identity().1)
            );
            // The same set without the revoked key's own signature: the key is left out.
            let records = answer(&[(&old, true), (&new, false)], &[(&new, false, NOW - 60)]);
            let (seen, validated) = run(&[&new], &records);
            assert!(validated);
            assert_eq!(seen.len(), 1);
            assert!(!seen[0].revoked);
        }

        #[test]
        fn a_rollover_runs_through_the_signed_path() {
            let (old, new) = (Key::new(), Key::new());
            let mut anchors = Anchors::seeded([old.identity()]);
            let day = 24 * 3600;
            let step = |anchors: &mut Anchors,
                        at: u64,
                        keys: &[(&Key, bool)],
                        signers: &[(&Key, bool, u32)]| {
                let records = answer(keys, signers);
                let (seen, validated) = evaluate(&anchors.trusted(), &Name::root(), &records, NOW);
                anchors.observe(at, &seen, validated)
            };
            let both = [(&old, false), (&new, false)];
            assert!(!step(&mut anchors, 0, &both, &[(&old, false, NOW - 60)]));
            assert!(step(
                &mut anchors,
                30 * day,
                &both,
                &[(&old, false, NOW - 60)]
            ));
            let revoked = [(&old, true), (&new, false)];
            let signers = [(&old, true, NOW - 60), (&new, false, NOW - 60)];
            assert!(step(&mut anchors, 31 * day, &revoked, &signers));
            assert_eq!(anchors.trusted(), vec![new.identity()]);
        }
    }
}

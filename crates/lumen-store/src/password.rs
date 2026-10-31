// SPDX-License-Identifier: Apache-2.0
//! Salted `PBKDF2-HMAC-SHA256` password records and random session secrets.

use ring::{
    pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use std::num::NonZeroU32;

/// OWASP's current minimum for `PBKDF2-HMAC-SHA256`.
pub const ITERATIONS: u32 = 600_000;
const PREFIX: &str = "pbkdf2-sha256";
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
pub const MIN_LEN: usize = 10;
pub const MAX_LEN: usize = 256;

/// Check the password policy shared by the console and `lumenctl`.
///
/// # Errors
/// Returns a user-facing reason when the password is unacceptable.
pub fn check_policy(password: &str, username: &str) -> Result<(), String> {
    let length = password.chars().count();
    if length < MIN_LEN {
        return Err(format!("password needs at least {MIN_LEN} characters"));
    }
    if length > MAX_LEN {
        return Err(format!("password may have at most {MAX_LEN} characters"));
    }
    let lower = password.to_lowercase();
    if lower == username.to_lowercase()
        || ["password", "12345678", "qwertyuiop", "letmein", "iloveyou"]
            .iter()
            .any(|common| lower.starts_with(common))
        || password
            .chars()
            .collect::<std::collections::HashSet<_>>()
            .len()
            < 5
    {
        return Err("password is too easy to guess".into());
    }
    Ok(())
}

/// Create a stored record. This is CPU heavy; call it off the async executor.
///
/// # Errors
/// Fails only if the system random source is unavailable.
pub fn hash(password: &str) -> Result<String, String> {
    hash_with_iterations(password, ITERATIONS)
}

/// Like [`hash`] with an explicit cost. Tests use a tiny cost; production uses [`ITERATIONS`].
///
/// # Errors
/// Fails only if the system random source is unavailable.
pub fn hash_with_iterations(password: &str, iterations: u32) -> Result<String, String> {
    let mut salt = [0_u8; SALT_LEN];
    SystemRandom::new()
        .fill(&mut salt)
        .map_err(|_| "random source unavailable".to_owned())?;
    let mut out = [0_u8; HASH_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).ok_or("invalid iteration count")?,
        &salt,
        password.as_bytes(),
        &mut out,
    );
    Ok(format!(
        "{PREFIX}${iterations}${}${}",
        to_hex(&salt),
        to_hex(&out)
    ))
}

/// Constant-time verification of a stored record.
#[must_use]
pub fn verify(password: &str, record: &str) -> bool {
    let mut parts = record.split('$');
    let (Some(PREFIX), Some(iterations), Some(salt), Some(hash), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    let (Ok(iterations), Some(salt), Some(hash)) =
        (iterations.parse::<u32>(), from_hex(salt), from_hex(hash))
    else {
        return false;
    };
    let Some(iterations) = NonZeroU32::new(iterations) else {
        return false;
    };
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &salt,
        password.as_bytes(),
        &hash,
    )
    .is_ok()
}

/// Spend the same work as a real check so unknown names are not detectable by timing.
pub fn verify_dummy(password: &str) {
    let _ = verify(password, DUMMY);
}

/// Precomputed record for a random password nobody knows (iterations 600000).
const DUMMY: &str = "pbkdf2-sha256$600000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000";

/// Random lowercase hex secret with `bytes` bytes of entropy.
///
/// # Errors
/// Fails only if the system random source is unavailable.
pub fn random_hex(bytes: usize) -> Result<String, String> {
    let mut buffer = vec![0_u8; bytes];
    SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| "random source unavailable".to_owned())?;
    Ok(to_hex(&buffer))
}

#[must_use]
pub fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    to_hex(&Sha256::digest(value.as_bytes()))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_rejects_wrong_and_malformed() {
        let record = hash_with_iterations("correct horse battery", 1_000).unwrap();
        assert!(record.starts_with("pbkdf2-sha256$1000$"));
        assert!(verify("correct horse battery", &record));
        assert!(!verify("correct horse batterx", &record));
        assert!(!verify("x", "garbage"));
        assert!(!verify("x", "pbkdf2-sha256$0$aa$bb"));
        assert!(!verify("x", &format!("{record}$extra")));
        assert_ne!(
            record,
            hash_with_iterations("correct horse battery", 1_000).unwrap()
        );
    }

    #[test]
    fn policy_blocks_short_common_and_username() {
        assert!(check_policy("short", "admin").is_err());
        assert!(check_policy("password1234", "admin").is_err());
        assert!(check_policy("aaaaaaaaaaaa", "admin").is_err());
        assert!(check_policy("Admin-Admin-1", "admin-admin-1").is_err());
        assert!(check_policy("correct horse battery", "admin").is_ok());
    }

    #[test]
    fn secrets_are_random_hex() {
        let a = random_hex(32).unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, random_hex(32).unwrap());
        assert_eq!(sha256_hex("abc").len(), 64);
    }
}

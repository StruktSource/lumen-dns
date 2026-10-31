// SPDX-License-Identifier: Apache-2.0
//! Time-based one-time passwords (RFC 6238, HMAC-SHA1, 6 digits, 30 s) and
//! single-use recovery codes.

use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};

pub const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// A new random 160-bit secret, as unpadded base32.
///
/// # Errors
/// Fails only if the system random source is unavailable.
pub fn generate_secret() -> Result<String, String> {
    let mut bytes = [0_u8; 20];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "random source unavailable".to_owned())?;
    Ok(base32_encode(&bytes))
}

#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            out.push(char::from(ALPHABET[((buffer >> (bits - 5)) & 31) as usize]));
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

#[must_use]
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    let mut out = Vec::new();
    for ch in text.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let upper = u8::try_from(ch.to_ascii_uppercase()).ok()?;
        let value = ALPHABET.iter().position(|a| *a == upper)?;
        buffer = (buffer << 5) | u32::try_from(value).ok()?;
        bits += 5;
        if bits >= 8 {
            out.push(u8::try_from((buffer >> (bits - 8)) & 0xff).ok()?);
            bits -= 8;
        }
    }
    Some(out)
}

/// The code for a time step.
#[must_use]
pub fn code_for_step(secret: &str, step: u64) -> Option<String> {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &base32_decode(secret)?);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let digest = tag.as_ref();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    Some(format!(
        "{:0width$}",
        binary % 10_u32.pow(DIGITS),
        width = DIGITS as usize
    ))
}

#[must_use]
pub fn step_at(unix_seconds: u64) -> u64 {
    unix_seconds / STEP_SECS
}

/// Check a code against the current step and one step either side (clock drift).
/// Returns the matching step so the caller can refuse a replay.
#[must_use]
pub fn verify(secret: &str, code: &str, unix_seconds: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_at(unix_seconds);
    let mut found = None;
    // Check every candidate so timing does not reveal which one matched.
    for step in [now.saturating_sub(1), now, now + 1] {
        let expected = code_for_step(secret, step)?;
        if bool::from(subtle::ConstantTimeEq::ct_eq(
            expected.as_bytes(),
            code.as_bytes(),
        )) {
            found = Some(step);
        }
    }
    found
}

/// `otpauth://` URI that authenticator apps understand.
#[must_use]
pub fn uri(secret: &str, account: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}"
    )
}

/// Ten single-use recovery codes like `7k3m9-q2x8d`.
///
/// # Errors
/// Fails only if the system random source is unavailable.
pub fn recovery_codes() -> Result<Vec<String>, String> {
    const CHARS: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut codes = Vec::new();
    for _ in 0..10 {
        let mut raw = [0_u8; 10];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| "random source unavailable".to_owned())?;
        let letters: Vec<char> = raw
            .iter()
            .map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()]))
            .collect();
        codes.push(format!(
            "{}-{}",
            letters[..5].iter().collect::<String>(),
            letters[5..].iter().collect::<String>()
        ));
    }
    Ok(codes)
}

/// Normalise what a person typed: lowercase, no spaces.
#[must_use]
pub fn clean_recovery(input: &str) -> String {
    input.trim().to_lowercase().replace(' ', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B secret "12345678901234567890" (SHA-1), 6-digit truncation.
    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn matches_rfc_6238_vectors() {
        for (time, expected) in [
            (59_u64, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(
                code_for_step(SECRET, step_at(time)).unwrap(),
                expected,
                "t={time}"
            );
        }
    }

    #[test]
    fn verify_allows_one_step_of_drift_only() {
        let now = 1_700_000_000;
        let code = code_for_step(SECRET, step_at(now)).unwrap();
        assert_eq!(verify(SECRET, &code, now), Some(step_at(now)));
        assert_eq!(verify(SECRET, &code, now + 30), Some(step_at(now)));
        assert_eq!(verify(SECRET, &code, now - 30), Some(step_at(now)));
        assert_eq!(verify(SECRET, &code, now + 90), None);
        assert_eq!(verify(SECRET, "12345", now), None);
        assert_eq!(verify(SECRET, "abcdef", now), None);
    }

    #[test]
    fn base32_round_trips_and_codes_are_unique() {
        let secret = generate_secret().unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(base32_encode(&base32_decode(&secret).unwrap()), secret);
        assert_eq!(
            base32_decode("gezd gnbv").unwrap(),
            base32_decode("GEZDGNBV").unwrap()
        );
        let codes = recovery_codes().unwrap();
        assert_eq!(codes.len(), 10);
        assert_eq!(
            codes.iter().collect::<std::collections::HashSet<_>>().len(),
            10
        );
        assert!(
            codes
                .iter()
                .all(|c| c.len() == 11 && c.as_bytes()[5] == b'-')
        );
        assert!(uri(&secret, "anna", "Lumen").starts_with("otpauth://totp/Lumen:anna?secret="));
    }
}

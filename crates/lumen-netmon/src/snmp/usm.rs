//! The `SNMPv3` user-based security model (RFC 3414), with the SHA-2 authentication protocols of
//! RFC 7860 and AES-128 privacy (RFC 3826). MD5 and DES are not offered.

use aes::Aes128;
use cfb_mode::{BufDecryptor, BufEncryptor, cipher::KeyIvInit};
use lumen_config::{SnmpAuth, SnmpPrivacy};
use ring::{digest, hmac};

/// Bytes of the stretched password (RFC 3414 section A.2.1).
const STRETCH: usize = 1_048_576;

fn algorithm(auth: SnmpAuth) -> (&'static digest::Algorithm, hmac::Algorithm, usize) {
    match auth {
        SnmpAuth::Sha1 => (
            &digest::SHA1_FOR_LEGACY_USE_ONLY,
            hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            12,
        ),
        SnmpAuth::Sha256 => (&digest::SHA256, hmac::HMAC_SHA256, 24),
        SnmpAuth::Sha384 => (&digest::SHA384, hmac::HMAC_SHA384, 32),
        SnmpAuth::Sha512 => (&digest::SHA512, hmac::HMAC_SHA512, 48),
    }
}

/// Length of the authentication parameter field for a protocol.
#[must_use]
pub fn mac_len(auth: SnmpAuth) -> usize {
    algorithm(auth).2
}

/// A password turned into a key tied to one device's engine ID.
///
/// # Panics
/// Never: the password is expanded in fixed blocks.
#[must_use]
pub fn localize(auth: SnmpAuth, password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let (hash, _, _) = algorithm(auth);
    let mut context = digest::Context::new(hash);
    let mut block = [0u8; 64];
    let mut at = 0;
    let mut fed = 0;
    while fed < STRETCH {
        for slot in &mut block {
            *slot = password[at % password.len()];
            at += 1;
        }
        context.update(&block);
        fed += block.len();
    }
    let ku = context.finish();
    let mut again = digest::Context::new(hash);
    again.update(ku.as_ref());
    again.update(engine_id);
    again.update(ku.as_ref());
    again.finish().as_ref().to_vec()
}

/// The authentication code of a whole message, whose authentication field is zeros.
#[must_use]
pub fn authenticate(auth: SnmpAuth, key: &[u8], message: &[u8]) -> Vec<u8> {
    let (_, algorithm, len) = algorithm(auth);
    let tag = hmac::sign(&hmac::Key::new(algorithm, key), message);
    tag.as_ref()[..len].to_vec()
}

/// Constant-time comparison of the received code with the one we compute.
#[must_use]
pub fn verify(auth: SnmpAuth, key: &[u8], message: &[u8], received: &[u8]) -> bool {
    let (_, algorithm, len) = algorithm(auth);
    if received.len() != len {
        return false;
    }
    let expected = hmac::sign(&hmac::Key::new(algorithm, key), message);
    let expected = &expected.as_ref()[..len];
    // ring has no truncated verify; compare without early exit.
    expected
        .iter()
        .zip(received)
        .fold(0u8, |d, (a, b)| d | (a ^ b))
        == 0
}

fn iv(boots: u32, time: u32, salt: [u8; 8]) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(&salt);
    iv
}

/// Encrypt a scoped PDU in place.
pub fn encrypt(
    privacy: SnmpPrivacy,
    key: &[u8],
    boots: u32,
    time: u32,
    salt: &[u8; 8],
    data: &mut [u8],
) {
    match privacy {
        SnmpPrivacy::Aes128 => {
            let mut key16 = [0u8; 16];
            key16.copy_from_slice(&key[..16]);
            BufEncryptor::<Aes128>::new(&key16.into(), &iv(boots, time, *salt).into())
                .encrypt(data);
        }
    }
}

/// Decrypt a scoped PDU in place.
pub fn decrypt(
    privacy: SnmpPrivacy,
    key: &[u8],
    boots: u32,
    time: u32,
    salt: &[u8; 8],
    data: &mut [u8],
) {
    match privacy {
        SnmpPrivacy::Aes128 => {
            let mut key16 = [0u8; 16];
            key16.copy_from_slice(&key[..16]);
            BufDecryptor::<Aes128>::new(&key16.into(), &iv(boots, time, *salt).into())
                .decrypt(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
    }

    #[test]
    fn sha1_key_localization_matches_rfc_3414_appendix_a() {
        let engine = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let key = localize(SnmpAuth::Sha1, b"maplesyrup", &engine);
        assert_eq!(hex(&key), "6695febc9288e36282235fc7151f128497b38f3f");
    }

    #[test]
    fn authentication_codes_are_truncated_per_protocol_and_verify() {
        for (auth, len) in [
            (SnmpAuth::Sha1, 12),
            (SnmpAuth::Sha256, 24),
            (SnmpAuth::Sha384, 32),
            (SnmpAuth::Sha512, 48),
        ] {
            let key = localize(auth, b"authpassword", b"engine");
            let tag = authenticate(auth, &key, b"message");
            assert_eq!(tag.len(), len);
            assert_eq!(mac_len(auth), len);
            assert!(verify(auth, &key, b"message", &tag));
            assert!(!verify(auth, &key, b"messagE", &tag));
            let mut bad = tag.clone();
            bad[0] ^= 1;
            assert!(!verify(auth, &key, b"message", &bad));
            assert!(!verify(auth, &key, b"message", &tag[1..]));
        }
    }

    #[test]
    fn aes_cfb_round_trips_and_changes_the_data() {
        let key = localize(SnmpAuth::Sha256, b"privpassword", b"engine");
        let plain = b"a scoped pdu of an odd length 123".to_vec();
        let mut data = plain.clone();
        encrypt(
            SnmpPrivacy::Aes128,
            &key,
            3,
            1000,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &mut data,
        );
        assert_ne!(data, plain);
        assert_eq!(data.len(), plain.len(), "CFB needs no padding");
        decrypt(
            SnmpPrivacy::Aes128,
            &key,
            3,
            1000,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &mut data,
        );
        assert_eq!(data, plain);
        let mut other = plain.clone();
        encrypt(SnmpPrivacy::Aes128, &key, 3, 1000, &[9; 8], &mut other);
        let mut first = plain.clone();
        encrypt(
            SnmpPrivacy::Aes128,
            &key,
            3,
            1000,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            &mut first,
        );
        assert_ne!(other, first, "a new salt gives new ciphertext");
    }
}

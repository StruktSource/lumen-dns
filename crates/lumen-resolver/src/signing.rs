//! DNSSEC signing keys for operator zones: loading, creation, and the DS record for the parent.

use base64::Engine as _;
use hickory_server::proto::{
    dnssec::{
        Algorithm, DigestType, DnssecSigner, PublicKey, SigningKey,
        crypto::{EcdsaSigningKey, Ed25519SigningKey, signing_key_from_der},
        rdata::DNSKEY,
    },
    rr::Name,
};
use lumen_config::{SigningAlgorithm, ZoneSigning, read_bounded};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use std::{fmt::Write as _, path::Path, time::Duration};

fn algorithm(choice: SigningAlgorithm) -> Algorithm {
    match choice {
        SigningAlgorithm::Ed25519 => Algorithm::ED25519,
        SigningAlgorithm::Ecdsap256sha256 => Algorithm::ECDSAP256SHA256,
    }
}

fn private_key(path: &Path, choice: SigningAlgorithm) -> Result<Box<dyn SigningKey>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path)
            .map_err(|_| "cannot read zone signing key")?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(
                "zone signing key must not be readable by group or others (chmod 600)".into(),
            );
        }
    }
    let bytes = read_bounded(path, 8192)?;
    let der = PrivatePkcs8KeyDer::from_pem_slice(&bytes)
        .map_err(|_| "zone signing key must be a PKCS#8 PEM private key")?;
    signing_key_from_der(&PrivateKeyDer::Pkcs8(der), algorithm(choice))
        .map_err(|_| "zone signing key does not match its algorithm".to_string())
}

/// Build the signer for `origin`: one combined key (zone and key signing), signatures valid
/// for `signature_days`.
pub(crate) fn signer(signing: &ZoneSigning, origin: &Name) -> Result<DnssecSigner, String> {
    let key = private_key(&signing.key_file, signing.algorithm)?;
    let public = key
        .to_public_key()
        .map_err(|_| "zone signing key has no usable public key")?;
    let dnskey = DNSKEY::from_key(&public);
    Ok(DnssecSigner::new(
        dnskey,
        key,
        origin.clone(),
        Duration::from_secs(u64::from(signing.signature_days) * 24 * 3600),
    ))
}

/// The DNSKEY and DS lines for a zone, in zone-file form.
fn describe(dnskey: &DNSKEY, origin: &Name) -> Result<String, String> {
    let tag = dnskey
        .calculate_key_tag()
        .map_err(|_| "cannot compute the key tag")?;
    let digest = dnskey
        .to_digest(origin, DigestType::SHA256)
        .map_err(|_| "cannot compute the DS digest")?;
    let mut hex = String::new();
    for byte in digest.as_ref() {
        let _ = write!(hex, "{byte:02X}");
    }
    let key = base64::engine::general_purpose::STANDARD.encode(dnskey.public_key().public_bytes());
    Ok(format!(
        "{origin} IN DNSKEY {} 3 {} {key}\n{origin} IN DS {tag} {} 2 {hex}\n",
        dnskey.flags(),
        u8::from(dnskey.public_key().algorithm()),
        u8::from(dnskey.public_key().algorithm()),
    ))
}

/// Create the key at `path` if it does not exist (mode `0600`, never overwritten), then
/// describe it. Give the DS line to the parent zone's operator or registrar.
///
/// # Errors
/// A non-sensitive message when the key cannot be created, read, or matched to `algorithm`.
pub fn zone_key(path: &Path, zone: &str, choice: SigningAlgorithm) -> Result<String, String> {
    let origin = Name::from_ascii(format!("{}.", zone.trim_end_matches('.')))
        .map_err(|_| "invalid zone name")?;
    let mut created = false;
    if !path.exists() {
        let der = match choice {
            SigningAlgorithm::Ed25519 => Ed25519SigningKey::generate_pkcs8(),
            SigningAlgorithm::Ecdsap256sha256 => {
                EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256)
            }
        }
        .map_err(|_| "cannot generate a key")?;
        let body = base64::engine::general_purpose::STANDARD.encode(der.secret_pkcs8_der());
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for line in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        write_new_private(path, pem.as_bytes())?;
        created = true;
    }
    let key = private_key(path, choice)?;
    let public = key
        .to_public_key()
        .map_err(|_| "key has no usable public key")?;
    let text = describe(&DNSKEY::from_key(&public), &origin)?;
    Ok(format!(
        "{} {}\n{text}",
        if created { "Created" } else { "Using" },
        path.display()
    ))
}

fn write_new_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .map_err(|_| "cannot write the key file".to_string())
}

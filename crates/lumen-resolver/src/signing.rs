//! DNSSEC signing keys for operator zones: loading, creation, and the DS record for the parent.

use base64::Engine as _;
use hickory_server::dnssec::NxProofKind;
use hickory_server::proto::{
    dnssec::{
        Algorithm, DigestType, DnssecSigner, Nsec3HashAlgorithm, PublicKey, PublicKeyBuf,
        SigningKey,
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

#[derive(Clone, Copy)]
enum KeyRole {
    Combined,
    Ksk,
    Zsk,
}

fn signer_for(
    path: &Path,
    choice: SigningAlgorithm,
    signing: &ZoneSigning,
    origin: &Name,
    role: KeyRole,
) -> Result<DnssecSigner, String> {
    let key = private_key(path, choice)?;
    let public = key
        .to_public_key()
        .map_err(|_| "zone signing key has no usable public key")?;
    let public_buf = PublicKeyBuf::new(public.public_bytes().to_vec(), public.algorithm());
    let dnskey = match role {
        KeyRole::Combined | KeyRole::Ksk => DNSKEY::new(true, true, false, public_buf),
        KeyRole::Zsk => DNSKEY::new(true, false, false, public_buf),
    };
    Ok(DnssecSigner::new(
        dnskey,
        key,
        origin.clone(),
        Duration::from_secs(u64::from(signing.signature_days) * 24 * 3600),
    ))
}

/// Build the pre-publish/double-sign set, or the set left after a scheduled handoff.
pub(crate) fn signers_for_phase(
    signing: &ZoneSigning,
    origin: &Name,
    after_rollover: bool,
) -> Result<Vec<DnssecSigner>, String> {
    let mut out = Vec::new();
    let mut add = |path: &Path, choice, role| -> Result<(), String> {
        let signer = signer_for(path, choice, signing, origin, role)?;
        let public = signer
            .key()
            .to_public_key()
            .map_err(|_| "zone signing key has no usable public key")?;
        if out.iter().any(|current: &DnssecSigner| {
            current
                .key()
                .to_public_key()
                .is_ok_and(|key| key.public_bytes() == public.public_bytes())
        }) {
            return Err("zone dnssec key files hold the same key".into());
        }
        out.push(signer);
        Ok(())
    };

    if !signing.key_file.as_os_str().is_empty() {
        if !after_rollover || signing.next_key_file.is_none() {
            add(&signing.key_file, signing.algorithm, KeyRole::Combined)?;
        }
        if let Some(next) = &signing.next_key_file {
            add(
                next,
                signing.next_algorithm.unwrap_or(signing.algorithm),
                KeyRole::Combined,
            )?;
        }
        return Ok(out);
    }

    let ksk = signing
        .ksk_file
        .as_ref()
        .ok_or("zone dnssec needs ksk_file")?;
    let zsk = signing
        .zsk_file
        .as_ref()
        .ok_or("zone dnssec needs zsk_file")?;
    if !after_rollover || signing.next_ksk_file.is_none() {
        add(ksk, signing.ksk_algorithm, KeyRole::Ksk)?;
    }
    if let Some(next) = &signing.next_ksk_file {
        add(
            next,
            signing.next_ksk_algorithm.unwrap_or(signing.ksk_algorithm),
            KeyRole::Ksk,
        )?;
    }
    if !after_rollover || signing.next_zsk_file.is_none() {
        add(zsk, signing.zsk_algorithm, KeyRole::Zsk)?;
    }
    if let Some(next) = &signing.next_zsk_file {
        add(
            next,
            signing.next_zsk_algorithm.unwrap_or(signing.zsk_algorithm),
            KeyRole::Zsk,
        )?;
    }
    Ok(out)
}

/// The denial-of-existence setting of a signed zone.
pub(crate) fn proof_kind(signing: &ZoneSigning) -> Result<NxProofKind, String> {
    Ok(match signing.denial {
        lumen_config::Denial::Nsec => NxProofKind::Nsec,
        lumen_config::Denial::Nsec3 => NxProofKind::Nsec3 {
            algorithm: Nsec3HashAlgorithm::SHA1,
            salt: match &signing.nsec3_salt {
                Some(salt) => lumen_config::parse_hex(salt)
                    .ok_or("invalid nsec3_salt")?
                    .into(),
                None => Vec::new().into(),
            },
            // RFC 9276: extra iterations only cost resolvers and add no protection.
            iterations: 0,
            opt_out: signing.nsec3_opt_out,
        },
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_ksk_zsk_sets_publish_then_retire_successors_by_role() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = ["ksk.pem", "zsk.pem", "next-ksk.pem", "next-zsk.pem"]
            .into_iter()
            .map(|name| dir.path().join(name))
            .collect();
        for path in &paths {
            zone_key(path, "signed.test", SigningAlgorithm::Ed25519).unwrap();
        }
        let signing = ZoneSigning {
            ksk_file: Some(paths[0].clone()),
            zsk_file: Some(paths[1].clone()),
            next_ksk_file: Some(paths[2].clone()),
            next_zsk_file: Some(paths[3].clone()),
            ..Default::default()
        };
        let origin = Name::from_ascii("signed.test.").unwrap();
        let before = signers_for_phase(&signing, &origin, false).unwrap();
        assert_eq!(before.len(), 4);
        assert_eq!(
            before
                .iter()
                .filter(|signer| signer.dnskey().secure_entry_point())
                .count(),
            2
        );
        assert_eq!(
            before
                .iter()
                .filter(|signer| !signer.dnskey().secure_entry_point())
                .count(),
            2
        );

        let after = signers_for_phase(&signing, &origin, true).unwrap();
        assert_eq!(after.len(), 2);
        assert_eq!(
            after
                .iter()
                .filter(|signer| signer.dnskey().secure_entry_point())
                .count(),
            1
        );
        assert_eq!(
            after
                .iter()
                .filter(|signer| !signer.dnskey().secure_entry_point())
                .count(),
            1
        );
    }
}

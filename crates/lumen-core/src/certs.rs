// SPDX-License-Identifier: Apache-2.0
//! TLS certificate loading with safe, in-place replacement.
//!
//! One resolver serves every encrypted DNS listener. A renewed certificate pair (from certbot,
//! acme.sh, lego, or any tool that writes PEM files) is picked up without a restart: the new
//! pair is loaded and checked first, and only a complete, matching pair replaces the old one.
//! A half-written or mismatched pair keeps the previous certificate serving.

use lumen_config::read_bounded;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::SystemTime,
};

type Stamp = [(Option<SystemTime>, u64); 2];

/// What one check found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reload {
    Unchanged,
    /// A new pair is now serving. The value is its `notAfter` as a Unix timestamp.
    Replaced(i64),
    /// The files changed but do not form a valid pair. The previous pair keeps serving.
    Rejected,
}

pub struct CertReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    current: RwLock<Arc<CertifiedKey>>,
    seen: Mutex<Stamp>,
}

impl std::fmt::Debug for CertReloader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CertReloader")
    }
}

fn stamp(cert: &Path, key: &Path) -> Stamp {
    let one = |path: &Path| {
        std::fs::metadata(path).map_or((None, 0), |meta| (meta.modified().ok(), meta.len()))
    };
    [one(cert), one(key)]
}

/// Load and verify one certificate pair. Returns the pair and its expiry.
fn read_pair(cert: &Path, key: &Path) -> io::Result<(CertifiedKey, i64)> {
    let cert_bytes = read_bounded(cert, 1_048_576).map_err(io::Error::other)?;
    let key_bytes = read_bounded(key, 65536).map_err(io::Error::other)?;
    let chain = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::other("invalid PEM certificate"))?;
    if chain.is_empty() || chain.len() > 8 {
        return Err(io::Error::other(
            "certificate file needs 1..=8 certificates",
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .map_err(|_| io::Error::other("invalid PEM private key"))?;
    let signing = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|_| io::Error::other("unsupported private key"))?;
    let certified = CertifiedKey::new(chain, signing);
    certified
        .keys_match()
        .map_err(|_| io::Error::other("certificate and private key do not match"))?;
    let (_, parsed) =
        x509_parser::parse_x509_certificate(certified.end_entity_cert().map_err(io::Error::other)?)
            .map_err(|_| io::Error::other("unreadable certificate"))?;
    let not_after = parsed.validity().not_after.timestamp();
    Ok((certified, not_after))
}

impl CertReloader {
    /// Load the first pair. Startup fails if it is unusable.
    ///
    /// # Errors
    /// Unreadable, oversized, malformed, or mismatched files.
    pub fn load(cert: &Path, key: &Path) -> io::Result<(Arc<Self>, i64)> {
        let seen = stamp(cert, key);
        let (certified, not_after) = read_pair(cert, key)?;
        Ok((
            Arc::new(Self {
                cert_path: cert.to_path_buf(),
                key_path: key.to_path_buf(),
                current: RwLock::new(Arc::new(certified)),
                seen: Mutex::new(seen),
            }),
            not_after,
        ))
    }

    /// Check the files and swap in a changed, valid pair.
    pub fn poll(&self) -> Reload {
        let now = stamp(&self.cert_path, &self.key_path);
        let Ok(mut seen) = self.seen.lock() else {
            return Reload::Unchanged;
        };
        if *seen == now {
            return Reload::Unchanged;
        }
        // Remember this state either way so one bad pair is reported once, not every tick. A
        // later write changes the stamp and is tried again.
        *seen = now;
        if let Ok((certified, not_after)) = read_pair(&self.cert_path, &self.key_path) {
            if let Ok(mut current) = self.current.write() {
                *current = Arc::new(certified);
            }
            Reload::Replaced(not_after)
        } else {
            Reload::Rejected
        }
    }
}

impl ResolvesServerCert for CertReloader {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.read().ok().map(|current| Arc::clone(&current))
    }
}

// SPDX-License-Identifier: Apache-2.0
//! `DNSCrypt` v2 server protocol: certificates, key rotation, and query/response boxes.
//!
//! This module is pure protocol logic with no sockets. Listeners live in `transport.rs`.
//! Both authenticated-encryption suites are offered: `X25519-XSalsa20Poly1305` (version 1)
//! and `X25519-XChaCha20Poly1305` (version 2). Short-term resolver keys live only in memory and
//! rotate at half the certificate lifetime; the long-term Ed25519 provider key is a file.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crypto_box::{
    ChaChaBox, PublicKey, SalsaBox, SecretKey,
    aead::{Aead, generic_array::GenericArray},
};
use ed25519_dalek::{Signer, SigningKey};
use lumen_proto::hickory_proto::{
    op::{Message, OpCode, ResponseCode},
    rr::{DNSClass, RData, Record, RecordType, rdata::TXT},
};
use rand_core::{OsRng, RngCore};
use std::{
    io,
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU32, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

/// Resolver response magic from the `DNSCrypt` v2 specification.
const RESOLVER_MAGIC: [u8; 8] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
const CERT_MAGIC: [u8; 4] = *b"DNSC";
const ES_XSALSA20: u16 = 1;
const ES_XCHACHA20: u16 = 2;
const TAG_BYTES: usize = 16;
const NONCE_HALF: usize = 12;
/// Smallest UDP query accepted. Shorter datagrams cannot amplify and are dropped.
pub const MIN_UDP_QUERY: usize = 256;
const PADDING_BLOCK: usize = 64;
/// Previous and current certificates kept at once (two suites times two generations).
const MAX_KEYS: usize = 4;

/// One short-lived resolver key pair with its signed certificate.
struct ResolverKeys {
    version: u16,
    secret: SecretKey,
    magic: [u8; 8],
    certificate: [u8; 124],
    created: u64,
    not_after: u64,
}

impl ResolverKeys {
    fn open(&self, client: &PublicKey, nonce: &[u8; 24], data: &[u8]) -> Option<Vec<u8>> {
        let nonce = GenericArray::from_slice(nonce);
        if self.version == ES_XCHACHA20 {
            ChaChaBox::new(client, &self.secret)
                .decrypt(nonce, data)
                .ok()
        } else {
            SalsaBox::new(client, &self.secret)
                .decrypt(nonce, data)
                .ok()
        }
    }

    fn seal(&self, client: &PublicKey, nonce: &[u8; 24], data: &[u8]) -> Option<Vec<u8>> {
        let nonce = GenericArray::from_slice(nonce);
        if self.version == ES_XCHACHA20 {
            ChaChaBox::new(client, &self.secret)
                .encrypt(nonce, data)
                .ok()
        } else {
            SalsaBox::new(client, &self.secret)
                .encrypt(nonce, data)
                .ok()
        }
    }
}

/// A decrypted client query and what is needed to answer it.
pub struct Decrypted {
    pub dns: Vec<u8>,
    keys: Arc<ResolverKeys>,
    client: PublicKey,
    client_nonce: [u8; NONCE_HALF],
    /// Size of the received datagram, which caps a UDP response.
    pub datagram: usize,
}

/// What a received packet turned out to be.
pub enum Packet {
    /// A plain DNS certificate query, answered directly.
    Certificate(Vec<u8>),
    /// An authenticated, decrypted DNS query.
    Query(Decrypted),
}

pub struct DnsCrypt {
    provider: String,
    signing: SigningKey,
    lifetime: u64,
    serial: AtomicU32,
    keys: RwLock<Vec<Arc<ResolverKeys>>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl DnsCrypt {
    /// Load or create the provider key and issue the first certificates.
    ///
    /// # Errors
    /// Fails if the key file is unreadable, malformed, or cannot be created.
    pub fn load(provider: &str, key_file: &Path, hours: u32) -> io::Result<Self> {
        let signing = load_or_create_key(key_file)?;
        let server = Self {
            provider: provider.to_ascii_lowercase(),
            signing,
            lifetime: u64::from(hours) * 3600,
            serial: AtomicU32::new(1),
            keys: RwLock::new(Vec::new()),
        };
        server.rotate(now());
        Ok(server)
    }

    /// The provider's Ed25519 public key, which clients pin through a DNS stamp.
    #[must_use]
    pub fn provider_public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    #[must_use]
    pub fn provider_name(&self) -> &str {
        &self.provider
    }

    /// Issue new certificates when the newest is older than half its lifetime.
    pub fn rotate_if_due(&self) {
        let now = now();
        let due = self.keys.read().map_or(true, |keys| {
            keys.iter()
                .map(|key| key.created)
                .max()
                .is_none_or(|created| now >= created + self.lifetime / 2)
        });
        if due {
            self.rotate(now);
        }
    }

    fn rotate(&self, now: u64) {
        let mut fresh = Vec::new();
        for version in [ES_XCHACHA20, ES_XSALSA20] {
            let secret = SecretKey::generate(&mut OsRng);
            let public = PublicKey::from(&secret);
            let mut magic = [0_u8; 8];
            magic.copy_from_slice(&public.as_bytes()[..8]);
            let serial = self.serial.fetch_add(1, Ordering::Relaxed);
            let start = now.saturating_sub(60);
            let end = now + self.lifetime;
            let mut signed = Vec::with_capacity(52);
            signed.extend_from_slice(public.as_bytes());
            signed.extend_from_slice(&magic);
            signed.extend_from_slice(&serial.to_be_bytes());
            signed.extend_from_slice(&clamp32(start).to_be_bytes());
            signed.extend_from_slice(&clamp32(end).to_be_bytes());
            let signature = self.signing.sign(&signed).to_bytes();
            let mut certificate = [0_u8; 124];
            certificate[..4].copy_from_slice(&CERT_MAGIC);
            certificate[4..6].copy_from_slice(&version.to_be_bytes());
            certificate[8..72].copy_from_slice(&signature);
            certificate[72..].copy_from_slice(&signed);
            fresh.push(Arc::new(ResolverKeys {
                version,
                secret,
                magic,
                certificate,
                created: now,
                not_after: end,
            }));
        }
        if let Ok(mut keys) = self.keys.write() {
            keys.retain(|key| key.not_after > now);
            keys.extend(fresh);
            // Newest first, bounded.
            keys.sort_by_key(|key| std::cmp::Reverse(key.created));
            keys.truncate(MAX_KEYS);
        }
    }

    /// Classify a datagram or TCP frame. `None` means silently drop it.
    #[must_use]
    pub fn open(&self, packet: &[u8], udp: bool) -> Option<Packet> {
        if udp && packet.len() < MIN_UDP_QUERY {
            // Too small for an encrypted query, but a plain certificate query is short.
            return self.certificate_response(packet).map(Packet::Certificate);
        }
        if packet.len() >= 8 + 32 + NONCE_HALF + TAG_BYTES {
            let keys = self
                .keys
                .read()
                .ok()?
                .iter()
                .find(|key| key.magic == packet[..8])
                .cloned();
            if let Some(keys) = keys {
                return Self::decrypt(&keys, packet).map(Packet::Query);
            }
        }
        self.certificate_response(packet).map(Packet::Certificate)
    }

    fn decrypt(keys: &Arc<ResolverKeys>, packet: &[u8]) -> Option<Decrypted> {
        let client_bytes: [u8; 32] = packet[8..40].try_into().ok()?;
        let client = PublicKey::from(client_bytes);
        let mut client_nonce = [0_u8; NONCE_HALF];
        client_nonce.copy_from_slice(&packet[40..40 + NONCE_HALF]);
        let mut nonce = [0_u8; 24];
        nonce[..NONCE_HALF].copy_from_slice(&client_nonce);
        let mut plain = keys.open(&client, &nonce, &packet[40 + NONCE_HALF..])?;
        // ISO/IEC 7816-4 padding: remove zero bytes, then exactly one 0x80.
        while plain.last() == Some(&0) {
            plain.pop();
        }
        if plain.pop() != Some(0x80) || plain.len() < 12 {
            return None;
        }
        Some(Decrypted {
            dns: plain,
            keys: Arc::clone(keys),
            client,
            client_nonce,
            datagram: packet.len(),
        })
    }

    /// Answer a plain `TXT` query for the provider name with every current certificate.
    fn certificate_response(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let request = lumen_proto::decode_message(packet).ok()?;
        if request.metadata.message_type != lumen_proto::hickory_proto::op::MessageType::Query {
            return None;
        }
        let question = request.queries.first()?;
        if request.queries.len() != 1
            || question.query_type() != RecordType::TXT
            || question.query_class() != DNSClass::IN
            || question
                .name()
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase()
                != self.provider
        {
            return None;
        }
        let mut response = Message::response(request.metadata.id, OpCode::Query);
        response.metadata.authoritative = true;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.response_code = ResponseCode::NoError;
        response.queries.clone_from(&request.queries);
        let now = now();
        for key in self
            .keys
            .read()
            .ok()?
            .iter()
            .filter(|key| key.not_after > now)
        {
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                600,
                RData::TXT(TXT::from_bytes(vec![&key.certificate[..]])),
            ));
        }
        response.to_vec().ok()
    }

    /// Encrypt a DNS response. For UDP, a response larger than the query datagram is replaced by
    /// a truncated one so the client retries over TCP and cannot be used for amplification.
    #[must_use]
    pub fn seal(query: &Decrypted, response: &[u8], udp: bool) -> Option<Vec<u8>> {
        let sealed = Self::seal_once(query, response)?;
        if !udp || sealed.len() <= query.datagram {
            return Some(sealed);
        }
        let mut message = lumen_proto::decode_message(response).ok()?;
        message.metadata.truncation = true;
        message.answers.clear();
        message.authorities.clear();
        message.additionals.clear();
        let truncated = Self::seal_once(query, &message.to_vec().ok()?)?;
        (truncated.len() <= query.datagram).then_some(truncated)
    }

    fn seal_once(query: &Decrypted, response: &[u8]) -> Option<Vec<u8>> {
        let mut plain = Vec::with_capacity(response.len() + PADDING_BLOCK);
        plain.extend_from_slice(response);
        plain.push(0x80);
        plain.resize(plain.len().div_ceil(PADDING_BLOCK) * PADDING_BLOCK, 0);
        let mut nonce = [0_u8; 24];
        nonce[..NONCE_HALF].copy_from_slice(&query.client_nonce);
        OsRng.fill_bytes(&mut nonce[NONCE_HALF..]);
        let encrypted = query.keys.seal(&query.client, &nonce, &plain)?;
        let mut out = Vec::with_capacity(8 + 24 + encrypted.len());
        out.extend_from_slice(&RESOLVER_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&encrypted);
        Some(out)
    }

    /// A `sdns://` stamp for clients such as dnscrypt-proxy. No privacy properties are claimed.
    #[must_use]
    pub fn stamp(&self, address: std::net::SocketAddr) -> String {
        let host = if address.ip().is_unspecified() {
            format!(":{}", address.port())
        } else {
            address.to_string()
        };
        let mut raw = vec![0x01];
        raw.extend_from_slice(&0_u64.to_le_bytes());
        for field in [
            host.as_bytes(),
            &self.provider_public_key()[..],
            self.provider.as_bytes(),
        ] {
            raw.push(u8::try_from(field.len()).unwrap_or(u8::MAX));
            raw.extend_from_slice(field);
        }
        format!("sdns://{}", URL_SAFE_NO_PAD.encode(raw))
    }
}

/// Lowercase hex, used for the provider key file and the startup log.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn clamp32(value: u64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn load_or_create_key(path: &Path) -> io::Result<SigningKey> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let bytes = decode_hex(text.trim())
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| io::Error::other("dnscrypt key_file must hold 64 hex characters"))?;
            let seed: [u8; 32] = bytes.try_into().map_err(|_| io::Error::other("bad key"))?;
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let signing = SigningKey::generate(&mut OsRng);
            write_private(path, to_hex(&signing.to_bytes()).as_bytes())?;
            Ok(signing)
        }
        Err(error) => Err(error),
    }
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(data)?;
    file.write_all(b"\n")
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
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
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    fn server() -> (DnsCrypt, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let server = DnsCrypt::load(
            "2.dnscrypt-cert.example.test",
            &directory.path().join("provider.key"),
            24,
        )
        .unwrap();
        (server, directory)
    }

    fn txt_query(name: &str) -> Vec<u8> {
        let mut message = Message::query();
        message.metadata.id = 7;
        message.add_query(lumen_proto::hickory_proto::op::Query::query(
            lumen_proto::hickory_proto::rr::Name::from_ascii(name).unwrap(),
            RecordType::TXT,
        ));
        message.to_vec().unwrap()
    }

    #[test]
    fn certificates_are_signed_and_only_for_the_provider_name() {
        let (server, directory) = server();
        let Some(Packet::Certificate(response)) =
            server.open(&txt_query("2.dnscrypt-cert.example.test."), false)
        else {
            panic!("expected certificates")
        };
        let message = lumen_proto::decode_message(&response).unwrap();
        assert_eq!(message.answers.len(), 2);
        let verifying = VerifyingKey::from_bytes(&server.provider_public_key()).unwrap();
        for record in &message.answers {
            let RData::TXT(txt) = &record.data else {
                panic!("not TXT")
            };
            let cert: Vec<u8> = txt.txt_data.iter().flat_map(|part| part.to_vec()).collect();
            assert_eq!((cert.len(), &cert[..4]), (124, &CERT_MAGIC[..]));
            let signature = Signature::from_slice(&cert[8..72]).unwrap();
            verifying.verify(&cert[72..], &signature).unwrap();
        }
        assert!(
            server
                .open(&txt_query("other.example.test."), false)
                .is_none()
        );
        // The same key file reloads to the same provider identity.
        let again = DnsCrypt::load(
            "2.dnscrypt-cert.example.test",
            &directory.path().join("provider.key"),
            24,
        )
        .unwrap();
        assert_eq!(again.provider_public_key(), server.provider_public_key());
        assert!(
            server
                .stamp("192.0.2.1:5443".parse().unwrap())
                .starts_with("sdns://AQ")
        );
    }

    fn client_query(
        server: &DnsCrypt,
        version: u16,
        dns: &[u8],
        pad_to: usize,
    ) -> (Vec<u8>, SecretKey, [u8; 12], Arc<ResolverKeys>) {
        let keys = server
            .keys
            .read()
            .unwrap()
            .iter()
            .find(|key| key.version == version)
            .cloned()
            .unwrap();
        let secret = SecretKey::generate(&mut OsRng);
        let public = PublicKey::from(&secret);
        let mut plain = dns.to_vec();
        plain.push(0x80);
        plain.resize(pad_to, 0);
        let mut client_nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut client_nonce);
        let mut nonce = [0_u8; 24];
        nonce[..12].copy_from_slice(&client_nonce);
        let resolver_public = PublicKey::from(&keys.secret);
        let encrypted = if version == ES_XCHACHA20 {
            ChaChaBox::new(&resolver_public, &secret)
                .encrypt(GenericArray::from_slice(&nonce), &plain[..])
                .unwrap()
        } else {
            SalsaBox::new(&resolver_public, &secret)
                .encrypt(GenericArray::from_slice(&nonce), &plain[..])
                .unwrap()
        };
        let mut packet = keys.magic.to_vec();
        packet.extend_from_slice(public.as_bytes());
        packet.extend_from_slice(&client_nonce);
        packet.extend_from_slice(&encrypted);
        (packet, secret, client_nonce, keys)
    }

    #[test]
    fn both_suites_round_trip_and_bad_packets_are_dropped() {
        let (server, _directory) = server();
        let dns = lumen_proto::hickory_proto::op::Message::query()
            .to_vec()
            .unwrap();
        for version in [ES_XCHACHA20, ES_XSALSA20] {
            let (packet, secret, client_nonce, keys) = client_query(&server, version, &dns, 256);
            let Some(Packet::Query(query)) = server.open(&packet, true) else {
                panic!("query not accepted for suite {version}")
            };
            assert_eq!(query.dns, dns);
            let answer = vec![7_u8; 100];
            let sealed = DnsCrypt::seal(&query, &answer, false).unwrap();
            assert_eq!(sealed[..8], RESOLVER_MAGIC);
            assert_eq!(sealed[8..20], client_nonce);
            assert_eq!((sealed.len() - 8 - 24 - TAG_BYTES) % PADDING_BLOCK, 0);
            let mut nonce = [0_u8; 24];
            nonce.copy_from_slice(&sealed[8..32]);
            let resolver_public = PublicKey::from(&keys.secret);
            let plain = if version == ES_XCHACHA20 {
                ChaChaBox::new(&resolver_public, &secret)
                    .decrypt(GenericArray::from_slice(&nonce), &sealed[32..])
                    .unwrap()
            } else {
                SalsaBox::new(&resolver_public, &secret)
                    .decrypt(GenericArray::from_slice(&nonce), &sealed[32..])
                    .unwrap()
            };
            assert_eq!(&plain[..100], &answer[..]);
            assert_eq!(plain[100], 0x80);
            // A flipped ciphertext bit fails authentication.
            let mut forged = packet.clone();
            let last = forged.len() - 1;
            forged[last] ^= 1;
            assert!(server.open(&forged, true).is_none());
        }
        assert!(server.open(&[0; 300], true).is_none());
        assert!(server.open(&[], false).is_none());
    }

    #[test]
    fn oversized_udp_responses_are_truncated_not_amplified() {
        let (server, _directory) = server();
        let mut request = Message::query();
        request.metadata.id = 9;
        request.add_query(lumen_proto::hickory_proto::op::Query::query(
            lumen_proto::hickory_proto::rr::Name::from_ascii("big.example.test.").unwrap(),
            RecordType::TXT,
        ));
        let dns = request.to_vec().unwrap();
        let (packet, ..) = client_query(&server, ES_XCHACHA20, &dns, 256);
        let Some(Packet::Query(query)) = server.open(&packet, true) else {
            panic!("query")
        };
        let mut response = Message::response(9, OpCode::Query);
        response.queries.clone_from(&request.queries);
        for index in 0..40 {
            response.add_answer(Record::from_rdata(
                lumen_proto::hickory_proto::rr::Name::from_ascii("big.example.test.").unwrap(),
                60,
                RData::TXT(TXT::new(vec![format!("{index}{}", "x".repeat(100))])),
            ));
        }
        let large = response.to_vec().unwrap();
        let udp = DnsCrypt::seal(&query, &large, true).unwrap();
        assert!(
            udp.len() <= query.datagram,
            "UDP response must not exceed the query"
        );
        let tcp = DnsCrypt::seal(&query, &large, false).unwrap();
        assert!(tcp.len() > query.datagram);
    }
}

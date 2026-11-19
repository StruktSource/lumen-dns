//! An SNMP client for monitoring: v2c and v3 (authenticated and encrypted), `GET`, `GETNEXT`,
//! `GETBULK` and bounded walks. Nothing here changes a device: there is no `SET`.

pub mod ber;
pub mod mib;
pub mod usm;

use ber::{
    DecodeError, GET_BULK_REQUEST, GET_NEXT_REQUEST, GET_REQUEST, OCTETS, Oid, REPORT, RESPONSE,
    Reader, SEQUENCE, Value, integer, null, octets, read_value, sequence, tlv,
};
use lumen_config::{SnmpAuth, SnmpPrivacy};
use std::{
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

/// Most rows a walk returns, so one device cannot fill memory.
pub const MAX_WALK_ROWS: usize = 8192;
const REPEATIONS: i64 = 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnmpError {
    /// The device did not answer (after the retries).
    Timeout,
    /// The credentials were refused: the user, the passwords, or the security level.
    Auth(&'static str),
    /// The device answered with an error status.
    Remote(&'static str),
    /// The answer was not valid SNMP.
    Decode(String),
    Io(String),
}

impl fmt::Display for SnmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "no answer"),
            Self::Auth(m) | Self::Remote(m) => write!(f, "{m}"),
            Self::Decode(m) | Self::Io(m) => write!(f, "{m}"),
        }
    }
}

impl From<DecodeError> for SnmpError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e.to_string())
    }
}

/// A v3 user.
#[derive(Clone)]
pub struct UsmUser {
    pub name: String,
    pub auth: Option<(SnmpAuth, Vec<u8>)>,
    pub privacy: Option<(SnmpPrivacy, Vec<u8>)>,
}

/// How to speak to a device. Passwords and communities are only ever held in memory.
#[derive(Clone)]
pub enum Credentials {
    V2c { community: Vec<u8> },
    V3(UsmUser),
}

struct Engine {
    id: Vec<u8>,
    boots: u32,
    time: u32,
    learned: Instant,
    auth_key: Option<Vec<u8>>,
    priv_key: Option<Vec<u8>>,
}

pub struct Client {
    socket: UdpSocket,
    credentials: Credentials,
    wait: Duration,
    retries: u8,
    next_id: i32,
    salt: u64,
    engine: Option<Engine>,
}

/// What came back, before anyone decides what it means.
struct Reply {
    tag: u8,
    status: i64,
    varbinds: Vec<(Oid, Value)>,
    msg_id: i64,
    request_id: i64,
    /// The sender's engine, for v3.
    engine: Option<(Vec<u8>, u32, u32)>,
}

fn status_text(status: i64) -> &'static str {
    match status {
        1 => "the answer was too big",
        2 => "no such name",
        3 => "bad value",
        4 => "read only",
        _ => "the device reported an error",
    }
}

fn varbinds(oids: &[Oid]) -> Vec<u8> {
    sequence(
        &oids
            .iter()
            .map(|o| sequence(&[ber::oid(o), null()]))
            .collect::<Vec<_>>(),
    )
}

fn pdu(tag: u8, id: i32, first: i64, second: i64, oids: &[Oid]) -> Vec<u8> {
    tlv(
        tag,
        &[
            integer(i64::from(id)),
            integer(first),
            integer(second),
            varbinds(oids),
        ]
        .concat(),
    )
}

fn read_pdu(tag: u8, mut inner: Reader<'_>) -> Result<Reply, SnmpError> {
    let request_id = inner.read_integer()?;
    let status = inner.read_integer()?;
    let _index = inner.read_integer()?;
    let mut list = inner.expect(SEQUENCE)?;
    let mut out = Vec::new();
    while !list.is_empty() {
        if out.len() >= MAX_WALK_ROWS {
            return Err(SnmpError::Decode("too many values".into()));
        }
        let mut bind = list.expect(SEQUENCE)?;
        let name = ber::parse_oid(bind.expect(ber::OBJECT_ID)?.bytes())?;
        out.push((name, read_value(&mut bind)?));
    }
    Ok(Reply {
        tag,
        status,
        varbinds: out,
        msg_id: 0,
        request_id,
        engine: None,
    })
}

impl Client {
    /// Open a socket to the device. Nothing is sent yet.
    ///
    /// # Errors
    /// The socket could not be opened.
    pub async fn connect(
        target: SocketAddr,
        credentials: Credentials,
        wait: Duration,
        retries: u8,
    ) -> Result<Self, SnmpError> {
        let bind: SocketAddr = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()
        .expect("static");
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| SnmpError::Io(e.to_string()))?;
        socket
            .connect(target)
            .await
            .map_err(|e| SnmpError::Io(e.to_string()))?;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |d| d.as_nanos());
        Ok(Self {
            socket,
            credentials,
            wait,
            retries,
            next_id: i32::try_from(seed % 1_000_000).unwrap_or(1) + 1,
            salt: u64::try_from(seed & 0xffff_ffff_ffff).unwrap_or(1),
            engine: None,
        })
    }

    fn id(&mut self) -> i32 {
        self.next_id = if self.next_id >= i32::MAX - 1 {
            1
        } else {
            self.next_id + 1
        };
        self.next_id
    }

    /// Ask for the values of these objects, in order. A missing object shows as a missing
    /// [`Value`] rather than an error.
    ///
    /// # Errors
    /// The device did not answer, refused the credentials, or sent bad data.
    pub async fn get(&mut self, oids: &[Oid]) -> Result<Vec<(Oid, Value)>, SnmpError> {
        self.call(GET_REQUEST, 0, 0, oids).await
    }

    /// # Errors
    /// As [`Client::get`].
    pub async fn get_next(&mut self, oids: &[Oid]) -> Result<Vec<(Oid, Value)>, SnmpError> {
        self.call(GET_NEXT_REQUEST, 0, 0, oids).await
    }

    /// # Errors
    /// As [`Client::get`].
    pub async fn get_bulk(
        &mut self,
        repetitions: i64,
        oids: &[Oid],
    ) -> Result<Vec<(Oid, Value)>, SnmpError> {
        self.call(GET_BULK_REQUEST, 0, repetitions, oids).await
    }

    /// Read everything under `root`, at most `max_rows` rows.
    ///
    /// # Errors
    /// As [`Client::get`], on the first request. Later failures end the walk with what was read.
    pub async fn walk(
        &mut self,
        root: &Oid,
        max_rows: usize,
    ) -> Result<Vec<(Oid, Value)>, SnmpError> {
        let max_rows = max_rows.min(MAX_WALK_ROWS);
        let mut rows: Vec<(Oid, Value)> = Vec::new();
        let mut cursor = root.clone();
        let mut repetitions = REPEATIONS;
        loop {
            let batch = match self
                .get_bulk(repetitions, std::slice::from_ref(&cursor))
                .await
            {
                Ok(batch) => batch,
                Err(SnmpError::Remote(_)) if repetitions > 1 => {
                    repetitions = (repetitions / 2).max(1);
                    continue;
                }
                Err(e) if rows.is_empty() => return Err(e),
                Err(_) => break,
            };
            let before = rows.len();
            let mut finished = batch.is_empty();
            for (name, value) in batch {
                if value == Value::EndOfMibView || !name.starts_with(root) || name <= cursor {
                    finished = true;
                    break;
                }
                cursor = name.clone();
                rows.push((name, value));
                if rows.len() >= max_rows {
                    finished = true;
                    break;
                }
            }
            if finished || rows.len() == before {
                break;
            }
        }
        Ok(rows)
    }

    async fn call(
        &mut self,
        tag: u8,
        first: i64,
        second: i64,
        oids: &[Oid],
    ) -> Result<Vec<(Oid, Value)>, SnmpError> {
        if oids.is_empty() || oids.len() > 32 {
            return Err(SnmpError::Decode(
                "ask for 1 to 32 objects at a time".into(),
            ));
        }
        let reply = match &self.credentials {
            Credentials::V2c { .. } => self.exchange_v2c(tag, first, second, oids).await?,
            Credentials::V3(_) => self.exchange_v3(tag, first, second, oids).await?,
        };
        if reply.status != 0 {
            return Err(SnmpError::Remote(status_text(reply.status)));
        }
        Ok(reply.varbinds)
    }

    // ---- v2c ----

    async fn exchange_v2c(
        &mut self,
        tag: u8,
        first: i64,
        second: i64,
        oids: &[Oid],
    ) -> Result<Reply, SnmpError> {
        let Credentials::V2c { community } = self.credentials.clone() else {
            return Err(SnmpError::Io("not a v2c session".into()));
        };
        let id = self.id();
        let packet = sequence(&[
            integer(1),
            octets(&community),
            pdu(tag, id, first, second, oids),
        ]);
        for _ in 0..=self.retries {
            self.socket
                .send(&packet)
                .await
                .map_err(|e| SnmpError::Io(e.to_string()))?;
            let deadline = Instant::now() + self.wait;
            let mut buffer = vec![0u8; ber::MAX_MESSAGE];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let Ok(received) = timeout(left, self.socket.recv(&mut buffer)).await else {
                    break;
                };
                let length = received.map_err(|e| SnmpError::Io(e.to_string()))?;
                let Ok(reply) = parse_v2c(&buffer[..length]) else {
                    continue;
                };
                if reply.request_id == i64::from(id) && reply.tag == RESPONSE {
                    return Ok(reply);
                }
            }
        }
        Err(SnmpError::Timeout)
    }

    // ---- v3 ----

    fn user(&self) -> Option<&UsmUser> {
        match &self.credentials {
            Credentials::V3(user) => Some(user),
            Credentials::V2c { .. } => None,
        }
    }

    fn learn(&mut self, id: Vec<u8>, boots: u32, time: u32) {
        let user = self.user().cloned();
        let (auth_key, priv_key) = match &user {
            Some(UsmUser {
                auth: Some((auth, password)),
                privacy,
                ..
            }) => {
                let auth_key = usm::localize(*auth, password, &id);
                let priv_key = privacy
                    .as_ref()
                    .map(|(_, pw)| usm::localize(*auth, pw, &id));
                (Some(auth_key), priv_key)
            }
            _ => (None, None),
        };
        self.engine = Some(Engine {
            id,
            boots,
            time,
            learned: Instant::now(),
            auth_key,
            priv_key,
        });
    }

    /// Find out the device's engine ID, boot count and clock (RFC 3414 section 4).
    async fn discover(&mut self) -> Result<(), SnmpError> {
        let msg_id = self.id();
        let scoped = sequence(&[
            octets(&[]),
            octets(&[]),
            pdu(GET_REQUEST, msg_id, 0, 0, &[]),
        ]);
        let usm_params = sequence(&[
            octets(&[]),
            integer(0),
            integer(0),
            octets(&[]),
            octets(&[]),
            octets(&[]),
        ]);
        let packet = sequence(&[
            integer(3),
            sequence(&[
                integer(i64::from(msg_id)),
                integer(65_507),
                octets(&[0x04]),
                integer(3),
            ]),
            octets(&usm_params),
            scoped,
        ]);
        for _ in 0..=self.retries {
            self.socket
                .send(&packet)
                .await
                .map_err(|e| SnmpError::Io(e.to_string()))?;
            let deadline = Instant::now() + self.wait;
            let mut buffer = vec![0u8; ber::MAX_MESSAGE];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let Ok(received) = timeout(left, self.socket.recv(&mut buffer)).await else {
                    break;
                };
                let length = received.map_err(|e| SnmpError::Io(e.to_string()))?;
                let Ok(reply) = self.parse_v3(&buffer[..length]) else {
                    continue;
                };
                if reply.msg_id != i64::from(msg_id) {
                    continue;
                }
                if let Some((id, boots, time)) = reply.engine
                    && !id.is_empty()
                {
                    self.learn(id, boots, time);
                    return Ok(());
                }
            }
        }
        Err(SnmpError::Timeout)
    }

    fn build_v3(
        &mut self,
        msg_id: i32,
        tag: u8,
        first: i64,
        second: i64,
        oids: &[Oid],
    ) -> Result<(Vec<u8>, i32), SnmpError> {
        let user = self
            .user()
            .cloned()
            .ok_or_else(|| SnmpError::Io("not a v3 session".into()))?;
        let salt = self.salt;
        self.salt = self.salt.wrapping_add(1);
        let engine = self
            .engine
            .as_ref()
            .ok_or_else(|| SnmpError::Io("no engine".into()))?;
        let elapsed = u32::try_from(engine.learned.elapsed().as_secs()).unwrap_or(u32::MAX);
        let time = engine.time.saturating_add(elapsed);
        let request_id = self.next_id;
        let engine = self
            .engine
            .as_ref()
            .ok_or_else(|| SnmpError::Io("no engine".into()))?;
        let scoped = sequence(&[
            octets(&engine.id),
            octets(&[]),
            pdu(tag, msg_id, first, second, oids),
        ]);
        let mut flags = 0x04u8;
        let mut priv_params: Vec<u8> = Vec::new();
        let data = if let (Some((privacy, _)), Some(key)) = (&user.privacy, &engine.priv_key) {
            flags |= 0x03;
            let salt_bytes = salt.to_be_bytes();
            let mut buf = scoped;
            usm::encrypt(*privacy, key, engine.boots, time, &salt_bytes, &mut buf);
            priv_params = salt_bytes.to_vec();
            octets(&buf)
        } else {
            if user.auth.is_some() {
                flags |= 0x01;
            }
            scoped
        };
        let marker: Vec<u8> = user
            .auth
            .as_ref()
            .map(|(auth, _)| {
                // A random-looking placeholder to locate the field, replaced by zeros for the code.
                let mut m = vec![0u8; usm::mac_len(*auth)];
                for (i, b) in m.iter_mut().enumerate() {
                    *b = (salt >> ((i % 8) * 8)) as u8
                        ^ 0xa7
                        ^ u8::try_from(i).unwrap_or(0).wrapping_mul(37);
                }
                m
            })
            .unwrap_or_default();
        let usm_params = sequence(&[
            octets(&engine.id),
            integer(i64::from(engine.boots)),
            integer(i64::from(time)),
            octets(user.name.as_bytes()),
            octets(&marker),
            octets(&priv_params),
        ]);
        let mut packet = sequence(&[
            integer(3),
            sequence(&[
                integer(i64::from(msg_id)),
                integer(65_507),
                octets(&[flags]),
                integer(3),
            ]),
            octets(&usm_params),
            data,
        ]);
        if let (Some((auth, _)), Some(key)) = (&user.auth, &engine.auth_key) {
            let at = packet
                .windows(marker.len())
                .position(|w| w == marker.as_slice())
                .ok_or_else(|| SnmpError::Io("cannot place the authentication field".into()))?;
            packet[at..at + marker.len()].fill(0);
            let code = usm::authenticate(*auth, key, &packet);
            packet[at..at + marker.len()].copy_from_slice(&code);
        }
        Ok((packet, request_id))
    }

    fn parse_v3(&self, buffer: &[u8]) -> Result<Reply, SnmpError> {
        let mut top = Reader::new(buffer);
        let mut message = top.expect(SEQUENCE)?;
        if message.read_integer()? != 3 {
            return Err(SnmpError::Decode("not an SNMPv3 message".into()));
        }
        let mut global = message.expect(SEQUENCE)?;
        let msg_id = global.read_integer()?;
        let _max = global.read_integer()?;
        let flags = *global
            .read_octets()?
            .first()
            .ok_or(SnmpError::Decode("no flags".into()))?;
        if global.read_integer()? != 3 {
            return Err(SnmpError::Decode(
                "not the user-based security model".into(),
            ));
        }
        let params = message.read_octets()?;
        let mut usm = Reader::new(params).expect(SEQUENCE)?;
        let engine_id = usm.read_octets()?.to_vec();
        let boots = u32::try_from(usm.read_integer()?).unwrap_or(0);
        let time = u32::try_from(usm.read_integer()?).unwrap_or(0);
        let _user = usm.read_octets()?;
        let auth = usm.read_octets()?;
        let priv_params = usm.read_octets()?;
        if flags & 0x01 != 0 {
            let (
                Some(UsmUser {
                    auth: Some((algorithm, _)),
                    ..
                }),
                Some(Engine {
                    auth_key: Some(key),
                    ..
                }),
            ) = (self.user(), self.engine.as_ref())
            else {
                return Err(SnmpError::Auth(
                    "an authenticated answer arrived without credentials",
                ));
            };
            let start = (auth.as_ptr() as usize).wrapping_sub(buffer.as_ptr() as usize);
            if start
                .checked_add(auth.len())
                .is_none_or(|end| end > buffer.len())
            {
                return Err(SnmpError::Decode("bad authentication field".into()));
            }
            let mut copy = buffer.to_vec();
            copy[start..start + auth.len()].fill(0);
            if !usm::verify(*algorithm, key, &copy, auth) {
                return Err(SnmpError::Auth("the answer failed authentication"));
            }
        }
        let scoped_bytes: Vec<u8>;
        let mut scoped = if flags & 0x02 != 0 {
            let encrypted = message.read_octets()?;
            let (
                Some(UsmUser {
                    privacy: Some((privacy, _)),
                    ..
                }),
                Some(Engine {
                    priv_key: Some(key),
                    ..
                }),
            ) = (self.user(), self.engine.as_ref())
            else {
                return Err(SnmpError::Auth(
                    "an encrypted answer arrived without credentials",
                ));
            };
            let salt: [u8; 8] = priv_params
                .try_into()
                .map_err(|_| SnmpError::Decode("bad privacy field".into()))?;
            let mut copy = encrypted.to_vec();
            usm::decrypt(*privacy, key, boots, time, &salt, &mut copy);
            scoped_bytes = copy;
            Reader::new(&scoped_bytes)
                .expect(SEQUENCE)
                .map_err(|_| SnmpError::Auth("decryption failed"))?
        } else {
            message.expect(SEQUENCE)?
        };
        let _context_engine = scoped.read_octets()?;
        let _context_name = scoped.read_octets()?;
        let (tag, inner) = scoped.next()?;
        let mut reply = read_pdu(tag, inner)?;
        reply.msg_id = msg_id;
        reply.engine = Some((engine_id, boots, time));
        Ok(reply)
    }

    async fn exchange_v3(
        &mut self,
        tag: u8,
        first: i64,
        second: i64,
        oids: &[Oid],
    ) -> Result<Reply, SnmpError> {
        for _ in 0..4 {
            if self.engine.is_none() {
                self.discover().await?;
            }
            let msg_id = self.id();
            let (packet, _) = self.build_v3(msg_id, tag, first, second, oids)?;
            let mut resync = false;
            'attempts: for _ in 0..=self.retries {
                self.socket
                    .send(&packet)
                    .await
                    .map_err(|e| SnmpError::Io(e.to_string()))?;
                let deadline = Instant::now() + self.wait;
                let mut buffer = vec![0u8; ber::MAX_MESSAGE];
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    let Ok(received) = timeout(left, self.socket.recv(&mut buffer)).await else {
                        break;
                    };
                    let length = received.map_err(|e| SnmpError::Io(e.to_string()))?;
                    let reply = match self.parse_v3(&buffer[..length]) {
                        Ok(reply) => reply,
                        Err(e @ SnmpError::Auth(_)) => return Err(e),
                        Err(_) => continue,
                    };
                    if reply.msg_id != i64::from(msg_id) {
                        continue;
                    }
                    if reply.tag == REPORT {
                        let counter = reply
                            .varbinds
                            .first()
                            .map(|(o, _)| o.to_string())
                            .unwrap_or_default();
                        match counter.as_str() {
                            "1.3.6.1.6.3.15.1.1.2.0" => {
                                // Our clock was off: take the device's and send again.
                                if let Some((id, boots, time)) = reply.engine {
                                    self.learn(id, boots, time);
                                }
                                resync = true;
                                break 'attempts;
                            }
                            "1.3.6.1.6.3.15.1.1.4.0" => {
                                self.engine = None;
                                resync = true;
                                break 'attempts;
                            }
                            "1.3.6.1.6.3.15.1.1.3.0" => {
                                return Err(SnmpError::Auth("unknown user name"));
                            }
                            "1.3.6.1.6.3.15.1.1.5.0" => {
                                return Err(SnmpError::Auth("wrong authentication password"));
                            }
                            "1.3.6.1.6.3.15.1.1.1.0" => {
                                return Err(SnmpError::Auth(
                                    "security level not allowed for this user",
                                ));
                            }
                            "1.3.6.1.6.3.15.1.1.6.0" => {
                                return Err(SnmpError::Auth("wrong privacy password"));
                            }
                            _ => return Err(SnmpError::Remote("the device sent an error report")),
                        }
                    }
                    if reply.tag == RESPONSE {
                        return Ok(reply);
                    }
                }
            }
            if !resync {
                return Err(SnmpError::Timeout);
            }
        }
        Err(SnmpError::Timeout)
    }
}

fn parse_v2c(buffer: &[u8]) -> Result<Reply, SnmpError> {
    let mut top = Reader::new(buffer);
    let mut message = top.expect(SEQUENCE)?;
    let version = message.read_integer()?;
    if version != 1 {
        return Err(SnmpError::Decode("not an SNMPv2c message".into()));
    }
    let _community = message.expect(OCTETS)?;
    let (tag, inner) = message.next()?;
    read_pdu(tag, inner)
}

#[cfg(test)]
mod tests;

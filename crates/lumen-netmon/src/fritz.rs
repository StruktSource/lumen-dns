//! A read-only client for the AVM FRITZ!Box (TR-064) that reads who is connected.
//!
//! It asks the box for its host list and its model, and nothing else: no setting is ever written,
//! and no action that changes the box is ever sent. TR-064 is plain HTTP on the local network
//! with HTTP Digest sign-in, so the password itself never crosses the wire; the answers do. Use a
//! dedicated FRITZ!Box user that has no more rights than it needs.

use md5::{Digest, Md5};
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use serde::Serialize;
use std::fmt::Write as _;
use std::time::Duration;
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpStream};

/// Largest reply read from the box. A host list of a few hundred devices is well under 1 MiB.
const MAX_REPLY: usize = 4 << 20;
/// Most hosts read, however many the box reports.
pub const MAX_HOSTS: usize = 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// One device the FRITZ!Box knows about.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Host {
    pub name: String,
    pub ip: Option<std::net::IpAddr>,
    pub mac: Option<crate::oui::Mac>,
    /// Connected right now (the box's own view).
    pub active: bool,
    /// `Ethernet`, `802.11`, ... as the box reports it.
    pub interface: String,
}

/// What the box says about itself.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct BoxInfo {
    pub model: String,
    pub firmware: String,
    pub uptime_secs: u64,
}

/// What the console shows about the integration.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Status {
    pub host: String,
    pub interval_secs: u32,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub uptime_secs: Option<u64>,
    /// Unix seconds of the last import that worked.
    pub last_import: Option<i64>,
    /// Hosts the box listed in the last import.
    pub hosts: usize,
    /// Hosts that were inside a scope and merged into the inventory.
    pub imported: usize,
    /// Why the last import failed, if it did.
    pub error: Option<String>,
}

/// A digest challenge the box sent, reused until it answers 401 again.
#[derive(Clone, Debug)]
struct Challenge {
    realm: String,
    nonce: String,
    opaque: Option<String>,
    sha256: bool,
}

/// One connection target with the user it signs in as.
pub struct Client {
    host: String,
    port: u16,
    user: String,
    password: Vec<u8>,
    challenge: Option<Challenge>,
    nc: u32,
}

struct Reply {
    status: u16,
    www_authenticate: Option<String>,
    body: Vec<u8>,
}

impl Client {
    #[must_use]
    pub fn new(host: &str, port: u16, user: &str, password: Vec<u8>) -> Self {
        Self {
            host: host.to_owned(),
            port,
            user: user.to_owned(),
            password,
            challenge: None,
            nc: 0,
        }
    }

    /// The model, firmware and uptime. Failure here is not fatal: the host list is what matters.
    ///
    /// # Errors
    /// The box is unreachable, refuses the sign-in, or answers something unexpected.
    pub async fn info(&mut self) -> Result<BoxInfo, String> {
        let xml = self
            .soap(
                "/upnp/control/deviceinfo",
                "urn:dslforum-org:service:DeviceInfo:1",
                "GetInfo",
            )
            .await?;
        Ok(BoxInfo {
            model: tag(&xml, "NewModelName").unwrap_or_default(),
            firmware: tag(&xml, "NewSoftwareVersion").unwrap_or_default(),
            uptime_secs: tag(&xml, "NewUpTime")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        })
    }

    /// Every host the box lists, up to [`MAX_HOSTS`].
    ///
    /// # Errors
    /// The box is unreachable, refuses the sign-in, or answers something unexpected.
    pub async fn hosts(&mut self) -> Result<Vec<Host>, String> {
        let answer = self
            .soap(
                "/upnp/control/hosts",
                "urn:dslforum-org:service:Hosts:1",
                "X_AVM-DE_GetHostListPath",
            )
            .await;
        match answer {
            Ok(xml) => {
                let path = tag(&xml, "NewX_AVM-DE_HostListPath")
                    .ok_or("the FRITZ!Box sent no host list path")?;
                if !safe_path(&path) {
                    return Err("the FRITZ!Box sent an unusable host list path".into());
                }
                let reply = self.request("GET", &path, None, None).await?;
                Ok(parse_host_list(&String::from_utf8_lossy(&reply)))
            }
            // Older firmware has no list path: ask one entry at a time.
            Err(error) if error.contains("sign-in") => Err(error),
            Err(_) => self.hosts_one_by_one().await,
        }
    }

    async fn hosts_one_by_one(&mut self) -> Result<Vec<Host>, String> {
        let count = self
            .soap(
                "/upnp/control/hosts",
                "urn:dslforum-org:service:Hosts:1",
                "GetHostNumberOfEntries",
            )
            .await?;
        let count: usize = tag(&count, "NewHostNumberOfEntries")
            .and_then(|v| v.parse().ok())
            .ok_or("the FRITZ!Box did not say how many hosts it has")?;
        let mut hosts = Vec::new();
        for index in 0..count.min(MAX_HOSTS) {
            let xml = self
                .soap_with(
                    "/upnp/control/hosts",
                    "urn:dslforum-org:service:Hosts:1",
                    "GetGenericHostEntry",
                    &format!("<NewIndex>{index}</NewIndex>"),
                )
                .await?;
            hosts.push(Host {
                name: tag(&xml, "NewHostName").unwrap_or_default(),
                ip: tag(&xml, "NewIPAddress").and_then(|v| v.parse().ok()),
                mac: tag(&xml, "NewMACAddress").and_then(|v| crate::oui::parse_mac(&v)),
                active: tag(&xml, "NewActive").is_some_and(|v| v == "1"),
                interface: tag(&xml, "NewInterfaceType").unwrap_or_default(),
            });
        }
        Ok(hosts)
    }

    async fn soap(&mut self, control: &str, service: &str, action: &str) -> Result<String, String> {
        self.soap_with(control, service, action, "").await
    }

    /// Only the actions named in this module are ever sent; each one reads.
    async fn soap_with(
        &mut self,
        control: &str,
        service: &str,
        action: &str,
        arguments: &str,
    ) -> Result<String, String> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body><u:{action} xmlns:u=\"{service}\">{arguments}</u:{action}></s:Body></s:Envelope>"
        );
        let soap_action = format!("\"{service}#{action}\"");
        let reply = self
            .request("POST", control, Some(&body), Some(&soap_action))
            .await?;
        Ok(String::from_utf8_lossy(&reply).into_owned())
    }

    /// One request, signing in with Digest. A stale challenge is replaced once.
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
        soap_action: Option<&str>,
    ) -> Result<Vec<u8>, String> {
        for attempt in 0..2 {
            let authorization = self
                .challenge
                .clone()
                .map(|c| self.authorize(&c, method, path));
            let reply = self
                .send(method, path, body, soap_action, authorization.as_deref())
                .await?;
            match reply.status {
                200 => return Ok(reply.body),
                401 => {
                    let Some(challenge) = reply.www_authenticate.as_deref().and_then(challenge)
                    else {
                        return Err(
                            "the FRITZ!Box asked for a sign-in Lumen does not support".into()
                        );
                    };
                    if attempt == 1 {
                        return Err("the FRITZ!Box refused the sign-in: check the user name and password, and that the user may use TR-064 (\"FRITZ!Box settings\" rights)".into());
                    }
                    self.nc = 0;
                    self.challenge = Some(challenge);
                }
                other => {
                    return Err(format!("the FRITZ!Box answered HTTP {other}"));
                }
            }
        }
        Err("the FRITZ!Box refused the sign-in".into())
    }

    fn authorize(&mut self, challenge: &Challenge, method: &str, uri: &str) -> String {
        self.nc = self.nc.wrapping_add(1);
        let nc = format!("{:08x}", self.nc);
        let mut raw = [0u8; 8];
        // A failed random source only weakens the client nonce; the sign-in still works.
        let _ = SystemRandom::new().fill(&mut raw);
        let cnonce = hex(&raw);
        let hash = |data: &[u8]| -> String {
            if challenge.sha256 {
                hex(digest(&SHA256, data).as_ref())
            } else {
                hex(Md5::digest(data).as_ref())
            }
        };
        let mut a1 = format!("{}:{}:", self.user, challenge.realm).into_bytes();
        a1.extend_from_slice(&self.password);
        let ha1 = hash(&a1);
        let ha2 = hash(format!("{method}:{uri}").as_bytes());
        let response =
            hash(format!("{ha1}:{}:{nc}:{cnonce}:auth:{ha2}", challenge.nonce).as_bytes());
        let mut header = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", response=\"{response}\", \
             algorithm={}, qop=auth, nc={nc}, cnonce=\"{cnonce}\"",
            self.user,
            challenge.realm,
            challenge.nonce,
            if challenge.sha256 { "SHA-256" } else { "MD5" },
        );
        if let Some(opaque) = &challenge.opaque {
            let _ = write!(header, ", opaque=\"{opaque}\"");
        }
        header
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        soap_action: Option<&str>,
        authorization: Option<&str>,
    ) -> Result<Reply, String> {
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: lumen\r\nConnection: close\r\n",
            self.host, self.port
        );
        if let Some(body) = body {
            let _ = write!(
                head,
                "Content-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\n",
                body.len()
            );
        }
        if let Some(action) = soap_action {
            let _ = write!(head, "SoapAction: {action}\r\n");
        }
        if let Some(authorization) = authorization {
            let _ = write!(head, "Authorization: {authorization}\r\n");
        }
        head.push_str("\r\n");
        if let Some(body) = body {
            head.push_str(body);
        }
        let target = (self.host.as_str(), self.port);
        let raw = tokio::time::timeout(STEP_TIMEOUT, async {
            let mut stream = TcpStream::connect(target)
                .await
                .map_err(|e| format!("cannot reach the FRITZ!Box: {e}"))?;
            stream
                .write_all(head.as_bytes())
                .await
                .map_err(|e| format!("cannot reach the FRITZ!Box: {e}"))?;
            let mut raw = Vec::new();
            // One byte over the cap tells us the reply was cut short.
            stream
                .take(MAX_REPLY as u64 + 1)
                .read_to_end(&mut raw)
                .await
                .map_err(|e| format!("cannot read from the FRITZ!Box: {e}"))?;
            Ok::<_, String>(raw)
        })
        .await
        .map_err(|_| "the FRITZ!Box did not answer in time".to_owned())??;
        if raw.len() > MAX_REPLY {
            return Err("the FRITZ!Box reply is too large".into());
        }
        parse_reply(&raw)
    }
}

fn parse_reply(raw: &[u8]) -> Result<Reply, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("the FRITZ!Box sent a broken reply")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("the FRITZ!Box sent a broken reply")?;
    let mut www_authenticate = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "www-authenticate" if value.to_ascii_lowercase().starts_with("digest") => {
                www_authenticate = Some(value.to_owned());
            }
            "transfer-encoding" if value.eq_ignore_ascii_case("chunked") => chunked = true,
            _ => {}
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        dechunk(rest).ok_or("the FRITZ!Box sent a broken reply")?
    } else {
        rest.to_vec()
    };
    Ok(Reply {
        status,
        www_authenticate,
        body,
    })
}

fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let end = data.windows(2).position(|w| w == b"\r\n")?;
        let size = usize::from_str_radix(
            std::str::from_utf8(&data[..end])
                .ok()?
                .split(';')
                .next()?
                .trim(),
            16,
        )
        .ok()?;
        data = &data[end + 2..];
        if size == 0 {
            return Some(out);
        }
        if data.len() < size + 2 || out.len() + size > MAX_REPLY {
            return None;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// `key="value"` pairs of a `WWW-Authenticate: Digest ...` header.
fn challenge(header: &str) -> Option<Challenge> {
    let rest = header.get(6..)?;
    let mut realm = None;
    let mut nonce = None;
    let mut opaque = None;
    let mut sha256 = false;
    let mut qop_ok = true;
    let mut chars = rest.trim().chars().peekable();
    loop {
        let mut key = String::new();
        while let Some(&c) = chars.peek() {
            if c == '=' {
                break;
            }
            chars.next();
            if c != ',' && !c.is_whitespace() {
                key.push(c);
            }
        }
        if chars.next().is_none() {
            break;
        }
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                value.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                value.push(c);
                chars.next();
            }
        }
        match key.to_ascii_lowercase().as_str() {
            "realm" => realm = Some(value),
            "nonce" => nonce = Some(value),
            "opaque" => opaque = Some(value),
            "algorithm" => {
                let v = value.trim().to_ascii_uppercase();
                if v == "SHA-256" {
                    sha256 = true;
                } else if v != "MD5" {
                    return None;
                }
            }
            "qop" => qop_ok = value.split(',').any(|q| q.trim() == "auth"),
            _ => {}
        }
    }
    // Header values go into a request line: no quotes or line breaks.
    let clean = |s: &str| !s.contains(['"', '\r', '\n']);
    let (realm, nonce) = (realm?, nonce?);
    (qop_ok && clean(&realm) && clean(&nonce) && opaque.as_deref().is_none_or(clean)).then_some(
        Challenge {
            realm,
            nonce,
            opaque,
            sha256,
        },
    )
}

/// A path the box may send us back to: no spaces or control characters, one leading slash.
fn safe_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= 512
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-?=&%~:+,;@".contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The text of the first `<name>...</name>`, with XML entities decoded.
fn tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(unescape(xml[start..end].trim()))
}

fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        if let Some(c) = decoded {
            out.push(c);
            rest = &rest[end + 1..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    out
}

/// The `<Item>` entries of the box's host list.
#[must_use]
pub fn parse_host_list(xml: &str) -> Vec<Host> {
    let mut hosts = Vec::new();
    let mut rest = xml;
    while hosts.len() < MAX_HOSTS
        && let Some(start) = rest.find("<Item>")
    {
        let after = &rest[start + 6..];
        let Some(end) = after.find("</Item>") else {
            break;
        };
        let item = &after[..end];
        hosts.push(Host {
            name: tag(item, "HostName").unwrap_or_default(),
            ip: tag(item, "IPAddress").and_then(|v| v.parse().ok()),
            mac: tag(item, "MACAddress").and_then(|v| crate::oui::parse_mac(&v)),
            active: tag(item, "Active").is_some_and(|v| v == "1"),
            interface: tag(item, "InterfaceType").unwrap_or_default(),
        });
        rest = &after[end + 7..];
    }
    hosts
}

/// A name the box shows for a device, made safe to keep: no control characters, at most 64
/// characters. `None` for the box's own placeholder or nothing.
#[must_use]
pub fn clean_label(name: &str) -> Option<String> {
    let name: String = name.chars().filter(|c| !c.is_control()).collect();
    let name = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let name: String = name.chars().take(64).collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const LIST: &str = r#"<?xml version="1.0"?><List>
<Item><Index>1</Index><IPAddress>192.168.178.20</IPAddress><MACAddress>00:1B:63:84:45:E6</MACAddress><Active>1</Active><HostName>Anne&apos;s iPhone</HostName><InterfaceType>802.11</InterfaceType></Item>
<Item><Index>2</Index><IPAddress></IPAddress><MACAddress>AA:BB:CC:DD:EE:FF</MACAddress><Active>0</Active><HostName>nas</HostName><InterfaceType>Ethernet</InterfaceType></Item>
</List>"#;

    #[test]
    fn the_host_list_is_read_with_entities_and_missing_addresses() {
        let hosts = parse_host_list(LIST);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].name, "Anne's iPhone");
        assert_eq!(hosts[0].ip, Some("192.168.178.20".parse().unwrap()));
        assert!(hosts[0].active);
        assert_eq!(hosts[1].ip, None);
        assert!(!hosts[1].active);
        assert_eq!(hosts[1].interface, "Ethernet");
    }

    #[test]
    fn challenges_are_read_and_odd_ones_refused() {
        let c = challenge(
            r#"Digest realm="F!Box SOAP-Auth", nonce="ABC123", algorithm=MD5, qop="auth", opaque="o""#,
        )
        .unwrap();
        assert_eq!(
            (c.realm.as_str(), c.nonce.as_str()),
            ("F!Box SOAP-Auth", "ABC123")
        );
        assert!(!c.sha256);
        assert!(challenge(r#"Digest realm="r", nonce="n", algorithm=SHA-512"#).is_none());
        assert!(challenge(r#"Digest realm="r", nonce="n", qop="auth-int""#).is_none());
        assert!(challenge(r#"Digest realm="r""#).is_none());
    }

    #[test]
    fn only_plain_paths_are_followed() {
        assert!(safe_path("/hostlist.lua?sid=abc123"));
        assert!(!safe_path("//evil.example/x"));
        assert!(!safe_path("/a b"));
        assert!(!safe_path("http://evil.example/"));
        assert!(!safe_path("/a\r\nHost: x"));
    }

    #[test]
    fn chunked_replies_are_joined_and_labels_are_cleaned() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"),
            Some(b"abcde".to_vec())
        );
        assert_eq!(dechunk(b"zz\r\nabc"), None);
        assert_eq!(
            clean_label("  Kitchen\u{7}  tablet "),
            Some("Kitchen tablet".into())
        );
        assert_eq!(clean_label("   "), None);
        assert_eq!(clean_label(&"x".repeat(200)).unwrap().len(), 64);
    }

    /// A box that wants Digest and checks the response hash, then serves the three things Lumen
    /// reads. It also records every request line, to prove nothing but reads is sent.
    async fn fake_box(
        user: &'static str,
        password: &'static str,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&log);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let seen = std::sync::Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut raw = vec![0u8; 8192];
                    let mut n = 0;
                    loop {
                        let Ok(read) = stream.read(&mut raw[n..]).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        n += read;
                        let text = String::from_utf8_lossy(&raw[..n]).into_owned();
                        if let Some(split) = text.find("\r\n\r\n") {
                            let length = text
                                .lines()
                                .find_map(|l| l.strip_prefix("Content-Length: "))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            if n >= split + 4 + length {
                                break;
                            }
                        }
                    }
                    let text = String::from_utf8_lossy(&raw[..n]).into_owned();
                    let line = text.lines().next().unwrap_or("").to_owned();
                    let action = text
                        .lines()
                        .find_map(|l| l.strip_prefix("SoapAction: "))
                        .unwrap_or("")
                        .to_owned();
                    seen.lock().unwrap().push(format!("{line} {action}"));
                    let authorized = text
                        .lines()
                        .find_map(|l| l.strip_prefix("Authorization: Digest "))
                        .is_some_and(|auth| {
                            let get = |k: &str| {
                                auth.split(", ")
                                    .find_map(|p| p.strip_prefix(&format!("{k}=")))
                                    .map(|v| v.trim_matches('"').to_owned())
                                    .unwrap_or_default()
                            };
                            let md5 = |s: String| hex(Md5::digest(s.as_bytes()).as_ref());
                            let method = line.split(' ').next().unwrap_or("");
                            let ha1 = md5(format!("{user}:testbox:{password}"));
                            let ha2 = md5(format!("{method}:{}", get("uri")));
                            get("username") == user
                                && get("response")
                                    == md5(format!(
                                        "{ha1}:{}:{}:{}:auth:{ha2}",
                                        get("nonce"),
                                        get("nc"),
                                        get("cnonce")
                                    ))
                        });
                    let (status, body) = if !authorized {
                        (
                            "401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"testbox\", nonce=\"n0nce\", algorithm=MD5, qop=\"auth\"",
                            String::new(),
                        )
                    } else if line.contains("/upnp/control/deviceinfo") {
                        (
                            "200 OK",
                            "<r><NewModelName>FRITZ!Box 7590</NewModelName><NewSoftwareVersion>7.57</NewSoftwareVersion><NewUpTime>3600</NewUpTime></r>".into(),
                        )
                    } else if line.contains("/upnp/control/hosts") {
                        (
                            "200 OK",
                            "<r><NewX_AVM-DE_HostListPath>/hostlist.lua?x=1</NewX_AVM-DE_HostListPath></r>".into(),
                        )
                    } else if line.contains("/hostlist.lua") {
                        ("200 OK", LIST.into())
                    } else {
                        ("404 Not Found", String::new())
                    };
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(reply.as_bytes()).await;
                });
            }
        });
        (port, log)
    }

    #[tokio::test]
    async fn it_signs_in_with_digest_and_reads_only() {
        let (port, log) = fake_box("lumen", "s3cret").await;
        let mut client = Client::new("127.0.0.1", port, "lumen", b"s3cret".to_vec());
        let info = client.info().await.unwrap();
        assert_eq!(info.model, "FRITZ!Box 7590");
        assert_eq!(info.uptime_secs, 3600);
        let hosts = client.hosts().await.unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].name, "Anne's iPhone");
        for line in log.lock().unwrap().iter() {
            assert!(
                line.contains("GetInfo")
                    || line.contains("X_AVM-DE_GetHostListPath")
                    || line.starts_with("GET /hostlist.lua"),
                "unexpected request: {line}"
            );
        }
    }

    #[tokio::test]
    async fn a_wrong_password_is_reported_plainly() {
        let (port, _) = fake_box("lumen", "s3cret").await;
        let mut client = Client::new("127.0.0.1", port, "lumen", b"wrong".to_vec());
        let error = client.info().await.unwrap_err();
        assert!(error.contains("refused the sign-in"), "{error}");
    }
}

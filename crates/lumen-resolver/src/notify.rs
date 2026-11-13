//! DNS NOTIFY (RFC 1996): tell secondary servers that a zone changed, so they transfer it now
//! instead of waiting for their refresh timer. Best effort, over UDP, never blocking updates.

use hickory_server::proto::{
    op::{Message, OpCode, Query as DnsQuery},
    rr::{Name, RecordType},
};
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher as _, Hasher as _},
    net::SocketAddr,
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

/// Tries per secondary, one second apart, before giving up.
const ATTEMPTS: u8 = 3;

fn message(zone: &Name, id: u16) -> Result<Vec<u8>, String> {
    let mut message = Message::query();
    message.metadata.id = id;
    message.metadata.op_code = OpCode::Notify;
    message.metadata.authoritative = true;
    message.metadata.recursion_desired = false;
    message.add_query(DnsQuery::query(zone.clone(), RecordType::SOA));
    message.to_vec().map_err(|_| "cannot encode NOTIFY".into())
}

fn identifier() -> u16 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(1);
    (hasher.finish() & 0xffff) as u16
}

/// Send one NOTIFY to `target` and wait for its acknowledgement. Returns whether it was
/// acknowledged. A secondary that never answers costs three tries and a few seconds.
async fn notify_one(zone: &Name, target: SocketAddr) -> bool {
    let bind: SocketAddr = if target.is_ipv4() {
        ([0, 0, 0, 0], 0).into()
    } else {
        ([0u16; 8], 0).into()
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        return false;
    };
    let id = identifier();
    let Ok(packet) = message(zone, id) else {
        return false;
    };
    for _ in 0..ATTEMPTS {
        if socket.send_to(&packet, target).await.is_err() {
            return false;
        }
        let mut buffer = [0u8; 512];
        let wait = timeout(Duration::from_secs(1), async {
            loop {
                match socket.recv_from(&mut buffer).await {
                    // The answer must come from the secondary, repeat our id, and be a NOTIFY
                    // response.
                    Ok((size, from))
                        if from == target
                            && size >= 12
                            && u16::from_be_bytes([buffer[0], buffer[1]]) == id
                            && buffer[2] & 0x80 != 0
                            && (buffer[2] >> 3) & 0x0f == 4 =>
                    {
                        return true;
                    }
                    Ok(_) => {}
                    Err(_) => return false,
                }
            }
        })
        .await;
        if wait == Ok(true) {
            return true;
        }
    }
    false
}

/// Notify every secondary of `zone`. Failures are logged without addresses of other zones.
pub(crate) async fn send(zone: Name, targets: Vec<SocketAddr>) {
    for target in targets {
        if !notify_one(&zone, target).await {
            eprintln!("zone {zone}: NOTIFY to {target} was not acknowledged");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_secondary_receives_a_notify_for_the_zone_and_acknowledges_it() {
        let secondary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = secondary.local_addr().unwrap();
        let zone = Name::from_ascii("home.example.").unwrap();
        let answer = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (size, from) = secondary.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..size]).unwrap();
            assert_eq!(request.metadata.op_code, OpCode::Notify);
            assert!(request.metadata.authoritative);
            assert_eq!(request.queries.len(), 1);
            assert_eq!(request.queries[0].query_type(), RecordType::SOA);
            assert_eq!(request.queries[0].name().to_ascii(), "home.example.");
            // An unrelated packet first, which must be ignored, then the real acknowledgement.
            secondary.send_to(&[0; 12], from).await.unwrap();
            let mut reply = buffer[..size].to_vec();
            reply[2] |= 0x80;
            secondary.send_to(&reply, from).await.unwrap();
        });
        assert!(notify_one(&zone, target).await);
        answer.await.unwrap();
    }

    #[tokio::test]
    async fn a_reply_for_another_request_does_not_count() {
        let secondary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = secondary.local_addr().unwrap();
        let zone = Name::from_ascii("home.example.").unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            loop {
                let (size, from) = secondary.recv_from(&mut buffer).await.unwrap();
                let mut reply = buffer[..size].to_vec();
                reply[0] ^= 0xff; // wrong identifier
                reply[2] |= 0x80;
                secondary.send_to(&reply, from).await.unwrap();
            }
        });
        assert!(!notify_one(&zone, target).await);
    }
}

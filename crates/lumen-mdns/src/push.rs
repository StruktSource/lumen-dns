//! DNS Push Notifications (RFC 8765) over a bounded TLS/DSO session.

use crate::Bridge;
use hickory_proto::{
    op::{Message, OpCode, ResponseCode},
    rr::{Name, Record, RecordType},
    serialize::binary::{BinEncodable, BinEncoder},
};
use ipnet::IpNet;
use rustls::ServerConfig;
use std::{collections::HashMap, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

const MAX_MESSAGE: usize = 16_382;
const DSO_OPCODE: u16 = 6;
const KEEPALIVE: u16 = 0x0001;
const SUBSCRIBE: u16 = 0x0040;
const PUSH: u16 = 0x0041;
const UNSUBSCRIBE: u16 = 0x0042;
const RCODE_FORMERR: u16 = 1;
const RCODE_REFUSED: u16 = 5;
const RCODE_DSO_TYPE_NOT_IMPLEMENTED: u16 = 11;

#[derive(Clone)]
struct Subscription {
    name: Name,
    kind: RecordType,
    records: Vec<Record>,
}

fn header(id: u16, response: bool, rcode: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    let flags = (DSO_OPCODE << 11) | u16::from(response) << 15 | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0; 8]);
    out
}

fn dso(id: u16, response: bool, kind: u16, payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(payload.len()).map_err(|_| io::Error::other("DSO TLV too large"))?;
    let mut out = header(id, response, 0);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let length = usize::from(reader.read_u16().await?);
    if !(12..=MAX_MESSAGE).contains(&length) {
        return Err(io::Error::other("invalid DNS Push message length"));
    }
    let mut packet = vec![0; length];
    reader.read_exact(&mut packet).await?;
    Ok(packet)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    if packet.len() > MAX_MESSAGE {
        return Err(io::Error::other("DNS Push message is too large"));
    }
    writer
        .write_u16(u16::try_from(packet.len()).unwrap_or(u16::MAX))
        .await?;
    writer.write_all(packet).await?;
    writer.flush().await
}

fn parse_name(packet: &[u8]) -> Option<(Name, usize)> {
    let mut labels: Vec<&[u8]> = Vec::new();
    let mut offset = 0;
    loop {
        let length = usize::from(*packet.get(offset)?);
        offset += 1;
        if length == 0 {
            return Name::from_labels(labels).ok().map(|name| (name, offset));
        }
        if length > 63 || offset.checked_add(length)? > packet.len() {
            return None;
        }
        labels.push(&packet[offset..offset + length]);
        offset += length;
    }
}

fn parse_tlv(packet: &[u8]) -> Option<(u16, &[u8])> {
    if packet.len() < 16 || packet[4..12] != [0; 8] {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([packet[14], packet[15]]));
    (16 + length == packet.len())
        .then(|| (u16::from_be_bytes([packet[12], packet[13]]), &packet[16..]))
}

fn same_set(left: &[Record], right: &[Record]) -> bool {
    left.len() == right.len()
        && left.iter().all(|a| {
            right.iter().any(|b| {
                a.name.to_lowercase() == b.name.to_lowercase()
                    && a.record_type() == b.record_type()
                    && a.data == b.data
            })
        })
}

fn push_message(added: &[Record], removed: &[Record]) -> io::Result<Vec<u8>> {
    let mut payload = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut payload);
        encoder.set_max_size(u16::try_from(MAX_MESSAGE - 16).unwrap_or(u16::MAX));
        for record in removed {
            let mut goodbye = record.clone();
            goodbye.ttl = 0;
            goodbye.emit(&mut encoder).map_err(io::Error::other)?;
        }
        for record in added {
            record.emit(&mut encoder).map_err(io::Error::other)?;
        }
    }
    dso(0, false, PUSH, &payload)
}

async fn records(bridge: &Bridge, name: &Name, kind: RecordType) -> Vec<Record> {
    bridge
        .resolve(name, kind)
        .await
        .map(|answer| answer.answers)
        .unwrap_or_default()
}

async fn answer_query<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bridge: &Bridge,
    packet: &[u8],
) -> io::Result<()> {
    let request = Message::from_vec(packet).map_err(io::Error::other)?;
    let Some(query) = request.queries.first() else {
        return write_frame(
            writer,
            &Message::error_msg(request.id, OpCode::Query, ResponseCode::FormErr)
                .to_vec()
                .map_err(io::Error::other)?,
        )
        .await;
    };
    let Some(answer) = bridge.resolve(query.name(), query.query_type()).await else {
        return write_frame(
            writer,
            &Message::error_msg(request.id, OpCode::Query, ResponseCode::Refused)
                .to_vec()
                .map_err(io::Error::other)?,
        )
        .await;
    };
    let mut response = Message::response(request.id, OpCode::Query);
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = answer.rcode;
    response.queries = request.queries;
    response.answers = answer.answers;
    response.authorities = answer.authorities;
    response.additionals = answer.additionals;
    write_frame(writer, &response.to_vec().map_err(io::Error::other)?).await
}

async fn refresh<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bridge: &Bridge,
    subscriptions: &mut HashMap<u16, Subscription>,
) -> io::Result<()> {
    for subscription in subscriptions.values_mut() {
        let current = bridge
            .snapshot(&subscription.name, subscription.kind)
            .unwrap_or_default();
        if !same_set(&current, &subscription.records) {
            let removed: Vec<Record> = subscription
                .records
                .iter()
                .filter(|old| !current.iter().any(|new| new.data == old.data))
                .cloned()
                .collect();
            write_frame(writer, &push_message(&current, &removed)?).await?;
            subscription.records = current;
        }
    }
    Ok(())
}

async fn session(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    bridge: Arc<Bridge>,
    maximum: usize,
) -> io::Result<()> {
    let tls = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS Push TLS handshake timed out"))?
        .map_err(io::Error::other)?;
    serve_io(tls, bridge, maximum).await
}

async fn serve_io<S>(stream: S, bridge: Arc<Bridge>, maximum: usize) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut subscriptions: HashMap<u16, Subscription> = HashMap::new();
    loop {
        tokio::select! {
            packet = read_frame(&mut reader) => {
                let packet = packet?;
                let id = u16::from_be_bytes([packet[0], packet[1]]);
                let flags = u16::from_be_bytes([packet[2], packet[3]]);
                let opcode = (flags >> 11) & 0x0f;
                if opcode == 0 {
                    answer_query(&mut writer, &bridge, &packet).await?;
                    continue;
                }
                if opcode != DSO_OPCODE || flags & 0x8000 != 0 {
                    write_frame(&mut writer, &header(id, true, RCODE_FORMERR)).await?;
                    continue;
                }
                let Some((kind, payload)) = parse_tlv(&packet) else {
                    write_frame(&mut writer, &header(id, true, RCODE_FORMERR)).await?;
                    continue;
                };
                match kind {
                    KEEPALIVE if payload.len() == 8 => {
                        write_frame(&mut writer, &dso(id, true, KEEPALIVE, payload)?).await?;
                    }
                    SUBSCRIBE if id != 0 => {
                        if subscriptions.contains_key(&id) || subscriptions.len() >= maximum {
                            write_frame(&mut writer, &header(id, true, RCODE_REFUSED)).await?;
                            continue;
                        }
                        let Some((name, used)) = parse_name(payload) else {
                            write_frame(&mut writer, &header(id, true, RCODE_FORMERR)).await?;
                            continue;
                        };
                        if used + 4 != payload.len() {
                            write_frame(&mut writer, &header(id, true, RCODE_FORMERR)).await?;
                            continue;
                        }
                        let kind = RecordType::from(u16::from_be_bytes([payload[used], payload[used + 1]]));
                        let class = u16::from_be_bytes([payload[used + 2], payload[used + 3]]);
                        if class != 1 {
                            write_frame(&mut writer, &header(id, true, RCODE_REFUSED)).await?;
                            continue;
                        }
                        if !bridge.handles(&name) {
                            write_frame(&mut writer, &header(id, true, RCODE_REFUSED)).await?;
                            continue;
                        }
                        let current = records(&bridge, &name, kind).await;
                        write_frame(&mut writer, &dso(id, true, SUBSCRIBE, &[])?).await?;
                        write_frame(&mut writer, &push_message(&current, &[])?).await?;
                        subscriptions.insert(id, Subscription { name, kind, records: current });
                    }
                    UNSUBSCRIBE if id == 0 && payload.len() == 2 => {
                        subscriptions.remove(&u16::from_be_bytes([payload[0], payload[1]]));
                    }
                    _ => {
                        write_frame(&mut writer, &header(id, true, RCODE_DSO_TYPE_NOT_IMPLEMENTED)).await?;
                    }
                }
            }
            () = bridge.changed(), if !subscriptions.is_empty() => {
                refresh(&mut writer, &bridge, &mut subscriptions).await?;
            }
            () = tokio::time::sleep(Duration::from_secs(1)), if !subscriptions.is_empty() => {
                refresh(&mut writer, &bridge, &mut subscriptions).await?;
            }
        }
    }
}

/// Bind all configured listeners before returning their serving tasks.
pub(crate) async fn start(
    addresses: &[SocketAddr],
    tls: Arc<ServerConfig>,
    bridge: Arc<Bridge>,
    max_connections: usize,
    max_subscriptions: usize,
    allowed_clients: Vec<IpNet>,
) -> io::Result<Vec<JoinHandle<()>>> {
    let mut listeners = Vec::new();
    for address in addresses {
        listeners.push(TcpListener::bind(address).await?);
    }
    let permits = Arc::new(Semaphore::new(max_connections));
    Ok(listeners
        .into_iter()
        .map(|listener| {
            let acceptor = TlsAcceptor::from(Arc::clone(&tls));
            let bridge = Arc::clone(&bridge);
            let permits = Arc::clone(&permits);
            let allowed_clients = allowed_clients.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, peer)) = listener.accept().await else {
                        continue;
                    };
                    if !allowed_clients
                        .iter()
                        .any(|network| network.contains(&peer.ip()))
                    {
                        continue;
                    }
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    let bridge = Arc::clone(&bridge);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let _ = session(stream, acceptor, bridge, max_subscriptions).await;
                    });
                }
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::Settings;

    #[test]
    fn subscribe_names_are_uncompressed_and_bounded() {
        let (name, used) = parse_name(b"\x03www\x07example\x00tail").unwrap();
        assert_eq!(name.to_ascii(), "www.example.");
        assert_eq!(used, 13);
        assert!(parse_name(b"\xc0\x00").is_none());
    }

    #[test]
    fn dso_headers_and_tlvs_are_well_formed() {
        let message = dso(7, true, SUBSCRIBE, &[]).unwrap();
        assert_eq!(u16::from_be_bytes([message[0], message[1]]), 7);
        assert_eq!(
            (u16::from_be_bytes([message[2], message[3]]) >> 11) & 0x0f,
            DSO_OPCODE
        );
        assert_eq!(parse_tlv(&message).unwrap().0, SUBSCRIBE);
    }

    #[tokio::test]
    async fn a_session_accepts_a_subscription_and_sends_initial_state() {
        let bridge = Bridge::new(
            Vec::new(),
            Settings {
                domain: Some("mdns.example".into()),
                reflect: false,
                wait: Duration::from_millis(1),
                ttl_cap: 120,
                max_records: 64,
                reflect_allow: Vec::new(),
                reflect_block: Vec::new(),
                publish: None,
                push_port: Some(853),
            },
        )
        .unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve_io(server, bridge, 4));
        let mut payload = b"\x03box\x04mdns\x07example\x00".to_vec();
        payload.extend_from_slice(&u16::from(RecordType::A).to_be_bytes());
        payload.extend_from_slice(&1_u16.to_be_bytes());
        write_frame(&mut client, &dso(17, false, SUBSCRIBE, &payload).unwrap())
            .await
            .unwrap();
        let accepted = read_frame(&mut client).await.unwrap();
        assert_eq!(parse_tlv(&accepted).unwrap().0, SUBSCRIBE);
        let initial = read_frame(&mut client).await.unwrap();
        assert_eq!(parse_tlv(&initial).unwrap().0, PUSH);
        drop(client);
        assert!(task.await.unwrap().is_err());
    }
}

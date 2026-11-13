//! `DHCPv6` relay agent messages (RFC 8415 section 19): unwrapping a Relay-forward and wrapping
//! the answer in a Relay-reply. The messages are simple enough to handle on the wire directly.

use std::net::Ipv6Addr;

const RELAY_FORWARD: u8 = 12;
const RELAY_REPLY: u8 = 13;
const OPTION_INTERFACE_ID: u16 = 18;
const OPTION_RELAY_MESSAGE: u16 = 9;
/// Relays may be chained; real networks use one or two.
pub const MAX_DEPTH: usize = 8;

/// One relay layer, as received.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Layer {
    pub hop_count: u8,
    pub link: Ipv6Addr,
    pub peer: Ipv6Addr,
    /// Echoed back unchanged so the relay can find the interface the client is on.
    pub interface_id: Option<Vec<u8>>,
}

/// A client message and the relay layers around it, outermost first.
#[derive(Debug, Eq, PartialEq)]
pub struct Relayed {
    pub layers: Vec<Layer>,
    pub message: Vec<u8>,
}

impl Relayed {
    /// The address of the client's link: the one the relay closest to the client reported.
    #[must_use]
    pub fn link(&self) -> Option<Ipv6Addr> {
        self.layers
            .iter()
            .rev()
            .map(|layer| layer.link)
            .find(|link| !link.is_unspecified())
    }
}

/// True when the first byte says this is a Relay-forward.
#[must_use]
pub fn is_relay_forward(packet: &[u8]) -> bool {
    packet.first() == Some(&RELAY_FORWARD)
}

fn options(mut data: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let code = u16::from_be_bytes(data.get(..2)?.try_into().ok()?);
        let length = usize::from(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?));
        out.push((code, data.get(4..4 + length)?));
        data = &data[4 + length..];
    }
    Some(out)
}

/// Take a Relay-forward apart. `None` when it is malformed or nested too deeply.
#[must_use]
pub fn unwrap(packet: &[u8]) -> Option<Relayed> {
    let mut layers = Vec::new();
    let mut current = packet;
    while is_relay_forward(current) {
        if layers.len() >= MAX_DEPTH || current.len() < 34 {
            return None;
        }
        let hop_count = current[1];
        let link = Ipv6Addr::from(<[u8; 16]>::try_from(&current[2..18]).ok()?);
        let peer = Ipv6Addr::from(<[u8; 16]>::try_from(&current[18..34]).ok()?);
        let mut interface_id = None;
        let mut inner = None;
        for (code, data) in options(&current[34..])? {
            match code {
                OPTION_INTERFACE_ID => interface_id = Some(data.to_vec()),
                OPTION_RELAY_MESSAGE => inner = Some(data),
                _ => {}
            }
        }
        layers.push(Layer {
            hop_count,
            link,
            peer,
            interface_id,
        });
        current = inner?;
    }
    (!layers.is_empty() && !current.is_empty()).then(|| Relayed {
        layers,
        message: current.to_vec(),
    })
}

fn option(code: u16, data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(data);
}

/// Wrap a reply in a Relay-reply for every layer, innermost first, so the outermost relay gets
/// the outermost wrapper.
#[must_use]
pub fn wrap(layers: &[Layer], reply: &[u8]) -> Vec<u8> {
    let mut current = reply.to_vec();
    for layer in layers.iter().rev() {
        let mut out = vec![RELAY_REPLY, layer.hop_count];
        out.extend_from_slice(&layer.link.octets());
        out.extend_from_slice(&layer.peer.octets());
        if let Some(id) = &layer.interface_id {
            option(OPTION_INTERFACE_ID, id, &mut out);
        }
        option(OPTION_RELAY_MESSAGE, &current, &mut out);
        current = out;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forward(link: &str, interface: Option<&[u8]>, inner: &[u8]) -> Vec<u8> {
        let mut out = vec![RELAY_FORWARD, 0];
        out.extend_from_slice(&link.parse::<Ipv6Addr>().unwrap().octets());
        out.extend_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        if let Some(id) = interface {
            option(OPTION_INTERFACE_ID, id, &mut out);
        }
        option(OPTION_RELAY_MESSAGE, inner, &mut out);
        out
    }

    #[test]
    fn a_relayed_message_comes_out_and_its_answer_goes_back_wrapped() {
        let packet = forward("fd00:7::1", Some(b"eth5"), &[1, 9, 9, 9]);
        let relayed = unwrap(&packet).unwrap();
        assert_eq!(relayed.message, vec![1, 9, 9, 9]);
        assert_eq!(relayed.link(), Some("fd00:7::1".parse().unwrap()));
        let wrapped = wrap(&relayed.layers, &[7, 9, 9, 9]);
        assert_eq!(wrapped[0], RELAY_REPLY);
        // The same shape comes back out, with the interface id echoed.
        let mut back = wrapped.clone();
        back[0] = RELAY_FORWARD;
        let again = unwrap(&back).unwrap();
        assert_eq!(again.layers, relayed.layers);
        assert_eq!(again.message, vec![7, 9, 9, 9]);
    }

    #[test]
    fn chained_relays_use_the_innermost_link_and_unwrap_in_order() {
        let inner = forward("fd00:7::1", None, &[1, 0, 0, 1]);
        let outer = forward("::", None, &inner);
        let relayed = unwrap(&outer).unwrap();
        assert_eq!(relayed.layers.len(), 2);
        assert_eq!(relayed.link(), Some("fd00:7::1".parse().unwrap()));
        assert_eq!(relayed.message, vec![1, 0, 0, 1]);
    }

    #[test]
    fn malformed_and_too_deeply_nested_relays_are_refused() {
        assert!(unwrap(&[RELAY_FORWARD, 0, 1, 2]).is_none());
        let mut broken = forward("fd00::1", None, &[1, 2, 3, 4]);
        broken.truncate(broken.len() - 2);
        assert!(unwrap(&broken).is_none());
        let mut packet = vec![1, 2, 3, 4];
        for _ in 0..=MAX_DEPTH {
            packet = forward("fd00::1", None, &packet);
        }
        assert!(unwrap(&packet).is_none());
        // A Relay-forward with no inner message says nothing.
        let mut empty = vec![RELAY_FORWARD, 0];
        empty.extend_from_slice(&[0; 32]);
        assert!(unwrap(&empty).is_none());
    }
}

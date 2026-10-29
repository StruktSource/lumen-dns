// SPDX-License-Identifier: Apache-2.0
//! Bounded DNS wire parsing, full message decoding, and safe error responses.

pub use hickory_proto;
use hickory_proto::{
    op::{Message, OpCode, ResponseCode},
    rr::{DNSClass, RecordType},
    serialize::binary::{BinDecodable, BinDecoder},
};

/// DNS-over-TCP's wire-format ceiling. Each listener may set a lower cap.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Error codes used before resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Rcode {
    FormErr = 1,
    ServFail = 2,
    Refused = 5,
}

/// A fully decoded, single-question standard query.
#[derive(Clone, Debug)]
pub struct Query {
    pub message: Message,
}

impl Query {
    /// Parse all sections; reject hidden trailing data, unsupported operations,
    /// invalid flags, invalid questions, and query records other than one OPT.
    ///
    /// # Errors
    /// Returns a non-sensitive error for invalid DNS wire data.
    pub fn parse(packet: &[u8]) -> Result<Self, ParseError> {
        if packet.len() < 12 || packet.len() > MAX_MESSAGE_SIZE {
            return Err(ParseError);
        }
        if packet[2] & 0xfa != 0 || packet[3] & 0x4f != 0 {
            return Err(ParseError);
        }
        if packet[4..10] != [0, 1, 0, 0, 0, 0] || u16::from_be_bytes([packet[10], packet[11]]) > 1 {
            return Err(ParseError);
        }
        // The first name has no previous name to reference. Never echo a pointer
        // to a section that may be omitted from the response.
        let mut offset = 12;
        let mut expanded = 1;
        loop {
            let length = usize::from(*packet.get(offset).ok_or(ParseError)?);
            offset += 1;
            if length == 0 {
                break;
            }
            expanded += length + 1;
            if length > 63 || expanded > 255 {
                return Err(ParseError);
            }
            offset += length;
            if offset >= packet.len() {
                return Err(ParseError);
            }
        }
        let message = decode_message(packet)?;
        let query = message.queries.first().ok_or(ParseError)?;
        if query.query_type() == RecordType::ZERO
            || query.query_class() != DNSClass::IN
            || message.signature.is_some()
            || !message.additionals.is_empty()
        {
            return Err(ParseError);
        }
        Ok(Self { message })
    }

    /// Encode an error while preserving the validated question and RD flag.
    #[must_use]
    pub fn response(&self, rcode: Rcode) -> Vec<u8> {
        let mut message = Message::response(self.message.metadata.id, OpCode::Query);
        message.metadata.recursion_desired = self.message.metadata.recursion_desired;
        message.metadata.recursion_available = true;
        message.metadata.response_code = ResponseCode::from(0, rcode as u8);
        message.queries.clone_from(&self.message.queries);
        message
            .to_vec()
            .unwrap_or_else(|_| malformed_response(&self.message.metadata.id.to_be_bytes()))
    }
}

/// Decode full responses, including compressed names, with byte and record caps.
///
/// # Errors
/// Rejects malformed, oversized, or partially consumed messages.
pub fn decode_message(packet: &[u8]) -> Result<Message, ParseError> {
    if !(12..=MAX_MESSAGE_SIZE).contains(&packet.len()) {
        return Err(ParseError);
    }
    let records: usize = packet[4..12]
        .chunks_exact(2)
        .map(|n| usize::from(u16::from_be_bytes([n[0], n[1]])))
        .sum();
    if records > 4096 {
        return Err(ParseError);
    }
    let mut decoder = BinDecoder::new(packet);
    let message = Message::read(&mut decoder).map_err(|_| ParseError)?;
    if decoder.index() != packet.len() {
        return Err(ParseError);
    }
    Ok(message)
}

/// Header-only FORMERR, bounded even for unparseable input.
#[must_use]
pub fn malformed_response(packet: &[u8]) -> Vec<u8> {
    let id = packet.get(..2).unwrap_or(&[0, 0]);
    let rd = packet.get(2).is_some_and(|flag| flag & 1 != 0);
    let flags = 0x8081_u16 | if rd { 0x0100 } else { 0 };
    [id, &flags.to_be_bytes(), &[0; 8]].concat()
}

/// Parse errors never include packet contents or client query names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError;

/// Whether input is a response. Never answer responses, which could form loops.
#[must_use]
pub fn is_response(packet: &[u8]) -> bool {
    packet.get(2).is_some_and(|flags| flags & 0x80 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    const QUERY: &[u8] = &[
        0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];

    #[test]
    fn preserves_question_and_advertises_recursion() {
        let response = Query::parse(QUERY).unwrap().response(Rcode::ServFail);
        assert_eq!(&response[..6], &[0xbe, 0xef, 0x81, 0x82, 0, 1]);
        assert_eq!(&response[12..], &QUERY[12..]);
    }
    #[test]
    fn rejects_trailing_bytes_missing_opt_and_bad_flags() {
        let mut data = QUERY.to_vec();
        data.push(0);
        assert!(Query::parse(&data).is_err());
        let mut data = QUERY.to_vec();
        data[11] = 1;
        assert!(Query::parse(&data).is_err());
        for (index, mask) in [(2, 0x80), (2, 0x02), (3, 0x40)] {
            let mut data = QUERY.to_vec();
            data[index] |= mask;
            assert!(Query::parse(&data).is_err());
        }
    }
    #[test]
    fn accepts_edns_and_decodes_compressed_answers() {
        let mut data = QUERY.to_vec();
        data[11] = 1;
        data.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0]);
        assert!(Query::parse(&data).is_ok());
        let mut data = QUERY.to_vec();
        data[2] = 0x81;
        data[7] = 1;
        data.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        assert_eq!(decode_message(&data).unwrap().answers.len(), 1);
        let end = data.len();
        data[end - 16] = 0xc0;
        data[end - 15] = 255;
        assert!(decode_message(&data).is_err());
    }
    #[test]
    fn rejects_all_truncated_queries_and_compression_loops() {
        for end in 0..QUERY.len() {
            assert!(Query::parse(&QUERY[..end]).is_err());
        }
        let mut data = QUERY.to_vec();
        data[12] = 0xc0;
        data[13] = 12;
        assert!(Query::parse(&data).is_err());
        for index in [26, 28] {
            let mut data = QUERY.to_vec();
            data[index] = 0;
            assert!(Query::parse(&data).is_err());
        }
        let mut data = vec![0; 12];
        data[5] = 1;
        for _ in 0..4 {
            data.push(63);
            data.extend_from_slice(&[b'a'; 63]);
        }
        data.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(Query::parse(&data).is_err());
    }
    #[test]
    fn malformed_inputs_never_panic() {
        let mut state = 42_u32;
        for len in 0..2048 {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    state.to_be_bytes()[0]
                })
                .collect();
            let _ = Query::parse(&data);
            let _ = decode_message(&data);
            assert_eq!(malformed_response(&data).len(), 12);
        }
    }
}

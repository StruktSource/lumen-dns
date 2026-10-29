//! Bounded DNS wire parsing and minimal response encoding.

/// Largest packet accepted by the initial transport layer.
pub const MAX_MESSAGE_SIZE: usize = 4096;
const HEADER_LEN: usize = 12;

/// DNS return codes used by the initial listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Rcode {
    FormErr = 1,
    ServFail = 2,
    Refused = 5,
}

/// A validated, single-question DNS query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    id: u16,
    recursion_desired: bool,
    question: Vec<u8>,
}

impl Query {
    /// Parses one standard DNS query with an uncompressed question name.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when packet length, header, or question encoding
    /// violates the initial transport limits.
    pub fn parse(packet: &[u8]) -> Result<Self, ParseError> {
        if packet.len() < HEADER_LEN || packet.len() > MAX_MESSAGE_SIZE {
            return Err(ParseError::InvalidLength);
        }

        let flags = u16::from_be_bytes([packet[2], packet[3]]);
        if flags & 0x8000 != 0 || (flags >> 11) & 0x0f != 0 {
            return Err(ParseError::UnsupportedOperation);
        }
        if flags & 0x0240 != 0 {
            return Err(ParseError::InvalidFlags);
        }
        if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
            return Err(ParseError::QuestionCount);
        }
        if packet[6..10] != [0; 4] {
            return Err(ParseError::UnexpectedRecords);
        }

        let question_end = parse_question_end(packet)?;
        // The first question has no earlier DNS names to reference. Never echo
        // pointers into sections omitted from the response.
        let mut offset = HEADER_LEN;
        while packet[offset] != 0 {
            let length = packet[offset];
            if length & 0xc0 != 0 {
                return Err(ParseError::InvalidName);
            }
            offset += usize::from(length) + 1;
        }
        Ok(Self {
            id: u16::from_be_bytes([packet[0], packet[1]]),
            recursion_desired: flags & 0x0100 != 0,
            question: packet[HEADER_LEN..question_end].to_vec(),
        })
    }

    /// Encodes a response that retains the validated question.
    #[must_use]
    pub fn response(&self, rcode: Rcode) -> Vec<u8> {
        let mut response = Vec::with_capacity(HEADER_LEN + self.question.len());
        response.extend_from_slice(&self.id.to_be_bytes());
        let flags =
            0x8000 | if self.recursion_desired { 0x0100 } else { 0 } | u16::from(rcode as u8);
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0; 6]);
        response.extend_from_slice(&self.question);
        response
    }
}

/// Builds a bounded error response when the query could not be parsed.
#[must_use]
pub fn malformed_response(packet: &[u8]) -> Vec<u8> {
    let id = packet.get(..2).unwrap_or(&[0, 0]);
    let recursion_desired = packet.get(2).is_some_and(|flags| flags & 0x01 != 0);
    let flags =
        0x8000 | if recursion_desired { 0x0100 } else { 0 } | u16::from(Rcode::FormErr as u8);
    [id, &flags.to_be_bytes(), &[0; 8]].concat()
}

/// Parse failures deliberately expose no packet detail to remote clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    InvalidLength,
    UnsupportedOperation,
    QuestionCount,
    InvalidFlags,
    UnexpectedRecords,
    InvalidQuestion,
    InvalidName,
}

fn parse_question_end(packet: &[u8]) -> Result<usize, ParseError> {
    let question_end = parse_name_end(packet, HEADER_LEN)?
        .checked_add(4)
        .ok_or(ParseError::InvalidName)?;
    if question_end > packet.len() {
        return Err(ParseError::InvalidName);
    }
    if packet[question_end - 4..question_end - 2] == [0, 0]
        || packet[question_end - 2..question_end] == [0, 0]
    {
        return Err(ParseError::InvalidQuestion);
    }
    Ok(question_end)
}

fn parse_name_end(packet: &[u8], start: usize) -> Result<usize, ParseError> {
    let mut index = start;
    let mut labels = 0_usize;
    let mut jumps = 0_usize;
    let mut expanded_len = 1_usize;
    let mut encoded_end = None;
    loop {
        let Some(&length) = packet.get(index) else {
            return Err(ParseError::InvalidName);
        };
        index += 1;
        if length == 0 {
            return Ok(encoded_end.unwrap_or(index));
        }
        if length & 0xc0 == 0xc0 {
            let Some(&tail) = packet.get(index) else {
                return Err(ParseError::InvalidName);
            };
            let target = usize::from((u16::from(length & 0x3f) << 8) | u16::from(tail));
            if target < HEADER_LEN || target >= index - 1 || jumps == 16 {
                return Err(ParseError::InvalidName);
            }
            encoded_end.get_or_insert(index + 1);
            index = target;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 || labels == 127 {
            return Err(ParseError::InvalidName);
        }
        let end = index
            .checked_add(usize::from(length))
            .ok_or(ParseError::InvalidName)?;
        if end > packet.len() {
            return Err(ParseError::InvalidName);
        }
        expanded_len += usize::from(length) + 1;
        if expanded_len > 255 {
            return Err(ParseError::InvalidName);
        }
        index = end;
        labels += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::{Query, Rcode, parse_name_end};

    const QUERY: [u8; 29] = [
        0xbe, 0xef, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];

    #[test]
    fn preserves_question_in_server_failure() {
        let query = Query::parse(&QUERY).expect("valid query");
        let response = query.response(Rcode::ServFail);
        assert_eq!(&response[..6], &[0xbe, 0xef, 0x81, 0x02, 0, 1]);
        assert_eq!(&response[12..], &QUERY[12..]);
    }

    #[test]
    fn decodes_bounded_name_compression() {
        let mut packet = vec![0; 12];
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        packet.extend_from_slice(&[3, b'w', b'w', b'w', 0xc0, 0x0c]);
        assert_eq!(parse_name_end(&packet, 25), Ok(31));
    }

    #[test]
    fn rejects_query_with_answer_records() {
        let mut query = QUERY;
        query[7] = 1;
        assert!(Query::parse(&query).is_err());
    }

    #[test]
    fn rejects_zero_question_type_or_class() {
        let mut query = QUERY;
        query[26] = 0;
        assert!(Query::parse(&query).is_err());
        query = QUERY;
        query[28] = 0;
        assert!(Query::parse(&query).is_err());
    }

    #[test]
    fn rejects_forward_pointers_and_loops() {
        let mut packet = vec![0; 12];
        packet.extend_from_slice(&[0xc0, 0x0e, 0]);
        assert!(parse_name_end(&packet, 12).is_err());
        packet[13] = 12;
        assert!(parse_name_end(&packet, 12).is_err());
    }

    #[test]
    fn rejects_name_over_255_bytes() {
        let mut packet = vec![0; 12];
        for _ in 0..4 {
            packet.push(63);
            packet.extend_from_slice(&[b'a'; 63]);
        }
        packet.push(0);
        assert!(parse_name_end(&packet, 12).is_err());
    }
}

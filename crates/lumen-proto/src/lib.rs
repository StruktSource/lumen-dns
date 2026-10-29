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
    /// Parses one standard DNS query without compressed question labels.
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
        if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
            return Err(ParseError::QuestionCount);
        }

        let question_end = parse_question_end(packet)?;
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
    InvalidName,
}

fn parse_question_end(packet: &[u8]) -> Result<usize, ParseError> {
    let mut index = HEADER_LEN;
    let mut labels = 0_usize;
    loop {
        let Some(&length) = packet.get(index) else {
            return Err(ParseError::InvalidName);
        };
        index += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 || length > 63 || labels == 127 {
            return Err(ParseError::InvalidName);
        }
        let end = index
            .checked_add(usize::from(length))
            .ok_or(ParseError::InvalidName)?;
        if end > packet.len() {
            return Err(ParseError::InvalidName);
        }
        index = end;
        labels += 1;
    }
    let question_end = index.checked_add(4).ok_or(ParseError::InvalidName)?;
    if question_end > packet.len() {
        return Err(ParseError::InvalidName);
    }
    Ok(question_end)
}

#[cfg(test)]
mod tests {
    use super::{Query, Rcode};

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
    fn rejects_compressed_question_name() {
        let mut query = QUERY;
        query[12] = 0xc0;
        assert!(Query::parse(&query).is_err());
    }
}

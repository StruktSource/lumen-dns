//! EDNS(0) padding of responses on encrypted transports (RFC 7830, RFC 8467).
//!
//! A client that sends a Padding option in its query asks the server to hide the length of the
//! answer. Lumen then pads the answer to a multiple of 468 bytes (the block size RFC 8467
//! recommends for servers). Plain UDP and TCP answers are never padded.

use lumen_proto::hickory_proto::{
    op::Message,
    rr::rdata::opt::{EdnsCode, EdnsOption},
};

/// Block size for padded responses (RFC 8467 section 4.1).
pub const RESPONSE_BLOCK: usize = 468;

/// Pads `response` when `query` asked for padding. Any failure returns the response unchanged.
#[must_use]
pub fn pad_response(query: &[u8], response: Vec<u8>) -> Vec<u8> {
    let Ok(question) = Message::from_vec(query) else {
        return response;
    };
    let wants = question
        .edns
        .as_ref()
        .is_some_and(|edns| edns.option(EdnsCode::Padding).is_some());
    if !wants {
        return response;
    }
    let Ok(mut message) = Message::from_vec(&response) else {
        return response;
    };
    let Some(edns) = message.edns.as_mut() else {
        return response;
    };
    edns.options_mut().remove(EdnsCode::Padding);
    let Ok(plain) = message.to_vec() else {
        return response;
    };
    // An empty option costs four bytes (code and length).
    let total = (plain.len() + 4).div_ceil(RESPONSE_BLOCK) * RESPONSE_BLOCK;
    if total > usize::from(u16::MAX) {
        return response;
    }
    if let Some(edns) = message.edns.as_mut() {
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, vec![0; total - plain.len() - 4]));
    }
    message.to_vec().unwrap_or(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumen_proto::hickory_proto::{
        op::{Edns, Query},
        rr::{Name, RecordType},
    };
    use std::str::FromStr;

    fn message(padding: bool, edns: bool) -> Message {
        let mut message = Message::query();
        message.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        if edns {
            let mut edns = Edns::new();
            edns.set_max_payload(1232);
            if padding {
                edns.options_mut()
                    .insert(EdnsOption::Unknown(12, vec![0; 8]));
            }
            message.edns = Some(edns);
        }
        message
    }

    #[test]
    fn pads_to_the_block_only_when_asked() {
        let asked = message(true, true).to_vec().unwrap();
        let plain = message(false, true).to_vec().unwrap();
        let response = message(false, true).to_vec().unwrap();
        let padded = pad_response(&asked, response.clone());
        assert_eq!(padded.len() % RESPONSE_BLOCK, 0);
        assert!(padded.len() >= response.len());
        assert_eq!(pad_response(&plain, response.clone()), response);
        assert_eq!(pad_response(&asked, padded.clone()), padded, "idempotent");
    }

    #[test]
    fn answers_without_an_opt_record_stay_as_they_are() {
        let asked = message(true, true).to_vec().unwrap();
        let bare = message(false, false).to_vec().unwrap();
        assert_eq!(pad_response(&asked, bare.clone()), bare);
        assert_eq!(pad_response(b"junk", bare.clone()), bare);
    }
}

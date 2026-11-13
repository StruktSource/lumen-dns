//! EDNS(0) padding (RFC 7830, RFC 8467): Lumen pads its encrypted upstream queries, and pads
//! its own answers on encrypted listeners when the client asks.

use hickory_proto::{
    op::{Edns, Message, Query},
    rr::{
        Name, RecordType,
        rdata::opt::{EdnsCode, EdnsOption},
    },
};
use hickory_server::net::xfer::padding::{QUERY_BLOCK, pad_message};
use std::str::FromStr;

fn query(name: &str, edns: bool) -> Message {
    let mut message = Message::query();
    message.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    if edns {
        let mut edns = Edns::new();
        edns.set_max_payload(1232).set_dnssec_ok(true);
        message.edns = Some(edns);
    }
    message
}

#[test]
fn upstream_queries_are_padded_to_whole_blocks() {
    let long = "x.".repeat(60);
    for name in [
        "a.",
        "example.com.",
        "a-much-longer-name.example.org.",
        &long,
    ] {
        let mut message = query(name, true);
        pad_message(&mut message, QUERY_BLOCK);
        let wire = message.to_vec().unwrap();
        assert_eq!(wire.len() % QUERY_BLOCK, 0, "{name}");
        let parsed = Message::from_vec(&wire).unwrap();
        let edns = parsed.edns.unwrap();
        assert!(matches!(
            edns.option(EdnsCode::Padding),
            Some(EdnsOption::Unknown(12, _))
        ));
        assert!(edns.flags().dnssec_ok, "other EDNS fields survive");
    }
}

#[test]
fn padding_is_stable_and_skips_messages_without_opt() {
    let mut message = query("example.com.", true);
    pad_message(&mut message, QUERY_BLOCK);
    let once = message.to_vec().unwrap();
    pad_message(&mut message, QUERY_BLOCK);
    assert_eq!(once, message.to_vec().unwrap());

    let mut bare = query("example.com.", false);
    let before = bare.to_vec().unwrap();
    pad_message(&mut bare, QUERY_BLOCK);
    assert_eq!(before, bare.to_vec().unwrap());
    let mut message = query("example.com.", true);
    let before = message.to_vec().unwrap();
    pad_message(&mut message, 0);
    assert_eq!(before, message.to_vec().unwrap());
}

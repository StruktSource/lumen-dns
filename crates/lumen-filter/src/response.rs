// SPDX-License-Identifier: Apache-2.0
//! Synthetic policy responses carry no AD bit, signatures, or cache lifetime.

use crate::config::Action;
use lumen_proto::{
    Query, Rcode,
    hickory_proto::{
        op::{Message, OpCode, ResponseCode},
        rr::{
            Name, RData, Record, RecordType,
            rdata::{A, AAAA, CNAME},
        },
    },
};

/// Build a policy answer. Missing address family and other RR types return NODATA.
/// Synthetic responses use TTL zero and are never inserted into resolver caches.
#[must_use]
pub fn response(query: &Query, action: &Action, maximum: usize) -> Vec<u8> {
    let mut message = Message::response(query.message.metadata.id, OpCode::Query);
    message.metadata.recursion_desired = query.message.metadata.recursion_desired;
    message.metadata.recursion_available = true;
    message.metadata.checking_disabled = query.message.metadata.checking_disabled;
    message.queries.clone_from(&query.message.queries);
    let question = &query.message.queries[0];
    match action {
        Action::Nxdomain => message.metadata.response_code = ResponseCode::NXDomain,
        Action::Refused => message.metadata.response_code = ResponseCode::Refused,
        Action::Nodata => (),
        Action::Address { ipv4, ipv6 } => {
            let data = match question.query_type() {
                RecordType::A => ipv4.map(|ip| RData::A(A(ip))),
                RecordType::AAAA => ipv6.map(|ip| RData::AAAA(AAAA(ip))),
                _ => None,
            };
            if let Some(data) = data {
                message.add_answer(Record::from_rdata(question.name().clone(), 0, data));
            }
        }
        Action::Cname { target } => {
            if let Ok(name) = Name::from_utf8(target) {
                message.add_answer(Record::from_rdata(
                    question.name().clone(),
                    0,
                    RData::CNAME(CNAME(name)),
                ));
            }
        }
    }
    let limit = maximum;
    let mut bytes = message
        .to_vec()
        .unwrap_or_else(|_| query.response(Rcode::ServFail));
    if bytes.len() > limit {
        message.answers.clear();
        message.metadata.truncation = true;
        bytes = message
            .to_vec()
            .unwrap_or_else(|_| query.response(Rcode::ServFail));
    }
    bytes
}

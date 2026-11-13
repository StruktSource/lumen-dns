//! ACME DNS-01 challenge answers. While a certificate order runs, the ACME client puts the
//! challenge value here, and the resolver answers `TXT _acme-challenge.<name>` with it,
//! authoritatively and straight from memory. Nothing else is answered from here.

use crate::response_base;
use hickory_server::proto::{
    op::Message,
    rr::{Name, RData, Record, RecordType, rdata::TXT},
};
use lumen_proto::Query;
use std::{collections::HashMap, sync::Mutex};

/// Most challenge values held at once. One per name on a certificate, with room for retries.
const MAX_VALUES: usize = 32;

/// The pending DNS-01 values, by lowercase owner name with a trailing dot.
#[derive(Default)]
pub struct Challenges {
    values: Mutex<HashMap<String, Vec<String>>>,
}

impl Challenges {
    /// Serve `value` as a TXT record at `_acme-challenge.<name>`. A wildcard and its base name
    /// share one owner, so they may hold two values.
    pub fn publish(&self, name: &str, value: &str) {
        let owner = owner(name);
        let Ok(mut values) = self.values.lock() else {
            return;
        };
        if values.len() >= MAX_VALUES && !values.contains_key(&owner) {
            return;
        }
        let entry = values.entry(owner).or_default();
        if entry.len() < 4 && !entry.iter().any(|existing| existing == value) {
            entry.push(value.to_owned());
        }
    }

    /// Forget every published value.
    pub fn clear(&self) {
        if let Ok(mut values) = self.values.lock() {
            values.clear();
        }
    }

    fn lookup(&self, owner: &str) -> Vec<String> {
        self.values
            .lock()
            .ok()
            .and_then(|values| values.get(owner).cloned())
            .unwrap_or_default()
    }

    /// The wire answer for a raw DNS query packet, when it asks for a published challenge name.
    /// Used by the temporary responder that runs before Lumen's own listeners exist.
    #[must_use]
    pub fn answer_packet(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let query = Query::parse(packet).ok()?;
        self.answer(&query)?.to_vec().ok()
    }

    /// The authoritative answer for a TXT question about a published name, or `None` when the
    /// query is about anything else.
    pub(crate) fn answer(&self, query: &Query) -> Option<Message> {
        let question = query.message.queries.first()?;
        if question.query_type() != RecordType::TXT {
            return None;
        }
        let name = question.name().to_ascii().to_ascii_lowercase();
        let texts = self.lookup(&name);
        if texts.is_empty() {
            return None;
        }
        let mut response = response_base(query, true);
        let owner: Name = question.name().clone();
        for text in texts {
            response.add_answer(Record::from_rdata(
                owner.clone(),
                1,
                RData::TXT(TXT::new(vec![text])),
            ));
        }
        Some(response)
    }
}

fn owner(name: &str) -> String {
    let base = name.trim_start_matches("*.").trim_end_matches('.');
    format!("_acme-challenge.{}.", base.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::op::Query as DnsQuery;
    use std::str::FromStr;

    fn ask(name: &str, kind: RecordType) -> Query {
        let mut message = Message::query();
        message.add_query(DnsQuery::query(Name::from_str(name).unwrap(), kind));
        Query::parse(&message.to_vec().unwrap()).unwrap()
    }

    #[test]
    fn only_published_names_get_a_txt_answer() {
        let challenges = Challenges::default();
        assert!(
            challenges
                .answer(&ask("_acme-challenge.dns.example.com.", RecordType::TXT))
                .is_none()
        );
        challenges.publish("dns.example.com", "token-one");
        let reply = challenges
            .answer(&ask("_ACME-Challenge.DNS.example.com.", RecordType::TXT))
            .unwrap();
        assert!(reply.metadata.authoritative);
        assert_eq!(reply.answers.len(), 1);
        assert!(
            matches!(&reply.answers[0].data, RData::TXT(txt) if txt.to_string() == "token-one")
        );
        assert!(
            challenges
                .answer(&ask("_acme-challenge.dns.example.com.", RecordType::A))
                .is_none()
        );
        assert!(
            challenges
                .answer(&ask("_acme-challenge.other.example.com.", RecordType::TXT))
                .is_none()
        );
        challenges.clear();
        assert!(
            challenges
                .answer(&ask("_acme-challenge.dns.example.com.", RecordType::TXT))
                .is_none()
        );
    }

    #[test]
    fn a_wildcard_and_its_base_name_share_one_owner_with_two_values() {
        let challenges = Challenges::default();
        challenges.publish("*.example.com", "wild");
        challenges.publish("example.com", "base");
        challenges.publish("example.com", "base");
        let reply = challenges
            .answer(&ask("_acme-challenge.example.com.", RecordType::TXT))
            .unwrap();
        assert_eq!(reply.answers.len(), 2);
    }
}

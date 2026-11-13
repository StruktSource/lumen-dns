//! A hook for a bridge to another naming system (multicast DNS). The resolver asks it first for
//! names under the bridge's own domain; the bridge answers from what it has learned, or says it
//! does not handle the name.

use async_trait::async_trait;
use hickory_server::proto::{
    op::ResponseCode,
    rr::{Name, Record, RecordType},
};

/// What a bridge answers.
#[derive(Debug, Default)]
pub struct BridgeAnswer {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

#[async_trait]
pub trait Bridge: Send + Sync {
    /// Answer a question, or `None` when the name is not the bridge's to answer. May wait for
    /// the network, but only for a short, bounded time.
    async fn answer(&self, name: &Name, rtype: RecordType) -> Option<BridgeAnswer>;
}

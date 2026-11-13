//! One network the bridge listens on and speaks to. Real links are UDP sockets; tests use memory.

use async_trait::async_trait;
use std::{
    io,
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    V4,
    V6,
}

/// A packet that arrived on a link.
pub struct Datagram {
    pub link: usize,
    pub source: SocketAddr,
    pub bytes: Vec<u8>,
}

#[async_trait]
pub trait Link: Send + Sync {
    fn name(&self) -> &str;
    fn family(&self) -> Family;
    /// Send a packet to the multicast group of this link.
    async fn send(&self, packet: &[u8]) -> io::Result<()>;
    /// Whether `source` could be a device on this link.
    fn on_link(&self, source: IpAddr) -> bool;
}

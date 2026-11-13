//! DHCP server for IPv4 and IPv6 that also feeds Lumen's DNS.
//!
//! The packet logic in [`v4`] and [`v6`] is pure: a request and the time go in, an optional reply
//! and the lease changes come out. Sockets, storage, and DNS publishing live around it, so every
//! rule can be tested without a network.

pub mod failover;
pub mod relay;
pub mod server;
pub mod store;
pub mod v4;
pub mod v6;

pub use server::{FailoverInfo, Handle, LeaseInfo, Running, ScopeInfo, Snapshot, start};

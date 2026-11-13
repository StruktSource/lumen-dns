// SPDX-License-Identifier: Apache-2.0
//! What the console may ask of the running daemon. Implemented by `lumen-core`.

use std::net::IpAddr;

/// One DHCP network, for the console.
#[derive(Clone, Debug)]
pub struct DhcpScopeInfo {
    /// 4 or 6.
    pub family: u8,
    pub interface: Option<String>,
    pub network: String,
    pub range: String,
    pub active: usize,
    pub capacity: u64,
}

/// One bound DHCP lease, for the console.
#[derive(Clone, Debug)]
pub struct DhcpLeaseInfo {
    pub family: u8,
    pub ip: IpAddr,
    pub client: String,
    pub hostname: Option<String>,
    /// Unix seconds.
    pub expires: u64,
}

/// What the DHCP module shows. `None` from [`Host::dhcp`] means the server is not running.
#[derive(Clone, Debug, Default)]
pub struct DhcpInfo {
    pub scopes: Vec<DhcpScopeInfo>,
    pub leases: Vec<DhcpLeaseInfo>,
}

/// Aggregate counters. No domain names, clients, or profiles.
#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub queries: u64,
    pub responses: u64,
    pub malformed: u64,
    pub refused: u64,
    pub timeouts: u64,
    pub failures: u64,
    pub active: u64,
    /// udp, tcp, tls, https, quic, other.
    pub transports: [u64; 6],
    /// Buckets: <=1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, slower.
    pub latency: [u64; 8],
    /// Responses by code: `NOERROR`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, other.
    pub rcodes: [u64; 5],
    pub blocked: u64,
    pub allowed: u64,
    pub refresh_successes: u64,
    pub refresh_failures: u64,
    pub rollbacks: u64,
    pub filter_generation: u64,
}

/// Rule counts of one list in the live filter generation.
#[derive(Clone, Debug)]
pub struct ListInfo {
    pub id: String,
    pub rules: usize,
    pub unsupported: usize,
    pub duplicates: usize,
}

/// Result of a dry-run policy decision.
#[derive(Clone, Debug)]
pub struct Explained {
    pub blocked: bool,
    pub rule: Option<String>,
    pub list: Option<String>,
    pub category: Option<String>,
    pub profile: Option<String>,
    pub device: Option<String>,
    pub group: Option<String>,
    pub generation: u64,
}

pub use lumen_store::{HistoryDetail, HistoryMode};

/// Current history behaviour of the daemon.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HistorySettings {
    pub mode: HistoryMode,
    pub detail: HistoryDetail,
}

/// One recorded lookup. `client` and `device` are `None` in anonymous mode.
#[derive(Clone, Debug)]
pub struct QueryRecord {
    pub unix_ms: u64,
    pub domain: String,
    pub qtype: String,
    pub client: Option<IpAddr>,
    pub device: Option<String>,
    pub blocked: bool,
    pub rcode: &'static str,
    pub micros: u64,
}

/// Live daemon data for the console.
pub trait Host: Send + Sync + 'static {
    fn counters(&self) -> Counters;
    fn lists(&self) -> Vec<ListInfo>;
    fn explain(&self, domain: &str, client: IpAddr, unix_seconds: u64) -> Explained;
    fn uptime_secs(&self) -> u64;
    fn history_settings(&self) -> HistorySettings;
    /// Switching away from a mode discards what that mode still holds in memory.
    fn set_history(&self, settings: HistorySettings);
    /// Memory mode only: the recent lookups, newest first.
    fn history(&self, limit: usize) -> Vec<QueryRecord>;
    /// Saved mode only: lookups waiting to be written to the database, oldest first.
    /// Each lookup is returned once.
    fn take_unsaved_history(&self) -> Vec<QueryRecord>;
    /// External sign-in settings when the operator turned them on.
    fn oidc(&self) -> Option<lumen_config::Oidc> {
        None
    }
    /// The DHCP server's scopes and leases, when it is running.
    fn dhcp(&self) -> Option<DhcpInfo> {
        None
    }
}

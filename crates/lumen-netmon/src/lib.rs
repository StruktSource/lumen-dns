//! Network discovery, a device inventory, topology, and monitoring.
//!
//! Everything here is opt-in (`[network]`) and only looks at the networks an administrator lists.
//! The inventory lives in the web console's state database; probes and SNMP run in the daemon.

// Rates, percentages and BER lengths are bounded numbers converted on purpose.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::trivially_copy_pass_by_ref
)]

pub mod api;
pub mod data;
pub mod engine;
pub mod health;
pub mod model;
pub mod neighbors;
pub mod oui;
pub mod probe;
pub mod scope;
pub mod snmp;
mod store;

pub use data::{IfReading, Target, octet_rate};
pub use engine::{DhcpHost, EngineStatus, Environment, Handle, Running, ScopeStatus, start};
pub use health::{CheckResult, Health, Transition};
pub use model::*;
pub use oui::{Mac, Oui, format_mac, parse_mac};
pub use store::{Merged, Netmon, Observation, Source, guess_kind};

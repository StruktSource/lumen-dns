//! Multicast DNS bridge.
//!
//! Two jobs, both off until configured:
//!
//! - a **discovery proxy** that answers ordinary DNS questions under a domain from what devices
//!   announce with mDNS (`printer.local` becomes `printer.<domain>`), and
//! - a **reflector** that repeats mDNS between interfaces, so devices on separate networks see
//!   each other.
//!
//! The rules (what is learned, what is repeated, how names are rewritten) are plain code with
//! tests. Sockets sit behind the [`link::Link`] trait, so everything is tested without a network.

pub mod bridge;
pub mod cache;
pub mod link;
pub mod net;
pub mod reflect;
pub mod rewrite;

pub use bridge::{Bridge, Settings};
pub use net::{Running, start};

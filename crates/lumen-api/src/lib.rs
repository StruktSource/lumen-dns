//! Reserved control-plane API boundary.
//!
//! No network API is exposed yet. Future endpoints must use `/v1`, scoped
//! authorization, explicit audit events, and opt-in remote exposure.

/// First reserved public API version.
pub const FIRST_API_VERSION: &str = "v1";

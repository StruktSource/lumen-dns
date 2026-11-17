//! IP address management: subnets, VLANs, locations, and an address inventory, kept in `SQLite`.
//!
//! This is bookkeeping only. Assigning an address here never configures a device, creates a DHCP
//! lease, or touches a network interface. DHCP leases are passed in by the caller (as a
//! [`Leased`] list) so the inventory can show them and never hand out an address a lease holds,
//! and so IPAM works unchanged when no DHCP server runs.
//!
//! Every change runs in one transaction, and allocation takes the write lock first, so two
//! requests can never receive the same address.

mod alloc;
pub mod api;
mod model;
mod store;

pub use model::{
    AddressFilter, AddressInput, AddressRow, AddressState, AllocateInput, Conflict, Leased,
    Location, LocationInput, Overview, Placement, Strategy, Subnet, SubnetInput, SubnetStats, Vlan,
    VlanInput,
};
pub use store::Ipam;

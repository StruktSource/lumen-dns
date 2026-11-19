//! The network module in the console: discovery, the device inventory, topology and monitoring.
//! The shared routes live in `lumen-netmon`; this adds the console's sign-in and audit trail.

use super::{Console, Ctx, Reply, enabled_modules, error, reply};
use hyper::StatusCode;
use lumen_netmon::api::{self, Request};
use lumen_store::Store;

impl Console {
    /// Handle `/api/network/...` for administrators.
    pub(super) fn network_route(
        &self,
        store: &mut Store,
        ctx: &Ctx<'_>,
        method: &str,
        parts: &[&str],
    ) -> Reply {
        let modules = enabled_modules(store);
        if !modules.contains(&"network") {
            return error(StatusCode::NOT_FOUND, "the network module is off");
        }
        if api::access(method, parts).is_none() {
            return error(StatusCode::NOT_FOUND, "not found");
        }
        let outcome = api::handle(&Request {
            method,
            parts,
            query: &ctx.request.query,
            body: &ctx.request.body,
            state: &self.state,
            ipam_enabled: modules.contains(&"ipam"),
            engine: self.host.network_engine(),
        });
        if let Some((action, target)) = &outcome.audit {
            Self::actor(store, ctx, action, target);
        }
        reply(
            StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &outcome.body,
        )
    }
}

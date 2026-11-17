//! The IPAM module in the console: the shared JSON routes of `lumen-ipam` behind the console's
//! sign-in, plus what only the daemon can do (read DHCP leases, publish names in DNS).
//!
//! Everything here is bookkeeping. Nothing configures a device, creates a DHCP lease, or changes
//! a network interface. Names given to addresses can be published in DNS when
//! `ipam.dns_domain` is set.

use super::{Console, Ctx, Reply, enabled_modules, error, reply};
use hyper::StatusCode;
use lumen_ipam::{
    Ipam, Leased,
    api::{self, Request},
};
use lumen_store::Store;
use std::{collections::HashSet, net::IpAddr, time::Duration};

impl Console {
    /// The addresses DHCP holds right now, when a server runs.
    fn live_leases(&self) -> Option<Vec<Leased>> {
        self.host.dhcp().map(|info| {
            info.leases
                .iter()
                .filter(|l| l.prefix_len.is_none() && !l.temporary)
                .map(|l| Leased {
                    ip: l.ip,
                    hostname: l.hostname.clone(),
                })
                .collect()
        })
    }

    /// Tell the shared state what only the daemon knows: the DNS domain and the DHCP leases, so
    /// the management API (which cannot ask the daemon) behaves the same.
    fn ipam_refresh(&self, ipam: &mut Ipam) -> Vec<Leased> {
        let domain = self.host.ipam_dns_domain().unwrap_or_default();
        if ipam.meta("dns_domain").ok().flatten().as_deref() != Some(domain.as_str()) {
            let _ = ipam.set_meta("dns_domain", &domain);
        }
        let live = self.live_leases();
        let now: Vec<Leased> = live.clone().unwrap_or_default();
        let key = |list: &[Leased]| -> HashSet<(IpAddr, Option<String>)> {
            list.iter().map(|l| (l.ip, l.hostname.clone())).collect()
        };
        let stored = ipam.leased().unwrap_or_default();
        if key(&stored) != key(&now) {
            let _ = ipam.replace_leases(&now);
        }
        let running = if live.is_some() { "1" } else { "0" };
        if ipam.meta("dhcp_running").ok().flatten().as_deref() != Some(running) {
            let _ = ipam.set_meta("dhcp_running", running);
        }
        now
    }

    /// Make DNS match the inventory: every address with a name and DNS publishing on.
    pub(super) fn ipam_sync_dns(&self) {
        if self.host.ipam_dns_domain().is_none() {
            return;
        }
        if let Ok(ipam) = Ipam::open(&self.state)
            && let Ok(entries) = ipam.dns_entries()
        {
            self.host.ipam_dns_sync(&entries);
        }
    }

    /// One pass of the background upkeep: refresh what the management API relies on, and
    /// publish DNS again when an address changed there.
    fn ipam_tick(&self, synced: &mut u64) {
        let Ok(store) = Store::open(&self.state) else {
            return;
        };
        if !enabled_modules(&store).contains(&"ipam") {
            return;
        }
        let Ok(mut ipam) = Ipam::open(&self.state) else {
            return;
        };
        self.ipam_refresh(&mut ipam);
        if let Ok(generation) = ipam.generation()
            && generation != *synced
        {
            *synced = generation;
            self.ipam_sync_dns();
        }
    }

    /// Keep DHCP leases, the DNS domain and the published names current while the module is
    /// on. Changes made through the management API reach DNS within a few seconds.
    ///
    /// # Errors
    /// Never returns an error; the signature matches the other web tasks.
    pub async fn run_ipam_sync(self: std::sync::Arc<Self>) -> std::io::Result<()> {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Names are published at start-up from the stored inventory.
        let mut synced = u64::MAX;
        loop {
            tick.tick().await;
            let console = std::sync::Arc::clone(&self);
            let seen = synced;
            if let Ok(next) = tokio::task::spawn_blocking(move || {
                let mut synced = seen;
                console.ipam_tick(&mut synced);
                synced
            })
            .await
            {
                synced = next;
            }
        }
    }

    /// Handle `/api/ipam/...` for administrators.
    pub(super) fn ipam_route(
        &self,
        store: &mut Store,
        ctx: &Ctx<'_>,
        method: &str,
        parts: &[&str],
    ) -> Reply {
        if !enabled_modules(store).contains(&"ipam") {
            return error(StatusCode::NOT_FOUND, "the IPAM module is off");
        }
        if api::access(method, parts).is_none() {
            return error(StatusCode::NOT_FOUND, "not found");
        }
        let Ok(mut ipam) = Ipam::open(&self.state) else {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "the IPAM database failed to open",
            );
        };
        let leased = self.ipam_refresh(&mut ipam);
        let outcome = api::handle(
            &mut ipam,
            &Request {
                method,
                parts,
                query: &ctx.request.query,
                body: &ctx.request.body,
                leased: &leased,
                dhcp: self.host.dhcp().is_some(),
            },
        );
        if let Some((action, target)) = &outcome.audit {
            Self::actor(store, ctx, action, target);
            if action.starts_with("ipam.address.") {
                self.ipam_sync_dns();
            }
        }
        reply(
            StatusCode::from_u16(outcome.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &outcome.body,
        )
    }
}

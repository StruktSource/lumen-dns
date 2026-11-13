//! Stateful `DHCPv6` (RFC 8415) decisions for one scope: one `IA_NA` address per client and `IAID`.

use crate::v4::host_label;
use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, IANA, IAPD, IAPrefix, Message, MessageType, OptionCode,
    Status, StatusCode,
};
use ipnet::Ipv6Net;
use lumen_config::{DhcpScope6, parse_hex};
use std::{collections::HashMap, net::Ipv6Addr};

/// How long an advertised address is held for the client it was advertised to.
pub const OFFER_HOLD_SECS: u64 = 60;
/// How long a declined address stays out of use.
pub const DECLINE_QUARANTINE_SECS: u64 = 600;
/// The `FQDN` option (RFC 4704), which the dhcproto crate does not model.
const FQDN_CODE: u16 = 39;

/// A lease or an advertisement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease6 {
    pub ip: Ipv6Addr,
    /// The client's `DUID`.
    pub client: Vec<u8>,
    pub iaid: u32,
    pub hostname: Option<String>,
    /// Unix seconds.
    pub expires: u64,
    /// An advertisement is held briefly and is neither stored nor published.
    pub offered: bool,
}

/// A delegated prefix (`IA_PD`) or an offer of one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delegation6 {
    pub prefix: Ipv6Net,
    /// The requesting router's `DUID`.
    pub client: Vec<u8>,
    pub iaid: u32,
    /// Unix seconds.
    pub expires: u64,
    pub offered: bool,
}

/// What a reply changes besides being sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change6 {
    Bind(Lease6),
    End(Ipv6Addr),
    BindPrefix(Delegation6),
    EndPrefix(Ipv6Net),
}

/// The answer to one client message.
pub struct Reply6 {
    pub message: Message,
    pub changes: Vec<Change6>,
}

/// One scope: its settings, leases, and allocation state.
pub struct Engine6 {
    scope: DhcpScope6,
    server_id: Vec<u8>,
    leases: HashMap<Ipv6Addr, Lease6>,
    declined: HashMap<Ipv6Addr, u64>,
    reservations: HashMap<Vec<u8>, (Ipv6Addr, Option<String>)>,
    reserved: HashMap<Ipv6Addr, Vec<u8>>,
    delegated: HashMap<Ipv6Net, Delegation6>,
    prefix_owner: HashMap<Ipv6Net, Vec<u8>>,
    prefix_reserved: HashMap<Vec<u8>, Ipv6Net>,
    /// See `v4::Engine::set_reserve`.
    reserve: Option<u8>,
}

/// What the prefix part of a message did.
#[derive(Default)]
struct Prefixes {
    granted: bool,
}

/// The first label of the client `FQDN` option, made safe to publish.
fn client_name(request: &Message) -> Option<String> {
    request.opts().iter().find_map(|option| match option {
        DhcpOption::Unknown(unknown) if u16::from(unknown.code()) == FQDN_CODE => {
            // Flags byte, then the name in DNS wire form (the first label is what we keep).
            let data = unknown.data();
            let length = usize::from(*data.get(1)?);
            let label = data.get(2..2 + length)?;
            host_label(std::str::from_utf8(label).ok()?)
        }
        _ => None,
    })
}

fn status(code: Status, message: &str) -> DhcpOption {
    DhcpOption::StatusCode(StatusCode {
        status: code,
        msg: message.to_owned(),
    })
}

/// A stable starting point in the range for a client, so it tends to get the same address back.
fn start_offset(client: &[u8], iaid: u32, size: u128) -> u128 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in client.iter().copied().chain(iaid.to_be_bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    u128::from(hash) % size
}

impl Engine6 {
    /// `bound` are leases restored from storage. Expired ones are dropped.
    #[must_use]
    pub fn new(scope: &DhcpScope6, server_id: Vec<u8>, bound: Vec<Lease6>, now: u64) -> Self {
        let mut reservations = HashMap::new();
        let mut reserved = HashMap::new();
        for reservation in &scope.reservations {
            if let Some(duid) = parse_hex(&reservation.duid) {
                let name = reservation.hostname.as_deref().and_then(host_label);
                reservations.insert(duid.clone(), (reservation.ip, name));
                reserved.insert(reservation.ip, duid);
            }
        }
        let mut prefix_owner = HashMap::new();
        let mut prefix_reserved = HashMap::new();
        if let Some(delegation) = &scope.delegation {
            for reservation in &delegation.reservations {
                if let Some(duid) = parse_hex(&reservation.duid) {
                    prefix_owner.insert(reservation.prefix, duid.clone());
                    prefix_reserved.insert(duid, reservation.prefix);
                }
            }
        }
        let leases = bound
            .into_iter()
            .filter(|lease| lease.expires > now && scope.prefix.contains(&lease.ip))
            .map(|lease| (lease.ip, lease))
            .collect();
        Self {
            scope: scope.clone(),
            server_id,
            leases,
            declined: HashMap::new(),
            reservations,
            reserved,
            delegated: HashMap::new(),
            prefix_owner,
            prefix_reserved,
            reserve: None,
        }
    }

    /// Restore delegated prefixes from storage. Expired or foreign ones are dropped.
    pub fn restore_prefixes(&mut self, bound: Vec<Delegation6>, now: u64) {
        let Some(pool) = self.scope.delegation.as_ref() else {
            return;
        };
        let (pool, length) = (pool.pool, pool.length);
        for item in bound {
            if item.expires > now
                && item.prefix.prefix_len() == length
                && pool.contains(&item.prefix.network())
            {
                self.delegated.insert(item.prefix, item);
            }
        }
    }

    /// Bound delegations, for tests and status.
    #[must_use]
    pub fn bound_prefixes(&self) -> Vec<Delegation6> {
        let mut out: Vec<Delegation6> = self
            .delegated
            .values()
            .filter(|item| !item.offered)
            .cloned()
            .collect();
        out.sort_by_key(|item| item.prefix);
        out
    }

    /// Drop delegations that have run out. Returns the prefixes that ended.
    pub fn expire_prefixes(&mut self, now: u64) -> Vec<Ipv6Net> {
        let mut ended = Vec::new();
        self.delegated.retain(|prefix, item| {
            let alive = item.expires > now;
            if !alive && !item.offered {
                ended.push(*prefix);
            }
            alive
        });
        ended
    }

    /// Restrict new leases to the last `percent` of the range, or lift the restriction.
    pub fn set_reserve(&mut self, percent: Option<u8>) {
        self.reserve = percent;
    }

    fn window_ok(&self, ip: Ipv6Addr, client: &[u8], now: u64) -> bool {
        let Some(percent) = self.reserve else {
            return true;
        };
        if self.reserved.contains_key(&ip)
            || self
                .leases
                .get(&ip)
                .is_some_and(|lease| lease.client == client && lease.expires > now)
        {
            return true;
        }
        let (start, end) = self.range();
        let tail = ((end - start + 1) * u128::from(percent) / 100).max(1);
        u128::from(ip) + tail > end
    }

    fn prefix_window_ok(&self, prefix: Ipv6Net, client: &[u8], now: u64) -> bool {
        let (Some(percent), Some(delegation)) = (self.reserve, &self.scope.delegation) else {
            return true;
        };
        if self.prefix_owner.contains_key(&prefix)
            || self
                .delegated
                .get(&prefix)
                .is_some_and(|item| item.client == client && item.expires > now)
        {
            return true;
        }
        let shift = 128 - u32::from(delegation.length);
        let count = 1u128 << (delegation.length - delegation.pool.prefix_len());
        let index = (u128::from(prefix.network()) - u128::from(delegation.pool.network())) >> shift;
        let tail = (count * u128::from(percent) / 100).max(1);
        index + tail >= count
    }

    /// Take a lease learned from the failover peer. False when someone else holds the address.
    pub fn adopt(&mut self, lease: Lease6, now: u64) -> bool {
        let taken = self
            .leases
            .get(&lease.ip)
            .is_some_and(|held| held.expires > now && held.client != lease.client);
        if lease.offered || lease.expires <= now || !self.scope.prefix.contains(&lease.ip) || taken
        {
            return false;
        }
        self.leases.insert(lease.ip, lease);
        true
    }

    /// Take a delegation learned from the failover peer.
    pub fn adopt_prefix(&mut self, item: Delegation6, now: u64) -> bool {
        let Some(delegation) = &self.scope.delegation else {
            return false;
        };
        let taken = self
            .delegated
            .get(&item.prefix)
            .is_some_and(|held| held.expires > now && held.client != item.client);
        if item.offered
            || item.expires <= now
            || item.prefix.prefix_len() != delegation.length
            || !delegation.pool.contains(&item.prefix.network())
            || taken
        {
            return false;
        }
        self.delegated.insert(item.prefix, item);
        true
    }

    /// Forget a lease the failover peer ended.
    pub fn forget(&mut self, ip: Ipv6Addr) {
        if self.leases.get(&ip).is_some_and(|lease| !lease.offered) {
            self.leases.remove(&ip);
        }
    }

    /// Forget a delegation the failover peer ended.
    pub fn forget_prefix(&mut self, prefix: Ipv6Net) {
        if self
            .delegated
            .get(&prefix)
            .is_some_and(|item| !item.offered)
        {
            self.delegated.remove(&prefix);
        }
    }

    #[must_use]
    pub fn scope(&self) -> &DhcpScope6 {
        &self.scope
    }

    /// Bound leases, for tests and status.
    #[must_use]
    pub fn bound(&self) -> Vec<Lease6> {
        let mut out: Vec<Lease6> = self
            .leases
            .values()
            .filter(|lease| !lease.offered)
            .cloned()
            .collect();
        out.sort_by_key(|lease| lease.ip);
        out
    }

    /// Drop everything that has run out. Returns the addresses whose leases ended.
    pub fn expire(&mut self, now: u64) -> Vec<Ipv6Addr> {
        let mut ended = Vec::new();
        self.leases.retain(|ip, lease| {
            let alive = lease.expires > now;
            if !alive && !lease.offered {
                ended.push(*ip);
            }
            alive
        });
        self.declined.retain(|_, until| *until > now);
        ended
    }

    fn range(&self) -> (u128, u128) {
        (
            u128::from(self.scope.range_start),
            u128::from(self.scope.range_end),
        )
    }

    fn usable(&self, ip: Ipv6Addr, client: &[u8], now: u64) -> bool {
        if !self.scope.prefix.contains(&ip) || !self.window_ok(ip, client, now) {
            return false;
        }
        if self
            .leases
            .get(&ip)
            .is_some_and(|lease| lease.expires > now && lease.client != client)
        {
            return false;
        }
        if self.declined.get(&ip).is_some_and(|until| *until > now) {
            return false;
        }
        if let Some(owner) = self.reserved.get(&ip) {
            return owner == client;
        }
        let (start, end) = self.range();
        !self.reservations.contains_key(client) && (start..=end).contains(&u128::from(ip))
    }

    fn pick(
        &self,
        client: &[u8],
        iaid: u32,
        wanted: Option<Ipv6Addr>,
        now: u64,
    ) -> Option<Ipv6Addr> {
        if let Some((ip, _)) = self.reservations.get(client) {
            return self.usable(*ip, client, now).then_some(*ip);
        }
        if let Some(lease) = self
            .leases
            .values()
            .find(|lease| lease.client == client && lease.iaid == iaid && lease.expires > now)
            && self.usable(lease.ip, client, now)
        {
            return Some(lease.ip);
        }
        if let Some(ip) = wanted
            && self.usable(ip, client, now)
        {
            return Some(ip);
        }
        let (start, end) = self.range();
        let size = end - start + 1;
        let first = start_offset(client, iaid, size);
        // The range is bounded by validation, so this walk is too.
        for step in 0..size {
            let candidate = Ipv6Addr::from(start + (first + step) % size);
            if self.usable(candidate, client, now) {
                return Some(candidate);
            }
        }
        None
    }

    fn timers(&self) -> (u32, u32) {
        let preferred = self.scope.preferred_secs;
        (preferred / 2, preferred / 10 * 8)
    }

    fn answer(&self, kind: MessageType, request: &Message, client: &[u8]) -> Message {
        let mut reply = Message::new_with_id(kind, request.xid());
        let options = reply.opts_mut();
        if !client.is_empty() {
            options.insert(DhcpOption::ClientId(client.to_vec()));
        }
        options.insert(DhcpOption::ServerId(self.server_id.clone()));
        options.insert(DhcpOption::DomainNameServers(self.scope.dns.clone()));
        reply
    }

    fn ia(
        &self,
        iaid: u32,
        address: Option<(Ipv6Addr, u32, u32)>,
        failure: Option<Status>,
    ) -> DhcpOption {
        let (t1, t2) = self.timers();
        let mut ia = IANA {
            id: iaid,
            t1,
            t2,
            opts: dhcproto::v6::DhcpOptions::new(),
        };
        if let Some((addr, preferred, valid)) = address {
            ia.opts.insert(DhcpOption::IAAddr(IAAddr {
                addr,
                preferred_life: preferred,
                valid_life: valid,
                opts: dhcproto::v6::DhcpOptions::new(),
            }));
        }
        if let Some(code) = failure {
            ia.t1 = 0;
            ia.t2 = 0;
            ia.opts.insert(status(
                code,
                match code {
                    Status::NoAddrsAvail => "no addresses available",
                    Status::NoBinding => "no binding",
                    _ => "failed",
                },
            ));
        }
        DhcpOption::IANA(ia)
    }

    fn bind(
        &mut self,
        ip: Ipv6Addr,
        client: &[u8],
        iaid: u32,
        name: Option<String>,
        now: u64,
    ) -> Lease6 {
        let hostname = self
            .reservations
            .get(client)
            .and_then(|(_, name)| name.clone())
            .or(name);
        let lease = Lease6 {
            ip,
            client: client.to_vec(),
            iaid,
            hostname,
            expires: now + u64::from(self.scope.valid_secs),
            offered: false,
        };
        self.leases.insert(ip, lease.clone());
        lease
    }

    fn hold(&mut self, ip: Ipv6Addr, client: &[u8], iaid: u32, now: u64) {
        // Do not overwrite a bound lease of this client with a shorter hold.
        if self
            .leases
            .get(&ip)
            .is_some_and(|lease| !lease.offered && lease.client == client)
        {
            return;
        }
        self.leases.insert(
            ip,
            Lease6 {
                ip,
                client: client.to_vec(),
                iaid,
                hostname: None,
                expires: now + OFFER_HOLD_SECS,
                offered: true,
            },
        );
    }

    /// The `IA_NA` options of a message, as (iaid, addresses the client names).
    fn requested(request: &Message) -> Vec<(u32, Vec<Ipv6Addr>)> {
        request
            .opts()
            .iter()
            .filter_map(|option| match option {
                DhcpOption::IANA(ia) => Some((
                    ia.id,
                    ia.opts
                        .iter()
                        .filter_map(|inner| match inner {
                            DhcpOption::IAAddr(address) => Some(address.addr),
                            _ => None,
                        })
                        .collect(),
                )),
                _ => None,
            })
            .collect()
    }

    /// The `IA_PD` options of a message: (iaid, prefixes the client names).
    fn requested_prefixes(request: &Message) -> Vec<(u32, Vec<Ipv6Net>)> {
        request
            .opts()
            .iter()
            .filter_map(|option| match option {
                DhcpOption::IAPD(ia) => Some((
                    ia.id,
                    ia.opts
                        .iter()
                        .filter_map(|inner| match inner {
                            DhcpOption::IAPrefix(prefix) => {
                                Ipv6Net::new(prefix.prefix_ip, prefix.prefix_len).ok()
                            }
                            _ => None,
                        })
                        .collect(),
                )),
                _ => None,
            })
            .collect()
    }

    fn has_prefix_request(request: &Message) -> bool {
        request
            .opts()
            .iter()
            .any(|option| matches!(option, DhcpOption::IAPD(_)))
    }

    fn prefix_usable(&self, prefix: Ipv6Net, client: &[u8], now: u64) -> bool {
        let Some(delegation) = &self.scope.delegation else {
            return false;
        };
        if prefix.prefix_len() != delegation.length
            || prefix != prefix.trunc()
            || !delegation.pool.contains(&prefix.network())
        {
            return false;
        }
        if !self.prefix_window_ok(prefix, client, now)
            || self
                .delegated
                .get(&prefix)
                .is_some_and(|item| item.expires > now && item.client != client)
        {
            return false;
        }
        match self.prefix_owner.get(&prefix) {
            Some(owner) => owner == client,
            None => !self.prefix_reserved.contains_key(client),
        }
    }

    fn pick_prefix(
        &self,
        client: &[u8],
        iaid: u32,
        wanted: Option<Ipv6Net>,
        now: u64,
    ) -> Option<Ipv6Net> {
        let delegation = self.scope.delegation.as_ref()?;
        if let Some(prefix) = self.prefix_reserved.get(client) {
            return self.prefix_usable(*prefix, client, now).then_some(*prefix);
        }
        if let Some(item) = self
            .delegated
            .values()
            .find(|item| item.client == client && item.iaid == iaid && item.expires > now)
            && self.prefix_usable(item.prefix, client, now)
        {
            return Some(item.prefix);
        }
        if let Some(prefix) = wanted
            && self.prefix_usable(prefix, client, now)
        {
            return Some(prefix);
        }
        let shift = 128 - u32::from(delegation.length);
        let count = 1u128 << (delegation.length - delegation.pool.prefix_len());
        let base = u128::from(delegation.pool.network());
        let first = start_offset(client, iaid, count);
        for step in 0..count {
            let network = Ipv6Addr::from(base + (((first + step) % count) << shift));
            let candidate = Ipv6Net::new(network, delegation.length).ok()?;
            if self.prefix_usable(candidate, client, now) {
                return Some(candidate);
            }
        }
        None
    }

    fn prefix_option(
        &self,
        iaid: u32,
        grant: Option<Ipv6Net>,
        failure: Option<Status>,
    ) -> DhcpOption {
        let (t1, t2) = self.timers();
        let mut ia = IAPD {
            id: iaid,
            t1,
            t2,
            opts: DhcpOptions::new(),
        };
        if let Some(prefix) = grant {
            ia.opts.insert(DhcpOption::IAPrefix(IAPrefix {
                preferred_lifetime: self.scope.preferred_secs,
                valid_lifetime: self.scope.valid_secs,
                prefix_len: prefix.prefix_len(),
                prefix_ip: prefix.network(),
                opts: DhcpOptions::new(),
            }));
        }
        if let Some(code) = failure {
            ia.t1 = 0;
            ia.t2 = 0;
            ia.opts.insert(status(
                code,
                if code == Status::NoBinding {
                    "no binding"
                } else {
                    "no prefixes available"
                },
            ));
        }
        DhcpOption::IAPD(ia)
    }

    /// Answer the `IA_PD` parts of a message, if it has any.
    #[allow(clippy::too_many_arguments)]
    fn prefixes(
        &mut self,
        kind: MessageType,
        request: &Message,
        client: &[u8],
        rapid: bool,
        now: u64,
        reply: &mut Message,
        changes: &mut Vec<Change6>,
    ) -> Prefixes {
        let asked = Self::requested_prefixes(request);
        let mut outcome = Prefixes::default();
        for (iaid, wanted) in asked {
            if kind == MessageType::Release {
                for prefix in wanted {
                    let held = self
                        .delegated
                        .get(&prefix)
                        .is_some_and(|item| item.client == client && item.iaid == iaid);
                    if held {
                        self.delegated.remove(&prefix);
                        changes.push(Change6::EndPrefix(prefix));
                    }
                }
                continue;
            }
            let renewing = matches!(kind, MessageType::Renew | MessageType::Rebind);
            let target = if renewing {
                wanted.iter().copied().find(|prefix| {
                    self.delegated.get(prefix).is_some_and(|item| {
                        item.client == client && item.iaid == iaid && item.expires > now
                    })
                })
            } else {
                self.pick_prefix(client, iaid, wanted.first().copied(), now)
            };
            let Some(prefix) = target else {
                let code = if renewing {
                    Status::NoBinding
                } else {
                    Status::NoPrefixAvail
                };
                reply
                    .opts_mut()
                    .insert(self.prefix_option(iaid, None, Some(code)));
                continue;
            };
            outcome.granted = true;
            let binding = !matches!(kind, MessageType::Solicit) || rapid;
            let valid = u64::from(self.scope.valid_secs);
            let item = Delegation6 {
                prefix,
                client: client.to_vec(),
                iaid,
                expires: now + if binding { valid } else { OFFER_HOLD_SECS },
                offered: !binding,
            };
            self.delegated.insert(prefix, item.clone());
            if binding {
                changes.push(Change6::BindPrefix(item));
            }
            reply
                .opts_mut()
                .insert(self.prefix_option(iaid, Some(prefix), None));
        }
        outcome
    }

    /// Decide what to answer. `None` means stay silent.
    #[allow(clippy::too_many_lines)]
    pub fn handle(&mut self, request: &Message, now: u64) -> Option<Reply6> {
        let kind = request.msg_type();
        let client = match request.opts().get(OptionCode::ClientId) {
            Some(DhcpOption::ClientId(id)) if !id.is_empty() && id.len() <= 130 => id.clone(),
            // Only a request for configuration may come without an identity.
            None if kind == MessageType::InformationRequest => Vec::new(),
            _ => return None,
        };
        let server = match request.opts().get(OptionCode::ServerId) {
            Some(DhcpOption::ServerId(id)) => Some(id.clone()),
            _ => None,
        };
        // Messages that name a server are for that server alone; the others must not name one.
        let for_us = server.as_ref().is_none_or(|id| *id == self.server_id);
        match kind {
            MessageType::Solicit | MessageType::Confirm | MessageType::Rebind => {
                if server.is_some() {
                    return None;
                }
            }
            MessageType::Request
            | MessageType::Renew
            | MessageType::Release
            | MessageType::Decline => {
                if server.is_none() || !for_us {
                    return None;
                }
            }
            MessageType::InformationRequest => {
                if !for_us {
                    return None;
                }
            }
            _ => return None,
        }
        let name = client_name(request);
        let asked = Self::requested(request);
        let (preferred, valid) = (self.scope.preferred_secs, self.scope.valid_secs);
        let mut changes = Vec::new();

        match kind {
            MessageType::Solicit => {
                if asked.is_empty() && !Self::has_prefix_request(request) {
                    return None;
                }
                let rapid = request.opts().get(OptionCode::RapidCommit).is_some();
                let mut reply = self.answer(
                    if rapid {
                        MessageType::Reply
                    } else {
                        MessageType::Advertise
                    },
                    request,
                    &client,
                );
                let mut any = false;
                for (iaid, wanted) in asked {
                    match self.pick(&client, iaid, wanted.first().copied(), now) {
                        Some(ip) => {
                            any = true;
                            if rapid {
                                changes.push(Change6::Bind(self.bind(
                                    ip,
                                    &client,
                                    iaid,
                                    name.clone(),
                                    now,
                                )));
                            } else {
                                self.hold(ip, &client, iaid, now);
                            }
                            reply.opts_mut().insert(self.ia(
                                iaid,
                                Some((ip, preferred, valid)),
                                None,
                            ));
                        }
                        None => {
                            reply.opts_mut().insert(self.ia(
                                iaid,
                                None,
                                Some(Status::NoAddrsAvail),
                            ));
                        }
                    }
                }
                let pd =
                    self.prefixes(kind, request, &client, rapid, now, &mut reply, &mut changes);
                any |= pd.granted;
                if rapid && any {
                    reply.opts_mut().insert(DhcpOption::RapidCommit);
                }
                if !any {
                    reply
                        .opts_mut()
                        .insert(status(Status::NoAddrsAvail, "no addresses available"));
                }
                Some(Reply6 {
                    message: reply,
                    changes,
                })
            }
            MessageType::Request | MessageType::Renew | MessageType::Rebind => {
                let mut reply = self.answer(MessageType::Reply, request, &client);
                let mut granted = false;
                for (iaid, wanted) in asked {
                    let renewing = kind != MessageType::Request;
                    let target = if renewing {
                        // Only an address this client already holds can be extended.
                        wanted.iter().copied().find(|ip| {
                            self.leases.get(ip).is_some_and(|lease| {
                                lease.client == client && lease.iaid == iaid && lease.expires > now
                            })
                        })
                    } else {
                        self.pick(&client, iaid, wanted.first().copied(), now)
                    };
                    match target {
                        Some(ip) => {
                            granted = true;
                            changes.push(Change6::Bind(self.bind(
                                ip,
                                &client,
                                iaid,
                                name.clone(),
                                now,
                            )));
                            reply.opts_mut().insert(self.ia(
                                iaid,
                                Some((ip, preferred, valid)),
                                None,
                            ));
                        }
                        None if renewing => {
                            reply
                                .opts_mut()
                                .insert(self.ia(iaid, None, Some(Status::NoBinding)));
                        }
                        None => {
                            reply.opts_mut().insert(self.ia(
                                iaid,
                                None,
                                Some(Status::NoAddrsAvail),
                            ));
                        }
                    }
                }
                let pd =
                    self.prefixes(kind, request, &client, false, now, &mut reply, &mut changes);
                granted |= pd.granted;
                // A rebind to a server that knows nothing about the client gets no answer, so
                // another server can take it.
                if kind == MessageType::Rebind && !granted {
                    return None;
                }
                Some(Reply6 {
                    message: reply,
                    changes,
                })
            }
            MessageType::Confirm => {
                let addresses: Vec<Ipv6Addr> =
                    asked.into_iter().flat_map(|(_, list)| list).collect();
                if addresses.is_empty() {
                    return None;
                }
                let on_link = addresses.iter().all(|ip| self.scope.prefix.contains(ip));
                let mut reply = self.answer(MessageType::Reply, request, &client);
                reply.opts_mut().insert(if on_link {
                    status(Status::Success, "on link")
                } else {
                    status(Status::NotOnLink, "not on link")
                });
                Some(Reply6 {
                    message: reply,
                    changes,
                })
            }
            MessageType::Release | MessageType::Decline => {
                let decline = kind == MessageType::Decline;
                for (iaid, addresses) in asked {
                    for ip in addresses {
                        let held = self
                            .leases
                            .get(&ip)
                            .is_some_and(|lease| lease.client == client && lease.iaid == iaid);
                        if held {
                            self.leases.remove(&ip);
                            if decline {
                                self.declined.insert(ip, now + DECLINE_QUARANTINE_SECS);
                            }
                            changes.push(Change6::End(ip));
                        }
                    }
                }
                let mut reply = self.answer(MessageType::Reply, request, &client);
                self.prefixes(kind, request, &client, false, now, &mut reply, &mut changes);
                reply.opts_mut().insert(status(Status::Success, "released"));
                Some(Reply6 {
                    message: reply,
                    changes,
                })
            }
            MessageType::InformationRequest => {
                let mut reply = self.answer(MessageType::Reply, request, &client);
                reply
                    .opts_mut()
                    .insert(DhcpOption::InformationRefreshTime(valid.max(600)));
                Some(Reply6 {
                    message: reply,
                    changes,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v6::DhcpOptions;

    fn scope() -> DhcpScope6 {
        DhcpScope6 {
            interface: Some("eth0".into()),
            prefix: "fd00:1::/64".parse().unwrap(),
            range_start: "fd00:1::100".parse().unwrap(),
            range_end: "fd00:1::1ff".parse().unwrap(),
            dns: vec!["fd00:1::1".parse().unwrap()],
            preferred_secs: 1000,
            valid_secs: 2000,
            delegation: None,
            reservations: Vec::new(),
        }
    }

    fn engine(scope: &DhcpScope6) -> Engine6 {
        Engine6::new(scope, vec![0, 3, 0, 1, 9, 9, 9, 9, 9, 9], Vec::new(), 0)
    }

    const SERVER: [u8; 10] = [0, 3, 0, 1, 9, 9, 9, 9, 9, 9];

    fn client(
        kind: MessageType,
        duid: u8,
        iaid: u32,
        with_server: bool,
        addr: Option<&str>,
    ) -> Message {
        let mut message = Message::new_with_id(kind, [1, 2, 3]);
        let options = message.opts_mut();
        options.insert(DhcpOption::ClientId(vec![0, 1, 0, 1, duid]));
        if with_server {
            options.insert(DhcpOption::ServerId(SERVER.to_vec()));
        }
        let mut ia = IANA {
            id: iaid,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        };
        if let Some(addr) = addr {
            ia.opts.insert(DhcpOption::IAAddr(IAAddr {
                addr: addr.parse().unwrap(),
                preferred_life: 0,
                valid_life: 0,
                opts: DhcpOptions::new(),
            }));
        }
        options.insert(DhcpOption::IANA(ia));
        message
    }

    fn granted(reply: &Reply6) -> Option<Ipv6Addr> {
        reply.message.opts().iter().find_map(|option| match option {
            DhcpOption::IANA(ia) => ia.opts.iter().find_map(|inner| match inner {
                DhcpOption::IAAddr(a) => Some(a.addr),
                _ => None,
            }),
            _ => None,
        })
    }

    fn solicit_and_request(engine: &mut Engine6, duid: u8, now: u64) -> Ipv6Addr {
        let advert = engine
            .handle(&client(MessageType::Solicit, duid, 1, false, None), now)
            .unwrap();
        assert_eq!(advert.message.msg_type(), MessageType::Advertise);
        let ip = granted(&advert).unwrap();
        let done = engine
            .handle(
                &client(MessageType::Request, duid, 1, true, Some(&ip.to_string())),
                now,
            )
            .unwrap();
        assert_eq!(done.message.msg_type(), MessageType::Reply);
        assert!(matches!(done.changes.as_slice(), [Change6::Bind(_)]));
        assert_eq!(granted(&done), Some(ip));
        ip
    }

    #[test]
    fn solicit_advertise_request_reply_grants_a_lease_with_dns() {
        let scope = scope();
        let mut engine = engine(&scope);
        let ip = solicit_and_request(&mut engine, 1, 100);
        assert!(scope.prefix.contains(&ip));
        assert_eq!(engine.bound().len(), 1);
        assert_eq!(engine.bound()[0].expires, 100 + 2000);
        let reply = engine
            .handle(&client(MessageType::Solicit, 1, 1, false, None), 101)
            .unwrap();
        assert!(matches!(
            reply.message.opts().get(OptionCode::DomainNameServers),
            Some(DhcpOption::DomainNameServers(list)) if list == &scope.dns
        ));
        // The same client is advertised the same address.
        assert_eq!(granted(&reply), Some(ip));
    }

    #[test]
    fn clients_get_different_addresses_and_foreign_servers_are_ignored() {
        let scope = scope();
        let mut engine = engine(&scope);
        let a = solicit_and_request(&mut engine, 1, 0);
        let b = solicit_and_request(&mut engine, 2, 0);
        assert_ne!(a, b);
        let mut stranger = client(MessageType::Request, 3, 1, true, Some(&a.to_string()));
        stranger
            .opts_mut()
            .insert(DhcpOption::ServerId(vec![7, 7, 7]));
        assert!(engine.handle(&stranger, 0).is_none());
        // A Solicit naming a server is malformed.
        assert!(
            engine
                .handle(&client(MessageType::Solicit, 4, 1, true, None), 0)
                .is_none()
        );
    }

    #[test]
    fn rapid_commit_binds_at_once() {
        let scope = scope();
        let mut engine = engine(&scope);
        let mut solicit = client(MessageType::Solicit, 1, 1, false, None);
        solicit.opts_mut().insert(DhcpOption::RapidCommit);
        let reply = engine.handle(&solicit, 0).unwrap();
        assert_eq!(reply.message.msg_type(), MessageType::Reply);
        assert!(reply.message.opts().get(OptionCode::RapidCommit).is_some());
        assert_eq!(engine.bound().len(), 1);
    }

    #[test]
    fn renew_extends_rebind_without_binding_is_silent_and_renew_says_no_binding() {
        let scope = scope();
        let mut engine = engine(&scope);
        let ip = solicit_and_request(&mut engine, 1, 0);
        let renewed = engine
            .handle(
                &client(MessageType::Renew, 1, 1, true, Some(&ip.to_string())),
                500,
            )
            .unwrap();
        assert_eq!(granted(&renewed), Some(ip));
        assert_eq!(engine.bound()[0].expires, 500 + 2000);
        // Another client cannot renew it.
        let theirs = engine
            .handle(
                &client(MessageType::Renew, 2, 1, true, Some(&ip.to_string())),
                500,
            )
            .unwrap();
        assert_eq!(granted(&theirs), None);
        // A rebind to a server that does not know the client gets no answer.
        assert!(
            engine
                .handle(
                    &client(MessageType::Rebind, 2, 1, false, Some(&ip.to_string())),
                    500
                )
                .is_none()
        );
        let rebound = engine
            .handle(
                &client(MessageType::Rebind, 1, 1, false, Some(&ip.to_string())),
                600,
            )
            .unwrap();
        assert_eq!(granted(&rebound), Some(ip));
    }

    #[test]
    fn confirm_checks_the_link_release_frees_and_decline_rests() {
        let scope = scope();
        let mut engine = engine(&scope);
        let ip = solicit_and_request(&mut engine, 1, 0);
        let on = engine
            .handle(
                &client(MessageType::Confirm, 1, 1, false, Some(&ip.to_string())),
                1,
            )
            .unwrap();
        assert!(matches!(
            on.message.opts().get(OptionCode::StatusCode),
            Some(DhcpOption::StatusCode(code)) if code.status == Status::Success
        ));
        let off = engine
            .handle(
                &client(MessageType::Confirm, 1, 1, false, Some("fd00:9::5")),
                1,
            )
            .unwrap();
        assert!(matches!(
            off.message.opts().get(OptionCode::StatusCode),
            Some(DhcpOption::StatusCode(code)) if code.status == Status::NotOnLink
        ));
        let done = engine
            .handle(
                &client(MessageType::Release, 1, 1, true, Some(&ip.to_string())),
                2,
            )
            .unwrap();
        assert_eq!(done.changes, vec![Change6::End(ip)]);
        assert!(engine.bound().is_empty());
        let again = solicit_and_request(&mut engine, 5, 3);
        let declined = engine
            .handle(
                &client(MessageType::Decline, 5, 1, true, Some(&again.to_string())),
                4,
            )
            .unwrap();
        assert_eq!(declined.changes, vec![Change6::End(again)]);
        let fresh = solicit_and_request(&mut engine, 5, 5);
        assert_ne!(fresh, again);
    }

    #[test]
    fn reservations_are_exclusive_and_information_request_needs_no_identity() {
        let mut scope = scope();
        scope.reservations.push(lumen_config::Reservation6 {
            duid: "0001000109".into(),
            ip: "fd00:1::2a".parse().unwrap(),
            hostname: Some("Printer".into()),
        });
        let mut engine = engine(&scope);
        let ip = solicit_and_request(&mut engine, 9, 0);
        assert_eq!(ip.to_string(), "fd00:1::2a");
        assert_eq!(engine.bound()[0].hostname.as_deref(), Some("printer"));
        // Nobody else is given the reserved address, even when asking for it.
        let other = engine
            .handle(
                &client(MessageType::Request, 2, 1, true, Some("fd00:1::2a")),
                0,
            )
            .unwrap();
        assert_ne!(granted(&other), Some(ip));
        let mut info = Message::new_with_id(MessageType::InformationRequest, [4, 5, 6]);
        info.opts_mut().insert(DhcpOption::ORO(dhcproto::v6::ORO {
            opts: vec![OptionCode::DomainNameServers],
        }));
        let reply = engine.handle(&info, 0).unwrap();
        assert!(reply.changes.is_empty());
        assert!(reply.message.opts().get(OptionCode::ClientId).is_none());
        assert!(
            reply
                .message
                .opts()
                .get(OptionCode::DomainNameServers)
                .is_some()
        );
    }

    #[test]
    fn a_full_range_answers_no_addresses_and_leases_expire() {
        let mut scope = scope();
        scope.range_end = scope.range_start;
        let mut engine = engine(&scope);
        solicit_and_request(&mut engine, 1, 0);
        let full = engine
            .handle(&client(MessageType::Solicit, 2, 1, false, None), 1)
            .unwrap();
        assert_eq!(granted(&full), None);
        assert_eq!(
            engine.expire(2001),
            vec!["fd00:1::100".parse::<Ipv6Addr>().unwrap()]
        );
        assert!(engine.bound().is_empty());
    }

    #[test]
    fn the_client_name_comes_from_the_fqdn_option() {
        let scope = scope();
        let mut engine = engine(&scope);
        let mut solicit = client(MessageType::Solicit, 1, 1, false, None);
        // Flags 0, then "Laptop.lan." in wire form.
        let mut data = vec![0u8, 6];
        data.extend_from_slice(b"Laptop");
        data.extend_from_slice(&[3, b'l', b'a', b'n', 0]);
        solicit
            .opts_mut()
            .insert(DhcpOption::Unknown(dhcproto::v6::UnknownOption::new(
                OptionCode::from(39u16),
                data,
            )));
        solicit.opts_mut().insert(DhcpOption::RapidCommit);
        engine.handle(&solicit, 0).unwrap();
        assert_eq!(engine.bound()[0].hostname.as_deref(), Some("laptop"));
    }

    fn pd_scope() -> DhcpScope6 {
        let mut scope = scope();
        scope.delegation = Some(lumen_config::PrefixDelegation {
            pool: "2001:db8:100::/40".parse().unwrap(),
            length: 56,
            reservations: vec![lumen_config::PrefixReservation {
                duid: "0001000109".into(),
                prefix: "2001:db8:100:4200::/56".parse().unwrap(),
            }],
        });
        scope
    }

    fn pd_message(kind: MessageType, duid: u8, prefix: Option<&str>, with_server: bool) -> Message {
        let mut message = Message::new_with_id(kind, [3, 3, 3]);
        let options = message.opts_mut();
        options.insert(DhcpOption::ClientId(vec![0, 1, 0, 1, duid]));
        if with_server {
            options.insert(DhcpOption::ServerId(SERVER.to_vec()));
        }
        let mut ia = IAPD {
            id: 7,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        };
        if let Some(prefix) = prefix {
            let net: Ipv6Net = prefix.parse().unwrap();
            ia.opts.insert(DhcpOption::IAPrefix(IAPrefix {
                preferred_lifetime: 0,
                valid_lifetime: 0,
                prefix_len: net.prefix_len(),
                prefix_ip: net.network(),
                opts: DhcpOptions::new(),
            }));
        }
        options.insert(DhcpOption::IAPD(ia));
        message
    }

    fn granted_prefix(reply: &Reply6) -> Option<Ipv6Net> {
        reply.message.opts().iter().find_map(|option| match option {
            DhcpOption::IAPD(ia) => ia.opts.iter().find_map(|inner| match inner {
                DhcpOption::IAPrefix(p) => Ipv6Net::new(p.prefix_ip, p.prefix_len).ok(),
                _ => None,
            }),
            _ => None,
        })
    }

    #[test]
    fn a_router_gets_a_delegated_prefix_and_keeps_it_until_released() {
        let scope = pd_scope();
        let mut engine = Engine6::new(&scope, SERVER.to_vec(), Vec::new(), 0);
        let advert = engine
            .handle(&pd_message(MessageType::Solicit, 1, None, false), 10)
            .unwrap();
        assert_eq!(advert.message.msg_type(), MessageType::Advertise);
        let prefix = granted_prefix(&advert).unwrap();
        assert_eq!(prefix.prefix_len(), 56);
        assert!(
            scope
                .delegation
                .as_ref()
                .unwrap()
                .pool
                .contains(&prefix.network())
        );
        assert!(
            engine.bound_prefixes().is_empty(),
            "an advertisement is not a lease"
        );

        let done = engine
            .handle(
                &pd_message(MessageType::Request, 1, Some(&prefix.to_string()), true),
                10,
            )
            .unwrap();
        assert_eq!(granted_prefix(&done), Some(prefix));
        assert!(matches!(done.changes.as_slice(), [Change6::BindPrefix(_)]));
        assert_eq!(engine.bound_prefixes()[0].expires, 10 + 2000);

        // Renewal extends; another router cannot take it over.
        let renewed = engine
            .handle(
                &pd_message(MessageType::Renew, 1, Some(&prefix.to_string()), true),
                500,
            )
            .unwrap();
        assert_eq!(granted_prefix(&renewed), Some(prefix));
        let theirs = engine
            .handle(
                &pd_message(MessageType::Renew, 2, Some(&prefix.to_string()), true),
                500,
            )
            .unwrap();
        assert_eq!(granted_prefix(&theirs), None);
        let other = engine
            .handle(&pd_message(MessageType::Solicit, 2, None, false), 500)
            .unwrap();
        assert_ne!(granted_prefix(&other), Some(prefix));

        let released = engine
            .handle(
                &pd_message(MessageType::Release, 1, Some(&prefix.to_string()), true),
                600,
            )
            .unwrap();
        assert_eq!(released.changes, vec![Change6::EndPrefix(prefix)]);
        assert!(engine.bound_prefixes().is_empty());
    }

    #[test]
    fn a_reserved_prefix_goes_only_to_its_router_and_a_scope_without_a_pool_refuses() {
        let scope = pd_scope();
        let mut engine = Engine6::new(&scope, SERVER.to_vec(), Vec::new(), 0);
        let mine = engine
            .handle(&pd_message(MessageType::Solicit, 9, None, false), 0)
            .unwrap();
        assert_eq!(
            granted_prefix(&mine).unwrap().to_string(),
            "2001:db8:100:4200::/56"
        );
        let ask = pd_message(
            MessageType::Solicit,
            3,
            Some("2001:db8:100:4200::/56"),
            false,
        );
        let other = engine.handle(&ask, 0).unwrap();
        assert_ne!(
            granted_prefix(&other).unwrap().to_string(),
            "2001:db8:100:4200::/56"
        );

        let mut plain = Engine6::new(&super::tests::scope(), SERVER.to_vec(), Vec::new(), 0);
        let none = plain
            .handle(&pd_message(MessageType::Solicit, 1, None, false), 0)
            .unwrap();
        assert_eq!(granted_prefix(&none), None);
    }

    #[test]
    fn expired_prefixes_are_reported_and_restored_ones_kept() {
        let scope = pd_scope();
        let mut engine = Engine6::new(&scope, SERVER.to_vec(), Vec::new(), 0);
        engine.restore_prefixes(
            vec![Delegation6 {
                prefix: "2001:db8:100:100::/56".parse().unwrap(),
                client: vec![5],
                iaid: 1,
                expires: 1000,
                offered: false,
            }],
            10,
        );
        assert_eq!(engine.bound_prefixes().len(), 1);
        assert_eq!(engine.expire_prefixes(1000).len(), 1);
        assert!(engine.bound_prefixes().is_empty());
    }

    #[test]
    fn a_standby_gives_new_leases_only_from_the_end_of_the_range() {
        let scope = scope();
        let mut engine = Engine6::new(&scope, SERVER.to_vec(), Vec::new(), 0);
        let before = solicit_and_request(&mut engine, 1, 0);
        engine.set_reserve(Some(10));
        let fresh = solicit_and_request(&mut engine, 2, 1);
        // 256 addresses, the last 10 percent: 25 of them.
        assert!(u128::from(fresh) > u128::from(scope.range_end) - 25);
        // A client that already had an address keeps it.
        let again = engine
            .handle(&client(MessageType::Solicit, 1, 1, false, None), 2)
            .unwrap();
        assert_eq!(granted(&again), Some(before));
        // An address outside the end of the range is refused to a client that did not hold it.
        let grab = engine
            .handle(
                &client(MessageType::Request, 3, 1, true, Some("fd00:1::150")),
                3,
            )
            .unwrap();
        assert_ne!(granted(&grab), Some("fd00:1::150".parse().unwrap()));
    }

    #[test]
    fn leases_from_the_partner_are_adopted_unless_someone_else_holds_the_address() {
        let scope = scope();
        let mut engine = Engine6::new(&scope, SERVER.to_vec(), Vec::new(), 0);
        let lease = Lease6 {
            ip: "fd00:1::150".parse().unwrap(),
            client: vec![1],
            iaid: 1,
            hostname: None,
            expires: 500,
            offered: false,
        };
        assert!(engine.adopt(lease.clone(), 0));
        let mut other = lease.clone();
        other.client = vec![2];
        assert!(!engine.adopt(other, 0));
        let mut foreign = lease.clone();
        foreign.ip = "fd00:9::1".parse().unwrap();
        assert!(!engine.adopt(foreign, 0));
        engine.forget(lease.ip);
        assert!(engine.bound().is_empty());
    }
}

//! `DHCPv4` (RFC 2131) decisions for one scope.

use dhcproto::v4::{DhcpOption, HType, Message, MessageType, Opcode, OptionCode};
use lumen_config::{DhcpScope, parse_mac};
use std::{collections::HashMap, net::Ipv4Addr};

/// How long an offered address is held for the client that was offered it.
pub const OFFER_HOLD_SECS: u64 = 60;
/// How long a declined address stays out of use (the client found it already taken).
pub const DECLINE_QUARANTINE_SECS: u64 = 600;

/// A lease or an offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Lease {
    pub ip: Ipv4Addr,
    /// The client identifier option, or the hardware address when the client sends none.
    pub client: Vec<u8>,
    pub hostname: Option<String>,
    /// Unix seconds.
    pub expires: u64,
    /// An offer is held briefly and is neither stored nor published.
    pub offered: bool,
}

/// What a reply changes besides being sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    /// A lease was granted or extended.
    Bind(Lease),
    /// A lease ended (release, decline).
    End(Ipv4Addr),
}

/// Where a reply goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination {
    /// To the local network's broadcast address.
    Broadcast,
    /// To a client that already has the address (renewal).
    Unicast(Ipv4Addr),
    /// Back through the relay agent.
    Relay(Ipv4Addr),
    /// Nothing goes on the wire (a release, a decline).
    Silent,
}

pub struct Reply {
    pub message: Message,
    pub destination: Destination,
    pub change: Option<Change>,
}

/// One scope: its settings, leases, and allocation state.
pub struct Engine {
    scope: DhcpScope,
    domain: String,
    leases: HashMap<Ipv4Addr, Lease>,
    declined: HashMap<Ipv4Addr, u64>,
    reservations: HashMap<[u8; 6], (Ipv4Addr, Option<String>)>,
    reserved: HashMap<Ipv4Addr, [u8; 6]>,
    cursor: u32,
}

/// A host name made safe to publish: the first label, lowercase letters, digits and hyphens.
#[must_use]
pub fn host_label(raw: &str) -> Option<String> {
    let first = raw.split('.').next().unwrap_or_default();
    let label: String = first
        .chars()
        .filter_map(|c| {
            let c = c.to_ascii_lowercase();
            (c.is_ascii_alphanumeric() || c == '-').then_some(c)
        })
        .take(63)
        .collect();
    let label = label.trim_matches('-').to_owned();
    (!label.is_empty()).then_some(label)
}

impl Engine {
    /// `bound` are leases restored from storage. Expired ones are dropped.
    #[must_use]
    pub fn new(scope: &DhcpScope, domain: &str, bound: Vec<Lease>, now: u64) -> Self {
        let mut reservations = HashMap::new();
        let mut reserved = HashMap::new();
        for reservation in &scope.reservations {
            if let Some(mac) = parse_mac(&reservation.mac) {
                let name = reservation.hostname.as_deref().and_then(host_label);
                reservations.insert(mac, (reservation.ip, name));
                reserved.insert(reservation.ip, mac);
            }
        }
        let leases = bound
            .into_iter()
            .filter(|lease| lease.expires > now && scope.subnet.contains(&lease.ip))
            .map(|lease| (lease.ip, lease))
            .collect();
        Self {
            scope: scope.clone(),
            domain: domain.to_owned(),
            leases,
            declined: HashMap::new(),
            reservations,
            reserved,
            cursor: 0,
        }
    }

    #[must_use]
    pub fn scope(&self) -> &DhcpScope {
        &self.scope
    }

    /// Bound leases, for tests and status.
    #[must_use]
    pub fn bound(&self) -> Vec<Lease> {
        let mut out: Vec<Lease> = self
            .leases
            .values()
            .filter(|lease| !lease.offered)
            .cloned()
            .collect();
        out.sort_by_key(|lease| lease.ip);
        out
    }

    /// Drop everything that has run out. Returns the addresses whose leases ended, so their
    /// names can be withdrawn and their rows deleted.
    pub fn expire(&mut self, now: u64) -> Vec<Ipv4Addr> {
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

    fn range(&self) -> (u32, u32) {
        (
            u32::from(self.scope.range_start),
            u32::from(self.scope.range_end),
        )
    }

    fn in_range(&self, ip: Ipv4Addr) -> bool {
        let (start, end) = self.range();
        (start..=end).contains(&u32::from(ip))
    }

    /// True when `ip` is held by a live lease or offer of someone other than `client`.
    fn taken_by_other(&self, ip: Ipv4Addr, client: &[u8], now: u64) -> bool {
        self.leases
            .get(&ip)
            .is_some_and(|lease| lease.expires > now && lease.client != client)
    }

    /// The address a client may have right now, or `None` when there is none to give.
    fn usable(&self, ip: Ipv4Addr, client: &[u8], mac: Option<[u8; 6]>, now: u64) -> bool {
        if !self.scope.subnet.contains(&ip) || ip == self.scope.server_address {
            return false;
        }
        if self.taken_by_other(ip, client, now) {
            return false;
        }
        if self.declined.get(&ip).is_some_and(|until| *until > now) {
            return false;
        }
        match (self.reserved.get(&ip), mac) {
            // A reserved address belongs to its device and nobody else.
            (Some(owner), mac) => mac == Some(*owner),
            (None, mac) => {
                // A device with a reservation takes only that address.
                let has_other = mac.is_some_and(|mac| self.reservations.contains_key(&mac));
                !has_other && self.in_range(ip)
            }
        }
    }

    fn pick(
        &mut self,
        client: &[u8],
        mac: Option<[u8; 6]>,
        wanted: Option<Ipv4Addr>,
        now: u64,
    ) -> Option<Ipv4Addr> {
        if let Some((ip, _)) = mac.and_then(|mac| self.reservations.get(&mac)) {
            return self.usable(*ip, client, mac, now).then_some(*ip);
        }
        if let Some(lease) = self.leases.values().find(|lease| lease.client == client)
            && lease.expires > now
            && self.usable(lease.ip, client, mac, now)
        {
            return Some(lease.ip);
        }
        if let Some(ip) = wanted
            && self.usable(ip, client, mac, now)
        {
            return Some(ip);
        }
        let (start, end) = self.range();
        let size = end - start + 1;
        for step in 0..size {
            let candidate = Ipv4Addr::from(start + (self.cursor + step) % size);
            if self.usable(candidate, client, mac, now) {
                self.cursor = (self.cursor + step + 1) % size;
                return Some(candidate);
            }
        }
        None
    }

    fn hostname(&self, request: &Message, mac: Option<[u8; 6]>) -> Option<String> {
        if let Some((_, Some(name))) = mac.and_then(|mac| self.reservations.get(&mac)) {
            return Some(name.clone());
        }
        match request.opts().get(OptionCode::Hostname) {
            Some(DhcpOption::Hostname(name)) => host_label(name),
            _ => None,
        }
    }

    fn reply_message(
        &self,
        request: &Message,
        kind: MessageType,
        ip: Ipv4Addr,
        lease_secs: Option<u32>,
    ) -> Message {
        let mut reply = Message::new_with_id(
            request.xid(),
            Ipv4Addr::UNSPECIFIED,
            ip,
            self.scope.server_address,
            request.giaddr(),
            request.chaddr(),
        );
        reply.set_opcode(Opcode::BootReply);
        reply.set_htype(request.htype());
        reply.set_flags(request.flags());
        let options = reply.opts_mut();
        options.insert(DhcpOption::MessageType(kind));
        options.insert(DhcpOption::ServerIdentifier(self.scope.server_address));
        if kind == MessageType::Nak {
            return reply;
        }
        if let Some(seconds) = lease_secs {
            options.insert(DhcpOption::AddressLeaseTime(seconds));
            options.insert(DhcpOption::Renewal(seconds / 2));
            options.insert(DhcpOption::Rebinding(seconds / 8 * 7));
        }
        options.insert(DhcpOption::SubnetMask(self.scope.subnet.netmask()));
        options.insert(DhcpOption::BroadcastAddr(self.scope.subnet.broadcast()));
        if let Some(router) = self.scope.router {
            options.insert(DhcpOption::Router(vec![router]));
        }
        let dns = if self.scope.dns.is_empty() {
            vec![self.scope.server_address]
        } else {
            self.scope.dns.clone()
        };
        options.insert(DhcpOption::DomainNameServer(dns));
        options.insert(DhcpOption::DomainName(self.domain.clone()));
        reply
    }

    fn destination(request: &Message, kind: MessageType) -> Destination {
        if !request.giaddr().is_unspecified() {
            return Destination::Relay(request.giaddr());
        }
        if kind == MessageType::Ack && !request.ciaddr().is_unspecified() {
            return Destination::Unicast(request.ciaddr());
        }
        Destination::Broadcast
    }

    /// Decide what to answer. `None` means stay silent.
    #[allow(clippy::too_many_lines)]
    pub fn handle(&mut self, request: &Message, now: u64) -> Option<Reply> {
        if request.opcode() != Opcode::BootRequest || request.htype() != HType::Eth {
            return None;
        }
        let kind = match request.opts().get(OptionCode::MessageType) {
            Some(DhcpOption::MessageType(kind)) => *kind,
            _ => return None,
        };
        let chaddr = request.chaddr();
        let mac: Option<[u8; 6]> = (chaddr.len() == 6)
            .then(|| chaddr.try_into().ok())
            .flatten();
        let client: Vec<u8> = match request.opts().get(OptionCode::ClientIdentifier) {
            Some(DhcpOption::ClientIdentifier(id)) if !id.is_empty() && id.len() <= 128 => {
                id.clone()
            }
            _ => chaddr.to_vec(),
        };
        if client.is_empty() {
            return None;
        }
        let requested = match request.opts().get(OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
            _ => None,
        };
        let server_id = match request.opts().get(OptionCode::ServerIdentifier) {
            Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
            _ => None,
        };
        match kind {
            MessageType::Discover => {
                let ip = self.pick(&client, mac, requested, now)?;
                // A client that asks again keeps its bound lease; an offer must not shorten it.
                let bound = self
                    .leases
                    .get(&ip)
                    .is_some_and(|lease| !lease.offered && lease.client == client);
                if !bound {
                    self.leases.insert(
                        ip,
                        Lease {
                            ip,
                            client,
                            hostname: None,
                            expires: now + OFFER_HOLD_SECS,
                            offered: true,
                        },
                    );
                }
                let message = self.reply_message(
                    request,
                    MessageType::Offer,
                    ip,
                    Some(self.scope.lease_secs),
                );
                Some(Reply {
                    message,
                    destination: Self::destination(request, MessageType::Offer),
                    change: None,
                })
            }
            MessageType::Request => self.request(request, &client, mac, requested, server_id, now),
            MessageType::Release => {
                let ip = request.ciaddr();
                let ours = self
                    .leases
                    .get(&ip)
                    .is_some_and(|lease| lease.client == client && !lease.offered);
                if !ours {
                    return None;
                }
                self.leases.remove(&ip);
                // A release gets no answer on the wire; only the change matters.
                Some(Reply {
                    message: self.reply_message(request, MessageType::Ack, ip, None),
                    destination: Destination::Silent,
                    change: Some(Change::End(ip)),
                })
            }
            MessageType::Decline => {
                let ip = requested?;
                if server_id.is_some_and(|id| id != self.scope.server_address) {
                    return None;
                }
                let held = self
                    .leases
                    .get(&ip)
                    .is_some_and(|lease| lease.client == client);
                if !held {
                    return None;
                }
                self.leases.remove(&ip);
                self.declined.insert(ip, now + DECLINE_QUARANTINE_SECS);
                Some(Reply {
                    message: self.reply_message(request, MessageType::Ack, ip, None),
                    destination: Destination::Silent,
                    change: Some(Change::End(ip)),
                })
            }
            MessageType::Inform => {
                let ip = request.ciaddr();
                if ip.is_unspecified() || !self.scope.subnet.contains(&ip) {
                    return None;
                }
                let message =
                    self.reply_message(request, MessageType::Ack, Ipv4Addr::UNSPECIFIED, None);
                Some(Reply {
                    message,
                    destination: Self::destination(request, MessageType::Ack),
                    change: None,
                })
            }
            _ => None,
        }
    }

    fn request(
        &mut self,
        request: &Message,
        client: &[u8],
        mac: Option<[u8; 6]>,
        requested: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
        now: u64,
    ) -> Option<Reply> {
        // A request that names another server is a decline of our offer.
        if let Some(id) = server_id
            && id != self.scope.server_address
        {
            let asked = requested.unwrap_or(Ipv4Addr::UNSPECIFIED);
            if self
                .leases
                .get(&asked)
                .is_some_and(|lease| lease.offered && lease.client == client)
            {
                self.leases.remove(&asked);
            }
            return None;
        }
        let ip = if request.ciaddr().is_unspecified() {
            requested?
        } else {
            request.ciaddr()
        };
        let refuse = |this: &Self| {
            Some(Reply {
                message: this.reply_message(request, MessageType::Nak, Ipv4Addr::UNSPECIFIED, None),
                destination: if request.giaddr().is_unspecified() {
                    Destination::Broadcast
                } else {
                    Destination::Relay(request.giaddr())
                },
                change: None,
            })
        };
        // A client on a network we do not serve is left alone: another server may own it.
        if !self.scope.subnet.contains(&ip) && server_id.is_none() {
            return refuse(self);
        }
        if !self.usable(ip, client, mac, now) {
            return refuse(self);
        }
        let lease = Lease {
            ip,
            client: client.to_vec(),
            hostname: self.hostname(request, mac),
            expires: now + u64::from(self.scope.lease_secs),
            offered: false,
        };
        self.leases.insert(ip, lease.clone());
        let message =
            self.reply_message(request, MessageType::Ack, ip, Some(self.scope.lease_secs));
        Some(Reply {
            message,
            destination: Self::destination(request, MessageType::Ack),
            change: Some(Change::Bind(lease)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::Flags;

    fn scope() -> DhcpScope {
        DhcpScope {
            interface: None,
            subnet: "192.168.1.0/24".parse().unwrap(),
            server_address: "192.168.1.2".parse().unwrap(),
            range_start: "192.168.1.100".parse().unwrap(),
            range_end: "192.168.1.102".parse().unwrap(),
            router: Some("192.168.1.1".parse().unwrap()),
            dns: vec![],
            lease_secs: 3600,
            reservations: vec![lumen_config::Reservation4 {
                mac: "aa:bb:cc:00:00:99".into(),
                ip: "192.168.1.50".parse().unwrap(),
                hostname: Some("Printer".into()),
            }],
        }
    }

    fn client(mac: u8, kind: MessageType) -> Message {
        let mut message = Message::new_with_id(
            7,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &[0xaa, 0xbb, 0xcc, 0, 0, mac],
        );
        message.set_flags(Flags::default().set_broadcast());
        message.opts_mut().insert(DhcpOption::MessageType(kind));
        message
    }

    fn with(mut message: Message, option: DhcpOption) -> Message {
        message.opts_mut().insert(option);
        message
    }

    fn kind_of(reply: &Reply) -> MessageType {
        match reply.message.opts().get(OptionCode::MessageType) {
            Some(DhcpOption::MessageType(kind)) => *kind,
            other => panic!("no message type: {other:?}"),
        }
    }

    fn lease_through(engine: &mut Engine, mac: u8, now: u64) -> Ipv4Addr {
        let offer = engine
            .handle(&client(mac, MessageType::Discover), now)
            .unwrap();
        assert_eq!(kind_of(&offer), MessageType::Offer);
        let ip = offer.message.yiaddr();
        let request = with(
            with(
                client(mac, MessageType::Request),
                DhcpOption::RequestedIpAddress(ip),
            ),
            DhcpOption::ServerIdentifier("192.168.1.2".parse().unwrap()),
        );
        let ack = engine.handle(&request, now).unwrap();
        assert_eq!(kind_of(&ack), MessageType::Ack);
        assert!(matches!(ack.change, Some(Change::Bind(_))));
        ip
    }

    #[test]
    fn discover_offer_request_ack_grants_a_lease_with_the_scope_options() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 1000);
        let offer = engine
            .handle(&client(1, MessageType::Discover), 1000)
            .unwrap();
        assert_eq!(
            offer.message.yiaddr(),
            "192.168.1.100".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(offer.message.xid(), 7);
        assert_eq!(offer.destination, Destination::Broadcast);
        assert!(
            offer.change.is_none(),
            "an offer changes nothing that is stored"
        );
        let opts = offer.message.opts();
        assert!(
            matches!(opts.get(OptionCode::SubnetMask), Some(DhcpOption::SubnetMask(m)) if m.to_string() == "255.255.255.0")
        );
        assert!(
            matches!(opts.get(OptionCode::Router), Some(DhcpOption::Router(r)) if r[0].to_string() == "192.168.1.1")
        );
        assert!(
            matches!(opts.get(OptionCode::DomainNameServer), Some(DhcpOption::DomainNameServer(d)) if d[0].to_string() == "192.168.1.2"),
            "defaults to Lumen itself"
        );
        assert!(
            matches!(opts.get(OptionCode::DomainName), Some(DhcpOption::DomainName(d)) if d == "home.example")
        );
        assert!(matches!(
            opts.get(OptionCode::AddressLeaseTime),
            Some(DhcpOption::AddressLeaseTime(3600))
        ));
        let ip = lease_through(&mut engine, 1, 1000);
        assert_eq!(ip.to_string(), "192.168.1.100");
        assert_eq!(engine.bound().len(), 1);
    }

    #[test]
    fn a_client_keeps_its_address_and_others_get_different_ones() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        let a = lease_through(&mut engine, 1, 0);
        let b = lease_through(&mut engine, 2, 0);
        let c = lease_through(&mut engine, 3, 0);
        assert!(a != b && b != c && a != c);
        // The pool of three is now full.
        assert!(
            engine
                .handle(&client(4, MessageType::Discover), 0)
                .is_none()
        );
        // The same client asking again gets the same address, even with a different request.
        let again = engine
            .handle(&client(2, MessageType::Discover), 10)
            .unwrap();
        assert_eq!(again.message.yiaddr(), b);
    }

    #[test]
    fn leases_expire_and_the_address_is_reused() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        let a = lease_through(&mut engine, 1, 0);
        lease_through(&mut engine, 2, 0);
        lease_through(&mut engine, 3, 0);
        let ended = engine.expire(3601);
        assert_eq!(ended.len(), 3);
        assert!(engine.bound().is_empty());
        let reused = lease_through(&mut engine, 9, 3601);
        assert!(ended.contains(&reused));
        assert!(ended.contains(&a));
    }

    #[test]
    fn reservations_are_exclusive_and_carry_their_host_name() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        // The reserved device gets its address, never one from the pool.
        let discover = client(0x99, MessageType::Discover);
        let offer = engine.handle(&discover, 0).unwrap();
        assert_eq!(offer.message.yiaddr().to_string(), "192.168.1.50");
        let request = with(
            with(
                client(0x99, MessageType::Request),
                DhcpOption::RequestedIpAddress("192.168.1.50".parse().unwrap()),
            ),
            DhcpOption::Hostname("whatever.local".into()),
        );
        let ack = engine.handle(&request, 0).unwrap();
        match ack.change {
            Some(Change::Bind(lease)) => assert_eq!(lease.hostname.as_deref(), Some("printer")),
            other => panic!("expected a bind, got {other:?}"),
        }
        // Nobody else may take the reserved address, even by asking for it.
        let ask = with(
            client(5, MessageType::Discover),
            DhcpOption::RequestedIpAddress("192.168.1.50".parse().unwrap()),
        );
        assert_ne!(
            engine.handle(&ask, 0).unwrap().message.yiaddr().to_string(),
            "192.168.1.50"
        );
        let steal = with(
            client(5, MessageType::Request),
            DhcpOption::RequestedIpAddress("192.168.1.50".parse().unwrap()),
        );
        assert_eq!(
            kind_of(&engine.handle(&steal, 0).unwrap()),
            MessageType::Nak
        );
    }

    #[test]
    fn a_bad_request_is_refused_and_a_foreign_server_is_ignored() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        let outside = with(
            client(1, MessageType::Request),
            DhcpOption::RequestedIpAddress("10.9.9.9".parse().unwrap()),
        );
        assert_eq!(
            kind_of(&engine.handle(&outside, 0).unwrap()),
            MessageType::Nak
        );
        let out_of_range = with(
            client(1, MessageType::Request),
            DhcpOption::RequestedIpAddress("192.168.1.150".parse().unwrap()),
        );
        assert_eq!(
            kind_of(&engine.handle(&out_of_range, 0).unwrap()),
            MessageType::Nak
        );
        let other_server = with(
            with(
                client(1, MessageType::Request),
                DhcpOption::RequestedIpAddress("192.168.1.100".parse().unwrap()),
            ),
            DhcpOption::ServerIdentifier("192.168.1.77".parse().unwrap()),
        );
        assert!(
            engine.handle(&other_server, 0).is_none(),
            "someone else was chosen"
        );
    }

    #[test]
    fn renewal_extends_and_goes_back_to_the_client() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        let ip = lease_through(&mut engine, 1, 0);
        let mut renew = client(1, MessageType::Request);
        renew.set_ciaddr(ip);
        renew.set_flags(Flags::default());
        let ack = engine.handle(&renew, 1800).unwrap();
        assert_eq!(kind_of(&ack), MessageType::Ack);
        assert_eq!(ack.destination, Destination::Unicast(ip));
        match ack.change {
            Some(Change::Bind(lease)) => assert_eq!(lease.expires, 1800 + 3600),
            other => panic!("expected a bind, got {other:?}"),
        }
        // A different client cannot renew someone else's address.
        let mut thief = client(2, MessageType::Request);
        thief.set_ciaddr(ip);
        assert_eq!(
            kind_of(&engine.handle(&thief, 1800).unwrap()),
            MessageType::Nak
        );
    }

    #[test]
    fn release_and_decline_end_leases_and_a_declined_address_rests() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        let ip = lease_through(&mut engine, 1, 0);
        let mut release = client(1, MessageType::Release);
        release.set_ciaddr(ip);
        let done = engine.handle(&release, 5).unwrap();
        assert_eq!(done.change, Some(Change::End(ip)));
        assert!(engine.bound().is_empty());
        // Someone else's release is ignored.
        let ip = lease_through(&mut engine, 2, 10);
        let mut other = client(3, MessageType::Release);
        other.set_ciaddr(ip);
        assert!(engine.handle(&other, 11).is_none());
        // A decline quarantines the address.
        let decline = with(
            client(2, MessageType::Decline),
            DhcpOption::RequestedIpAddress(ip),
        );
        assert_eq!(
            engine.handle(&decline, 12).unwrap().change,
            Some(Change::End(ip))
        );
        let fresh = engine
            .handle(&client(7, MessageType::Discover), 13)
            .unwrap();
        assert_ne!(fresh.message.yiaddr(), ip);
        let later = engine.handle(
            &client(8, MessageType::Discover),
            13 + DECLINE_QUARANTINE_SECS + 1,
        );
        assert!(later.is_some());
    }

    #[test]
    fn relayed_requests_reply_through_the_relay_and_inform_gets_options_only() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        let mut relayed = client(1, MessageType::Discover);
        relayed.set_giaddr("192.168.1.1".parse::<Ipv4Addr>().unwrap());
        let offer = engine.handle(&relayed, 0).unwrap();
        assert_eq!(
            offer.destination,
            Destination::Relay("192.168.1.1".parse().unwrap())
        );
        assert_eq!(offer.message.giaddr().to_string(), "192.168.1.1");
        let mut inform = client(6, MessageType::Inform);
        inform.set_ciaddr("192.168.1.60".parse::<Ipv4Addr>().unwrap());
        let ack = engine.handle(&inform, 0).unwrap();
        assert_eq!(kind_of(&ack), MessageType::Ack);
        assert!(ack.message.yiaddr().is_unspecified());
        assert!(
            ack.message
                .opts()
                .get(OptionCode::AddressLeaseTime)
                .is_none()
        );
        assert!(engine.bound().is_empty());
    }

    #[test]
    fn restored_leases_are_kept_until_they_expire() {
        let lease = Lease {
            ip: "192.168.1.101".parse().unwrap(),
            client: vec![0xaa, 0xbb, 0xcc, 0, 0, 1],
            hostname: Some("tv".into()),
            expires: 500,
            offered: false,
        };
        let engine = Engine::new(&scope(), "home.example", vec![lease.clone()], 100);
        assert_eq!(engine.bound(), vec![lease.clone()]);
        let engine = Engine::new(&scope(), "home.example", vec![lease], 500);
        assert!(engine.bound().is_empty());
    }

    #[test]
    fn host_names_are_made_safe() {
        assert_eq!(host_label("My-Laptop.local").as_deref(), Some("my-laptop"));
        assert_eq!(host_label("-x-").as_deref(), Some("x"));
        assert_eq!(host_label("a b_c!").as_deref(), Some("abc"));
        assert!(
            host_label("").is_none() && host_label("...").is_none() && host_label("!!").is_none()
        );
        assert_eq!(host_label(&"a".repeat(100)).unwrap().len(), 63);
    }

    #[test]
    fn asking_again_does_not_shorten_a_bound_lease() {
        let mut engine = Engine::new(&scope(), "home.example", vec![], 0);
        let ip = lease_through(&mut engine, 1, 0);
        let again = engine
            .handle(&client(1, MessageType::Discover), 100)
            .unwrap();
        assert_eq!(again.message.yiaddr(), ip);
        let bound = engine.bound();
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].expires, 3600);
        assert!(engine.expire(500).is_empty());
    }
}

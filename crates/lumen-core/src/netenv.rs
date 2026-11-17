//! What the network module may use from the running daemon: DHCP leases and reverse DNS.

use crate::Service;
use async_trait::async_trait;
use lumen_netmon::DhcpHost;
use lumen_proto::{
    Query,
    hickory_proto::{
        op::{Message, Query as DnsQuery},
        rr::{Name, RData, RecordType},
    },
};
use lumen_resolver::Transport;
use std::{fmt::Write, net::IpAddr, sync::Arc};

pub struct Environment(pub Arc<Service>);

/// `4.3.2.1.in-addr.arpa.` or the nibble form under `ip6.arpa.`.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut name = String::new();
            for byte in v6.octets().iter().rev() {
                let _ = write!(name, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
            }
            name.push_str("ip6.arpa.");
            name
        }
    }
}

#[async_trait]
impl lumen_netmon::Environment for Environment {
    fn dhcp_hosts(&self) -> Vec<DhcpHost> {
        let Some(dhcp) = self.0.dhcp.get() else {
            return Vec::new();
        };
        dhcp.snapshot()
            .leases
            .into_iter()
            .filter(|l| l.prefix_len.is_none() && !l.temporary)
            .map(|l| DhcpHost {
                ip: l.ip,
                client: l.client,
                hostname: l.hostname,
            })
            .collect()
    }

    /// Ask this daemon's own resolver, as a local client, so what it answers (local zones, DHCP
    /// and IPAM names, forwarders) is what the inventory learns. The question skips the client
    /// access list and the query history: it is the daemon asking itself.
    async fn reverse(&self, ip: IpAddr) -> Option<String> {
        let name = Name::from_ascii(reverse_name(ip)).ok()?;
        let mut message = Message::query();
        message.add_query(DnsQuery::query(name, RecordType::PTR));
        let query = Query::parse(&message.to_vec().ok()?).ok()?;
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let answer = self
            .0
            .resolver
            .answer(&query, peer, Transport::Udp, 1232)
            .await
            .ok()?;
        let response = Message::from_vec(&answer).ok()?;
        response
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RData::PTR(ptr) => Some(ptr.0.to_ascii().trim_end_matches('.').to_owned()),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::reverse_name;

    #[test]
    fn reverse_names_follow_the_standard_forms() {
        assert_eq!(
            reverse_name("192.168.1.20".parse().unwrap()),
            "20.1.168.192.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }
}

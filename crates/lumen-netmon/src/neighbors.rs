//! Reading this machine's ARP (IPv4) and NDP (IPv6) neighbor tables.
//!
//! The tables are read with the system's own tools (`ip`, `arp`, `ndp`) or `/proc/net/arp`, run
//! without a shell and with fixed arguments. The parsers are plain functions over text, so they
//! are tested with real sample output.

use crate::oui::{Mac, is_usable, parse_mac};
use std::{
    net::IpAddr,
    process::{Command, Stdio},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub mac: Mac,
    pub interface: Option<String>,
}

/// An address with an optional `%scope`, as `ndp` and `ip` print link-local IPv6.
fn parse_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim().trim_matches(['(', ')']);
    text.split('%').next()?.parse().ok()
}

fn entry(ip: &str, mac: &str, interface: Option<&str>) -> Option<Neighbor> {
    let ip = parse_ip(ip)?;
    let mac = parse_mac(mac).filter(is_usable)?;
    if ip.is_multicast() || ip.is_unspecified() {
        return None;
    }
    Some(Neighbor {
        ip,
        mac,
        interface: interface.map(str::to_owned),
    })
}

/// Linux `/proc/net/arp`:
/// `IP address HW type Flags HW address Mask Device`.
#[must_use]
pub fn parse_proc_arp(text: &str) -> Vec<Neighbor> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            // Flags 0x2 is a complete entry; 0x0 is incomplete.
            let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None;
            }
            entry(f[0], f[3], Some(f[5]))
        })
        .collect()
}

/// Linux `ip neigh show`:
/// `192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`.
#[must_use]
pub fn parse_ip_neigh(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let ip = *f.first()?;
            if f.iter().any(|w| matches!(*w, "FAILED" | "INCOMPLETE")) {
                return None;
            }
            let dev = f
                .iter()
                .position(|w| *w == "dev")
                .and_then(|i| f.get(i + 1))
                .copied();
            let mac = f
                .iter()
                .position(|w| *w == "lladdr")
                .and_then(|i| f.get(i + 1))?;
            entry(ip, mac, dev)
        })
        .collect()
}

/// macOS and BSD `arp -an`: `? (192.168.1.1) at 0:1b:63:84:45:e6 on en0 ifscope [ethernet]`.
#[must_use]
pub fn parse_arp_an(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|line| {
            let open = line.find('(')?;
            let close = line.find(')')?;
            let ip = &line[open + 1..close];
            let rest = line[close + 1..].trim();
            let rest = rest.strip_prefix("at ")?;
            let mut words = rest.split_whitespace();
            let mac = words.next()?;
            if mac == "(incomplete)" {
                return None;
            }
            let interface = rest.split_whitespace().skip_while(|w| *w != "on").nth(1);
            entry(ip, mac, interface)
        })
        .collect()
}

/// macOS and BSD `ndp -an`:
/// `Neighbor Linklayer Address Netif Expire S Flags`.
#[must_use]
pub fn parse_ndp_an(text: &str) -> Vec<Neighbor> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 || f[1] == "(incomplete)" {
                return None;
            }
            entry(f[0], f[1], Some(f[2]))
        })
        .collect()
}

/// Run a tool with fixed arguments and read at most 4 MiB of its output.
fn run(program: &str, args: &[&str]) -> Option<String> {
    use std::io::Read;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut text = String::new();
    child
        .stdout
        .take()?
        .take(4 << 20)
        .read_to_string(&mut text)
        .ok()?;
    let status = child.wait().ok()?;
    status.success().then_some(text)
}

fn first_of(candidates: &[&str], args: &[&str]) -> Option<String> {
    candidates
        .iter()
        .filter(|p| std::path::Path::new(p).exists())
        .find_map(|p| run(p, args))
}

/// Everything in this machine's neighbor tables right now.
#[must_use]
pub fn collect() -> Vec<Neighbor> {
    let mut found: Vec<Neighbor> = Vec::new();
    if cfg!(target_os = "linux") {
        if let Some(text) = first_of(
            &["/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"],
            &["neigh", "show"],
        ) {
            found.extend(parse_ip_neigh(&text));
        } else if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
            found.extend(parse_proc_arp(&text));
        }
    } else {
        if let Some(text) = first_of(&["/usr/sbin/arp", "/sbin/arp"], &["-an"]) {
            found.extend(parse_arp_an(&text));
        }
        if let Some(text) = first_of(&["/usr/sbin/ndp", "/sbin/ndp"], &["-an"]) {
            found.extend(parse_ndp_an(&text));
        }
    }
    found.sort_by_key(|a| (a.ip, a.mac));
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(list: &[Neighbor]) -> Vec<String> {
        list.iter().map(|n| n.ip.to_string()).collect()
    }

    #[test]
    fn linux_proc_net_arp_keeps_complete_entries() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         3c:a6:2f:11:22:33     *        eth0\n\
                    192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                    192.168.1.20     0x1         0x2         b8:27:eb:00:00:01     *        eth0\n";
        let got = parse_proc_arp(text);
        assert_eq!(ips(&got), ["192.168.1.1", "192.168.1.20"]);
        assert_eq!(got[0].interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn linux_ip_neigh_covers_both_families_and_skips_failures() {
        let text = "192.168.1.1 dev eth0 lladdr 3c:a6:2f:11:22:33 REACHABLE\n\
                    192.168.1.7 dev eth0  FAILED\n\
                    fe80::3ea6:2fff:fe11:2233 dev eth0 lladdr 3c:a6:2f:11:22:33 router STALE\n\
                    fd00::20 dev eth0 lladdr b8:27:eb:00:00:01 DELAY\n\
                    192.168.1.8 dev eth0 INCOMPLETE\n";
        let got = parse_ip_neigh(text);
        assert_eq!(
            ips(&got),
            ["192.168.1.1", "fe80::3ea6:2fff:fe11:2233", "fd00::20"]
        );
    }

    #[test]
    fn macos_arp_and_ndp_output_parses_with_short_mac_octets() {
        let arp = "? (192.168.1.1) at 3c:a6:2f:11:22:33 on en0 ifscope [ethernet]\n\
                   ? (192.168.1.40) at 0:1b:63:84:45:e6 on en0 ifscope [ethernet]\n\
                   ? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]\n\
                   ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n\
                   ? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n";
        let got = parse_arp_an(arp);
        assert_eq!(ips(&got), ["192.168.1.1", "192.168.1.40"]);
        assert_eq!(got[1].mac, [0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6]);
        let ndp = "Neighbor                        Linklayer Address  Netif Expire    S Flags\n\
                   fe80::1%en0                     3c:a6:2f:11:22:33  en0   23h59m58s S R\n\
                   fd00::20                        b8:27:eb:0:0:1     en0   23h57m1s  S\n\
                   fe80::9%en0                     (incomplete)       en0   expired   N\n";
        let got = parse_ndp_an(ndp);
        assert_eq!(ips(&got), ["fe80::1", "fd00::20"]);
        assert_eq!(got[1].mac, [0xb8, 0x27, 0xeb, 0, 0, 1]);
    }

    #[test]
    fn collecting_never_panics_and_returns_only_usable_entries() {
        for n in collect() {
            assert!(is_usable(&n.mac) && !n.ip.is_multicast());
        }
    }
}

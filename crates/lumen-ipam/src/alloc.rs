//! Address arithmetic and the search for a free address. No database in here.

use crate::model::Strategy;
use ipnet::IpNet;
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// An address as a number, so ranges and gaps are plain arithmetic for both families.
pub fn to_num(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

pub fn from_num(net: &IpNet, number: u128) -> IpAddr {
    match net {
        IpNet::V4(_) => IpAddr::V4(Ipv4Addr::from(u32::try_from(number).unwrap_or(u32::MAX))),
        IpNet::V6(_) => IpAddr::V6(Ipv6Addr::from(number)),
    }
}

/// First and last address of the whole block, including network and broadcast.
pub fn block(net: &IpNet) -> (u128, u128) {
    (to_num(net.network()), to_num(net.broadcast()))
}

/// First and last address that can be given to a device. IPv4 skips the network and broadcast
/// addresses (except on /31 and /32), IPv6 skips the subnet-router anycast address.
pub fn usable(net: &IpNet) -> (u128, u128) {
    let (first, last) = block(net);
    match net {
        IpNet::V4(v4) if v4.prefix_len() <= 30 => (first + 1, last - 1),
        IpNet::V6(v6) if v6.prefix_len() <= 126 => (first + 1, last),
        _ => (first, last),
    }
}

/// How many addresses a subnet can give out.
pub fn usable_count(net: &IpNet) -> u128 {
    let (first, last) = usable(net);
    last - first + 1
}

/// The size of the whole block.
pub fn block_count(net: &IpNet) -> u128 {
    let (first, last) = block(net);
    last - first + 1
}

fn random(bound: u128) -> u128 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(1);
    let high = u128::from(hasher.finish());
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u8(2);
    let low = u128::from(hasher.finish());
    ((high << 64) | low) % bound.max(1)
}

/// The free stretches of `[first, last]`, in order, once the `blocked` inclusive ranges (in any
/// order) are taken out. The cost is the number of blocked ranges, not the size of the subnet.
pub fn gaps(first: u128, last: u128, blocked: &[(u128, u128)]) -> Vec<(u128, u128)> {
    let mut gaps = Vec::new();
    if first > last {
        return gaps;
    }
    let mut ranges: Vec<(u128, u128)> = blocked
        .iter()
        .copied()
        .filter(|(low, high)| *high >= first && *low <= last)
        .collect();
    ranges.sort_unstable();
    let mut next = first;
    for (low, high) in ranges {
        if low > next {
            gaps.push((next, low - 1));
        }
        if high >= last {
            // Everything from here to the end is blocked.
            return gaps;
        }
        next = next.max(high + 1);
    }
    gaps.push((next, last));
    gaps
}

/// The address to give out: free of every blocked range, inside `[first, last]`.
pub fn pick(first: u128, last: u128, blocked: &[(u128, u128)], strategy: Strategy) -> Option<u128> {
    finish(&gaps(first, last, blocked), strategy)
}

fn finish(gaps: &[(u128, u128)], strategy: Strategy) -> Option<u128> {
    match strategy {
        Strategy::First => gaps.first().map(|(low, _)| *low),
        Strategy::Last => gaps.last().map(|(_, high)| *high),
        Strategy::Random => {
            let total: u128 = gaps.iter().map(|(low, high)| high - low + 1).sum();
            if total == 0 {
                return None;
            }
            let mut index = random(total);
            for (low, high) in gaps {
                let size = high - low + 1;
                if index < size {
                    return Some(low + index);
                }
                index -= size;
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_ranges_skip_network_broadcast_and_the_anycast_address() {
        let net: IpNet = "192.168.1.0/24".parse().unwrap();
        assert_eq!(usable_count(&net), 254);
        assert_eq!(usable_count(&"10.0.0.0/31".parse().unwrap()), 2);
        assert_eq!(usable_count(&"10.0.0.1/32".parse().unwrap()), 1);
        assert_eq!(
            usable_count(&"2001:db8::/64".parse().unwrap()),
            (1u128 << 64) - 1
        );
        assert_eq!(block_count(&net), 256);
    }

    #[test]
    fn the_first_last_and_random_pick_stay_inside_the_gaps() {
        let blocked = [(10, 12), (14, 14), (1, 3)];
        assert_eq!(pick(1, 20, &blocked, Strategy::First), Some(4));
        assert_eq!(pick(1, 20, &blocked, Strategy::Last), Some(20));
        for _ in 0..200 {
            let got = pick(1, 20, &blocked, Strategy::Random).unwrap();
            assert!(!blocked.iter().any(|(l, h)| (*l..=*h).contains(&got)));
            assert!((1..=20).contains(&got));
        }
        // Blocked at both ends.
        assert_eq!(pick(1, 5, &[(1, 5)], Strategy::First), None);
        assert_eq!(pick(1, 5, &[(0, 9)], Strategy::Last), None);
        assert_eq!(pick(1, 5, &[(1, 4)], Strategy::Last), Some(5));
        assert_eq!(pick(1, 5, &[(2, 5)], Strategy::Last), Some(1));
        // A huge IPv6 range costs nothing.
        assert_eq!(pick(1, u128::MAX / 2, &[(1, 1)], Strategy::First), Some(2));
    }
}

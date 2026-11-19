use super::*;
use crate::model::{AddressState, Strategy};

fn ipam() -> Ipam {
    Ipam::open_memory().unwrap()
}

fn subnet(ipam: &mut Ipam, cidr: &str) -> Subnet {
    ipam.add_subnet(&SubnetInput {
        cidr: cidr.into(),
        name: cidr.into(),
        ..SubnetInput::default()
    })
    .unwrap()
}

fn assign(ip: &str, state: AddressState) -> AddressInput {
    AddressInput {
        ip: ip.into(),
        state,
        hostname: None,
        description: String::new(),
        device: String::new(),
        location_id: None,
        dns: false,
    }
}

fn next(strategy: Strategy) -> AllocateInput {
    AllocateInput {
        strategy,
        state: AddressState::Assigned,
        hostname: None,
        description: String::new(),
        device: String::new(),
        location_id: None,
        dns: false,
    }
}

fn lease(ip: &str, name: Option<&str>) -> Leased {
    Leased {
        ip: ip.parse().unwrap(),
        hostname: name.map(str::to_owned),
    }
}

#[test]
fn subnets_are_normalized_unique_and_nest_into_a_hierarchy() {
    let mut ipam = ipam();
    let outer = subnet(&mut ipam, "10.1.0.0/16");
    let inner = subnet(&mut ipam, "10.1.5.77/24");
    assert_eq!(inner.cidr, "10.1.5.0/24", "host bits are cleared");
    assert_eq!(inner.parent_id, Some(outer.id));
    let v6 = subnet(&mut ipam, "2001:db8::/64");
    assert_eq!(v6.parent_id, None);
    for (cidr, why) in [
        ("10.1.5.0/24", "duplicate"),
        ("nonsense", "syntax"),
        ("0.0.0.0/0", "too wide"),
        ("2001:db8::/8", "too wide"),
    ] {
        assert!(
            ipam.add_subnet(&SubnetInput {
                cidr: cidr.into(),
                name: "x".into(),
                ..SubnetInput::default()
            })
            .is_err(),
            "{why}"
        );
    }
    let all = ipam.subnets().unwrap();
    assert_eq!(
        all.iter().find(|s| s.id == outer.id).unwrap().parent_id,
        None
    );
    // A parent that still contains a subnet cannot be removed; neither can one that holds addresses.
    assert!(ipam.delete_subnet(outer.id).is_err());
    ipam.set_address(&assign("10.1.5.9", AddressState::Assigned), &[])
        .unwrap();
    assert!(ipam.delete_subnet(inner.id).is_err());
    assert!(ipam.release("10.1.5.9").unwrap());
    assert!(ipam.delete_subnet(inner.id).unwrap());
    assert!(ipam.delete_subnet(outer.id).unwrap());
}

#[test]
fn a_subnet_keeps_its_network_and_checks_its_gateway_and_references() {
    let mut ipam = ipam();
    let s = subnet(&mut ipam, "192.168.1.0/24");
    let mut change = SubnetInput {
        name: "Lab".into(),
        gateway: Some("192.168.1.1".into()),
        ..SubnetInput::default()
    };
    assert_eq!(
        ipam.update_subnet(s.id, &change)
            .unwrap()
            .gateway
            .as_deref(),
        Some("192.168.1.1")
    );
    change.gateway = Some("192.168.2.1".into());
    assert!(
        ipam.update_subnet(s.id, &change).is_err(),
        "outside the subnet"
    );
    change.gateway = Some("192.168.1.255".into());
    assert!(ipam.update_subnet(s.id, &change).is_err(), "broadcast");
    change.gateway = None;
    change.cidr = "192.168.9.0/24".into();
    assert!(
        ipam.update_subnet(s.id, &change).is_err(),
        "the network cannot change"
    );
    change.cidr = String::new();
    change.vlan_id = Some(99);
    assert!(ipam.update_subnet(s.id, &change).is_err(), "no such VLAN");
    change.vlan_id = None;
    change.metadata = (0..17).map(|i| (format!("k{i}"), "v".into())).collect();
    assert!(
        ipam.update_subnet(s.id, &change).is_err(),
        "too much metadata"
    );
}

#[test]
fn vlans_are_unique_per_location_and_checked() {
    let mut ipam = ipam();
    let site = ipam
        .add_location(&LocationInput {
            parent_id: None,
            kind: "site".into(),
            name: "HQ".into(),
            description: String::new(),
        })
        .unwrap();
    let vlan = |vid, location_id| VlanInput {
        vid,
        name: "Users".into(),
        description: String::new(),
        location_id,
    };
    let a = ipam.add_vlan(&vlan(10, None)).unwrap();
    assert!(
        ipam.add_vlan(&vlan(10, None)).is_err(),
        "duplicate in the same scope"
    );
    ipam.add_vlan(&vlan(10, Some(site.id))).unwrap();
    assert!(ipam.add_vlan(&vlan(0, None)).is_err());
    assert!(ipam.add_vlan(&vlan(4095, None)).is_err());
    assert!(ipam.add_vlan(&vlan(20, Some(999))).is_err());
    assert_eq!(ipam.update_vlan(a.id, &vlan(11, None)).unwrap().vid, 11);
    let s = ipam
        .add_subnet(&SubnetInput {
            cidr: "10.0.0.0/24".into(),
            name: "n".into(),
            vlan_id: Some(a.id),
            ..SubnetInput::default()
        })
        .unwrap();
    assert!(ipam.delete_vlan(a.id).is_err(), "a subnet uses it");
    assert_eq!(s.vlan_id, Some(a.id));
}

#[test]
fn locations_nest_without_loops_and_cannot_be_removed_while_used() {
    let mut ipam = ipam();
    let loc = |parent_id, kind: &str, name: &str| LocationInput {
        parent_id,
        kind: kind.into(),
        name: name.into(),
        description: String::new(),
    };
    let site = ipam.add_location(&loc(None, "site", "HQ")).unwrap();
    let building = ipam
        .add_location(&loc(Some(site.id), "building", "A"))
        .unwrap();
    let rack = ipam
        .add_location(&loc(Some(building.id), "rack", "R1"))
        .unwrap();
    assert!(ipam.add_location(&loc(None, "castle", "x")).is_err());
    assert!(ipam.add_location(&loc(Some(404), "room", "x")).is_err());
    assert!(
        ipam.update_location(site.id, &loc(Some(rack.id), "site", "HQ"))
            .is_err(),
        "loop"
    );
    assert!(
        ipam.update_location(site.id, &loc(Some(site.id), "site", "HQ"))
            .is_err(),
        "itself"
    );
    assert!(ipam.delete_location(site.id).is_err(), "has children");
    let s = ipam
        .add_subnet(&SubnetInput {
            cidr: "10.9.0.0/24".into(),
            name: "n".into(),
            location_id: Some(rack.id),
            ..SubnetInput::default()
        })
        .unwrap();
    assert!(ipam.delete_location(rack.id).is_err(), "a subnet is there");
    ipam.delete_subnet(s.id).unwrap();
    assert!(ipam.delete_location(rack.id).unwrap());
}

#[test]
fn manual_addresses_are_validated_and_can_be_reserved_and_released() {
    let mut ipam = ipam();
    subnet(&mut ipam, "192.168.1.0/24");
    let mut input = assign("192.168.1.10", AddressState::Assigned);
    input.hostname = Some("NAS.lab".into());
    input.dns = true;
    let row = ipam.set_address(&input, &[]).unwrap();
    assert_eq!(row.hostname.as_deref(), Some("nas.lab"));
    assert!(
        ipam.set_address(&assign("10.0.0.5", AddressState::Assigned), &[])
            .is_err(),
        "no subnet"
    );
    assert!(
        ipam.set_address(&assign("192.168.1.0", AddressState::Assigned), &[])
            .is_err(),
        "network"
    );
    assert!(
        ipam.set_address(&assign("192.168.1.255", AddressState::Reserved), &[])
            .is_err(),
        "broadcast"
    );
    assert!(
        ipam.set_address(
            &assign("192.168.1.20", AddressState::Assigned),
            &[lease("192.168.1.20", None)]
        )
        .is_err(),
        "leased"
    );
    let mut dup = assign("192.168.1.11", AddressState::Assigned);
    dup.hostname = Some("nas.lab".into());
    assert!(
        ipam.set_address(&dup, &[]).is_err(),
        "same name, same family"
    );
    let mut bad = assign("192.168.1.12", AddressState::Assigned);
    bad.dns = true;
    assert!(ipam.set_address(&bad, &[]).is_err(), "DNS needs a name");
    bad.hostname = Some("-bad-".into());
    assert!(ipam.set_address(&bad, &[]).is_err());
    // Changing state is an update, not a second record.
    ipam.set_address(&assign("192.168.1.10", AddressState::Reserved), &[])
        .unwrap();
    let all = ipam.addresses(&AddressFilter::default(), &[], 100).unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].state, "reserved");
    assert!(ipam.release("192.168.1.10").unwrap());
    assert!(!ipam.release("192.168.1.10").unwrap());
    assert!(ipam.release("nope").is_err());
}

#[test]
fn allocation_skips_everything_that_is_taken_and_never_repeats() {
    let mut ipam = ipam();
    let s = ipam
        .add_subnet(&SubnetInput {
            cidr: "192.168.1.0/29".into(),
            name: "tiny".into(),
            gateway: Some("192.168.1.1".into()),
            ..SubnetInput::default()
        })
        .unwrap();
    // .1 gateway, .2 recorded, .3 leased, .4-.5 inside a smaller subnet; .6 is the last usable.
    ipam.set_address(&assign("192.168.1.2", AddressState::Reserved), &[])
        .unwrap();
    let leases = [lease("192.168.1.3", Some("tv"))];
    let first = ipam
        .allocate(s.id, &next(Strategy::First), &leases)
        .unwrap();
    assert_eq!(first.ip, "192.168.1.4");
    let last = ipam.allocate(s.id, &next(Strategy::Last), &leases).unwrap();
    assert_eq!(last.ip, "192.168.1.6");
    let random = ipam
        .allocate(s.id, &next(Strategy::Random), &leases)
        .unwrap();
    assert_eq!(random.ip, "192.168.1.5");
    let err = ipam
        .allocate(s.id, &next(Strategy::First), &leases)
        .unwrap_err();
    assert!(err.contains("no free address"), "{err}");
    // Releasing makes the address available again, to the same allocator.
    ipam.release("192.168.1.4").unwrap();
    assert_eq!(
        ipam.allocate(s.id, &next(Strategy::First), &leases)
            .unwrap()
            .ip,
        "192.168.1.4"
    );
}

#[test]
fn allocation_leaves_room_inside_child_subnets_alone() {
    let mut ipam = ipam();
    let parent = subnet(&mut ipam, "10.0.0.0/24");
    subnet(&mut ipam, "10.0.0.0/25");
    let got = ipam
        .allocate(parent.id, &next(Strategy::First), &[])
        .unwrap();
    assert_eq!(
        got.ip, "10.0.0.128",
        "the lower half belongs to the smaller subnet"
    );
    // A recorded address inside the child subnet belongs to the child.
    let row = ipam
        .set_address(&assign("10.0.0.7", AddressState::Assigned), &[])
        .unwrap();
    assert_ne!(row.subnet_id, parent.id);
}

#[test]
fn adding_a_more_specific_subnet_adopts_the_addresses_inside_it() {
    let mut ipam = ipam();
    let wide = subnet(&mut ipam, "10.0.0.0/16");
    let row = ipam
        .set_address(&assign("10.0.5.9", AddressState::Assigned), &[])
        .unwrap();
    assert_eq!(row.subnet_id, wide.id);
    let narrow = subnet(&mut ipam, "10.0.5.0/24");
    let all = ipam.addresses(&AddressFilter::default(), &[], 10).unwrap();
    assert_eq!(all[0].subnet_id, narrow.id);
}

#[test]
fn ipv6_allocation_works_in_a_huge_subnet() {
    let mut ipam = ipam();
    let s = subnet(&mut ipam, "2001:db8:1::/64");
    assert_eq!(
        ipam.allocate(s.id, &next(Strategy::First), &[]).unwrap().ip,
        "2001:db8:1::1"
    );
    assert_eq!(
        ipam.allocate(s.id, &next(Strategy::First), &[]).unwrap().ip,
        "2001:db8:1::2"
    );
    let last = ipam.allocate(s.id, &next(Strategy::Last), &[]).unwrap();
    assert_eq!(last.ip, "2001:db8:1:0:ffff:ffff:ffff:ffff");
    let random = ipam.allocate(s.id, &next(Strategy::Random), &[]).unwrap();
    assert!(random.ip.starts_with("2001:db8:1:"));
    let overview = ipam.overview(&[]).unwrap();
    assert_eq!(overview.subnets[0].assigned, 4);
    assert!(overview.subnets[0].percent_used < 0.001);
}

#[test]
fn concurrent_allocations_never_hand_out_the_same_address() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    let id = {
        let mut ipam = Ipam::open(&path).unwrap();
        subnet(&mut ipam, "172.16.0.0/24").id
    };
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut ipam = Ipam::open(&path).unwrap();
                (0..10)
                    .map(|_| ipam.allocate(id, &next(Strategy::First), &[]).unwrap().ip)
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut seen = HashSet::new();
    for thread in threads {
        for ip in thread.join().unwrap() {
            assert!(seen.insert(ip.clone()), "{ip} was given out twice");
        }
    }
    assert_eq!(seen.len(), 80);
    // Allocations survive a restart.
    let ipam = Ipam::open(&path).unwrap();
    assert_eq!(
        ipam.addresses(&AddressFilter::default(), &[], 1000)
            .unwrap()
            .len(),
        80
    );
}

#[test]
fn the_inventory_merges_leases_and_lists_free_addresses() {
    let mut ipam = ipam();
    let s = subnet(&mut ipam, "192.168.7.0/29");
    ipam.set_address(&assign("192.168.7.1", AddressState::Assigned), &[])
        .unwrap();
    let leases = [
        lease("192.168.7.2", Some("phone")),
        lease("10.99.0.1", None),
    ];
    let all = ipam
        .addresses(&AddressFilter::default(), &leases, 100)
        .unwrap();
    let states: Vec<_> = all
        .iter()
        .map(|r| (r.ip.as_str(), r.state.as_str()))
        .collect();
    assert_eq!(
        states,
        [("192.168.7.1", "assigned"), ("192.168.7.2", "leased")],
        "a lease outside any subnet is ignored"
    );
    let free = ipam
        .addresses(
            &AddressFilter {
                subnet_id: Some(s.id),
                state: Some("available".into()),
                ..AddressFilter::default()
            },
            &leases,
            100,
        )
        .unwrap();
    let ips: Vec<_> = free.iter().map(|r| r.ip.as_str()).collect();
    assert_eq!(
        ips,
        ["192.168.7.3", "192.168.7.4", "192.168.7.5", "192.168.7.6"]
    );
    let two = ipam
        .addresses(
            &AddressFilter {
                subnet_id: Some(s.id),
                state: Some("available".into()),
                ..AddressFilter::default()
            },
            &leases,
            2,
        )
        .unwrap();
    assert_eq!(two.len(), 2);
    let found = ipam
        .addresses(
            &AddressFilter {
                query: "PHONE".into(),
                ..AddressFilter::default()
            },
            &leases,
            100,
        )
        .unwrap();
    assert_eq!(found.len(), 1);
}

#[test]
fn utilization_counts_recorded_leased_and_delegated_addresses() {
    let mut ipam = ipam();
    let outer = subnet(&mut ipam, "10.0.0.0/24");
    subnet(&mut ipam, "10.0.0.0/25");
    ipam.set_address(&assign("10.0.0.200", AddressState::Assigned), &[])
        .unwrap();
    ipam.set_address(&assign("10.0.0.201", AddressState::Reserved), &[])
        .unwrap();
    let leases = [lease("10.0.0.202", None), lease("10.0.0.200", None)];
    let overview = ipam.overview(&leases).unwrap();
    let stats = overview
        .subnets
        .iter()
        .find(|s| s.subnet_id == outer.id)
        .unwrap();
    assert_eq!((stats.assigned, stats.reserved, stats.leased), (1, 1, 1));
    assert_eq!(stats.size, "254");
    assert_eq!(stats.delegated, "128");
    assert_eq!(stats.free, "123");
    assert!(
        (stats.percent_used - 2.4).abs() < 0.11,
        "{}",
        stats.percent_used
    );
    assert_eq!(
        (overview.assigned, overview.reserved, overview.leased),
        (1, 1, 1)
    );
}

#[test]
fn conflicts_and_dns_entries_follow_the_records() {
    let mut ipam = ipam();
    subnet(&mut ipam, "192.168.1.0/24");
    let mut a = assign("192.168.1.10", AddressState::Assigned);
    a.hostname = Some("nas".into());
    a.dns = true;
    ipam.set_address(&a, &[]).unwrap();
    let mut b = assign("192.168.1.11", AddressState::Assigned);
    b.hostname = Some("printer".into());
    ipam.set_address(&b, &[]).unwrap();
    assert_eq!(
        ipam.dns_entries().unwrap(),
        vec![("nas".to_owned(), "192.168.1.10".parse().unwrap())]
    );
    assert!(ipam.conflicts(&[]).unwrap().is_empty());
    // DHCP later leases an address IPAM holds, and gives another device the name "nas".
    let leases = [
        lease("192.168.1.11", None),
        lease("192.168.1.50", Some("NAS.home.example")),
    ];
    let kinds: Vec<_> = ipam
        .conflicts(&leases)
        .unwrap()
        .into_iter()
        .map(|c| (c.kind, c.ip))
        .collect();
    assert!(kinds.contains(&("leased-and-assigned".to_owned(), "192.168.1.11".to_owned())));
    assert!(kinds.contains(&("name-held-by-dhcp".to_owned(), "192.168.1.10".to_owned())));
}

#[test]
fn the_database_keeps_everything_across_reopening() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.db");
    {
        let mut ipam = Ipam::open(&path).unwrap();
        let s = subnet(&mut ipam, "10.20.0.0/24");
        ipam.allocate(s.id, &next(Strategy::First), &[]).unwrap();
    }
    let ipam = Ipam::open(&path).unwrap();
    assert_eq!(ipam.subnets().unwrap().len(), 1);
    assert_eq!(
        ipam.addresses(&AddressFilter::default(), &[], 10).unwrap()[0].ip,
        "10.20.0.1"
    );
}

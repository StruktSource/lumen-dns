use super::*;
use crate::model::{CheckMethod, DeviceFilter};

fn db() -> Netmon {
    Netmon::open_memory().unwrap()
}

fn seen(source: Source, ip: &str, mac: Option<&str>, host: Option<&str>) -> Observation {
    Observation {
        ip: Some(ip.parse().unwrap()),
        mac: mac.map(|m| parse_mac(m).unwrap()),
        dhcp_id: None,
        hostname: host.map(str::to_owned),
        source,
        sys: None,
    }
}

fn all(db: &Netmon) -> Vec<Device> {
    db.devices(&DeviceFilter {
        include_gone: true,
        ..DeviceFilter::default()
    })
    .unwrap()
}

#[test]
fn a_dhcp_client_id_keeps_one_device_across_address_changes() {
    let (mut db, oui) = (db(), Oui::new());
    let mut first = seen(Source::Dhcp, "192.168.1.20", None, Some("laptop"));
    first.dhcp_id = Some("01-aa-bb-cc-dd-ee-ff".into());
    let id = db.observe(&first, &oui).unwrap().unwrap().device_id;
    let mut next = seen(Source::Dhcp, "192.168.1.44", None, Some("laptop"));
    next.dhcp_id = Some("01:aa:bb:cc:dd:ee:ff".into());
    assert_eq!(db.observe(&next, &oui).unwrap().unwrap().device_id, id);
    let device = db.device(id).unwrap().unwrap();
    assert_eq!(device.addresses.len(), 2);
    assert_eq!(device.dhcp_ids, vec!["01aabbccddeeff"]);
    assert_eq!(device.identity_confidence, "probable");
    assert!(db.detach(id, "01-aa-bb-cc-dd-ee-ff").unwrap());
    assert!(db.device(id).unwrap().unwrap().dhcp_ids.is_empty());
}

#[test]
fn rooms_nest_assign_and_refuse_cycles() {
    let (mut db, oui) = (db(), Oui::new());
    let floor = db
        .add_room(&RoomInput {
            name: "First floor".into(),
            ..RoomInput::default()
        })
        .unwrap();
    let office = db
        .add_room(&RoomInput {
            parent_id: Some(floor.id),
            name: "Office".into(),
            ..RoomInput::default()
        })
        .unwrap();
    assert!(
        db.update_room(
            floor.id,
            &RoomInput {
                parent_id: Some(office.id),
                name: floor.name.clone(),
                description: String::new(),
            },
        )
        .is_err()
    );
    let device = db
        .add_device(
            &DeviceInput {
                name: "Desk phone".into(),
                room_id: Some(office.id),
                ..DeviceInput::default()
            },
            &oui,
        )
        .unwrap();
    assert_eq!(device.room_id, Some(office.id));
    assert!(db.delete_room(office.id).unwrap());
    assert_eq!(db.device(device.id).unwrap().unwrap().room_id, None);
}

#[test]
fn the_same_device_seen_by_several_methods_is_one_entry() {
    let (mut db, oui) = (db(), Oui::new());
    let a = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.20",
                Some("b8:27:eb:00:00:01"),
                None,
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    assert!(a.created);
    let b = db
        .observe(&seen(Source::Icmp, "192.168.1.20", None, None), &oui)
        .unwrap()
        .unwrap();
    let c = db
        .observe(
            &seen(
                Source::Dhcp,
                "192.168.1.20",
                Some("b8:27:eb:00:00:01"),
                Some("Pi-Hole"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    let d = db
        .observe(
            &seen(Source::Dns, "192.168.1.20", None, Some("pi-hole.lan")),
            &oui,
        )
        .unwrap()
        .unwrap();
    assert_eq!([b.device_id, c.device_id, d.device_id], [a.device_id; 3]);
    assert!(!b.created && !c.created && !d.created);
    let devices = all(&db);
    assert_eq!(devices.len(), 1);
    let device = &devices[0];
    assert_eq!(device.vendor.as_deref(), Some("Raspberry Pi Foundation"));
    assert_eq!(
        device.hostname.as_deref(),
        Some("pi-hole.lan"),
        "the latest name wins while nobody set one"
    );
    assert_eq!(device.name, "pi-hole", "the first label of the host name");
    assert_eq!(
        device.status,
        Status::Online,
        "an answer to ping means online"
    );
    assert_eq!(device.kind, "iot");
    assert!(device.last_ok.is_some());
    assert_eq!(
        db.events(None, 10)
            .unwrap()
            .iter()
            .filter(|e| e.kind == "new")
            .count(),
        1
    );
}

#[test]
fn a_neighbor_entry_is_present_but_not_awake_and_a_lease_is_neither() {
    let (mut db, oui) = (db(), Oui::new());
    let n = db
        .observe(
            &seen(
                Source::Neighbor,
                "10.0.0.5",
                Some("3c:a6:2f:00:00:01"),
                None,
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        db.device(n.device_id).unwrap().unwrap().status,
        Status::Unknown
    );
    let l = db
        .observe(
            &seen(
                Source::Dhcp,
                "10.0.0.6",
                Some("00:0c:29:00:00:01"),
                Some("vm"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    let lease = db.device(l.device_id).unwrap().unwrap();
    assert_eq!(lease.status, Status::Unknown);
    assert_eq!(
        lease.addresses[0].last_seen, 0,
        "a lease alone is not a sighting"
    );
    assert!(lease.vendor.as_deref().unwrap().starts_with("VMware"));
}

#[test]
fn a_changed_address_moves_a_known_device_and_a_late_mac_joins_an_ip_only_device() {
    let (mut db, oui) = (db(), Oui::new());
    // Found by ping first: no hardware address yet.
    let ip_only = db
        .observe(&seen(Source::Icmp, "192.168.1.50", None, None), &oui)
        .unwrap()
        .unwrap();
    // The neighbor table later shows its MAC: still one device.
    let joined = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.50",
                Some("00:11:22:33:44:55"),
                None,
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    assert_eq!(joined.device_id, ip_only.device_id);
    // Another device, with its own MAC, takes over the address: two devices, the address moves.
    let other = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.51",
                Some("00:11:22:33:44:66"),
                None,
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    assert_ne!(other.device_id, ip_only.device_id);
    let moved = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.50",
                Some("00:11:22:33:44:66"),
                None,
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    assert_eq!(moved.device_id, other.device_id);
    assert!(
        moved.absorbed.is_empty(),
        "different hardware means different devices"
    );
    let devices = all(&db);
    assert_eq!(devices.len(), 2);
    let holder = devices.iter().find(|d| d.id == other.device_id).unwrap();
    assert_eq!(holder.addresses.len(), 2);
    assert!(
        devices
            .iter()
            .find(|d| d.id == ip_only.device_id)
            .unwrap()
            .addresses
            .is_empty()
    );
}

#[test]
fn two_entries_that_turn_out_to_be_one_device_are_merged_without_losing_manual_data() {
    let (mut db, oui) = (db(), Oui::new());
    let found = db
        .observe(&seen(Source::Icmp, "192.168.1.70", None, None), &oui)
        .unwrap()
        .unwrap();
    let manual = db
        .add_device(
            &DeviceInput {
                name: "Living room TV".into(),
                kind: Some("tv".into()),
                macs: vec!["00:aa:bb:cc:dd:ee".into()],
                notes: "bought in 2022".into(),
                ..DeviceInput::default()
            },
            &oui,
        )
        .unwrap();
    // The neighbor table then shows that MAC at the address the ping found.
    let merged = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.70",
                Some("00:aa:bb:cc:dd:ee"),
                None,
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        merged.device_id, manual.id,
        "the device an administrator made survives"
    );
    assert_eq!(merged.absorbed, vec![found.device_id]);
    let devices = all(&db);
    assert_eq!(devices.len(), 1);
    let tv = &devices[0];
    assert_eq!(
        (tv.name.as_str(), tv.kind.as_str(), tv.notes.as_str()),
        ("Living room TV", "tv", "bought in 2022")
    );
    assert_eq!(tv.addresses[0].ip, "192.168.1.70");
}

#[test]
fn what_an_administrator_set_is_never_overwritten_by_discovery() {
    let (mut db, oui) = (db(), Oui::new());
    let seen_first = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.9",
                Some("00:11:22:00:00:09"),
                Some("host9"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap();
    let edited = db
        .update_device(
            seen_first.device_id,
            &DeviceInput {
                name: "Kitchen printer".into(),
                kind: Some("printer".into()),
                icon: Some("printer".into()),
                description: "HP".into(),
                ..DeviceInput::default()
            },
            &oui,
        )
        .unwrap();
    assert_eq!(edited.locked, vec!["icon", "kind", "name"]);
    db.observe(
        &seen(
            Source::Dhcp,
            "192.168.1.9",
            Some("00:11:22:00:00:09"),
            Some("renamed-host"),
        ),
        &oui,
    )
    .unwrap();
    let after = db.device(seen_first.device_id).unwrap().unwrap();
    assert_eq!(
        (
            after.name.as_str(),
            after.kind.as_str(),
            after.icon.as_deref()
        ),
        ("Kitchen printer", "printer", Some("printer"))
    );
    assert_eq!(
        after.hostname.as_deref(),
        Some("renamed-host"),
        "an unlocked field still follows discovery"
    );
    assert_eq!(after.description, "HP");
}

#[test]
fn saving_a_device_without_changing_a_field_does_not_lock_it() {
    let (mut db, oui) = (db(), Oui::new());
    let id = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.9",
                Some("00:11:22:00:00:09"),
                Some("host9"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap()
        .device_id;
    let device = db.device(id).unwrap().unwrap();
    // Turning monitoring off with the form's current values keeps discovery in charge of the rest.
    db.update_device(
        id,
        &DeviceInput {
            name: device.name.clone(),
            hostname: device.hostname.clone(),
            kind: Some(device.kind.clone()),
            description: "note".into(),
            monitoring: Some(Monitoring {
                enabled: false,
                ..Monitoring::default()
            }),
            ..DeviceInput::default()
        },
        &oui,
    )
    .unwrap();
    let after = db.device(id).unwrap().unwrap();
    assert!(after.locked.is_empty(), "{:?}", after.locked);
    assert!(!after.monitoring.enabled);
    db.observe(
        &seen(
            Source::Dhcp,
            "192.168.1.9",
            Some("00:11:22:00:00:09"),
            Some("renamed"),
        ),
        &oui,
    )
    .unwrap();
    assert_eq!(db.device(id).unwrap().unwrap().name, "renamed");
}

#[test]
fn manual_devices_are_validated_and_cannot_share_addresses() {
    let (mut db, oui) = (db(), Oui::new());
    let ok = DeviceInput {
        name: "NAS".into(),
        addresses: vec!["192.168.1.5".into(), "fd00::5".into()],
        macs: vec!["02:00:00:00:00:05".into()],
        ..DeviceInput::default()
    };
    let nas = db.add_device(&ok, &oui).unwrap();
    assert_eq!(nas.addresses.len(), 2, "one device, several addresses");
    assert!(nas.manual);
    let clash = DeviceInput {
        name: "Other".into(),
        addresses: vec!["192.168.1.5".into()],
        ..DeviceInput::default()
    };
    assert!(
        db.add_device(&clash, &oui)
            .unwrap_err()
            .contains("already belongs")
    );
    for bad in [
        DeviceInput {
            name: String::new(),
            ..DeviceInput::default()
        },
        DeviceInput {
            name: "x".into(),
            kind: Some("toaster".into()),
            ..DeviceInput::default()
        },
        DeviceInput {
            name: "x".into(),
            icon: Some("nope".into()),
            ..DeviceInput::default()
        },
        DeviceInput {
            name: "x".into(),
            addresses: vec!["nope".into()],
            ..DeviceInput::default()
        },
        DeviceInput {
            name: "x".into(),
            macs: vec!["ff:ff:ff:ff:ff:ff".into()],
            ..DeviceInput::default()
        },
        DeviceInput {
            name: "x".into(),
            monitoring: Some(Monitoring {
                method: CheckMethod::Tcp,
                ..Monitoring::default()
            }),
            ..DeviceInput::default()
        },
        DeviceInput {
            name: "x".into(),
            monitoring: Some(Monitoring {
                interval_secs: Some(1),
                ..Monitoring::default()
            }),
            ..DeviceInput::default()
        },
    ] {
        assert!(db.add_device(&bad, &oui).is_err(), "{bad:?}");
    }
    // A wrong match is corrected by moving an address off a device.
    assert!(db.detach(nas.id, "fd00::5").unwrap());
    assert!(!db.detach(nas.id, "fd00::5").unwrap());
    assert!(db.detach(nas.id, "nonsense").is_err());
    assert_eq!(db.device(nas.id).unwrap().unwrap().addresses.len(), 1);
}

#[test]
fn a_device_missed_often_enough_is_gone_but_is_kept_and_comes_back() {
    let (mut db, oui) = (db(), Oui::new());
    let scope: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
    let a = db
        .observe(
            &seen(
                Source::Icmp,
                "192.168.1.10",
                Some("00:11:22:00:00:0a"),
                Some("a"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap()
        .device_id;
    let b = db
        .observe(
            &seen(
                Source::Icmp,
                "192.168.1.11",
                Some("00:11:22:00:00:0b"),
                Some("b"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap()
        .device_id;
    let elsewhere = db
        .observe(
            &seen(
                Source::Dhcp,
                "10.9.9.9",
                Some("00:11:22:00:00:0c"),
                Some("c"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap()
        .device_id;
    let present: HashSet<i64> = [a].into();
    assert!(
        db.finish_sweep(&present, &[scope], 2).unwrap().is_empty(),
        "one miss is not enough"
    );
    assert_eq!(
        db.finish_sweep(&present, &[scope], 2).unwrap(),
        vec![b],
        "two misses in a row"
    );
    let gone = db.device(b).unwrap().unwrap();
    assert!(gone.gone);
    assert_eq!(gone.status, Status::Offline);
    assert!(
        !db.device(elsewhere).unwrap().unwrap().gone,
        "outside the scanned networks is not judged"
    );
    assert!(
        db.devices(&DeviceFilter::default())
            .unwrap()
            .iter()
            .all(|d| d.id != b),
        "hidden by default"
    );
    assert_eq!(all(&db).len(), 3, "but never deleted");
    let back = db
        .observe(&seen(Source::Icmp, "192.168.1.11", None, None), &oui)
        .unwrap()
        .unwrap();
    assert!(back.returned);
    let again = db.device(b).unwrap().unwrap();
    assert!(!again.gone);
    assert_eq!(again.status, Status::Online);
    assert!(
        db.events(None, 50)
            .unwrap()
            .iter()
            .any(|e| e.kind == "returned")
    );
    let counts = db.counts().unwrap();
    assert_eq!((counts.total, counts.gone), (3, 0));
}

#[test]
fn search_filters_and_merge_work() {
    let (mut db, oui) = (db(), Oui::new());
    db.observe(
        &seen(
            Source::Icmp,
            "192.168.1.10",
            Some("b8:27:eb:00:00:01"),
            Some("pi"),
        ),
        &oui,
    )
    .unwrap();
    let two = db
        .observe(
            &seen(
                Source::Neighbor,
                "192.168.1.11",
                Some("00:0c:29:00:00:02"),
                Some("esx"),
            ),
            &oui,
        )
        .unwrap()
        .unwrap()
        .device_id;
    let search = |query: &str| {
        db.devices(&DeviceFilter {
            query: query.into(),
            ..DeviceFilter::default()
        })
        .unwrap()
        .len()
    };
    assert_eq!(
        (
            search("raspberry"),
            search("192.168.1.11"),
            search("00:0C:29"),
            search("zzz")
        ),
        (1, 1, 1, 0)
    );
    let kind = db
        .devices(&DeviceFilter {
            kind: Some("server".into()),
            ..DeviceFilter::default()
        })
        .unwrap();
    assert_eq!(kind.len(), 1);
    let status = db
        .devices(&DeviceFilter {
            status: Some("online".into()),
            ..DeviceFilter::default()
        })
        .unwrap();
    assert_eq!(status.len(), 1);
    let one = db
        .observe(&seen(Source::Neighbor, "192.168.1.10", None, None), &oui)
        .unwrap()
        .unwrap()
        .device_id;
    let merged = db.merge(one, two).unwrap();
    assert_eq!(merged.addresses.len(), 2);
    assert_eq!(merged.macs.len(), 2);
    assert!(db.merge(one, one).is_err());
    assert!(db.merge(one, 999).is_err());
    assert!(db.delete_device(one).unwrap());
    assert!(all(&db).is_empty());
}

#[test]
fn kinds_are_guessed_from_what_is_known() {
    assert_eq!(
        guess_kind(Some("Hewlett Packard"), Some("printer-2"), None, None),
        "printer"
    );
    assert_eq!(guess_kind(None, Some("cam-garage"), None, None), "camera");
    assert_eq!(guess_kind(Some("AVM GmbH"), None, None, None), "router");
    assert_eq!(
        guess_kind(None, None, Some("Cisco IOS Catalyst switch"), None),
        "switch"
    );
    assert_eq!(guess_kind(None, None, None, Some(0b110)), "router");
    assert_eq!(guess_kind(None, None, None, Some(0b10)), "switch");
    assert_eq!(
        guess_kind(Some("Zyxel"), Some("host1"), None, None),
        "unknown"
    );
}

//! The routes: devices, links, the topology, and the link to IPAM.

use lumen_netmon::{
    Netmon, Observation, Oui, Source,
    api::{Access, Outcome, Request, access, handle},
};
use serde_json::{Value, json};
use std::path::Path;

fn call(state: &Path, method: &str, path: &str, body: &Value, ipam: bool) -> Outcome {
    let (route, query) = path.split_once('?').unwrap_or((path, ""));
    let parts: Vec<&str> = route.split('/').filter(|p| !p.is_empty()).collect();
    let body = if body.is_null() {
        Vec::new()
    } else {
        body.to_string().into_bytes()
    };
    handle(&Request {
        method,
        parts: &parts,
        query,
        body: &body,
        state,
        ipam_enabled: ipam,
        engine: None,
    })
}

#[test]
fn routes_have_the_right_access_level() {
    assert_eq!(access("GET", &["devices"]), Some(Access::Read));
    assert_eq!(
        access("GET", &["devices", "3", "interfaces", "7", "history"]),
        Some(Access::Read)
    );
    assert_eq!(access("GET", &["topology"]), Some(Access::Read));
    assert_eq!(access("POST", &["scan"]), Some(Access::Operate));
    for (method, parts) in [
        ("POST", vec!["devices"]),
        ("PUT", vec!["links", "1"]),
        ("DELETE", vec!["devices", "1"]),
        ("POST", vec!["devices", "1", "merge"]),
        ("POST", vec!["devices", "1", "ipam"]),
    ] {
        assert_eq!(
            access(method, &parts),
            Some(Access::Manage),
            "{method} {parts:?}"
        );
    }
    assert_eq!(access("GET", &["nothing"]), None);
    assert_eq!(access("PATCH", &["devices"]), None);
}

#[test]
#[allow(clippy::too_many_lines)] // One walk through the routes.
fn devices_links_and_the_topology_work_together() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.db");
    let (switch, router, nas) = {
        let make = |name: &str, kind: &str, ip: &str, mac: &str| {
            let out = call(
                &state,
                "POST",
                "/devices",
                &json!({"name": name, "kind": kind, "addresses": [ip], "macs": [mac]}),
                false,
            );
            assert_eq!(out.status, 200, "{}", out.body);
            out.body["id"].as_i64().unwrap()
        };
        (
            make("Core switch", "switch", "192.168.1.2", "02:00:00:00:00:02"),
            make("Router", "router", "192.168.1.1", "02:00:00:00:00:01"),
            make("NAS", "nas", "192.168.1.10", "02:00:00:00:00:10"),
        )
    };
    // Listing, searching, filtering and sorting.
    let list = |q: &str| call(&state, "GET", &format!("/devices{q}"), &Value::Null, false).body;
    assert_eq!(list("")["total"], 3);
    assert_eq!(list("?q=nas")["total"], 1);
    assert_eq!(list("?kind=router")["devices"][0]["name"], "Router");
    let by_ip = list("?sort=ip");
    assert_eq!(by_ip["devices"][0]["name"], "Router");
    assert_eq!(list("?sort=ip&dir=desc")["devices"][0]["name"], "NAS");
    assert_eq!(list("?sort=name")["devices"][0]["name"], "Core switch");
    assert_eq!(
        list("?limit=1&offset=1")["devices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Links: an administrator's are confirmed; the reverse direction is the same link.
    let link = |a: i64, b: i64, ap: &str, bp: &str| {
        call(
            &state,
            "POST",
            "/links",
            &json!({"a_device": a, "a_port": ap, "b_device": b, "b_port": bp, "speed_mbps": 1000}),
            false,
        )
    };
    assert_eq!(link(router, switch, "lan", "uplink").status, 200);
    assert_eq!(
        link(switch, router, "uplink", "lan").status,
        400,
        "the same link the other way round"
    );
    assert_eq!(link(switch, switch, "a", "b").status, 400);
    let second = link(switch, nas, "port 5", "eth0");
    assert_eq!(second.status, 200);
    assert_eq!(second.body["kind"], "manual");
    assert_eq!(second.body["confirmed"], true);
    // A device that discovery inferred a link to is shown as inferred.
    {
        let mut nm = Netmon::open(&state).unwrap();
        nm.replace_reported_links(
            switch,
            "inferred",
            &[("port 9".into(), nas, String::new(), None)],
        )
        .unwrap();
    }
    let topology = call(&state, "GET", "/topology", &Value::Null, false).body;
    assert_eq!(topology["nodes"].as_array().unwrap().len(), 3);
    let edges = topology["links"].as_array().unwrap();
    assert_eq!(edges.len(), 3);
    assert_eq!(edges.iter().filter(|e| e["confirmed"] == true).count(), 2);
    assert_eq!(
        edges
            .iter()
            .filter(|e| e["kind"] == "inferred" && e["confirmed"] == false)
            .count(),
        1
    );
    // Filtering the topology drops links to devices that are not shown.
    let routers = call(&state, "GET", "/topology?kind=router", &Value::Null, false).body;
    assert_eq!(
        (
            routers["nodes"].as_array().unwrap().len(),
            routers["links"].as_array().unwrap().len()
        ),
        (1, 0)
    );
    // Correcting a link makes it a confirmed manual one.
    let inferred_id = edges.iter().find(|e| e["kind"] == "inferred").unwrap()["id"]
        .as_i64()
        .unwrap();
    let fixed = call(
        &state,
        "PUT",
        &format!("/links/{inferred_id}"),
        &json!({"a_device": switch, "a_port": "port 9", "b_device": nas, "b_port": "eth1"}),
        false,
    );
    assert_eq!(
        (
            fixed.status,
            fixed.body["kind"].clone(),
            fixed.body["confirmed"].clone()
        ),
        (200, json!("manual"), json!(true))
    );
    // Detail: everything about one device.
    let detail = call(
        &state,
        "GET",
        &format!("/devices/{switch}"),
        &Value::Null,
        false,
    )
    .body;
    assert_eq!(detail["device"]["name"], "Core switch");
    assert_eq!(detail["links"].as_array().unwrap().len(), 3);
    assert_eq!(
        call(&state, "GET", "/devices/999", &Value::Null, false).status,
        404
    );
    assert_eq!(
        call(&state, "GET", "/devices/abc", &Value::Null, false).status,
        400
    );
    // Merge two entries, correct a wrong match, delete.
    assert_eq!(
        call(
            &state,
            "POST",
            &format!("/devices/{router}/merge"),
            &json!({"other": nas}),
            false
        )
        .status,
        200
    );
    assert_eq!(list("")["total"], 2);
    let wrong = call(
        &state,
        "DELETE",
        &format!("/devices/{router}/addresses/192.168.1.10"),
        &Value::Null,
        false,
    );
    assert_eq!(wrong.status, 200);
    assert_eq!(
        call(
            &state,
            "DELETE",
            &format!("/devices/{router}/addresses/192.168.1.10"),
            &Value::Null,
            false
        )
        .status,
        404
    );
    assert_eq!(
        call(
            &state,
            "DELETE",
            &format!("/devices/{router}"),
            &Value::Null,
            false
        )
        .status,
        200
    );
    assert_eq!(
        call(
            &state,
            "DELETE",
            &format!("/devices/{router}"),
            &Value::Null,
            false
        )
        .status,
        404
    );
    // Bad input is refused with a reason that names no internals.
    let bad = call(
        &state,
        "POST",
        "/devices",
        &json!({"name": "x", "kind": "toaster"}),
        false,
    );
    assert_eq!(bad.status, 400);
    assert!(
        bad.body["error"]
            .as_str()
            .unwrap()
            .contains("kind must be one of")
    );
    assert_eq!(
        call(&state, "POST", "/devices", &json!({"nope": 1}), false).status,
        400
    );
}

#[test]
fn a_scan_can_be_requested_and_devices_are_placed_in_ipam() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.db");
    let out = call(&state, "POST", "/scan", &Value::Null, false);
    assert_eq!(
        (out.status, out.audit.as_ref().map(|a| a.0)),
        (200, Some("network.scan"))
    );
    let nm = Netmon::open(&state).unwrap();
    assert!(nm.take_scan_request().unwrap());
    assert!(!nm.take_scan_request().unwrap(), "a request is taken once");
    // A discovered device shows the subnet and VLAN IPAM has for its address.
    let mut nm = Netmon::open(&state).unwrap();
    let mut seen = Observation::new(Source::Icmp);
    seen.ip = Some("192.168.1.77".parse().unwrap());
    seen.hostname = Some("laptop".into());
    let id = nm.observe(&seen, &Oui::new()).unwrap().unwrap().device_id;
    let mut ipam = lumen_ipam::Ipam::open(&state).unwrap();
    let vlan = ipam
        .add_vlan(&lumen_ipam::VlanInput {
            vid: 20,
            name: "Users".into(),
            ..Default::default()
        })
        .unwrap();
    ipam.add_subnet(&lumen_ipam::SubnetInput {
        cidr: "192.168.1.0/24".into(),
        name: "LAN".into(),
        vlan_id: Some(vlan.id),
        ..Default::default()
    })
    .unwrap();
    let listed = call(
        &state,
        "GET",
        "/devices?subnet=192.168.1.0/24",
        &Value::Null,
        true,
    )
    .body;
    assert_eq!(listed["devices"][0]["subnet"], "192.168.1.0/24");
    assert_eq!(listed["devices"][0]["vlan"], "VLAN 20 · Users");
    assert_eq!(
        call(&state, "GET", "/devices?vlan=Users", &Value::Null, true).body["total"],
        1
    );
    assert_eq!(
        call(&state, "GET", "/devices?vlan=Servers", &Value::Null, true).body["total"],
        0
    );
    assert_eq!(
        call(
            &state,
            "GET",
            "/devices?subnet=10.0.0.0/8",
            &Value::Null,
            true
        )
        .body["total"],
        0
    );
    // The device can be recorded in IPAM, once, when the module is on.
    let record = |ipam_on: bool, ip: &str| {
        call(
            &state,
            "POST",
            &format!("/devices/{id}/ipam"),
            &json!({"ip": ip}),
            ipam_on,
        )
    };
    assert_eq!(record(false, "192.168.1.77").status, 400);
    assert_eq!(
        record(true, "192.168.9.9").status,
        400,
        "not this device's address"
    );
    assert_eq!(record(true, "192.168.1.77").status, 200);
    let rows = ipam
        .addresses(&lumen_ipam::AddressFilter::default(), &[], 10)
        .unwrap();
    assert_eq!(
        (
            rows[0].ip.as_str(),
            rows[0].device.as_str(),
            rows[0].hostname.as_deref()
        ),
        ("192.168.1.77", "laptop", Some("laptop"))
    );
    // The location list is IPAM's.
    assert_eq!(
        call(&state, "GET", "/locations", &Value::Null, true).body,
        json!([])
    );
}

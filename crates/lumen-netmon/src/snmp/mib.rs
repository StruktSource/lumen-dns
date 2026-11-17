//! What Lumen reads over SNMP, using only standard MIBs (SNMPv2-MIB, IF-MIB, HOST-RESOURCES,
//! ENTITY-SENSOR, LLDP, BRIDGE and Q-BRIDGE) so no vendor-specific support is needed. The
//! net-snmp (UCD) CPU and memory objects are used as a fallback because they are everywhere.

use super::{
    Client, SnmpError,
    ber::{Oid, Value},
};
use crate::{
    data::IfReading,
    model::SysInfo,
    oui::{Mac, is_usable},
};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

fn o(text: &str) -> Oid {
    Oid::parse(text).expect("static OID")
}

/// One column of a table, as index → value, where the index is the OID suffix as text.
async fn column(
    client: &mut Client,
    root: &str,
    rows: usize,
) -> Result<BTreeMap<Vec<u32>, Value>, SnmpError> {
    let root = o(root);
    let mut out = BTreeMap::new();
    for (name, value) in client.walk(&root, rows).await? {
        if let Some(suffix) = name.suffix(&root) {
            out.insert(suffix.to_vec(), value);
        }
    }
    Ok(out)
}

fn one(index: i64) -> Vec<u32> {
    vec![u32::try_from(index).unwrap_or(0)]
}

/// The system group: what the device says it is.
///
/// # Errors
/// The device did not answer.
pub async fn system(client: &mut Client, now: i64) -> Result<SysInfo, SnmpError> {
    let names = [
        "1.3.6.1.2.1.1.1.0",
        "1.3.6.1.2.1.1.2.0",
        "1.3.6.1.2.1.1.3.0",
        "1.3.6.1.2.1.1.4.0",
        "1.3.6.1.2.1.1.5.0",
        "1.3.6.1.2.1.1.6.0",
        "1.3.6.1.2.1.1.7.0",
    ];
    let oids: Vec<Oid> = names.iter().map(|n| o(n)).collect();
    let got = client.get(&oids).await?;
    let value = |i: usize| got.get(i).map(|(_, v)| v).filter(|v| !v.is_missing());
    let text = |i: usize| value(i).and_then(Value::as_text).filter(|t| !t.is_empty());
    Ok(SysInfo {
        descr: text(0),
        object_id: match value(1) {
            Some(Value::Oid(oid)) => Some(oid.to_string()),
            _ => None,
        },
        uptime_secs: value(2).and_then(Value::as_u64).map(|ticks| ticks / 100),
        contact: text(3),
        name: text(4),
        location: text(5),
        services: value(6)
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        cpu_percent: None,
        memory_percent: None,
        temperature_c: None,
        updated: now,
    })
}

/// Counters and state of every interface.
///
/// # Errors
/// The device did not answer the first request.
pub async fn interfaces(client: &mut Client) -> Result<Vec<IfReading>, SnmpError> {
    let descr = column(client, "1.3.6.1.2.1.2.2.1.2", 1024).await?;
    let speed = column(client, "1.3.6.1.2.1.2.2.1.5", 1024)
        .await
        .unwrap_or_default();
    let admin = column(client, "1.3.6.1.2.1.2.2.1.7", 1024)
        .await
        .unwrap_or_default();
    let oper = column(client, "1.3.6.1.2.1.2.2.1.8", 1024)
        .await
        .unwrap_or_default();
    let in32 = column(client, "1.3.6.1.2.1.2.2.1.10", 1024)
        .await
        .unwrap_or_default();
    let out32 = column(client, "1.3.6.1.2.1.2.2.1.16", 1024)
        .await
        .unwrap_or_default();
    let in_disc = column(client, "1.3.6.1.2.1.2.2.1.13", 1024)
        .await
        .unwrap_or_default();
    let in_err = column(client, "1.3.6.1.2.1.2.2.1.14", 1024)
        .await
        .unwrap_or_default();
    let out_disc = column(client, "1.3.6.1.2.1.2.2.1.19", 1024)
        .await
        .unwrap_or_default();
    let out_err = column(client, "1.3.6.1.2.1.2.2.1.20", 1024)
        .await
        .unwrap_or_default();
    // The extension table: names, aliases, high-speed counters (not on every device).
    let name = column(client, "1.3.6.1.2.1.31.1.1.1.1", 1024)
        .await
        .unwrap_or_default();
    let alias = column(client, "1.3.6.1.2.1.31.1.1.1.18", 1024)
        .await
        .unwrap_or_default();
    let high_speed = column(client, "1.3.6.1.2.1.31.1.1.1.15", 1024)
        .await
        .unwrap_or_default();
    let in64 = column(client, "1.3.6.1.2.1.31.1.1.1.6", 1024)
        .await
        .unwrap_or_default();
    let out64 = column(client, "1.3.6.1.2.1.31.1.1.1.10", 1024)
        .await
        .unwrap_or_default();
    let mut out = Vec::new();
    for (index, label) in &descr {
        let key = index.clone();
        let number = |m: &BTreeMap<Vec<u32>, Value>| m.get(&key).and_then(Value::as_u64);
        let status = |m: &BTreeMap<Vec<u32>, Value>| m.get(&key).and_then(Value::as_i64) == Some(1);
        let (in_octets, out_octets, bits) = match (number(&in64), number(&out64)) {
            (Some(i), Some(o)) => (i, o, 64),
            _ => (number(&in32).unwrap_or(0), number(&out32).unwrap_or(0), 32),
        };
        let speed_bps = number(&high_speed)
            .filter(|mbps| *mbps > 0)
            .map(|mbps| mbps.saturating_mul(1_000_000))
            .or_else(|| number(&speed).filter(|s| *s > 0 && *s < u64::from(u32::MAX)));
        out.push(IfReading {
            index: i64::from(*index.last().unwrap_or(&0)),
            name: name
                .get(&key)
                .and_then(Value::as_text)
                .filter(|n| !n.is_empty())
                .or_else(|| label.as_text())
                .unwrap_or_default(),
            alias: alias.get(&key).and_then(Value::as_text).unwrap_or_default(),
            speed_bps,
            admin_up: status(&admin),
            oper_up: status(&oper),
            in_octets,
            out_octets,
            in_errors: number(&in_err).unwrap_or(0),
            out_errors: number(&out_err).unwrap_or(0),
            in_discards: number(&in_disc).unwrap_or(0),
            out_discards: number(&out_disc).unwrap_or(0),
            counter_bits: bits,
        });
    }
    out.sort_by_key(|r| r.index);
    Ok(out)
}

/// The multiplier a sensor's scale code stands for (ENTITY-SENSOR-MIB `entPhySensorScale`).
#[must_use]
pub fn sensor_scale(code: i64) -> f64 {
    match code {
        1 => 1e-24,
        2 => 1e-21,
        3 => 1e-18,
        4 => 1e-15,
        5 => 1e-12,
        6 => 1e-9,
        7 => 1e-6,
        8 => 1e-3,
        10 => 1e3,
        11 => 1e6,
        12 => 1e9,
        13 => 1e12,
        14 => 1e15,
        15 => 1e18,
        16 => 1e21,
        17 => 1e24,
        _ => 1.0,
    }
}

/// The mean of processor loads, or `None` without any.
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn mean_load(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(values.iter().map(|v| (*v).min(100) as f64).sum::<f64>() / values.len() as f64)
}

/// Processor, memory and temperature, where the device offers them. Each is optional.
pub async fn resources(client: &mut Client, sys: &mut SysInfo) {
    // CPU: the standard processor table, then the UCD idle counter.
    if let Ok(loads) = column(client, "1.3.6.1.2.1.25.3.3.1.2", 128).await {
        let values: Vec<u64> = loads.values().filter_map(Value::as_u64).collect();
        sys.cpu_percent = mean_load(&values);
    }
    if sys.cpu_percent.is_none()
        && let Ok(got) = client.get(&[o("1.3.6.1.4.1.2021.11.11.0")]).await
        && let Some(idle) = got.first().and_then(|(_, v)| v.as_u64())
    {
        sys.cpu_percent = Some(100.0 - (idle.min(100) as f64));
    }
    // Memory: the UCD memory group (total, available, buffers, cached), then hrStorage RAM.
    if let Ok(got) = client
        .get(&[
            o("1.3.6.1.4.1.2021.4.5.0"),
            o("1.3.6.1.4.1.2021.4.6.0"),
            o("1.3.6.1.4.1.2021.4.14.0"),
            o("1.3.6.1.4.1.2021.4.15.0"),
        ])
        .await
    {
        let n = |i: usize| got.get(i).and_then(|(_, v)| v.as_u64());
        if let (Some(total), Some(avail)) = (n(0), n(1))
            && total > 0
        {
            let free = avail
                .saturating_add(n(2).unwrap_or(0))
                .saturating_add(n(3).unwrap_or(0));
            // No free memory at all is how agents that do not track it (some BSDs) answer: it is
            // not a measurement.
            if free > 0 {
                sys.memory_percent =
                    Some(100.0 * (total.saturating_sub(free.min(total))) as f64 / total as f64);
            }
        }
    }
    if sys.memory_percent.is_none()
        && let (Ok(kinds), Ok(units), Ok(size), Ok(used)) = (
            column(client, "1.3.6.1.2.1.25.2.3.1.2", 256).await,
            column(client, "1.3.6.1.2.1.25.2.3.1.4", 256).await,
            column(client, "1.3.6.1.2.1.25.2.3.1.5", 256).await,
            column(client, "1.3.6.1.2.1.25.2.3.1.6", 256).await,
        )
    {
        let ram = o("1.3.6.1.2.1.25.2.1.2");
        for (index, kind) in kinds {
            if matches!(kind, Value::Oid(ref oid) if *oid == ram) {
                let total = size.get(&index).and_then(Value::as_u64).unwrap_or(0);
                let taken = used.get(&index).and_then(Value::as_u64).unwrap_or(0);
                let _unit = units.get(&index);
                if total > 0 {
                    sys.memory_percent = Some((100.0 * taken as f64 / total as f64).min(100.0));
                }
                break;
            }
        }
    }
    // Temperature: the hottest standard sensor reporting degrees Celsius.
    if let (Ok(kinds), Ok(scales), Ok(precisions), Ok(values)) = (
        column(client, "1.3.6.1.2.1.99.1.1.1.1", 256).await,
        column(client, "1.3.6.1.2.1.99.1.1.1.2", 256).await,
        column(client, "1.3.6.1.2.1.99.1.1.1.3", 256).await,
        column(client, "1.3.6.1.2.1.99.1.1.1.4", 256).await,
    ) {
        let hottest = kinds
            .iter()
            .filter(|(_, kind)| kind.as_i64() == Some(8))
            .filter_map(|(index, _)| {
                let raw = values.get(index).and_then(Value::as_i64)? as f64;
                let scale = sensor_scale(scales.get(index).and_then(Value::as_i64).unwrap_or(9));
                let precision = precisions.get(index).and_then(Value::as_i64).unwrap_or(0);
                let degrees = raw * scale / 10f64.powi(i32::try_from(precision).unwrap_or(0));
                (-60.0..=250.0).contains(&degrees).then_some(degrees)
            })
            .fold(None, |best: Option<f64>, d| {
                Some(best.map_or(d, |b| b.max(d)))
            });
        if hottest.is_some() {
            sys.temperature_c = hottest;
        }
    }
}

/// A neighbor a device reports over LLDP.
#[derive(Clone, Debug, PartialEq)]
pub struct LldpNeighbor {
    /// The reporting device's own port.
    pub local_port: String,
    pub chassis_mac: Option<Mac>,
    pub chassis: String,
    pub remote_port: String,
    pub sys_name: Option<String>,
    pub address: Option<IpAddr>,
}

fn chassis_text(subtype: i64, raw: &[u8]) -> (Option<Mac>, String) {
    if subtype == 4 && raw.len() == 6 {
        let mac: Mac = raw.try_into().expect("six bytes");
        let text = crate::oui::format_mac(&mac);
        return (Some(mac).filter(is_usable), text);
    }
    (
        None,
        String::from_utf8_lossy(raw)
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect(),
    )
}

/// The management address in an LLDP address-table row index: `... subtype, length, bytes...`.
#[must_use]
pub fn lldp_address(index: &[u32]) -> Option<(Vec<u32>, IpAddr)> {
    // timeMark, localPort, remIndex, subtype, length, bytes
    let subtype = *index.get(3)?;
    let length = usize::try_from(*index.get(4)?).ok()?;
    let bytes: Vec<u8> = index
        .get(5..5 + length)?
        .iter()
        .map(|b| u8::try_from(*b).ok())
        .collect::<Option<_>>()?;
    let ip = match (subtype, bytes.len()) {
        (1, 4) => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
        (2, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes.as_slice()).ok()?)),
        _ => return None,
    };
    Some((index[..3].to_vec(), ip))
}

/// What the device's LLDP table says is connected to its ports.
///
/// # Errors
/// The device did not answer, or does not run LLDP (an empty table is not an error).
pub async fn lldp(client: &mut Client) -> Result<Vec<LldpNeighbor>, SnmpError> {
    let chassis_kind = column(client, "1.0.8802.1.1.2.1.4.1.1.4", 512).await?;
    let chassis = column(client, "1.0.8802.1.1.2.1.4.1.1.5", 512)
        .await
        .unwrap_or_default();
    let port = column(client, "1.0.8802.1.1.2.1.4.1.1.7", 512)
        .await
        .unwrap_or_default();
    let port_desc = column(client, "1.0.8802.1.1.2.1.4.1.1.8", 512)
        .await
        .unwrap_or_default();
    let name = column(client, "1.0.8802.1.1.2.1.4.1.1.9", 512)
        .await
        .unwrap_or_default();
    let local_id = column(client, "1.0.8802.1.1.2.1.3.7.1.3", 512)
        .await
        .unwrap_or_default();
    let local_desc = column(client, "1.0.8802.1.1.2.1.3.7.1.4", 512)
        .await
        .unwrap_or_default();
    let mut addresses: HashMap<Vec<u32>, IpAddr> = HashMap::new();
    if let Ok(rows) = column(client, "1.0.8802.1.1.2.1.4.2.1.3", 512).await {
        for index in rows.keys() {
            if let Some((row, ip)) = lldp_address(index) {
                addresses.entry(row).or_insert(ip);
            }
        }
    }
    let mut out = Vec::new();
    for (index, kind) in &chassis_kind {
        // timeMark, localPortNum, remIndex
        let local_num = *index.get(1).unwrap_or(&0);
        let local = local_desc
            .get(&one(i64::from(local_num)))
            .or_else(|| local_id.get(&one(i64::from(local_num))))
            .and_then(Value::as_text)
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| format!("port {local_num}"));
        let (mac, chassis_text) = chassis_text(
            kind.as_i64().unwrap_or(0),
            chassis.get(index).and_then(Value::as_bytes).unwrap_or(&[]),
        );
        let remote_port = port_desc
            .get(index)
            .and_then(Value::as_text)
            .filter(|t| !t.is_empty())
            .or_else(|| match port.get(index) {
                Some(Value::Text(raw))
                    if raw.len() == 6 && raw.iter().any(|b| !b.is_ascii_graphic()) =>
                {
                    Some(crate::oui::format_mac(
                        &raw.as_slice().try_into().expect("six bytes"),
                    ))
                }
                Some(v) => v.as_text(),
                None => None,
            })
            .unwrap_or_default();
        out.push(LldpNeighbor {
            local_port: local,
            chassis_mac: mac,
            chassis: chassis_text,
            remote_port,
            sys_name: name
                .get(index)
                .and_then(Value::as_text)
                .filter(|t| !t.is_empty()),
            address: addresses.get(index).copied(),
        });
    }
    Ok(out)
}

/// A hardware address a bridge has learned on a port.
#[derive(Clone, Debug, PartialEq)]
pub struct FdbEntry {
    pub mac: Mac,
    /// The IF-MIB index of the port, or the bridge port number when the map is missing.
    pub if_index: i64,
}

fn mac_from_arcs(arcs: &[u32]) -> Option<Mac> {
    if arcs.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (slot, arc) in mac.iter_mut().zip(arcs) {
        *slot = u8::try_from(*arc).ok()?;
    }
    Some(mac).filter(is_usable)
}

/// The bridge's forwarding table: which hardware addresses it has learned on which port.
///
/// # Errors
/// The device did not answer, or has no bridge MIB.
pub async fn forwarding_table(client: &mut Client) -> Result<Vec<FdbEntry>, SnmpError> {
    let mut found: Vec<(Mac, i64)> = Vec::new();
    // Q-BRIDGE: index is the FDB id followed by the six bytes of the address.
    for (index, port) in column(client, "1.3.6.1.2.1.17.7.1.2.2.1.2", 4096)
        .await
        .unwrap_or_default()
    {
        if index.len() == 7
            && let (Some(mac), Some(p)) = (mac_from_arcs(&index[1..]), port.as_i64())
        {
            found.push((mac, p));
        }
    }
    if found.is_empty() {
        for (index, port) in column(client, "1.3.6.1.2.1.17.4.3.1.2", 4096).await? {
            if let (Some(mac), Some(p)) = (mac_from_arcs(&index), port.as_i64()) {
                found.push((mac, p));
            }
        }
    }
    let ports = column(client, "1.3.6.1.2.1.17.1.4.1.2", 1024)
        .await
        .unwrap_or_default();
    Ok(found
        .into_iter()
        .filter(|(_, port)| *port > 0)
        .map(|(mac, port)| FdbEntry {
            mac,
            if_index: ports
                .get(&one(port))
                .and_then(Value::as_i64)
                .unwrap_or(port),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processor_loads_average_and_clamp() {
        assert_eq!(mean_load(&[]), None);
        assert_eq!(mean_load(&[10, 30]), Some(20.0));
        assert_eq!(
            mean_load(&[250, 0]),
            Some(50.0),
            "a nonsense value is capped at 100"
        );
    }

    #[test]
    fn sensor_scales_follow_the_mib() {
        assert!((sensor_scale(8) - 0.001).abs() < 1e-12);
        assert!((sensor_scale(9) - 1.0).abs() < 1e-12);
        assert!((sensor_scale(10) - 1000.0).abs() < 1e-9);
    }

    #[test]
    fn lldp_management_addresses_come_from_the_row_index() {
        let v4 = [0, 7, 1, 1, 4, 192, 168, 1, 2];
        let (row, ip) = lldp_address(&v4).unwrap();
        assert_eq!(
            (row, ip.to_string()),
            (vec![0, 7, 1], "192.168.1.2".to_owned())
        );
        let mut v6 = vec![0, 7, 1, 2, 16];
        v6.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(lldp_address(&v6).unwrap().1.to_string(), "fd00::1");
        assert!(
            lldp_address(&[0, 7, 1, 6, 6, 1, 2, 3, 4, 5, 6]).is_none(),
            "a non-IP address"
        );
        assert!(lldp_address(&[0, 7, 1, 1, 4, 192, 168, 300, 2]).is_none());
        assert!(lldp_address(&[0, 7]).is_none());
    }

    #[test]
    fn chassis_ids_that_are_macs_are_recognized() {
        let (mac, text) = chassis_text(4, &[0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6]);
        assert_eq!(mac, Some([0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6]));
        assert_eq!(text, "00:1b:63:84:45:e6");
        let (mac, text) = chassis_text(7, b"switch-1");
        assert_eq!((mac, text.as_str()), (None, "switch-1"));
        assert_eq!(
            mac_from_arcs(&[0, 0x1b, 0x63, 0x84, 0x45, 0xe6]),
            Some([0, 0x1b, 0x63, 0x84, 0x45, 0xe6])
        );
        assert_eq!(mac_from_arcs(&[0, 1, 2, 3, 4, 300]), None);
        assert_eq!(mac_from_arcs(&[255; 6]), None, "broadcast is no device");
    }
}

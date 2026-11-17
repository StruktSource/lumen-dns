# Network discovery, devices, topology, and monitoring

The **Network** module finds the devices on the networks you name, keeps an inventory of them, draws how they connect, and tells you when one stops answering. It is a **module**: it is **off by default**, and nothing is probed until you list the networks to look at. It only ever **reads**: Lumen never changes a device, never sends an SNMP `SET`, and never configures a switch or a router.

The inventory lives in the web console's state database, next to [IPAM](ipam.md). Discovery and monitoring run in the daemon, so the module needs [managed mode](managed-mode.md) (`--state`).

## What it does

| Part | Behavior |
| :--- | :--- |
| Discovery | Finds devices with the system's ARP and NDP neighbor tables, ICMP echo (IPv4 hosts one by one, IPv6 links through the all-nodes group), your [DHCP](dhcp.md) leases, reverse DNS, and SNMP. A run starts when you ask, and on a schedule if you set one. Only addresses in your scopes are probed, learned, or stored. |
| One entry per device | A device seen by several methods is one entry: it is matched by hardware address first, then by IP address. A device with several addresses (IPv4 and IPv6, a link-local address) is one entry. If two entries turn out to be the same device, they are merged. If an address changes hands between two devices that each have their own hardware address, the address moves and they stay two. |
| Gone devices | A device not seen in the networks of a run counts as a miss. After `gone_after_scans` misses in a row it is marked **gone**. It is hidden by default, never deleted, keeps all its data, and comes back by itself when it is seen again. |
| Device details | Name, host name, addresses, hardware addresses, manufacturer (from the IEEE registry), type, operating system, icon, description, notes, first and last seen, location, subnet, and VLAN. Types are guessed from the manufacturer, the name, and what SNMP reports. You can always set your own. |
| What you set stays | Anything you edit is locked against discovery. Fields you leave alone keep following what discovery learns. Merging never loses what you set. |
| IPAM link | A device's subnet and VLAN come from [IPAM](ipam.md) by its address, locations come from IPAM, and **Record in IPAM** adds a device's address to the inventory. |
| Topology | A map of devices and the links between them, with zoom, pan, filters, and click-through to the device. See [Topology](#topology). |
| SNMP | v2c and v3. System facts, interfaces (state, speed, traffic rates, errors, discards, utilization), CPU, memory, temperature, LLDP neighbors, and bridge forwarding tables, all from standard MIBs. See [SNMP](#snmp). |
| Availability | Regular ICMP, TCP, or SNMP checks with a failure threshold, response times, packet loss, history, and events when a device goes offline, recovers, or starts losing packets. See [Availability](#availability-monitoring). |

## Turn it on

1. In the console, open **Modules** and switch **Network** on. A **Network** page appears. You can add devices by hand right away.
2. For discovery and monitoring, list the networks to look at in the configuration and apply it:

```toml
[network]
enabled = true
scan_interval_secs = 3600          # 0: only when you press Run discovery now

[[network.scopes]]
name = "Home"
networks = ["192.168.1.0/24", "fd00:1::/64"]
exclude = ["192.168.1.1/32"]       # never probed, learned, or stored
interface = "eth0"                 # needed for IPv6 networks
# snmp_profile = "core"
```

Without `enabled = true` and at least one scope, nothing is probed. IPv4 scopes can be as large as a `/16` (and at most 262,144 addresses in all); an IPv6 scope is learned from the neighbor table and an all-nodes ping on its interface, and is never swept.

## Discovery

| Method | What it learns | Notes |
| :--- | :--- | :--- |
| Neighbor tables | Hardware addresses of devices on the link, for IPv4 (ARP) and IPv6 (NDP), and the other addresses of the same device | Read with `ip`, `arp`, and `ndp`, run without a shell, or `/proc/net/arp`. Only this machine's own link is visible. |
| ICMP echo | Which addresses answer | Uses the unprivileged "ping" socket. On Linux the account must be allowed by `net.ipv4.ping_group_range`. Without it, discovery still uses the neighbor table and DHCP, and the console says so. |
| DHCP | Addresses, hardware addresses, and host names of leases | A lease alone is not a sighting: it creates or updates a device but does not mark it present. |
| DNS | Host names, by reverse lookup of addresses that have none | Asks Lumen's own resolver, so local zones and DHCP and IPAM names answer. |
| SNMP | Name, description, uptime, and type of devices in a scope with an SNMP profile | Off unless `methods.snmp = true`. |

**Service managers.** The packaged systemd unit allows only `AF_INET` and `AF_INET6`. That is enough for ICMP, TCP, and SNMP, but `ip neigh` needs a netlink socket, so on Linux the unit reads IPv4 neighbors from `/proc/net/arp` only. To read IPv6 neighbors too, add `AF_NETLINK` to `RestrictAddressFamilies` in a drop-in. Ping also needs the account's group to fall in `net.ipv4.ping_group_range`.

A device found by a neighbor table entry is **present** but not necessarily awake: its state stays **unknown** until a ping, a connection, or an SNMP answer shows it is up, because many phones never answer a ping and a neighbor entry can linger. A device that answers a ping is **online**.

Probes are bounded and spread out: `concurrency` probes in flight (default 32), at most `packets_per_second` (default 100) across everything, `timeout_ms` to wait (default 800), and the total sweep size above. A run on a `/24` is a few seconds.

Reverse DNS and SNMP run for at most a few hundred addresses per run, a few at a time.

## Devices

The **Devices** tab lists every device. Search matches names, addresses, hardware addresses, manufacturers, and descriptions. Filter by type, status, subnet, VLAN, or location, sort by last seen, name, address, status, type, or first seen, and group by type, status, subnet, VLAN, or location. Open a device for its details, addresses, recent checks, SNMP facts, interfaces with traffic rates, connections, and history.

- **Add or edit** a device, including several IP addresses and hardware addresses, a type, an icon, notes, a location, and how it is monitored.
- **Merge** two entries that are the same device. The one you choose to keep keeps what you set.
- **Remove an address** from a device to correct a wrong match.
- **Delete** a device and its history. If it is still on the network, discovery may add it again.
- A device with no address can exist, but is not checked.

Device data stays when a device is offline or gone.

## Topology

The **Topology** tab draws devices (circles with an icon, a status color, and the name) and the links between them. Zoom with the wheel or the buttons, drag the background to pan, press **Fit** to see everything, and click a device to open it. Filter by subnet, VLAN, location, or type. Devices with no known link are set apart below the rest.

**Pings and neighbor tables cannot show how devices are wired.** So a link is drawn **solid (confirmed)** only when a device reported it or you added it:

| Link | Source |
| :--- | :--- |
| Confirmed, "Reported by a device" | LLDP: a switch or router lists its neighbors and ports over SNMP. |
| Confirmed, "Set by you" | You added or corrected it. |
| **Dashed, "Inferred"** | A switch's forwarding table shows exactly one known hardware address on a port. That is probably the device on that port, but it can be behind another switch. Correct it to confirm it. |

Add, correct, and remove links by hand (click a link). A corrected link becomes a confirmed one. With **Show speed and use**, links show their speed and the utilization of the busier end, colored green, amber, or red.

## SNMP

SNMP profiles say how to talk to devices. A profile applies to a scope (`snmp_profile`) or to one device (set it in the device's form). **Prefer SNMPv3 with authentication and privacy.**

```toml
[[network.snmp_profiles]]
name = "core"
version = "v3"
username = "lumen"
auth_protocol = "sha256"            # sha1, sha256, sha384, sha512
auth_password_file = "snmp-auth.pw" # mode 0600, at least 8 characters
privacy_protocol = "aes128"
privacy_password_file = "snmp-priv.pw"
# port = 161
# timeout_ms = 1500
# retries = 1

[[network.snmp_profiles]]
name = "legacy"
version = "v2c"
community_file = "snmp-community"   # mode 0600
```

**Secrets never appear in the configuration or the database.** Each profile names a file; Lumen reads it at start, keeps it in memory, and refuses to start if the file is readable by others (mode `0600` on Unix). v3 supports no authentication, authentication, and authentication with AES-128 privacy (RFC 3414, RFC 3826, RFC 7860). MD5 and DES are not offered. Use a read-only SNMP user on the device.

Polling happens every `snmp_interval_secs` (default 300), one device at a time per slot and at most eight at once. From standard MIBs, with no vendor-specific code:

| Data | Source |
| :--- | :--- |
| Name, description, contact, location, uptime, services | SNMPv2-MIB |
| Interface state, speed, traffic counters (64-bit when available), errors, discards | IF-MIB |
| CPU | HOST-RESOURCES (processor load), then the net-snmp CPU counters |
| Memory | net-snmp memory counters, then HOST-RESOURCES storage |
| Temperature | ENTITY-SENSOR (the hottest sensor in degrees Celsius) |
| Neighbors | LLDP-MIB |
| Learned hardware addresses | Q-BRIDGE-MIB or BRIDGE-MIB |

Rates come from counter changes between polls and handle 32-bit wraps; a counter that goes backwards (a reboot) gives no rate for that poll. A device that stops answering is reported once after three failed polls, and once when it answers again. Walks are bounded (8,192 rows).

## Availability monitoring

Every device with an address is checked every `monitor.interval_secs` (default 60; set a different interval per device), unless you turn monitoring off for it. A check sends `probes_per_check` probes (default 3) and passes if any is answered. Methods: **ICMP**, **TCP** (a connection to a port you choose), or **SNMP** (an answer to `sysUpTime`).

| State | Meaning |
| :--- | :--- |
| Online | Answers. |
| Degraded | Answers, but recent checks lose at least `degraded_loss_percent` of their probes (default 20). |
| Offline | `failures_before_offline` checks in a row failed (default 3). One lost packet is never an outage. |
| Unknown | Nothing is known yet. |

A device comes back **online** on its first answer, and the outage's failed checks are not counted as packet loss. Each change adds an event (offline, recovered, degraded, back to normal), and the device shows its last answer, response times, packet loss, a strip of recent checks, and its availability over 24 hours and 7 days. History is kept for `retention_days` (default 30). First checks are spread out so a restart is not a burst of probes. A check that this machine cannot run at all (no ICMP, for instance) is skipped, never counted as the device being down.

## Management API

Everything the console does is also available under `/v1/network` with a bearer token: see the [Management API](../reference/management-api.md#network). Viewers read, operators can ask for a discovery run, and administrators change devices and links. A discovery request is picked up by the running daemon within a few seconds.

## Limits and not included

- 20,000 devices and 50,000 links. Names are limited to 64 characters, descriptions to 500, notes to 2,000.
- Only this machine's link shows in the neighbor tables. Devices on other networks are found by ping and, with an SNMP profile, by the neighbor and forwarding tables of the routers and switches that profile can read.
- Not included: CDP, a vendor-specific protocol integration, SNMP traps and `SET`, flow data, device configuration or backup, and e-mail or push notifications. Events are shown in the console and kept for the retention period. (Audit entries for changes to the inventory go to the audit log, and [webhooks](../reference/management-api.md#signed-webhooks) carry management-API activity.)
- The Network page is English-only for now.

## Data

Manufacturer names come from the public IEEE registry (MA-L), included at build time (about 40,000 entries, fetched 2026-11-17). Set `oui_file` to an `oui.txt` from IEEE to add or override entries.

## Related

- [IP address management](ipam.md)
- [DHCP server](dhcp.md)
- [Web console](web-console.md#modules)
- [Management API](../reference/management-api.md)
- [Configuration reference](../reference/configuration.md#network)

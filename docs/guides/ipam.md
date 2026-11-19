# IP address management (IPAM)

IPAM is Lumen's **inventory of your network addressing**: the subnets you manage, the VLANs and locations they belong to, and which addresses are assigned, reserved, or leased. It is a **module**: it is **off by default** and you switch it on under **Modules** in the web console.

**IPAM is bookkeeping.** Assigning an address here never configures a device, never creates a DHCP lease, and never touches a network interface, a route, or a VLAN. You still set the address on the device (or let your DHCP server do it). IPAM records the decision, shows you what is left, and keeps two people from choosing the same address.

It works with or without the [DHCP server](dhcp.md). With it, leases show up in the inventory and are never handed out by IPAM. Without it (static addresses, or another DHCP server), IPAM is just the inventory.

## What it does

| Part | Behavior |
| :--- | :--- |
| Subnets | IPv4 (`/8` to `/32`) and IPv6 (`/16` to `/128`) in CIDR notation. A subnet inside another nests under it. The network is fixed once created; host bits are cleared (`10.1.5.77/24` becomes `10.1.5.0/24`). Each subnet has a name, description, group, optional gateway, up to 16 `key=value` metadata entries, a VLAN, and a location. The same network cannot be added twice. |
| Addresses | `assigned` (given to a device by hand), `reserved` (held back), `leased` (DHCP, read-only), and `available`. Each recorded address can have a host name, device, description, and location. Network and broadcast addresses cannot be recorded. An address always belongs to the most specific subnet that contains it. |
| Utilization | Per subnet: assigned, reserved, leased, delegated to smaller subnets inside it, free, and percent used. A gateway nobody recorded counts as reserved. IPv6 sizes are exact. |
| VLANs | ID 1 to 4094, name, description, location. The same ID can exist once per location (and once with no location), so two sites can each have a VLAN 10. |
| Locations | A tree of sites, buildings, floors, rooms, and racks. A location cannot be removed while anything uses it, and cannot be moved inside itself. |
| Allocation | **Allocate the next free address** from a subnet: the lowest, the highest, or any free one. It skips recorded addresses, DHCP leases, the gateway, the network and broadcast addresses, and everything inside a smaller subnet. Two requests at the same moment can never receive the same address. |
| Conflicts | An address IPAM holds that DHCP also leases, and a name IPAM gave to one address that DHCP gave to another. |
| DNS | Optional. An address with a host name and **Publish in DNS** on becomes `name.<ipam.dns_domain>` (`A` or `AAAA`) with a matching `PTR`. Only those names are touched; your own zones and records are never changed. |
| Storage | In the web console's state database, so it survives restarts and is included wherever you keep that file. |

## Turn it on

1. In the console, open **Modules** and switch **IPAM** on. An **IPAM** page appears in the sidebar.
2. Optional, for DNS names: set a domain in the configuration and apply it.

```toml
[ipam]
dns_domain = "net.home.example"   # names become host.net.home.example
```

The domain must not be `.local` or under `.arpa`, and must not overlap a configured zone, `dhcp.domain`, or `mdns.domain`. Without it, **Publish in DNS** is refused with a message that says why.

## The IPAM page

| Tab | Use it to |
| :--- | :--- |
| **Overview** | See subnet and address totals, utilization bars, and any conflicts. |
| **Subnets** | Add, edit, and delete subnets, and allocate an address from one. |
| **IP addresses** | Search and filter by subnet, state, location, or text; assign or reserve an address; allocate the next free one; release one. Choose a subnet and **Available** to list its free addresses. |
| **VLANs** | Manage VLAN IDs and see which subnets use each. |
| **Locations** | Build the location tree. |

Deleting something that is still used is refused with a reason: a subnet that holds addresses or smaller subnets, a VLAN that subnets use, a location that anything refers to. Releasing an address only removes it from the inventory.

## DHCP and DNS together

- **DHCP leases** are shown in the inventory and counted in utilization. IPAM refuses to assign or allocate an address a lease holds, and the next free address skips leased ones. Leases the DHCP server holds are read from the running server; if the server stops, IPAM stops considering them.
- **If DHCP gives out an address IPAM already holds**, the **Overview** lists it as a conflict. Keep your DHCP ranges and your static addresses apart; IPAM does not change DHCP scopes.
- **DNS names** are separate from the DHCP names. If IPAM and DHCP both name the same address, the DHCP name answers first.

## Management API

The same inventory is available to scripts through the [management API](../reference/management-api.md#ipam) with a bearer token: viewers read, operators assign, reserve, allocate, and release addresses, and administrators change subnets, VLANs, and locations. Allocation is atomic. Changes made through the API reach DNS and the DHCP-lease check within a few seconds, because the running daemon applies them.

## Limits

5,000 subnets, 5,000 VLANs, 5,000 locations, and 200,000 recorded addresses. Names are limited to 64 characters and descriptions to 500. IPv6 subnets are never listed address by address: only recorded and leased addresses appear, and allocation finds a free address without scanning.

## Not included

- IPAM does not configure addresses on devices, create DHCP leases or reservations, scan the network, or change routing and VLANs on switches. (Network discovery is a separate, planned feature.)
- Subnets cannot overlap with the same network twice, so separate routing domains (VRFs) with the same addresses are not modeled.
- The web console's text is English for now; the new IPAM page is not translated yet.

## Related

- [DHCP server](dhcp.md)
- [Your own DNS zones](authoritative-dns.md)
- [Web console](web-console.md#modules)
- [Management API](../reference/management-api.md)
- [Configuration reference](../reference/configuration.md#ipam)

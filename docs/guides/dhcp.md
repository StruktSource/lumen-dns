# DHCP server (IPv4 and IPv6)

Lumen can hand out addresses on your network, and turn every lease into a DNS name. A phone that joins and calls itself `Pixel` becomes `pixel.home.lan` the moment it has an address, forward and reverse, and the name disappears when the lease ends. It is a **module**: it is **off by default**, and Lumen never serves an address until you enable it and name the network it may serve.

**Important.** A network should have exactly one DHCP server. Turn the one in your router off (or limit it to other addresses) before you turn this one on.

## What it does

| Part | Behavior |
| :--- | :--- |
| IPv4 | DISCOVER, OFFER, REQUEST, ACK/NAK, RELEASE, DECLINE and INFORM (RFC 2131), with relay agents (`giaddr`). Subnet mask, broadcast address, router, DNS servers, domain name, lease time, and renew/rebind timers. |
| IPv6 | Stateful `IA_NA` addresses (RFC 8415): Solicit, Advertise, Request, Renew, Rebind, Confirm, Release, Decline and Information-request, Rapid Commit, a stable server DUID, and the DNS servers option (RFC 3646). |
| Reservations | A device by hardware address (IPv4) or DUID (IPv6) always gets the same address. Nobody else is ever given a reserved address. |
| DNS names | The host name a device sends (or the reservation's name) is published under `domain` as an `A`/`AAAA` record and a `PTR` record. Names are sanitized to one safe label. |
| Storage | Leases live in a SQLite file (mode `0600`) and survive restarts. Expired leases are removed every 30 seconds, together with their DNS names. |
| Console | The optional **DHCP** module shows your networks, how full they are, and every lease. |

## Configure it

```toml
[dhcp]
enabled = true
domain = "home.lan"              # names become device.home.lan
lease_file = "dhcp-leases.db"    # required

[[dhcp.scopes]]                  # one IPv4 network
interface = "eth0"
subnet = "192.168.1.0/24"
server_address = "192.168.1.2"   # Lumen's own address here
range_start = "192.168.1.100"
range_end = "192.168.1.199"
router = "192.168.1.1"
# dns = ["192.168.1.2"]          # defaults to server_address
lease_secs = 43200

[[dhcp.scopes.reservations]]
mac = "aa:bb:cc:dd:ee:01"
ip = "192.168.1.10"
hostname = "printer"

[[dhcp.scopes6]]                 # one IPv6 network
interface = "eth0"
prefix = "fd00:1::/64"
range_start = "fd00:1::100"
range_end = "fd00:1::1ff"
dns = ["fd00:1::2"]
preferred_secs = 21600
valid_secs = 43200

[[dhcp.scopes6.reservations]]
duid = "00010001aabbccdd"
ip = "fd00:1::10"
```

Check it with `lumen --config lumen.toml --check`. Every address is checked against its network: the range must be inside the subnet and must not contain the server address, reservations must be unique and inside the subnet, and scopes must not overlap.

Binding to port 67 (IPv4) and 547 (IPv6) needs privileges. Use the capability `CAP_NET_BIND_SERVICE` (the native packages and the container examples already grant it for DNS on port 53), or run as root. On Linux and macOS each IPv4 scope is tied to its interface so a request on one network is never answered from another. With more than one IPv4 scope, each needs its own `interface`. Other systems can serve a single scope.

## Names in DNS

Lumen answers the leased names itself, from memory, with a 30-second TTL. They are served for any client that may query Lumen. A `domain` must not overlap a configured `[[zones]]` zone. Reverse names (`in-addr.arpa`, `ip6.arpa`) are answered for leased addresses only. Your own zone files remain the place for names that never change.

Clients that send a host name (DHCP option 12, or the `FQDN` option on IPv6) get a name. A client with no name gets an address and no DNS entry. Two devices with the same name share it, and both addresses answer.

## Limits and good behavior

- At most 16 scopes of each family, 65,536 addresses per range, and 512 reservations per scope.
- An offered address is held for 60 seconds for the device it was offered to. A declined address (the device found it already in use) rests for 10 minutes. A device that asks again keeps its address.
- A request that names another server is ignored, and an unknown device never gets a reserved address.
- Packets are small and parsed with bounds. Malformed packets are dropped without an answer.
- Nothing is sent from `0.0.0.0` unless a client without an address asked. IPv4 replies to such a client are broadcast, as the protocol requires.

## Not included

DHCPv6 prefix delegation (`IA_PD`) and temporary addresses (`IA_TA`), DHCPv6 relay agents, Reconfigure, failover between two servers, dynamic DNS updates to other servers (the names are served by Lumen itself), and BOOTP/PXE options. Say so on the [roadmap](../project/roadmap.md) if you need one.

## The console module

Switch **DHCP** on under **Modules** (administrators only). The page lists each network with how many addresses are in use, and every current lease with its name, device and expiry. It is read-only: the configuration file decides what is served. The module shows nothing while the server is not enabled in the configuration.

## Related

- [Your own DNS zones](authoritative-dns.md)
- [Configuration reference](../reference/configuration.md#dhcp)
- [Threat model](../design/threat-model.md)

# DHCP server (IPv4 and IPv6)

Lumen can hand out addresses on your network, and turn every lease into a DNS name. A phone that joins and calls itself `Pixel` becomes `pixel.home.lan` the moment it has an address, forward and reverse, and the name disappears when the lease ends. It is a **module**: it is **off by default**, and Lumen never serves an address until you enable it and name the network it may serve.

**Important.** A network should have exactly one DHCP server. Turn the one in your router off (or limit it to other addresses) before you turn this one on.

## What it does

| Part | Behavior |
| :--- | :--- |
| IPv4 | DISCOVER, OFFER, REQUEST, ACK/NAK, RELEASE, DECLINE and INFORM (RFC 2131), with relay agents (`giaddr`). Subnet mask, broadcast address, router, DNS servers, domain name, lease time, and renew/rebind timers. |
| IPv6 | Stateful `IA_NA` addresses (RFC 8415): Solicit, Advertise, Request, Renew, Rebind, Confirm, Release, Decline and Information-request, Rapid Commit, a stable server DUID, and the DNS servers option (RFC 3646). Relay agents are supported, and so are [prefix delegation](#prefix-delegation-ia_pd), [temporary addresses](#temporary-addresses-ia_ta) and [Reconfigure](#reconfigure). IPv4 has the matching [FORCERENEW](#reconfigure). |
| Router Advertisements | On an IPv6 network Lumen can tell devices which prefix to use, whether to ask DHCPv6, and which DNS servers to use ([Router Advertisements](#router-advertisements-ipv6)). |
| Network boot | An IPv4 scope can send a boot server and file name (`next_server`, `boot_file`) for PXE and similar. |
| Failover | Two Lumen servers can cover for each other ([failover](#failover)). |
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

Binding to port 67 (IPv4) and 547 (IPv6) needs privileges. Use the capability `CAP_NET_BIND_SERVICE` (the native packages and the container examples already grant it for DNS on port 53), or run as root.

Each IPv4 scope is tied to its network so a request on one is never answered from another. With more than one IPv4 scope, each needs its own `interface`. How it is tied depends on the system:

| System | How |
| :--- | :--- |
| Linux | The socket is bound to the interface. Several scopes work. |
| macOS | The socket is bound to the interface index. Several scopes work. |
| Windows | The socket is bound to the scope's `server_address`, which receives that network's broadcasts. Name IPv6 interfaces by their index (`interface = "12"`; see `netsh interface ipv6 show interfaces`). Several scopes work. |
| Other Unix (BSD) | One IPv4 scope only. Requests that plainly come from another network are dropped. |

The Windows and BSD paths are written for those systems' socket rules but have **not been tried on real hardware**; Linux and macOS have. Test them on a spare network before relying on them.

## Relay agents

Clients on a network with no Lumen interface of their own are reached through a relay agent (a router's DHCP relay). IPv4 scopes already answer relayed requests (`giaddr`). For IPv6, leave `interface` out of the scope: Lumen picks the scope whose `prefix` contains the relay's link address, and answers inside a Relay-reply that echoes the relay's interface-id. Chained relays work up to eight deep. Replies go back to the relay that sent the message, so the relay must be able to reach Lumen on UDP port 547.

## Prefix delegation (IA_PD)

A home or office router can ask Lumen for a whole prefix to give to its own network. Add a `delegation` to the IPv6 scope:

```toml
[dhcp.scopes6.delegation]
pool = "2001:db8:100::/40"   # the prefixes to give out
length = 56                  # each router gets a /56

[[dhcp.scopes6.delegation.reservations]]
duid = "00010001aabbccdd"
prefix = "2001:db8:100:4200::/56"
```

Prefixes are tracked like addresses: held for 60 seconds when offered, kept in the lease file, extended on renewal, freed on release or expiry, and given back to the same router when it asks again. A reserved prefix goes only to its router. `length` is at most 64 and at most 16 bits longer than the pool (at most 65,536 prefixes). The pool must not overlap the scope's own `prefix`. Lumen does **not** add routes for delegated prefixes: the router that delegates to is yours to set up (a static route to the requesting router is the usual way). Delegated prefixes appear in the console with their length and publish no DNS names.

## Temporary addresses (IA_TA)

A device that asks for temporary addresses (RFC 8415 `IA_TA`, for outgoing connections only) gets one from the scope's normal range. Unlike a permanent address it is picked **at random** from the free ones each time, so connections from different moments are harder to tie together. It is advertised and held like any lease, saved in the lease file, and freed on release or expiry. It is **never renewed** (clients ask again when it runs out) and **never published in DNS**, whatever name the device sent. A device with a reservation takes only its reserved address and gets no temporary one. There is nothing to configure: a client that asks gets one while the range has room.

## Reconfigure

Normally a client decides when to renew. The server can tell a device to renew **now**, for example after you change the DNS servers in a scope. It is **off by default**, and it works for IPv6 (Reconfigure, RFC 8415 section 18.4) and for IPv4 (FORCERENEW, RFC 3203). Turn it on per scope:

```toml
[[dhcp.scopes6]]
# ...
reconfigure = true      # IPv6

[[dhcp.scopes]]
# ...
forcerenew = true       # IPv4
```

### IPv6: Reconfigure

- A client that sends the Reconfigure Accept option is told in the Reply to accept it and receives a random 16-byte key (the Reconfigure Key authentication protocol, section 20.4). Keys are saved with the leases.
- In the console, **DHCP** lists a button **Ask to renew** next to every lease of such a device. It sends a Reconfigure message to the device's address and port 546, from port 547, signed with that key. The device then sends a Renew and picks up the new settings. An Information-request instead of a Renew is available through the API (`info_only`).
- The signature is **HMAC-MD5**, because the protocol requires it. It only proves that the message comes from the server that issued the key; it does not hide anything. Do not rely on it against an attacker who can read the DHCP exchange: that attacker can also learn the key.
- Only IPv6 devices with a permanent address can be reconfigured.

### IPv4: FORCERENEW

- A client that sends the *Forcerenew Nonce Capable* option (145, RFC 6704) with algorithm 1 gets a random 16-byte nonce in the Authentication option (90) of its ACK. The nonce is saved with the leases and dropped when the client has no lease left.
- **Ask to renew** then sends a `DHCPFORCERENEW` message (type 9) to the device's address, port 68, from port 67. It is authenticated as RFC 6704 describes: an HMAC-MD5 over the whole message, keyed with the nonce, with a replay counter that only goes up. The device checks it and sends a normal renewal.
- It protects the same way the IPv6 key does: it proves the message came from the server that handed out the nonce, and does not hide anything.
- **Many clients do not support it.** A client that never sends option 145 is never given a nonce, so Lumen cannot force it and the button is not shown. The messages are built to the RFC and checked against the RFC's construction in tests, but they have not been tried against real clients. Try your devices before you rely on it.
- A failover partner does not copy nonces. After a takeover, devices that got their nonce from the other server renew normally; they just cannot be forced until they ask again.

## Router Advertisements (IPv6)

An IPv6 device finds its network by listening for **Router Advertisements** (RA, RFC 4861), not by DHCP. DHCPv6 gives addresses, but it cannot say which prefix is on the link, and it does not tell a device where the default router is. Lumen can send the advertisements itself.

```toml
[[dhcp.router_advertisements]]
interface = "eth0"
managed = true                   # devices ask DHCPv6 for their address (the M flag)
other_config = true              # and for other settings (the O flag)
# router_lifetime_secs = 0       # 0 (default): this machine is NOT a default router
# preference = "medium"          # low, medium or high, only if it is a default router
# interval_secs = 600            # longest wait between advertisements, 4 to 1800
# mtu = 1500
# dns = ["fd00:1::2"]            # left out: the DNS servers of the DHCPv6 scope on this interface
# search = ["home.lan"]          # left out: dhcp.domain

[[dhcp.router_advertisements.prefixes]]
prefix = "fd00:1::/64"
autonomous = false               # DHCPv6 gives the addresses, so devices should not also build their own
# on_link = true
# valid_secs = 2592000           # 30 days
# preferred_secs = 604800        # 7 days

# [[dhcp.router_advertisements.routes]]    # more specific routes (RFC 4191)
# prefix = "fd00:20::/48"
# preference = "medium"
# lifetime_secs = 1800
```

Pick one way for devices to get an address:

| Goal | `managed` | `autonomous` | What happens |
| :--- | :--- | :--- | :--- |
| DHCPv6 only | `true` | `false` | Devices ask DHCPv6, so leases and DNS names work. Android does not do DHCPv6 and gets no IPv6 address. |
| SLAAC only | `false` | `true` | Devices make their own address from the prefix. No lease and no DNS name, but every device works. |
| Both | `true` | `true` | Devices have both. Convenient and noisy: each device has two addresses. |

What Lumen sends:

- The prefixes with their lifetimes and the on-link and autonomous flags, an optional MTU, the interface's hardware address, route information (RFC 4191), **DNS servers** (RDNSS) and **search domains** (DNSSL), both from RFC 8106. Devices that read the DNS options need no DHCPv6 to learn the DNS servers. Android, which has no DHCPv6, learns them this way.
- **When:** three advertisements in the first seconds, then at random times up to `interval_secs` (never closer than a third of it, at least 3 seconds), as RFC 4861 asks. A device that has just joined and sends a Router Solicitation gets an answer after a short random wait, and never more than one every 3 seconds, however many devices ask at once.
- **On stop,** an advertisement with router lifetime 0 withdraws this machine as a default router, if it advertised itself as one.

Things to know:

- **Lumen advertises; it does not route.** With the default `router_lifetime_secs = 0` devices learn the prefix and the DNS servers but are told this machine is **not** their router. That is right when your router does the routing and Lumen only adds DHCPv6 and DNS. Set `router_lifetime_secs` only on a machine that really forwards packets, otherwise devices will send their traffic to a host that drops it. Two machines advertising a prefix is fine; two *default* routers must both be real.
- **Turn off the RA of your router for the same prefix**, or make them agree. Devices follow every RA they hear.
- The prefix is configured, not learned. A prefix that your provider changes (a dynamic delegated prefix) is not picked up automatically.
- It needs a **raw ICMPv6 socket**: give the service only the `CAP_NET_RAW` capability (systemd: `AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE`, the second one for the DHCP ports; containers: `--cap-add NET_RAW`, with host networking), or run as root. Do not use a wider privilege than that. It works on Linux, macOS and the BSDs, not on Windows. A refusal is reported at startup and nothing else starts.
- Only Router Solicitations from the link (source `::` or link-local) are answered. The kernel's ICMPv6 filter cannot be set from safe code, so the socket also hears other ICMPv6 traffic on the interface and drops it at once.
- The console's **DHCP** module lists each interface, its prefixes, the DNS servers, whether it is a default router, and when it last sent.

**How it was checked.** The packet is built byte by byte in unit tests. On a real Linux link (a veth pair) a test hears the advertisements, sends a solicitation and gets an answer in under a second, and hears the withdrawal when the server stops. The Linux kernel on the other end accepted an advertisement and configured a SLAAC address with the advertised lifetimes, the default route and the MTU, and `rdisc6` (an independent decoder) read every option back correctly. Not tried: macOS and BSD on real hardware (the code compiles and the socket options are the standard ones), and clients other than Linux.

## Network boot

```toml
[[dhcp.scopes]]
# ...
next_server = "192.168.1.9"   # the TFTP or boot server
boot_file = "undionly.kpxe"   # printable characters, at most 128
```

The server address goes into `siaddr` and option 66, the file name into the `file` field and option 67. Both settings go together. Boot menus that depend on the client type (UEFI and BIOS need different files) need one scope per network today.

## Failover

Two Lumen servers with the same `[dhcp]` scopes can cover for each other. This is a **hot standby**, not the full ISC failover protocol: it only works between two Lumen servers.

```toml
# On the primary
[dhcp.failover]
role = "primary"
peer = "192.168.1.3:647"          # the secondary
secret_file = "dhcp-failover.secret"

# On the secondary
[dhcp.failover]
role = "secondary"
listen = "0.0.0.0:647"
secret_file = "dhcp-failover.secret"
# takeover_secs = 30              # silence before it answers (5 to 3600)
# reserve_percent = 20            # share of each range it may use while covering (5 to 50)
```

- The primary connects to the secondary. Both copy every lease change to each other and send a heartbeat every two seconds. When the link comes up they exchange everything they hold.
- The **secondary stays silent** while it hears the primary. After `takeover_secs` of silence it answers. It renews every lease it knows, and gives **new** leases only from the last `reserve_percent` of each range (and of each prefix pool), so it cannot hand out an address the primary gave just before it failed but could not copy. A request for another free address is refused, and the client starts over.
- When the primary returns, the secondary goes quiet again and the two merge what they know. If both gave the same address to different devices while apart, each keeps its own client and the address stays in conflict until a lease ends. A bigger `reserve_percent` makes that rarer.
- Every frame is signed with `secret_file` (at least 16 characters, readable only by its owner), and each connection derives a fresh key from random values both sides contribute, so frames cannot be forged, replayed, or reflected. The link is **not encrypted**: leases and device names cross it in the clear. Run it on a trusted network or through a VPN.
- Failover covers leases and prefixes. It does not copy the configuration: keep both `[dhcp]` sections the same (use the same `domain` and scopes).

## Names in DNS

Lumen answers the leased names itself, from memory, with a 30-second TTL. They are served for any client that may query Lumen. A `domain` must not overlap a configured `[[zones]]` zone. Reverse names (`in-addr.arpa`, `ip6.arpa`) are answered for leased addresses only. Your own zone files remain the place for names that never change.

Clients that send a host name (DHCP option 12, or the `FQDN` option on IPv6) get a name. A client with no name gets an address and no DNS entry. Two devices with the same name share it, and both addresses answer.

## Limits and good behavior

- At most 16 scopes of each family, 65,536 addresses per range, and 512 reservations per scope.
- An offered address is held for 60 seconds for the device it was offered to. A declined address (the device found it already in use) rests for 10 minutes. A device that asks again keeps its address.
- A request that names another server is ignored, and an unknown device never gets a reserved address.
- An IPv6 client without a name still gets an address and no DNS entry.
- Packets are small and parsed with bounds. Malformed packets are dropped without an answer.
- Nothing is sent from `0.0.0.0` unless a client without an address asked. IPv4 replies to such a client are broadcast, as the protocol requires.

## Not included

Failover with servers other than Lumen (the ISC protocol), dynamic DNS updates to other servers (the names are served by Lumen itself), and per-client boot options such as separate BIOS and UEFI files in one scope. Say so on the [roadmap](../project/roadmap.md) if you need one.

## The console module

Switch **DHCP** on under **Modules** (administrators only). The page lists each network with how many addresses are in use, the router advertisements Lumen sends, every current lease and delegated prefix with its name, device and expiry, and, for a failover pair, whether this server is answering or standing by. It is read-only: the configuration file decides what is served. The module shows nothing while the server is not enabled in the configuration.

## Related

- [Your own DNS zones](authoritative-dns.md)
- [Configuration reference](../reference/configuration.md#dhcp)
- [Threat model](../design/threat-model.md)

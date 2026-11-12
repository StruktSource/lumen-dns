# Your own DNS zones

Lumen can answer for names you own, instead of asking the internet. This page covers four related features, all **off by default**:

| Feature | Use it to |
| :--- | :--- |
| [Authoritative zones](#authoritative-zones) | Serve `home.example` records (hosts, services, DNS-SD) from a zone file or inline text |
| [Split-horizon views](#split-horizon-views) | Give different clients different answers for the same zone |
| [Conditional forwarding](#conditional-forwarding) | Send one domain to a specific internal resolver |
| [Dynamic updates and transfers](#dynamic-updates-rfc-2136) | Let a router or DHCP server edit records (RFC 2136) and let a secondary server copy a zone (AXFR/IXFR), both with TSIG keys |

> [!NOTE]
> These zones are separate from Lumen's built-in empty local zones (`home.arpa`, `.local`, reverse zones). A zone you define always wins for its own names. Lumen does **not** sign these zones, so DNSSEC-validating clients treat them as unsigned.

Operator zones and forwarders are **never cached** by Lumen's response caches (see [Resolver modes](resolver-modes.md)). Answers depend on the client and change when records change, so each query reads the live zone.

## Authoritative zones

Add one `[[zones]]` table per zone. Give it exactly one of `file` (an RFC 1035 zone file) or `text` (the same format, inline):

```toml
[[zones]]
name = "home.example"
file = "zones/home.example.zone"
```

```text
; zones/home.example.zone
$TTL 300
@        IN SOA ns.home.example. hostmaster.home.example. 1 3600 600 86400 300
@        IN NS  ns.home.example.
ns       IN A   192.168.1.2
nas      IN A   192.168.1.10
printer  IN A   192.168.1.20
_ipp._tcp IN SRV 0 0 631 printer.home.example.
```

- The zone needs a **SOA** record at its apex. Lumen checks this at startup (`lumen --config FILE --check`).
- Names inside the zone that have no record get an authoritative `NXDOMAIN`. They never leave Lumen.
- Relative file paths resolve beside the config file. A zone file or inline text is at most 1 MiB. At most 64 zones.
- Zone names are unique and written without a trailing dot.
- Edit a zone file, then restart Lumen (or [reload](managed-mode.md#change-the-configuration-safely) in managed mode). Use [dynamic updates](#dynamic-updates-rfc-2136) when something else must change records while Lumen runs.

### Service discovery (DNS-SD)

Wide-area DNS-SD is just records: a `PTR` under `_services._dns-sd._udp`, plus `PTR`, `SRV`, and `TXT` records for each instance. Put them in the zone as above, and clients configured with the search domain can browse them. Lumen does **not** bridge or reflect multicast DNS, so devices that only speak mDNS stay invisible outside their own network segment.

## Split-horizon views

A zone can carry alternative copies for specific client networks. The first matching view wins, and clients that match none get the zone's own `file` or `text`:

```toml
[[zones]]
name = "app.example"
text = """
$TTL 60
@   IN SOA ns.app.example. hostmaster.app.example. 1 60 60 60 60
@   IN NS  ns.app.example.
ns  IN A   203.0.113.53
www IN A   203.0.113.10
"""

  [[zones.views]]
  clients = ["192.168.0.0/16", "10.0.0.0/8"]
  text = """
  $TTL 60
  @   IN SOA ns.app.example. hostmaster.app.example. 1 60 60 60 60
  @   IN NS  ns.app.example.
  ns  IN A   192.168.1.2
  www IN A   192.168.1.40
  """
```

- At most 8 views per zone, 32 networks per view. IPv4-mapped IPv6 addresses match their IPv4 network.
- Views are chosen by the **client address** Lumen sees. Behind a NAT or a proxy, every client looks like the proxy.
- A zone with views cannot be dynamic and cannot be transferred. A transfer would hand one audience's data to another.
- Views change *answers*. They are not access control: [`allow_clients`](../reference/configuration.md#listeners) still decides who may ask at all.

## Conditional forwarding

Send one domain, and everything below it, to specific resolvers:

```toml
[[forwarders]]
domain = "corp.example"
upstreams = ["10.0.0.53:53", "10.0.0.54:53"]
```

- Plain UDP, with TCP when an answer is too large. The upstream is usually an internal directory server, so Lumen does **not** DNSSEC-validate these answers, and the traffic is not encrypted. Use it only across networks you trust.
- 1 to 8 upstreams per domain, at most 64 forwarders. A domain cannot be both a zone and a forwarder. An upstream cannot be one of Lumen's own listeners.
- Filtering rules still apply first. A name your filter blocks is never forwarded.
- Names under the domain use only these resolvers, even when Lumen's main mode is recursive. They never fall back to the main resolver.

## Dynamic updates (RFC 2136)

A *dynamic* zone accepts signed update messages, so a DHCP server or script can add and remove records. Changes are saved to a SQLite journal and survive restarts.

First create a shared TSIG secret. It is one line of base64 (at least 16 bytes) in a file only Lumen and the updating system can read:

```sh
openssl rand -base64 32 > ddns.key
chmod 600 ddns.key
```

```toml
[[tsig_keys]]
name = "ddns"                 # a DNS-style name; the updater must use the same name
algorithm = "hmac-sha256"     # or hmac-sha384, hmac-sha512
secret_file = "ddns.key"

[[zones]]
name = "dyn.example"
file = "zones/dyn.example.zone"     # initial records, read once when the journal is created
journal = "zones/dyn.example.journal"

  [[zones.update_rules]]
  key = "ddns"
  names = ["*.dyn.example"]         # any name below dyn.example, or an exact name
  types = ["A", "AAAA", "TXT"]
```

The secret never appears in the config file. Then use any RFC 2136 client, for example `nsupdate`:

```sh
nsupdate -k ddns.key <<'EOF'
server 192.168.1.2 53
zone dyn.example
update add laptop.dyn.example. 300 A 192.168.1.77
send
EOF
```

Updates are **scoped**. A key can change only the names and types its `update_rules` allow, nothing else:

- Names are exact (`printer.dyn.example`) or `*.suffix` for anything *strictly below* the suffix. The zone apex is never matched by a `*.` rule.
- Allowed types: `A`, `AAAA`, `CNAME`, `TXT`, `PTR`, `SRV`, `MX`, `CAA`, `TLSA`. `SOA`, `NS`, and DNSSEC records can never be changed, and "delete everything at this name" is refused.
- One update message may change at most 64 records. A zone holds at most 20,000 record sets.
- An update with no TSIG signature gets `REFUSED`, a wrong signature or unknown key gets `NOTAUTH`, and a key with no matching rule gets `REFUSED`. RFC 2136 prerequisites are checked, and the signature's time must be within 300 seconds of the server clock, so keep the clock correct (NTP).
- A zone with a `journal` needs `file`, at least one rule, and no views. The journal and `file` stay on disk; Lumen sets the journal's mode to `0600` on Unix.
- `lumen --check` validates the config and the zone file but never creates or opens a journal.
- Back up the journal with the config. If it is deleted, the zone returns to its `file` contents.
- A plain zone without a journal answers update messages with `NOTIMP`.

## Zone transfers (AXFR and IXFR)

List the TSIG keys allowed to copy a zone with `transfer_keys`. With none, every transfer is refused. This works for static and dynamic zones:

```toml
[[tsig_keys]]
name = "xfr"
algorithm = "hmac-sha256"
secret_file = "xfr.key"

[[zones]]
name = "home.example"
file = "zones/home.example.zone"
transfer_keys = ["xfr"]
```

```sh
dig @192.168.1.2 home.example AXFR -k xfr.key
```

- Transfers need a **valid TSIG signature from a listed key**, over **plain TCP** only. UDP, DoT, DoH, and the other transports are refused, and unsigned requests are refused.
- A key allowed to update is not automatically allowed to transfer, and the other way round. Use separate keys.
- **Bounded size:** the whole zone must fit one DNS message (about 64 KiB on the wire). A larger zone gets `SERVFAIL` instead of a partial copy. Split big zones, or use delegation.
- **IXFR is answered as a full transfer.** Lumen keeps no history of changes, and RFC 1995 allows a server to reply to an incremental request with the whole zone. Secondaries still work; they just copy everything each time.
- Lumen does not send `NOTIFY`. Set the secondary's refresh interval to how quickly you need changes to appear.

## Limits and failure behavior

| Item | Limit |
| :--- | :--- |
| Zones / forwarders | 64 / 64 |
| Zone file or inline text | 1 MiB |
| Views per zone / networks per view | 8 / 32 |
| TSIG keys | 32 |
| Update rules per zone | 16 |
| Records per update message / record sets per dynamic zone | 64 / 20,000 |
| Transfer size | One DNS message (about 64 KiB) |

An invalid zone, key file, or rule stops startup with an error that names the problem but never prints secrets. A bad journal also stops startup: Lumen does not guess.

## Related

- [Configuration reference](../reference/configuration.md#authoritative-zones-forwarders-and-tsig-keys)
- [Threat model](../design/threat-model.md)
- [Serve your network](serve-your-network.md)

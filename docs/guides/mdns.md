# Multicast DNS bridge

Many devices (printers, TVs, speakers, laptops) announce themselves with **multicast DNS** (mDNS): a name like `printer.local` and services like `_airplay._tcp`. Multicast stays on one network segment, so a phone on the guest network cannot see a printer on the main one, and an ordinary DNS client cannot ask for `printer.local` at all. Lumen can bridge that. It is **off by default**, and it does two separate jobs that you can use alone or together.

| Job | What it does |
| :--- | :--- |
| **Discovery proxy** | Answers normal DNS questions under a domain you choose from what devices announce: `printer.mdns.home.example` is `printer.local`, and `_http._tcp.mdns.home.example` lists the web services. Any device that can reach Lumen can use it, from any network. |
| **Reflector** | Repeats mDNS between the interfaces you list, so devices on separate networks see each other the way they would on one network. |

## Configure it

```toml
[mdns]
enabled = true
interfaces = ["eth0", "eth1"]       # the networks to listen on (1 to 8)
domain = "mdns.home.example"        # discovery proxy: <name>.<domain> is <name>.local
# reflect = false                   # repeat mDNS between the interfaces (needs two or more)
# reflect_services = ["_airplay._tcp"]   # repeat only these services (empty: all)
# reflect_block_services = ["_ssh._tcp"] # never repeat these
# publish_name = "lumen"            # answer for and announce lumen.local
# push_listen = ["0.0.0.0:853"]     # DNS Push over TLS for the proxy domain
# push_max_connections = 64
# push_max_subscriptions = 128
# ipv6 = true                       # also use ff02::fb next to 224.0.0.251
# wait_ms = 700                     # how long a question waits for devices (100 to 3000)
# ttl_cap_secs = 120                # longest TTL in an answer (1 to 3600)
# max_records = 4096                # records remembered (64 to 65536)
```

At least `domain` or `reflect` is needed. The `domain` is a normal DNS name that is **not** `.local` and not under `.arpa`, and it must not overlap one of your `[[zones]]` or the DHCP domain. Check with `lumen --config FILE --check`.

Lumen binds UDP port 5353 on each listed interface (sharing it with any responder already running on the machine, such as Avahi or macOS's own), so it needs no special privilege for the port, only for the multicast groups on some systems. Supported on **Linux and macOS**; Windows is not supported.

## The discovery proxy

- **A name**: a question for `tv.mdns.home.example` makes Lumen ask `tv.local` on every listed interface and wait up to `wait_ms` for an answer (it returns as soon as one arrives). Records are kept for their TTL (capped by `ttl_cap_secs`), so the next question is answered from memory without touching the network.
- **Browsing**: `_services._dns-sd._udp.<domain>` lists the service types on the network; `_http._tcp.<domain>` lists the instances of a type, with the matching `SRV`, `TXT` and address records alongside, so a client needs fewer round trips. Instance names with spaces or dots survive.
- **Targets are rewritten** from `.local` to the domain, so a `SRV` points at `box.<domain>`, not `box.local`, and the client can resolve it through Lumen too.
- A name nobody answers for gets `NXDOMAIN`; a name that exists without the asked type gets an empty answer. The domain itself has a `SOA` and nothing else. Answers are authoritative for the domain and are **not DNSSEC-signed**.
- The network sees at most about 50 questions a second on behalf of all clients, and the same question is not repeated within 300 ms, so a busy resolver cannot flood the segment.

Because the names live under a domain Lumen answers itself, they never leak to public DNS.

## The reflector

With `reflect = true`, an mDNS packet that arrives on one interface is sent on the others. Use it when a client and a device are on different networks (VLANs) and must find each other by multicast, for example casting from a phone on one VLAN to a TV on another.

- **Loops are cut**: a packet seen in the last 3 seconds is not repeated, and Lumen marks its own questions so they are not repeated when the network hands them back. At most 200 packets a second are repeated, with a short burst allowed.
- **Only multicast is repeated**: packets from a source port other than 5353 (unicast questions) are not, and a packet whose source is not on the link it came from is dropped (RFC 6762 section 11).
- IPv4 is repeated to IPv4 interfaces and IPv6 to IPv6; one family is never turned into the other.

> [!WARNING]
> Reflecting mDNS **crosses a network boundary on purpose**. A device on a guest network can then announce itself to, and ask about, devices on your main network, which weakens the isolation between them. Reflect only between networks you trust each other, and prefer the discovery proxy (which exposes names, not the multicast stream) where it is enough. Reflection does not carry any traffic between the networks: after discovery, the devices still need firewall rules that allow them to talk.

## Per-service reflection filters

With `reflect_services` set, only those service types cross between networks; `reflect_block_services` removes types and wins over the allow list. A packet is judged by every service name in its questions and records, including PTR targets, so an instance such as `Living-Room._airplay._tcp.local` counts as `_airplay._tcp`. Plain host lookups (`tv.local`) always pass, because a client that found a service on another network must still resolve its host.

## Publishing this machine

`publish_name = "lumen"` probes three times before it uses `lumen.local`, then announces it twice. If another device already owns the name, or claims it later, Lumen tries `lumen-2.local`, `lumen-3.local`, and so on. A and AAAA records come from each listed interface.

## DNS Push

`push_listen` serves DNS Push Notifications (RFC 8765) over TLS and DSO. It uses the same certificate and private key as the encrypted DNS listeners. The certificate must cover `mdns.domain`, which is also the TLS server name. Lumen advertises the first listener's port as `_dns-push-tls._tcp.<domain>`; every configured address must use that port.

Clients allowed by `listen.allow_clients` can subscribe to a name and type below the proxy domain. Lumen sends the current record set, then sends additions and TTL-zero removals when mDNS announcements change or expire. `SUBSCRIBE`, `UNSUBSCRIBE`, DSO keepalive, and ordinary DNS queries on the same TLS session are supported. Messages, sessions, and subscriptions are bounded by the configuration. A subscription never causes a repeated multicast query after its first lookup.

## Who can see what

The discovery proxy answers anyone who may query Lumen, so what devices announce becomes visible to every client allowed by [`allow_clients`](../reference/configuration.md). Names and service names can reveal what you own ("Gerrit's iPhone"). The cache holds only names under `.local` and reverse names, never other data, and never clients.

## Not included

DNS-SD Service Registration is not a part of DNS Push and is not included. Lumen does not accept remote service registrations. The mDNS bridge has no separate console page.

## Related

- [Your own DNS zones](authoritative-dns.md) (for service discovery you write by hand)
- [Configuration reference](../reference/configuration.md#mdns)
- [Threat model](../design/threat-model.md)

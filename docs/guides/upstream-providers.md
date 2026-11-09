# Upstream providers

Lumen ships an **offline catalog** of public encrypted DNS resolvers so you can forward to one by name instead of typing IP addresses and certificate names. This page explains how to use it and what each entry means.

> [!IMPORTANT]
> No provider is selected by default, and Lumen stays in recursive mode. Using a provider sends your queries to that operator. Read their privacy policy first. A catalog entry is not a guarantee of availability, privacy, or live service.

Background: [Resolver modes](resolver-modes.md).

## Use a provider

Provider presets work in forward mode (and as timeout-fallback upstreams):

```toml
[resolver]
mode = "forward"
dnssec = true

[[resolver.providers]]
id = "cloudflare-unfiltered"
protocol = "auto"
encryption = "required"
address_family = "ipv4"
transport_priority = ["quic", "https", "tls"]
```

| Field | Meaning |
| :--- | :--- |
| `id` | The stable ID from the table below. |
| `protocol` | A specific transport (`udp`, `tcp`, `tls`, `https`, `quic`), or `auto` for an encrypted-only list. |
| `address_family` | `any` (default), `ipv4`, or `ipv6`. |
| `encryption` | Auto mode only. Defaults to, and only accepts, `required`. There is no plaintext policy. |
| `transport_priority` | Auto mode only. An ordered, unique subset of `quic`, `https`, `tls`. Default order: QUIC, HTTPS, TLS. |

## Use several providers

Choose **up to 8 providers**, and add up to 8 custom `[[resolver.upstreams]]` next to them. The order you write the `providers` is their **rank**, and custom upstreams rank after them. A provider can be selected only once. Automatic and explicit transports cannot be mixed in one config, and a provider with no encrypted transport (such as `dns-watch`) cannot be used with `auto`.

```toml
[resolver]
mode = "forward"
strategy = "failover"        # failover | fastest | round_robin | race

[[resolver.providers]]       # rank 1
id = "quad9-unfiltered"
protocol = "auto"

[[resolver.providers]]       # rank 2
id = "cloudflare-unfiltered"
protocol = "auto"

[[resolver.providers]]       # rank 3
id = "dns4eu-unfiltered"
protocol = "auto"
```

In the web console this is **DNS settings → Upstreams**: add providers, move them up and down to rank them, and pick how they are used.

### Choose a strategy

| `strategy` | What happens | Who sees your lookups |
| :--- | :--- | :--- |
| `failover` (ranked fallback) | The first provider answers. The next is used only when it does not respond. | One provider at a time |
| `fastest` | The provider that answered fastest recently takes the query. | Mostly the fastest provider |
| `round_robin` | Each query goes to the next provider in turn, so load and exposure are spread evenly. | Every provider sees a share |
| `race` | Every provider gets every query at once, and the first answer wins. | **Every provider sees every lookup** |

If you do not set a strategy, the older behavior stays: `failover` for automatic transports, `fastest` otherwise. With a single provider there is nothing to choose between.

If you know load balancing from other filter apps: *Load balancing* corresponds to `round_robin` or `fastest` here, and *Parallel requests* corresponds to `race`. Random, weighted spreading is not offered yet.

### How failover works

Each provider is its own forwarder with its own timeout. Lumen moves to the next provider after a **connection, transport, timeout, or upstream SERVFAIL** failure. SERVFAIL has no usable DNS data, so the next provider may still answer. A usable DNS answer, including NXDOMAIN, and a local DNSSEC failure ends the lookup: another provider is never asked for a different answer.

- A provider that **just failed** is left alone for 10 seconds and then tried again at its rank, so every query does not wait for it. If every provider fails, all of them are tried again.
- A provider that accepts connections but never answers costs **one timeout** (`upstream_timeout_ms`, 2 seconds by default) the first time. Lower it if you want quicker fallback.
- When several providers are in use, each gets one attempt per query; the next provider is the retry. A single provider keeps `attempts` retries.
- Within one provider, `auto` still tries its transports in order (QUIC, then HTTPS, then TLS) as before. **Known limit:** if a provider's *first* transport is silently blocked (for example a firewall that drops QUIC), that provider can fail as a whole instead of moving on to its next transport. Other providers still answer. Until this is improved, choose HTTPS or TLS for that provider on such a network.
- `race` is the fastest but the least private. `round_robin` and `failover` send each lookup to one provider, `race` sends it to all.

Certificate chain and hostname checks always stay on, and selection never probes public services at startup.

## Included providers

| Stable ID | Operator country | Jurisdiction | Network scope | Variant | ECS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `dns4eu-unfiltered` | CZ | EU | EU anycast | unfiltered | no |
| `ffmuc-unfiltered` | DE | EU | regional | unfiltered | no |
| `libredns-unfiltered` | GR | EU | regional | unfiltered | no |
| `dns-sb-unfiltered` | DE | EU | global anycast | unfiltered | no |
| `quad9-unfiltered` | CH | Europe, non-EU | global anycast | unfiltered | no |
| `uncensoreddns-anycast` | DK | EU | global anycast | uncensored | no |
| `dns-watch` | DE | EU | regional | uncensored | no |
| `cloudflare-unfiltered` | US | outside Europe | global anycast | unfiltered | no |
| `google-public-dns` | US | outside Europe | global anycast | unfiltered | yes |
| `adguard-unfiltered` | CY | EU | global anycast | unfiltered | no |
| `controld-unfiltered` | CA | outside Europe | global anycast | unfiltered | no |
| `controld-uncensored` | CA | outside Europe | global anycast | uncensored | no |

**Reading the table**

- **Operator country** and **jurisdiction** (which laws apply) are separate from **network scope** (where servers physically are).
- **Variant:** *unfiltered* and *uncensored* are distinct operator profiles, not equal promises.
- **ECS** (EDNS Client Subnet): *yes* means the operator may pass part of the client's network address to authoritative servers.

## What the catalog records

Each transport of each entry has a status:

| Status | Meaning |
| :--- | :--- |
| `supported` | The operator documents it. Only these can be selected. |
| `unsupported` | The operator says it is unavailable. |
| `not_documented` | The operator's official page does not claim it. |

`test_status = "not_tested"` means this release made no live query to that service; Lumen's own tests use local fixtures. The catalog lives in `config/providers/resolvers.toml` and was checked against operator documentation on 2026-10-30, so endpoints may have changed since.

Each entry supplies a fixed IP, port, TLS name, and full DoH path, so encrypted setups never need DNS to find their DNS server. Control D's secure transports use its documented secure-endpoint bootstrap IPs. Encrypted choices never downgrade to plaintext.

## Official sources

- [DNS4EU](https://joindns4.eu/for-public)
- [Freifunk Munich](https://www.freifunk-muenchen.de/wiki/knb:dohdot)
- [LibreDNS](https://libredns.gr/)
- [DNS.SB](https://dns.sb/faq/)
- [Quad9](https://docs.quad9.net/services/)
- [UncensoredDNS](https://blog.uncensoreddns.org/)
- [DNS.WATCH](https://dns.watch/)
- [Cloudflare](https://developers.cloudflare.com/1.1.1.1/ip-addresses/)
- [Google Public DNS](https://developers.google.com/speed/public-dns/docs/using)
- [AdGuard DNS](https://adguard-dns.io/kb/general/dns-providers/)
- [Control D Free DNS](https://docs.controld.com/docs/free-dns)
- [Control D secure endpoint IPs](https://docs.controld.com/docs/control-d-ip-ranges)

Privacy-policy links, where operators supply them, live with each catalog entry. They are operator statements, not Lumen endorsements.

## For developers

`lumen_config::providers::Catalog::bundled()` validates the versioned catalog. `select(stable_id, protocol, address_family)` returns one explicit transport, and `select_encrypted(stable_id, address_family, priority)` returns the ordered automatic set. Both produce the same verified `Upstream` records the resolver uses. Selection fails for unknown profiles, unavailable protocols, invalid priorities, or missing address families.

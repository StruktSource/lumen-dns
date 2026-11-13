<div align="center">

# ✦ Lumen

### Your DNS. Your rules. Your network.

**A self-hosted DNS resolver with built-in filtering, built for privacy, visibility, and control.**
Recursive DNS, encrypted transports, DNSSEC validation, per-device filtering, and optional local zones, DHCP, and certificates in one small Rust service.

[**Quick start**](docs/getting-started/quick-start.md) · [**What is DNS?**](docs/getting-started/concepts.md) · [**Documentation**](docs/README.md) · [**Install**](docs/deployment/README.md) · [**Roadmap**](docs/project/roadmap.md)

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-2563eb?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-2d3748?style=flat-square&logo=rust)](Cargo.toml)
[![Status: Pre-release](https://img.shields.io/badge/status-pre--release-f59e0b?style=flat-square)](docs/project/roadmap.md)
[![DNS: UDP · TCP · DoH · DoH3 · DoT · DoQ · DNSCrypt](https://img.shields.io/badge/DNS-UDP%20%7C%20TCP%20%7C%20DoH%20%7C%20DoH3%20%7C%20DoT%20%7C%20DoQ%20%7C%20DNSCrypt-0f766e?style=flat-square)](docs/guides/encrypted-dns.md)

</div>

---

> [!IMPORTANT]
> **Lumen is in active pre-release development.** The resolver, encrypted transports, filtering, local DNS and DHCP, web console, and optional management API all work. Security review, soak testing, and release validation are still underway, so try it in a controlled environment before relying on it for network-wide DNS.

## What is Lumen?

Every website, app, and smart TV on your network starts by asking a **DNS resolver** where to connect. Today that is usually your router or your internet provider. **Lumen lets you run that resolver yourself**, without making a public service, a tracking dashboard, or someone else's block list part of the default setup.

New to the ideas? Read [Concepts](docs/getting-started/concepts.md) for a plain-language tour.

## Why Lumen?

| | |
| :--- | :--- |
| 🔒 **Private by default** | No telemetry, no query history unless you opt in, and no outside provider unless you add one. |
| 🧭 **Resolves for itself** | Walks the DNS tree directly and validates DNSSEC locally, or forwards over encrypted connections to a provider you choose. |
| 🛡️ **Filters per device** | Block ads, trackers, or categories globally, or with different rules and schedules for each device. |
| 🏠 **Runs your home network** | Name your own devices with the Local DNS manager, hand out addresses with the optional DHCP server, and bridge `.local` (mDNS) names, all from the console. |
| 🖥️ **Easy to manage** | A built-in web console and a `lumenctl` command-line tool, with safe reloads that roll back on failure. |
| 📊 **Visible** | Opt-in aggregate metrics for Prometheus, Grafana, and Home Assistant. |
| 🪶 **Small** | An idle Lumen uses about 8 MiB of memory (about 11 MiB with the web console), and answers cached or blocked names in about 0.03 ms. |

## Features

| Capability | What you get |
| :--- | :--- |
| **Recursive DNS** | Iterative resolution, QNAME minimization, bounded caches, and bundled root hints. Optional **serve-stale** (RFC 8767) keeps answering from an expired entry during an outage, and an optional **persistent cache** restarts warm |
| **DNSSEC** | Local validation on by default, configurable trust anchors, and optional automatic root key rollover (RFC 5011) |
| **Seven transports** | UDP, TCP, DNS-over-HTTPS (HTTP/2), **DNS-over-HTTP/3**, DNS-over-TLS, DNS-over-QUIC, and a **DNSCrypt v2** server. Encrypted answers are padded (RFC 8467). Encrypted listeners need your own certificate, or **automatic certificates (ACME)** |
| **Automatic certificates** | Opt-in Let's Encrypt-style issuance and renewal (HTTP-01 or DNS-01, wildcards included). Renewed files load without a restart |
| **Forwarding** | A catalog of encrypted public resolvers over TLS, HTTPS, QUIC, or HTTP/3: use up to 8, rank them, and choose ranked fallback, fastest first, round-robin, or race. Never downgrades to plain text |
| **Timeout fallback** | Optional forwarding **only** after a recursive timeout, never for DNSSEC failures or normal answers |
| **Filtering** | Allow and block rules (including **regular expressions**), hosts, domain, and Adblock-style lists, one-click popular lists, CNAME-aware blocking, configurable block replies, and opt-in **SafeSearch** |
| **Per-client policy** | Device, subnet, group, profile, category, and UTC-scheduled rules, with explainable decisions and one-click **child-safety** categories |
| **Local DNS manager** | Create your own zones and records (`A`, `AAAA`, `CNAME`, `TXT`, `PTR`, `MX`, `SRV`, `CAA`, `TLSA`) in the console. `home.arpa` is recommended; changes apply safely and roll back on failure |
| **Your own zones** | Authoritative zones from files, split-horizon views, conditional forwarding, TSIG-signed dynamic updates (RFC 2136), zone transfers (AXFR/IXFR), and DNSSEC signing with NSEC or NSEC3 and key rollover |
| **DHCP server** | Opt-in IPv4 and IPv6 addresses with reservations, relay agents, prefix delegation, network boot options, Router Advertisements, and Lumen-to-Lumen failover. Leases become DNS names |
| **Multicast DNS bridge** | Opt-in discovery proxy and reflector, so `printer.local` also answers as `printer.your-domain` and across networks |
| **Web console** | First-run setup, one Users page for accounts and roles, optional two-step verification and optional, experimental single sign-on (OpenID Connect), live overview and activity, filtering, devices, local DNS, and an optional **Modules** page (Traffic map, DHCP), in [English, German, Italian, Spanish, and Dutch](docs/guides/translations.md) |
| **Query history** | Opt-in. Recent lookups in memory, or saved for 1 to 90 days, anonymous or with the device, with search and one-click deletion |
| **Operations** | Validated TOML config, optional SQLite state, staged reloads with rollback, audit log, signed webhooks, and Prometheus metrics |

## Quick start

To build from source you need Rust 1.89 or newer; a release download needs nothing. By default Lumen listens only on **loopback port 5353**, validates DNSSEC, and uses no outside provider.

```sh
git clone https://github.com/StruktSource/lumen-dns.git
cd lumen-dns
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/lumen.toml
```

In another terminal:

```sh
dig @127.0.0.1 -p 5353 example.com A +dnssec
```

That is a private recursive resolver with DNSSEC validation. Prefer a ready-made download or Docker? Follow the full **[Quick start](docs/getting-started/quick-start.md)**.

## Where to go next

| I want to… | Read |
| :--- | :--- |
| Install it as an always-on service | [Deployment guides](docs/deployment/README.md) (Docker, Podman, Kubernetes, Linux, macOS, Windows) |
| Let my phone, laptop, and TV use it | [Serve your network](docs/guides/serve-your-network.md) |
| Block ads and trackers | [Filtering](docs/guides/filtering.md) |
| Name my own devices and services | [Your own DNS zones](docs/guides/authoritative-dns.md#easy-local-dns-manager) |
| Hand out IP addresses | [DHCP server](docs/guides/dhcp.md) |
| Serve encrypted DNS with a real certificate | [Encrypted DNS](docs/guides/encrypted-dns.md) and [Automatic certificates](docs/guides/certificates.md) |
| Use the browser interface | [Web console](docs/guides/web-console.md) (start Lumen with `--state`) |
| Forward to an encrypted provider | [Resolver modes](docs/guides/resolver-modes.md) and [Upstream providers](docs/guides/upstream-providers.md) |
| Look up every setting | [Configuration reference](docs/reference/configuration.md) |

## Safe by default

- **Local clients only:** DNS and web listeners are on loopback, plus an explicit client allow-list.
- **No automatic provider:** recursive DNS by default. Forwarding and timeout fallback are opt-in.
- **DNSSEC on:** local validation is enabled unless you change it.
- **No telemetry, and query history is off.** You can opt in to anonymous or full [query history](docs/guides/query-history.md), and aggregate metrics are opt-in too.
- **No surprise filters:** external block lists and integrations need deliberate configuration.
- **Restricted administration:** the management API is off by default, and when enabled it needs managed mode, a loopback address, and authentication.

**Privacy has limits.** Recursive queries still reach internet DNS servers, and forwarders see the queries you send them. DNS filtering cannot stop apps that use other DNS servers. TLS keys, trust anchors, file permissions, and public exposure are your responsibility. Lumen has **not** yet had an external security review.

Details: [Threat model](docs/design/threat-model.md) and [Security policy](SECURITY.md). Report vulnerabilities **privately** through [GitHub security advisories](https://github.com/StruktSource/lumen-dns/security/advisories/new), never in public issues.

## How it works

```text
Client (UDP · TCP · DoH · DoH3 · DoT · DoQ · DNSCrypt)
                    │
           Access and rate limits
                    │
          Filter policy snapshot ─── Block response
                    │
        Your own zones (if any), then
        recursive or forward resolver
                    │
        DNSSEC validation + cache
                    │
                 Response
```

Lumen is a Rust workspace with a single shared resolver pipeline and deliberately separate DNS, filtering, state, API, and web components. It builds on [Hickory DNS](https://github.com/hickory-dns/hickory-dns). The diagram is conceptual: see [Architecture](docs/design/architecture.md) for the details.

## Project status

**Implemented:** recursive and forwarding DNS, seven transports, DNSSEC, per-device filtering with regex rules and SafeSearch, serve-stale and a persistent cache, local DNS and authoritative zones, an optional DHCP server and mDNS bridge, automatic certificates, managed mode, the web console in five languages, opt-in query history, optional single sign-on, an authenticated API, metrics, and deployment files for six platforms.

**Still ahead:** a device and room manager, DNSCrypt upstreams and native ECH, high availability, more interoperability and soak testing (including live ACME and real-hardware checks), and independent security review. These are **roadmap items, not current capabilities**.

See the [roadmap](docs/project/roadmap.md), the [verification record](docs/project/verification.md), and [performance notes](docs/project/performance.md). Measured idle memory and loopback latency are recorded there; there is no verified production throughput claim yet.

## Documentation

Everything lives in **[`docs/`](docs/README.md)**:

| Section | What is in it |
| :--- | :--- |
| [Getting started](docs/getting-started/quick-start.md) | Quick start and concepts |
| [Guides](docs/README.md#guides-how-to-do-things) | Network access, resolver modes, encrypted DNS, certificates, local zones, DHCP, mDNS, filtering, console, monitoring |
| [Deployment](docs/deployment/README.md) | Platform guides and the compatibility matrix |
| [Reference](docs/reference/configuration.md) | Configuration, command line, API, DNS behavior, DNSSEC |
| [Design](docs/design/architecture.md) | Architecture and threat model |
| [Project](docs/project/roadmap.md) | Roadmap, versioning, verification, performance |

## Contributing

Bug reports, interoperability tests, documentation fixes, and reproducible deployment feedback are all welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Recent changes are in the [changelog](CHANGELOG.md).

Lumen is developed by [Strukt](https://github.com/StruktSource) and released under the [Apache License 2.0](LICENSE).

---

<div align="center">

**Own your resolver. Understand your DNS. Build on your terms.**

[Quick start](docs/getting-started/quick-start.md) · [Documentation](docs/README.md) · [Contribute](CONTRIBUTING.md)

</div>

<div align="center">

# ✦ Lumen

### Your DNS. Your rules. Your network.

**An open-source, self-hosted DNS resolver built for privacy, visibility, and control.**  
Recursive DNS, encrypted transports, DNSSEC validation, and fine-grained filtering — in one Rust-powered service.

[**Get started**](#quick-start) · [**Explore features**](#what-lumen-can-do) · [**Documentation**](#documentation) · [**Deployment guides**](docs/deployment/README.md) · [**Roadmap**](docs/progress.md)

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-2563eb?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-2d3748?style=flat-square&logo=rust)](Cargo.toml)
[![Status: Pre-release](https://img.shields.io/badge/status-pre--release-f59e0b?style=flat-square)](docs/progress.md)
[![DNS: UDP · TCP · DoH · DoT · DoQ](https://img.shields.io/badge/DNS-UDP%20%7C%20TCP%20%7C%20DoH%20%7C%20DoT%20%7C%20DoQ-0f766e?style=flat-square)](docs/resolver.md)

</div>

---

> [!IMPORTANT]
> **Lumen is in active pre-release development.** The DNS resolver, transport support, filtering engine, local controls, and optional management API are implemented. A **web console** (accounts, overview, filtering, devices, DNS settings) is built in and runs in managed mode (`--state`). Security review, soak testing, and release validation are still underway. Evaluate it in a controlled environment before relying on it for production or network-wide DNS.

## DNS infrastructure that answers to you

Your DNS service sits at the front door of almost every network connection. Lumen gives you a way to run that service yourself — without making a public resolver, a tracking dashboard, or a third-party filter list part of the default setup.

**Resolve locally.** Start with iterative recursive resolution and locally validated DNSSEC, without a preconfigured forwarding provider.

**Choose your transport.** Serve conventional DNS over UDP and TCP, or configure encrypted DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ).

**Apply policy where it matters.** Combine global rules, imported lists, category profiles, and per-device or group policies, including time-based schedules.

**Stay in control.** Use versioned configuration, optional SQLite-backed state, local CLI management, authenticated API access, and privacy-conscious metrics.

## What Lumen can do

| Capability | Today |
| :--- | :--- |
| **Recursive DNS** | Iterative resolution, delegation checks, QNAME minimization, positive/negative caching, and bundled root hints. |
| **DNSSEC** | Local validation enabled by default, with configurable trust anchors. |
| **Five DNS transports** | IPv4/IPv6 UDP, TCP, DoH (HTTP/2), DoT, and DoQ; encrypted listeners require your own TLS certificates. |
| **Upstream flexibility** | Explicit forwarding over plaintext or verified encrypted protocols; encrypted-only provider transport failover. |
| **Controlled fallback** | Optional forwarding **only after an identified recursive timeout** — never silently on DNSSEC failures or ordinary DNS answers. |
| **DNS filtering** | Global allow/block rules; local or HTTPS lists; hosts, domain, and Adblock-style formats; configurable block responses. |
| **Per-client policy** | Device, subnet, group, profile, category, and UTC-scheduled rules, with explainable rule decisions. |
| **Local operations** | Validated TOML configuration; optional SQLite state, migrations, staged reload and rollback; `lumenctl` commands. |
| **Observability** | Opt-in aggregate Prometheus metrics, a liveness endpoint, Grafana assets, authenticated management API, audit events, and signed webhooks. |
| **Web console** | Built in. First-run account setup, sign-in with admin and user roles, live overview, filtering and profiles, devices, full DNS settings with review-before-apply, users, audit log, and opt-in in-memory recent queries. See [Web console](docs/web-hosting.md). |

Implementation details: [architecture](docs/architecture.md) · [resolver](docs/resolver.md) · [filtering](docs/filtering.md) · [management API](docs/management-api.md).

## Quick start

Get a local recursive DNS resolver running from source. The default configuration binds DNS to **loopback port 5353**, enables DNSSEC, and does not enable external forwarding providers or filtering.

**Prerequisites:** Rust **1.88+** (stable recommended; CI/container builds use 1.95.0), Git, and optionally `dig` for testing.

### 1. Get the source

```bash
git clone https://github.com/StruktSource/lumen-dns.git
cd lumen-dns
```

### 2. Check and run

```bash
./scripts/dev.sh check
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/lumen.toml
```

On Windows, use `./scripts/dev.ps1` from PowerShell for the development checks; see the [Windows guide](docs/deployment/windows.md).

### 3. Ask Lumen a question

In another terminal:

```bash
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com A +dnssec
dig @::1 -p 5353 example.com AAAA +tcp
```

**That's it:** a local recursive resolver, DNSSEC validation, and bounded caches — with no default third-party upstream or DNS query history.

For a minimal start without a config file, run `cargo run --locked --bin lumen -- --bind 127.0.0.1:5353`. Run `cargo run --locked --bin lumen -- --help` for startup options.

> [!NOTE]
> The built-in page at `http://127.0.0.1:8080` is currently a **placeholder**, not a DNS administration interface. The management API is separate and disabled by default.

## Make it yours

### Enable filtering

Lumen's filter engine is implemented, but **no third-party blocklist is preloaded**. Start with the documented example, then provide sources and rules you trust.

```bash
cargo run --locked --bin lumen -- --config config/filtering.example.toml --check
cargo run --locked --bin lumenctl -- filter-explain --config config/filtering.example.toml --client 192.0.2.10 --domain games.example --at 75600
cargo run --locked --bin lumen -- --config config/filtering.example.toml
```

The example uses reserved domains and is intended for demonstration, not out-of-the-box internet ad blocking. See the [filtering guide](docs/filtering.md) for matching, policy precedence, list updates, and schedules.

### Choose an upstream instead of recursion

Prefer a forwarding setup? Explore [`config/forward.example.toml`](config/forward.example.toml), which demonstrates encrypted provider forwarding and failover. **Running that example sends DNS requests to its configured upstream.** The default configuration does not.

Read [resolver modes](docs/resolver.md) and [provider presets](docs/upstream-providers.md) before switching.

### Enable persistent local control

Add `--state ./data/state.db` when starting Lumen to enable persistent configuration/device state and the local `lumenctl` control channel. Config changes can be validated and staged before runtime activation, with rollback if the replacement fails to start.

```bash
cargo run --locked --bin lumen -- --config config/lumen.toml --state ./data/state.db
```

See [state and local control](docs/state-and-control.md). Managed-mode changes require understanding which configuration revision is active; editing the original TOML alone does not reconfigure an already initialized database.

## Deployment options

Lumen uses the **same Rust DNS core and TOML schema** across its native and container packaging. Choose the environment that fits your infrastructure:

| Environment | Guide |
| :--- | :--- |
| Docker / Docker Compose | [Docker](docs/deployment/docker.md) · [Compose](docs/deployment/docker-compose.md) |
| Podman | [Rootless/container guide](docs/deployment/podman.md) |
| Kubernetes / Helm | [Kubernetes deployment](docs/deployment/kubernetes.md) |
| Linux / systemd | [Bare-metal deployment](docs/deployment/linux-bare-metal.md) |
| macOS / Windows | [macOS](docs/deployment/macos.md) · [Windows](docs/deployment/windows.md) |
| Homelab platforms | [Proxmox LXC](docs/deployment/proxmox-lxc.md) · [Unraid](docs/deployment/unraid.md) · [Raspberry Pi](docs/deployment/raspberry-pi.md) |

**Read the [compatibility matrix](docs/deployment/compatibility.md) before deployment.** All platforms remain pre-release; the matrix distinguishes experimentally tested targets from guides that have not yet been hardware-validated. The provided Compose/OCI configurations are an evaluation starting point, not proof of production readiness or published image availability.

For local images and optimized binaries:

```bash
./scripts/dev.sh build
./scripts/dev.sh image
./scripts/dev.sh release
```

`release` performs local checks and builds; it **does not publish** an official release. On Windows PowerShell use `./scripts/dev.ps1` with the matching command. A Docker-compatible engine is needed for image operations.

### Opening access to your LAN

Lumen deliberately listens on loopback by default. To serve other devices, configure **both** the listener bind addresses **and** `listen.allow_clients` CIDRs, then validate the configuration. Standard client DNS typically uses port 53; the source-development default uses 5353. Review host firewall rules, container port mapping, client-IP visibility behind NAT, and TLS certificate handling before exposing services. Keep the console on loopback or behind HTTPS: sign-in over plain HTTP is only safe on the local machine.

See [configuration](docs/configuration.md), [deployment instructions](docs/deployment/README.md), and [security boundaries](docs/threat-model.md).

## Privacy and security by default

Lumen's defaults are intentionally conservative:

- **Local clients only:** loopback DNS and web listeners, plus an explicit client CIDR allowlist.
- **No automatic external provider:** recursive DNS by default, with forwarding and timeout fallback opt-in.
- **DNSSEC on:** local validation is enabled unless explicitly changed.
- **No query history or telemetry:** neither is enabled in the release configuration; aggregate metrics are opt-in.
- **No surprise filters:** external blocklists, policies, and provider integrations require deliberate configuration.
- **Restricted administration:** the local management API is off by default and, when enabled, requires managed mode, loopback binding, and authentication.

**Privacy has limits.** Recursive queries still contact internet DNS infrastructure; configured forwarders receive the queries you send them. DNS filtering cannot stop applications that use other DNS endpoints without separate network controls. TLS keys, trust anchors, logs, local file permissions, and public listener exposure remain operator responsibilities. Lumen has not yet completed external security review.

Read the [threat model](docs/threat-model.md) and [security policy](SECURITY.md). Report vulnerabilities **privately** via [GitHub security advisories](https://github.com/StruktSource/lumen-dns/security/advisories/new), not public issues.

## Built for operators and contributors

Lumen is a Rust workspace with a shared resolver pipeline, bounded network admission, and deliberately separated DNS, filtering, state, API, and web components. It builds on [Hickory DNS](https://github.com/hickory-dns/hickory-dns) for DNS protocol and resolver foundations.

```text
Client (UDP · TCP · DoH · DoT · DoQ)
                    │
           Access and rate limits
                    │
          Filter policy snapshot ─── Block response
                    │
        Recursive or forward resolver
                    │
        DNSSEC validation + cache
                    │
                 Response

TOML / SQLite / lumenctl / opt-in API → configuration + control
Opt-in Prometheus / Grafana / webhooks → visibility + integration
```

The diagram is conceptual; see [architecture](docs/architecture.md) for exact component responsibilities and boundaries.

## Where the project stands

**Implemented:** recursive and forwarding DNS, five client transports, DNSSEC, policy filtering, local state/CLI controls, authenticated management API, metrics, and baseline deployment artifacts.

**Still ahead:** persistent query history, expanded interoperability and soak tests, image/release validation, automatic certificate and trust-anchor rotation, split DNS/local records, high availability, and independent security review. These are **roadmap items, not current product capabilities**.

Follow the [implementation checklist](docs/progress.md), [detailed TODO](docs/TODO.md), and [long-term product plan](docs/DNS_SERVICE_PLAN.md). Existing measurements and their limitations are in [performance snapshots](docs/performance.md); there is no verified production throughput or latency claim here.

## Documentation

| Topic | Start here |
| :--- | :--- |
| Installation & platform evidence | [Deployment index](docs/deployment/README.md) · [Compatibility](docs/deployment/compatibility.md) |
| Configure Lumen | [Configuration reference](docs/configuration.md) |
| DNS behavior, modes & encryption | [Resolver operations](docs/resolver.md) · [Providers](docs/upstream-providers.md) |
| Blocklists, devices & schedules | [Filtering](docs/filtering.md) |
| Local control & storage | [State and control](docs/state-and-control.md) |
| Authenticated API | [Management API](docs/management-api.md) |
| Metrics & integrations | [Observability](docs/observability.md) |
| Web console (accounts, UI, HTTPS) | [Web console](docs/web-hosting.md) |
| Design and security | [Architecture](docs/architecture.md) · [Threat model](docs/threat-model.md) |
| Testing and measurement | [Verification](docs/verification.md) · [Performance](docs/performance.md) |

## Help build Lumen

Contributions, bug reports, interoperability testing, documentation improvements, and reproducible deployment feedback are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and follow the [Code of Conduct](CODE_OF_CONDUCT.md). For vulnerabilities, use the [private reporting channel](SECURITY.md).

Lumen is developed by [Strukt](https://github.com/StruktSource) and released under the [Apache License 2.0](LICENSE).

---

<div align="center">

**Own your resolver. Understand your DNS. Build on your terms.**

[Get started](#quick-start) · [Read the docs](#documentation) · [Contribute](CONTRIBUTING.md)

</div>

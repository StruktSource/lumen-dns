# Roadmap and status

Where Lumen is today and where it is going. This page replaces the former separate *progress*, *TODO*, and *product plan* documents.

_Last updated 2026-11-08 for version 0.5.6._

> [!IMPORTANT]
> Lumen is **pre-release**. A checked box means *implemented, documented, and covered by the checks in the [verification record](verification.md)*. It does **not** mean production-ready, and unrun platform checks or planned features are never marked as shipped.

## At a glance

**Working today**

- Recursive and forwarding DNS over UDP, TCP, DoH, DoT, and DoQ on IPv4 and IPv6
- Local DNSSEC validation, bounded caches, and rate and resource limits
- Filtering with lists, per-device profiles, categories, and UTC schedules
- Managed mode with SQLite state, safe reloads, and `lumenctl`
- The built-in web console with accounts, roles, and optional two-step verification
- An optional authenticated loopback management API with signed webhooks
- Privacy-safe Prometheus metrics, a Grafana dashboard, and Home Assistant examples
- Native packages for six platforms and container images for `linux/amd64` and `linux/arm64`

**Still ahead**

- Opt-in persistent query history
- Certificate automation and automatic trust-anchor rollover
- Split DNS, local records, and conditional forwarding
- High availability and cluster configuration replication
- Extended DNS and DNSSEC conformance tests and long-running soak tests
- Real-hardware validation for Proxmox, Unraid, Raspberry Pi, and dual-stack Kubernetes
- Image signing, reproducible builds, and backup, restore, and upgrade tests
- **Independent security review before a stable release**

## The goal

One ultra-light, high-performance, fully open-source DNS service that combines Pi-hole or AdGuard-style filtering with an Unbound-style validating recursive cache. Privacy first, fully self-hosted. The product is **Lumen**, built by **Strukt**.

Principles that shape every decision:

- **Private by default:** no telemetry, no tracking, no cloud dependency. Query logging is disabled or minimized by default, and DNS data stays on your systems unless you configure an upstream.
- **Least privilege:** rootless or unprivileged execution wherever the platform allows.
- **Bounded everything:** strict caps, timeouts, retries, and rate limits.
- **Readable config with safe defaults**, plus a full CLI, an optional UI, and a secure local API.
- **x86-64 and ARM64** from the first release, IPv4 and IPv6 end to end, and one shared engine on every platform.

## Progress by area

### Foundation

- [x] Rust workspace, Apache-2.0, SemVer (currently `0.5.6`)
- [x] README, contributor guide, security policy, and code of conduct
- [x] Architecture, threat model, privacy defaults, and protocol scope
- [x] CI for Linux, macOS, Windows, lint, tests, and the minimum Rust version
- [x] Binary release workflow with distinct platform archives and checksums
- [x] Non-root Docker image and local build scripts
- [x] Startup schema 1, validation rules, and explicit rejection of future versions
- [x] Minimal release default with opt-in forwarding and filtering examples
- [x] Aggregate metrics naming contract and loopback Prometheus endpoint
- [x] DNS, config, and filter fuzz targets with fuzz smoke CI
- [x] RustSec dependency audit and audit CI
- [x] SQLite schema migrations and validated config reload with rollback
- [ ] SBOM, signed images, and reproducible-release verification (SBOM and provenance are configured, signing and reproducibility are not)

### Phase 1: Secure resolver core (implemented)

- [x] Full bounded DNS message decoding, including compressed response names
- [x] Strict single-question and EDNS query validation, and DNS error encoding
- [x] UDP and persistent framed TCP listeners
- [x] DoH (HTTP/2 GET and POST), DoT, and DoQ listeners with supplied TLS credentials
- [x] IPv4 and IPv6 integration coverage for all five client transports
- [x] Iterative resolver with bundled dual-stack root hints and QNAME minimization
- [x] Delegation, bailiwick and glue filtering, and recursive authority-address controls
- [x] Positive and negative response cache, TTL ceilings, delegation and validation caches
- [x] DNSSEC validation, signed denial, bundled and override trust anchors, and a rollover runbook
- [x] Explicit forwarding with UDP, TCP, and verified DoT, DoH, and DoQ upstreams
- [x] Encrypted-only provider transport selection and connection-failure failover
- [x] Opt-in recursive timeout fallback with DNSSEC, loop, and deadline guards
- [x] Shared query and connection admission, packet bounds, and client IP rate limits
- [x] Query, I/O, handshake, and forwarding retry and deadline bounds
- [x] DNS failure handling, listener failure propagation, and signal shutdown
- [x] Aggregate query, failure, and timeout metrics and a loopback liveness endpoint
- [x] Offline protocol, DNSSEC, cache, delegation, and load-limit tests
- [x] A bounded 256-query concurrent load regression

### Phase 2: Filtering (implemented)

- [x] Normalized allow and block rules with precedence
- [x] Global lists and manual domain rules
- [x] Per-device, subnet, group, and profile policies
- [x] Online list fetcher and local file importer
- [x] Hosts, domain-list, and Adblock DNS parsers
- [x] Atomic list update, validation, and rollback
- [x] Configurable block responses and explainable decisions
- [x] Parental schedules and category profiles

### Phase 3: Control and visibility

- [x] Validated reload and explicit SQLite schema migrations
- [x] SQLite configuration and device storage
- [x] Cross-platform local `lumenctl` for config, device, filter, status, and shutdown
- [x] Extended privacy-safe Prometheus metrics and a ready Grafana dashboard
- [x] Loopback authenticated `/v1` API with scoped roles, rate limits, and audit events
- [x] Signed HTTPS audit webhooks and Home Assistant examples
- [x] Embedded web hosting over HTTP and direct TLS HTTP/2, with a vendor-neutral HTTP/3 reverse-proxy contract
- [x] Functional web console: aggregate status, settings, filtering, devices, users, audit log, and opt-in in-memory recent queries (off by default)
- [x] Optional TOTP two-step verification with recovery codes and admin reset
- [x] Shared in-flight recursion, startup priming, opt-in expiry refresh and hedging, and recursion latency metrics (Issue #9)
- [ ] Opt-in anonymous or full **persistent** query history, with retention and redaction controls

### Phase 4: Deployment

- [x] Local Docker and OrbStack build base
- [x] One shared Rust DNS core and schema across native and container targets
- [x] Native AMD64 and ARM64 CI jobs for Linux, macOS, and Windows
- [x] Versioned native archives, checksums, SBOM and provenance, and OCI publishing
- [x] Restricted Docker Compose, Kubernetes, Helm, and systemd files
- [x] Guides for Docker, Podman, Kubernetes, bare metal, Proxmox, Unraid, Raspberry Pi, macOS, and Windows
- [x] Hosted native runtime evidence for every configured runner
- [x] Hosted OCI, rootless Podman, and Kind UDP and TCP runtime smoke tests
- [x] Tagged releases publish step by step, with native packages and multi-architecture images (v0.5.5 and v0.5.6)
- [ ] Real Proxmox, Unraid, Raspberry Pi, Podman ARM64, and dual-stack Kubernetes validation
- [ ] Backup, restore, upgrade, and removal tests

### Phase 5: Advanced DNS and availability

- [x] Base DoH, DoT, and DoQ listeners (delivered in Phase 1)
- [ ] Certificate automation and automatic trust-anchor rollover
- [ ] Split DNS, local records, conditional forwarding, and safe local service discovery
- [ ] High availability, multi-service use, cluster configuration replication, and a cache strategy
- [ ] Optional DNS threat feeds and enterprise policy features that leave privacy defaults unchanged
- [ ] Extended DNS and DNSSEC conformance and long-running soak tests
- [ ] **External security review before stable release**

## What is planned next

This is a recommended order, not a dated commitment.

1. Opt-in anonymous or full query history with retention and redaction. When built, default retention is seven days, with detail level and retention configurable per profile and device group.
2. Continue release validation, soak tests, and independent security review.
3. Record real-hardware platform results and add backup, restore, and upgrade tests.
4. Add keyless image signing and reproducible-build comparison.
5. Trust-anchor rollover automation and certificate lifecycle tooling.

## Recursion speed (Issue #9)

Implemented and partly measured.

- [x] Reproducible A/B benchmark with trial-level statistics (`scripts/recursion_bench.py`)
- [x] Shared in-flight recursion, startup priming, opt-in expiry refresh and hedging, and latency metrics
- [ ] Show a statistically significant public-network cold single-query gain. The first 12-trial run was **not** significant; a deterministic local test does prove that priming reduces authority round trips and latency
- [ ] Benchmark expiry refresh (it has unit tests only)

Results and caveats: [Performance](performance.md).

## Upstream follow-up

`vendor/hickory-net` carries a one-line DNSSEC fix, described in [DNSSEC and trust anchors](../reference/dnssec-and-trust.md#edge-case-parent-and-child-on-the-same-servers) and [`vendor/README.md`](../../vendor/README.md). The plan is to report it to the Hickory project with the reproduction (`safebrowsing.google.com`, then `google.com`, on a fresh process with validation enabled) and drop the vendored copy once a release contains it.

## Open design questions

- UI technology and whether the UI ships in the default image (the current console is embedded)
- The high-availability and cluster consistency model
- Certificate automation and encrypted-listener defaults

## Release gates for 1.0

Stable `1.0.0` needs proven resolver and filter behavior, migration and upgrade paths, deployment validation, and a security review. See [Versioning and releases](versioning.md).

## Related

- [Verification record](verification.md): what has actually been run
- [Compatibility matrix](../deployment/compatibility.md): platform-by-platform evidence
- [Changelog](../../CHANGELOG.md)

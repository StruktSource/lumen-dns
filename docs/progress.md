# Lumen implementation checklist

Updated 2026-10-30. Checked means implemented, documented, and covered by the
checks in [verification](verification.md). It does not mean production-ready.

## Foundation

- [x] Lumen by Strukt, Apache-2.0, Rust workspace, SemVer `0.1.0`
- [x] README, contributor guide, security policy, code of conduct
- [x] Architecture, threat model, privacy defaults, and protocol scope
- [x] CI definitions for Linux, macOS, Windows, lint, tests, and MSRV
- [x] Binary release workflow with distinct platform archives and checksums
- [x] Non-root Docker image and local build scripts
- [x] Blank UI shell and disabled API extension boundary
- [x] Startup schema 1, validation rules, explicit future-version rejection
- [x] Aggregate metric naming contract and loopback Prometheus endpoint
- [x] DNS/config fuzz targets and fuzz smoke CI
- [x] RustSec dependency audit and audit CI
- [ ] Actual schema migrations and hot reload
- [ ] SBOM, signed images, reproducible-release verification

## Phase 1 — Secure resolver core: implemented

- [x] Full bounded DNS message and compressed response-name decoding
- [x] Strict single-question/EDNS query validation and DNS error encoding
- [x] UDP and persistent framed TCP listeners
- [x] DoH HTTP/2 GET/POST, DoT, and DoQ listeners with supplied TLS credentials
- [x] IPv4/IPv6 integration coverage for all five client transports
- [x] Iterative resolver, bundled dual-stack root hints, QNAME minimization
- [x] Delegation, bailiwick/glue filtering, and recursive authority-address controls
- [x] Positive/negative response cache, TTL ceilings, delegation and validation caches
- [x] DNSSEC validation, signed denial, bundled/override trust anchors, rollover runbook
- [x] Explicit forwarding with UDP/TCP and verified DoT/DoH/DoQ upstreams
- [x] Shared query/connection admission, packet bounds, client IP rate limits
- [x] Query, IO, handshake, and forwarding retry/deadline bounds
- [x] DNS failure handling, listener failure propagation, signal shutdown
- [x] Aggregate query/failure/timeout metrics and loopback liveness endpoint
- [x] Offline protocol, DNSSEC, cache, delegation, and load-limit tests
- [x] Bounded 256-query concurrent load regression

## Phase 2 — Filtering: implemented

- [x] Normalized allow/block rules and precedence
- [x] Global lists and manual domain rules
- [x] Per-device, subnet, group, and profile policies
- [x] Online list fetcher and local-file importer
- [x] Hosts, domain-list, and Adblock DNS parsers
- [x] Atomic list update, validation, rollback
- [x] Configurable block responses and explainable decisions
- [x] Parental schedules and category profiles

## Phase 3 — Control and visibility

- [ ] Hot reload and schema migrations
- [ ] Full `lumenctl` commands
- [ ] SQLite configuration and device storage
- [ ] Extended Prometheus metrics and Grafana dashboard
- [ ] Authenticated `/v1` API, scoped roles, audit events
- [ ] Webhooks and Home Assistant examples
- [ ] Local UI prototype with mock data after the first filtering slice
- [ ] Functional web UI after config persistence/reload and API security
- [ ] Opt-in anonymous/full query history

## Phase 4 — Deployment

- [x] Local Docker/OrbStack build base
- [ ] Multi-architecture image publishing and platform runtime validation
- [ ] Network-wide and local-only Compose examples
- [ ] Proxmox LXC, Unraid, systemd, bare-metal guides
- [ ] Backup, restore, upgrade, removal tests

## Phase 5 — Advanced DNS and availability

- [x] Base DoH/DoT/DoQ listeners delivered in Phase 1
- [ ] Certificate automation and automatic trust-anchor rollover
- [ ] Split DNS, local records, conditional forwarding
- [ ] HA, cluster configuration replication, cache strategy
- [ ] Extended DNS/DNSSEC conformance and long-running soak tests
- [ ] External security review before stable release

## Next technical slice

1. Add SQLite configuration/device persistence and explicit schema migrations.
2. Add validated config reload and full CLI control, including Windows controls.
3. Build authenticated management API before a functional web UI.

Filtering usage and bounds: [guide](filtering.md).

Detailed next work: [TODO](TODO.md). Product scope:
[roadmap](DNS_SERVICE_PLAN.md). Current validation limits:
[verification](verification.md).

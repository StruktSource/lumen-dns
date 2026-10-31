# Lumen implementation checklist

Updated 2026-10-31. Checked means implemented, documented, and covered by the
checks in [verification](verification.md). It does not mean production-ready.

## Foundation

- [x] Lumen by Strukt, Apache-2.0, Rust workspace, SemVer `0.1.1`
- [x] README, contributor guide, security policy, code of conduct
- [x] Architecture, threat model, privacy defaults, and protocol scope
- [x] CI definitions for Linux, macOS, Windows, lint, tests, and MSRV
- [x] Binary release workflow with distinct platform archives and checksums
- [x] Non-root Docker image and local build scripts
- [x] Blank UI shell and disabled API extension boundary
- [x] Startup schema 1, validation rules, explicit future-version rejection
- [x] Minimal release default with opt-in forwarding and filtering examples
- [x] Aggregate metric naming contract and loopback Prometheus endpoint
- [x] DNS/config fuzz targets and fuzz smoke CI
- [x] RustSec dependency audit and audit CI
- [x] SQLite schema migrations and validated config reload with rollback
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
- [x] Encrypted-only provider transport selection and connection-failure failover
- [x] Opt-in recursive timeout fallback with DNSSEC, loop, and deadline guards
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

- [x] Validated reload and explicit SQLite schema migrations
- [x] Cross-platform local `lumenctl` config/device/filter/status controls
- [x] SQLite configuration and device storage
- [x] Extended privacy-safe Prometheus metrics and ready Grafana dashboard
- [x] Loopback authenticated `/v1` API, scoped roles, rate limits, audit events
- [x] Signed HTTPS audit webhooks and Home Assistant examples
- [x] Embedded blank UI hosting over HTTP and direct TLS HTTP/2
- [x] Vendor-neutral HTTP/3 reverse-proxy contract
- [ ] Local UI prototype with mock data after the first filtering slice
- [ ] Functional web UI after config persistence/reload and API security
- [ ] Opt-in anonymous/full query history
- [x] Shared in-flight recursion, startup priming, opt-in expiry refresh and hedging, recursion latency metrics (Issue #9); cold single-query gain not statistically significant

## Phase 4 — Deployment

- [x] Local Docker/OrbStack build base
- [x] One shared Rust DNS core and schema across native and container targets
- [x] Native AMD64/ARM64 Linux, macOS, and Windows CI job definitions
- [x] Versioned native archive, checksum, SBOM/provenance, and OCI publish definitions
- [x] Restricted Docker Compose, Kubernetes, Helm, and systemd deployment files
- [x] Docker, Podman, Kubernetes, bare-metal, Proxmox, Unraid, Pi, macOS, and Windows guides
- [x] Hosted native runtime evidence for every configured runner
- [x] Hosted OCI, rootless Podman, and Kind UDP/TCP runtime smoke
- [ ] Tagged multi-architecture image publishing and release-artifact validation
- [ ] Real Proxmox, Unraid, Raspberry Pi, and dual-stack Kubernetes validation
- [ ] Backup, restore, upgrade, removal tests

## Phase 5 — Advanced DNS and availability

- [x] Base DoH/DoT/DoQ listeners delivered in Phase 1
- [ ] Certificate automation and automatic trust-anchor rollover
- [ ] Split DNS, local records, conditional forwarding
- [ ] HA, cluster configuration replication, cache strategy
- [ ] Extended DNS/DNSSEC conformance and long-running soak tests
- [ ] External security review before stable release

## Next technical slice

1. Add the first small UI screen on the embedded hosting base.
2. Add opt-in anonymous/full query history with retention and redaction controls.
3. Continue release validation, soak tests, and external review.

Filtering usage and bounds: [guide](filtering.md).

Detailed next work: [TODO](TODO.md). Product scope:
[roadmap](DNS_SERVICE_PLAN.md). Current validation limits:
[verification](verification.md).

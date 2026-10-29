# ✅ Lumen implementation checklist

Updated as features land. Checked means present, tested where applicable, and
documented. It does **not** mean production-ready unless stated.

## Foundation

- [x] Product identity: Lumen by Strukt
- [x] Apache-2.0 license
- [x] Rust workspace and SemVer `0.1.0`
- [x] Public README, contributor guide, security policy, code of conduct
- [x] Architecture and threat-model documents
- [x] CI checks on Linux, macOS, and Windows
- [x] Tag-triggered GitHub binary-release workflow
- [x] Dockerfile and local OCI-image build scripts
- [x] Linux/macOS shell and Windows PowerShell development scripts
- [x] Blank UI shell and reserved API crate
- [ ] Config schema and migration rules
- [ ] Metrics naming contract and Prometheus endpoint
- [ ] SBOM, signed images, reproducible release verification
- [ ] Fuzz harness and fuzzing CI

## Phase 1 — DNS transport and resolver

- [x] Bounded single-question parser and bounded compression-pointer validation
- [ ] Full DNS message and compressed-name decoding for resolver responses
- [x] DNS error-response encoder
- [x] Unit tests for valid and invalid DNS question handling
- [x] UDP listener base
- [x] TCP listener base with DNS-over-TCP framing
- [x] TCP connection cap and read/write timeouts
- [x] Safe default response: `SERVFAIL` until resolver exists
- [ ] IPv4 and IPv6 listener integration tests
- [ ] Recursive resolver and root-hints handling
- [ ] Delegation and bailiwick checks
- [ ] Positive and negative cache
- [ ] DNSSEC trust-anchor management and validation
- [ ] Upstream forwarding mode
- [ ] Encrypted upstream resolver support
- [ ] Resolver query timeout, retry, concurrency, and client rate limits
- [ ] Basic resolver health and query metrics
- [ ] DNS conformance and sustained-load tests

## Phase 2 — Filtering

- [ ] Normalized allow/block rule engine and precedence
- [ ] Global lists and manual domain rules
- [ ] Per-device, subnet, group, and profile policies
- [ ] Online list fetcher and local-file importer
- [ ] Hosts, domain-list, and Adblock DNS format parsers
- [ ] Atomic list update, validation, and rollback
- [ ] Configurable block responses
- [ ] Explainable filter decision records
- [ ] Parental schedules and category profiles

## Phase 3 — Control and visibility

- [ ] Config file, validation, hot reload, and migrations
- [ ] Full `lumenctl` commands
- [ ] SQLite configuration and device storage
- [ ] Prometheus metrics and Grafana dashboard
- [ ] Authenticated `/v1` API, scoped roles, and audit events
- [ ] Webhooks and Home Assistant examples
- [ ] Functional web UI
- [ ] Opt-in anonymous and full query history

## Phase 4 — Deployment

- [x] Local Docker/OrbStack build base
- [ ] Rootless runtime image verification
- [ ] Multi-architecture container publishing: x86_64 and ARM64
- [ ] Network-wide Compose example
- [ ] Local-only Docker Desktop/OrbStack Compose example
- [ ] Proxmox LXC, Unraid, systemd, and bare-metal guides
- [ ] Backup, restore, upgrade, and removal tests

## Phase 5 — Advanced DNS and availability

- [ ] DoH listener
- [ ] DoT listener
- [ ] DoQ listener
- [ ] Certificate and key management
- [ ] Split DNS, local records, and conditional forwarding
- [ ] HA, multi-service, cluster configuration replication
- [ ] External security review

## Next technical slice

1. Define resolver interfaces and root-hints source.
2. Implement iterative resolution with hard timeout and recursion limits.
3. Add bounded positive/negative cache before upstream forwarding.

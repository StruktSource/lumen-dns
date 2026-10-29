# DNS Service Plan

## General

### Product goal

Build one ultra-light, high-performance, fully open-source DNS service.
It joins Pi-hole or AdGuard-style filtering with an Unbound-style recursive,
validating cache. Privacy-first. Fully self-hosted.

Product name: **Lumen**. Organization: **Strukt**.

### Platform and runtime

- Rust implementation.
- Setup lets operator enable only needed modules. Built-in modules come first; plugin model comes later.
- x86_64 and ARM64 support from first release.
- IPv4 and IPv6 end-to-end.
- Docker, Docker Compose, Proxmox LXC, Unraid, bare-metal, and Linux service-manager support.
- Network-wide mode: router or DHCP advertises service as DNS server.
- Local-only mode: Docker Desktop or OrbStack binds listeners only to loopback.
- Least privilege. Rootless or unprivileged execution where platform permits it.

### DNS service

- Recursive resolution, local DNS records, and validating cache.
- Cache positive, negative, delegation, and DNSSEC records.
- DNSSEC validation with safe trust-anchor management.
- Configurable UDP, TCP, DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC, and normal unencrypted DNS.
- Configurable encrypted upstream resolvers and full recursive mode.
- Split DNS, conditional forwarding, local zones, and custom records.
- Strict resource caps, timeouts, retries, rate limits, and abuse resistance.

### Filtering and policies

- Import online blocklists by URL, local file, pasted text, CLI, UI, config, or API.
- Parse common hosts-file, domain-list, and Adblock DNS list formats.
- Global allow/block lists plus client, device, subnet, group, and profile policies.
- Filter groups and profiles for family, guest, work, IoT, and custom uses.
- Parental-control schedules and category rules.
- Configurable block action: NXDOMAIN, NODATA, local address, or custom response.
- Atomic list updates with validation and rollback. Failed update never disrupts live filtering.
- Explain each decision: matched rule, list, profile, and action.

### Control plane

- Plain readable config file with safe privacy defaults.
- Full CLI for config, health, cache, list, device, profile, and service actions.
- Optional web UI for setup, activity, devices, policies, and diagnostics.
- First release includes CLI, config, and a blank UI shell. API routes and access stay disabled until API security work is complete.
- Secure local API by default. Strong auth, authorization, rate limits, and audit records when exposed.
- Stable API with webhooks and integrations for Home Assistant, scripts, and user tooling.
- Hot reload for safe config and list changes with no resolver downtime.

### Observability and privacy

- Structured logs, health endpoints, Prometheus-compatible metrics.
- Grafana dashboard definitions and documented metric names.
- No external telemetry, tracking, or cloud dependency.
- Query logging disabled or minimized by default. Retention, redaction, and access configurable.
- Default dashboards show aggregate numbers only. Optional anonymous or full query logs default to seven days; each profile, device group, detail level, and retention period stays configurable.
- DNS data stays on user systems unless user configures an upstream resolver.

### Reliability, security, and distribution

- Fuzz DNS parser and every external input.
- Unit, integration, compatibility, DNSSEC, load, and upgrade tests.
- Threat model, security policy, contribution guide, license, reproducible builds, SBOM, signed images, and checksums.
- Small multi-architecture container images.
- Clear install and upgrade guides for each deployment target.
- Design for multi-service and cluster use. Start with safe standalone operation.

## Implementation status — 2026-10-29

Phase 1 secure resolver core is implemented. UDP/TCP/DoH/DoT/DoQ, IPv4/IPv6,
iterative recursion, DNSSEC, bounded caches, verified upstream forwarding,
resource admission, aggregate metrics, and offline regression tests are present.
Startup schema and fuzz/audit CI also landed. This is a pre-release, not the
complete first release. Phase 2 filtering is next. See
[progress](docs/progress.md), [verification](docs/verification.md), and
[TODO](TODO.md) for shipped scope and remaining release gates.

## Roadmap

### Phase 0 — Foundation

1. Choose project name, Rust workspace layout, license, and version policy.
2. Write architecture, protocol scope, threat model, privacy model, and compatibility rules.
3. Define config schema, API versioning, error model, and metrics names.
4. Create CI for formatting, linting, tests, fuzzing, releases, SBOM, and multi-arch containers.
5. Add empty UI and API extension points without enabling API access.

### Phase 1 — Secure resolver core (implemented)

1. Implement UDP, TCP, DoH, DoT, and DoQ listeners for IPv4 and IPv6.
2. Implement recursive resolver, cache, root hints, delegation handling, and DNSSEC validation.
3. Add upstream-forwarding mode and encrypted upstream support.
4. Add bounded memory, timeouts, retries, rate limits, and basic query metrics.
5. Test DNS behavior, DNSSEC failures, cache behavior, and load limits.

### Phase 2 — Filtering engine

1. Build normalized domain-rule engine with allow/block precedence.
2. Add global rules and per-client, subnet, device, group, and profile policies.
3. Add online-list fetcher, local import, manual edits, format parsers, checks, atomic updates, and rollback.
4. Add filter-action choices and decision-explanation logs/API.
5. Add parental schedules and initial category profiles.

### Phase 3 — Configuration and integrations

1. Deliver config file, validation, migration, reload, and CLI.
2. Deliver authenticated API, scoped roles, tokens, audit logs, and webhooks.
3. Add Home Assistant integration and API-client examples.
4. Add Prometheus metrics, ready Grafana dashboard, health checks, and diagnostics bundle.
5. Build optional web UI. API and CLI stay full-featured without it.

### Phase 4 — Deployment

1. Publish rootless Docker image for x86_64 and ARM64.
2. Provide Compose examples for router-wide DNS and local-only Docker Desktop/OrbStack DNS.
3. Provide Proxmox LXC, Unraid, systemd, and bare-metal install guides.
4. Document port 53, encrypted-DNS ports, router DHCP settings, firewall rules, IPv6, and upgrade paths.
5. Test clean install, upgrade, backup, restore, and removal on each target.

### Phase 5 — Advanced DNS and availability

1. Extend Phase 1 DoH, DoT, and DoQ with automated certificate/key lifecycle management.
2. Add split DNS, local records, conditional forwarding, and safe local service discovery.
3. Add HA, multi-service, cluster config replication, and cache strategy.
4. Add optional DNS threat feeds and enterprise policy features without changing privacy defaults.
5. Run external security review and sustained load tests before stable release.

## Later decisions

- UI technology and whether UI ships in default image.
- HA/cluster consistency model.
- Certificate automation and encrypted-listener defaults.

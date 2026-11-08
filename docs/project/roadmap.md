# Roadmap and status

Where Lumen is today and where it is going. This page replaces the former separate *progress*, *TODO*, and *product plan* documents.

_Last updated 2026-11-08 for version 0.5.7._

> [!IMPORTANT]
> Lumen is **pre-release**. A checked box means *implemented, documented, and covered by the checks in the [verification record](verification.md)*. It does **not** mean production-ready, and unrun platform checks or planned features are never marked as shipped.

## At a glance

**Working today**

- Recursive and forwarding DNS over UDP, TCP, DoH, DoT, and DoQ on IPv4 and IPv6
- Local DNSSEC validation, bounded caches, and rate and resource limits
- Filtering with lists, per-device profiles, categories, and UTC schedules
- Managed mode with SQLite state, safe reloads, and `lumenctl`
- The built-in web console with accounts, roles, and optional two-step verification, in English, German, Italian, Spanish, and Dutch
- Opt-in query history: recent lookups in memory, or saved for 1 to 90 days, anonymous or with the device
- An optional authenticated loopback management API with signed webhooks
- Privacy-safe Prometheus metrics, a Grafana dashboard, and Home Assistant examples
- Native packages for six platforms and container images for `linux/amd64` and `linux/arm64`

**Still ahead**

- Certificate automation and automatic trust-anchor rollover
- Split DNS, local records, and conditional forwarding
- High availability and cluster configuration replication
- Extended DNS and DNSSEC conformance tests and long-running soak tests
- Real-hardware validation for Proxmox, Unraid, Raspberry Pi, and dual-stack Kubernetes
- Image signing, reproducible builds, and backup, restore, and upgrade tests
- A customizable console UI through CSS themes
- More console languages, and translating the remaining long help texts
- **Independent security review before a stable release**

Parked ideas that are **not planned yet** (such as community plugins and a store) are listed at the end under [Ideas, not now](#ideas-not-now).

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

- [x] Rust workspace, Apache-2.0, SemVer (currently `0.5.7`)
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
- [x] Functional web console: aggregate status, settings, filtering, devices, users, and audit log
- [x] Optional TOTP two-step verification with recovery codes and admin reset
- [x] Shared in-flight recursion, startup priming, opt-in expiry refresh and hedging, and recursion latency metrics (Issue #9)
- [x] Opt-in query history: off by default, recent-only (memory) or saved (SQLite), anonymous or with device and address, 1-90 days retention (default 7), a 500,000-row cap, search, paging, deletion, and `lumenctl history` (0.5.7)

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

### Phase 6: Customization

Each item has to keep Lumen's defaults intact: private, bounded, and explicit opt-in.

**Customizable UI via CSS** (planned)

- [ ] A **theme file in plain CSS**. Users open it, edit the colors, and apply it in the console, for example for a dark or high-contrast look and their own accent colors
- [ ] A design that fits the console's strict Content-Security-Policy (no inline styles or scripts, same-origin assets only), such as a theme file served by Lumen itself. A theme changes appearance only, and must not be able to read or send data

**Localization** (0.5.7)

- [x] The web console in English (default), German, Italian, Spanish, and Dutch
- [x] A translation framework: message catalogs keyed by the English text, a per-browser choice, a console default for administrators, a browser-language fallback, and locale-aware numbers
- [x] A language step in the setup wizard, and language settings under My account and Users & access
- [x] A documented way to add or improve a translation, with tests that keep the catalogs complete and current ([Languages and translations](../guides/translations.md))
- [ ] Translate the remaining long help texts on the DNS settings and Filtering pages
- [ ] More languages
- [ ] Localize the documentation where practical. Technical terms such as DoH, DoT, and DNSSEC stay recognizable

## What is planned next

Open items, from most to least urgent. This is a recommended order, not a dated commitment. Validation, testing, and release-hardening work lives in [Side projects](#side-projects) so it does not crowd the feature list.

### High priority: do next

1. **Publish release 0.5.7.** It carries opt-in query history and the localized console. Tag `v0.5.7` to run the release pipeline.

### Medium priority: soon

2. **CSS themes** for the console.
3. **Finish the translations:** the remaining long help texts, and more languages.

### Lower priority: later

4. **Trust-anchor rollover automation and certificate lifecycle tooling.**
5. **Split DNS, local records, and conditional forwarding.**
6. **Recursion speed evidence:** a statistically significant cold-query result and an expiry-refresh benchmark (see [Recursion speed](#recursion-speed-issue-9)).

### Large efforts, before or after 1.0

7. **Independent security review.** Required before a stable release.
8. **High availability and cluster configuration replication.**
9. **Optional DNS threat feeds and enterprise policy features.**

### Not now

10. **Plugins, add-ons, and a community store.** Parked as an idea. See [Ideas, not now](#ideas-not-now).

## Side projects

Important work that does not add a feature. It can be done in any order and by anyone, and does not block the feature list above, except that the first two are needed before a stable release.

- [ ] **Real-hardware validation:** Proxmox, Unraid, Raspberry Pi, Podman ARM64, and dual-stack Kubernetes. Record the results in the [compatibility matrix](../deployment/compatibility.md)
- [ ] **Backup, restore, upgrade, and removal tests**, now that persistent state exists
- [ ] **Conformance and soak tests:** extended DNS and DNSSEC conformance suites and long-running soak tests
- [ ] **Release hardening:** keyless image signing and reproducible-build comparison (SBOM and provenance are already configured)
- [ ] **Report the DNSSEC fix upstream** to Hickory, then drop the vendored copy (see [Upstream follow-up](#upstream-follow-up))

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
- How custom CSS themes coexist with the console's strict Content-Security-Policy, and whether a theme applies per user or to the whole console
- Where translations live (embedded in the binary or loaded as language packs) and how contributors submit them

## Release gates for 1.0

Stable `1.0.0` needs proven resolver and filter behavior, migration and upgrade paths, deployment validation, and a security review. See [Versioning and releases](versioning.md).

## Ideas, not now

Ideas that are written down so they are not lost, but **not planned, not designed, and not scheduled**. Nobody has worked out how to build them safely yet, and nothing here should be read as a commitment.

### Plugins, add-ons, and a community store

The idea: users could write plugins ("extension modules") that add features to Lumen. A first, deliberately small version would have **no store, no marketplace, and no server of our own**. GitHub would be the only place involved:

1. A contributor writes a plugin as **one file that follows a defined standard**.
2. They submit it as a **pull request** to the Lumen repository, where review is the trust gate.
3. Merged plugins live **in the repository, but not in the container image or release binary**.
4. A running Lumen reads the **list of available plugins from the repository**, and the user installs the ones they want from the **web console or `lumenctl`**.

CSS themes shared by the community, and translations, could use the same route. Nothing would be downloaded or run until the user asks for it, and nothing would contact GitHub in the background.

If this is ever picked up, it would need at least:

- [ ] A plugin standard: the single-file format and a manifest (name, version, description, author, required permissions, compatible Lumen versions)
- [ ] Plugins that add features without being able to touch the DNS parser or bypass resolver limits, admission, or filtering
- [ ] Explicit, user-approved permissions, shown before install
- [ ] List, install, enable, disable, update, and remove from the console and `lumenctl`
- [ ] Install only on explicit user action, over verified HTTPS, checked against a pinned commit or hash, kept outside the container image, and stored in the state directory
- [ ] An offline install from a local file for air-gapped networks
- [ ] A contributor guide, review rules, and a pull request template

Open questions (all unanswered):

- What the plugin file actually is: a declarative manifest, a script, or a compiled module, and how it is sandboxed
- What a plugin may read, change, or call, and how permissions are shown and approved
- Where installed plugins live in the state directory, and how that works with a read-only container filesystem, upgrades, and rollback
- Supply-chain safety of a GitHub-based list: pinning, review rules for pull requests, and revoking a plugin that turns out to be bad
- Privacy: fetching the list contacts GitHub, so it must only happen on a user action and never in the background
- Whether a store of any larger kind is ever worth it

## Related

- [Verification record](verification.md): what has actually been run
- [Compatibility matrix](../deployment/compatibility.md): platform-by-platform evidence
- [Changelog](../../CHANGELOG.md)

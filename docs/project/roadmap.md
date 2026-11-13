# Roadmap and status

Where Lumen is today and where it is going. This page replaces the former separate *progress*, *TODO*, and *product plan* documents.

_Last updated 2026-11-13 for version 0.7.0._

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
- Block lists that install in the background without restarting anything, are never downloaded twice by accident, and can be cancelled
- Forward mode with up to 8 ranked providers and a choice of ranked fallback, fastest first, round-robin, or race
- Optional external console login through OpenID Connect providers (off by default)
- Native packages for six platforms and container images for `linux/amd64` and `linux/arm64`
- An admin-only local DNS manager with typed, bounded zones and records, safe staged apply, and advanced zones shown read-only
- Authoritative zones with split-horizon views, conditional forwarding, RFC 2136 dynamic updates, zone transfers, and DNSSEC signing (NSEC, NSEC3, operator-driven key rollover)
- Seven transports: UDP, TCP, DoT, DoH (HTTP/2), DoH3, DoQ, and a DNSCrypt v2 server, with DoH3 upstreams and EDNS padding on encrypted links
- Automatic certificates (ACME, HTTP-01 and DNS-01) with renewal that loads without a restart, and automatic root key rollover (RFC 5011)
- Serve-stale (RFC 8767) and an optional persistent DNS cache
- Regex filter rules, CNAME-based blocking, opt-in SafeSearch, and child-safety categories
- Optional DHCP server (IPv4, IPv6, Router Advertisements, failover) and multicast DNS bridge, both off by default

**Completed in 0.7.0**

- [x] **Easy local DNS manager (0.7.0):** The admin-only **DNS → Local DNS** page creates, edits, and deletes bounded typed zones and `A`, `AAAA`, `CNAME`, `TXT`, `PTR`, `MX`, `SRV`, `CAA`, and `TLSA` records. It includes a quick hostname-to-IP path, recommends `home.arpa`, rejects `.local`, explains client DNS setup, and shows advanced zones read-only. Changes stay in the normal draft, validate before apply, restart DNS and clear caches when applied, and roll back if startup fails. Config and resolver tests cover the typed bounds and generated authoritative zone data.

**Still ahead**

- [ ] **Device and room manager:** Add a simple web UI to name devices, assign them to virtual rooms or areas, and manage their DNS policies using the existing group and profile support. Group a device's IPv4 and multiple IPv6 addresses under one identity, including changing IPv6 privacy addresses where possible. Explore optional FRITZ!Box integration to discover devices and address associations; support manual linking and corrections when matching is uncertain. Consider router-managed IPv4 reservations where supported, with explicit user control. Show when a device or query cannot be identified reliably.
- More encrypted DNS options: DNSCrypt upstreams, Anonymized DNSCrypt, and ECH support
- High availability and cluster configuration replication
- Phase 7: high availability, threat feeds and enterprise policy, extended conformance and soak tests, and an external security review
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

- [x] Rust workspace, Apache-2.0, SemVer (currently `0.7.0`)
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
- [x] Up to 8 ranked providers with a strategy (ranked fallback, fastest first, round-robin, race), per-provider timeouts, and a short rest for a failed provider (0.5.8)
- [x] Lists load in the background, are cached across reloads, can be cancelled, and filtering-only changes go live without restarting listeners (0.5.8)
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

### Phase 5: Advanced DNS

- [x] Base DoH over HTTP/2, DoT, and DoQ listeners (delivered in Phase 1)
- [x] RFC 8767 **serve-stale** with bounded stale age and one background refresh per name; unsigned data only (0.7.0). Existing prefetch is separate
- [x] Optional **persistent DNS cache**: separate SQLite file, off by default, entry, byte and TTL caps, corrupt-file recovery, no client data (0.7.0)
- [x] Certificate renewal without restart: renewed PEM pairs are verified and swapped in, with an expiry metric (0.7.0 line). Lumen still does not fetch certificates itself
- [x] Built-in certificate automation: ACME issuance and daily renewal with the HTTP-01 and DNS-01 challenges (wildcards with DNS-01, answered by Lumen's own resolver), tested against Pebble. Not built: TLS-ALPN-01, External Account Binding, DNS-provider APIs, and managing the web console's certificate. Not yet run against Let's Encrypt
- [x] Automatic trust-anchor rollover (RFC 5011): persistent state, 30-day hold-down, revocation, daily signed check. Opt-in with `trust_anchor_state`. Changes apply at the next restart; not yet run across a real root KSK rollover
- [x] Authoritative DNS zones and operator-managed records from zone files or inline text, separate from Lumen's built-in empty local zones. Unsigned; see the DNSSEC signing item
- [x] **Split-horizon views** by client network, **conditional forwarding**, and DNS-SD as ordinary records. mDNS bridging (discovery proxy and reflector, 0.7.0) is a separate opt-in module
- [x] Multicast DNS bridge (0.7.0): a discovery proxy (`.local` devices answered under your own domain, service browsing included) and a reflector between interfaces. Opt-in, Linux and macOS. Open: publishing Lumen's own names over mDNS, DNS Push, and per-service reflection filters
- [x] Dynamic DNS updates (RFC 2136) with TSIG authentication, per-key name and type scope, a SQLite journal, and bounded size
- [x] Zone transfers over TCP with TSIG-keyed policy and a one-message size bound. Dynamic zones answer IXFR with the differences from the last 32 updates (in memory; a full transfer after a restart or for older serials), NOTIFY is sent to `notify` secondaries at startup and after accepted updates
- [x] DNSSEC signing for plain operator zones (NSEC3 and double-signature key rollover added in 0.7.0): one combined key (Ed25519 or ECDSA P-256), NSEC, daily signature renewal, `lumen --zone-key` for key creation and the DS record. **Still open:** timer-driven rollover, separate KSK/ZSK, and signing for dynamic or split-horizon zones
- [x] Native DoH over HTTP/3 listener (`listen.doh3`), same `/dns-query` contract as HTTP/2 DoH. Client-side DoH3 to an upstream is available as `protocol = "h3"` for explicit upstreams and, since 0.7.0, in the automatic provider list for providers that advertise HTTP/3 (untested against the live providers); Lumen does not advertise HTTP/3 itself
- [x] DNSCrypt v2 **server** (UDP and TCP, both cipher suites, signed rotating certificates). Still open: DNSCrypt as an upstream transport, Anonymized DNSCrypt relays, and interop testing against `dnscrypt-proxy` releases
- [ ] HTTPS and SVCB record interoperability, including preserving ECH configuration from authoritative answer to browser ([Issue #36](https://github.com/StruktSource/lumen-dns/issues/36)). Started: an end-to-end test proves an HTTPS record with `alpn` and `ech` from an operator zone arrives byte-identical, live and repeated. Forwarded answers (UDP, TCP, and from the cache) are proven the same way. Recursive answers (validation off and on) and DNSSEC-validated forwarded answers are proven the same way (0.7.0). Native ECH is the part still blocked
- [ ] Optional native ECH for Lumen's own TLS connections and encrypted DNS listeners where the TLS stack supports it. **Checked 2026-11-12: blocked.** rustls 0.23 implements ECH for clients only, so Lumen's listeners cannot accept ECH, and Hickory 0.26.3 does not pass an ECH config to its upstream connections. Revisit when rustls adds server-side ECH or Hickory exposes client ECH ([Issue #36](https://github.com/StruktSource/lumen-dns/issues/36))
- [x] Regular-expression blocking with explicit syntax, compile limits, linear-time matching, and explainable matches (0.7.0)
- [x] CNAME-based tracker blocking that inspects upstream answer chains without bypassing DNSSEC or response bounds (0.7.0)
- [x] SafeSearch with explicit opt-in, per-profile scope, documented providers (Google, Bing, YouTube), and no hidden logging (0.7.0). Wider child-safety categories shipped as per-list categories (0.7.0)
- [x] Optional DHCP server module with bounded leases, reservations, DNS integration, and no default network authority (0.7.0): IPv4 and stateful IPv6, SQLite leases, names published to DNS, console module. Relay agents, prefix delegation, network boot options, and Lumen-to-Lumen failover are included. Temporary addresses, DHCPv6 Reconfigure and IPv4 FORCERENEW are included, and so are IPv6 Router Advertisements with DNS options (RFC 8106). Open: ISC-compatible failover, and real-hardware tests of the Windows and BSD socket paths

### Phase 6: Customization

Each item has to keep Lumen's defaults intact: private, bounded, and explicit opt-in.

**Customizable UI via CSS** (planned)

- [ ] A **theme file in plain CSS**. Users open it, edit the colors, and apply it in the console, for example for a dark or high-contrast look and their own accent colors
- [ ] A design that fits the console's strict Content-Security-Policy (no inline styles or scripts, same-origin assets only), such as a theme file served by Lumen itself. A theme changes appearance only, and must not be able to read or send data

**Localization** (0.5.7)

- [x] The web console in English (default), German, Italian, Spanish, and Dutch
- [x] A translation framework: message catalogs keyed by the English text, a per-browser choice, a console default for administrators, a browser-language fallback, and locale-aware numbers
- [x] A language step in the setup wizard, and language settings under Users → My account and System → Console
- [x] A documented way to add or improve a translation, with tests that keep the catalogs complete and current ([Languages and translations](../guides/translations.md))
- [ ] Translate the remaining long help texts on the DNS settings and Filtering pages
- [ ] More languages
- [ ] Localize the documentation where practical. Technical terms such as DoH, DoT, and DNSSEC stay recognizable

### Phase 7: Scale, assurance, and enterprise

Moved out of Phase 5 on 2026-11-12 so Phase 5 stays focused on DNS features.

- [ ] High availability, multi-service use, cluster configuration replication, and a cache strategy
- [ ] Optional DNS threat feeds and enterprise policy features that leave privacy defaults unchanged
- [ ] Extended DNS and DNSSEC conformance and long-running soak tests
- [ ] **External security review before stable release**

## What is planned next

Open items, from most to least urgent. This is a recommended order, not a dated commitment. Validation, testing, and release-hardening work lives in [Side projects](#side-projects) so it does not crowd the feature list.

### Open GitHub issues

- [x] [Issue #35: forward mode returns SERVFAIL for names under `l.google.com` when local DNSSEC validation is on](https://github.com/StruktSource/lumen-dns/issues/35). Fixed in 0.7.0 with bounded insecure-ancestor recovery for forward mode: signed-zone failures and bogus ancestors still return `SERVFAIL`, provider answers stay final, both DS reply shapes are covered by local tests. Public-network behavior is not claimed
- [ ] [Issue #36: native ECH support and HTTPS/SVCB interoperability](https://github.com/StruktSource/lumen-dns/issues/36). First prove HTTPS/SVCB and ECH configuration survive filtering, caching, forwarding, recursion, and DNSSEC; then evaluate native ECH for Lumen's own encrypted transports

### High priority: do next

1. **Logic-led cleanup and optimization (v0.6.0).** Completed with local checks; selected changes and verification are in [the audit](optimization-audit.md) and [verification](verification.md). Implemented and checked: response ownership transfer, discarded filter-match allocation removal, and portable ThinLTO. Large I/O, allocator, arena, tree and parser rewrites are rejected or deferred with reasons.
2. **Silent first encrypted transport failover (v0.6.0).** Implement bounded per-transport shares inside the provider deadline, preserve final DNS/DNSSEC results and encrypted-only policy. Local checks pass; cross-platform hosted CI remains pending. See [provider behavior](../guides/upstream-providers.md#how-failover-works).
3. **Cold recursive DNSSEC latency diagnosis and recovery (v0.6.0 bounded work complete).** Each full walk now has a Lumen attempt budget; only timeouts retry, and attempts plus the one DNSSEC recovery budget must fit the outer deadline. The extra SOA/NS ancestor scan shares one budget instead of multiplying waits. Opt-in fixed-cardinality attempt metrics expose timing, timeout, retry, and failure counts without names or addresses. A local fixture proves a silent first walk times out and the next walk can finish. Usable and authenticated negative answers and DNSSEC failures remain final. **Still open:** Hickory 0.26.3 does not expose privacy-safe per-authority timing through its stable recursor API, so exact authority-hop attribution and a statistically significant public-network latency gain are not claimed.
4. **Local-only DNS names (v0.6.0 complete).** Default-on, operator-disableable local answering covers the current IANA RFC 6303/RFC 7793 reverse registry, `home.arpa`, `resolver.arpa`, `service.arpa`, and `.local` leak prevention. Empty zones return authoritative SOA/NS/NXDOMAIN/NODATA, the DNSSEC `home.arpa` DS exception still gets the public proof, and DDR returns local NODATA. Tests prove public reverse DNS and `ipv4only.arpa` are not blanket-blocked. Lumen does not bridge mDNS or yet provide per-zone conditional forwarding. See [resolver behavior](../guides/resolver-modes.md#cold-recursion-and-local-names).

### Medium priority: soon

5. **Optional external login: done in 0.6.0** ([guide](../guides/external-login.md)). Authorization code with PKCE for any OpenID Connect provider, off by default, built-in login kept. Includes linking an existing account, optional group-to-role sync, optional single logout, and a setup-wizard step. **Experimental.** Not yet checked against live Authentik, Authelia, Pocket ID, or Octelium installations; back-channel logout and per-group roles beyond one admin group are not built.
6. **CSS themes** for the console.
7. **Finish the translations:** the remaining long help texts, and more languages.

### Lower priority: later

8. **Faster, lighter list downloads (partly done in 0.6.0).** Done: conditional requests (`ETag` / `Last-Modified`), compressed transfer, and a bounded disk cache in managed mode so a restart does not fetch fresh lists again. Still open: downloading several lists at once with a bound, and delta updates for very large lists.
9. **Weighted random load balancing** across providers (spreading by recent speed rather than evenly), as some filter apps offer. Round-robin and fastest-first cover most of it today.
10. **Serve-stale and persistent cache (done in 0.7.0).** Bounded RFC 8767 stale answers and a separate opt-in persistent DNS cache. Cache behavior under real restarts and long soaks is still unmeasured.
11. **Authoritative and local DNS.** Add authoritative zones, operator-managed records, a split-horizon module, conditional forwarding, RFC 2136 updates, AXFR/IXFR, and DNSSEC zone signing.
12. **Encrypted DNS and ECH.** Keep current DoH over HTTP/2; add native DoH over HTTP/3, DNSCrypt, HTTPS/SVCB and ECH-config delivery to browsers, and optional native ECH in Lumen's own TLS paths.
13. **Filtering and family policy (mostly done in 0.7.0).** Regex rules, CNAME-based blocking, and opt-in SafeSearch profiles shipped. Wider child-safety categories shipped (0.7.0).
14. **Optional DHCP server module (done in 0.7.0).** IPv4 and IPv6 with reservations, SQLite leases and DNS names. Open: ISC-compatible failover (a separate, large protocol; ISC DHCP is end-of-life). Integrate leases and reservations with device and local-DNS policy without making Lumen authoritative for the network by default.
15. **Trust-anchor rollover automation and certificate lifecycle tooling.**

### Large efforts, before or after 1.0

16. **Independent security review.** Required before a stable release.
17. **High availability and cluster configuration replication.**
18. **Optional DNS threat feeds and enterprise policy features.**

### Not now

19. **Plugins, add-ons, and a community store.** Parked as an idea. See [Ideas, not now](#ideas-not-now).

## Side projects

Important work that does not add a feature. It can be done in any order and by anyone, and does not block the feature list above, except that the first two are needed before a stable release.

- [ ] **Real-hardware validation:** Proxmox, Unraid, Raspberry Pi, Podman ARM64, and dual-stack Kubernetes. Record the results in the [compatibility matrix](../deployment/compatibility.md)
- [ ] **Backup, restore, upgrade, and removal tests**, now that persistent state exists
- [ ] **Conformance and soak tests:** extended DNS and DNSSEC conformance suites and long-running soak tests
- [ ] **Release hardening:** keyless image signing and reproducible-build comparison (SBOM and provenance are already configured)
- [ ] **Report the DNSSEC fix upstream** to Hickory, then drop the vendored copy (see [Upstream follow-up](#upstream-follow-up))

## Recursion speed (Issue #9)

Implemented.

- [x] Reproducible A/B benchmark with trial-level statistics (`scripts/recursion_bench.py`)
- [x] Shared in-flight recursion, startup priming, opt-in expiry refresh and hedging, and latency metrics

No significant public-network cold-query gain is claimed: the first 12-trial run was not significant, while a deterministic local test shows that priming reduces authority round trips and latency. Expiry refresh has unit tests only.

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

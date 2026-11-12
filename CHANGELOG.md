# Changelog

All notable user-facing changes are listed here. Lumen is still pre-release.

## [Unreleased]

## [0.7.0] - 2026-11-12

### Added

- **DoH3 upstreams.** An explicit upstream can use `protocol = "h3"` (DNS over HTTP/3, QUIC with ALPN `h3`, optional `doh_path`). Certificates and names are verified like the other encrypted transports. The automatic provider list does not use it yet.
- **DNSSEC signing for your own zones, opt-in.** `[zones.dnssec]` signs a plain zone with one Ed25519 or ECDSA P-256 key and NSEC, renews signatures daily, and serves them to clients that ask for DNSSEC data. `lumen --zone-key FILE --zone NAME` creates the key (mode `0600`) and prints the `DNSKEY` and `DS` records. Not built: key rollover, NSEC3, signing for dynamic or split-horizon zones. See [Your own DNS zones](docs/guides/authoritative-dns.md#dnssec-signing).
- **Automatic trust-anchor rollover (RFC 5011), opt-in.** `resolver.trust_anchor_state` keeps trust-anchor state in a `0600` file. Lumen checks the signed root DNSKEY set daily, trusts a new key after 30 days, drops revoked keys, and exports `lumen_dns_trust_anchor_*` metrics. Changes load at the next restart. See [DNSSEC and trust](docs/reference/dnssec-and-trust.md#automatic-rollover-rfc-5011).
- **DNS over HTTP/3 (DoH3).** `listen.doh3` serves `/dns-query` over QUIC with ALPN `h3`, with the same methods, media type, status codes, limits, certificate, and `allow_clients` rules as DoH over HTTP/2. Metrics gain an `http3` transport label (the former `other` label moves to a new index but keeps its name).
- **DNSCrypt v2 server (opt-in).** `[dnscrypt]` serves signed, automatically rotating certificates and encrypted queries over UDP and TCP, with `X25519-XChaCha20Poly1305` and `X25519-XSalsa20Poly1305`. The long-term provider key lives in a `0600` file, UDP replies are never larger than the query, and Lumen logs a `sdns://` stamp at startup. Not included: DNSCrypt upstreams and Anonymized DNSCrypt.
- **Your own DNS zones (opt-in).** `[[zones]]` serves authoritative records from zone files or inline text, with split-horizon `views` by client network, DNS-SD as ordinary records, and `[[forwarders]]` for conditional forwarding of a domain to specific resolvers. These names bypass the response caches. See [Your own DNS zones](docs/guides/authoritative-dns.md).
- **Dynamic updates (RFC 2136) and zone transfers.** A zone with a `journal` accepts TSIG-signed updates scoped per key to names and record types, saved to a SQLite journal. `transfer_keys` allow AXFR and IXFR over TCP, TSIG-signed, bounded to one DNS message. IXFR is answered as a full transfer. `notify` lists secondaries that get a NOTIFY (RFC 1996) at startup and after each accepted update. The vendored `hickory-server` now uses `rusqlite` 0.41 and treats IXFR like AXFR under the same policy (see `vendor/README.md`).
- **Certificate renewal without restart.** Renewed PEM files for DoT, DoH, DoH3, and DoQ are checked every 30 seconds, verified, and swapped in; bad files keep the old pair serving. New metrics export expiry and reload counts. The web console's HTTPS certificate still needs a restart.
- **Serve-stale (RFC 8767), opt-in.** `[resolver.serve_stale]` answers from an expired entry for up to `max_age_secs` while one background refresh runs. Replies carry a short TTL, and expired DNSSEC-authenticated data is never served. Stale data is also used when live resolution times out.
- **Persistent DNS cache, opt-in.** `[resolver.persistent_cache]` saves bounded responses in a separate mode `0600` SQLite file so restarts start warm. It stores names and answers, never clients. A corrupt file is moved aside and rebuilt.
- **Regular-expression filter rules.** `regex_allow` and `regex_block`, global or per profile, whole-name, linear-time, and size-limited. `filter-explain` shows the matching pattern.
- **CNAME-based blocking.** Filter rules now also check CNAME targets in upstream answers and replace the answer with the block action.
- **SafeSearch, per profile, opt-in.** `safe_search = true` rewrites Google, Bing, and YouTube names to their restricted endpoints.

### Changed

- HTTPS and SVCB target names are lowercased like CNAME targets, keeping the other record data intact.
- Runtime pins (Helm, Compose, Podman guide) point at 0.7.0.

### Not included

Zone key rollover and NSEC3, built-in ACME issuance, native ECH, DHCP, DNSCrypt or DoH3 upstreams, and Anonymized DNSCrypt are **not** available in this release.

## [0.6.0] - 2026-11-09

### Added

- **Live view on Activity.** A *Live* switch adds new lookups to the list every 2 seconds, with a short highlight on new rows. The choice is remembered in the browser, so it stays on until you switch it off.
- **Modules and the Traffic map.** A new *Modules* page lists big, optional features. Each is off until an administrator turns it on, and the choice is saved on the server. The first module, *Traffic map*, draws your DNS traffic as an interactive tree: the Lumen server, then domain endings, then the domains under them. You can drag, zoom, search, filter and open any domain for details. It needs query history. The map costs nothing while you are not using it: its code is fetched only when you open the page, it refreshes only while the page is open and visible, and it frees what it holds as soon as you leave or turn the module off.
- **Hide the sidebar.** A button in the sidebar header (or the `[` key) hides it for more room, and a tab on the left edge brings it back. The choice is remembered in the browser.
- **External login (optional, experimental).** Administrators can add a *Sign in with …* button for Authentik, Authelia, Pocket ID, Octelium, or any OpenID Connect provider under `[web.oidc]`. It is off by default, the built-in login always stays, each person gets their own account tied to the provider's stable identity (never to a username), and the provider handles any second factor. People can **link their existing account** under *My account*, an optional **role sync** keeps roles in step with an admin group on every sign-in, an optional **single logout** also ends the provider session, and the first-run setup has a **Single sign-on** step. Administrators can also turn it on, check the provider, and save it under **Users → Sign-in** without editing a file. The callback address is built automatically from the address people use to open the console (name, IP address, `http` or `https`) and shown read-only with a Copy button, so there is nothing to type; an optional override covers reverse proxies. See [External login](docs/guides/external-login.md).

### Resolver and build updates

- **Benchmarks.** New `scripts/load_bench.py` and a measured idle and load snapshot (with and without the web console) in [Performance](docs/project/performance.md). Idle memory with the console is about 10.9 MiB; cached and blocked answers take about 0.03 ms at the median on loopback.

- The state database migrates to **schema 7** on first start (a table tying console accounts to single sign-on identities). The migration is automatic and one-way, so keep a backup if you may go back to 0.5.x.
- Updated bundled SQLite through `rusqlite 0.41.1` and `libsqlite3-sys 0.39.1` to resolve RUSTSEC-2026-0459. Minimum source-build Rust is now 1.89; release binary requirements are unchanged.
- Automatic encrypted transports now share one provider deadline with bounded per-transport time slices. A silent or failed first transport can reach the next encrypted transport. DNS answers and local DNSSEC failures remain final; upstream SERVFAIL keeps its existing next-provider policy.
- Removed a response-buffer clone and allocations for discarded filter block matches. Portable release builds enable cross-crate ThinLTO, retaining baseline CPU support and unwinding.
- Added the v0.6.0 optimization audit with explicit rejected/deferred ideas. Recursive walks now have bounded timeout-only retries, DNSSEC unsigned-zone recovery has one total budget, and optional fixed-cardinality diagnostics expose attempt timing without names or addresses. Registered local reverse, `home.arpa`, `resolver.arpa`, `service.arpa`, and `.local` requests no longer leak to public DNS. Public cold-latency gains and exact per-authority tracing are not claimed.

### Changed

- **One Users page.** *Users & access* and *My account* are now a single **Users** menu point with the tabs *My account* (everyone), *People*, *Sign-in* and *Audit log* (administrators). Where the console is served, its default language, the Overview auto reload and monitoring moved to **System → Console**. Old links still work.
- **Lighter list downloads.** Lists are requested compressed and revalidated with `ETag` / `Last-Modified`, so an unchanged list costs a `304`. In managed mode downloaded lists are also kept in a bounded `filter-cache` folder beside the state database, so a restart does not download fresh lists again.
- The Overview now reloads every 10 seconds (it was 5). A new *Auto reload* slider under *System → Console* lets an administrator choose 1, 2, 5, 10, 30 or 60 seconds, or off. The choice is saved on the server and applies to everyone.

### Fixed

- Choosing *Use another resolver* (Quad9) in the setup wizard now sticks. The stock config enabled recursive-only zone warm-up, which made the forward config invalid, so Lumen silently stayed in recursive mode.

## [0.5.9] - 2026-11-09

### Fixed

- Forwarding now tries the next provider when an upstream returns SERVFAIL. The failing provider rests for 10 seconds, which avoids repeated failures and delay without overriding usable DNS answers or local DNSSEC failures.

### Documentation

- Added a Docker and Compose update guide with a consistent state backup, UDP/TCP smoke tests, rollback, and database restore steps.

## [0.5.8] - 2026-11-08

### Added

- **Several forwarding providers.** Choose up to 8 bundled providers (plus up to 8 custom upstreams), rank them, and pick how they are used: *ranked fallback*, *fastest first*, *round-robin*, or *race* (`resolver.strategy`). Only a connection failure or timeout moves on to another provider; a DNS answer or DNSSEC failure is final. A provider that just failed is left alone for 10 seconds so queries do not keep waiting for it.
- **Cancel from the progress panel.** Administrators can stop block-list downloads. Nothing changes and what was already downloaded is kept.

### Changed

- **Lists apply right away.** Installing, removing, adding or editing a list now asks you to confirm and then loads in the background, with no draft and no *Apply* bar. A list change that touches only filtering goes live **without restarting the listeners**, closing connections, or clearing caches, and the filter counters carry on.
- **Lists are no longer downloaded again after unrelated changes.** Lumen keeps downloaded lists in memory, so changing the resolver, an upstream, or another list never re-downloads the lists you already have. Refresh and a list's own interval still do. A restart downloads them again.
- Provider addresses are no longer limited to 8 in total: the limits are now 8 providers, 8 custom upstreams, and 128 addresses together.

## [0.5.7] - 2026-11-08

### Added

- **Opt-in query history.** Off by default. Administrators can choose *recent only* (the last 1,000 lookups, in memory) or *saved* (kept in the state database for 1 to 90 days, 7 by default, at most 500,000 lookups), either anonymous or with the device and address. The Activity page has search, filters, paging, and a delete button, and `lumenctl history status|set|clear` does the same from the command line. Saving never slows DNS answers down.
- **Console languages.** The web console is available in English, German, Italian, Spanish, and Dutch. The setup wizard starts with a language picker, each person can choose their own under *My account*, and administrators set the default under *Users & access*. See `docs/guides/translations.md` to add or improve one.
- New documentation guides: quick start, concepts, serving your network, encrypted DNS, resolver modes, query history, and translations, plus references for the `lumen` and `lumenctl` commands and for DNSSEC and trust anchors.

### Changed

- The state database schema is now 6 (adds the query history table). It upgrades itself on first start. Back it up before upgrading, because an older Lumen cannot open it afterwards.
- The older on/off *Recent queries* switch now maps to the *recent only* mode and keeps working.
- Documentation was rewritten for newcomers and reorganized into `getting-started`, `guides`, `deployment`, `reference`, `design`, and `project` folders, with a new index at `docs/README.md`. The roadmap, progress checklist, and product plan are now one page.
- Shipped configuration files have clearer comments. No setting changed.

## [0.5.6] - 2026-11-08

### Changed

- Releases now publish step by step: each tested native package and each architecture's container image goes online as soon as it is ready, and the final `latest` image index and `SHA256SUMS` follow once everything passes.
- Container images are built and tested on native amd64 and arm64 runners instead of emulation.

### Fixed

- `SHA256SUMS` no longer contains Windows line endings, so `sha256sum --check` works for every entry.

## [0.5.5] - 2026-11-08

### Added

- Built-in web console with first-run setup, accounts, roles, optional TOTP, filtering, devices, DNS settings, audit events, and recent activity.
- Guided list setup and quick-install filter lists.
- Version details on setup and sign-in screens.

### Changed

- Large filter lists now load with bounded, more efficient work.
- Release archives now include deployment files, checksums, an internal file manifest, and both versioned binaries.
- Container and release builds now use the same pinned Rust toolchain.
- Core dependencies and CI actions were refreshed.

### Fixed

- DNSSEC recursion for parent and child zones that share name servers.
- Console null text, query totals, KPI sparkline overlap, and provider-limit handling.

## [0.1.3] - 2026-10-31

- Added a supported v1 configuration fixture and initial six-platform release packages.
- Added stricter DNSSEC policy handling and release checks.

[0.5.9]: https://github.com/StruktSource/lumen-dns/compare/v0.5.8...v0.5.9
[0.5.8]: https://github.com/StruktSource/lumen-dns/compare/v0.5.7...v0.5.8
[0.5.7]: https://github.com/StruktSource/lumen-dns/compare/v0.5.6...v0.5.7
[0.5.6]: https://github.com/StruktSource/lumen-dns/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/StruktSource/lumen-dns/compare/v0.1.3...v0.5.5
[0.1.3]: https://github.com/StruktSource/lumen-dns/releases/tag/v0.1.3

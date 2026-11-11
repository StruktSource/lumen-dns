# Changelog

All notable user-facing changes are listed here. Lumen is still pre-release.

## [0.6.0] - 2026-11-09

### Added

- **Live view on Activity.** A *Live* switch adds new lookups to the list every 2 seconds, with a short highlight on new rows. The choice is remembered in the browser, so it stays on until you switch it off.
- **Modules and the Traffic map.** A new *Modules* page lists big, optional features. Each is off until an administrator turns it on, and the choice is saved on the server. The first module, *Traffic map*, draws your DNS traffic as an interactive tree: the Lumen server, then domain endings, then the domains under them. You can drag, zoom, search, filter and open any domain for details. It needs query history.
- **Hide the sidebar.** A button in the sidebar header (or the `[` key) hides it for more room, and a tab on the left edge brings it back. The choice is remembered in the browser.

### Resolver and build updates

- Updated bundled SQLite through `rusqlite 0.41.1` and `libsqlite3-sys 0.39.1` to resolve RUSTSEC-2026-0459. Minimum source-build Rust is now 1.89; database schema and release binary requirements are unchanged.
- Automatic encrypted transports now share one provider deadline with bounded per-transport time slices. A silent or failed first transport can reach the next encrypted transport. DNS answers and local DNSSEC failures remain final; upstream SERVFAIL keeps its existing next-provider policy.
- Removed a response-buffer clone and allocations for discarded filter block matches. Portable release builds enable cross-crate ThinLTO, retaining baseline CPU support and unwinding.
- Added the v0.6.0 optimization audit with explicit rejected/deferred ideas. Recursive walks now have bounded timeout-only retries, DNSSEC unsigned-zone recovery has one total budget, and optional fixed-cardinality diagnostics expose attempt timing without names or addresses. Registered local reverse, `home.arpa`, `resolver.arpa`, `service.arpa`, and `.local` requests no longer leak to public DNS. Public cold-latency gains and exact per-authority tracing are not claimed.

### Changed

- The Overview now reloads every 10 seconds (it was 5). A new *Auto reload* slider under *Users & access → Console* lets an administrator choose 1, 2, 5, 10, 30 or 60 seconds, or off. The choice is saved on the server and applies to everyone.

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

# Changelog

All notable user-facing changes are listed here. Lumen is still pre-release.

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

[0.5.6]: https://github.com/StruktSource/lumen-dns/compare/v0.5.5...v0.5.6
[0.5.5]: https://github.com/StruktSource/lumen-dns/compare/v0.1.3...v0.5.5
[0.1.3]: https://github.com/StruktSource/lumen-dns/releases/tag/v0.1.3

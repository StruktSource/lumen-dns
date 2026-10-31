# Lumen foundation

## Identity and scope

Lumen is private, self-hosted DNS software by Strukt. Rust, Apache-2.0, workspace
version `0.1.3`. Phases 1 and 2 implement the resolver core and filtering. Phase 3
local persistence, control, authenticated loopback management, and observability
are implemented. Remote management remains out of scope. See [progress](progress.md).

## Workspace

```text
apps/lumen/          daemon startup and signal handling
apps/lumenctl/       local cross-platform administrative CLI
crates/lumen-proto/  bounded DNS wire admission and full message decoding
crates/lumen-config/ schema 1, validation, safe defaults, bounded file reads
crates/lumen-resolver/ recursive/forward modes, DNSSEC, cache and trust setup
crates/lumen-filter/ rules, policies, imports, snapshots, schedules and responses
crates/lumen-core/   client transports, limits, lifecycle and aggregate metrics
crates/lumen-store/  SQLite migrations, config/device state and local controls
crates/lumen-api/    opt-in loopback /v1 management, roles, audit, webhooks
config/             safe release default and opt-in feature examples
web/                blank UI shell embedded by lumen-web at compile time
fuzz/               DNS/config/filter fuzz targets; separate Cargo workspace
scripts/            local checks, builds, packaging
.agent/             concise project continuity notes
```

Extended observability and authenticated remote control are future slices.
Protocol parsing never imports UI,
API, storage, or resolver code. `lumen-core` wires components; resolver business
rules stay in `lumen-resolver`. Hickory owns DNS algorithms and cryptography;
Lumen does not implement custom DNSSEC crypto.

## Runtime and compatibility

Minimum Rust: 1.88, required by Hickory 0.26.3. `rust-toolchain.toml` selects the
installed stable channel. CI and Docker pin 1.95.0; CI also checks the 1.88 MSRV.
No unsafe code is allowed in Lumen crates. Platform CI targets Linux, macOS, and
Windows; the resolver uses portable Tokio/rustls/ring transports. Runtime claims
must be backed by the [verification record](verification.md).

## Contracts

- Startup [configuration schema](configuration.md) is versioned; unknown fields
  and future versions fail closed. SQLite state migrations are explicit and
  config candidates are validated before reload.
- DNS errors use protocol response codes. Startup errors are local and do not
  dump configuration, keys, query packets, or query names.
- [Metrics](resolver.md#metrics-and-health) have stable `lumen_dns_` names with
  no client/domain labels. Liveness has a separate loopback endpoint.
- Management API starts at `/v1`; authentication, scoped authorization, rate
  limits, and durable audit apply before dispatch. DNS-over-HTTPS is a DNS
  transport, not a management API.
- SQLite stores config revisions and devices when `--state` is enabled. Hot DNS
  caches remain bounded in memory. Query history and external telemetry are off.
- Blank UI hosting is static and unauthenticated. It contains no management data;
  `/v1` remains a separate authenticated listener.
- Operators opt into each encrypted listener and each upstream; recursive mode
  has no implicit upstream fallback.

## First-release boundaries

The intended first release includes recursive resolution, filtering, DNSSEC,
UDP/TCP/DoH/DoT/DoQ, setup-selected built-in modules, CLI/config, and a blank UI.
Phase 1 alone does not satisfy that full release scope. Optional plugins come
later. API access stays disabled until its security work is complete.

## Version and release policy

Use SemVer. `0.y.z` is preview and may change config/storage/public contracts.
Stable `1.0.0` requires proven resolver/filter behavior, migration and upgrade
paths, deployment validation, and security review. Patch releases fix bugs;
minor releases add compatible features; breaking stable contracts require a
major release. MSRV increases need explicit minor/major release notes.

One version lives in root `Cargo.toml`. Platform release archives have unique
names, include both binaries and startup documentation, and carry SHA-256
checksums. SBOM, signed images, reproducible-release verification, and embedded
Git revision/target metadata remain release-hardening work.

Contributions use Apache-2.0. New source files carry
`SPDX-License-Identifier: Apache-2.0`.

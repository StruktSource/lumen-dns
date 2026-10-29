# Lumen Foundation

## Identity

- Product name: **Lumen**.
- Organization: **Strukt**.
- Purpose: private, self-hosted DNS filtering and validating resolver.
- Implementation language: Rust, stable channel.

## Rust workspace layout

Use one Cargo workspace. Keep protocol, policy, and deployment code separate.
This makes core resolver tests fast and lets CLI, API, and UI evolve without
mixing trusted DNS-path code with control-plane code.

```text
.
├── Cargo.toml                 # Workspace only; shared metadata and lint rules
├── rust-toolchain.toml        # Pinned stable Rust toolchain
├── crates/
│   ├── lumen-proto/           # DNS wire format, packet limits, protocol types
│   ├── lumen-resolver/        # Recursive resolver, forwarding, cache, DNSSEC
│   ├── lumen-filter/          # Rules, blocklists, profiles, decision engine
│   ├── lumen-config/          # Config schema, validation, safe reloads
│   ├── lumen-api/             # Authenticated HTTP API and webhook support
│   ├── lumen-observability/   # Logs, health checks, Prometheus metrics
│   └── lumen-core/            # Service lifecycle and component wiring
├── apps/
│   ├── lumen/                 # Main daemon binary
│   └── lumenctl/              # Administrative CLI binary
├── web/                       # Optional web UI; no DNS-path dependency
├── deploy/                    # Docker, Compose, LXC, systemd, Unraid examples
├── docs/                      # User and operator documentation
├── agent-docs/                # Architecture and implementation decisions
├── tests/                     # Cross-crate integration and conformance tests
├── fuzz/                      # Cargo-fuzz targets for untrusted input
└── scripts/                   # Repeatable release and verification helpers
```

Rules:

- DNS packet handling stays in `lumen-proto`; no UI, API, or storage imports.
- `lumen-resolver` and `lumen-filter` have no web-UI dependency.
- `lumen-core` composes components; business rules stay in owned crates.
- Binaries remain thin. They parse startup options and call library crates.
- New crates need a clear owner, tests, documentation, and dependency reason.

## First-release boundaries

- Ship recursive resolution, filtering, DNSSEC validation, UDP, TCP, DoH, DoT, and DoQ.
- Setup chooses enabled built-in modules. Future plugins use separate, permissioned extension points.
- Ship CLI, config file, and a blank UI shell.
- Do not expose API access in first release. Reserve API crate, route namespace, versioning, auth, and audit model now.
- Resolve recursively or forward upstream only when operator selects that module at setup.

## Data and privacy defaults

- SQLite stores configuration, list metadata, devices, groups, profiles, and future opt-in history.
- Query logs default off.
- Dashboards use aggregate counters only by default.
- Optional anonymous and full history modes default to seven-day retention.
- Operators choose retention, devices/groups, and logged fields. Privacy choices are not global-only switches.

## Version policy

Use Semantic Versioning: `MAJOR.MINOR.PATCH`.

- `0.y.z`: public preview. API, config, storage, and cluster behavior may change.
- `1.0.0`: only after recursive resolution, filtering, migration, and upgrade paths are proven stable.
- `PATCH`: bug fixes and security fixes. No intended public API or config break.
- `MINOR`: backward-compatible features. Deprecated items get migration notes and removal target.
- `MAJOR`: breaking public API, config, data, behavior, or cluster changes.
- One workspace version lives in root `Cargo.toml`. Release binaries, containers, API, and docs use same version.
- Release builds include version, Git revision, build target, and Rust toolchain in `lumen --version`.
- Pin toolchain in `rust-toolchain.toml`. Update minimum supported Rust version only in a minor or major release, never silently in a patch.
- API starts at `/v1`. Breaking API changes require `/v2` or a major release.
- Config schema has explicit version field and migrations. Service rejects unknown future schema versions.

## License

Use **Apache-2.0**.

Why:

- Clear patent rights and patent-termination terms protect contributors and users.
- Permissive terms suit open-source self-hosting, commercial use, and distribution.
- One license removes ambiguity for contributors and downstream packagers.

Ship `LICENSE` at repository root. New source files state
`SPDX-License-Identifier: Apache-2.0`. Accept contributions under Apache-2.0.

## Initial repository files

1. `Cargo.toml` workspace manifest.
2. `rust-toolchain.toml` pinned to current stable Rust.
3. `LICENSE` with Apache-2.0 text.
4. `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`.
5. `docs/architecture.md` and `docs/threat-model.md`.
6. CI for `fmt`, `clippy`, tests, dependency audit, fuzz smoke test, and multi-architecture build.

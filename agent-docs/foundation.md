# Strukt Lumen Foundation

## Identity

- Product name: **Strukt Lumen**.
- Short name: **Lumen**.
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

Use **Apache-2.0 OR MIT** dual license.

Why:

- MIT stays simple for users and small self-hosted projects.
- Apache-2.0 adds clear patent rights and patent termination terms.
- Dual licensing maximizes adoption while protecting contributors from unclear patent terms.

Ship `LICENSE-MIT` and `LICENSE-APACHE` at repository root. New source files state
`SPDX-License-Identifier: MIT OR Apache-2.0`. Accept contributions under same dual license.

## Initial repository files

1. `Cargo.toml` workspace manifest.
2. `rust-toolchain.toml` pinned to current stable Rust.
3. `LICENSE-MIT` and `LICENSE-APACHE`.
4. `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md`.
5. `docs/architecture.md` and `docs/threat-model.md`.
6. CI for `fmt`, `clippy`, tests, dependency audit, fuzz smoke test, and multi-architecture build.

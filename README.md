# ✦ Lumen

> Private DNS, in your control.

**Lumen** is open-source, self-hosted DNS software by [Strukt](https://github.com/StruktSource).

## Status

**The DNS resolver works today.** Lumen can resolve queries recursively, validate
DNSSEC, cache answers, and serve plaintext or encrypted DNS. It can also forward
queries to a configured upstream.
Recursive mode can also use an explicitly configured timeout-only fallback. It
is disabled by default and never activates for DNSSEC failure or DNS answers.

Lumen also filters DNS with global and per-client rules, imported lists, category
profiles, and UTC schedules. Lumen is pre-release; wider testing and security
review remain before production readiness.

| Available | Next |
| --- | --- |
| UDP, TCP, DoH, DoT, DoQ on IPv4/IPv6 | Authenticated management API |
| Filtering, device policies, bounded list imports and atomic refresh/rollback | Functional web UI |
| Recursive resolution, delegation checks, DNSSEC | Config reload and migrations |
| Positive, negative, delegation, and validation caches | Full administrative CLI and web UI |
| Explicit plaintext or encrypted upstream forwarding | Deployment guides, signed images, external review |
| Startup config, client ACLs, resource limits, aggregate metrics | Extended interoperability and performance validation |

Defaults: loopback clients only, recursive resolution, DNSSEC on, no query
history, no telemetry, and no management API. Encrypted listeners require
operator-supplied certificates and keys. Filtering is opt-in through config;
no third-party blocklists or external DNS providers are enabled by default.

## Run

Requirements: Rust 1.88 or newer; stable toolchain recommended. CI and container
builds use Rust 1.95.0. No external DNS server is needed for automated tests.

```sh
./scripts/dev.sh check
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/lumen.toml
```

In another terminal:

```sh
dig @127.0.0.1 -p 5353 example.com A
dig @::1 -p 5353 example.com AAAA +tcp
```

`lumen --bind 127.0.0.1:5353` starts UDP/TCP with the same safe resolver defaults.
`lumen --help` lists startup options. Aggregate metrics are disabled until the
loopback `metrics` line is uncommented. `config/forward.example.toml` is an
explicit DoT forwarding example; running it sends DNS to its configured upstream.

See [filtering guide](docs/filtering.md), [resolver guide](docs/resolver.md), [configuration reference](docs/configuration.md),
[upstream provider presets](docs/upstream-providers.md),
[security boundaries](docs/threat-model.md), [verification](docs/verification.md),
and [performance snapshots](docs/performance.md).
Track remaining work in [TODO](docs/TODO.md) and [implementation checklist](docs/progress.md).
The [product plan](docs/DNS_SERVICE_PLAN.md) describes the complete intended product.

## Build

Linux/macOS: `./scripts/dev.sh <check|build|image|release>`.
Windows PowerShell: `.\scripts\dev.ps1 <check|build|image|release>`.
`release` checks code, builds optimized binaries, and creates local image
`lumen:local`. It does not publish a release.

Docker/OrbStack requires an accessible Docker-compatible engine. The image runs
as UID 65532 with a loopback-only config. For host or network clients, mount a
config that explicitly sets listener addresses and allowed client CIDRs. Native
network-wide deployment examples remain Phase 4 work.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities through
[SECURITY.md](SECURITY.md). Licensed under [Apache-2.0](LICENSE).

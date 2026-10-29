# ✦ Lumen

> Private DNS, in your control.

**Lumen** is open-source DNS software by [Strukt](https://github.com/StruktSource).
It will unite recursive DNS, filtering, caching, and encrypted DNS in one small service.

## 🚧 Status

Foundation stage. **Not a DNS server yet.** Do not use Lumen in production.

| Available now | Planned first release |
| --- | --- |
| Rust workspace, CI, Docker base, CLI/UI/API foundations, bounded DNS parser, UDP/TCP transport base | Recursive resolver, DNSSEC, cache, filtering, DoH, DoT, DoQ |

## ✨ Direction

- **Private** — no telemetry, no cloud need, query logs off.
- **One service** — resolver, DNSSEC, cache, filtering, device policies.
- **Your rules** — profiles, lists, local records, split DNS.
- **Your deployment** — Docker, OrbStack, LXC, Unraid, bare metal, x86_64, ARM64.
- **Your visibility** — local dashboard, Prometheus, Grafana-ready metrics.

Read [plan](DNS_SERVICE_PLAN.md), [foundation](docs/foundation.md), and
[architecture](docs/architecture.md) before DNS-path changes.

## 🧰 Development

Requirements: stable Rust and, for container builds, a Docker-compatible engine.

Linux and macOS:

```bash
./scripts/dev.sh check
./scripts/dev.sh build
./scripts/dev.sh release
```

Windows PowerShell:

```powershell
.\scripts\dev.ps1 check
.\scripts\dev.ps1 build
.\scripts\dev.ps1 release
```

`release` creates local image `lumen:local`. Docker Desktop, OrbStack, Podman,
or another compatible engine may provide image runtime. It is a foundation image
until DNS listeners exist.

## 🤝 Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Use [SECURITY.md](SECURITY.md) for
security reports. Licensed under [Apache-2.0](LICENSE).

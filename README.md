# ✦ Lumen

> Private DNS, in your control.

**Lumen** is open-source DNS software by [Strukt](https://github.com/StruktSource).
It will unite recursive DNS, filtering, caching, and encrypted DNS in one small service.

## 🚧 Status

Foundation stage. **Not a DNS server yet.** Do not use Lumen in production.

| Available now | Planned first release |
| --- | --- |
| Rust workspace, CI, release workflow, Docker base, CLI/UI/API foundations | Resolver, DNSSEC, filtering, cache, UDP, TCP, DoH, DoT, DoQ |

## ✨ Direction

- **Private** — no telemetry, no cloud need, query logs off.
- **One service** — resolver, DNSSEC, cache, filtering, device policies.
- **Your rules** — profiles, lists, local records, split DNS.
- **Your deployment** — Docker, OrbStack, LXC, Unraid, bare metal, x86_64, ARM64.
- **Your visibility** — local dashboard, Prometheus, Grafana-ready metrics.

Read [plan](DNS_SERVICE_PLAN.md), [foundation](agent-docs/foundation.md), and
[architecture](docs/architecture.md) before DNS-path changes.

## 🧰 Development

```bash
./scripts/dev-macos.sh check
./scripts/dev-macos.sh build
./scripts/dev-macos.sh release
```

`release` creates local Docker image `lumen:local`. It is a foundation image
until DNS listeners exist.

## 🤝 Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Use [SECURITY.md](SECURITY.md) for
security reports. Licensed under [Apache-2.0](LICENSE).

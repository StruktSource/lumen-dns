# Lumen documentation

Welcome! This is the map to everything written about Lumen, a self-hosted DNS resolver with built-in filtering.

> [!NOTE]
> Lumen is **pre-release** software. Try it on a test network first. [Project status](project/roadmap.md) explains what is done and what is still ahead.

## Where do I start?

| I want to… | Read |
| :--- | :--- |
| Understand what Lumen is and how DNS works | [Concepts](getting-started/concepts.md) |
| Run Lumen for the first time | [Quick start](getting-started/quick-start.md) |
| Install it on my server, NAS, or Pi | [Deployment guides](deployment/README.md) |
| Let my phone, laptop, and TV use it | [Serve your network](guides/serve-your-network.md) |
| Block ads, trackers, or adult sites | [Filtering](guides/filtering.md) |
| Manage everything from a browser | [Web console](guides/web-console.md) |

## Getting started

- [Quick start](getting-started/quick-start.md): download or build Lumen, run it, and send your first query.
- [Concepts](getting-started/concepts.md): a plain-language tour of DNS, recursion, DNSSEC, filtering, and Lumen's vocabulary.

## Guides (how to do things)

- [Serve your network](guides/serve-your-network.md): allow other devices to use Lumen safely.
- [Resolver modes](guides/resolver-modes.md): recursive or forwarding, timeout fallback, and speed features.
- [Upstream providers](guides/upstream-providers.md): the bundled catalog of encrypted public resolvers.
- [Encrypted DNS](guides/encrypted-dns.md): serve DNS-over-TLS, DNS-over-HTTPS, and DNS-over-QUIC.
- [DHCP server](guides/dhcp.md): hand out IPv4 and IPv6 addresses and turn every lease into a DNS name (off by default).
- [Automatic certificates (ACME)](guides/certificates.md): get and renew the encrypted-DNS certificate from Let's Encrypt or another ACME CA.
- [Your own DNS zones](guides/authoritative-dns.md): authoritative zones, split-horizon views, conditional forwarding, dynamic updates, and zone transfers.
- [Filtering](guides/filtering.md): block lists, rules, per-device profiles, and schedules.
- [Web console](guides/web-console.md): accounts, setup, two-step verification, and HTTPS.
- [External login](guides/external-login.md): optional console sign-in through Authentik, Authelia, Pocket ID, and other OpenID Connect providers.
- [Query history](guides/query-history.md): the opt-in record of lookups, with retention and an anonymous mode.
- [Languages and translations](guides/translations.md): switch language, or add and improve one.
- [Managed mode](guides/managed-mode.md): persistent settings, `lumenctl`, and safe reloads.
- [Monitoring](guides/monitoring.md): Prometheus, Grafana, Home Assistant, and the metric list.

## Deployment

- [Choose a platform](deployment/README.md) and check the [compatibility matrix](deployment/compatibility.md).
- [Docker and Compose](deployment/docker.md) · [Podman](deployment/podman.md) · [Kubernetes and Helm](deployment/kubernetes.md)
- [Linux (systemd)](deployment/linux.md) · [macOS](deployment/macos.md) · [Windows](deployment/windows.md)
- [Proxmox, Unraid, and Raspberry Pi](deployment/homelab.md)

## Reference (look things up)

- [Configuration](reference/configuration.md): every setting, its default, and its limits.
- [Command line (`lumen` and `lumenctl`)](reference/cli.md)
- [Management API](reference/management-api.md): roles, routes, and signed webhooks.
- [DNS behavior](reference/dns-behavior.md): what Lumen accepts, answers, and limits.
- [DNSSEC and trust anchors](reference/dnssec-and-trust.md): validation, edge cases, and key updates.

## Design and security

- [Architecture](design/architecture.md): how the pieces fit together.
- [Threat model](design/threat-model.md): what Lumen defends against and what it does not.
- [Security policy](../SECURITY.md): how to report a vulnerability.

## Project

- [Roadmap and status](project/roadmap.md): what works today and what is planned.
- [Versioning and releases](project/versioning.md): version rules and how to verify a download.
- [Verification record](project/verification.md): tests and checks that have actually been run.
- [Performance](project/performance.md) and raw benchmarks: [load and idle](project/benchmarks/2026-11-12-load/load-table.md), [recursion A/B](project/benchmarks/2026-10-31-recursion/ab-report.md)
- [Contributing](../CONTRIBUTING.md) · [Code of conduct](../CODE_OF_CONDUCT.md) · [Changelog](../CHANGELOG.md)

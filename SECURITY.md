# 🛡️ Security policy

## Supported versions

Lumen is pre-release. Security fixes land on `main` until stable support exists.

## Report privately

Do **not** open public issues for vulnerabilities. Use private reporting at
[`StruktSource/lumen-dns`](https://github.com/StruktSource/lumen-dns/security/advisories/new).
Include version or commit, impact, reproduction, and a safe proof of concept.

## Security boundary

DNS packets, lists, configuration, network clients, API requests, and imports
are untrusted. Lumen must bound parsing, CPU, memory, disk, and network work.
No telemetry or query history is enabled. Management API access remains disabled.
Metrics/liveness are loopback-only. See [threat model](docs/threat-model.md) for
implemented controls, trust inputs, and remaining risks. Phase 1 uses Hickory
0.26.3 with local DNSSEC validation; recursion is still pre-release. Static trust
anchors and operator certificates need reviewed updates; see the
[resolver runbook](docs/resolver.md#root-hints-and-trust-anchors).

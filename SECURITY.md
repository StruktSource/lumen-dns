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
No telemetry. Remote management and history remain opt-in.

# 🛡️ Security policy

## Supported versions

Lumen is pre-release. Security fixes land on `main` until stable support exists.

## Report a vulnerability privately

**Do not open a public issue for a vulnerability.** Use private reporting on GitHub:

👉 [**Report a vulnerability**](https://github.com/StruktSource/lumen-dns/security/advisories/new)

Please include:

- the Lumen version or commit,
- the impact,
- steps to reproduce, and
- a safe proof of concept.

## What Lumen treats as untrusted

DNS packets, filter lists, configuration, network clients, API requests, and imports are all untrusted. Lumen must bound parsing, CPU, memory, disk, and network work for all of them.

By default no telemetry is sent and query history is off (an administrator can opt in), the management API is disabled, and metrics and liveness endpoints are loopback-only.

## Learn more

- [Threat model](docs/design/threat-model.md): implemented controls, trust inputs, and remaining risks
- [DNSSEC and trust anchors](docs/reference/dnssec-and-trust.md): how to update the static trust anchors and operator certificates through a reviewed process
- [Verification record](docs/project/verification.md): what has been tested, and what has not

Lumen uses Hickory DNS 0.26.3 with local DNSSEC validation. The recursive resolver is still pre-release and has not had an external security review.

# Threat model

What Lumen defends against, what it trusts, and where its protection ends. Read this before exposing Lumen beyond your own computer.

For reporting a vulnerability, see the [security policy](../../SECURITY.md).

## The short version

- **Untrusted:** DNS packets, filter lists, configuration files you did not write, network clients, API requests, and imports.
- **Trusted (your responsibility):** the host, your startup config, TLS keys, root hints, trust anchors, private CA bundles, client allow-lists, key file access, the system clock, and certificate renewal.
- **Lumen's job:** bound parsing, CPU, memory, disk, and network work so hostile input cannot take the service down or leak data.
- **Not Lumen's job:** a compromised host, router, or client; an upstream operator's honesty; or the privacy of plain-text DNS to authoritative servers.

## Controls in place

### DNS input and abuse

| Threat | Control |
| :--- | :--- |
| Malformed DNS, compression loops, forged section counts | Bounded full-message decoder, strict query shape, full consumption, parser regression tests, and fuzz targets |
| Oversized packets and partial stream frames | Per-message cap, UDP oversize detection, whole-frame read and write deadlines |
| Response loops and reflection | Incoming responses and short packets dropped, loopback and client CIDR defaults, rate and work caps, UDP response ceiling |
| Idle or hostile TCP/TLS clients | Shared connection cap, TLS handshake and frame deadlines, bounded response work |
| HTTP/2 body and header floods | Header, body, window, and stream caps and deadlines; GET, POST, path, and media-type checks |
| QUIC resource exhaustion | Connection admission, transport windows, bounded streams, deadlines, no unidirectional streams or early data |
| Query floods from many client IPs | Global query slots, per-IP one-second rate windows, bounded client table, bounded UDP workers |
| DNSSEC computational load | Recursion depth limit, bounded validation cache, NSEC3 limits, outer query deadline |
| Open resolver deployment | Loopback release default; network examples use private client CIDRs and an internal-only Kubernetes Service and NetworkPolicy |

### Correct answers

| Threat | Control |
| :--- | :--- |
| Cache poisoning and bad delegations | Hickory source and query matching, random query state, case randomization, bailiwick checks, and DNSSEC |
| Recursive access to local services | Hickory's recommended authority-address filters retained. No automatic private-range exception for custom hints |
| Bad upstream or certificate impostor | Local DNSSEC validation, explicit upstream IP and TLS name, verified CA chain, timeout-only opt-in fallback, no insecure downgrade |
| Forwarding loop | Exact listener endpoints rejected, recursive and fallback deadlines bounded, NAT and split-network limits documented |
| Listener silently fails | The daemon observes background task errors, and startup binds all sockets before serving |

### Privacy and management

| Threat | Control |
| :--- | :--- |
| Query privacy | No query history, no domain or client metric labels, no external telemetry. Startup logs show only listener addresses |
| Management exposure | API and metrics bind loopback only. The API requires hashed bearer tokens, scoped roles, per-token rate limits, bounded parsing, and durable audit |
| Static UI hosting | Embedded fixed routes, no filesystem paths or templates, bounded connections, strict response headers. Release HTTP binds loopback |

### Packaging and release

| Threat | Control |
| :--- | :--- |
| Container impact | Non-root UID 65532, no runtime key generation or download, minimal Debian runtime |
| Orchestrator breakout | Non-root UID, read-only root, dropped capabilities, no privilege escalation, seccomp, resource limits |
| CI or release compromise | Read-only PR permissions, no persisted checkout credentials, locked Rust dependencies, publish only on version tags after required gates |
| Artifact substitution | Per-archive SHA-256, GitHub artifact provenance, OCI provenance and SBOM. Image signing remains pending |

## Filtering

Filtering implements bounded parsers, verified HTTPS with public-IP pinning, atomic updates, and one in-memory rollback generation. Rules run before cache lookup, including for unusual wire labels. Synthetic answers clear the AD flag and use TTL zero.

- List contents are untrusted. Source paths and policy selection are administrator inputs.
- Schedules rely on the host's UTC clock.
- Query-name filtering is **not** CNAME-chain inspection and **not** a network firewall.
- Optional decision logs disclose names and client IPs only when you enable them.

## Management and the console

The management API uses bearer tokens, scoped roles, audit, and rate limits. It has no browser session or cookie authentication, so CSRF is not an API credential path. The web console has its own sessions, CSRF protection, lockouts, and optional two-step verification, described in the [web console guide](../guides/web-console.md). Remote exposure of either is outside the supported boundary, so keep them on loopback or behind HTTPS. Optional query history, when built, will need retention, redaction, and access controls, and will stay disabled by default.

## Limits of these guarantees

- **Memory.** Caches have entry and TTL bounds, not a contractual memory ceiling. Transient cache maintenance and protocol libraries use extra memory, and rate-limit state holds IP addresses only in transient bounded memory. Apply OS or container limits for hard isolation.
- **Denial of service.** Tests exercise overload and timeout paths but do not establish resistance to every strategy.
- **DNSSEC.** It authenticates signed data only. Unsigned zones can legitimately validate as insecure. Static root anchors need reviewed updates, because automatic RFC 5011 rollover is not implemented.
- **Hickory.** Its recursive implementation is upstream-experimental. External review, broader conformance, and extended soak testing remain stable-release gates. Fuzz smoke tests and a clean dependency audit are useful checks, not proof of security.
- **Supply chain.** GitHub Actions and third-party actions are part of the release trust boundary. Actions are pinned to reviewed commit IDs, but updates still need review. Artifact provenance records a build, and it does not make a compromised build safe.
- **Kubernetes.** Probes and Kind smoke tests do not prove CNI source-IP preservation, public-recursion safety, or real platform isolation.
- **Not yet done.** OCI image signing and reproducible-build comparison.

## Related

- [Security policy](../../SECURITY.md)
- [Verification record](../project/verification.md)
- [Architecture](architecture.md)

# Threat model

## Implemented Phase 1 controls

| Entry / threat | Control |
| --- | --- |
| Malformed DNS, compression loops, forged section counts | Bounded full-message decoder, strict query shape, full consumption, parser regressions and fuzz targets |
| Oversized packets / partial stream frames | Per-message cap; UDP oversize detection; whole-frame read/write deadlines |
| Response loops and reflection | Incoming responses/short packets dropped; loopback/client CIDR defaults; rate/work caps; UDP response ceiling |
| Idle or hostile TCP/TLS clients | Shared connection cap, TLS handshake/frame deadlines, bounded response work |
| HTTP/2 body/header floods | Header/body/window/stream caps and deadlines; GET/POST/path/media checks |
| QUIC resource exhaustion | Connection admission, transport windows, bounded streams, deadlines, no unidirectional streams or early data |
| Cache poisoning and bad delegations | Hickory source/query matching, random query state, case randomization, bailiwick checks and DNSSEC |
| Recursive access to local services | Hickory recommended authority-address filters retained; no automatic private-range exception for custom hints |
| Bad upstream / certificate impostor | Local DNSSEC; explicit upstream IP and TLS name; verified CA chain; timeout-only opt-in fallback; no insecure downgrade |
| Forwarding loop | Reject exact listener endpoints; bound recursive/fallback deadlines; document NAT and split-network limits |
| DNSSEC computational load | Recursive depth, bounded validation cache, NSEC3 limits, outer query deadline |
| Query floods / many client IPs | Global query slots, per-IP one-second rate windows, bounded client table, bounded UDP workers |
| Listener silently fails | Daemon observes background task errors; startup binds all sockets before serving |
| Query privacy | No query history, domain/client metric labels, or external telemetry; startup logs show only listener addresses |
| Management exposure | No management API routes; metrics/liveness bind only loopback |
| Container impact | Non-root UID 65532, no runtime key generation/download, minimal Debian runtime |

Caches have configurable entry/TTL bounds, not a contractual RSS byte ceiling.
Transient cache maintenance and protocol libraries use extra memory. Rate-limit
state contains IP addresses only in transient bounded memory. Apply OS/container
memory limits for hard resource isolation. Tests exercise overload and timeout
paths but do not establish resistance to every denial-of-service strategy.

## Trust and residual risks

The host, startup config, supplied certificate keys, hints, trust anchors, and
private CA bundles are administrator trust inputs. The operator controls network
reachability, client CIDRs, key file access, clock accuracy, and renewal. DNSSEC
authenticates signed DNS data, not the honesty of an upstream or the privacy of
plaintext authoritative DNS. Unsigned zones can legitimately validate as insecure.

Static root anchors need reviewed updates; automatic RFC 5011 rollover is not
implemented. A compromised host/router/client or wrong operator trust input is
outside Lumen's boundary. Hickory's recursive implementation remains upstream
experimental; external review, broader conformance, and extended soak testing
remain stable-release gates. Fuzz smoke tests and a clean dependency audit are
useful checks, not a proof of security.

## Later controls

Filtering implements bounded parsers, verified HTTPS with public-IP pinning,
atomic updates, and one in-memory rollback generation. Rules run before cache
lookup, including unusual wire labels; synthetic answers clear AD and use TTL
zero. List source contents remain untrusted. Source paths and policy selection
are administrator inputs. Schedules rely on the host UTC clock. Query-name
filtering is not CNAME-chain inspection or a network firewall. Optional decision
logs disclose names and client IPs only when explicitly enabled.

Future management requires auth, scoped roles, audit,
rate limits, and explicit remote exposure. Optional query history needs retention,
redaction, and access controls. These features remain disabled/unimplemented.

See [security policy](../SECURITY.md) and [verification](verification.md).

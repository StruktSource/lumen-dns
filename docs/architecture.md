# Architecture

```text
UDP / TCP / TLS / HTTPS / QUIC
    -> bounded listener work, connection admission, client CIDR access
    -> shared per-IP rate admission and bounded full DNS decoding
    -> global resolver admission and whole-query deadline
    -> Hickory catalog -> selected recursive or forwarding resolver
                       -> bounded response/delegation/validation caches
                       -> local DNSSEC verification -> bounded DNS encoding
    -> client reply

TOML / CLI -> schema and trust validation -> bind all sockets -> serve
Counters -> optional loopback /metrics and /healthz
```

All DNS transports share one resolver/cache set and one global query budget.
A listener failure reaches the daemon; individual client IO failures are isolated.
Shutdown cancels listener and child tasks. No thread is created per query.

## Crate ownership

| Crate | Owns |
| --- | --- |
| `lumen-proto` | Wire bounds, full-consumption decode, query validation, safe error responses |
| `lumen-config` | Startup schema, safe defaults, ACL/limit validation, bounded config reads |
| `lumen-resolver` | Mode, hints, anchors, verified upstream config, Hickory catalog adapter |
| `lumen-core` | Transport tasks, shared admission, metrics, service lifecycle |
| `lumen-api` | Reserved authenticated API boundary; no network routes |
| `apps/lumen` | Strict startup arguments and OS signals |

Hickory 0.26.3 provides full DNS records, iterative resolution, referral/glue
validation, positive/negative caching, DNSSEC, and upstream protocols. Tokio
provides async IO; rustls/ring provide TLS and QUIC cryptography; h2 and quinn
provide bounded client transports. The direct `hickory-proto` dependency uses
the same pinned version as the resolver/server crates.

Transport admission bounds live tasks, message allocations, HTTP/QUIC streams,
and deadlines. Cache limits count entries; OS/container limits remain the way
to impose a strict process-memory ceiling. Recursive authorities in private or
special-use address ranges are denied by Hickory's recommended filters.

## Planned extension points

Filtering will sit before cache lookup and resolution. Config reload must validate
then replace runtime state atomically. SQLite is planned for configuration and
opt-in history. The web shell and future scoped API cannot affect parser ownership
or bypass resolver limits. Future plugins need explicit permissions.

See [configuration](configuration.md), [resolver behavior](resolver.md), and
[threat model](threat-model.md) for operational contracts.

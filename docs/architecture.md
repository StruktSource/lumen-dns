# Architecture

```text
UDP / TCP / TLS / HTTPS / QUIC
    -> bounded listener work, connection admission, client CIDR access
    -> shared per-IP rate admission and bounded full DNS decoding
    -> global query admission
    -> client profile and atomic filter snapshot -> synthetic reply if blocked
    -> whole-resolution deadline
    -> Hickory catalog -> selected recursive or forwarding resolver
                       -> bounded response/delegation/validation caches
                       -> local DNSSEC verification -> bounded DNS encoding
    -> client reply

TOML / SQLite / CLI -> schema, trust, and filter-source validation -> bind all sockets -> serve
Counters -> optional loopback /metrics and /healthz
```

All DNS transports share one resolver/cache set and one global query budget.
A listener failure reaches the daemon; individual client IO failures are isolated.
Shutdown cancels listener and child tasks. No thread is created per query.

## Platform boundary

The workspace above is the only DNS implementation. Native binaries, OCI images,
Docker Compose, Podman, Kubernetes, Proxmox LXC, and Unraid all run `apps/lumen`
with the same crates and TOML schema. Platform files may choose paths, service
users, port mapping, probes, and shutdown integration. They must not fork resolver,
DNSSEC, cache, filtering, or transport behavior. Conditional compilation is
limited to OS signal handling and does not change DNS results.

## Crate ownership

| Crate | Owns |
| --- | --- |
| `lumen-proto` | Wire bounds, full-consumption decode, query validation, safe error responses |
| `lumen-config` | Startup schema, safe defaults, ACL/limit validation, bounded config reads |
| `lumen-resolver` | Mode, hints, anchors, verified upstream config, Hickory catalog adapter |
| `lumen-filter` | Rule normalization, policy selection, bounded imports, snapshots, schedules, synthetic replies |
| `lumen-store` | SQLite migrations, config revisions, devices, control queue, daemon status |
| `apps/lumenctl` | Local config, device, reload, filter, status, shutdown, and decision controls |
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

Filtering sits before cache lookup and resolution. Managed config reload stages
a SQLite revision, validates it, restarts runtime state, and restores the prior
server on bind failure. Query history remains planned. The web shell and future
scoped API cannot affect parser ownership
or bypass resolver limits. Future plugins need explicit permissions.

See [configuration](configuration.md), [resolver behavior](resolver.md), and
[threat model](threat-model.md) for operational contracts. The
[compatibility matrix](deployment/compatibility.md) keeps runtime evidence apart
from build-only or planned support.

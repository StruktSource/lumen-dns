# Architecture

How Lumen is built and why. This page is for operators who want to understand what runs on their network, and for contributors who want to find their way around the code.

## The big picture

Every DNS query, whatever transport it arrives on, follows the same path through one shared pipeline:

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

TOML / SQLite / CLI / authenticated API -> schema and trust validation -> bind -> serve
Counters -> optional loopback /metrics and /healthz
Embedded web console -> bounded HTTP/1.1 or HTTP/2 -> optional TLS 1.3
```

In words:

1. A query arrives and is admitted only if the client is allowed and within its rate and connection limits.
2. It is decoded strictly and bounded.
3. The client's profile and the current filter snapshot decide whether to block it. Filtering happens **before** any cache or resolver work.
4. Otherwise a recursive or forwarding resolver answers it, using bounded caches and local DNSSEC validation, all under one whole-resolution deadline.

All transports share **one resolver and cache set** and one global query budget. A listener failure reaches the daemon, while individual client I/O failures are isolated. Shutdown cancels listener and child tasks, and no thread is created per query.

## The code layout

Lumen is a Rust workspace. Each crate owns one concern:

| Crate | Owns |
| :--- | :--- |
| `lumen-proto` | Wire bounds, full-consumption decoding, query validation, safe error responses |
| `lumen-config` | Startup schema, safe defaults, access-list and limit validation, bounded config reads |
| `lumen-resolver` | Mode, hints, anchors, verified upstream config, Hickory catalog adapter |
| `lumen-filter` | Rule normalization, policy selection, bounded imports, snapshots, schedules, synthetic replies |
| `lumen-store` | SQLite migrations, config revisions, devices, control queue, daemon status |
| `lumen-core` | Transport tasks, shared admission, metrics, service lifecycle |
| `lumen-api` | Loopback `/v1` auth, roles, rate limits, audit, control queue, signed webhooks |
| `lumen-web` | Embedded console UI, session-authenticated `/api`, strict routes and headers, HTTP/1.1, HTTP/2, direct TLS |
| `apps/lumen` | Strict startup arguments and OS signals |
| `apps/lumenctl` | Local config, device, reload, filter, status, shutdown, user, and decision controls |

Other top-level folders:

```text
config/    safe release default and opt-in feature examples
deploy/    Docker Compose, Kubernetes, Helm, systemd, and observability files
docs/      this documentation
fuzz/      DNS, config, and filter fuzz targets (a separate Cargo workspace)
scripts/   local checks, builds, packaging, and benchmarks
vendor/    one patched dependency (see the DNSSEC page)
web/       console UI (HTML, CSS, JS) embedded by lumen-web at compile time
.agent/    concise project continuity notes
```

Design rules that keep this honest:

- Protocol parsing never imports UI, API, storage, or resolver code.
- `lumen-core` wires components together; resolver business rules stay in `lumen-resolver`.
- Hickory owns DNS algorithms and cryptography. Lumen implements **no** custom DNSSEC crypto.
- No `unsafe` code is allowed in Lumen crates.

### Libraries

[Hickory DNS](https://github.com/hickory-dns/hickory-dns) 0.26.3 provides full DNS records, iterative resolution, referral and glue validation, caching, DNSSEC, and upstream protocols. Tokio provides async I/O, rustls and ring provide TLS and QUIC cryptography, and `h2` and `quinn` provide bounded client transports. The direct `hickory-proto` dependency uses the same pinned version as the resolver and server crates.

## One engine, every platform

Native binaries, OCI images, Docker Compose, Podman, Kubernetes, Proxmox, and Unraid all run `apps/lumen` with the same crates and TOML schema. Platform files may choose paths, service users, port mappings, probes, and shutdown integration. They **must not** fork resolver, DNSSEC, cache, filtering, or transport behavior. Conditional compilation is limited to OS signal handling and never changes DNS results.

## Resource bounds

Transport admission bounds live tasks, message allocations, HTTP and QUIC streams, and deadlines. Cache limits count entries, so OS or container limits remain the way to impose a strict process-memory ceiling. Recursive authorities in private or special-use address ranges are denied by Hickory's recommended filters. All the numbers are in the [configuration reference](../reference/configuration.md#limits).

## Contracts Lumen keeps

- **Versioned config.** The startup [schema](../reference/configuration.md) is versioned. Unknown fields and future versions fail closed. SQLite migrations are explicit, and config candidates are validated before a reload.
- **Protocol errors stay protocol errors.** DNS errors use DNS response codes. Startup errors are local and never dump configuration, keys, query packets, or query names.
- **Stable metrics.** Names start with `lumen_dns_` and carry no client or domain labels. See [Monitoring](../guides/monitoring.md).
- **A separate, authenticated API.** The management API starts at `/v1`, with authentication, scoped authorization, rate limits, and durable audit applied before dispatch. DNS-over-HTTPS is a DNS transport, not a management API.
- **State is opt-in and local.** SQLite holds config revisions and devices only with `--state`. Hot DNS caches remain bounded in memory. Query history and external telemetry are off.
- **Nothing implicit.** Operators opt into each encrypted listener and each upstream, and recursive mode has no implicit upstream fallback.

## Extension points

- Filtering sits before cache lookup and resolution.
- A managed config reload stages a SQLite revision, validates it, restarts runtime state, and restores the prior server on bind failure.
- The web console and scoped API cannot affect parser ownership or bypass resolver limits.
- Query history is planned. Future plugins would need explicit permissions.

## Runtime and compatibility

- **Minimum Rust:** 1.88, required by Hickory 0.26.3. `rust-toolchain.toml` selects the installed stable channel, CI and Docker pin 1.95.0, and CI also checks the 1.88 minimum.
- **Platforms:** CI targets Linux, macOS, and Windows with portable Tokio, rustls, and ring transports. Runtime claims must be backed by the [verification record](../project/verification.md) and the [compatibility matrix](../deployment/compatibility.md).

## Related

- [Threat model](threat-model.md)
- [Configuration reference](../reference/configuration.md)
- [Versioning and releases](../project/versioning.md)

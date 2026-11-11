# Configuration reference

Every setting Lumen accepts, with defaults and limits. New to Lumen? Start with the [Quick start](../getting-started/quick-start.md); this page is for looking things up.

**On this page:** [Basics](#basics) · [Top-level settings](#top-level-settings) · [Listeners](#listeners) · [Resolver](#resolver) · [Limits](#limits) · [Filtering](#filtering)

## Basics

Lumen reads a TOML file with `schema_version = 1`, passed as `lumen --config FILE`.

| File | Purpose |
| :--- | :--- |
| [`config/lumen.toml`](../../config/lumen.toml) | The **only** release default: local recursive DNS plus required safety limits |
| [`config/forward.example.toml`](../../config/forward.example.toml) | Example: encrypted provider forwarding (sends queries to that provider) |
| [`config/filtering.example.toml`](../../config/filtering.example.toml) | Example: filtering with reserved fake domains |
| [`deploy/lumen.toml`](../../deploy/lumen.toml) | Container and service defaults with private-network client ranges |

Files ending in `.example.toml` are opt-in examples and are never loaded automatically. The release default enables no metrics, provider, fallback, filter policy, external list, history, telemetry, or management API.

**Strict by design.** Unknown fields, future schema versions, invalid addresses, and out-of-range limits fail startup. Config files must be UTF-8 and at most 64 KiB. Relative file paths resolve **beside the config file**, not the working directory. Socket addresses include the port, and IPv6 uses brackets, like `[::1]:5353`.

**Check before you run:**

```sh
lumen --config FILE --check
```

`--check` validates the config, root hints, trust anchors, TLS credentials, and **all filter sources** without opening any listener. HTTPS filter sources do perform host DNS lookups and downloads during the check. Port availability is only tested when the daemon really starts, and all enabled sockets must bind before any traffic is served.

**Managed mode.** With `--state FILE`, the first start stores your TOML as revision 1 and later changes come from the database. See [Managed mode](../guides/managed-mode.md).

**Not in the TOML.** Some console settings live in the state database, not in this file: the console [language](../guides/translations.md), the [query history](../guides/query-history.md) mode, detail, and retention, the session timeout, and the accounts. Change them in the console or with `lumenctl`.

## Top-level settings

| Field | Default and meaning |
| :--- | :--- |
| `schema_version` | **Required**, must be `1` |
| `metrics` | Disabled. Optional nonzero loopback address for `/metrics` and `/healthz`. See [Monitoring](../guides/monitoring.md) |
| `management.listen` | Disabled. Optional nonzero loopback address, managed mode only |
| `management.requests_per_minute` | `60`. Per-token limit, 1 to 600 |
| `management.tokens` | 1 to 16 named SHA-256 token hashes, each with a `viewer`, `operator`, or `admin` role, when the API is enabled |
| `management.webhooks` | Up to 8 signed HTTPS audit webhooks with secret files. See [Management API](management-api.md) |
| `web.http` | Release config: `127.0.0.1:8080` and `[::1]:8080`. An empty list disables HTTP |
| `web.https` | Empty. When set, serves direct TLS 1.3 with HTTP/2 and HTTP/1.1 |
| `web.certificate`, `web.private_key` | Required together when `web.https` is set |
| `web.max_connections` | `64`. Shared web connection limit, 1 to 1024 |
| `listen` | Listener and client-access settings: [below](#listeners) |
| `resolver` | Mode, cache, DNSSEC, and upstreams: [below](#resolver) |
| `limits` | Shared admission and I/O limits: [below](#limits) |
| `filtering` | Optional rules, lists, profiles, devices, groups, subnets, schedules: [below](#filtering) |

## Listeners

| Field | Default |
| :--- | :--- |
| `udp`, `tcp` | Each `["127.0.0.1:5353"]` |
| `dot`, `doh`, `doq` | Each `[]` (disabled) |
| `allow_clients` | `["127.0.0.0/8", "::1/128"]` |
| `certificate`, `private_key` | Unset. Both are required for any encrypted listener |

- An empty array disables that transport. Enable 1 to 16 DNS listeners in total.
- Ports must be nonzero, and duplicates within one transport are invalid. The OS also rejects incompatible bindings across transports. UDP and TCP may share a port, and DoT (TCP) and DoQ (UDP) may share a port. IPv6 sockets are IPv6-only, so IPv4 and IPv6 wildcard listeners can coexist.
- **Every client must match an allowed CIDR**, including on encrypted transports. An empty allowlist is invalid (maximum 128 CIDRs). A wildcard bind does not grant access. See [Serve your network](../guides/serve-your-network.md).
- TLS listeners use TLS 1.3 with no early data and PEM files (certificate up to 1 MiB, key up to 64 KiB). Startup verifies the key matches the certificate. You manage validity, renewal, permissions, and restarts after rotation. See [Encrypted DNS](../guides/encrypted-dns.md).

## Resolver

### Core settings

| Field | Default | Bounds and scope |
| :--- | :--- | :--- |
| `mode` | `"recursive"` | `"recursive"` or `"forward"`. Only one runs at a time |
| `dnssec` | `true` | Both modes validate locally by default |
| `root_hints` | Bundled InterNIC hints | Optional BIND-format file. Recursive mode only. 64 KiB, 1 to 64 IP records, directives disabled |
| `trust_anchor` | Hickory's bundled root DNSKEYs | Optional DNSKEY-format file. 64 KiB, at least one key. DNSSEC must be enabled |
| `upstream_ca` | Public WebPKI roots | Optional PEM CA bundle (1 MiB). Replaces the public roots for encrypted forwarding |
| `upstreams` | `[]` | Up to 8 custom endpoints, which rank after any providers. In forward mode you need at least one provider or upstream. Rejected in recursive mode |
| `providers` | `[]` | Up to 8 bundled provider selections, in rank order, each used once. They expand to at most 128 addresses together with the custom upstreams |
| `strategy` | unset | Forward mode only: `failover`, `fastest`, `round_robin`, or `race`. Unset keeps the older behavior (`failover` for automatic transports, otherwise `fastest`). See [Upstream providers](../guides/upstream-providers.md#use-several-providers) |
| `attempts` | `2` | 1 to 5. Forwarding retries, or full recursive-walk attempts after a timeout |
| `upstream_timeout_ms` | `2000` | 1 to 30000. Per-attempt forwarding or recursive-walk timeout |
| `recursion_depth` | `24` | 1 to 64. Bounds recursive query and nameserver recursion |
| `local_zones` | `true` | Serve registered local-only zones locally. Set `false` only when another local DNS path owns them |
| `diagnostics` | `false` | Export extra fixed-cardinality recursive attempt counters and timing. Never includes names, server IPs, or clients |

### Caches

| Field | Default | Bounds and scope |
| :--- | :--- | :--- |
| `cache_entries` | `4096` | 1 to 65536 response entries |
| `nameserver_cache_entries` | `1024` | 1 to 4096. Recursive delegation cache (raised from 256 so busy networks stop re-walking delegations) |
| `validation_cache_entries` | `4096` | 1 to 65536. Recursive DNSSEC validation cache |
| `positive_ttl_secs` | `86400` | 1 to 604800. A TTL **ceiling**, never a forced minimum |
| `negative_ttl_secs` | `3600` | 1 to 86400. TTL ceiling for NXDOMAIN and NODATA |

Capacities count **entries, not bytes of memory**. Record sizes, separate caches, in-flight work, library maintenance, and TLS or QUIC buffers also use memory. For a hard memory ceiling, use container or OS limits. A TTL of zero is never extended into a positive cache lifetime.

### Speed features (recursive mode only)

| Field | Default | Meaning |
| :--- | :--- | :--- |
| `warm` | Off in code, **on** in the shipped configs | Startup priming. See [`[resolver.warm]`](#resolverwarm) |
| `prefetch` | Off | Refresh of repeatedly requested names when their answer expires. See [`[resolver.prefetch]`](#resolverprefetch) |
| `hedge_ms` | `0` (off) | `0` or 100 to 5000. Starts one extra recursion for lookups still unanswered after this long; the first usable answer wins. Measurements were inconclusive, see [Performance](../project/performance.md) |
| `fallback` | Disabled | Timeout-only forwarding. See [`[resolver.fallback]`](#resolverfallback) |

Each recursive walk is capped by `upstream_timeout_ms`. Only a timeout can start another walk, up to `attempts`; DNS answers and DNSSEC failures stay final. The extra unsigned-zone SOA/NS recovery work shares one further attempt-sized budget. Configuration must fit those attempts and recovery inside the recursive deadline. Hickory still chooses and retries authorities inside each walk. The outer query deadline applies to both modes. Recursive mode filters private, loopback, link-local, and other special-use authority addresses (Hickory's recommended server filters), and custom root hints do not disable that boundary. It never silently switches to a public forwarding resolver.

With `local_zones = true`, Lumen serves the current IANA IPv4 and IPv6 locally-served reverse zones, `home.arpa`, `resolver.arpa`, and `service.arpa` without public leakage. Empty-zone apex SOA/NS and negative replies follow RFC 6303. `home.arpa` DS queries with the DO bit still recurse for the public insecure-delegation proof. `resolver.arpa` returns NODATA because Lumen does not advertise a Designated Resolver. `.local` is stopped locally because it belongs to mDNS; Lumen does not bridge multicast DNS. Public reverse DNS and `ipv4only.arpa` are unchanged.

### `[resolver.fallback]`

| Field | Default | Meaning |
| :--- | :--- | :--- |
| `enabled` | `false` | Must be set explicitly. Recursive mode only |
| `recursive_timeout_ms` | `7000` | 1 to 60000. Recursive budget before fallback is allowed |
| `timeout_ms` | `2000` | 1 to 30000. Budget for the whole fallback lookup |
| `attempts` | `1` | 1 to 5, bounded within `timeout_ms` |
| `upstreams` | `[]` | 1 to 8 explicit endpoints, required when enabled |

Fallback upstreams use the same fields and rules as forward-mode upstreams. `recursive_timeout_ms + timeout_ms` must not exceed `limits.query_timeout_ms`. Lumen rejects any fallback endpoint that matches one of its own listeners, but loopback, NAT, split-network, or forwarded addresses can still loop back, so verify the path. Fallback runs **only** for resolver-layer recursion timeouts, never for NXDOMAIN, NODATA, DNSSEC failures, generic SERVFAIL, filtering, admission refusals, or other network failures. See [Resolver modes](../guides/resolver-modes.md#optional-timeout-fallback).

### `[resolver.warm]`

| Field | Default | Meaning |
| :--- | :--- | :--- |
| `enabled` | `false` | Set explicitly. The shipped `config/lumen.toml` and `deploy/lumen.toml` enable it |
| `zones` | 12 common zones | At most 64 ASCII names without a trailing dot. The root is always primed |

Priming sends an `NS` and a `DNSKEY` query per zone through the normal validating recursor, two at a time, each bounded to 10 seconds. It names only the zones you list, never client data. Failures are counted and otherwise ignored.

### `[resolver.prefetch]`

| Field | Default | Bounds | Meaning |
| :--- | :--- | :--- | :--- |
| `enabled` | `false` | | Must be set explicitly |
| `min_hits` | `2` | 1 to 100 | Cache hits needed after the initial fill, within one cache lifetime |
| `max_tracked` | `1024` | 16 to 8192 | Names tracked at once; the least recently seen is dropped |
| `max_concurrent` | `4` | 1 to 16 | Refreshes running at the same time |
| `budget_per_minute` | `240` | 1 to 6000 | Refreshes started in any minute |

Tracked names live in memory only, are never logged, exported, or saved, and are forgotten after an hour without a lookup. Refresh never starts before the authoritative TTL has elapsed, and answers with a TTL under 10 seconds are not refreshed.

### `[[resolver.upstreams]]`

| Field | Meaning |
| :--- | :--- |
| `address` | **Required.** Explicit IPv4 or IPv6 address and port. No bootstrap DNS lookup |
| `protocol` | `udp`, `tcp`, `tls`, `https`, or `quic` |
| `server_name` | Required for encrypted protocols. Used as the certificate name and SNI |
| `doh_path` | Optional, HTTPS only. An absolute path, default `/dns-query` |

`udp` also enables TCP fallback at the same address and port. `https` uses HTTP/2. Certificate chain and name verification always stay on, and a private CA bundle changes the trusted roots without bypassing name checks.

### `[[resolver.providers]]`

| Field | Meaning |
| :--- | :--- |
| `id` | **Required.** Stable ID from the bundled [provider catalog](../guides/upstream-providers.md) |
| `protocol` | An explicit `udp`, `tcp`, `tls`, `https`, or `quic`; or encrypted-only `auto` |
| `address_family` | `any` (default), `ipv4`, or `ipv6` |
| `encryption` | Auto mode only. Defaults to, and only accepts, `required` |
| `transport_priority` | Auto mode only. A unique ordered subset of `quic`, `https`, `tls` |

Auto mode defaults to QUIC, then HTTPS, then TLS, skips transports the preset does not support, and fails over only on connection, transport, or timeout errors. Automatic and explicit preset transports cannot be mixed. All normal attempt and deadline limits still apply.

## Limits

| Field | Default | Range and meaning |
| :--- | :--- | :--- |
| `max_in_flight` | 128 | 1 to 4096 shared resolver queries |
| `max_connections` | 64 | 1 to 1024 TCP, TLS, HTTP/2, QUIC, and metrics connections |
| `max_clients` | 4096 | 1 to 65536 tracked rate-limit IPs |
| `queries_per_second` | 100 | 1 to 10000 per IP in one-second windows, shared by all transports |
| `query_timeout_ms` | 10000 | 1 to 60000. Whole-resolution deadline |
| `io_timeout_ms` | 5000 | 1 to 30000. Deadline for frames, TLS handshakes, HTTP bodies, and writes |
| `max_message_bytes` | 4096 | 512 to 65535 DNS message bytes |

What happens at the limits:

- Stream slots are capped at eight per HTTP/2 or QUIC connection. UDP workers are bounded per listener, while resolver concurrency is global.
- Overloaded UDP work and disallowed or rate-limited traffic may simply be **dropped**.
- A valid query that arrives when the resolver budget is full gets `REFUSED`. A resolver timeout or failure produces `SERVFAIL`.
- Idle or malformed streams are closed.
- Rate tracking lives in bounded, transient memory. It is not query history.

## Filtering

The optional `[filtering]` table holds rules, lists, profiles, groups, devices, and subnets. The full guide with examples is [Filtering](../guides/filtering.md). Key facts:

| Item | Detail |
| :--- | :--- |
| `filtering.action` | `nxdomain` (default), `nodata`, `refused`, `address`, or `cname`; profiles may override |
| `filtering.default_profile` | Profile used for clients no device, group, or subnet matches |
| `filtering.decision_log` | Default `false`. When `true`, logs names, client IPs, and decisions to stderr |
| `[[filtering.lists]]` | Unique `id`, a `format` (`domains`, `hosts`, `adblock`), exactly one of `path`, `url`, `text`, optional `category`, and `refresh_secs` (60 to 604800, default 86400, `0` disables) |
| Limits | 64 MiB per list, 4096 bytes per line, 4,000,000 rules total, 4096 manual rules per tier, 64 lists, 128 profiles and groups, 1024 devices (32 addresses each), 256 subnets, 32 schedule windows per profile |

## Related

- [Command line reference](cli.md)
- [DNS behavior](dns-behavior.md)
- [Threat model](../design/threat-model.md)

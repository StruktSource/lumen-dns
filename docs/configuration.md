# Startup configuration

Lumen accepts TOML schema **1** through `lumen --config FILE`. See
[`config/lumen.toml`](../config/lumen.toml) and
[`config/forward.toml`](../config/forward.toml).

Unknown fields, future schema versions, invalid addresses, and out-of-range
limits fail startup. No implicit migration occurs. Config files are limited to
64 KiB and must be UTF-8. Relative file paths resolve beside the config file,
not the process working directory. Hot reload and schema migrations are later work.

`lumen --config FILE --check` validates configuration, hints, trust anchors, and
TLS credentials and all filter sources without opening listeners. HTTPS filter
sources perform host DNS lookups and downloads during this check. Port availability
is checked only when the daemon starts. All enabled sockets must bind before
traffic is served. Startup fails if any listener cannot bind.

## Top level

| Field | Default / meaning |
| --- | --- |
| `schema_version` | Required; must be `1` |
| `metrics` | Disabled; optional nonzero loopback socket address for HTTP `/metrics` and `/healthz` |
| `listen` | Listener and client-access settings |
| `resolver` | Selected mode, cache, DNSSEC, and upstream settings |
| `limits` | Shared admission and IO bounds |
| `filtering` | Optional rules, sources, profiles, devices, groups, subnets, UTC schedules; see [filtering reference](filtering.md) |

Socket addresses include ports; IPv6 uses brackets. Example: `[::1]:5353`.

## Listeners

| Field | Default |
| --- | --- |
| `udp`, `tcp` | Each `["127.0.0.1:5353"]` |
| `dot`, `doh`, `doq` | Each `[]`, disabled |
| `allow_clients` | `["127.0.0.0/8", "::1/128"]` |
| `certificate`, `private_key` | Unset; both required for encrypted listeners |

Empty arrays disable individual transports. Enable 1–16 DNS listeners in total.
Ports must be nonzero; duplicates within a transport are invalid. The OS also
rejects incompatible bindings between transports. UDP and TCP may share a port;
DoT and DoQ may share a port because they use TCP and UDP respectively. IPv6
sockets are IPv6-only, so IPv4 and IPv6 wildcard listeners can coexist.

Every client must match an allowed CIDR, including on encrypted transports.
An empty allowlist is invalid; maximum 128 CIDRs. Binding a wildcard address does
not grant access. Remote access requires an explicit allowlist change.

TLS listeners use TLS 1.3, no early data, and PEM certificate/key files. File
limits: certificate 1 MiB, private key 64 KiB. Startup checks key/certificate
matching. The operator manages certificate validity, renewal, file permissions,
and restart after rotation. Lumen does not create or download certificates.

## Resolver

| Field | Default | Bounds / scope |
| --- | --- | --- |
| `mode` | `"recursive"` | `"recursive"` or `"forward"` |
| `dnssec` | `true` | Both modes validate locally by default |
| `root_hints` | Bundled InterNIC hints | Optional BIND-format file; recursive mode only; 64 KiB; 1–64 IP records; directives disabled |
| `trust_anchor` | Hickory bundled root DNSKEYs | Optional DNSKEY-format file; 64 KiB; at least one key; DNSSEC must be enabled |
| `upstream_ca` | Public WebPKI roots | Optional PEM CA bundle, 1 MiB; replaces public roots for encrypted forwarding |
| `upstreams` | `[]` | 1–8 required in forward mode; rejected in recursive mode |
| `cache_entries` | `4096` | 1–65536 response entries |
| `nameserver_cache_entries` | `256` | 1–4096; recursive delegation cache |
| `validation_cache_entries` | `4096` | 1–65536; recursive DNSSEC validation cache |
| `positive_ttl_secs` | `86400` | 1–604800; TTL ceiling, never a forced minimum |
| `negative_ttl_secs` | `3600` | 1–86400; TTL ceiling for NXDOMAIN/NODATA |
| `recursion_depth` | `24` | 1–64; recursive query and nameserver recursion |
| `attempts` | `2` | 1–5; forwarding attempts |
| `upstream_timeout_ms` | `2000` | 1–30000; per-attempt forwarding timeout |
| `fallback` | Disabled | Optional timeout-only forwarding after recursive mode times out |

Recursive transport retries/timeouts use Hickory's bounded internal policy. The
outer query deadline applies to both modes. Recursive mode filters private,
loopback, link-local, and other special-use authority addresses using Hickory's
recommended server filters. Custom root hints do not disable that boundary.
Recursive mode never silently switches to a public forwarding resolver.

`[resolver.fallback]` fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Must be set explicitly; recursive mode only |
| `recursive_timeout_ms` | `7000` | 1–60000; recursive budget before fallback eligibility |
| `timeout_ms` | `2000` | 1–30000; whole fallback lookup budget |
| `attempts` | `1` | 1–5, bounded inside `timeout_ms` |
| `upstreams` | `[]` | 1–8 explicit endpoints required when enabled |

Fallback upstreams use the same fields and transport rules as forward-mode
upstreams. `recursive_timeout_ms + timeout_ms` must not exceed the whole query
deadline. Lumen rejects a fallback endpoint matching any configured listener.
Other loopback, NAT, split-network, or forwarded addresses can still create a
loop if they route back to Lumen; verify the network path before enabling them.
The fallback runs only for resolver-layer recursion timeouts. NXDOMAIN, NODATA,
DNSSEC bogus responses, generic SERVFAIL, filtering, admission refusal, and
other network failures do not trigger it.

Cache capacities count entries, not process RSS bytes. Record sizes, separate
caches, in-flight work, library eviction maintenance, and TLS/QUIC buffers also
consume memory. Use container/OS memory limits when an absolute RSS ceiling is
needed. TTL zero is not extended into a positive cache lifetime.

Each `[[resolver.upstreams]]` has:

| Field | Meaning |
| --- | --- |
| `address` | Required explicit IPv4/IPv6 address and port; no bootstrap DNS lookup |
| `protocol` | `udp`, `tcp`, `tls`, `https`, or `quic` |
| `server_name` | Required for encrypted protocols; certificate name and SNI |

`udp` enables TCP fallback at the same address/port. `https` uses HTTP/2 and
`/dns-query`. Certificate identity and chain verification stay enabled. A
private CA bundle changes trusted roots; it does not bypass name verification.

## Limits

| Field | Default | Allowed range |
| --- | --- | --- |
| `max_in_flight` | 128 | 1–4096 shared resolver queries |
| `max_connections` | 64 | 1–1024 TCP/TLS/HTTP2/QUIC/metrics connections |
| `max_clients` | 4096 | 1–65536 tracked rate-limit IPs |
| `queries_per_second` | 100 | 1–10000 per IP in one-second windows, shared by transports |
| `query_timeout_ms` | 10000 | 1–60000 whole resolution deadline |
| `io_timeout_ms` | 5000 | 1–30000 frame, TLS handshake, HTTP body, and write deadline |
| `max_message_bytes` | 4096 | 512–65535 DNS message bytes |

Stream slots are bounded to eight per HTTP/2 or QUIC connection. UDP worker
count is bounded per listener; resolver concurrency is global. Overloaded UDP
work and disallowed/rate-limited traffic may be dropped. A parsed query that
reaches a full resolver budget gets REFUSED. Resolver timeout/failure produces
SERVFAIL. Idle or malformed streams close. Rate tracking stays in bounded,
transient memory; it is not query history.

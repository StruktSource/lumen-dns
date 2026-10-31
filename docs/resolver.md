# Resolver operations

Phase 1 provides DNS transport, iterative recursion, forwarding, caches, local
DNSSEC validation, admission control, and aggregate metrics. Filtering, storage,
an opt-in management API, and a functional UI are separate Phase 3 surfaces.

## Start and query

```sh
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/lumen.toml
dig @127.0.0.1 -p 5353 example.com A
dig @::1 -p 5353 example.com AAAA +tcp
dig @127.0.0.1 -p 5353 example.com A +dnssec
```

Use `config/forward.example.toml` for encrypted provider forwarding. Provider
`protocol = "auto"` keeps a configured encrypted transport order and fails over
only after connection, transport, or timeout errors. It never adds UDP or TCP.
DNS answers and DNSSEC failures do not trigger another transport. The same cache
and resolver are shared across client transports. Only one mode runs at a time.

## Optional recursive fallback

Recursive mode stays the default and does not contact a forwarding provider
unless `[resolver.fallback]` is explicitly enabled with at least one upstream.
The decision path is:

1. Filtering runs before any resolver work.
2. Lumen checks the recursive cache and performs iterative resolution.
3. A recursive answer, NXDOMAIN, NODATA, DNSSEC failure, generic SERVFAIL,
   policy block, rate refusal, or non-timeout network error ends the decision.
4. Only an identified recursive timeout starts one bounded fallback lookup.
5. The fallback result is validated with the same DNSSEC and trust settings.

`recursive_timeout_ms + timeout_ms` must fit within `limits.query_timeout_ms`.
The fallback future is cancelled when its budget ends, so no background query
continues after Lumen replies. Fallback endpoints must not match a Lumen
listener. Take care with other loopback, split-network, NAT, and port-forwarded
addresses because static validation cannot prove that they do not route back to
Lumen.

An enabled fallback discloses queries that time out during recursion to the
chosen operator. Plain recursive DNS normally discloses parts of the lookup to
root, TLD, and authoritative servers over UDP/TCP. Encrypted fallback protocols
verify certificate identity and never downgrade to plaintext.

## Cold-cache speed

Recursive mode keeps one validating recursor. Three bounded mechanisms reduce the
time to answer names that are not cached yet, without any forwarding resolver and
without relaxing DNSSEC validation, TTLs, or filtering:

- **Shared recursion (always on).** Identical in-flight queries (same name, type,
  and DNSSEC-OK flag) wait for one recursion instead of each walking the tree.
  Waiters receive the leader's validated answer; a failed or cancelled leader never
  strands them. At most 4096 groups are in flight; beyond that queries recurse
  alone. `lumen_dns_recursive_coalesced_total` counts the saved recursions.
- **Startup priming (`[resolver.warm]`).** Fetches root and top-level-zone
  delegations and DNSKEY/DS data once, in the background, after every listener is
  bound. See [configuration](configuration.md#resolver).
- **Expiry refresh (`[resolver.prefetch]`, off by default).** Names looked up at
  least `min_hits` times in one cache lifetime are re-resolved right after they
  expire, within a concurrency and per-minute budget.

- **Hedged recursion (`hedge_ms`, off by default).** A lookup still unanswered after
  the delay starts one second recursion; the first usable answer wins.
  `lumen_dns_recursive_hedged_total` counts them. Measurements were inconclusive.

Filtering runs before any of this, so a blocked name is never resolved, primed, or
refreshed, and a refreshed answer is still filtered when served.

Evaluated and not shipped: serve-stale (RFC 8767) and delegation-cache persistence.
Hickory drops expired entries and keeps its caches private, so both would need a
second Lumen-owned cache of validated messages with its own expiry, revalidation
and memory bounds. Persisting delegations would also have to revalidate every
record on load. Priming recovers most of the restart cost without that surface.
Nameserver selection already uses Hickory's smoothed round-trip statistics; the
recursor fixes one outstanding request per nameserver pool and a 5 second
per-attempt timeout, which sets the slow tail on unresponsive authorities and
cannot be changed from Lumen. Measurements are in
[performance](performance.md).

## Encrypted listeners

Set `listen.certificate` and `listen.private_key`, then replace the empty
`dot`, `doh`, and `doq` arrays with selected addresses. Defaults enable none.
Example development ports are 8853 (DoT TCP and DoQ UDP) and 8443 (DoH TCP).
Use a certificate trusted by clients and matching the DNS service name.

- **DoT:** TLS 1.3, ALPN `dot`, two-byte DNS message lengths, multiple framed
  queries on a connection.
- **DoH:** TLS 1.3, ALPN `h2`, HTTP/2 GET or POST at `/dns-query`. GET uses the
  base64url `dns` parameter without padding. POST requires
  `Content-Type: application/dns-message`. Replies use that media type and
  `Cache-Control: no-store`. Wrong path/method/media returns 404/405/415;
  malformed HTTP payloads return 400 and oversized bodies return 413.
- **DoQ:** TLS 1.3, ALPN `doq`, one two-byte-length-prefixed message per
  bidirectional stream, with stream FIN. DNS message IDs must be zero. Invalid
  framing or IDs close the connection with DoQ protocol error.

Use a DoH client with HTTP/2 support or a DoT/DoQ-capable DNS client. Plaintext
HTTP is not served on DoH ports. Credentials are never logged.

## DNS behavior

The parser accepts exactly one uncompressed IN-class question plus an optional
EDNS OPT record. Response decoding supports compressed names and all DNS
sections through Hickory. Packet bounds, full consumption, header flags,
question class/type, compression validity, and record counts are checked.
Unparseable queries receive bounded FORMERR when a header is available. Short
packets and incoming responses are dropped to prevent response loops.

UDP replies respect the advertised payload and Lumen's 1232-byte ceiling; without
EDNS they respect 512 bytes. Truncated replies set TC so clients can retry over
TCP. Stream responses respect the configured message bound. RD=0 requests do
not trigger recursive network work. Zone transfers and dynamic updates are not
served. DNSSEC AD is derived from local validation, not trusted from upstream.
The CD flag follows Hickory's DNSSEC behavior; operators can explicitly disable
validation only through startup configuration.

Hickory owns recursion, referral/bailiwick checks, query/source-port randomness,
QNAME minimization, nameserver selection, TCP fallback, cache TTLs, DNSSEC chain
validation, and authenticated denial. Lumen owns mode selection, trust material,
client access, wire admission, task/connection budgets, deadlines, and metrics.
NSEC3 soft/hard iteration ceilings are 100/500 in recursive mode.

## Root hints and trust anchors

The binary bundles [`data/root.hints`](../crates/lumen-resolver/data/root.hints)
from [InterNIC](https://www.internic.net/domain/named.root), fetched on
2026-10-29. Both IPv4 and IPv6 roots are present. Hickory 0.26.3 bundles the
20326 and 38696 root DNSKEYs. No DNS or trust files are downloaded at startup.

For an operator override, obtain hints or DNSKEY trust anchors through a trusted
channel. Check the new keys against the
[IANA root trust anchor publication](https://www.iana.org/dnssec/files), retain
current keys during rollover, place the new file beside the existing file, run
`--check` against a candidate config, atomically replace it, and restart Lumen.
Keep the previous trusted file/config for rollback. DNSSEC needs a correct host
clock. A wrong anchor fails validation; there is no automatic insecure fallback.

Automatic RFC 5011 key rollover and certificate automation are not implemented.
Keep bundled dependencies and operator trust material current. Custom hints and
anchors are local administrator trust decisions, not remote client input.

## Metrics and health

When `metrics` is set to a loopback address, HTTP `/metrics` provides Prometheus
text and `/healthz` provides `ok`. Health reports process liveness, not public
DNS reachability or a DNSSEC guarantee. No management operations are exposed.

| Metric | Type |
| --- | --- |
| `lumen_dns_queries_total` | counter |
| `lumen_dns_responses_total` | counter |
| `lumen_dns_malformed_total` | counter |
| `lumen_dns_refused_total` | counter |
| `lumen_dns_timeouts_total` | counter |
| `lumen_dns_failures_total` | counter |
| `lumen_dns_active_queries` | gauge |
| `lumen_dns_transport_queries_total{transport}` | counter |
| `lumen_dns_query_duration_seconds` | histogram |
| `lumen_dns_fallback_attempts_total` | counter |
| `lumen_dns_fallback_successes_total` | counter |
| `lumen_dns_fallback_failures_total` | counter |
| `lumen_dns_fallback_trigger_recursion_timeout_total` | counter |
| `lumen_dns_recursive_lookup_duration_seconds` | histogram |
| `lumen_dns_recursive_coalesced_total` | counter |
| `lumen_dns_recursive_hedged_total` | counter |
| `lumen_dns_warm_queries_total` | counter |
| `lumen_dns_warm_failures_total` | counter |
| `lumen_dns_prefetch_refreshes_total` | counter |
| `lumen_dns_prefetch_failures_total` | counter |
| `lumen_dns_prefetch_skipped_total` | counter |

The recursive lookup histogram has 11 fixed buckets (1 ms to 5 s) and includes
cache hits, so the sub-millisecond bucket approximates the cache hit ratio.
These have no client/domain labels. Query names and history are not stored or
logged. Transport totals and query latency use fixed-cardinality series. Full
query logs remain disabled. A ready Grafana dashboard is under
`deploy/observability/`. See
[configuration](configuration.md) for admission/drop semantics.

## Shutdown and failure

Ctrl-C and, on Unix, SIGTERM stop listeners and cancel outstanding work. Restart
loads config and trust material again; in-memory caches start empty. Background
listener failures terminate the daemon with an error. Individual malformed
clients or failed response writes do not terminate healthy listeners.

Library details: [Hickory 0.26.3 server](https://docs.rs/hickory-server/0.26.3/),
[Hickory source](https://github.com/hickory-dns/hickory-dns). Lumen remains a
pre-release resolver; independent security review and extended interoperability
and soak testing remain release gates.

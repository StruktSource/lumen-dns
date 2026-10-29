# Resolver operations

Phase 1 provides DNS transport, iterative recursion, forwarding, caches, local
DNSSEC validation, admission control, and aggregate metrics. Filtering, storage,
management API access, and a functional UI are not implemented yet.

## Start and query

```sh
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/lumen.toml
dig @127.0.0.1 -p 5353 example.com A
dig @::1 -p 5353 example.com AAAA +tcp
dig @127.0.0.1 -p 5353 example.com A +dnssec
```

Use `config/forward.toml` for explicit encrypted forwarding. The same cache and
resolver are shared across client transports. Only one mode runs at a time.

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

These have no client/domain labels. Query names and history are not stored or
logged. Full query logs, cache-hit metrics, latency histograms, and Grafana
panels remain later observability work. See
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

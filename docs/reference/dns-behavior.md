# DNS behavior

The precise rules Lumen follows when it receives, answers, and limits DNS traffic. Most people never need this page. It is here for operators debugging an unusual client and for contributors.

For the concepts, see [Concepts](../getting-started/concepts.md). For choosing how answers are found, see [Resolver modes](../guides/resolver-modes.md).

## What Lumen accepts

- Exactly **one** uncompressed IN-class question, plus an optional EDNS OPT record.
- Packet bounds, full consumption, header flags, question class and type, compression validity, and record counts are all checked.
- Unparseable queries get a bounded `FORMERR` when a header is available. Short packets and incoming responses are **dropped**, which prevents response loops.
- Zone transfers and dynamic updates are not served.
- `RD=0` requests do not trigger recursive network work.

## What Lumen answers

| Topic | Behavior |
| :--- | :--- |
| **UDP size** | Replies respect the advertised EDNS payload and Lumen's 1232-byte ceiling. Without EDNS, 512 bytes. Truncated replies set `TC` so clients retry over TCP |
| **Streams** | TCP, TLS, and HTTP responses respect the configured `max_message_bytes` |
| **Response codes** | Resolver timeout or failure gives `SERVFAIL`. A full resolver budget gives `REFUSED`. Blocked names get the [configured block action](../guides/filtering.md#what-blocked-clients-see) |
| **DNSSEC `AD` flag** | Set from Lumen's **own** validation, never trusted from an upstream |
| **`CD` flag** | Follows Hickory's DNSSEC behavior. Validation can only be disabled in startup configuration |
| **Answer case** | Upstream queries use random case (0x20) for anti-spoofing, but owner names in answers are lowercased before they reach the client. Authority and additional sections are left untouched because validation proofs compare them exactly |

## Who does what

| Hickory DNS owns | Lumen owns |
| :--- | :--- |
| Recursion, referral and bailiwick checks, query and source-port randomness, QNAME minimization, nameserver selection, TCP fallback, cache TTLs, DNSSEC chain validation, authenticated denial of existence | Mode selection, trust material, client access, wire admission, task and connection budgets, deadlines, filtering, and metrics |

NSEC3 iteration ceilings (soft and hard) are 100 and 500 in recursive mode.

## Encrypted transports

Protocol details for DoT, DoH, and DoQ are in [Encrypted DNS](../guides/encrypted-dns.md).

## Health, metrics, and shutdown

- `/metrics` and `/healthz` are described in [Monitoring](../guides/monitoring.md).
- **Shutdown:** Ctrl-C and, on Unix, `SIGTERM` stop listeners and cancel outstanding work. A restart reloads config and trust material, and in-memory caches start empty.
- **Failures:** a background listener failure terminates the daemon with an error. Individual malformed clients or failed response writes do not affect healthy listeners.

## Libraries

Lumen is built on [Hickory DNS](https://github.com/hickory-dns/hickory-dns) 0.26.3 ([server documentation](https://docs.rs/hickory-server/0.26.3/)). Hickory's recursive resolver is still labelled experimental upstream, which is one reason independent security review, broader interoperability testing, and soak testing are release gates. See the [roadmap](../project/roadmap.md).

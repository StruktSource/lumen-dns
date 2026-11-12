# Resolver modes

Lumen can find DNS answers in two ways, and runs exactly one at a time. This guide helps you choose, and explains the optional fallback and speed features.

If the terms are new, read [Concepts](../getting-started/concepts.md#recursive-or-forwarding) first.

## Recursive mode (default)

Lumen walks the DNS tree itself: root servers, then the top-level domain, then the domain's own servers. No outside provider is involved, and answers are validated locally with DNSSEC.

```toml
[resolver]
mode = "recursive"
dnssec = true
```

**Good for:** independence and privacy from any single provider.
**Trade-offs:** the first lookup of an uncached name is slower, and you need outbound UDP/TCP port 53 to the internet. The servers along the path still see parts of your lookups, in plain text.

Recursive mode never switches to a public provider on its own.

## Forwarding mode

Lumen sends each question to one or more resolvers you choose, ideally over an encrypted connection. Answers are still validated locally with DNSSEC.

```toml
[resolver]
mode = "forward"
dnssec = true

[[resolver.providers]]
id = "cloudflare-unfiltered"
protocol = "auto"
encryption = "required"
address_family = "ipv4"
transport_priority = ["quic", "https", "tls"]
```

`config/forward.example.toml` is a ready-made example.

> [!WARNING]
> Running a forwarding configuration sends your queries to the chosen provider. The default configuration never does this. Read the provider's privacy policy first.

You can pick a provider from the [bundled catalog](upstream-providers.md) or define your own upstreams:

```toml
[[resolver.upstreams]]
address = "1.1.1.1:853"
protocol = "tls"
server_name = "cloudflare-dns.com"
```

Rules for upstreams:

- The address is a fixed IP and port. Lumen does no bootstrap lookup to find it.
- Encrypted protocols (`tls`, `https`, `quic`) require `server_name`, and Lumen always verifies the certificate chain and name. A private CA bundle (`upstream_ca`) changes which roots are trusted but never skips name checks.
- `udp` also enables TCP fallback to the same address and port.
- You can use up to 8 bundled providers and up to 8 custom upstreams, and choose how they are used. See [Upstream providers](upstream-providers.md#use-several-providers).

Full field list: [Configuration: resolver](../reference/configuration.md#resolver).

### Encrypted transport failover

With `protocol = "auto"`, Lumen builds an encrypted-only list for a provider, in the order you set (default: QUIC, then HTTPS, then TLS). It moves to the next transport **only** after a connection, transport, or timeout error. An upstream SERVFAIL can move to the next configured provider, but a usable DNS answer (including NXDOMAIN) or local DNSSEC failure is final. It never falls back to plain text. Each automatic transport gets the remaining provider budget divided by the number of transports left; early failures donate unused time to later transports. All tiers share one provider deadline, including silent handshakes and DNSSEC work. The outer client deadline still applies.

## Which should I choose?

| If you… | Choose |
| :--- | :--- |
| want no outside provider and accept slower first lookups | Recursive |
| trust a specific provider and want fast, simple lookups | Forwarding |
| are on a network that blocks or throttles direct DNS | Forwarding |
| want recursion but a safety net for slow moments | Recursive with [timeout fallback](#optional-timeout-fallback) |

## Optional timeout fallback

In recursive mode you can allow **one** carefully limited fallback to a provider when recursion times out. It is off by default and contacts nothing until you enable it with at least one upstream.

```toml
[resolver.fallback]
enabled = true
recursive_timeout_ms = 7000
timeout_ms = 2000
attempts = 1

[[resolver.fallback.upstreams]]
address = "1.1.1.1:853"
protocol = "tls"
server_name = "cloudflare-dns.com"
```

How a query is decided:

1. Filtering runs first.
2. Lumen checks the cache and performs iterative resolution.
3. An answer, NXDOMAIN, NODATA, DNSSEC failure, generic SERVFAIL, policy block, rate refusal, or any non-timeout network error **ends** the decision.
4. Only an identified recursive **timeout** starts a single, bounded fallback lookup.
5. The fallback answer is validated with the same DNSSEC and trust settings.

Things to know:

- `recursive_timeout_ms + timeout_ms` must fit inside `limits.query_timeout_ms`. The fallback is cancelled when its budget ends.
- Fallback upstreams follow the same rules as forwarding upstreams, and Lumen rejects any endpoint that matches one of its own listeners.
- Addresses reached through NAT, split networks, or port forwarding can still loop back to Lumen. Check the network path yourself before enabling them.
- **Privacy:** an enabled fallback tells the chosen operator about the queries that timed out during recursion.

## Speed features (recursive mode)

Several bounded mechanisms make uncached lookups faster without weakening DNSSEC, TTLs, or filtering:

| Feature | Default | What it does |
| :--- | :--- | :--- |
| **Shared recursion** | Always on | Identical in-flight queries (same name, type, and DNSSEC flag) wait for one recursion instead of each walking the tree. At most 4096 groups at once. |
| **Startup priming** (`[resolver.warm]`) | Off in code, **on** in the shipped configs | After listeners are bound, fetches delegations and keys for the root and a list of common zones once, two at a time. It queries only the zone names you list, never client data. |
| **Expiry refresh** (`[resolver.prefetch]`) | Off | Re-resolves names that were requested repeatedly, just after their answer expires, within concurrency and per-minute limits. |
| **Serve stale** (`[resolver.serve_stale]`) | Off | Returns an eligible expired unsigned answer at once and starts one background refresh. |
| **Persistent response cache** (`[resolver.persistent_cache]`) | Off | Saves bounded response data across restarts in a separate local SQLite file. Works in both resolver modes. |
| **Hedged recursion** (`hedge_ms`) | Off | Starts one extra recursion for a lookup that is still unanswered after the delay. The first usable answer wins. |

The numbers behind these are in [Performance](../project/performance.md): shared recursion clearly helped bursts of identical queries, while the single cold-query gain and hedging were **not** statistically significant, so hedging is not recommended.

How expiry refresh stays safe:

- Names are tracked in memory only, never logged, exported, or saved. They are forgotten after an hour without a lookup.
- Nothing is refreshed before its authoritative TTL has elapsed, so answers are never served longer than allowed. Answers with a TTL under 10 seconds are not refreshed.
- Filtering runs before refresh, and every filter refresh or rollback clears all pending refresh candidates, so a newly blocked name is never refreshed under the old policy.

Serve-stale and persistence use a second Lumen-owned response cache because Hickory keeps its caches private. Both are off by default. Stale replies keep their own age bound and small response TTL, never include expired DNSSEC-authenticated data, and trigger one background refresh without making the client wait. Persistence stores names and answers, so enable it only when local disk disclosure is acceptable. It never stores the client that asked. See the [cache configuration](../reference/configuration.md#caches).

## Related

- [Upstream providers](upstream-providers.md)
- [DNSSEC and trust anchors](../reference/dnssec-and-trust.md)
- [Configuration reference](../reference/configuration.md#resolver)

## Cold recursion and local names

Cold validating recursion can require delegation, DS/DNSKEY, denial and CNAME walks.
A quick direct provider reply does not measure this work. Startup warming and shared
recursion still do not remove slow authorities or DNSSEC work.

Lumen now caps each full recursive walk with `upstream_timeout_ms` and retries only a
timeout, up to `attempts`. Hickory keeps completed cache work between walks. A usable DNS
answer, authenticated negative answer, or DNSSEC failure is final. The extra SOA/NS scan used
to recover a proven unsigned ancestor has one shared attempt-sized budget, rather than one
unbounded wait per ancestor. The outer query deadline remains the final cap. This is a bounded
failure-recovery change, not a claim that public cold-query speed is now proven.

Set `diagnostics = true` for aggregate recursive-attempt timing and outcome metrics. They have
fixed labels and contain no query names, authority IPs, or client data. Hickory does not expose
safe per-authority timing through its stable recursor API, so Lumen does not turn on Hickory's
verbose trace events, which can include DNS names, addresses, and response data.

With `local_zones = true` (the default), Lumen answers the IANA locally-served reverse zones
under [RFC 6303](https://www.rfc-editor.org/rfc/rfc6303.html) and RFC 7793. It also handles
[`home.arpa`](https://www.rfc-editor.org/rfc/rfc8375.html),
[`resolver.arpa`](https://www.rfc-editor.org/rfc/rfc9462.html), and `service.arpa` locally.
Apple DNS-SD queries inside private reverse zones therefore fail fast with a correct local
negative answer. `.local` never goes to public DNS, but Lumen is not an mDNS bridge. Public
reverse zones and `ipv4only.arpa` still recurse normally. Disable `local_zones` only when a
separate local authority or conditional DNS path owns these names.

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
- You can use up to 8 endpoints in total across presets and custom upstreams.

Full field list: [Configuration: resolver](../reference/configuration.md#resolver).

### Encrypted transport failover

With `protocol = "auto"`, Lumen builds an encrypted-only list for a provider, in the order you set (default: QUIC, then HTTPS, then TLS). It moves to the next transport **only** after a connection, transport, or timeout error. It never fails over because of a DNS answer (including NXDOMAIN or SERVFAIL) or a DNSSEC failure, and it never falls back to plain text.

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
| **Hedged recursion** (`hedge_ms`) | Off | Starts one extra recursion for a lookup that is still unanswered after the delay. The first usable answer wins. |

The numbers behind these are in [Performance](../project/performance.md): shared recursion clearly helped bursts of identical queries, while the single cold-query gain and hedging were **not** statistically significant, so hedging is not recommended.

How expiry refresh stays safe:

- Names are tracked in memory only, never logged, exported, or saved. They are forgotten after an hour without a lookup.
- Nothing is refreshed before its authoritative TTL has elapsed, so answers are never served longer than allowed. Answers with a TTL under 10 seconds are not refreshed.
- Filtering runs before refresh, and every filter refresh or rollback clears all pending refresh candidates, so a newly blocked name is never refreshed under the old policy.

**Evaluated and not built:** serve-stale answers (RFC 8767) and saving delegations across restarts. Hickory drops expired entries and keeps its caches private, so both would need a second Lumen-owned cache with its own expiry, revalidation, and memory bounds. Priming recovers most of the restart cost without that.

## Related

- [Upstream providers](upstream-providers.md)
- [DNSSEC and trust anchors](../reference/dnssec-and-trust.md)
- [Configuration reference](../reference/configuration.md#resolver)

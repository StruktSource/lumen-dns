# DNSSEC and trust anchors

How Lumen proves answers are genuine, the one DNSSEC edge case it works around, and how to update the keys it trusts.

New to DNSSEC? Start with [Concepts](../getting-started/concepts.md#dnssec).

## How validation works

DNSSEC validation is **on by default** in both modes (`resolver.dnssec = true`). Lumen checks signatures itself using [Hickory DNS](https://github.com/hickory-dns/hickory-dns), and does not implement custom DNSSEC cryptography.

- The `AD` ("authenticated data") flag in a reply comes from **Lumen's own validation**, never from an upstream's claim.
- Signed denial of existence (NXDOMAIN and NODATA proofs) is verified.
- Data from **unsigned** zones can legitimately validate as *insecure*. DNSSEC proves authenticity of signed data, not the honesty of an upstream or the privacy of plain-text DNS.
- A wrong or missing trust anchor fails validation. **There is no automatic insecure fallback.**
- DNSSEC needs a **correct system clock**, because signatures have validity windows.

## Edge case: parent and child on the same servers

Some operators serve a parent zone and its child from the same name servers (for example `google.com` and `l.google.com`, behind `safebrowsing.google.com`). A DS question about the child then comes back from the child, carrying the child's own SOA. The stock validator tried to prove that SOA through the very DS record being asked for, looped until its depth limit, and failed unrelated validations. `safebrowsing.google.com` and, in about half of fresh processes, `google.com` returned `SERVFAIL`.

Lumen's fix has three layers:

1. **A vendored patch.** Lumen carries a copy of `hickory-net` with a one-line change (see [`vendor/README.md`](../../vendor/README.md)). Such an SOA is no longer validated through itself, and the delegation is judged from the parent side, as unbound does. The patch should be removed once an upstream release contains the fix (see the [roadmap](../project/roadmap.md#upstream-follow-up)).
2. **A safety net.** If validation still fails for a name and an ancestor was proven *insecure* (an unsigned delegation proven by its parent), the lookup is repeated once without validation. Signed or bogus chains still return `SERVFAIL`. `dnssec-failed.org` and `sigfail.verteiltesysteme.net` are the regression checks.
3. **The same safety net in forward mode.** In forward mode the providers' answers are validated locally too, and the same family of zones used to return `SERVFAIL` there (Issue #35: `clients4.google.com`, `clients.l.google.com`). After a DNSSEC failure Lumen now walks the name's ancestors from the top-level domain down with validating lookups. The first ancestor that validates as *insecure* means nothing below it can be secure, so the lookup is repeated once through a second, small forwarder without validation, over the same upstreams and TLS settings, and the answer is returned **without** the authenticated-data flag. A *secure* ancestor sends the walk one level down. A *bogus* or unanswered ancestor ends it, and the `SERVFAIL` stands, as it does for a signed zone with a bad signature. The walk and the retry share one `upstream_timeout_ms` budget and are cancelled with the query. A usable answer (including `NXDOMAIN`) from a provider is never asked of another one. `lumen_dns_forward_insecure_recoveries_total` (with `resolver.diagnostics`) counts how often this ran.

   Tested with a local signed root, an unsigned `google.` below it, and a child zone on the same server whose DS answer comes back either with only the child's SOA or with an empty authority section. Not tested: the public `google.com`, whose behavior may differ by provider and over time.

## Root hints and trust anchors

| Material | Where it comes from |
| :--- | :--- |
| **Root hints** | Bundled in the binary from [InterNIC](https://www.internic.net/domain/named.root), fetched 2026-10-29, covering IPv4 and IPv6 roots ([`data/root.hints`](../../crates/lumen-resolver/data/root.hints)) |
| **Trust anchors** | Hickory 0.26.3 bundles the root DNSKEYs with key tags 20326 and 38696 |

Nothing is downloaded at startup. Custom hints and anchors are **local administrator trust decisions**, not remote client input.

### Update them safely

Use this only if you must override the bundled material.

1. Obtain new hints or DNSKEY trust anchors through a **trusted channel**.
2. Check the keys against the [IANA root trust anchor publication](https://www.iana.org/dnssec/files). Keep current keys during a rollover.
3. Put the new file beside the existing one and point a **candidate** config at it.
4. Run `lumen --config CANDIDATE --check`.
5. Atomically replace the file and restart Lumen.
6. Keep the previous file and config for rollback.

```toml
[resolver]
root_hints = "dns/root.hints"      # BIND format, 64 KiB, 1 to 64 IP records
trust_anchor = "dns/root.keys"     # DNSKEY format, 64 KiB, at least one key
```

## Automatic rollover (RFC 5011)

Set `trust_anchor_state` and Lumen follows root key rollovers by itself. It is **off by default**.

```toml
[resolver]
trust_anchor_state = "dns/anchors.state"   # created on first start, mode 0600
```

How it works:

- On first start the state file is seeded from `trust_anchor` (or the built-in root keys). Later starts read the file instead, so the file is the source of truth. Delete it to start over.
- Lumen asks for the root DNSKEY set one minute after start and then once a day. A set counts only if a key you already trust signed it and the signature is valid right now.
- A **new key** is trusted only after it has been visible for 30 days without a gap. A **revoked key** stops being trusted at once, is kept 30 days, and is never trusted again. A key that goes missing stays trusted. An answer that fails validation changes nothing, and neither does an empty one.
- The REVOKE flag only counts if the revoked key signed the set itself, so a forged flag cannot remove a key.
- The resolvers load their anchors at start. Changes are saved at once but **applied at the next restart or reload**. The gauge `lumen_dns_trust_anchor_restart_pending` is `1` while a restart is due, and Lumen logs `trust anchors changed under RFC 5011`. Restart within the 30 days before an old key is retired. A server that is off for longer than the whole rollover window must be re-seeded by hand.
- It needs DNSSEC validation. Back up the state file with the config. It holds public keys only.
- Tested with real signatures and a simulated rollover. It has **not** been run across a real root KSK rollover.

## Related

- [Resolver modes](../guides/resolver-modes.md)
- [Configuration: resolver](configuration.md#resolver)
- [Threat model](../design/threat-model.md)

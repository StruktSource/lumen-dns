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

Lumen's fix has two layers:

1. **A vendored patch.** Lumen carries a copy of `hickory-net` with a one-line change (see [`vendor/README.md`](../../vendor/README.md)). Such an SOA is no longer validated through itself, and the delegation is judged from the parent side, as unbound does. The patch should be removed once an upstream release contains the fix (see the [roadmap](../project/roadmap.md#upstream-follow-up)).
2. **A safety net.** If validation still fails for a name and an ancestor was proven *insecure* (an unsigned delegation proven by its parent), the lookup is repeated once without validation. Signed or bogus chains still return `SERVFAIL`. `dnssec-failed.org` and `sigfail.verteiltesysteme.net` are the regression checks.

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

> [!NOTE]
> Automatic RFC 5011 key rollover is **not implemented**. Keep Lumen and its bundled dependencies current so the built-in anchors stay up to date. See the [roadmap](../project/roadmap.md).

## Related

- [Resolver modes](../guides/resolver-modes.md)
- [Configuration: resolver](configuration.md#resolver)
- [Threat model](../design/threat-model.md)

# Lumen 0.7.0

Lumen 0.7.0 adds optional stale answers, an optional persistent cache, and stronger filtering. All new features are off by default.

## Highlights

- **Serve-stale (RFC 8767).** Enable `[resolver.serve_stale]` to keep answering from an expired entry (up to a bounded age) while one background refresh runs. Expired DNSSEC-authenticated data is never served.
- **Persistent DNS cache.** Enable `[resolver.persistent_cache]` to keep bounded responses across restarts in a separate SQLite file. It holds queried names and answers, never clients. Exclude it from backups.
- **Regex rules, CNAME blocking, SafeSearch.** `regex_allow`/`regex_block` rules, filtering of CNAME targets in upstream answers, and per-profile `safe_search` for Google, Bing, and YouTube.

## Not in this release

Authoritative zones, split-horizon DNS, dynamic updates, zone transfers, zone signing, DoH over HTTP/3, DNSCrypt, and native ECH remain on the roadmap.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.7.0-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- No state-database schema change. Config schema 1 stays compatible; the new tables are optional.

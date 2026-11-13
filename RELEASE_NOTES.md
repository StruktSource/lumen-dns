# Lumen 0.7.0

Lumen 0.7.0 adds optional stale answers, a persistent cache, stronger filtering, two new encrypted transports, and your own DNS zones. All new features are off by default.

## Highlights

- **Serve-stale (RFC 8767).** Enable `[resolver.serve_stale]` to keep answering from an expired entry (up to a bounded age) while one background refresh runs. Expired DNSSEC-authenticated data is never served.
- **Persistent DNS cache.** Enable `[resolver.persistent_cache]` to keep bounded responses across restarts in a separate SQLite file. It holds queried names and answers, never clients. Exclude it from backups.
- **Regex rules, CNAME blocking, SafeSearch.** `regex_allow`/`regex_block` rules, filtering of CNAME targets in upstream answers, and per-profile `safe_search` for Google, Bing, and YouTube.

- **DoH over HTTP/3 and DNSCrypt v2.** `listen.doh3` serves `/dns-query` over QUIC. `[dnscrypt]` serves encrypted queries over UDP and TCP with rotating signed certificates.
- **Your own DNS zones.** `[[zones]]` serves records from zone files, with split-horizon `views` and `[[forwarders]]` for conditional forwarding. See [Your own DNS zones](docs/guides/authoritative-dns.md).
- **Dynamic updates and zone transfers.** TSIG-signed RFC 2136 updates scoped per key to names and types, saved to a SQLite journal, and TSIG-protected AXFR/IXFR over TCP. Dynamic zones answer IXFR with the differences from their last 32 updates (kept in memory), and with the whole zone otherwise. Listed secondaries get a NOTIFY at startup and after each accepted update.
- **DNSSEC for your own zones and automatic root key rollover.** `[zones.dnssec]` signs a plain zone (Ed25519 or ECDSA P-256, NSEC), and `lumen --zone-key` creates the key and prints the `DS` record. `resolver.trust_anchor_state` follows RFC 5011 root key rollovers, applied at restart.
- **Automatic certificates (ACME).** `[acme]` gets and renews the encrypted-DNS certificate from Let's Encrypt or another ACME CA (HTTP-01 or DNS-01, including wildcards), with no restart on renewal.
- **DHCP server for IPv4 and IPv6 (off by default).** `[dhcp]` hands out addresses with reservations and bounded ranges, keeps leases in SQLite, and publishes every named lease as a DNS name, forward and reverse. Relay agents, prefix delegation, network boot options, and a hot-standby failover between two Lumen servers are included. The console gets an optional DHCP module. See [DHCP server](docs/guides/dhcp.md).
- **Certificate renewal without restart.** Renewed DoT, DoH, DoH3, and DoQ certificates are picked up within 30 seconds; a bad file keeps the old pair serving.

## Not in this release

Zone key rollover and NSEC3, TLS-ALPN-01 ACME challenges, native ECH, DNSCrypt upstreams, and Anonymized DNSCrypt. DNSCrypt has not been tested against a third-party client.

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

# Upstream provider presets

Lumen ships an offline provider catalog at
`config/providers/resolvers.toml`. No preset is selected by default, and the
release config stays in recursive mode. Forward mode can select a preset by its
stable ID:

```toml
[resolver]
mode = "forward"
dnssec = true

[[resolver.providers]]
id = "cloudflare-unfiltered"
protocol = "tls"
address_family = "ipv4"
```

`address_family` accepts `any`, `ipv4`, or `ipv6`. Multiple selections are
allowed when they expand to at most eight endpoints. Protocols are accepted only
when marked supported by the catalog. Presets cannot be mixed with custom
`[[resolver.upstreams]]` entries. Custom upstreams remain supported.

The catalog was checked against operator documentation on 2026-10-30. A catalog
entry is not a live-service, privacy, or availability guarantee. Operators can
change endpoints after that date. Check the linked operator page before a
production rollout.

## Included profiles

| Stable ID | Operator country | Jurisdiction | Network scope | Variant | ECS |
| --- | --- | --- | --- | --- | --- |
| `dns4eu-unfiltered` | CZ | EU | EU anycast | unfiltered | no |
| `ffmuc-unfiltered` | DE | EU | regional | unfiltered | no |
| `libredns-unfiltered` | GR | EU | regional | unfiltered | no |
| `dns-sb-unfiltered` | DE | EU | global anycast | unfiltered | no |
| `quad9-unfiltered` | CH | Europe, non-EU | global anycast | unfiltered | no |
| `uncensoreddns-anycast` | DK | EU | global anycast | uncensored | no |
| `dns-watch` | DE | EU | regional | uncensored | no |
| `cloudflare-unfiltered` | US | outside Europe | global anycast | unfiltered | no |
| `google-public-dns` | US | outside Europe | global anycast | unfiltered | yes |
| `adguard-unfiltered` | CY | EU | global anycast | unfiltered | no |
| `controld-unfiltered` | CA | outside Europe | global anycast | unfiltered | no |
| `controld-uncensored` | CA | outside Europe | global anycast | uncensored | no |

`unfiltered` and `uncensored` are kept as distinct operator profiles. They are
not treated as equal promises. Operator country and legal jurisdiction are also
separate from anycast network scope.

## Selection rules

`lumen_config::providers::Catalog::bundled()` validates the versioned catalog.
Call `select(stable_id, protocol, address_family)` to produce the same explicit
`Upstream` records used by the resolver. Expert tools can instead build custom
`Upstream` records. Selection fails for unknown profiles, unavailable protocols,
or missing address families.

Only a transport marked `supported` can be selected. `unsupported` means the
operator says it is unavailable. `not_documented` means the official page does
not claim it. `test_status = "not_tested"` means this release did not make a live
query to that public service. Offline tests use local fixtures.

Encrypted choices never fall back to plaintext. The catalog supplies a fixed IP,
port, TLS name, and full DoH path. Certificate and name checks stay enabled.
Control D secure transports use its documented secure-endpoint bootstrap IPs, so
the setup does not need DNS to find its DNS server.

## Official sources

- [DNS4EU](https://joindns4.eu/for-public)
- [Freifunk Munich](https://www.freifunk-muenchen.de/wiki/knb:dohdot)
- [LibreDNS](https://libredns.gr/)
- [DNS.SB](https://dns.sb/faq/)
- [Quad9](https://docs.quad9.net/services/)
- [UncensoredDNS](https://blog.uncensoreddns.org/)
- [DNS.WATCH](https://dns.watch/)
- [Cloudflare](https://developers.cloudflare.com/1.1.1.1/ip-addresses/)
- [Google Public DNS](https://developers.google.com/speed/public-dns/docs/using)
- [AdGuard DNS](https://adguard-dns.io/kb/general/dns-providers/)
- [Control D Free DNS](https://docs.controld.com/docs/free-dns)
- [Control D secure endpoint IPs](https://docs.controld.com/docs/control-d-ip-ranges)

Privacy-policy links, where supplied by the operator, live with each catalog
entry. They are operator statements, not Lumen endorsements.

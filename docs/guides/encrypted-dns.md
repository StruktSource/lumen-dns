# Encrypted DNS (DoT, DoH, DoH3, DoQ, DNSCrypt)

Plain DNS is readable by anyone on the path. Lumen can serve five encrypted forms so supported devices, browsers, and phones can talk to it privately. All of them are **off by default**.

> [!NOTE]
> This page is about the connections *clients make to Lumen*. For Lumen's own encrypted connections to a provider, see [Resolver modes](resolver-modes.md).

| Protocol | Transport | ALPN | Typical use |
| :--- | :--- | :--- | :--- |
| **DoT**: DNS over TLS | TCP | `dot` | Android "Private DNS", routers |
| **DoH**: DNS over HTTPS | TCP, HTTP/2 | `h2` | Browsers, apps |
| **DoH3**: DoH over HTTP/3 | UDP (QUIC) | `h3` | Browsers and apps that prefer HTTP/3 |
| **DoQ**: DNS over QUIC | UDP | `doq` | Newer clients |
| **DNSCrypt v2** | UDP and TCP | none (own protocol) | `dnscrypt-proxy` and other DNSCrypt clients |

DoT, DoH, DoH3, and DoQ use TLS 1.3 with no early data. [DNSCrypt](#dnscrypt) uses its own keys and is set up differently.

## What you need

1. **A TLS certificate and private key in PEM format**, issued for the name your clients will use (for example `dns.home.example`). Clients must trust it. Bring your own files, or let Lumen get them from an ACME CA with [automatic certificates](certificates.md).
2. **A name that clients can resolve** and that matches the certificate.
3. **File permissions** that let the Lumen service account read the key.

Size limits: certificate file 1 MiB, private key 64 KiB. Lumen checks that the key matches the certificate at startup. **Renewing a certificate needs no restart.** Lumen checks the two files every 30 seconds. When either changes, it loads the new pair, verifies that the certificate and key match, and only then starts serving it, on every encrypted listener (DoT, DoH, DoH3, DoQ) for new connections. If the new files are half-written, unreadable, or do not match, the previous certificate keeps serving and the failure is counted (`lumen_dns_certificate_reload_failures_total`); fixing the files is picked up on the next check. Any tool that writes PEM files works, such as certbot, acme.sh, or lego. Lumen does not obtain certificates itself, and the web console's own HTTPS certificate (`[web]`) still needs a restart after renewal.

Watch for expiry with the `lumen_dns_certificate_not_after_timestamp_seconds` metric, for example alerting when `lumen_dns_certificate_not_after_timestamp_seconds - time() < 14 * 86400`.

## Turn it on

Set the certificate paths and replace the empty listener arrays with the addresses you want:

```toml
[listen]
dot = ["0.0.0.0:8853", "[::]:8853"]
doh = ["0.0.0.0:8443", "[::]:8443"]
doh3 = ["0.0.0.0:8443", "[::]:8443"]
doq = ["0.0.0.0:8853", "[::]:8853"]
certificate = "tls/cert.pem"
private_key = "tls/key.pem"
allow_clients = ["127.0.0.0/8", "::1/128", "192.168.1.0/24"]
```

Notes:

- 8853 (DoT over TCP and DoQ over UDP) and 8443 (DoH over TCP, DoH3 over UDP) are development ports. Standard ports are 853 for DoT and DoQ, and 443 for DoH.
- DoT and DoQ may share a port because they use different transports. DoH (TCP) and DoH3 (UDP) may share one too, which is how browsers expect HTTP/3 to be found. Within one transport, duplicate ports are invalid.
- Relative paths resolve beside the config file, not the working directory.
- **The same `allow_clients` list applies.** Encrypted listeners do not bypass access control.
- Always validate first with `lumen --config FILE --check`.

## How each protocol behaves

**DoT**

- Two-byte length prefix per DNS message.
- Several queries can share one connection.

**DoH3** (DNS over HTTP/3)

- Same `/dns-query` path, methods, media type, status codes, and size limits as DoH, carried over QUIC with ALPN `h3`.
- Uses the same certificate and `allow_clients` list as every other encrypted listener. Eight concurrent requests per connection, and idle or oversized requests are cut off like DoH.
- Lumen does **not** advertise HTTP/3 with `Alt-Svc` or an HTTPS record by itself. Clients need the DoH3 address directly (for example in a DoH template such as `https://dns.home.example/dns-query` with a client that prefers HTTP/3), or you can publish an `HTTPS` record for the name.
- This is the DNS listener. The web console's HTTP/3 reverse-proxy path is unrelated.

**DoH**

- HTTP/2 only, at the path `/dns-query`. Plain HTTP is never served on DoH ports.
- `GET` carries the query in the `dns` parameter as base64url without padding.
- `POST` requires `Content-Type: application/dns-message`.
- Replies use that media type and `Cache-Control: no-store`.
- Wrong path returns 404, wrong method 405, wrong media type 415, a malformed payload 400, and an oversized body 413.

**DoQ**

- One length-prefixed message per bidirectional stream, finished with a FIN.
- DNS message IDs must be zero. Invalid framing or IDs close the connection with a DoQ protocol error.

Both DoH and DoQ allow at most eight concurrent streams per connection.

## Test it

```sh
# DoT (with kdig from knot-dnsutils)
kdig @192.168.1.2 -p 8853 +tls +tls-host=dns.home.example example.com

# DoH (with curl and a query built by your tooling)
curl --http2 -H 'accept: application/dns-message' \
  'https://dns.home.example:8443/dns-query?dns=<base64url-query>'
```

Use a DoH client with HTTP/2 support, or a DoT or DoQ capable client. Credentials and keys are never logged.

## Troubleshooting

| Symptom | Check |
| :--- | :--- |
| `--check` fails on TLS | The key does not match the certificate, a path is wrong, or a file exceeds its size limit. |
| Clients report a certificate error | The certificate name does not match the name clients use, or the issuing CA is not trusted on the client. |
| No response from a remote client | The client is outside `allow_clients`, or the firewall blocks the port (open TCP for DoT and DoH, UDP for DoQ). |
| Works locally only | The listener address is loopback. Bind a LAN address and allow the client range. |

## Related

- [Serve your network](serve-your-network.md)
- [Configuration: listeners](../reference/configuration.md#listeners)
- [DNS behavior](../reference/dns-behavior.md)

## DNSCrypt

DNSCrypt v2 is a separate, older encrypted protocol with its own keys. It needs **no TLS certificate**, so it suits clients such as `dnscrypt-proxy` and some routers. It is off by default.

```toml
[dnscrypt]
enabled = true
listen = ["0.0.0.0:5443", "[::]:5443"]
provider_name = "2.dnscrypt-cert.dns.home.example"
key_file = "dnscrypt-provider.key"
cert_hours = 24
```

- `provider_name` must start with `2.dnscrypt-cert.` followed by a name you control, as the specification requires. Clients ask for the certificate under this name.
- `key_file` holds the long-term Ed25519 provider key (64 hex characters). If the file does not exist, Lumen creates it with mode `0600` on first start. **Back it up and keep it private**: clients pin its public half, so replacing it means every client must update its stamp.
- Short-lived resolver keys and signed certificates are generated in memory and replaced every `cert_hours / 2` (2 to 168 hours, default 24). Two suites are offered side by side: `X25519-XChaCha20Poly1305` and `X25519-XSalsa20Poly1305`. Clients choose; Lumen cannot be downgraded to plain DNS.
- Each listener answers on **both UDP and TCP** on the same port. Over UDP, a reply larger than the query is replaced by a truncated reply, so the client retries over TCP and Lumen cannot be used to amplify traffic.
- Only a TXT query for the exact `provider_name` gets a plain answer (the certificate). Everything else that is not an authenticated encrypted query is dropped without a reply.
- Queries pass through the same `allow_clients` check, filtering, cache, resolver, and limits as every other transport.
- At startup Lumen logs the provider public key and a `sdns://` stamp for each listener. The stamp sets no privacy properties, because Lumen cannot promise what your resolver or upstream does with queries. Paste it into `dnscrypt-proxy` or another client. Replace a wildcard address in the stamp with your host name.

Not supported yet: Anonymized DNSCrypt relaying, DNSCrypt as an **upstream** transport (Lumen's own provider connections still use DoQ, DoH, and DoT only), and protocol-level replay caches. The encrypted-only provider policy is unchanged, and DNSCrypt adds no plaintext fallback.

# Encrypted DNS (DoT, DoH, DoQ)

Plain DNS is readable by anyone on the path. Lumen can serve three encrypted forms so supported devices, browsers, and phones can talk to it privately. All of them are **off by default**.

> [!NOTE]
> This page is about the connections *clients make to Lumen*. For Lumen's own encrypted connections to a provider, see [Resolver modes](resolver-modes.md).

| Protocol | Transport | ALPN | Typical use |
| :--- | :--- | :--- | :--- |
| **DoT**: DNS over TLS | TCP | `dot` | Android "Private DNS", routers |
| **DoH**: DNS over HTTPS | TCP, HTTP/2 | `h2` | Browsers, apps |
| **DoQ**: DNS over QUIC | UDP | `doq` | Newer clients |

All three use TLS 1.3 with no early data.

## What you need

1. **A TLS certificate and private key in PEM format**, issued for the name your clients will use (for example `dns.home.example`). Clients must trust it. Lumen does **not** create, download, or renew certificates.
2. **A name that clients can resolve** and that matches the certificate.
3. **File permissions** that let the Lumen service account read the key.

Size limits: certificate file 1 MiB, private key 64 KiB. Lumen checks that the key matches the certificate at startup. Rotating a certificate means replacing the files and restarting Lumen.

## Turn it on

Set the certificate paths and replace the empty listener arrays with the addresses you want:

```toml
[listen]
dot = ["0.0.0.0:8853", "[::]:8853"]
doh = ["0.0.0.0:8443", "[::]:8443"]
doq = ["0.0.0.0:8853", "[::]:8853"]
certificate = "tls/cert.pem"
private_key = "tls/key.pem"
allow_clients = ["127.0.0.0/8", "::1/128", "192.168.1.0/24"]
```

Notes:

- 8853 (DoT over TCP and DoQ over UDP) and 8443 (DoH over TCP) are development ports. Standard ports are 853 for DoT and DoQ, and 443 for DoH.
- DoT and DoQ may share a port because they use different transports. Within one transport, duplicate ports are invalid.
- Relative paths resolve beside the config file, not the working directory.
- **The same `allow_clients` list applies.** Encrypted listeners do not bypass access control.
- Always validate first with `lumen --config FILE --check`.

## How each protocol behaves

**DoT**

- Two-byte length prefix per DNS message.
- Several queries can share one connection.

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

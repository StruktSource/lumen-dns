# Web UI hosting

Lumen embeds the blank UI shell in the daemon binary. Requests do not read the
filesystem, scan directories, resolve paths, render templates, or allocate an
asset cache. Only `/`, `/index.html`, and `/healthz` exist. Other paths return
404; methods other than GET and HEAD return 405.

The shell has no UI authentication. It contains no management data and cannot
bypass the separately authenticated `/v1` management API. Current content stays
the existing title and foundation text; no UI design is part of this slice.

## Direct listeners

The release config enables loopback HTTP on port 8080:

```toml
[web]
http = ["127.0.0.1:8080", "[::1]:8080"]
https = []
max_connections = 64
```

Plain listeners support HTTP/1.1 and HTTP/2 prior knowledge. Direct HTTPS uses
TLS 1.3 with HTTP/2 and HTTP/1.1 ALPN:

```toml
[web]
http = []
https = ["127.0.0.1:8443", "[::1]:8443"]
certificate = "tls/web-cert.pem"
private_key = "tls/web-key.pem"
max_connections = 64
```

Certificate files are bounded and checked for a matching key at startup. Lumen
does not issue or renew certificates. The DNS and web listeners may point to the
same certificate files, but each config section remains explicit.

## HTTP/3 and reverse proxies

The daemon does not claim direct HTTP/3. DNS-over-QUIC is a different protocol
and cannot serve browsers. Any reverse proxy with HTTP/3 support can terminate
TCP/UDP 443 and forward normal HTTP to Lumen's private port 8080.

Proxy requirements:

- forward only to a private or loopback Lumen HTTP listener;
- expose TCP 443 and UDP 443 when HTTP/3 is wanted;
- preserve the `Host` header;
- use `/healthz` for liveness;
- set certificate issuance, renewal, redirects, and public access at the proxy;
- do not proxy the authenticated management API unless its separate security
  model is deliberately extended.

Lumen sends a strict no-script content security policy, frame denial, MIME
sniffing denial, no-referrer policy, and `no-cache`. These headers are part of
the blank-shell base and will be reviewed when real UI assets arrive.

## Container

The image exposes TCP 8080 as metadata. The supplied Compose file publishes it
only on host loopback as `127.0.0.1:8080`. Its mounted container config binds
`0.0.0.0:8080` inside the isolated container network so a host browser or any
chosen reverse proxy can reach it. Change public exposure deliberately.

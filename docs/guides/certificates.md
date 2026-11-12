# Automatic certificates (ACME)

Lumen can get and renew the TLS certificate for its encrypted listeners (DoT, DoH, DoH3, DoQ) by itself, from an ACME certificate authority such as Let's Encrypt, with the HTTP-01 or DNS-01 challenge. It is **off by default**: without `[acme]` Lumen never contacts a certificate authority.

## What you need

- A **public DNS name** that points at the machine Lumen runs on, for example `dns.example.com`.
- For the default HTTP-01 challenge, **port 80** on that machine reachable from the internet. The CA proves you control the name by fetching a token over plain HTTP (the *HTTP-01* challenge). Lumen opens the port only while an order runs, and closes it afterwards. If port 80 is taken or blocked, forward another port to `challenge_listen`.
- At least one encrypted listener and the `listen.certificate` and `listen.private_key` paths. Lumen writes the certificate and key there.

HTTP-01 cannot issue wildcard certificates, and it needs port 80. If that does not suit you, use [DNS-01](#dns-01-wildcards-and-no-port-80), where Lumen answers the CA's check through DNS. For names no CA can reach at all, keep using your own certificate files ([Encrypted DNS](encrypted-dns.md)).

## Configure it

```toml
[listen]
dot = ["0.0.0.0:853"]
certificate = "tls/fullchain.pem"
private_key = "tls/privkey.pem"

[acme]
domains = ["dns.example.com"]            # 1 to 8 names, no wildcards
directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
terms_agreed = true                      # you accept the CA's terms of service
email = "you@example.com"                # optional, for expiry notices
account_file = "tls/acme-account.json"   # created on first use, mode 0600
# challenge_listen = "0.0.0.0:80"
# renew_before_days = 30                 # 1 to 60
# directory_ca = "tls/private-ca.pem"    # only for a private CA
```

There is **no default `directory`**, so you choose on purpose. Start with the CA's *staging* directory, check that it works, then switch to the production one (`https://acme-v02.api.letsencrypt.org/directory` for Let's Encrypt). Staging certificates are not trusted by clients. Delete the account file when you change the directory, because an account belongs to one CA.

## DNS-01: wildcards and no port 80

Set `challenge = "dns-01"` and Lumen proves control by answering a DNS question instead of a web request. The CA looks up `TXT _acme-challenge.<name>`, and Lumen's resolver answers it from memory while the order runs. This allows wildcard names such as `*.example.com`, and needs no port 80.

```toml
[acme]
challenge = "dns-01"
domains = ["*.example.com", "example.com"]
directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
terms_agreed = true
account_file = "tls/acme-account.json"
```

The CA must be able to reach Lumen's DNS service, so one more setup step is yours:

1. Lumen must answer on a public address and port 53, and `listen.allow_clients` must let the CA's resolvers ask (it is private by default).
2. **Delegate the challenge name to Lumen** in your public zone, once, so only that one name goes to Lumen:

   ```text
   _acme-challenge.example.com.  IN  NS  lumen.example.com.
   lumen.example.com.            IN  A   203.0.113.53
   ```

Lumen answers only the published challenge names for the length of an order, with a one-second TTL, and clears them afterwards. On the very first start, before any certificate exists, Lumen cannot open its encrypted listeners yet, so a small stand-in answers on your configured `listen.udp` and `listen.tcp` addresses just for the order and gives the ports back before the real listeners bind.

## What happens

1. **At startup**, if the certificate files are missing, unreadable, or have fewer than `renew_before_days` days left, Lumen orders a new certificate before it opens the encrypted listeners. If it cannot get one and none exists, startup fails with a clear error. If one exists, Lumen logs the problem and keeps the old certificate.
2. **Every day** Lumen checks again. When a certificate is due it renews it. A failed attempt is retried after one hour.
3. The new certificate and key are written atomically (key mode `0600`), and the running listeners **load them within 30 seconds** through [certificate reload](encrypted-dns.md). Nothing restarts.

Watch the result with `lumen_dns_certificate_not_after_timestamp_seconds` and the reload metrics in [Monitoring](monitoring.md).

## Limits and safety

- HTTP-01 and DNS-01 are supported. No TLS-ALPN-01, no External Account Binding, and no updating of an outside DNS provider: the delegation above is how DNS-01 reaches Lumen.
- The challenge listener answers `GET /.well-known/acme-challenge/<token>` for tokens of the running order and nothing else. It serves at most 16 connections at once and times out slow ones.
- One order may take up to 5 minutes. The account key stays in `account_file`. Back it up with your config; losing it only means a new account.
- The web console's own HTTPS certificate (`web.certificate`) is not managed by ACME and still needs a restart to change.
- Lumen does not check for revocation and does not renew early after a CA incident. Delete the certificate files and restart to force a new order.
- Both challenges, including a wildcard order, are tested against the Pebble ACME test server, not against Let's Encrypt itself.

## Related

- [Encrypted DNS](encrypted-dns.md)
- [Configuration reference](../reference/configuration.md#acme)
- [Threat model](../design/threat-model.md)

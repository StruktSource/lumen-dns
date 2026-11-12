# Automatic certificates (ACME)

Lumen can get and renew the TLS certificate for its encrypted listeners (DoT, DoH, DoH3, DoQ) by itself, from an ACME certificate authority such as Let's Encrypt. It is **off by default**: without `[acme]` Lumen never contacts a certificate authority.

## What you need

- A **public DNS name** that points at the machine Lumen runs on, for example `dns.example.com`.
- **Port 80** on that machine reachable from the internet. The CA proves you control the name by fetching a token over plain HTTP (the *HTTP-01* challenge). Lumen opens the port only while an order runs, and closes it afterwards. If port 80 is taken or blocked, forward another port to `challenge_listen`.
- At least one encrypted listener and the `listen.certificate` and `listen.private_key` paths. Lumen writes the certificate and key there.

HTTP-01 cannot issue wildcard certificates, and it cannot work for names that are not reachable from the internet. For those, keep using your own certificate files ([Encrypted DNS](encrypted-dns.md)).

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

## What happens

1. **At startup**, if the certificate files are missing, unreadable, or have fewer than `renew_before_days` days left, Lumen orders a new certificate before it opens the encrypted listeners. If it cannot get one and none exists, startup fails with a clear error. If one exists, Lumen logs the problem and keeps the old certificate.
2. **Every day** Lumen checks again. When a certificate is due it renews it. A failed attempt is retried after one hour.
3. The new certificate and key are written atomically (key mode `0600`), and the running listeners **load them within 30 seconds** through [certificate reload](encrypted-dns.md). Nothing restarts.

Watch the result with `lumen_dns_certificate_not_after_timestamp_seconds` and the reload metrics in [Monitoring](monitoring.md).

## Limits and safety

- Only the HTTP-01 challenge is supported. No DNS-01, no TLS-ALPN-01, no External Account Binding.
- The challenge listener answers `GET /.well-known/acme-challenge/<token>` for tokens of the running order and nothing else. It serves at most 16 connections at once and times out slow ones.
- One order may take up to 5 minutes. The account key stays in `account_file`. Back it up with your config; losing it only means a new account.
- The web console's own HTTPS certificate (`web.certificate`) is not managed by ACME and still needs a restart to change.
- Lumen does not check for revocation and does not renew early after a CA incident. Delete the certificate files and restart to force a new order.
- Tested against the Pebble ACME test server, not against Let's Encrypt itself.

## Related

- [Encrypted DNS](encrypted-dns.md)
- [Configuration reference](../reference/configuration.md#acme)
- [Threat model](../design/threat-model.md)

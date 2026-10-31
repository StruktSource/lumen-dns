# Web console

Lumen embeds a complete management console in the daemon binary: overview, activity,
filtering, devices, DNS settings, users, and system pages. It needs no separate web
server, database, or build step. The files in [`web/`](../web) are compiled in with
`include_bytes!`; requests never read the filesystem.

## Turn it on

The console is served by the web listener and stores accounts in the managed state
database, so start Lumen in managed mode:

```sh
lumen --config /etc/lumen/lumen.toml --state /var/lib/lumen/state.db
```

The release config enables loopback HTTP on port 8080:

```toml
[web]
http = ["127.0.0.1:8080", "[::1]:8080"]
https = []
max_connections = 64
```

Without `--state` the static files are still served, but every `/api` call answers
`503` and the page tells the visitor that managed mode is required.

## First run

1. Open `http://127.0.0.1:8080` on the machine that runs Lumen.
2. Create the administrator account (username, password, resolution mode, allowed
   networks).

If you browse from another machine, setup also asks for a **setup code**. Lumen prints
it at startup (`docker logs lumen` for containers) and keeps it until an account
exists. Anyone who can reach the port before setup finishes could otherwise claim the
console, so the code is mandatory off the local machine. Loopback visitors do not need
it. Headless alternative:

```sh
printf '%s' "$PASSWORD" | lumenctl user add --state state.db --name admin --role admin --password stdin
```

## Accounts and sessions

| Role | Can do |
| --- | --- |
| Administrator | Everything: settings, filtering, devices, users, audit log, reload, shutdown |
| User | See the overview, activity, and devices; change their own password |

- Passwords are stored as salted PBKDF2-HMAC-SHA256 records (600,000 iterations) and
  must be at least 10 characters.
- Sessions use a random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie
  (`Secure` on HTTPS). Only a hash of the token is stored. Sessions end after
  30 minutes idle (admin-adjustable, 5 to 1440) or 12 hours total, on sign-out, and
  on any password change or reset for that account.
- **Two-step verification (TOTP)** is optional per account, under *My account*. It works
  with any authenticator app (RFC 6238: SHA-1, 6 digits, 30 s; Google Authenticator,
  Authy, 1Password, Aegis, and others). Turning it on asks for the password, shows a
  setup key (and an `otpauth://` link for phones), and needs one valid code before it
  activates. It then shows **ten single-use recovery codes**, once. Signing in asks for
  the code after the password; a code works only once, so a captured code cannot be
  replayed, and one step of clock drift is allowed. Turning it off needs the password
  and a code or recovery code. The secret is stored in the state database (mode 0600)
  because the server must compute codes; recovery codes are stored only as hashes.
  An administrator can remove it for someone who lost their phone and codes
  (*Users & access*), or run `lumenctl user reset-2fa --state FILE --name NAME`. Both
  end that account's sessions. There is no QR code: use the setup key or the link.
- Five wrong passwords lock a username for 30 seconds, then longer. Per-address limits
  are looser because many people can share one address.
- Every change-making request must carry the session's CSRF token and, if the browser
  sends `Origin`, it must match `Host`.
- The last administrator can be neither deleted nor demoted. Reset a forgotten
  password with `lumenctl user reset-password --state FILE --name NAME --password generate`.
- Sign-in, setup, user changes, configuration, device, filter, and control actions go
  to the audit log (the newest 10,000 events). Passwords, tokens, and request bodies
  never do.

## What the console can change

Configuration edits are staged, validated by the same parser the daemon uses, then
applied through the normal reload path: listeners restart, caches clear, and a failure
restores the previous settings. Revisions (the newest 50) are kept and can be restored.
Saving from the console rewrites the stored TOML from the form: comments are not
preserved and values equal to the defaults are omitted. The `[management]` API settings
are passed through untouched; the console does not use API tokens. Devices are stored
separately and applied immediately.

## Privacy

The overview shows aggregate counters only. **Recent queries** is off by default; when
an administrator turns it on, Lumen keeps the last 1,000 lookups (domain, device,
result, latency) **in memory only**. They are never written to disk and are dropped on
restart or when the switch is turned off.

## Direct HTTPS

```toml
[web]
http = []
https = ["0.0.0.0:8443"]
certificate = "tls/web-cert.pem"
private_key = "tls/web-key.pem"
max_connections = 64
```

Direct HTTPS uses TLS 1.3 with HTTP/2 and HTTP/1.1 ALPN. Lumen does not issue or
renew certificates. Sign-in over plain HTTP is only safe on the local machine: use
HTTPS or a reverse proxy for any other access.

## HTTP/3 and reverse proxies

The daemon does not claim direct HTTP/3. Any proxy with HTTP/3 support can terminate
TCP/UDP 443 and forward plain HTTP to Lumen's private port 8080. Preserve the `Host`
header (the same-origin check compares it with `Origin`), forward only to a private or
loopback listener, and use `/healthz` for liveness. A proxy that adds TLS should also
set `Secure` on the session cookie, or Lumen should itself listen on HTTPS.

## Security headers

Every response sends `Content-Security-Policy: default-src 'none'; script-src 'self';
style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self';
base-uri 'none'; frame-ancestors 'none'`, plus `X-Frame-Options: DENY`,
`X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and same-origin
cross-origin policies. The console has no inline script or style, loads no font, image,
or script from any other origin, and uses no external services. API responses are
`Cache-Control: no-store`.

## Container

The image keeps accounts and settings in `/var/lib/lumen` (a volume, writable by UID
65532) and starts in managed mode. The supplied Compose file publishes the console on
host loopback as `127.0.0.1:8080`; inside the container it binds `0.0.0.0:8080`, so
visitors appear as a non-loopback address and need the setup code from `docker logs`.
Once state exists, edits to the mounted `lumen.toml` no longer apply: use the console
or `lumenctl config apply`.

## Console API

The console talks to `/api/*` on the same listener. It is an internal interface for
the bundled UI and may change between releases; for automation use the
[management API](management-api.md) with its scoped tokens.

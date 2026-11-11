# Web console

Lumen includes a complete management console in the same program: overview, activity, filtering, devices, DNS settings, users, and system pages. You need no separate web server, database, or build step. The files in [`web/`](../../web) are compiled into the binary, and requests never read the filesystem.

## Turn it on

The console needs [managed mode](managed-mode.md) because it stores accounts in the state database:

```sh
lumen --config /etc/lumen/lumen.toml --state /var/lib/lumen/state.db
```

The release config serves the console on loopback port 8080:

```toml
[web]
http = ["127.0.0.1:8080", "[::1]:8080"]
https = []
max_connections = 64
```

Without `--state`, the static page is served but every `/api` call answers `503`, and the page tells you that managed mode is required.

## First-run setup

1. Open <http://127.0.0.1:8080> on the machine that runs Lumen.
2. A guided setup walks you through:
   - Welcome, with a choice of language
   - Setup code (only when you are not on the local machine)
   - Your administrator account
   - How answers are found: private recursion or a forwarding provider
   - Which networks may use the server
   - A starting set of block lists: Recommended, Light, Strict, or none
3. The lists you pick are installed right after sign-in through the normal apply flow, so you can watch the progress and retry a failure.
4. The Overview then shows a **Getting started** checklist (point a device at Lumen, install lists, enable two-step verification, name devices). It ticks itself off and can be dismissed.

### The setup code

If you browse from another machine, setup asks for a **setup code**. Lumen prints it at startup (use `docker logs lumen` for containers) and keeps it until an account exists. Without it, anyone who could reach the port before setup finished could claim the console. Visitors on loopback do not need it.

### Create an account from the command line

```sh
printf '%s' "$PASSWORD" | lumenctl user add --state state.db --name admin --role admin --password stdin
```

## Day to day

### Activity panel

Whenever Lumen applies a change or downloads lists, a panel in the corner of every page shows what it is doing: checking, downloading (per list, with bytes received), reading rules, restarting DNS. When it finishes you get a notification. If a change is **not** applied, the panel stays, shows the reason (for example `list address answered HTTP 404`), and tells you the previous settings are still running. It contains only list names, byte counts, and error text.

While lists are downloading, an administrator can press **Cancel**. The downloads stop, nothing changes, and your current settings and lists stay live. What was already downloaded is kept, so trying again does not start from zero.

### What you can change

**Lists apply right away.** Installing, removing, adding, or editing a list asks you to confirm, then Lumen downloads in the background. There is no draft and no *Apply* bar for lists, DNS keeps answering, and the other lists you already have are **not** downloaded again.

**Other edits are staged.** Changes to DNS settings, rules, profiles, and schedules stay in a draft until you press *Apply*. They are validated by the daemon's own parser, then applied through the [reload path](managed-mode.md#change-the-configuration-safely). If a change only touches filtering (lists, rules, profiles, schedules, devices), it goes live **without restarting the listeners**. Anything else restarts them and clears caches, and a failure restores the previous settings.

- The newest 50 revisions are kept and can be restored.
- Saving from the console **rewrites the stored TOML from the form**: comments are not preserved and values equal to the defaults are omitted.
- `[management]` API settings pass through untouched. The console does not use API tokens.
- Devices are stored separately and applied immediately.

### Privacy

The overview shows aggregate counters only. **[Query history](query-history.md)** is off by default. An administrator can turn on *recent only* (the last 1,000 lookups, in memory, never written to disk) or *saved* (kept in the state database for 1 to 90 days), either anonymous or with the device and address. See [Query history](query-history.md).

### Language

The console is available in English, German, Italian, Spanish, and Dutch. The setup wizard asks first, each person can choose their own under **My account**, and administrators set the default under **Users & access → Console**. See [Languages and translations](translations.md).

## Accounts and sign-in

| Role | Can do |
| :--- | :--- |
| **Administrator** | Everything: settings, filtering, devices, users, audit log, reload, shutdown |
| **User** | See the overview, activity, and devices; change their own password |

- **Passwords** must be at least 10 characters and are stored as salted PBKDF2-HMAC-SHA256 (600,000 iterations).
- **Sessions** use a random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` on HTTPS), and only a hash is stored. Sessions end after 30 minutes idle (adjustable by an admin, 5 to 1440), after 12 hours total, on sign-out, and whenever that account's password changes or is reset.
- **Lockouts:** five wrong passwords lock a username for 30 seconds, then longer. Per-address limits are looser because many people can share an address.
- **CSRF:** every change-making request must carry the session's CSRF token, and if the browser sends `Origin`, it must match `Host`.
- **The last administrator** can be neither deleted nor demoted.
- **Audit log:** sign-in, setup, user changes, configuration, device, filter, and control actions are recorded (newest 10,000). Passwords, tokens, and request bodies never are.

Administrators can also let people sign in with Authentik, Authelia, Pocket ID, or another OpenID Connect provider: [External login](external-login.md). It is off by default and this login always stays.

Forgot a password:

```sh
lumenctl user reset-password --state FILE --name NAME --password generate
```

### Two-step verification (TOTP)

Optional per account, under **My account**. It works with any authenticator app (RFC 6238: SHA-1, 6 digits, 30 seconds), such as Google Authenticator, Authy, 1Password, or Aegis.

1. Turning it on asks for your password and shows a **setup key** and an `otpauth://` link. There is no QR code.
2. Enter one valid code to activate it.
3. Lumen shows **ten single-use recovery codes**, once. Save them.
4. From then on, sign-in asks for a code after the password. A code works only once, so a captured code cannot be replayed, and one step of clock drift is allowed.
5. Turning it off needs your password plus a code or recovery code.

The secret is stored in the state database (mode `0600`) because the server must compute codes. Recovery codes are stored only as hashes.

Lost phone and codes? An administrator can remove two-step verification under **Users & access**, or run `lumenctl user reset-2fa --state FILE --name NAME`. Either way, that account's sessions end.

## HTTPS and remote access

> [!WARNING]
> Sign-in over plain HTTP is only safe on the local machine. For any other access, use HTTPS or a reverse proxy.

### Direct HTTPS

```toml
[web]
http = []
https = ["0.0.0.0:8443"]
certificate = "tls/web-cert.pem"
private_key = "tls/web-key.pem"
max_connections = 64
```

Direct HTTPS uses TLS 1.3 with HTTP/2 and HTTP/1.1. Lumen does not issue or renew certificates.

### Behind a reverse proxy (including HTTP/3)

Lumen does not offer HTTP/3 directly. Any proxy with HTTP/3 support can terminate TCP/UDP 443 and forward plain HTTP to Lumen's private port 8080. When you do this:

- Preserve the `Host` header, because the same-origin check compares it with `Origin`.
- Forward only to a private or loopback listener.
- Use `/healthz` for liveness checks.
- Make sure the session cookie is marked `Secure`, or have Lumen listen on HTTPS itself.

### In a container

The image keeps accounts and settings in `/var/lib/lumen` (a volume writable by UID 65532) and starts in managed mode. The supplied Compose file publishes the console on host loopback as `127.0.0.1:8080`. Inside the container Lumen binds `0.0.0.0:8080`, so visitors look like non-loopback clients and need the setup code from `docker logs`. Once state exists, edits to the mounted `lumen.toml` no longer apply: use the console or `lumenctl config apply`.

## Security details

- Every response carries `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`, plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and same-origin cross-origin policies.
- The console has no inline script or style, loads nothing from other origins, and uses no external services.
- API responses are `Cache-Control: no-store`.

## The console API

The console talks to `/api/*` on the same listener. This is an **internal interface** for the bundled UI and may change between releases. For automation, use the [management API](../reference/management-api.md) with its scoped tokens.

## Related

- [Managed mode](managed-mode.md)
- [Filtering](filtering.md)
- [Threat model](../design/threat-model.md)
- Working on the UI itself? See [`web/README.md`](../../web/README.md).

## Modules

Modules are big, optional features. Each one is **off until an administrator turns it on** under **Modules**, and a module that is off adds nothing to the sidebar. The choice is stored in the state database and applies to everyone who uses the console.

### Traffic map

An interactive tree of your DNS traffic: the Lumen server at the top, then domain endings (`.com`, `.co.uk`), then the domains under each one.

- Line thickness shows how many lookups; red means mostly blocked. Moving dots show live traffic.
- Click an ending to open or close its branch. Click a domain to see its lookups, blocked share, speed, record types, names under it, and (with full history) which devices asked.
- Filter by result, time window, or search; zoom, drag to move around, and switch the live refresh on or off.

The map is drawn from the [query history](query-history.md), so it needs history turned on (it offers to switch on *recent only*). It uses the newest 1,000 lookups in memory mode, or up to 5,000 saved lookups, and it reads nothing beyond what the Activity page already shows.

# Management API

Lumen's management API is disabled by default. It starts only in managed mode
with `--state`, binds only to a nonzero loopback address, and exposes versioned
HTTP/1.1 routes below `/v1`. It never serves DNS traffic or query history.

## Authentication and roles

Create a random token of at least 32 bytes. Store the token outside Lumen. Put
only its SHA-256 hash in config:

```sh
token="$(openssl rand -hex 32)"
printf '%s' "$token" | shasum -a 256
```

Use `Authorization: Bearer TOKEN`. Token comparison is constant-time. Token
names, roles, actions, targets, outcomes, and source IPs enter the durable audit
log; tokens and request bodies never do. The newest 10,000 events are retained.
Each token has a bounded per-minute
request rate. Roles are cumulative:

| Role | Access |
| --- | --- |
| `viewer` | status and devices |
| `operator` | viewer plus filter refresh/rollback |
| `admin` | operator plus audit, config, device, reload, and shutdown actions |

## Routes

| Method and path | Role | Result |
| --- | --- | --- |
| `GET /v1/status` | viewer | daemon status and last control error |
| `GET /v1/devices` | viewer | persistent devices |
| `GET /v1/audit?limit=100` | admin | newest 1–1000 audit events |
| `PUT /v1/devices` | admin | store JSON device and queue reload |
| `DELETE /v1/devices/ID` | admin | remove device and queue reload |
| `POST /v1/filter/refresh` | operator | queue list refresh |
| `POST /v1/filter/rollback` | operator | queue list rollback |
| `POST /v1/reload` | admin | queue config reload |
| `POST /v1/config` | admin | stage `application/toml` body and queue reload |
| `POST /v1/shutdown` | admin | queue clean shutdown |

Headers stop at 16 KiB. Bodies stop at 64 KiB. Chunked bodies are rejected.
Connections and reads have hard limits. Error bodies are generic JSON and never
include config, database, token, or parser details.

Example:

```sh
curl --fail-with-body \
  --header "Authorization: Bearer $token" \
  http://127.0.0.1:9080/v1/status
```

## Signed webhooks

Each accepted or rejected API audit event can be sent to up to eight configured
HTTPS endpoints. A webhook secret file must contain 32–256 bytes. Delivery uses
public WebPKI roots, port 443, no proxy, no redirects, a five-second deadline,
and a 128-event memory queue. Delivery is best effort; the SQLite audit record
is authoritative.

`X-Lumen-Signature` is `sha256=HEX`, computed as HMAC-SHA256 over the exact JSON
body. Verify it before parsing or acting. `X-Lumen-Event` is `audit`, and
`X-Lumen-Webhook` contains the configured webhook ID.

Management listener and webhooks reload with DNS config. If either new listener
cannot start, Lumen restores the prior DNS and management configuration.

# Management API

The management API lets scripts and tools control Lumen over HTTP. It is **disabled by default**, and most people can do everything they need with the [web console](../guides/web-console.md) or [`lumenctl`](cli.md) instead.

Where it applies:

- It starts only in [managed mode](../guides/managed-mode.md) (`--state`).
- It binds only to a nonzero **loopback** address.
- It serves versioned HTTP/1.1 routes below `/v1`.
- It never serves DNS traffic or query history.

## Turn it on

1. Create a random token of at least 32 bytes and keep it **outside** Lumen. Put only its SHA-256 hash in the config.

   ```sh
   token="$(openssl rand -hex 32)"
   printf '%s' "$token" | shasum -a 256
   ```

2. Add the API to your config:

   ```toml
   [management]
   listen = "127.0.0.1:9080"
   requests_per_minute = 60

   [[management.tokens]]
   name = "local-admin"
   role = "admin"
   sha256 = "<the 64 lowercase hex characters from step 1>"
   ```

3. Apply it (`lumenctl config apply`) and try it:

   ```sh
   curl --fail-with-body \
     --header "Authorization: Bearer $token" \
     http://127.0.0.1:9080/v1/status
   ```

You can define 1 to 16 tokens. `requests_per_minute` defaults to 60 per token (range 1 to 600).

## Authentication and roles

Send `Authorization: Bearer TOKEN`. Token comparison is constant-time. Each token has its own bounded per-minute request rate. Roles are cumulative:

| Role | Can do |
| :--- | :--- |
| `viewer` | Read status and devices |
| `operator` | Everything a viewer can, plus refresh and roll back filter lists |
| `admin` | Everything an operator can, plus audit, config, devices, reload, and shutdown |

**Audit log.** Every accepted or rejected call is recorded with the token name, role, action, target, outcome, and source IP. Tokens and request bodies are never recorded. The newest 10,000 events are kept.

## Routes

| Method and path | Role | Result |
| :--- | :--- | :--- |
| `GET /v1/status` | viewer | Daemon status and last control error |
| `GET /v1/devices` | viewer | Saved devices |
| `GET /v1/audit?limit=100` | admin | Newest 1 to 1000 audit events |
| `PUT /v1/devices` | admin | Store a JSON device and queue a reload |
| `DELETE /v1/devices/ID` | admin | Remove a device and queue a reload |
| `POST /v1/filter/refresh` | operator | Queue a list refresh |
| `POST /v1/filter/rollback` | operator | Queue a list rollback |
| `POST /v1/reload` | admin | Queue a configuration reload |
| `POST /v1/config` | admin | Stage an `application/toml` body and queue a reload |
| `POST /v1/shutdown` | admin | Queue a clean shutdown |

**Limits.** Headers stop at 16 KiB and bodies at 64 KiB. Chunked bodies are rejected, and connections and reads have hard time limits. Error bodies are generic JSON and never include config, database, token, or parser details.

## Signed webhooks

Each accepted or rejected API audit event can be sent to up to **eight** HTTPS endpoints.

```toml
[[management.webhooks]]
id = "home-assistant"
url = "https://home.example/api/webhook/lumen"
secret_file = "secrets/home-assistant-webhook.key"
```

- The secret file must contain 32 to 256 bytes.
- Delivery uses public WebPKI roots, port 443, no proxy, no redirects, a five-second deadline, and a 128-event memory queue.
- Delivery is **best effort**. The SQLite audit record is authoritative.
- Headers: `X-Lumen-Event` is `audit`, `X-Lumen-Webhook` is your configured ID, and `X-Lumen-Signature` is `sha256=HEX`, an HMAC-SHA256 over the exact JSON body.
- **Verify the signature before parsing or acting on the body.**

The management listener and webhooks reload together with the DNS config. If either new listener cannot start, Lumen restores the prior DNS and management configuration.

## Not the same as…

- **The console API** (`/api/*`) is internal to the bundled UI and may change. Use this `/v1` API for automation.
- **DNS-over-HTTPS** is a DNS transport, not a management API.

## Related

- [Home Assistant and Prometheus setup](../guides/monitoring.md)
- [Threat model](../design/threat-model.md)

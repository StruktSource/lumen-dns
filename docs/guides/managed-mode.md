# Managed mode

Managed mode lets Lumen remember its settings, devices, and accounts in a small local database, and lets you change them while it runs, safely. It is what powers the [web console](web-console.md), `lumenctl`, and the [management API](../reference/management-api.md).

## Turn it on

Add `--state` with a path for the database:

```sh
lumen --config /etc/lumen/lumen.toml --state /var/lib/lumen/state.db
```

Container images and the systemd unit already start this way.

## The database is in charge after first start

On the **first** managed start, Lumen stores your TOML file as **revision 1** and seeds the device table once. From then on, **the database is the source of truth**.

> [!WARNING]
> Editing the original TOML file does nothing once the database exists. Apply changes with `lumenctl config apply`, the web console, or the management API.

Database facts:

- It is created at schema 1 and migrated transactionally to the current schema 6. A database made by a newer Lumen is rejected, so back it up before you upgrade.
- On Unix the file mode is restricted to `0600`. The service account needs read and write access to the database **directory**.
- One database belongs to one daemon. Never share it between instances.
- **Back it up** with SQLite-aware tooling while Lumen is stopped, or with the SQLite backup API. Do not just copy a live file.
- It holds config revisions, devices, accounts, console settings (such as the language), the control queue, daemon status, and the audit log. **Saved [query history](query-history.md)** is stored in it too, but only if you turn that on. It does **not** hold filter rollback snapshots, DNS caches, or secrets from external key files.

## Change the configuration safely

```sh
lumenctl config validate --config /etc/lumen/lumen.toml
lumenctl config apply    --config /etc/lumen/lumen.toml --state /var/lib/lumen/state.db
lumenctl config show     --state /var/lib/lumen/state.db
```

What `apply` does:

1. It stages your file as a candidate revision and queues a reload.
2. The daemon parses it with the original base directory, loads filter sources, and checks resolver and TLS state.
3. It restarts the listeners and promotes the revision **only after every socket binds**.
4. If anything fails, the previous runtime is restored and the candidate is discarded.

Filter lists are downloaded and validated **before** the swap, while DNS keeps answering, and the new server reuses that loaded filter. DNS is unavailable only during the listener swap, about a second, even with multi-megabyte lists.

A reload is not zero-downtime: it closes active connections, briefly releases the listener sockets, and clears the in-memory DNS caches.

## Control a running daemon

The same commands work on Linux, macOS, and Windows:

```sh
lumenctl status          --state /var/lib/lumen/state.db
lumenctl reload          --state /var/lib/lumen/state.db
lumenctl filter refresh  --state /var/lib/lumen/state.db
lumenctl filter rollback --state /var/lib/lumen/state.db
lumenctl shutdown        --state /var/lib/lumen/state.db
```

Commands are queued in the database and normally applied within 500 ms. `status` shows the last daemon state and any control error. **Queuing a command does not prove a daemon is running**, so check `status` and your service supervisor.

## Manage devices

Device changes are saved and queue a reload automatically:

```sh
lumenctl device set --state /var/lib/lumen/state.db \
  --id phone --address 192.0.2.44 --profile family
lumenctl device list   --state /var/lib/lumen/state.db
lumenctl device remove --state /var/lib/lumen/state.db --id phone
```

Each device needs at least one IP address and a profile, a group, or both. Profiles and groups come from the active configuration. A missing reference or a duplicate IP rejects the reload and keeps the previous runtime.

## Security note

The database is a **local control channel**, not an authenticated remote API. Protect its directory with operating-system permissions. For remote or scripted control, use the authenticated [management API](../reference/management-api.md).

## Related

- [`lumenctl` reference](../reference/cli.md)
- [Web console](web-console.md)
- [Configuration reference](../reference/configuration.md)

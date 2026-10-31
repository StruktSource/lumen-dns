# State and local control

Managed mode stores configuration, devices, control commands, and daemon status
in a local SQLite database:

```sh
lumen --config /etc/lumen/lumen.toml --state /var/lib/lumen/state.db
```

The daemon creates schema 1 and migrates it transactionally to current schema 3.
Schema 3 adds the bounded management audit log.
It rejects a database created by a newer Lumen version. On Unix, opening the
database restricts its mode to `0600`. The service account needs read/write
access to the database directory. Do not share one database between daemon
instances. Back up the database with SQLite-aware tooling while Lumen is stopped,
or use the SQLite backup API.

The first managed start stores the supplied TOML as active revision 1 and seeds
the device table once. After that, the database is authoritative for config and
devices. Editing the original TOML has no effect until it is applied:

```sh
lumenctl config validate --config /etc/lumen/lumen.toml
lumenctl config apply --config /etc/lumen/lumen.toml --state /var/lib/lumen/state.db
lumenctl config show --state /var/lib/lumen/state.db
```

Apply stages a candidate and queues a reload. The daemon parses it with its
original base directory, loads filter sources, checks resolver/TLS state, then
restarts listeners. It promotes the revision only after every socket binds.
Failure restores the previous runtime and discards the candidate. Reload closes
active connections, briefly releases listener sockets, and resets in-memory DNS
caches. It does not provide zero-downtime listener replacement.

Local control uses the same database on Linux, macOS, and Windows:

```sh
lumenctl status --state /var/lib/lumen/state.db
lumenctl reload --state /var/lib/lumen/state.db
lumenctl filter refresh --state /var/lib/lumen/state.db
lumenctl filter rollback --state /var/lib/lumen/state.db
lumenctl shutdown --state /var/lib/lumen/state.db
```

Commands are queued and normally applied within 500 ms. `status` reports the
last daemon state and control error. Queuing a command does not prove that a
daemon is running; check status and service supervision.

Device commands persist policy selectors and queue reload automatically:

```sh
lumenctl device set --state /var/lib/lumen/state.db \
  --id phone --address 192.0.2.44 --profile family
lumenctl device list --state /var/lib/lumen/state.db
lumenctl device remove --state /var/lib/lumen/state.db --id phone
```

Each device needs one or more IP addresses and a profile, group, or both.
Profiles and groups still come from active configuration. A missing reference or
duplicate IP rejects reload and leaves the prior runtime active.

The database is a local control channel, not an authenticated remote API. Protect
its directory with OS permissions. Query history, filter rollback snapshots,
DNS caches, and secrets from external key files are not stored in it.

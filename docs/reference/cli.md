# Command-line reference

Lumen ships two programs:

- **`lumen`** is the DNS service (the daemon).
- **`lumenctl`** is the control tool. It checks configs, manages a running managed-mode daemon, and administers console accounts. It works the same on Linux, macOS, and Windows.

Run either with `--help` or `--version` to see what your build supports.

## `lumen`

```text
lumen --config FILE [--state FILE] [--check]
lumen --bind ADDRESS
lumen --version
```

| Option | Meaning |
| :--- | :--- |
| `--config FILE` | Load a schema-versioned TOML configuration. See [Configuration](configuration.md) |
| `--state FILE` | Turn on [managed mode](../guides/managed-mode.md): SQLite config and device storage, the web console, and cross-platform control |
| `--check` | Validate the config, filter sources, root hints, trust anchors, and TLS keys, then exit. Opens no listeners |
| `--bind ADDRESS` | Minimal start with no config file: UDP and TCP recursive DNS, loopback clients only |
| `--help`, `--version` | Show help or the version |

Encrypted DNS and web listeners always need explicit config and certificate and key files.

Stop with Ctrl-C or, on Unix, `SIGTERM`. Listeners stop and outstanding work is cancelled. Caches are in memory only, so a restart begins empty.

## `lumenctl`

Most commands need `--state FILE`, the same database the daemon uses.

### Configuration

| Command | Meaning |
| :--- | :--- |
| `lumenctl config validate --config FILE` | Check a config file without touching the daemon |
| `lumenctl config apply --config FILE --state FILE` | Stage a new revision and queue a reload. Rolls back if the daemon cannot start it |
| `lumenctl config show --state FILE` | Show the active configuration |

### Daemon control

| Command | Meaning |
| :--- | :--- |
| `lumenctl status --state FILE` | Last daemon state and last control error |
| `lumenctl reload --state FILE` | Queue a configuration reload |
| `lumenctl shutdown --state FILE` | Queue a clean shutdown |
| `lumenctl filter refresh --state FILE` | Refresh all filter lists now |
| `lumenctl filter rollback --state FILE` | Swap back to the previous list generation |

Commands are queued and normally applied within 500 ms. Queuing does not prove a daemon is running, so check `status`.

### Devices

| Command | Meaning |
| :--- | :--- |
| `lumenctl device list --state FILE` | List saved devices |
| `lumenctl device set --state FILE --id ID --address IP [--address IP] [--profile ID] [--group ID]` | Add or update a device (needs at least one address, and a profile, a group, or both) |
| `lumenctl device remove --state FILE --id ID` | Remove a device |

### Query history

| Command | Meaning |
| :--- | :--- |
| `lumenctl history status --state FILE` | Show the mode, detail, retention, and how many lookups are saved |
| `lumenctl history set --state FILE --mode off\|memory\|saved [--detail anonymous\|full] [--days 1-90]` | Choose what is recorded. `--detail` and `--days` keep their current value when left out |
| `lumenctl history clear --state FILE` | Permanently delete every saved lookup |

A running Lumen picks up `history set` within a few seconds. See [Query history](../guides/query-history.md).

### Filter explanation

```sh
lumenctl filter-explain --config FILE --client IP --domain NAME [--at UNIX_SECONDS]
```

Shows whether a name would be blocked for a client, and why. It works offline from a config file and never contacts the daemon. See [Filtering](../guides/filtering.md#try-it-safely).

### Console users

| Command | Meaning |
| :--- | :--- |
| `lumenctl user list --state FILE` | List accounts |
| `lumenctl user add --state FILE --name NAME [--role admin\|user] --password stdin\|generate` | Create an account |
| `lumenctl user reset-password --state FILE --name NAME --password stdin\|generate` | Set a new password and end that account's sessions |
| `lumenctl user reset-2fa --state FILE --name NAME` | Remove two-step verification and end that account's sessions |

These work for accounts created by [single sign-on](../guides/external-login.md) too. Such an account starts with a random password nobody knows, so `reset-password` gives it a local fallback.

`--password stdin` reads one line from standard input:

```sh
printf '%s' "$PASSWORD" | lumenctl user add --state state.db --name admin --role admin --password stdin
```

`--password generate` prints a random password that the person must change at first sign-in.

## Development scripts

For contributors working from a source checkout:

| Command | Meaning |
| :--- | :--- |
| `./scripts/dev.sh check` | Format check, Clippy with warnings denied, and all tests |
| `./scripts/dev.sh build` | Build development binaries |
| `./scripts/dev.sh image` | Build the local container image `lumen:local` (needs a Docker-compatible engine) |
| `./scripts/dev.sh release` | Run checks, build optimized binaries, then build the image. **Does not publish anything** |

On Windows, use `./scripts/dev.ps1` with the same commands.

## Related

- [Managed mode](../guides/managed-mode.md)
- [Management API](management-api.md), for remote or scripted control

# Query history

Query history lets you see which domains were looked up, when, and (if you choose) by which device. It is **off by default** and entirely opt-in.

> [!IMPORTANT]
> Query history records what people on your network look up. Turn it on only if everyone who uses the network knows. With history off, Lumen keeps only aggregate counters, so there is no browsing data to leak.

## Choose a mode

| Mode | What happens | Where it lives |
| :--- | :--- | :--- |
| **Off** (default) | Nothing is recorded. Only counters exist. | |
| **Recent only** | Keeps the last 1,000 lookups so you can watch live. | In memory. Never written to disk, and gone when you switch it off or restart Lumen. |
| **Saved** | Keeps lookups for a retention period so you can look back over days. | In the [state database](managed-mode.md) on this machine. |

## Choose how much is recorded

| Detail | Recorded for each lookup |
| :--- | :--- |
| **Anonymous** | Time, domain, record type, result (allowed, blocked, or an error code), and how long it took. **Not** the device or IP address. |
| **Device and address** | All of the above, plus the device name (if you named it) and the client IP address. |

Anonymous is the better choice when you only want to see *what* gets blocked, not *who* asked. The detail level is applied **before** anything is stored, so anonymous history never contains addresses to hide later.

## Turn it on

### In the web console

Open **Activity**. Under **Query history**, pick a mode, pick the detail, and (for Saved) the number of days. Lumen asks you to confirm and explains exactly what will be kept. Only administrators can change it. Other users can see the status and the lookups.

### From the command line

```sh
lumenctl history set --state /var/lib/lumen/state.db --mode saved --detail anonymous --days 7
lumenctl history status --state /var/lib/lumen/state.db
```

A running Lumen picks up the change within a few seconds, with no restart.

## Retention and limits

| Setting | Value |
| :--- | :--- |
| Retention | 1 to 90 days. Default **7 days** |
| Row cap | 500,000 saved lookups, whatever the retention. The oldest go first |
| Cleanup | Expired lookups are deleted automatically, about every 10 minutes |
| Write path | Lookups are batched and saved every 2 seconds, so DNS answers never wait for the disk |
| Under heavy load | If the writer cannot keep up, up to 8,192 waiting lookups are held, and any beyond that are dropped rather than slowing DNS down |

## Read and search

The Activity page lists the newest lookups first. You can search by domain, device name, or IP address, filter to allowed or blocked, and page back with **Show more**. Times are in UTC.

Switching history **off** stops new recording. Lookups already saved stay visible, and they are still deleted when their retention ends. To remove them right away, use **Delete saved history** in the console or:

```sh
lumenctl history clear --state /var/lib/lumen/state.db
```

Deleting is permanent. In the console, lookups still waiting to be written are discarded too. With `lumenctl`, the lookups of the last couple of seconds may still be written just afterwards, so switch history off first if you need a clean cut.

## Privacy notes

- **Nothing leaves your machine.** History is stored in the local state database (mode `0600` on Unix). It is not sent anywhere, and it is not exposed through the [management API](../reference/management-api.md) or metrics.
- **Backups include it.** A copy of the state database includes saved history, so protect backups the same way.
- **Console changes are audited.** Changing the mode or deleting history in the console is written to the audit log. The log records the action and the settings, never the domains. Changes made with `lumenctl` are local administration and are not audited, like the other `lumenctl` commands.
- **Blocked lookups are recorded too.** They appear like any other lookup, with the result `Blocked`.
- **Filter decision logs are separate.** The `decision_log` filter option writes to the process log and is unrelated to this feature. See [Filtering](filtering.md#privacy-and-logging).

## Related

- [Web console](web-console.md)
- [`lumenctl` reference](../reference/cli.md#query-history)
- [Threat model](../design/threat-model.md)

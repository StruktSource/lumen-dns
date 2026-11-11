# Lumen 0.6.0

Lumen 0.6.0 adds console features, fixes setup forwarding selection, and bounds automatic encrypted transport failover.

## Highlights

- **Live view.** Switch on *Live* in Activity to watch lookups arrive as they happen. The switch is remembered in your browser.
- **Modules and a Traffic map.** Turn on optional modules under *Modules*. The Traffic map shows your DNS traffic as a tree you can drag and zoom: server, domain endings, then domains.
- **A sidebar you can hide.** Press `[` or use the button in the sidebar header to get more room.
- **Overview refreshes every 10 seconds, and you can change that.** An *Auto reload* slider under *Users & access → Console* offers 1, 2, 5, 10, 30, 60 seconds or off, saved on the server for everyone.
- **Setup keeps your resolver choice.** Picking *Use another resolver* (Quad9) now results in forward mode instead of falling back to recursive.

## Resolver changes

- Bundled SQLite updated to address RUSTSEC-2026-0459 (`rusqlite 0.41.1`, `libsqlite3-sys 0.39.1`). Building from source now needs Rust 1.89 or newer. Database schema stays unchanged.

- A silent first encrypted transport no longer consumes the provider's whole deadline. Each transport gets its share of remaining time; only transport failures/timeouts advance transports. DNSSEC failures and usable answers stay final; upstream SERVFAIL may still advance providers.
- Recursive walks now use the configured attempt timeout and retry only after a timeout. Extra DNSSEC recovery work has one shared budget. Optional aggregate diagnostics contain no names, authority IPs, or clients.
- Registered local reverse zones, `home.arpa`, `resolver.arpa`, `service.arpa`, and `.local` requests are handled locally by default. Public reverse DNS and `ipv4only.arpa` still work. Set `resolver.local_zones = false` only when another local DNS path owns these names.
- Small response/filter allocation cleanups and portable ThinLTO are included. No new benchmark gain is claimed. Native CPU tuning stays opt-in and separate from release artifacts.
- See `docs/project/optimization-audit.md` for rejected and deferred I/O, allocator, parser and data-structure changes. No statistically significant public cold-recursion gain is claimed, and Hickory does not expose privacy-safe per-authority timing through its stable API.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.6.0-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- No required configuration or database schema changes since 0.5.9. New resolver fields keep safe defaults.
- Replace both `lumen` and `lumenctl` from the same archive.
- Container and Helm users should pin image tag `0.6.0` and back up `/var/lib/lumen` before recreating the container.
- Installs that picked forward mode in setup but ended up recursive can switch under DNS settings, then Resolver.

Lumen remains pre-release software. Test it on the target network before wider use. See `CHANGELOG.md` for the full summary.

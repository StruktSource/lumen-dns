# Windows

Run Lumen natively on Windows, AMD64 or ARM64.

> [!NOTE]
> Status: experimental. Hosted CI builds and tests both targets, and Windows ARM64 is the more experimental of the two. Managed-control runtime uses portable SQLite but has not been exercised on real native Windows hardware. See the [compatibility matrix](compatibility.md).

## Install

1. Download the matching `windows-amd64` or `windows-arm64` ZIP and `SHA256SUMS` from the [releases](https://github.com/StruktSource/lumen-dns/releases), and verify the checksum.
2. Unzip it, then run from PowerShell:

   ```powershell
   ./lumen.exe --config ./config/lumen.toml --check
   ./lumen.exe --config ./config/lumen.toml --state ./data/state.db
   ```

3. Control a running instance with the same `--state` path:

   ```powershell
   ./lumenctl.exe status --state ./data/state.db
   ```

   Other commands: `config apply`, `reload`, `filter refresh`, `filter rollback`, and `shutdown`. See the [command-line reference](../reference/cli.md).

Ctrl+C also performs a graceful shutdown.

## Running it long-term

- **No service wrapper is bundled yet.** Run it under a restricted service account that has exclusive read and write access to `./data`.
- **Firewall.** For a network deployment, allow both UDP and TCP in Windows Firewall. Keep the loopback default until your client ranges are reviewed. See [Serve your network](../guides/serve-your-network.md).

## Developing on Windows

Use `./scripts/dev.ps1` from PowerShell for the development checks (`check`, `build`, `image`, `release`).

## Related

- [Quick start](../getting-started/quick-start.md)
- [Compatibility matrix](compatibility.md)

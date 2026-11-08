# macOS

Run Lumen natively on Apple silicon or Intel Macs.

> [!NOTE]
> Status: experimental. Apple-silicon runtime tests exist (a local M4 plus hosted CI). The Intel target is hosted build, test, and config-check only. See the [compatibility matrix](compatibility.md).

## Install

1. Download the `macos-arm64` archive (Apple silicon) or `macos-amd64` (Intel), plus `SHA256SUMS`, from the [releases](https://github.com/StruktSource/lumen-dns/releases).
2. Verify the checksum. If `sha256sum` is not installed, use `shasum -a 256 -c` with the matching `.sha256` file.
3. Unpack it and validate the default config before starting:

   ```sh
   ./lumen --config config/lumen.toml --check
   ./lumen --config config/lumen.toml
   ```

The local default uses port **5353** and loopback only.

## Run it as a service

For a persistent service, create a dedicated launchd plist that runs the binary as an **unprivileged account**. Port 53 needs a deliberate redirect or an elevated bind setup. Do not run the whole service as root.

## Watch out for

- The macOS firewall and VPN software can change UDP and TCP routing and source addresses.
- Per-device filtering depends on Lumen seeing each device's real address.

## Related

- [Quick start](../getting-started/quick-start.md)
- [Serve your network](../guides/serve-your-network.md)

# Linux (systemd)

Run Lumen natively as a locked-down systemd service on Linux, AMD64 or ARM64. No Docker needed.

> [!NOTE]
> Status: experimental. Hosted CI builds, tests, and config-checks both architectures. See the [compatibility matrix](compatibility.md).

## 1. Download and verify

Get the `linux-amd64` or `linux-arm64` archive for your version, plus `SHA256SUMS`, from the [GitHub releases](https://github.com/StruktSource/lumen-dns/releases):

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.7-linux-amd64.tar.gz --repo StruktSource/lumen-dns
tar -xzf lumen-v0.5.7-linux-amd64.tar.gz
cd lumen-v0.5.7
./lumen --version
./lumenctl --version
```

Use `linux-arm64` on ARM64 hosts. The archive includes the configuration, deployment files, docs, release notes, and a file manifest.

## 2. Install

1. Copy `lumen` and `lumenctl` to `/usr/local/bin`.
2. Create an unprivileged service user:

   ```sh
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin lumen
   ```

3. Place a root-owned, world-readable config at `/etc/lumen/lumen.toml` (start from `config/lumen.toml` or `deploy/lumen.toml`).
4. Install the unit from `deploy/systemd/lumen.service`, then start it:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now lumen
   sudo journalctl -u lumen
   ```

## What the unit does

- Validates the config before every start (`ExecStartPre … --check`).
- Creates `/var/lib/lumen` with mode `0700` and enables [managed mode](../guides/managed-mode.md) at `/var/lib/lumen/state.db`.
- Restarts on failure and allows 15 seconds to stop.
- Blocks writes to the system, a private home and `/tmp`, and kernel controls, with no new privileges.

Use `lumenctl` with the state path for config, devices, reload, filter controls, status, and shutdown. Apply changes with `lumenctl config apply`. A failed validation or bind restores the previous config.

## Port 53

The example listens on port **5353**, which needs no capability. To serve port 53, either redirect it with a systemd socket or firewall rule, or add **only** `CAP_NET_BIND_SERVICE` to the service. **Never run the resolver as root.**

## Back up and test

- Back up the config, the state database, local lists, trust anchors, and TLS files. Runtime caches are not persistent.
- Before relying on it, test UDP, TCP, IPv4, IPv6, DNSSEC, shutdown, and source-IP behavior on the real host.

## Related

- [Serve your network](../guides/serve-your-network.md)
- [Web console](../guides/web-console.md)
- [Raspberry Pi and Proxmox notes](homelab.md)

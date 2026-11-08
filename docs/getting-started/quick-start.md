# Quick start

Get Lumen answering DNS questions on your own computer in a few minutes. By default it listens on **loopback port 5353**, validates DNSSEC, and talks to no outside provider, so it is safe to try.

> [!NOTE]
> Lumen is pre-release. Use it on a test machine first. See the [compatibility matrix](../deployment/compatibility.md) for what has been tested where.

## Choose how to run it

| Option | Best for |
| :--- | :--- |
| [Download a release](#option-a-download-a-release) | Most people. No build tools needed. |
| [Docker](../deployment/docker.md) | Servers, NAS devices, and homelabs. |
| [Build from source](#option-b-build-from-source) | Developers and contributors. |

## Option A: download a release

1. Open the [latest release](https://github.com/StruktSource/lumen-dns/releases/latest) and download two files: the archive for your system, plus `SHA256SUMS`.

   | System | Archive |
   | :--- | :--- |
   | Linux (Intel/AMD, ARM64) | `lumen-v<version>-linux-amd64.tar.gz`, `…-linux-arm64.tar.gz` |
   | macOS (Intel, Apple silicon) | `lumen-v<version>-macos-amd64.tar.gz`, `…-macos-arm64.tar.gz` |
   | Windows (Intel/AMD, ARM64) | `lumen-v<version>-windows-amd64.zip`, `…-windows-arm64.zip` |

2. Verify the download (see [Versioning and releases](../project/versioning.md#verify-a-download) for details):

   ```sh
   sha256sum --check SHA256SUMS --ignore-missing
   ```

   On macOS without `sha256sum`, use `shasum -a 256 -c` with the matching `.sha256` file.

3. Unpack it and check the version:

   ```sh
   tar -xzf lumen-v0.5.7-linux-amd64.tar.gz   # use the archive you downloaded
   cd lumen-v0.5.7
   ./lumen --version
   ```

   On Windows, unzip the `.zip` and use `lumen.exe` instead. The archive holds `lumen` (the DNS service), `lumenctl` (the control tool), the `config/` and `deploy/` folders, and these docs.

4. Validate the default configuration, then start Lumen:

   ```sh
   ./lumen --config config/lumen.toml --check
   ./lumen --config config/lumen.toml
   ```

   `--check` reads and validates everything without opening any ports, so it is a safe first step before any change.

Continue with [Ask Lumen a question](#ask-lumen-a-question).

## Option B: build from source

**You need:** Rust 1.88 or newer (stable is recommended; CI uses 1.95.0), Git, and optionally `dig` for testing.

```sh
git clone https://github.com/StruktSource/lumen-dns.git
cd lumen-dns
./scripts/dev.sh check                                   # format, lint, and tests
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/lumen.toml
```

On Windows, use `./scripts/dev.ps1` from PowerShell for the development checks; see the [Windows guide](../deployment/windows.md).

For the smallest possible start with no config file: `cargo run --locked --bin lumen -- --bind 127.0.0.1:5353`. Run `lumen --help` to see every startup option.

## Ask Lumen a question

In a second terminal:

```sh
dig @127.0.0.1 -p 5353 example.com A
dig @127.0.0.1 -p 5353 example.com A +dnssec
dig @::1 -p 5353 example.com AAAA +tcp
```

Look for `status: NOERROR` and an answer section. In the `+dnssec` query, the `ad` flag means Lumen verified the answer's signatures.

> [!TIP]
> The first lookup of a name can take a second or two because Lumen is walking the DNS tree itself. Repeat it and the answer comes back almost instantly from the cache.

**That is it:** a private recursive resolver with DNSSEC and bounded caches, no outside provider, and no query history unless you turn it on.

## What next?

### Open the web console

Start Lumen in [managed mode](../guides/managed-mode.md) by adding a state file, then open <http://127.0.0.1:8080>:

```sh
./lumen --config config/lumen.toml --state ./data/state.db
```

A guided setup creates your administrator account and, optionally, installs starter block lists. See the [Web console](../guides/web-console.md).

### Try filtering

Lumen preloads no block list. Try the safe demo configuration, which uses only reserved example domains:

```sh
./lumen --config config/filtering.example.toml --check
./lumenctl filter-explain --config config/filtering.example.toml \
  --client 192.0.2.10 --domain games.example --at 75600
```

Then read [Filtering](../guides/filtering.md) to add real lists.

### Forward to an encrypted provider instead

`config/forward.example.toml` forwards to an encrypted public resolver. **Running it sends your queries to that provider.** Read [Resolver modes](../guides/resolver-modes.md) and [Upstream providers](../guides/upstream-providers.md) first.

### Let other devices use it

Lumen only answers your own computer until you say otherwise. Follow [Serve your network](../guides/serve-your-network.md).

### Run it as a service

See the [deployment guides](../deployment/README.md) for Docker, systemd, Kubernetes, and more.

## Troubleshooting

| Symptom | Likely cause and fix |
| :--- | :--- |
| `--check` reports an unknown field | Settings are strict: typos and future schema versions fail on purpose. See [Configuration](../reference/configuration.md). |
| "address already in use" | Another program owns the port. Pick another port in `[listen]`. |
| `dig` times out | Check that you passed `-p 5353` and that Lumen is still running. |
| First answers are slow or `SERVFAIL` | Recursion needs outbound UDP/TCP 53 and an accurate clock (DNSSEC). Test your network, or try [forwarding](../guides/resolver-modes.md). |
| Another device cannot connect | Expected by default. See [Serve your network](../guides/serve-your-network.md). |

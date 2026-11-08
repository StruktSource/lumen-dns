# Lumen 0.5.5

Lumen 0.5.5 is a major pre-release step since 0.1.3. It adds a usable local web console and makes release packages easier to check and install.

## Highlights

- Built-in console for setup, accounts, roles, optional TOTP, filtering, devices, DNS settings, audit events, and recent activity.
- Guided filter-list setup and faster loading of very large lists.
- DNSSEC recursion fix for parent and child zones that share name servers.
- Six native packages: Linux, macOS, and Windows on x64 and ARM64.
- Multi-architecture OCI image for Linux amd64 and arm64.
- Packages now carry deployment files, documentation, checksums, and a file manifest.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.5-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

## Upgrade notes

- Back up `state.db`, configuration, local lists, TLS keys, and custom trust anchors.
- Replace both `lumen` and `lumenctl` from the same archive.
- Container and Helm users should pin image tag `0.5.5`.
- Read the deployment guide in the archive before starting the new build.

Lumen remains pre-release software. Test it on the target network before wider use. See `CHANGELOG.md` for the full summary.

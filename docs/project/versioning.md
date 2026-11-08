# Versioning and releases

How Lumen numbers its versions, what a release contains, and how to check that what you downloaded is genuine.

## Version rules

Lumen follows [Semantic Versioning](https://semver.org).

| Change | Version bump |
| :--- | :--- |
| Bug fixes | Patch (`0.5.6` to `0.5.7`) |
| New compatible features | Minor |
| Breaking a stable contract | Major |

- **`0.y.z` is preview.** Config, storage, and public contracts may still change.
- **`1.0.0` (stable)** requires proven resolver and filter behavior, migration and upgrade paths, deployment validation, and a security review.
- An increase in the **minimum Rust version** needs explicit minor or major release notes.
- There is **one version**, in the root `Cargo.toml`.
- Within minor releases, config, API, and storage changes must stay compatible. Config schema versions fail closed: a future schema is rejected rather than guessed.

## What a release contains

Each release is published step by step as every target passes its tests. The final `latest` image tag and `SHA256SUMS` appear last, so a release page may briefly list only the platforms that are ready.

| Artifact | Details |
| :--- | :--- |
| **Native packages** | Six: Linux, macOS, and Windows for AMD64 and ARM64, named `lumen-v<version>-<platform>.<tar.gz or zip>` |
| **Package contents** | Both binaries (`lumen`, `lumenctl`), `config/`, `deploy/`, `docs/`, the changelog, release notes, security policy, and an internal file manifest |
| **Checksums** | One `SHA256SUMS` file, plus a `.sha256` file per archive |
| **Provenance** | GitHub build attestations for the archives |
| **Container image** | `ghcr.io/struktsource/lumen-dns` for `linux/amd64` and `linux/arm64`, with provenance and SBOM. Image signing is still pending |

Before anything is published, every release tag runs the full gate: native tests on all six platforms, native container runtime checks on both architectures, and the Kubernetes smoke test. Evidence is tracked in the [compatibility matrix](../deployment/compatibility.md#release-evidence).

## Verify a download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.7-<platform>.<extension> --repo StruktSource/lumen-dns
```

- On macOS without `sha256sum`, use `shasum -a 256 -c` with the matching `.sha256` file.
- `gh attestation verify` proves the file was built by this repository's release workflow. It does not make a compromised build safe.

## Upgrade

1. Read the [changelog](../../CHANGELOG.md) and the release's upgrade notes.
2. Replace **both** `lumen` and `lumenctl` from the same archive. Never mix versions.
3. Container and Helm users should **pin** the image tag (for example `0.5.7`) rather than `latest`.
4. Validate your config with the new binary: `lumen --config FILE --check`.
5. In [managed mode](../guides/managed-mode.md), the database migrates itself on first start. A database from a newer Lumen is rejected, so back it up first.

## Contributor notes

- New source files carry `SPDX-License-Identifier: Apache-2.0`, and contributions are licensed Apache-2.0.
- Embedding the Git revision and target in binaries, reproducible-release verification, and signed images remain release-hardening work.
- Local `./scripts/dev.sh release` runs checks and builds. It **never publishes** a release.

## Related

- [Changelog](../../CHANGELOG.md)
- [Contributing](../../CONTRIBUTING.md)
- [Roadmap](roadmap.md)

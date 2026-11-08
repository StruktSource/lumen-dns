# Lumen 0.5.6

Lumen 0.5.6 is a release-pipeline update on top of 0.5.5. The application itself is unchanged.

## Highlights

- Step-by-step publishing: each platform package and each container architecture is published as soon as it is built and tested, so finished downloads are available while slower platforms complete.
- Container images are built and tested natively on amd64 and arm64.
- `SHA256SUMS` now uses Unix line endings, so `sha256sum --check` works for the Windows archives too.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.6-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- No configuration or data changes since 0.5.5.
- Replace both `lumen` and `lumenctl` from the same archive.
- Container and Helm users should pin image tag `0.5.6`.

Lumen remains pre-release software. Test it on the target network before wider use. See `CHANGELOG.md` for the full summary.

# Lumen 0.5.7

Lumen 0.5.7 adds an opt-in query history and a console in five languages, and gives the documentation a complete rewrite. DNS behavior is unchanged.

## Highlights

- **Query history, opt-in.** Off by default. Choose *recent only* (in memory) or *saved* for 1 to 90 days, either anonymous or with the device and address. Search, filter, and delete it on the Activity page, or use `lumenctl history`. Saving happens off the DNS path, so answers are never delayed.
- **Console in English, German, Italian, Spanish, and Dutch.** The setup wizard asks for a language first. Everyone can pick their own under *My account*, and administrators set the default under *Users & access*.
- **New documentation.** A quick start, a concepts guide, and task-based guides, reorganized into folders. Start at `docs/README.md`.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.7-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- No configuration changes since 0.5.6. The state database upgrades itself to schema 6 on first start, so back it up first: an older Lumen cannot open it afterwards.
- Query history stays off until an administrator turns it on.
- Replace both `lumen` and `lumenctl` from the same archive.
- Container and Helm users should pin image tag `0.5.7`.
- Documentation links moved. If you bookmarked a file under `docs/`, start from `docs/README.md`.
- Some longer help texts on the DNS settings and Filtering pages are not translated yet and appear in English.

Lumen remains pre-release software. Test it on the target network before wider use. See `CHANGELOG.md` for the full summary.

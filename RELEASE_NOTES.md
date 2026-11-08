# Lumen 0.5.7

Lumen 0.5.7 is a documentation release on top of 0.5.6. The application itself is unchanged.

## Highlights

- The documentation was rewritten for newcomers and sorted into folders: getting started, guides, deployment, reference, design, and project. Start at `docs/README.md`.
- New pages: a quick start, a plain-language concepts guide, "Serve your network", encrypted DNS, resolver modes, a `lumen` and `lumenctl` command reference, and DNSSEC and trust anchors.
- The roadmap, progress checklist, and product plan are merged into one `docs/project/roadmap.md`.
- The Docker, Compose, Proxmox, Unraid, and Raspberry Pi pages were merged into shorter guides.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.7-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- No configuration or data changes since 0.5.6.
- Replace both `lumen` and `lumenctl` from the same archive.
- Container and Helm users should pin image tag `0.5.7`.
- Documentation links moved. If you bookmarked a file under `docs/`, start from `docs/README.md`.

Lumen remains pre-release software. Test it on the target network before wider use. See `CHANGELOG.md` for the full summary.

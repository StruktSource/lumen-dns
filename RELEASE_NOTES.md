# Lumen 0.5.8

Lumen 0.5.8 makes block lists painless and lets forward mode use several providers at once.

## Highlights

- **Lists install in the background.** Installing, removing, adding or editing a list asks you to confirm, then loads without a draft or an *Apply* bar. DNS keeps working, and nothing restarts: no listener restart, no closed connections, no cleared caches.
- **No more re-downloading.** Changing the resolver mode, an upstream, or another list no longer downloads the lists you already have. Only new, changed or due lists are fetched.
- **Cancel a download.** The progress panel has a *Cancel* button. Nothing changes if you press it, and what was already downloaded is kept.
- **Up to 8 providers, ranked.** Pick several bundled providers, rank them, and choose *ranked fallback*, *fastest first*, *round-robin*, or *race*. A provider that is down is skipped for a short while.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.8-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- No configuration or data changes since 0.5.7. Existing forward settings keep their old behavior until you choose a strategy.
- Downloaded lists are kept in memory only, so the first start after an upgrade downloads them once.
- Replace both `lumen` and `lumenctl` from the same archive.
- Container and Helm users should pin image tag `0.5.8`.
- Known limit: if a provider's *first* transport is silently blocked (for example a firewall dropping QUIC), that provider can fail as a whole. Other providers still answer. Choose HTTPS or TLS for it on such a network.
- Some longer help texts on the DNS settings and Filtering pages are not translated yet and appear in English.

Lumen remains pre-release software. Test it on the target network before wider use. See `CHANGELOG.md` for the full summary.

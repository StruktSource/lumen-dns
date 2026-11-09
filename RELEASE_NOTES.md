# Lumen 0.5.9

Lumen 0.5.9 makes multi-provider forwarding recover from upstream SERVFAIL responses and documents safe container updates.

## Highlights

- **SERVFAIL provider fallback.** When one upstream provider returns SERVFAIL, Lumen asks the next configured provider instead of returning the failure to the client.
- **Less repeat delay.** A provider that returns SERVFAIL rests for 10 seconds, so each repeated query does not pay for the same failed path.
- **Safe Docker updates.** The Docker guide now backs up the stopped state volume, validates the new image, tests UDP and TCP, and explains rollback when a database schema changed.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.9-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- No configuration or database schema changes since 0.5.8.
- Replace both `lumen` and `lumenctl` from the same archive.
- Container and Helm users should pin image tag `0.5.9` and back up `/var/lib/lumen` before recreating the container.
- NXDOMAIN, usable DNS answers, and local DNSSEC validation failures remain final. Only an upstream SERVFAIL joins connection and timeout errors as a reason to try another provider.

Lumen remains pre-release software. Test it on the target network before wider use. See `CHANGELOG.md` for the full summary.

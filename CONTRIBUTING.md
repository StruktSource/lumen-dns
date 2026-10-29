# 🤝 Contributing to Lumen

## Before code

1. Read [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).
2. Open an issue before large work. State problem, security impact, and tests.
3. Keep one pull request focused on one change.

## Checks

```bash
./scripts/dev.sh check
```

On Windows PowerShell, run `.\scripts\dev.ps1 check`.

Documentation-only pushes and pull requests skip CI. Mixed code and documentation
changes run the full checks; manual CI runs remain available. Version tags still
trigger the release workflow.

This checks format, Clippy, and offline tests using the committed lockfile. Tests
need IPv4/IPv6 loopback sockets. CI defines Linux, macOS, Windows, MSRV, audit,
and fuzz jobs. See [verification](docs/verification.md) for commands and limits.

Run `cargo audit` after dependency changes. DNS/config changes also need fuzz
smoke runs; the fuzz workspace has its own committed lockfile. Keep protocol
regressions local and deterministic. Do not make CI depend on public DNS.

## Rules

- Keep DNS parsing bounded and fuzzable. `unsafe` is forbidden.
- Do not add telemetry, network calls, or stored data without docs and review.
- Add regression tests for bugs and tests for behavior changes.
- Keep config, API, and storage changes compatible within minor releases.
- Never commit secrets, query logs, private lists, or user configuration.

## Commits

Use short conventional subjects: `feat(resolver): add cache lookup`.
Explain why in pull request text. Contributions are Apache-2.0.

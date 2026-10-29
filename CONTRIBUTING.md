# 🤝 Contributing to Lumen

## Before code

1. Read [architecture](docs/architecture.md) and [threat model](docs/threat-model.md).
2. Open an issue before large work. State problem, security impact, and tests.
3. Keep one pull request focused on one change.

## Checks

```bash
./scripts/dev-macos.sh check
```

This checks format, Clippy, and tests. CI checks Linux, macOS, and Windows.

## Rules

- Keep DNS parsing bounded and fuzzable. `unsafe` is forbidden.
- Do not add telemetry, network calls, or stored data without docs and review.
- Add regression tests for bugs and tests for behavior changes.
- Keep config, API, and storage changes compatible within minor releases.
- Never commit secrets, query logs, private lists, or user configuration.

## Commits

Use short conventional subjects: `feat(resolver): add cache lookup`.
Explain why in pull request text. Contributions are Apache-2.0.

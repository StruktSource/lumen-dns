# 🤝 Contributing to Lumen

Thanks for helping! Bug reports, interoperability tests, documentation fixes, and reproducible deployment feedback are as valuable as code. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Ways to help

- **Report a bug or idea** by opening an issue. For anything touching security, see the [security policy](SECURITY.md) and report privately.
- **Test on real hardware.** Platforms like Proxmox, Unraid, and Raspberry Pi are not yet validated. See the [compatibility matrix](docs/deployment/compatibility.md).
- **Improve the docs.** The [documentation index](docs/README.md) shows how they are organized.
- **Translate the console.** Languages are plain data files. See [Languages and translations](docs/guides/translations.md).
- **Send code.** Read the steps below first.

## Before you write code

1. Read the [architecture](docs/design/architecture.md) and the [threat model](docs/design/threat-model.md).
2. **Open an issue before large work.** Describe the problem, its security impact, and how you will test it.
3. Keep each pull request focused on **one change**.

## Check your work

```sh
./scripts/dev.sh check
```

On Windows PowerShell, run `.\scripts\dev.ps1 check`. This checks formatting, Clippy (warnings are errors), and offline tests using the committed lockfile. Tests need IPv4 and IPv6 loopback sockets.

Also:

- Run `cargo audit` after dependency changes.
- DNS and config changes need fuzz smoke runs. The fuzz workspace has its own committed lockfile.
- Keep protocol regressions local and deterministic. **Never make CI depend on public DNS.**

CI defines Linux, macOS, Windows, minimum-Rust, audit, and fuzz jobs. Commands and limits are in the [verification record](docs/project/verification.md).

**CI behavior:** documentation-only pushes and pull requests (Markdown, `docs/`, `.agent/`, and license-only changes) skip CI. Mixed code and documentation changes run the full checks. Manual CI runs are available, and version tags trigger the release workflow.

## Rules for code

- Keep DNS parsing bounded and fuzzable. `unsafe` is forbidden.
- Do not add telemetry, network calls, or stored data without documentation and review.
- Add regression tests for bugs and tests for behavior changes.
- Keep config, API, and storage changes compatible within minor releases.
- **Never commit** secrets, query logs, private lists, or user configuration.
- New source files carry `SPDX-License-Identifier: Apache-2.0`.

## Writing documentation

- Write for a newcomer first: explain a term the first time, and link to [Concepts](docs/getting-started/concepts.md) rather than repeating it.
- Put task-based how-tos in `docs/guides/`, lookup tables in `docs/reference/`, and platform steps in `docs/deployment/`.
- Never mark an unrun platform check or a planned feature as shipped. Back claims with the [verification record](docs/project/verification.md).
- Use relative links and check that they resolve before you submit.

## Commits and pull requests

Use short conventional subjects, such as `feat(resolver): add cache lookup` or `docs: clarify port 53`. Explain **why** in the pull request description. Contributions are licensed under Apache-2.0.

## Releases

Maintainers handle releases. See [Versioning and releases](docs/project/versioning.md).

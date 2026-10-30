# Compatibility matrix

Status terms:

- **Supported**: native runtime tests pass and the target is in release scope.
- **Experimental**: integration exists, but enough runtime evidence is not yet available.
- **Build-only**: compilation passed; runtime behavior was not proved.
- **Planned**: no complete build or runtime proof exists.

Lumen is pre-release. No platform is marked supported yet.

| Target | Status | Current evidence |
| --- | --- | --- |
| Linux AMD64 native | Experimental | hosted build, tests, and config checks pass |
| Linux ARM64 native | Experimental | hosted build, tests, and config checks pass |
| macOS ARM64 | Experimental | local M4 and hosted build, tests, and config checks pass |
| macOS AMD64 | Experimental | hosted build, tests, and config checks pass |
| Windows AMD64 | Experimental | hosted build, tests, and config checks pass |
| Windows ARM64 | Experimental | hosted experimental build, tests, and config checks pass |
| OCI AMD64/ARM64 | Experimental | local ARM64 plus hosted native runtime checks pass |
| Podman rootless | Experimental | hosted rootless build, config, read-only, and UID checks pass |
| Kubernetes/Helm | Experimental | local raw/Helm and hosted raw-manifest UDP/TCP smoke pass |
| Proxmox LXC | Planned | generic Linux guidance only; no Proxmox host test |
| Unraid | Planned | OCI guidance only; no Unraid host test |
| Raspberry Pi ARM64 | Planned | covered by Linux ARM64 build, not hardware-tested |

The runner labels were checked on 2026-10-30 against the
[official GitHub-hosted runner table](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):
`ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15`, `macos-15-intel`,
`windows-2025`, and `windows-11-arm`. Hosted evidence above comes from
[CI run 41116220947](https://github.com/StruktSource/lumen-dns/actions/runs/41116220947).

All targets use the same workspace crates and `lumen` binary. Docker, Podman,
Kubernetes, Proxmox, and Unraid do not have separate DNS engines. Platform files
only set process, network, storage, and service-manager behavior.

# Compatibility matrix

Status terms:

- **Supported**: native runtime tests pass and the target is in release scope.
- **Experimental**: integration exists, but enough runtime evidence is not yet available.
- **Build-only**: compilation passed; runtime behavior was not proved.
- **Planned**: no complete build or runtime proof exists.

Lumen is pre-release. No platform is marked supported yet.

| Target | Status | Current evidence |
| --- | --- | --- |
| Linux AMD64 native | Experimental | local tests; native GitHub job configured |
| Linux ARM64 native | Experimental | native GitHub job configured; result pending |
| macOS ARM64 | Experimental | local M4 tests; native GitHub job configured |
| macOS AMD64 | Build-only | native GitHub job configured; result pending |
| Windows AMD64 | Build-only | native GitHub job configured; result pending |
| Windows ARM64 | Experimental | native experimental job configured; result pending |
| OCI AMD64/ARM64 | Experimental | ARM64 local runtime passed; AMD64 native CI pending |
| Podman rootless | Experimental | Linux CI smoke job configured; result pending |
| Kubernetes/Helm | Experimental | local Kind raw-manifest and Helm UDP/TCP smoke passed; hosted CI pending |
| Proxmox LXC | Planned | generic Linux guidance only; no Proxmox host test |
| Unraid | Planned | OCI guidance only; no Unraid host test |
| Raspberry Pi ARM64 | Planned | covered by Linux ARM64 build, not hardware-tested |

The runner labels were checked on 2026-10-30 against the
[official GitHub-hosted runner table](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):
`ubuntu-24.04`, `ubuntu-24.04-arm`, `macos-15`, `macos-15-intel`,
`windows-2025`, and `windows-11-arm`. A configured job is not a passing test.
Update this table only from completed CI or real-platform evidence.

All targets use the same workspace crates and `lumen` binary. Docker, Podman,
Kubernetes, Proxmox, and Unraid do not have separate DNS engines. Platform files
only set process, network, storage, and service-manager behavior.

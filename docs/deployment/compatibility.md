# Compatibility matrix

Which platforms Lumen runs on, and how much evidence backs each claim. Check this before deploying. Platform guides are listed in the [deployment index](README.md).

## How to read the status

| Status | Meaning |
| :--- | :--- |
| **Supported** | Native runtime tests pass and the target is in release scope |
| **Experimental** | Integration exists, but there is not yet enough runtime evidence |
| **Build-only** | Compilation passed; runtime behavior was not proved |
| **Planned** | No complete build or runtime proof exists |

Lumen is pre-release, so **no platform is marked supported yet**.

## Matrix

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

## Release evidence

Every release tag runs the full release gate before anything is published:
native tests on all six platforms, native OCI runtime checks on amd64 and
arm64, and the Kubernetes smoke test. Packages and images are published step by
step as each target passes. The latest verified release is
[v0.5.6](https://github.com/StruktSource/lumen-dns/releases/tag/v0.5.6)
([release run](https://github.com/StruktSource/lumen-dns/actions/runs/42484167179)):
six native packages with checksums and build provenance, plus a public
`ghcr.io/struktsource/lumen-dns` image index for `linux/amd64` and `linux/arm64`.
Check a download with `sha256sum --check SHA256SUMS --ignore-missing` and
`gh attestation verify <file> --repo StruktSource/lumen-dns`.

## Validation not yet done

These runs and tests have not been performed. Until they are, the targets stay
at the status shown above, and nothing here should be read as tested.

- **Windows ARM64**: only the hosted `windows-11-arm` runner has exercised it.
  There is no runtime test on a physical device, and it is not in the supported
  scope.
- **Proxmox LXC**: the guide has not been run on a Proxmox host, including
  container features, storage, and network setup.
- **Unraid**: the guide has not been run on an Unraid host, including template
  and share handling.
- **Raspberry Pi**: ARM64 is covered by the hosted Linux ARM64 runner only; no
  Raspberry Pi hardware has been used.
- **Public resolver reachability**: upstream provider endpoints are not tested
  from CI.
- **Long-running and failure behavior**: crash, power-loss, and native Windows
  service-control behavior are unverified.
- **Block-list disk cache on Windows**: the cache folder's owner-only permissions are
  applied on Unix only; Windows relies on the state directory's own access rules.
- **External login**: only a local test provider has been used. Authentik, Authelia,
  Pocket ID, Octelium, and Keycloak installations, and the console in real browsers and
  screen readers, have not been tried.
- **Client-IP preservation**: behind Kubernetes load balancers and NAT it
  depends on the cluster network and is not tested.

All targets use the same workspace crates and `lumen` binary. Docker, Podman,
Kubernetes, Proxmox, and Unraid do not have separate DNS engines. Platform files
only set process, network, storage, and service-manager behavior.

## Related

- [Deployment guides](README.md)
- [Verification record](../project/verification.md): the tests behind these statuses
- [Roadmap](../project/roadmap.md)

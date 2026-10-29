# Lumen TODO

Phase 1 resolver implementation is complete. See the detailed
[implementation checklist](docs/progress.md) and
[verification record](docs/verification.md).

## Next: Phase 2 filtering

- [ ] Define normalized domain rules and allow/block precedence.
- [ ] Add global rules and explainable filter outcomes before DNS cache lookup.
- [ ] Add client, subnet, device, group, and profile policy selection.
- [ ] Add bounded list imports for hosts, domains, and Adblock DNS formats.
- [ ] Add validated atomic list refresh, rollback, and schedules.

## Release gates and later work

- [ ] Extended DNS interoperability, DNSSEC conformance, and long-running soak tests.
- [ ] Independent security review and production memory/performance measurements.
- [ ] Trust-anchor rollover automation and certificate lifecycle tooling.
- [ ] Config reload/migrations, complete CLI, authenticated API, and optional UI.
- [ ] Signed multi-architecture images, SBOM, and reproducible-release checks.
- [ ] Deployment guides and backup/restore/upgrade tests.

Keep checkbox detail in `docs/progress.md`; do not mark unrun platform checks or
planned features as shipped.

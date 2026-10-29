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

## UI timing and recommended order

1. Finish the first filtering slice: global allow/block rules, precedence, and
   explainable decisions with regression tests.
2. Begin UI design/prototyping alongside the remaining Phase 2 work. Use mock
   data for an overview, list management, and settings; keep the prototype local
   and management API access disabled.
3. Build the functional UI during Phase 3, once configuration persistence/reload
   and an authenticated, scoped management API are ready. Start with aggregate
   status, then settings and filtering controls. Keep query history off by default.

This is a recommended dependency order, not a dated delivery commitment. UI
prototyping need not wait for every advanced filtering feature. The existing
first-release commitment remains a blank UI shell; a functional UI is later scope.

## Release gates and later work

- [ ] Extended DNS interoperability, DNSSEC conformance, and long-running soak tests.
- [ ] Independent security review and production memory/performance measurements.
- [ ] Trust-anchor rollover automation and certificate lifecycle tooling.
- [ ] Config reload/migrations, complete CLI, authenticated API, and optional UI.
- [ ] Signed multi-architecture images, SBOM, and reproducible-release checks.
- [ ] Deployment guides and backup/restore/upgrade tests.

Keep checkbox detail in `docs/progress.md`; do not mark unrun platform checks or
planned features as shipped.

# Lumen TODO

Phases 1 and 2 resolver/filtering implementation are complete. See the detailed
[implementation checklist](progress.md) and
[verification record](verification.md).

## Phase 2 filtering: implemented

- [x] Define normalized domain rules and allow/block precedence.
- [x] Add global rules and explainable filter outcomes before DNS cache lookup.
- [x] Add client, subnet, device, group, and profile policy selection.
- [x] Add bounded list imports for hosts, domains, and Adblock DNS formats.
- [x] Add validated atomic list refresh, rollback, and schedules.

## Phase 3 local state and control: implemented

- [x] Add versioned SQLite config and device persistence with migrations.
- [x] Add staged config apply, runtime validation, reload, and rollback.
- [x] Add cross-platform local CLI config, device, filter, status, and shutdown controls.

## Phase 3 next work

1. [x] Build the loopback authenticated `/v1` management API on the completed
   persistence, reload, migration, and local-control base. Add scoped roles,
   bounded tokens, request limits, and durable audit events.
2. [x] Add extended privacy-safe Prometheus metrics, a ready Grafana dashboard,
   bounded signed HTTPS webhooks, and Home Assistant examples.
3. [x] Add embedded blank-shell hosting over HTTP and direct TLS HTTP/2, with a
   vendor-neutral reverse-proxy contract for HTTP/3.
4. Begin UI design/prototyping. Use mock
   data for an overview, list management, and settings; keep the prototype local
   and management API access disabled.
5. Build the functional UI during Phase 3, once configuration persistence/reload
   and an authenticated, scoped management API are ready. Start with aggregate
   status, then settings and filtering controls. Keep query history off by default.

This is a recommended dependency order, not a dated delivery commitment. UI
prototyping need not wait for every advanced filtering feature. The existing
first-release commitment remains a blank UI shell; a functional UI is later scope.

## Release gates and later work

- [ ] Extended DNS interoperability, DNSSEC conformance, and long-running soak tests.
- [ ] Independent security review and production memory/performance measurements.
- [ ] Trust-anchor rollover automation and certificate lifecycle tooling.
- [ ] Optional functional UI and opt-in query history. Authenticated API, scoped
  audit events, extended metrics, and integration examples are implemented.
- [ ] Record passing native multi-OS/architecture and multi-arch OCI release runs.
- [ ] Add keyless image signing and reproducible-build comparison; SBOM/provenance is configured.
- [ ] Run real Proxmox, Unraid, Raspberry Pi, Podman ARM64, and dual-stack Kubernetes tests.
- [ ] Add backup/restore/upgrade/removal tests when persistent state exists.

Keep checkbox detail in `progress.md`; do not mark unrun platform checks or
planned features as shipped.

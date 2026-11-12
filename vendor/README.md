# Vendored dependencies

`hickory-net` 0.26.3 with one change, marked `LUMEN PATCH` in `src/dnssec/mod.rs`:

A DS answer that includes the child zone's own SOA (parent and child served by the same
name servers, as with Google's `l.google.com`) was validated through the very DS record
being asked for. That loops until `exceeded max validation depth`, which then fails
unrelated validations and made `google.com` and `safebrowsing.google.com` return SERVFAIL
in about half of fresh processes (validation order is randomized per process). The SOA is
now skipped, and the delegation is judged from the parent side.

Remove this patch and the `[patch.crates-io]` entry in the root `Cargo.toml` once the fix is
in an upstream hickory release.

## `hickory-server` 0.26.3

Three changes, all marked `LUMEN PATCH`:

- `Cargo.toml`: the optional `sqlite` store depends on `rusqlite` 0.41 (upstream asks for 0.39). Two SQLite bindings cannot link into one binary, and Lumen is pinned to 0.41.1 for RUSTSEC-2026-0459. The store compiles unchanged.
- `zone_handler/catalog.rs` and `store/in_memory/mod.rs`: an `IXFR` query is treated as a transfer under the same policy as `AXFR` and answered in AXFR format, which RFC 1995 section 4 allows. Without it, an IXFR query skipped the transfer policy.

- `store/sqlite/mod.rs`: `set_tsig_signers` is no longer limited to tests, so Lumen can install its TSIG keys.

Remove this directory and its `[patch.crates-io]` entry once upstream supports both.

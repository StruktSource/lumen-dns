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

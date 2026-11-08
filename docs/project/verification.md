# Verification record

An honest list of what has been tested, how, and what has **not** been established. Claims elsewhere in these docs must trace back to this page or to the [compatibility matrix](../deployment/compatibility.md).

> [!NOTE]
> Passing checks are evidence, not proof of security or production readiness. Unless a section says otherwise, results come from macOS ARM64 (Apple M4) and from GitHub-hosted CI.

**On this page:** [Run the checks yourself](#run-the-checks-yourself) · [What the tests cover](#what-the-tests-cover) · [Results by date](#results-by-date) · [Public-network smoke check](#public-network-smoke-check) · [Not established](#not-established)

## Run the checks yourself

Everyday checks (format, Clippy with warnings denied, and offline tests with the committed lockfile):

```sh
./scripts/dev.sh check
cargo +1.88.0 check --workspace --all-targets --locked    # minimum Rust version
cargo build --workspace --release --locked
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/forward.example.toml --check
```

Tests need IPv4 and IPv6 loopback sockets, so run them outside restrictive sandboxes. CI never depends on public DNS.

### Fuzzing

Fuzzing needs nightly Rust and `cargo-fuzz` 0.13.2. The fuzz workspace has its own committed lockfile, and CI checks its metadata with `--locked` first.

```sh
cargo +nightly install cargo-fuzz --version 0.13.2 --locked
cargo +nightly metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 > /dev/null
mkdir -p fuzz/corpus/dns_wire fuzz/corpus/config
cp fuzz/seeds/dns_wire/* fuzz/corpus/dns_wire/
cp fuzz/seeds/config/* fuzz/corpus/config/
ASAN_OPTIONS=quarantine_size_mb=32:thread_local_quarantine_size_kb=64 \
  cargo +nightly fuzz run dns_wire -- -max_total_time=15 -max_len=65535 -rss_limit_mb=512
ASAN_OPTIONS=quarantine_size_mb=32:thread_local_quarantine_size_kb=64 \
  cargo +nightly fuzz run config -- -max_total_time=15 -max_len=65536 -rss_limit_mb=512
ASAN_OPTIONS=quarantine_size_mb=32:thread_local_quarantine_size_kb=64 \
  cargo +nightly fuzz run filter_list -- -max_total_time=15 -max_len=65536 -rss_limit_mb=512
```

Fuzz memory figures describe the instrumented test processes, **not** Lumen's runtime memory. The AddressSanitizer quarantine is capped at 32 MiB to keep freed allocations within the 512 MiB fuzz budget; an early run hit that instrumentation limit before the cap was added.

### Container smoke test

```sh
docker build --tag lumen:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges lumen:local --config /etc/lumen/lumen.toml --check
```

## What the tests cover

Tests bind ephemeral local sockets and use in-process DNS fixtures. They do not need public DNS or trust any remote service.

**Protocols and transports**

- UDP and TCP queries, plus persistent TCP framing, on IPv4 and IPv6
- DoT, DoH (HTTP/2 GET and POST), and DoQ on IPv4 and IPv6 with generated test keys
- Malformed queries, compressed response names, EDNS, short packets, name loops, invalid flags, classes, and types, trailing bytes, and generated random inputs
- UDP truncation with TCP fallback

**Resolution and DNSSEC**

- Encrypted upstream forwarding over TLS, HTTPS, and QUIC. Wrong certificate names fail, and test CA trust is explicit because verification is never skipped
- DNSSEC-valid data sets AD. Tampered data, unsigned-after-signing data, and wrong trust keys fail. Signed denial returns NXDOMAIN
- Positive, NXDOMAIN, and NODATA caching, cache hits avoiding upstream work, and TTL expiry causing new upstream queries
- Root, TLD, and authority iterative delegation, where unrelated glue cannot supply a forged cached answer, cached lookups avoid network work, and recursion depth is bounded. (A test-only runtime remaps authority IPs to loopback ports. Production authority-address filters are unchanged)

**Limits and lifecycle**

- Query timeouts, rate limits, connection caps, shared resolver concurrency, rate-table capacity, and bounded cleanup scans
- Atomic startup failure, aggregate metrics, cancellation and shutdown, socket reuse, and a 256-query load regression in batches of eight
- Schema rejection, nested unknown fields, example configs, relative file paths, bounded config reads, and strict daemon argument parsing

**Filtering**

- Normalized exact, suffix, and IDNA rules, profile, global, and list precedence, device, group, subnet, and default selection, category and UTC overnight schedules, and all block actions
- Large CNAME response budgets, and malformed or oversized imports
- HTTPS certificate verification, status, redirect, compression, and streaming size checks, and private-address rejection
- Multi-list failure atomicity, concurrent snapshot readers, periodic refresh, and rollback hold
- Blocking over all five transports on IPv4 and IPv6, per-client decisions before shared cache hits, failed startup, refresh, and rollback

## Results by date

### 2026-10-29: Phase 1 resolver core

Native host macOS ARM64 and OrbStack Linux ARM64.

| Check | Result |
| :--- | :--- |
| `./scripts/dev.sh check` | Format, Clippy, 21 offline tests, and doc tests passed |
| Minimum Rust (1.88) all-targets check | Passed, including tests |
| Release build | Daemon and CLI passed |
| `cargo audit` | No advisories in 213 workspace dependencies; none in 115 fuzz dependencies |
| DNS wire fuzz smoke (ASan) | 375,493 inputs in 15 s, no crash, peak instrumented RSS 118 MiB |
| Config fuzz smoke (ASan) | 417,910 inputs in 15 s, no crash, peak instrumented RSS 139 MiB |
| Docker image | Native Linux ARM64 image built. Ran as UID 65532 with a read-only filesystem, no network, and all capabilities dropped. UDP and TCP IPv4 and IPv6 listeners started, and SIGTERM stopped the service |
| Release packaging | Native ZIP with both binaries, docs, config, and SHA-256 checksum. Archive integrity checked |
| Docs, shell, YAML | Local links, shell syntax, workflow YAML, and `git diff --check` checked |

### 2026-10-30: Phase 2 filtering and issues #3 to #5

- `./scripts/dev.sh check` passed with **42 tests**, plus format, Clippy, and doc tests. Rust 1.88 and release builds passed. All three supplied configs passed `--check`.
- `lumenctl filter-explain` returned a category block inside the example UTC bedtime window and allowed the same name outside it.
- A release-daemon smoke test confirmed that `SIGUSR1` published a changed local list, `SIGUSR2` restored the previous one, both were counted in metrics, logs and metrics omitted queried names by default, and `SIGTERM` exited cleanly.
- Both RustSec audits passed (253 workspace and 169 fuzz dependencies). The first run found [RUSTSEC-2026-0383](https://rustsec.org/advisories/RUSTSEC-2026-0383), and both lockfiles now resolve `webpki-root-certs` 1.0.10.
- Filter-list fuzz smoke (ASan): 182,056 inputs in 16 s, no crash. Config fuzz smoke: 81,200 inputs, no crash.
- A draft bypass using unusual wire labels was **fixed**: decisions now use decoded label bytes, preserving suffix boundaries even for escaped dots and non-UTF-8 labels. This was a targeted analysis, not a full independent audit.
- **Issue #3** (timeout fallback) added a fixture proving one identified recursive timeout invokes the fallback once, and tests proving recursion-limit and budget failures do not. Config tests cover explicit enablement, budgets, TLS identity, and listener-loop rejection.
- **Issue #4** made `config/lumen.toml` the minimal release default and renamed the forwarding and filtering samples to `.example.toml`. Tests assert loopback listeners and clients, DNSSEC recursion, empty filters and upstreams, disabled fallback and metrics, schema-1 compatibility, and successful startup.
- **Issue #5** added the provider catalog. Public provider reachability was **not tested**.

### 2026-10-30: local deployment (Apple M4, OrbStack 29.8.2)

The Linux ARM64 image built and passed:

- UID 65532, read-only root filesystem, config validation, startup, and clean `SIGTERM` shutdown
- Real UDP and TCP DNS queries through mapped host ports (`scripts/dns-smoke.py`)
- Docker Compose config, startup on host port 53, UDP and TCP replies, and clean removal
- Raw Kubernetes manifests in Kind 0.33.0 with rollout, Service, ConfigMap, NetworkPolicy, readiness probe, and a UDP and TCP smoke pod
- Helm chart install in a separate namespace with the same smoke checks
- Both Kubernetes deployments ran as UID 65532, rejected root-filesystem writes, and had service-account token mounting disabled
- The local release script, macOS ARM64 archive, required contents, SHA-256 verification, and unsafe version-string rejection

The temporary Compose stack and Kind cluster were removed. A multi-architecture local build was stopped early, and the other architectures were left to hosted CI.

### 2026-10-30: hosted platforms

[CI run 41116220947](https://github.com/StruktSource/lumen-dns/actions/runs/41116220947) passed native build, test, and config checks on Linux AMD64 and ARM64, macOS AMD64 and ARM64, Windows AMD64, and experimental Windows ARM64. Native container runtime checks passed on Linux AMD64 and ARM64, rootless Podman checks passed, and the Kind job passed Helm lint and render, raw-manifest rollout, and deterministic UDP and TCP queries through the ClusterIP Service.

Along the way CI exposed a Windows QUIC client socket error and a Linux TCP restart bind error. The DoQ test now supplies an explicitly bound socket, Unix TCP listeners set `SO_REUSEADDR`, and the shutdown regression restarts the actual service.

### 2026-10-31: providers, state, API, web hosting, recursion speed

- **Issue #7 (provider presets).** Full local check passed 48 tests, format, and Clippy. Coverage includes stable-ID expansion, address-family selection, TLS identity mapping, unknown-ID rejection, and combining presets with custom upstreams. Public provider reachability was not tested.
- **Issue #8 (automatic encrypted transport).** 51 tests, format, Clippy, doc tests, and Rust 1.88 checks passed. Coverage includes priority order, skipping unsupported transports, encrypted-only expansion, connection-failure failover, no failover after NXDOMAIN, and certificate-name rejection.
- **Local state and control.** Migration tests build a schema-1 database, migrate it through schema 3, preserve active config, stage and promote a revision, round-trip IPv4 and IPv6 devices, consume commands once, and verify Unix mode `0600`. The full check passed 50 tests. An end-to-end managed daemon test used loopback ports 55353 and 55354: a device update queued a reload and stayed running; a staged config targeting an occupied port made the daemon report the bind failure, restore the old listeners, and discard the candidate; status and queued shutdown also passed.
- **Management and observability.** 57 tests plus doc tests passed, including an authenticated loopback request, constant-time token hash matching, role routing, per-token rate limits, schema-3 audit migration, management config rejection cases, and extended metric output. Grafana JSON parsing passed. No live webhook or Home Assistant instance was contacted.
- **Embedded web hosting.** 61 tests plus doc tests passed, covering fixed routes, security headers, a real loopback HTTP request for the shell, release-config startup, listener collisions, and TLS 1.3 and HTTP/2 ALPN setup. Direct HTTPS was configuration-tested with a self-signed certificate. No browser or external reverse proxy was used.
- **Recursion speed (Issue #9, version 0.1.1).** 14 new resolver tests (deterministic coalescing, cancelled-leader recovery, refresh scheduling and budgets, priming, hedging, histogram shape). A mutation check confirmed the coalescing test fails (73 versus 4 upstream packets) when sharing is disabled. Public-internet results: [Performance](performance.md).

### 2026-11-08: query history, localization, and release 0.5.7

Local macOS ARM64 checks. These cover the new code only, and no hosted CI result is claimed here.

- **Saved query history.** Store tests cover the schema-5 to schema-6 upgrade without touching settings, saving, case-insensitive search across domain, device, and client, literal `%` in searches, paging, retention by age and by row cap, clearing, and the private defaults and validation of the history settings (including the older on/off flag). Console tests cover the modes, rejected input, anonymous rows without client or device, filters, URL-decoded search, paging, switching off while saved rows stay visible, administrator-only changes and deletion, audit entries that contain no domains, and a setting changed behind the daemon's back being applied. An end-to-end `lumen-core` test starts a real server, sends real UDP queries, and reads the rows back from SQLite: nothing is saved by default, anonymous mode stores no client, a `lumenctl`-style change to full detail is applied within seconds, and switching off stops recording.
- **`lumenctl history`.** Strict parsing tests for `status`, `set`, and `clear`, including out-of-range days and unknown modes.
- **Localization.** The console language setting is public until chosen, validated, clearable, and saved by the setup wizard. A test checks that the language list in the UI matches the server, that every catalog is valid, has the same entries and placeholders as the others, and only contains text that still exists in the console. The real console scripts were also loaded in a stubbed DOM and rendered in all five languages (sign-in page, setup welcome step, Activity in each history mode, My account) with the expected language picked by saved choice, console default, and browser language. No real browser was used.
- **Config cleanup.** `config/lumen.toml`, `deploy/lumen.toml`, and both example configs pass `lumen --check`. Only comments changed.
- **Not covered.** No real browser session, no screen-reader check, no review of translations by native speakers, and no long-running test of the history writer under sustained load.

### 2026-11-08: releases 0.5.5 and 0.5.6

- **0.5.5:** local checks passed (release metadata, format, Clippy, 93 workspace tests, release build, binary versions, repeatable macOS ARM64 archive and SHA-256). The hosted release run succeeded with six native packages, checksums, and attestations (all six verified), plus a `linux/amd64` and `linux/arm64` image index. The GHCR package had to be made public by org policy before `docker pull` worked.
- **0.5.6:** the `SHA256SUMS` in 0.5.5 had Windows line endings on the Windows entries, which broke `sha256sum -c`. Fixed by writing LF at the source and stripping CR in the workflow. Releases now publish each platform as soon as it is tested.

## Public-network smoke check

A temporary daemon with a **30-second query deadline** was started and later stopped cleanly. Native recursive mode returned:

| Query | Result | Observed duration |
| :--- | :--- | :--- |
| `cloudflare.com A +dnssec` | NOERROR, AD set | 8.06 s |
| `example.com A +dnssec` | NOERROR, AD set | 1.94 s |
| `dnssec-failed.org A +dnssec` | SERVFAIL, AD clear | 18.29 s |

All three answered before the deadline. This is a dated smoke check, not a latency guarantee or a CI dependency. The normal default deadline is 10 seconds, and slower recursion fails within it. Root servers were also reached over UDP and TCP.

## Not established

- External DNS and DNSSEC conformance suites, extended soak and abuse tests, and production memory and performance measurements
- Native Windows managed-control runtime on real hardware, and crash or power-loss behavior on any platform
- Real third-party list compatibility beyond fixtures, and public provider and fallback reachability
- Real Proxmox, Unraid, Raspberry Pi, and dual-stack Kubernetes hosts, and Kubernetes client-IP preservation
- Automatic trust-anchor rollover, signed images, reproducible releases, and **independent security review**

See the [roadmap](roadmap.md) for how these are tracked.

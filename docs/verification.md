# Verification

## Phase 3 management and observability — 2026-10-31

Native validation: macOS ARM64. The full locked workspace test run passed 57
tests plus doc tests. This includes an authenticated loopback API request,
constant-time token hash matching, role routing, per-token rate bounds, schema-3
audit migration/round-trip, management config rejection cases, and extended
metric output. Format, Clippy with warnings denied, Grafana JSON parsing, and
`git diff --check` pass.

The API is disabled by default, managed-mode-only, and loopback-only. Headers,
bodies, connections, rates, tokens, webhooks, and audit retention are bounded.
Audit records omit tokens and bodies. Webhook configuration enforces HTTPS port
443, no credentials/fragments, public WebPKI roots, no redirects/proxy, a short
deadline, HMAC-SHA256 bodies, and a bounded best-effort queue. No live external
webhook or Home Assistant instance was contacted. Grafana and Home Assistant
files were validated as local examples only. Remote API exposure is not supported.

## Phase 3 local state and control — 2026-10-31

Native validation: macOS ARM64. `lumen-store` migration tests create a schema-1
database, migrate it through schema 3, preserve active config, stage/promote a new
revision, round-trip IPv4/IPv6 devices, consume commands once, and verify Unix
mode `0600`. Strict CLI parsing covers config, device, reload, status, filter,
and shutdown commands.

The full local `./scripts/dev.sh check` passed format, Clippy with warnings
denied, 50 tests, and doc tests. Rust 1.88 workspace/all-target compilation also
passed with the locked dependency graph.

An end-to-end managed daemon test used loopback ports 55353/55354. Device update
queued reload and stayed running. A staged config then targeted an occupied port;
the daemon reported the bind failure, restored the old 55353 listeners, discarded
the candidate, and kept the prior config active. Local status and queued shutdown
also passed. Listener restart has a brief bind gap and resets DNS caches. Native
Windows managed-control runtime and crash/power-loss testing remain unverified.

## Phase 2 — 2026-10-30

Native validation: macOS ARM64. Phase 1 results below are historical and are not
new Linux/Windows results for Phase 2.

Issue #7 provider presets were validated on macOS ARM64 on 2026-10-31. The full
local check passed 48 tests, format, and Clippy. The preset forwarding example
also passed daemon config validation. Coverage includes stable-ID expansion,
address-family selection, TLS identity mapping, unknown-ID rejection, and
rejection of mixed preset and custom upstream configuration. Public provider
reachability was not tested.

Issue #8 automatic encrypted transport selection was validated on macOS ARM64
on 2026-10-31. The full local check passed 51 tests, format, Clippy, and doc
tests. Rust 1.88 workspace checks and automatic provider example validation also
passed. Offline coverage checks priority order, unsupported transport skipping,
encrypted-only expansion, connection-failure failover, no failover after
NXDOMAIN, and certificate-name rejection. Public provider reachability was not
tested.

- `./scripts/dev.sh check`: format, Clippy with warnings denied, **42 tests**,
  and doc tests pass. Socket tests run outside the restricted filesystem/network
  sandbox because its loopback binds return `Operation not permitted`.
- `cargo +1.88.0 check --workspace --all-targets --locked`: passes.
- `cargo build --workspace --release --locked`: daemon and CLI pass.
- All three supplied configs pass release `lumen --config ... --check`.
- `lumenctl filter-explain` returns a category block during the example UTC
  bedtime window and allows the same name outside it.
- Release-daemon loopback smoke: SIGUSR1 publishes a changed local list,
  SIGUSR2 restores the previous list, metrics count both, logs/metrics omit
  queried names with default settings, and SIGTERM exits cleanly.
- Native release ZIP builds and passes integrity checking with relocated
  roadmap/TODO, filter guide, and example config included.
- Both RustSec audits pass: 253 workspace and 169 fuzz dependencies. The first
  run found [RUSTSEC-2026-0383](https://rustsec.org/advisories/RUSTSEC-2026-0383);
  both lockfiles now resolve `webpki-root-certs` 1.0.10.
- Filter-list AddressSanitizer fuzz smoke: 182056 inputs in 16 seconds with
  a 15-second time budget and 64 KiB max input; no crash. macOS `atos`
  symbolization emitted warnings; the fuzz run itself exited successfully.
- Config AddressSanitizer fuzz smoke: 81200 inputs in 16 seconds, no crash.
- Local Markdown links and `git diff --check` pass.

Coverage includes normalized exact/suffix/IDNA rules; profile/global/list
precedence; device/group/subnet/default selection; category and UTC overnight
schedules; all block actions; large CNAME response budgets; malformed/oversized
imports; HTTPS certificate verification, status/redirect/compression/streaming
size checks, and private-address rejection; multi-list failure atomicity,
concurrent snapshot readers, periodic refresh, and rollback hold. Service tests
exercise blocking over all five transports on IPv4/IPv6, per-client decisions
before shared cache hits, failed startup, refresh, and rollback.

A draft bypass involving unusual wire labels was fixed: production decisions
now use decoded label bytes, preserving suffix boundaries even for escaped dots
and non-UTF-8 labels. The targeted Attack Path Analysis record is retained by the
Codex Security plugin; this was not a full independent security audit.

Not established: native Windows/Linux Phase 2 runtime, hosted CI, real third-party
feed compatibility, extended soak, or production performance. Windows runtime
refresh/rollback is available through the Rust API, not a daemon CLI channel.
Rollback snapshots are memory-only, schedules are UTC-only, and filtering checks
question names rather than upstream CNAME chains. See [filtering](filtering.md).

Issue #3 adds a local fixture proving that one identified recursive timeout
invokes the configured fallback once, plus error-provenance tests proving that
recursion-limit and query-budget failures do not invoke it. Config tests cover
explicit enablement, deadline budgets, TLS identity, and direct listener-loop
rejection. A Codex Security diff scan reviewed all five changed runtime/config
files and found no reportable issue. Public fallback reachability was not tested.

Issue #4 makes `config/lumen.toml` the minimal release default and renames the
active forwarding/filtering samples to `.example.toml`. Tests assert loopback
listeners/clients, DNSSEC recursion, empty filters/upstreams, disabled fallback,
disabled metrics, schema-1 compatibility, and successful startup. The default
and both examples pass `lumen --check`.
A Codex Security diff scan reviewed the six changed config surfaces and found no
reportable issue.

## Phase 1 verification

Verification date: **2026-10-29**. Native host: macOS ARM64. Container runtime:
OrbStack, Linux ARM64. These results do not certify other platforms or production
readiness.

## Checks run

| Check | Result / scope |
| --- | --- |
| `./scripts/dev.sh check` | Format, Clippy with warnings denied, 21 offline tests, doc tests |
| `cargo +1.88.0 check --workspace --all-targets --locked` | Declared MSRV compiles, including tests |
| `cargo build --workspace --release --locked` | Optimized daemon and CLI build |
| `cargo audit` | No matching RustSec advisories in 213 locked workspace dependencies |
| `cargo audit --file fuzz/Cargo.lock` | No matching RustSec advisories in 115 locked fuzz dependencies |
| DNS wire fuzz smoke, AddressSanitizer | 375493 inputs in a bounded 15-second run; no crash; peak instrumented RSS 118 MiB |
| Config fuzz smoke, AddressSanitizer | 417910 inputs in a bounded 15-second run; no crash; peak instrumented RSS 139 MiB |
| Docker image build | Native Linux ARM64 image built successfully |
| Container startup / `--check` / `--version` | UID 65532, read-only filesystem, no network, all Linux capabilities dropped; UDP/TCP IPv4/IPv6 listeners start; SIGTERM stops service |
| Release packaging | Native platform ZIP, both binaries, operator docs/config, SHA-256 checksum; archive integrity checked |
| Docs / shell / YAML | Local links, shell syntax, workflow YAML syntax, and `git diff --check` checked |

Fuzz RSS figures describe the instrumented test processes, not Lumen's runtime
memory use. AddressSanitizer quarantine is capped at 32 MiB to keep retained
freed allocations within the fuzz process's 512 MiB budget. An initial run hit
that instrumentation budget; the bounded-quarantine runs above completed.

## Offline coverage

Tests bind ephemeral local sockets and use in-process DNS fixtures. They do not
require public DNS or trust remote service uptime.

- UDP/TCP queries and persistent TCP framing on IPv4 and IPv6.
- DoT, DoH HTTP/2 GET/POST, and DoQ on IPv4 and IPv6 with generated test keys.
- Encrypted upstream forwarding over TLS, HTTPS, QUIC; wrong certificate names
  fail. Test CA trust is explicit; verification is never skipped.
- DNSSEC-valid data sets AD; tampered/unsigned-after-signing data and wrong trust
  keys fail; signed denial returns NXDOMAIN.
- Positive, NXDOMAIN, and NODATA caching; cache hits avoid upstream work; TTL
  expiry causes new upstream queries.
- Root/TLD/authority iterative delegation; unrelated glue cannot supply a cached
  forged answer; cached lookups avoid network work; recursion depth is bounded.
- Malformed queries, compressed response names, EDNS, short packets, name loops,
  invalid flags/classes/types, trailing bytes, and generated random inputs.
- UDP truncation/TCP fallback, query timeouts, rate limits, connection caps,
  shared resolver concurrency, rate-table capacity and bounded cleanup scans;
  response counters include malformed/refused DNS replies.
- Atomic startup failure, aggregate metrics, cancellation/shutdown, socket reuse,
  and a 256-query load regression in batches of eight.
- Schema rejection, nested unknown fields, example configs, relative file paths,
  bounded config reads, and strict daemon argument parsing.

The recursive hierarchy test remaps test authority IPs to ephemeral loopback
ports through a test-only runtime. Production authority-address filters remain
unchanged.

## Public-network smoke check

A temporary daemon with a **30-second query deadline** was started after checking
listener readiness and then stopped cleanly. Native recursive mode returned:

| Query | Result | Observed duration |
| --- | --- | --- |
| `cloudflare.com A +dnssec` | NOERROR, AD set | 8.06 s |
| `example.com A +dnssec` | NOERROR, AD set | 1.94 s |
| `dnssec-failed.org A +dnssec` | SERVFAIL, AD clear | 18.29 s |

All three requests produced responses; none reached that configured deadline.
This is a dated smoke check, not a latency guarantee or a CI dependency. The
normal default query deadline is 10 seconds; slower recursion fails within that
bound. Operators can tune it up to 60 seconds. Direct root-server reachability
was also checked over UDP and TCP.

## Repeat

```sh
./scripts/dev.sh check
cargo +1.88.0 check --workspace --all-targets --locked
cargo build --workspace --release --locked
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo run --locked --bin lumen -- --config config/lumen.toml --check
cargo run --locked --bin lumen -- --config config/forward.example.toml --check
```

Fuzzing needs nightly Rust and `cargo-fuzz` 0.13.2. The fuzz workspace has its own
committed lockfile. CI checks its metadata with `--locked` before fuzzing.

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

Container smoke commands:

```sh
docker build --tag lumen:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges lumen:local --config /etc/lumen/lumen.toml --check
```

## Not established by these checks

The PowerShell packaging script was not run by the CI workflow, and the release
workflow was not triggered because no release tag was created. No remote release
or multi-architecture image was published.

External DNS/DNSSEC conformance suites, extended soak/abuse tests, production
memory/performance measurements, automatic trust rollover, signed images,
reproducible releases, and independent security review remain release gates.

## 2026-10-30 local deployment verification

On an Apple M4 host with OrbStack 29.8.2, the native Linux ARM64 OCI image built
and passed these checks:

- UID 65532, read-only root filesystem, config validation, startup, and clean `SIGTERM` shutdown.
- Real UDP and TCP DNS queries through mapped host ports using `scripts/dns-smoke.py`.
- Docker Compose config, startup on host port 53, UDP/TCP DNS replies, and clean removal.
- Raw Kubernetes manifests in Kind 0.33.0 with working rollout, Service, ConfigMap,
  NetworkPolicy, readiness probe, and UDP/TCP smoke pod.
- Helm chart install in a separate namespace with the same UDP/TCP smoke checks.
- Both Kubernetes deployments ran as UID 65532, rejected root-filesystem writes,
  and had service-account token mounting disabled.
- The local release script, macOS ARM64 archive, required archive contents,
  SHA-256 verification, and unsafe version-string rejection passed.

The temporary Compose stack and Kind cluster were removed. The requested local
multi-architecture build was stopped before completion; Linux AMD64 and other
native targets were left to hosted CI.

## 2026-10-30 hosted platform verification

[CI run 41116220947](https://github.com/StruktSource/lumen-dns/actions/runs/41116220947)
passed native build, test, and config checks on Linux AMD64/ARM64, macOS
AMD64/ARM64, Windows AMD64, and experimental Windows ARM64. Native OCI runtime
checks passed on Linux AMD64/ARM64. Rootless Podman checks passed. The Kind job
passed Helm lint/render, raw-manifest rollout, and deterministic UDP/TCP DNS
queries through the ClusterIP Service.

## CI socket regression fixes

CI reported a Windows QUIC client socket error and a Linux TCP restart bind
error. The DoQ test now supplies an explicitly bound socket. Unix TCP listeners
set `SO_REUSEADDR`, and the shutdown regression restarts the actual service.
After the fix, hosted native checks passed on every configured runner.

# Phase 1 verification

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
cargo run --locked --bin lumen -- --config config/forward.toml --check
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
```

Container smoke commands:

```sh
docker build --tag lumen:local .
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges lumen:local --config /etc/lumen/lumen.toml --check
```

## Not established by these checks

Windows and x86_64 native execution, the PowerShell script on a Windows host,
and hosted GitHub CI/release execution were not run in this session. CI definitions
cover those workflows; YAML syntax alone does not prove a hosted run. GitHub issue
lookup was unavailable through the connected account. No remote release was
published.

External DNS/DNSSEC conformance suites, extended soak/abuse tests, production
memory/performance measurements, automatic trust rollover, signed images,
reproducible releases, and independent security review remain release gates.

## CI socket regression fixes

CI reported a Windows QUIC client socket error and a Linux TCP restart bind
error. The DoQ test now supplies an explicitly bound socket. Unix TCP listeners
set `SO_REUSEADDR`, and the shutdown regression restarts the actual service.
After the fix, the full macOS ARM64 checks and all eight Linux ARM64 container
integration tests passed. Windows and Ubuntu x86_64 hosted CI must still verify
their respective fixes.

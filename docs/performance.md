# Performance snapshots

These are local idle measurements, not throughput or latency benchmarks. No DNS
requests were sent. The computer was not a dedicated server and other system
activity was not controlled. Results are specific to each run.

## 2026-10-30 — Phase 2 filtering comparison

Phase 2 uses the same method as the Phase 1 baseline: a native release process,
two seconds of warm-up, then 30 `ps` samples about one second apart. Two matched
runs separate the current binary from the cost of an active filter snapshot.

| Environment | Value |
| --- | --- |
| CPU | Apple M4, 10 logical cores |
| Memory | 16 GiB |
| OS | macOS 27.2 / Darwin 27.2.0, ARM64 |
| Lumen | commit `2191831728fb1609df8a70faf61eabb0c9e8c9cf` |
| Build | `cargo build --release --locked -p lumen`, rustc 1.95.0 |
| Runtime | Native process; UDP/TCP on an ephemeral loopback port; recursive mode and DNSSEC enabled |
| Traffic | None; no queries sent |
| Sampling | 30 `ps` samples about one second apart, after two seconds of warm-up |

| Scenario | Mean CPU | Peak CPU | Mean RSS | RSS range | Process CPU time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Phase 2 binary, filtering disabled | 0.0% | 0.0% | 8.98 MiB | 8.98–8.98 MiB | 0:00.01 → 0:00.01 |
| Phase 2 binary, filtering enabled | 0.0% | 0.0% | 9.37 MiB | 9.36–9.38 MiB | 0:00.01 → 0:00.01 |

The active sample policy added **0.39 MiB** mean RSS over the same Phase 2 binary.
That policy contained global allow/block rules and one three-domain imported
list. It is a functional-path check, not a representative large production list.
The release executable was **11.52 MiB** (12,081,456 bytes).

Compared with the older Phase 1 snapshot, the current filtering-enabled process
used 1.06 MiB more mean RSS and the executable grew by 2.30 MiB. This comparison
includes all code and dependency changes between the two commits; it does not
attribute the full difference to filtering.

### Repeat the snapshot

The script builds Lumen, selects ephemeral loopback ports, runs both scenarios,
stops each daemon, and prints a Markdown report:

```sh
./scripts/performance.py
./scripts/performance.py --output /tmp/lumen-performance.md
```

Use `--skip-build` only when the current locked release binary already exists.
`--samples`, `--interval`, and `--warmup` can shorten a smoke run, but results
with different settings are not directly comparable to the recorded snapshots.
The script requires Python 3 and a Unix-like `ps` with `%cpu`, `rss`, and `time`
columns. It currently targets Linux and macOS; Windows needs a separate sampler.

## 2026-10-29 — Phase 1 idle development baseline

| Environment | Value |
| --- | --- |
| CPU | Apple M4, 10 cores |
| Memory | 16 GiB |
| OS | macOS 27.2 (26B5091g), ARM64 |
| Lumen | 0.1.0, source commit `e915f350d1a15236ae6a6cde488c684c1385f19b` |
| Build | `cargo build --release --locked -p lumen`, rustc 1.95.0 |
| Runtime | Native process, `lumen --bind 127.0.0.1:<ephemeral-port>`; UDP/TCP, recursive mode, DNSSEC enabled |
| Traffic | None; no queries sent |
| Sampling | 30 `ps` samples about one second apart, after two seconds of warm-up |

| Metric | Result |
| --- | --- |
| Process CPU | Mean 0.0%, peak 0.0%, as reported by `ps` to one decimal place |
| Resident set size (RSS) | Mean 8.31 MiB; min/max 8.31 MiB |
| Cumulative process CPU time | 0:00.01 at first and last samples, as reported by `ps` |
| Release executable size | 9.22 MiB (9,671,072 bytes) |

CPU percentage is process usage; 100% means one logical CPU core. The 0.0%
readings are rounded observations, not proof of zero CPU use. RSS includes
resident shared memory and is not the same as private memory or a container
memory limit. Binary size excludes OS libraries and container images.

Server throughput, latency, cache behavior, large-list scaling, and sustained
load measurements remain future work. Those tests need a controlled local
upstream and a load generator so public-network variance does not become a Lumen
performance claim.

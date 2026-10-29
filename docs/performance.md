# Performance snapshots

## 2026-10-29 — idle development baseline

This is a local idle measurement, not a throughput or latency benchmark.
No DNS requests were sent. The computer was not a dedicated server and other
system activity was not controlled. Results are specific to this run.

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
memory limit. The binary size excludes OS libraries and container images.

For a comparable later snapshot, record the commit, configuration, platform,
build command, warm-up, sample interval, traffic, and the same metrics. Server
throughput, latency, cache behavior, and sustained-load measurements remain
future work and need a suitable network and controlled test environment.

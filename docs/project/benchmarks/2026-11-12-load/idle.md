# Lumen native idle performance snapshot

| Environment | Value |
| --- | --- |
| CPU | Apple M4, 10 logical cores |
| Memory | 16 GiB |
| OS | macOS 27.3 (26C5035r), arm64 |
| Lumen | commit `2bff0e937bb0340c19a550e23801c6f746168bc5` |
| Build | `cargo build --release --locked -p lumen`, rustc 1.95.0 (59807616e 2026-04-14) |
| Sampling | 30 samples, 1 second interval, after 2 seconds warm-up |
| Traffic | None; UDP/TCP listeners on loopback |

| Scenario | Mean CPU | Peak CPU | Mean RSS | RSS range | Process CPU time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Phase 2 binary / filtering disabled | 0.0% | 0.0% | 7.72 MiB | 7.72–7.73 MiB | 0:00.01 → 0:00.01 |
| Phase 2 binary / filtering enabled | 0.0% | 0.0% | 8.37 MiB | 8.36–8.39 MiB | 0:00.01 → 0:00.01 |

Release executable: **18.52 MiB** (19,423,888 bytes).

CPU is process usage as reported by `ps`; 100% equals one logical core. RSS includes resident shared memory. This local idle snapshot is not a throughput, latency, or capacity benchmark.

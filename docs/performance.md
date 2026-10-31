# Performance snapshots

The idle snapshots are local measurements, not throughput or latency benchmarks;
no DNS requests were sent for them. The newest section below measures cold-cache
latency with real queries. The computer was not a dedicated server and other system
activity was not controlled. Results are specific to each run.

## 2026-10-31 — Cold-cache recursion A/B (Issue #9)

Unlike the idle snapshots below, this section sends real queries. It compares
Lumen 0.1.0 at commit `6dd2ac1` (baseline) with the same tree plus the Issue #9
changes (candidate: shared recursion, startup priming) on the public internet, with
no forwarding resolver. Raw data and the full reports are in
[`benchmarks/2026-10-31-recursion/`](benchmarks/2026-10-31-recursion/ab-report.md).

| Environment | Value |
| --- | --- |
| CPU / OS | Apple M4, macOS 27.2, ARM64, no IPv6 connectivity |
| Method | 12 trials per variant, fresh daemon per trial, order interleaved ABBA; 36 real domains, shuffled per trial (same order for both variants); 10 s idle before timed queries for both |
| Queries | A, RD=1, no DO bit, 8 s timeout (right-censored, counted as failures) |
| Statistics | Trial-level cluster bootstrap (4000 resamples, 95% CI); Wilcoxon signed-rank on per-trial medians is the primary test; Mann–Whitney on pooled queries is reported but anticonservative because queries within a trial share caches |
| Reproduce | `./scripts/recursion_bench.py --baseline OLD --candidate NEW --trials 12 --settle 10 --seed 20261031` |

| Variant | Category | n | median | p90 | p95 | timeouts |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| baseline | first query of a trial | 12 | 1554 ms | 2717 ms | 3029 ms | 0 |
| candidate | first query of a trial | 12 | 1154 ms | 3131 ms | 3981 ms | 0 |
| baseline | all cold queries | 432 | 910 ms | 2980 ms | 5732 ms | 15 |
| candidate | all cold queries | 432 | 747 ms | 2825 ms | 5089 ms | 13 |
| baseline | 32 identical concurrent queries | 1152 | 2326 ms | 7500 ms | 7694 ms | 50 |
| candidate | 32 identical concurrent queries | 1152 | 1482 ms | 3637 ms | 3959 ms | 0 |

What the data supports:

- **Concurrent identical queries improved clearly.** Shared recursion removed all
  50 timeouts in the burst test and cut p95 from 7.7 s to 4.0 s. This category is
  compared descriptively; each trial coalesced 93–97 queries, visible in
  `lumen_dns_recursive_coalesced_total`. A deterministic offline test confirms 24
  concurrent identical queries cost one recursion instead of 73 upstream packets.
- **Cold single-query latency did not show a statistically significant change.**
  The median of all cold queries was 17.9% lower (−163 ms; 95% CI −382 to +47 ms).
  The trial-level test gives p = 0.20 (first query: −25.7%, CI −64% to +28%,
  p = 0.38), so this run cannot distinguish the change from network variance.
  The pooled Mann–Whitney p = 0.006 is not used as evidence for the reason above.
- **Priming:** all 26 priming queries succeeded in 11 of 12 candidate trials. In
  trial 5 every one failed (network or server trouble at that moment), so that trial
  ran without priming. It is kept in the analysis. A deterministic offline
  three-authority hierarchy with fixed per-hop delay also verifies that priming
  reduces both authority round trips and elapsed time for a cold leaf name. This
  regression proves the mechanism, not a production-network latency claim.
- **Slow tail unchanged.** About 3% of cold queries time out in both variants. They
  concentrate on a few domains (openbsd.org, videolan.org, torproject.org) whose
  authoritative servers do not answer. Hickory's recursor fixes its per-attempt
  timeout and one outstanding request, so Lumen cannot shorten it.
- **Warm lookups:** the median stayed 0.1 ms. The warm pass re-queries the same names,
  so its tail follows the cold failures (2 vs 5 timeouts) and is not a cache-hit
  regression claim either way.
- **DNSSEC:** `dnssec-failed.org` returned SERVFAIL and `example.com` NOERROR in
  12/12 trials for both variants.

Optional hedged recursion (`resolver.hedge_ms`, off by default) was tried on the
eight slowest names with `hedge_ms = 1200`, 10 trials per variant. Timeouts fell from
9 to 4 of 80 and p95 from 8000 ms to 6612 ms, but the medians and the trial-level
test showed no significant difference (p = 0.70), so it is documented as
inconclusive rather than recommended
([report](benchmarks/2026-10-31-recursion/hedge-report.md)).

Limitations: one machine, one network vantage, public authoritative servers whose
own caches affect "cold", 36 names, and 12 trials, which limits the smallest
detectable difference. This is not a throughput or capacity claim.

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

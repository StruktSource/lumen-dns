# Performance

Measurements of how Lumen performs, with the method and the limits of each one.

> [!NOTE]
> **The short version.** Lumen is small: an idle process uses roughly 8 MiB of memory and no measurable CPU. Answering from the filter or the cache takes about 0.03 ms at the median on loopback, and memory stays near 12 MiB under heavy local load. The release binary is about 18.5 MiB. Lumen has **no verified production throughput claim yet**. The measurements below are snapshots from one machine, not guarantees.

| Question | Answer | Details |
| :--- | :--- | :--- |
| How much memory does it idle at? | About 8 MiB (7.72 MiB without filtering, 8.37 MiB with a small active filter) in v0.6.0 | [v0.6.0 snapshot](#2026-11-12--v060-idle-and-load-snapshot) |
| How fast does it answer once it knows the answer? | Median 0.03 ms for a cached name and 0.02 ms for a blocked name with one query in flight; p99 under 1.5 ms with 64 in flight | [v0.6.0 snapshot](#2026-11-12--v060-idle-and-load-snapshot) |
| What does heavy load cost? | Peak 11–13 MiB RSS and under 1 core of CPU at 9,000 answers per second from one client | [v0.6.0 snapshot](#2026-11-12--v060-idle-and-load-snapshot) |
| Do the recursion speed-ups work? | Shared recursion clearly helped identical-query bursts. A cold single-query gain was **not** statistically significant | [Cold-cache A/B](#2026-10-31--cold-cache-recursion-ab-issue-9) |
| How much memory do big block lists need? | About 19 MiB for Hagezi Pro, about 150 MiB for roughly 2.4 million rules | [Filtering guide](../guides/filtering.md#limits-and-memory) |

The idle snapshots are local measurements, not throughput or latency benchmarks; no DNS requests were sent for them. The v0.6.0 section adds loopback load and the cold-cache section measures latency with real queries. The computer was not a dedicated server and other system activity was not controlled. Results are specific to each run.

## 2026-11-12 — v0.6.0 idle and load snapshot

The first run with real load, on the v0.6.0 tree (commit `2bff0e9`). Raw tables and JSON are in
[`benchmarks/2026-11-12-load/`](benchmarks/2026-11-12-load/load-table.md).

| Environment | Value |
| --- | --- |
| CPU / OS | Apple M4, 10 logical cores, 16 GiB, macOS 27.3, ARM64 |
| Build | `cargo build --release --locked -p lumen`, rustc 1.95.0 (portable ThinLTO) |
| Runtime | Native process, UDP on loopback, recursive mode, DNSSEC on, one blocked name |
| Network | The test machine uses Tailscale DNS in front of NextDNS. Lumen resolves iteratively on its own, so neither affected the results; only the one cold lookup used the internet |

**Idle** (30 `ps` samples one second apart, after 2 s warm-up, no queries):

| Scenario | Mean CPU | Mean RSS | Process CPU time |
| --- | ---: | ---: | ---: |
| Filtering disabled | 0.0% | 7.72 MiB | 0:00.01 → 0:00.01 |
| Small active filter | 0.0% | 8.37 MiB | 0:00.01 → 0:00.01 |

The release executable is **18.52 MiB** (19,423,888 bytes), up from 11.52 MiB at the Phase 2 snapshot. That compares different commits and includes every dependency and feature added since (console, single sign-on, query history, more transports); it is not attributed to any one change. Idle memory went down: 8.98 → 7.72 MiB without filtering.

**Load** (10 s per scenario, closed loop: each worker keeps a fixed number of queries in flight; UDP, A records):

| Scenario | Answered/s | p50 | p95 | p99 | Max | Mean CPU | Peak CPU | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Blocked name, 1 in flight | 8,000 | 0.024 ms | 0.040 ms | 0.076 ms | 0.4 ms | 7% | 18% | 11.3 MiB |
| Blocked name, 8 in flight | 9,000 | 0.075 ms | 0.134 ms | 0.175 ms | 0.6 ms | 22% | 83% | 11.3 MiB |
| Blocked name, 64 in flight | 9,000 | 0.738 ms | 1.088 ms | 1.266 ms | 2.3 ms | 51% | 172% | 11.4 MiB |
| Cached name, 1 in flight | 8,000 | 0.033 ms | 0.047 ms | 0.091 ms | 0.7 ms | 14% | 38% | 11.5 MiB |
| Cached name, 8 in flight | 9,000 | 0.088 ms | 0.167 ms | 0.249 ms | 6.3 ms | 30% | 108% | 12.0 MiB |
| Cached name, 64 in flight | 9,000 | 0.698 ms | 1.162 ms | 1.417 ms | 2.5 ms | 47% | 180% | 12.6 MiB |
| Cached name, shipped 100/s limit | 100 | 0.182 ms | 0.785 ms | 0.990 ms | 1.2 ms | 0% | 1% | 11.8 MiB |

Other results:

- The first (cold) recursive lookup of `example.com`, with an empty cache, took **617 ms** over the internet. This is one sample, not a distribution; see the cold-cache A/B below for that.
- RSS was 8.17 MiB before load and **11.80 MiB five seconds after** it stopped. Lumen does not return all of the memory it touched right away, so expect idle after a busy period to sit a few MiB above a fresh start.
- Every answer in the blocked scenarios was `NXDOMAIN` and every answer in the cached scenarios was `NOERROR`; no wrong answers were seen.

How to read this:

- **Throughput is capped by the per-client rate limit, not by Lumen's CPU.** One loopback client is one IP, and the limiter allows at most 10,000 queries per second per IP (the table raises it from the default 100 to that maximum). The "Answered/s" column therefore shows the limiter, and the 1 s dropped-query timeout of the load tool, rather than the daemon's ceiling. Peak CPU stayed below two cores of ten. The last row shows the shipped default working as documented: exactly 100 answers per second, the rest dropped.
- **Latency is the useful number.** It is the time from send to reply on loopback, so it excludes the network. Real clients add their own round trip. Blocked and cached answers cost about the same, as both skip recursion.
- Loopback, one client IP, one machine, a Python load generator, A records only, no DNSSEC-signed cached name, no TCP, DoH, DoT or DoQ. This is not a capacity claim for a network of devices.

### Repeat the load test

```sh
cargo build --release --locked -p lumen
./scripts/load_bench.py --seconds 10 --output /tmp/lumen-load.md
```

The script needs Python 3 and a Unix-like `ps`. It starts and stops its own daemon on an ephemeral loopback port and does not touch your configuration.

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
  authoritative servers do not answer. Hickory's recursor fixes its pool
  timeout and one outstanding authority request. Its current public options do not
  expose these settings to Lumen.
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

## v0.6.0 logic-led audit

[Optimization decisions](optimization-audit.md) record current hot paths, selected
cleanup and rejected/deferred ideas. Response ownership transfer and skipped discarded
filter-match allocations remove known work; portable ThinLTO enables cross-crate code
optimization. No new latency, throughput or memory measurement is claimed. Native CPU
builds are opt-in local artifacts, separate from standard portable releases.

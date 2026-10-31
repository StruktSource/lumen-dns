# Lumen recursion A/B benchmark

## Environment

- Date: 2026-10-31T13:05:23+01:00
- CPU: Apple M4
- OS: Darwin 27.2.0 (arm64)
- Python: 3.15.0
- Baseline: `/Users/gerrxt/Code/StruktApps/dnsservice/target/release/lumen`
  - version: Lumen 0.1.0
  - sha256: `d0521297f24091328e5fc5c115665da48dae94f01b6eef24c9f039da9e22566c`
  - git commit: 6dd2ac179b89f178e1ab4945ee4cb8d42ae3fe63
- Candidate: `/Users/gerrxt/Code/StruktApps/dnsservice/target/release/lumen`
  - version: Lumen 0.1.0
  - sha256: `d0521297f24091328e5fc5c115665da48dae94f01b6eef24c9f039da9e22566c`
  - git commit: 6dd2ac179b89f178e1ab4945ee4cb8d42ae3fe63
- Trials: 10 (fresh daemon per trial per variant, interleaved ABBA)
- Names: 8; settle: 8.0 s; per-query timeout: 8.0 s
- Seed: 7; bootstrap resamples: 2000

## Per-variant latency (ms)

Percentiles use linear interpolation between order statistics (index (n-1)p). Timeouts are right-censored at the timeout value and included.

| Variant | Category | n | mean | median | p90 | p95 | p99 | min | max | failures |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline | cold_first | 10 | 3163.1 | 985.1 | 8000.0 | 8000.0 | 8000.0 | 351.9 | 8000.0 | 2 |
| baseline | cold_all | 80 | 2336.7 | 948.4 | 8000.0 | 8000.0 | 8000.0 | 240.1 | 8000.0 | 9 |
| baseline | warm_all | 80 | 1216.7 | 0.2 | 5311.9 | 5361.5 | 5537.8 | 0.1 | 5793.0 | 0 |
| baseline | burst | 960 | 1521.4 | 1340.4 | 2563.1 | 2822.0 | 2940.6 | 515.2 | 2941.4 | 0 |
| candidate | cold_first | 10 | 2864.5 | 1404.9 | 6386.0 | 7193.0 | 7838.6 | 492.9 | 8000.0 | 1 |
| candidate | cold_all | 80 | 2271.7 | 1030.9 | 5871.6 | 6612.4 | 8000.0 | 233.1 | 8000.0 | 4 |
| candidate | warm_all | 80 | 1125.9 | 0.2 | 5343.7 | 5943.7 | 8000.0 | 0.1 | 8000.0 | 2 |
| candidate | burst | 960 | 1518.4 | 1257.7 | 2637.1 | 3330.6 | 3406.7 | 563.3 | 3407.6 | 0 |

Burst latencies are pooled across 3 names x 32 concurrent identical UDP queries per trial.

## Paired comparison (candidate minus baseline)

Negative values mean the candidate is faster. 95% CIs are percentile bootstrap over TRIALS (cluster bootstrap; same resampled trials for both variants).

### cold_first (10 paired trials; n_base=10, n_cand=10)

| Statistic | baseline | candidate | diff (ms) | diff 95% CI | change % | change 95% CI |
|---|---|---|---|---|---|---|
| median | 985.1 | 1404.9 | 419.73 | [-3970.22, 2302.64] | 42.6% | [-70.9%, 266.2%] |
| mean | 3163.1 | 2864.5 | -298.56 | [-1706.74, 1026.48] | -9.4% | [-43.6%, 55.3%] |
| p95 | 8000.0 | 7193.0 | -807.02 | [-2954.77, 2199.72] | -10.1% | [-43.5%, 51.4%] |
| p99 | 8000.0 | 7838.6 | -161.40 | [-2828.16, 2182.00] | -2.0% | [-37.9%, 54.1%] |

- Wilcoxon signed-rank over per-trial medians (PRIMARY): W+=27.0, non-zero pairs=10, p=1.0000 (exact)
- Mann-Whitney U on pooled latencies (secondary): U=56.0, p=0.6771
- Cliff's delta: 0.120 (negligible); positive = candidate slower
- Hodges-Lehmann shift (cand - base): 162.97 ms
- **Verdict (cold_first, Wilcoxon over trials, alpha=0.05): no significant difference at alpha=0.05**
- Verdict (cold_first, Mann-Whitney, anticonservative): no significant difference at alpha=0.05

### cold_all (10 paired trials; n_base=80, n_cand=80)

| Statistic | baseline | candidate | diff (ms) | diff 95% CI | change % | change 95% CI |
|---|---|---|---|---|---|---|
| median | 948.4 | 1030.9 | 82.46 | [-107.24, 497.80] | 8.7% | [-10.1%, 60.2%] |
| mean | 2336.7 | 2271.7 | -64.98 | [-371.45, 307.54] | -2.8% | [-15.1%, 14.4%] |
| p95 | 8000.0 | 6612.4 | -1387.57 | [-2136.83, 0.00] | -17.3% | [-26.7%, 0.0%] |
| p99 | 8000.0 | 8000.0 | 0.00 | [-1416.77, 0.00] | 0.0% | [-17.7%, 0.0%] |

- Wilcoxon signed-rank over per-trial medians (PRIMARY): W+=32.0, non-zero pairs=10, p=0.6953 (exact)
- Mann-Whitney U on pooled latencies (secondary): U=3221.0, p=0.9442
- Cliff's delta: 0.007 (negligible); positive = candidate slower
- Hodges-Lehmann shift (cand - base): 0.74 ms
- **Verdict (cold_all, Wilcoxon over trials, alpha=0.05): no significant difference at alpha=0.05**
- Verdict (cold_all, Mann-Whitney, anticonservative): no significant difference at alpha=0.05

Burst category: compared descriptively only.

- baseline: burst p50=1340.4 ms, p95=2822.0 ms, max=2941.4 ms
- candidate: burst p50=1257.7 ms, p95=3330.6 ms, max=3407.6 ms

## DNSSEC check

Skipped (--skip-dnssec-check).

## Failures

- baseline: cold_first=2, cold_all=9, warm_all=0, burst=0
- candidate: cold_first=1, cold_all=4, warm_all=2, burst=0

## Limitations

- Single machine and single network vantage point; results may not transfer elsewhere.
- Real-internet variance (routing, authoritative load, rate limiting) is not controlled; ABBA interleaving only mitigates slow drift.
- Authoritative-side caching can make 'cold' include warm authoritative caches, so absolute cold latencies are optimistic and depend on what other resolvers recently asked.
- Mann-Whitney treats queries as independent, which they are not (queries within a trial share delegation caches), so it is anticonservative; the trial-level Wilcoxon test and cluster bootstrap are the primary evidence.
- With few trials the exact Wilcoxon p-value has a coarse floor (2/2^n for n non-zero pairs).
- This is a latency comparison on a small name list, not a throughput or capacity claim.

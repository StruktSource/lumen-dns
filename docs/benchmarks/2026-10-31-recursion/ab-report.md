# Lumen recursion A/B benchmark

## Environment

- Date: 2026-10-31T12:29:15+01:00
- CPU: Apple M4
- OS: Darwin 27.2.0 (arm64)
- Python: 3.15.0
- Baseline: `/private/tmp/lumen-baseline-target/release/lumen`
  - version: Lumen 0.1.0
  - sha256: `b25419d2cec1b3900e9fec27a08094aaf2a46143d6e08a49117703c133d895ad`
  - git commit: n/a
- Candidate: `/Users/gerrxt/Code/StruktApps/dnsservice/target/release/lumen`
  - version: Lumen 0.1.0
  - sha256: `f8af012a8bf6daae8dc989102ea8ad7eb7d8b8de6020b4c34a02a53f90cf8824`
  - git commit: 6dd2ac179b89f178e1ab4945ee4cb8d42ae3fe63
- Trials: 12 (fresh daemon per trial per variant, interleaved ABBA)
- Names: 36; settle: 10.0 s; per-query timeout: 8.0 s
- Seed: 20261031; bootstrap resamples: 4000

## Per-variant latency (ms)

Percentiles use linear interpolation between order statistics (index (n-1)p). Timeouts are right-censored at the timeout value and included.

| Variant | Category | n | mean | median | p90 | p95 | p99 | min | max | failures |
|---|---|---|---|---|---|---|---|---|---|---|
| baseline | cold_first | 12 | 1619.2 | 1554.1 | 2717.0 | 3029.0 | 3310.1 | 428.3 | 3380.3 | 0 |
| baseline | cold_all | 432 | 1464.5 | 910.2 | 2980.4 | 5732.0 | 8000.0 | 0.5 | 8000.0 | 15 |
| baseline | warm_all | 432 | 265.1 | 0.1 | 1.1 | 1265.6 | 5734.3 | 0.1 | 8000.0 | 2 |
| baseline | burst | 1152 | 3541.9 | 2325.8 | 7499.9 | 7693.6 | 8000.0 | 0.9 | 8000.0 | 50 |
| candidate | cold_first | 12 | 1511.1 | 1154.0 | 3131.0 | 3981.3 | 4715.4 | 303.7 | 4899.0 | 0 |
| candidate | cold_all | 432 | 1328.6 | 747.3 | 2825.1 | 5088.5 | 8000.0 | 154.5 | 8000.0 | 13 |
| candidate | warm_all | 432 | 356.3 | 0.1 | 0.6 | 3426.3 | 7503.7 | 0.1 | 8000.0 | 5 |
| candidate | burst | 1152 | 1705.2 | 1482.1 | 3636.5 | 3959.2 | 5002.8 | 459.0 | 5003.5 | 0 |

Burst latencies are pooled across 3 names x 32 concurrent identical UDP queries per trial.

## Paired comparison (candidate minus baseline)

Negative values mean the candidate is faster. 95% CIs are percentile bootstrap over TRIALS (cluster bootstrap; same resampled trials for both variants).

### cold_first (12 paired trials; n_base=12, n_cand=12)

| Statistic | baseline | candidate | diff (ms) | diff 95% CI | change % | change 95% CI |
|---|---|---|---|---|---|---|
| median | 1554.1 | 1154.0 | -400.10 | [-1157.70, 407.54] | -25.7% | [-64.3%, 28.4%] |
| mean | 1619.2 | 1511.1 | -108.09 | [-857.15, 770.59] | -6.7% | [-46.4%, 53.9%] |
| p95 | 3029.0 | 3981.3 | 952.34 | [-1556.75, 2738.45] | 31.4% | [-46.1%, 126.7%] |
| p99 | 3310.1 | 4715.4 | 1405.37 | [-1227.88, 2720.65] | 42.5% | [-37.2%, 144.3%] |

- Wilcoxon signed-rank over per-trial medians (PRIMARY): W+=27.0, non-zero pairs=12, p=0.3804 (exact)
- Mann-Whitney U on pooled latencies (secondary): U=56.0, p=0.3708
- Cliff's delta: -0.222 (small); positive = candidate slower
- Hodges-Lehmann shift (cand - base): -250.78 ms
- **Verdict (cold_first, Wilcoxon over trials, alpha=0.05): no significant difference at alpha=0.05**
- Verdict (cold_first, Mann-Whitney, anticonservative): no significant difference at alpha=0.05

### cold_all (12 paired trials; n_base=432, n_cand=432)

| Statistic | baseline | candidate | diff (ms) | diff 95% CI | change % | change 95% CI |
|---|---|---|---|---|---|---|
| median | 910.2 | 747.3 | -162.92 | [-382.19, 47.15] | -17.9% | [-36.2%, 5.8%] |
| mean | 1464.5 | 1328.6 | -135.94 | [-462.87, 279.67] | -9.3% | [-28.2%, 20.8%] |
| p95 | 5732.0 | 5088.5 | -643.51 | [-1770.45, 1129.96] | -11.2% | [-25.7%, 20.8%] |
| p99 | 8000.0 | 8000.0 | 0.00 | [0.00, 0.00] | 0.0% | [0.0%, 0.0%] |

- Wilcoxon signed-rank over per-trial medians (PRIMARY): W+=22.0, non-zero pairs=12, p=0.2036 (exact)
- Mann-Whitney U on pooled latencies (secondary): U=83202.5, p=0.0058
- Cliff's delta: -0.108 (negligible); positive = candidate slower
- Hodges-Lehmann shift (cand - base): -109.27 ms
- **Verdict (cold_all, Wilcoxon over trials, alpha=0.05): no significant difference at alpha=0.05**
- Verdict (cold_all, Mann-Whitney, anticonservative): candidate faster

Burst category: compared descriptively only.

- baseline: burst p50=2325.8 ms, p95=7693.6 ms, max=8000.0 ms
- candidate: burst p50=1482.1 ms, p95=3959.2 ms, max=5003.5 ms

## DNSSEC check

| Variant | trials passed | trials total |
|---|---|---|
| baseline | 12 | 12 |
| candidate | 12 | 12 |

Pass requires dnssec-failed.org A -> SERVFAIL and example.com A -> NOERROR.

## Failures

- baseline: cold_first=0, cold_all=15, warm_all=2, burst=50
- candidate: cold_first=0, cold_all=13, warm_all=5, burst=0

## Limitations

- Single machine and single network vantage point; results may not transfer elsewhere.
- Real-internet variance (routing, authoritative load, rate limiting) is not controlled; ABBA interleaving only mitigates slow drift.
- Authoritative-side caching can make 'cold' include warm authoritative caches, so absolute cold latencies are optimistic and depend on what other resolvers recently asked.
- Mann-Whitney treats queries as independent, which they are not (queries within a trial share delegation caches), so it is anticonservative; the trial-level Wilcoxon test and cluster bootstrap are the primary evidence.
- With few trials the exact Wilcoxon p-value has a coarse floor (2/2^n for n non-zero pairs).
- This is a latency comparison on a small name list, not a throughput or capacity claim.

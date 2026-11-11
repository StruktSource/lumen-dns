| Scenario | Answered/s | p50 | p95 | p99 | Max | Dropped | Mean CPU | Peak CPU | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blocked, window 1 | 8,000 | 0.024 ms | 0.040 ms | 0.076 ms | 0.4 ms | 7 | 7% | 18% | 11.3 MiB |
| blocked, window 8 | 9,000 | 0.075 ms | 0.134 ms | 0.175 ms | 0.6 ms | 64 | 22% | 82% | 11.3 MiB |
| blocked, window 64 | 9,000 | 0.738 ms | 1.088 ms | 1.266 ms | 2.3 ms | 512 | 51% | 172% | 11.4 MiB |
| cached, window 1 | 8,000 | 0.033 ms | 0.047 ms | 0.091 ms | 0.7 ms | 7 | 14% | 38% | 11.5 MiB |
| cached, window 8 | 9,000 | 0.088 ms | 0.167 ms | 0.249 ms | 6.3 ms | 64 | 30% | 108% | 12.0 MiB |
| cached, window 64 | 9,000 | 0.698 ms | 1.162 ms | 1.417 ms | 2.5 ms | 512 | 47% | 180% | 12.6 MiB |
| cached, shipped 100 qps limit | 100 | 0.182 ms | 0.785 ms | 0.990 ms | 1.2 ms | 72 | 0% | 1% | 11.8 MiB |

Cold first lookup of `example.com`: 617 ms.
RSS before load 8.17 MiB, 5 s after load 11.80 MiB.

| Scenario | Answered/s | p50 | p95 | p99 | Max | Dropped | Mean CPU | Peak CPU | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| blocked, window 1 | 8,000 | 0.021 ms | 0.036 ms | 0.086 ms | 0.5 ms | 7 | 7% | 24% | 14.0 MiB |
| blocked, window 8 | 9,000 | 0.071 ms | 0.135 ms | 0.187 ms | 0.8 ms | 64 | 22% | 78% | 14.0 MiB |
| blocked, window 64 | 9,000 | 0.744 ms | 1.178 ms | 1.387 ms | 3.1 ms | 512 | 50% | 181% | 14.1 MiB |
| cached, window 1 | 8,000 | 0.030 ms | 0.044 ms | 0.099 ms | 0.7 ms | 7 | 13% | 36% | 14.5 MiB |
| cached, window 8 | 9,000 | 0.081 ms | 0.151 ms | 0.199 ms | 1.0 ms | 64 | 31% | 106% | 15.0 MiB |
| cached, window 64 | 9,000 | 0.691 ms | 1.154 ms | 1.407 ms | 2.6 ms | 512 | 72% | 208% | 15.7 MiB |
| cached, shipped 100 qps limit | 100 | 0.189 ms | 0.649 ms | 0.802 ms | 0.9 ms | 72 | 0% | 1% | 14.1 MiB |

Cold first lookup of `example.com`: 631 ms.
RSS before load 10.70 MiB, 5 s after load 14.12 MiB.

Console enabled (state database, web on loopback): idle 10.90 MiB RSS, 0.0% mean CPU (0.3% peak) over 15 s.
Console page `GET /` (HTTP/1.1 200 OK, 2,111 bytes): p50 0.14 ms, p99 0.31 ms over 200 requests.

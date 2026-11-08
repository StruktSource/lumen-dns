# Monitoring

Lumen can expose privacy-safe numbers about its own health and activity for Prometheus, Grafana, and Home Assistant. It is **off by default** and never exposes domains, clients, devices, profiles, tokens, or upstream identities.

## Turn it on

```toml
metrics = "127.0.0.1:9153"
```

This enables two endpoints on that address:

| Endpoint | Returns |
| :--- | :--- |
| `/metrics` | Metrics in Prometheus text format |
| `/healthz` | `ok` while the process is alive |

`/healthz` reports process liveness only. It does not prove public DNS works or that DNSSEC is valid. No management operations are available here.

> [!WARNING]
> Lumen rejects a non-loopback metrics address on purpose. Never expose `/metrics` to an untrusted network.

## Ready-made files

| File | Purpose |
| :--- | :--- |
| [`prometheus.yml`](../../deploy/observability/prometheus.yml) | Prometheus scrape example |
| [`grafana-lumen.json`](../../deploy/observability/grafana-lumen.json) | Grafana dashboard |
| [`home-assistant.yaml`](../../deploy/observability/home-assistant.yaml) | Home Assistant package |

**Reaching the loopback endpoint.** The Prometheus example assumes it can reach Lumen at `lumen:9153`. Because Lumen only binds loopback, provide that path with a local sidecar, host networking, or a loopback proxy, without making metrics public.

**Home Assistant.** Read status with a *viewer* token and keep it in `secrets.yaml`, never in the package. Control actions need an *operator* or *admin* token. Put the webhook receiver ID and HMAC verification in the Home Assistant automation or reverse proxy, and never act on an unsigned body. See [signed webhooks](../reference/management-api.md#signed-webhooks).

## Metric reference

All metrics use stable `lumen_dns_` names (and `lumen_filter_` for filtering) with no client or domain labels. The only labels are fixed, bounded ones such as the transport.

| Metric | Type | Meaning |
| :--- | :--- | :--- |
| `lumen_dns_queries_total` | counter | Queries received |
| `lumen_dns_responses_total` | counter | Responses sent |
| `lumen_dns_malformed_total` | counter | Unparseable queries |
| `lumen_dns_refused_total` | counter | Refused queries |
| `lumen_dns_timeouts_total` | counter | Queries that hit a deadline |
| `lumen_dns_failures_total` | counter | Failed resolutions |
| `lumen_dns_active_queries` | gauge | Queries in progress now |
| `lumen_dns_transport_queries_total{transport}` | counter | Queries per transport |
| `lumen_dns_query_duration_seconds` | histogram | End-to-end query latency (includes cache hits) |
| `lumen_dns_fallback_attempts_total` | counter | Timeout fallbacks started |
| `lumen_dns_fallback_successes_total` | counter | Fallbacks that answered |
| `lumen_dns_fallback_failures_total` | counter | Fallbacks that failed |
| `lumen_dns_fallback_trigger_recursion_timeout_total` | counter | Fallbacks triggered by a recursion timeout |
| `lumen_dns_recursive_lookup_duration_seconds` | histogram | Client-facing recursion latency |
| `lumen_dns_recursive_background_duration_seconds` | histogram | Background (priming, refresh) recursion latency |
| `lumen_dns_recursive_coalesced_total` | counter | Recursions saved by sharing |
| `lumen_dns_recursive_hedged_total` | counter | Hedged extra recursions started |
| `lumen_dns_warm_queries_total` | counter | Startup priming queries |
| `lumen_dns_warm_failures_total` | counter | Failed priming queries |
| `lumen_dns_prefetch_refreshes_total` | counter | Expiry refreshes done |
| `lumen_dns_prefetch_failures_total` | counter | Failed refreshes |
| `lumen_dns_prefetch_skipped_total` | counter | Refreshes skipped |
| `lumen_filter_*_total` | counters | Allowed and blocked decisions, list refresh success and failure, rollbacks |

**About the histograms**

- The two recursion histograms have 11 fixed buckets from 1 ms to 5 s.
- The client histogram includes cache hits, so its sub-millisecond bucket roughly tracks your cache hit ratio. Priming and refresh traffic is excluded because it is counted in the background histogram.

## Logs and privacy

Full query logs stay disabled, and startup logs show only listener addresses. The only way to log domain names is the explicit `decision_log` option in [filtering](filtering.md#privacy-and-logging).

## Related

- [Management API](../reference/management-api.md)
- [Resolver modes: speed features](resolver-modes.md#speed-features-recursive-mode)
- [Configuration reference](../reference/configuration.md#top-level-settings)

# Observability and integrations

Set `metrics = "127.0.0.1:9153"` to enable Prometheus `/metrics` and liveness
`/healthz`. Both remain loopback-only. Metrics contain bounded transport labels
only. No domain, client, device, profile, token, or upstream identity is exposed.

The extended set includes total queries/responses, failures, refusal and parse
counts, active work, transport totals, end-to-end query latency histogram,
recursive fallback counters, and filter allow/block/refresh/rollback counters.

Ready files:

- [Prometheus scrape example](../deploy/observability/prometheus.yml)
- [Grafana dashboard](../deploy/observability/grafana-lumen.json)
- [Home Assistant package](../deploy/observability/home-assistant.yaml)

The Prometheus example assumes Prometheus can reach Lumen at `lumen:9153`.
Lumen itself rejects a non-loopback metrics bind, so a local sidecar, host
network, or loopback proxy must provide that path without making metrics public.
Do not expose `/metrics` to an untrusted network.

Home Assistant reads Lumen status through a viewer token. Keep the token in
`secrets.yaml`; do not place it in the package. Control actions use an operator
or admin token. The webhook receiver ID and HMAC verification belong in the
Home Assistant automation or reverse proxy; never act on an unsigned body.

# Docker Compose

Copy `deploy/docker-compose.yml` and `deploy/lumen.toml` into one directory.
Review client CIDRs and the pinned image tag, then run:

```sh
docker compose config
docker compose up -d
docker compose logs -f lumen
```

The compose file maps host UDP/TCP 53 to container port 5353 and publishes the
web console as host-loopback `127.0.0.1:8080` and keeps its accounts in the
`lumen-state` volume. On first start run `docker compose logs lumen` for the
setup code, then open the console. It drops all Linux capabilities,
sets a read-only root filesystem, and runs as UID 65532. Any reverse proxy may
use the private HTTP upstream for HTTPS or HTTP/3. Stop with
`docker compose down`. Upgrade by changing the pinned tag, pulling, validating
the config with `docker compose run --rm lumen --check`, and recreating.

IPv6 port publishing depends on the host daemon network setup. Confirm it with a
real `dig -6` test. Compose does not preserve a client address hidden by NAT; do
not claim per-device policy works unless the observed source address is stable.

# Linux bare metal

Download the archive that matches `linux-amd64` or `linux-arm64`. Verify it with
`SHA256SUMS` and GitHub artifact attestation before install. Put `lumen` and
`lumenctl` in `/usr/local/bin`, create an unprivileged `lumen` user, and place a
root-owned, world-readable config at `/etc/lumen/lumen.toml`.

Install `deploy/systemd/lumen.service`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now lumen
sudo journalctl -u lumen
```

The unit creates `/var/lib/lumen` mode `0700` and enables managed state at
`/var/lib/lumen/state.db`. Use `lumenctl` with that path for config, devices,
reload, filter controls, status, and shutdown. The example listens on port 5353
and needs no capability. To bind port 53, use a
systemd socket redirect or add only `CAP_NET_BIND_SERVICE` to the service. Never
run the resolver as root. The unit blocks writes to the system, private home, and
kernel controls. Validate and apply changes with `lumenctl config apply`; failed
runtime validation or binding restores the prior config.

Back up config, state database, local lists, trust anchors, and TLS files. Runtime caches are not
persistent. Test UDP, TCP, IPv4, IPv6, DNSSEC, shutdown, and source-IP behavior on
the actual host before production use.

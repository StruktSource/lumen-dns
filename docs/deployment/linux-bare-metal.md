# Linux bare metal

Download the `v0.5.6` archive that matches `linux-amd64` or `linux-arm64`, plus
`SHA256SUMS`, from the GitHub release. Verify it before install:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.5.6-linux-amd64.tar.gz --repo StruktSource/lumen-dns
tar -xzf lumen-v0.5.6-linux-amd64.tar.gz
cd lumen-v0.5.6
./lumen --version
./lumenctl --version
```

Use `linux-arm64` on ARM64 hosts. Put `lumen` and `lumenctl` in
`/usr/local/bin`, create an unprivileged `lumen` user, and place a root-owned,
world-readable config at `/etc/lumen/lumen.toml`. The archive includes the
configuration, deployment files, docs, release notes, and a file manifest.

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

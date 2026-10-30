# Docker

Build with `docker build -t lumen:local .`, or use a versioned image from
`ghcr.io/struktsource/lumen-dns`. The image runs as UID/GID 65532, has no need
for root, and handles `SIGTERM` for a bounded shutdown.

The bundled config listens only inside the container loopback. For network use,
mount an explicit config such as `deploy/lumen.toml` and publish both UDP and TCP:

```sh
docker run --name lumen --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=16m -p 53:5353/udp -p 53:5353/tcp \
  -v "$PWD/deploy/lumen.toml:/etc/lumen/lumen.toml:ro" \
  ghcr.io/struktsource/lumen-dns:0.1.0
```

Review `allow_clients` first. The example accepts only private IPv4 and ULA IPv6
ranges. Do not expose port 53 to the internet. The current core keeps caches and
filter snapshots in memory, so restarts discard them. Config and list files are
the only state to mount.

Use `docker stop --time 15 lumen` for shutdown. Upgrades replace the container
with a pinned version. CI checks non-root startup, read-only operation, config
loading, and shutdown on native AMD64 and ARM64 runners. A passed CI run is still
required before changing the compatibility status.

# Docker

Build with `docker build -t lumen:local .`, or use a versioned image from
`ghcr.io/struktsource/lumen-dns`. The image runs as UID/GID 65532, has no need
for root, and handles `SIGTERM` for a bounded shutdown.

The bundled config listens only inside the container loopback. For network use,
mount an explicit config such as `deploy/lumen.toml` and publish both UDP and TCP:

```sh
docker run --name lumen --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=16m -v lumen-state:/var/lib/lumen -p 53:5353/udp -p 53:5353/tcp \
  -p 127.0.0.1:8080:8080/tcp \
  -v "$PWD/deploy/lumen.toml:/etc/lumen/lumen.toml:ro" \
  ghcr.io/struktsource/lumen-dns:0.2.0
```

Review `allow_clients` first. The example accepts only private IPv4 and ULA IPv6
ranges. Do not expose port 53 to the internet. Port 8080 serves the web console and is published on host loopback. Any chosen reverse proxy can use that
upstream and terminate HTTPS or HTTP/3. The current core keeps caches and
filter snapshots in memory, so restarts discard them. The image runs in managed mode and keeps accounts, settings, and device
policy in `/var/lib/lumen`: mount a volume there (`-v lumen-state:/var/lib/lumen`,
UID 65532-writable) and keep the root filesystem read-only. Open
`http://127.0.0.1:8080` to create the administrator account; because Docker
forwards from a non-loopback address, setup asks for the code printed by
`docker logs lumen`. After the first start the mounted `lumen.toml` is no longer
read: change settings in the console or with `lumenctl config apply`.

Use `docker stop --time 15 lumen` for shutdown. Upgrades replace the container
with a pinned version. CI checks non-root startup, read-only operation, config
loading, and shutdown on native AMD64 and ARM64 runners. A passed CI run is still
required before changing the compatibility status.

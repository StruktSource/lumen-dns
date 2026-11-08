# Docker and Docker Compose

Run Lumen as a container. Compose is the easiest way to keep it running on a server or NAS.

Images are published as `ghcr.io/struktsource/lumen-dns` for `linux/amd64` and `linux/arm64`. The image runs as UID and GID `65532`, needs no root, and handles `SIGTERM` for a bounded shutdown.

> [!NOTE]
> Status: experimental. CI checks non-root startup, read-only operation, config loading, and shutdown on native AMD64 and ARM64 runners. See the [compatibility matrix](compatibility.md).

## Docker Compose (recommended)

1. Copy [`deploy/docker-compose.yml`](../../deploy/docker-compose.yml) and [`deploy/lumen.toml`](../../deploy/lumen.toml) into one directory.
2. Review the allowed client ranges and the pinned image tag.
3. Start it:

   ```sh
   docker compose config
   docker compose up -d
   docker compose logs -f lumen
   ```

4. Run `docker compose logs lumen` and note the **setup code**, then open the console at <http://127.0.0.1:8080>.

What the Compose file does:

- Maps host UDP and TCP **53** to container port 5353.
- Publishes the web console on host loopback only (`127.0.0.1:8080`).
- Keeps accounts and settings in the `lumen-state` volume.
- Drops all Linux capabilities, uses a read-only root filesystem, and runs as UID 65532.

Day-to-day:

| Task | Command |
| :--- | :--- |
| Stop | `docker compose down` |
| Upgrade | Change the pinned tag, `docker compose pull`, check with `docker compose run --rm lumen --check`, then `docker compose up -d` |

## Plain Docker

Build locally with `docker build -t lumen:local .`, or use a versioned image:

```sh
docker run --name lumen --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=16m -v lumen-state:/var/lib/lumen \
  -p 53:5353/udp -p 53:5353/tcp \
  -p 127.0.0.1:8080:8080/tcp \
  -v "$PWD/deploy/lumen.toml:/etc/lumen/lumen.toml:ro" \
  ghcr.io/struktsource/lumen-dns:0.5.6
```

Stop with `docker stop --time 15 lumen`. Upgrade by replacing the container with a newer **pinned** version.

## Things to know

- **Access control.** Review `allow_clients` first. The example accepts only private IPv4 and ULA IPv6 ranges. Never expose port 53 to the internet.
- **State.** The image runs in [managed mode](../guides/managed-mode.md) and keeps accounts, settings, and device policy in `/var/lib/lumen`. Mount a volume there (writable by UID 65532) and keep the root filesystem read-only. Caches and filter snapshots live in memory, so restarts discard them.
- **After the first start**, the mounted `lumen.toml` is no longer read. Change settings in the console or with `lumenctl config apply`.
- **Console setup code.** Docker forwards from a non-loopback address, so first-run setup asks for the code printed by `docker logs lumen`.
- **HTTPS.** Port 8080 serves the web console and is published on host loopback only. Put any reverse proxy in front to terminate HTTPS or HTTP/3. See [Web console](../guides/web-console.md#https-and-remote-access).
- **IPv6.** Port publishing depends on your Docker network setup. Confirm with a real `dig -6` test.
- **Client addresses.** Docker/Compose does not preserve a client address hidden by NAT, so do not rely on per-device policy unless the observed source address is stable.

## Related

- [Serve your network](../guides/serve-your-network.md)
- [Podman](podman.md) for the same image without Docker
- [Kubernetes](kubernetes.md)

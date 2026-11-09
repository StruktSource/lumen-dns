# Podman

Podman uses the same container image and configuration as [Docker](docker.md), with no Docker socket or daemon needed. Rootless operation works well.

> [!NOTE]
> Status: experimental. CI builds and checks the image with rootless Podman on Linux AMD64. ARM64 Podman, restart persistence, and IPv6 still need real runtime proof. See the [compatibility matrix](compatibility.md).

## Run it

```sh
podman run --name lumen --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 5353:5353/udp -p 5353:5353/tcp \
  -v "$PWD/deploy/lumen.toml:/etc/lumen/lumen.toml:ro,Z" \
  ghcr.io/struktsource/lumen-dns:0.6.0
```

## Tips

- **Ports.** Port 5353 keeps rootless operation simple. If you need port 53, redirect or forward it with the host firewall.
- **SELinux.** On SELinux hosts use the `:Z` label (as above) or otherwise label the files correctly.
- **File permissions.** Config files must be readable by UID 65532.
- **Client addresses.** Rootless networking may replace the original client IP, so test device rules with the addresses Lumen actually observes.
- To keep accounts and settings, add a state volume as in the [Docker guide](docker.md#things-to-know).

## Related

- [Serve your network](../guides/serve-your-network.md)
- [Docker and Compose](docker.md)

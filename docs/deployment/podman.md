# Podman

Podman uses the same OCI image and config as Docker. No Docker socket or Docker
API is needed.

```sh
podman run --name lumen --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges \
  -p 5353:5353/udp -p 5353:5353/tcp \
  -v "$PWD/deploy/lumen.toml:/etc/lumen/lumen.toml:ro,Z" \
  ghcr.io/struktsource/lumen-dns:0.1.2
```

Port 5353 keeps rootless operation simple. Redirect or forward host port 53 with
the host firewall if needed. SELinux hosts need `:Z` or a correct file label.
Config files must be readable by UID 65532. Rootless networking may replace the
original client IP, so test device rules with observed addresses.

CI builds and checks the image with rootless Podman on Linux AMD64. ARM64 Podman,
restart persistence, and IPv6 still need real runtime proof.

# Deployment guides

Pick the guide that matches where you want to run Lumen. All of them run the **same `lumen` program and the same configuration format**. Only the packaging differs, so nothing here changes how DNS behaves.

> [!IMPORTANT]
> Read the [compatibility matrix](compatibility.md) first. A guide existing does **not** mean its platform has passed runtime tests. The matrix records what has really been verified, and no platform is "supported" yet.

## Which one should I use?

| I have… | Use | Status |
| :--- | :--- | :--- |
| A server, VM, or NAS with Docker | [Docker and Compose](docker.md) | Experimental |
| Podman (rootless is fine) | [Podman](podman.md) | Experimental |
| A Kubernetes cluster | [Kubernetes and Helm](kubernetes.md) | Experimental |
| A Linux machine and I like systemd | [Linux (systemd)](linux.md) | Experimental |
| A Mac | [macOS](macos.md) | Experimental |
| A Windows PC | [Windows](windows.md) | Experimental |
| Proxmox, Unraid, or a Raspberry Pi | [Homelab platforms](homelab.md) | Planned |

If you are unsure, **Docker Compose** is the easiest way to run Lumen as an always-on service.

## Before you start

1. Decide who should use Lumen. The default is this machine only. To serve other devices, follow [Serve your network](../guides/serve-your-network.md).
2. Plan for port 53. Lumen defaults to 5353 so it needs no special privileges. Each guide shows how to expose 53.
3. Keep Lumen off the public internet.
4. Validate any config change with `lumen --config FILE --check`.
5. Pin versions: use a specific release or image tag rather than `latest`.

## What every platform has in common

- Config lives in a TOML file, and managed mode adds a small SQLite state directory. **Back up both**, along with local lists, trust anchors, and TLS files. Runtime caches are not persistent.
- Run as an unprivileged account, never as root.
- Test UDP **and** TCP, IPv4 **and** IPv6, DNSSEC, shutdown, and source-IP behavior on your real setup before relying on it.
- Anything that rewrites client addresses (NAT, container bridges, load balancers) breaks per-device filtering.

## Files in the repository

| Path | Used by |
| :--- | :--- |
| [`deploy/docker-compose.yml`](../../deploy/docker-compose.yml) and [`deploy/lumen.toml`](../../deploy/lumen.toml) | Docker, Compose, Podman |
| [`deploy/kubernetes/`](../../deploy/kubernetes) and [`deploy/helm/lumen/`](../../deploy/helm/lumen) | Kubernetes |
| [`deploy/systemd/lumen.service`](../../deploy/systemd/lumen.service) | Linux |
| [`deploy/observability/`](../../deploy/observability) | Prometheus, Grafana, Home Assistant |

These files are also inside every release archive.

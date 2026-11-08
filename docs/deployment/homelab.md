# Homelab platforms: Proxmox, Unraid, Raspberry Pi

Short guides for popular homelab setups. All three reuse a guide you already have, so read that one first.

> [!WARNING]
> **Status: planned.** None of these has been run on real hardware or a real host. They are generic guidance built on the Linux and container guides. Lumen is only tested on hosted CI runners for the underlying platforms. See the [compatibility matrix](compatibility.md).

| Platform | Built on |
| :--- | :--- |
| [Proxmox LXC](#proxmox-lxc) | [Linux (systemd)](linux.md) |
| [Unraid](#unraid) | [Docker](docker.md) |
| [Raspberry Pi](#raspberry-pi) | [Linux](linux.md) or [Docker](docker.md) |

## Proxmox LXC

Use the native Linux archive inside an **unprivileged** Debian-family LXC. Docker is not required. Follow the [Linux guide](linux.md) and keep the systemd unit unprivileged.

- Port 5353 needs no added container capability. Redirect host or LXC port 53 only after checking the Proxmox firewall and bridge.
- Mount `/etc/lumen` read-only where practical, and give the service user read access to the config, list, trust-anchor, and TLS files.
- Set CPU and memory limits in the LXC configuration.
- Confirm IPv4 and IPv6 routes and client source addresses with real DNS queries. NAT can break device identity.
- A privileged LXC is not required by the design.

## Unraid

Use the standard versioned container image from the [Docker guide](docker.md).

- Map host UDP and TCP **53** to container port 5353.
- Mount one config directory read-only at `/etc/lumen`.
- Run as UID and GID `65532` and drop all capabilities.
- Set a **15-second** stop timeout.
- Keep config and local list files in the appdata share. Caches do not persist.
- Pin image versions and validate the config before upgrades.

Networking trade-off: bridge mode may hide client addresses, while host networking preserves more source detail but broadens network access. Test UDP, TCP, ACLs, IPv6, and per-device policy before choosing.

No Unraid template ships yet.

## Raspberry Pi

Use a **64-bit** Linux OS and the `linux-arm64` archive or the `linux/arm64` container image. The 32-bit ARM target is **not built**. Follow the [Linux](linux.md) or [Docker](docker.md) guide.

- Start with conservative cache and connection limits on small devices (see [Configuration: limits](../reference/configuration.md#limits)).
- Use wired networking for a network resolver where possible.
- Confirm thermal behavior, memory use, UDP and TCP 53 routing, DNSSEC, and IPv6 on your exact board and OS.

Native Linux ARM64 CI is not Raspberry Pi hardware validation, and Pi support stays planned until a real board run is recorded.

## Help us validate

Tested one of these? Run through the guide and report what worked and what did not. Real-hardware reports move a platform out of "planned". See [Contributing](../../CONTRIBUTING.md).

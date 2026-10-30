# Proxmox LXC

Use the native Linux archive inside an unprivileged Debian-family LXC. Docker is
not required. Follow the bare-metal guide and keep the systemd unit unprivileged.
Port 5353 needs no added container capability; redirect host/LXC port 53 only
after checking the Proxmox firewall and bridge.

Mount `/etc/lumen` read-only where practical. Give the service user read access
to config, list, trust-anchor, and TLS files. Set CPU and memory limits in the LXC
configuration. Confirm IPv4/IPv6 routes and client source addresses with real DNS
queries. NAT can break device identity.

This is generic Linux guidance. It is not a Proxmox validation result. Privileged
LXC is not required by the design, but a real Proxmox host test remains pending.

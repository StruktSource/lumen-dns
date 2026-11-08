# Serve your network

By default Lumen listens on loopback, so only the computer it runs on can use it. This guide shows how to let the other devices on your network use Lumen, and what to check first.

> [!WARNING]
> Never expose Lumen's DNS port to the public internet. An open resolver can be abused for attacks on other people. Keep access limited to your own private network.

## How access works

Two settings together decide who can talk to Lumen. **You must change both** for LAN use:

1. **Where it listens** (`listen.udp` and `listen.tcp`): the addresses and ports Lumen opens.
2. **Who may ask** (`listen.allow_clients`): the address ranges (CIDRs) that Lumen will answer.

Opening a wildcard address such as `0.0.0.0` does **not** grant access by itself. A client must also match an allowed range, on every transport including encrypted ones. An empty allowlist is invalid (maximum 128 ranges).

## Step by step

1. **Pick the address and port.** Devices expect DNS on port **53**; the source and release defaults use **5353** so Lumen can run without special privileges. You can keep 5353 and redirect 53 to it (see [Port 53](#port-53)).

2. **Edit your config.** A typical home network:

   ```toml
   [listen]
   udp = ["0.0.0.0:5353", "[::]:5353"]
   tcp = ["0.0.0.0:5353", "[::]:5353"]
   allow_clients = [
     "127.0.0.0/8",
     "::1/128",
     "192.168.1.0/24",   # your home network
     "fd00::/8"          # your IPv6 private range, if you use one
   ]
   ```

   `deploy/lumen.toml` is a ready-made example that allows the standard private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `fc00::/7`).

3. **Validate it.** `lumen --config FILE --check` catches mistakes before anything changes. In [managed mode](managed-mode.md), apply with `lumenctl config apply`; a failed bind rolls back to your previous settings.

4. **Test from another device** before touching your router:

   ```sh
   dig @<lumen-host-ip> -p 5353 example.com A
   ```

5. **Point devices at Lumen.** Either set the DNS server on one device to try it, or set it in your router's DHCP settings so every device learns it automatically. Router menus differ; look for "DNS server" under LAN or DHCP.

## Port 53

| Platform | Options |
| :--- | :--- |
| **Docker / Compose** | Publish `53:5353` (the supplied files do this). See [Docker](../deployment/docker.md). |
| **Linux (systemd)** | Redirect 53 to 5353 with a systemd socket or firewall rule, or grant only `CAP_NET_BIND_SERVICE`. **Never run Lumen as root.** See [Linux](../deployment/linux.md). |
| **macOS** | Use a deliberate redirect or a privileged bind setup. See [macOS](../deployment/macos.md). |
| **Kubernetes** | The Service publishes 53 and forwards to 5353. See [Kubernetes](../deployment/kubernetes.md). |

## Checklist before going live

- [ ] `allow_clients` lists only networks you trust.
- [ ] The host firewall allows **both UDP and TCP** on the DNS port.
- [ ] You tested IPv4 and IPv6 from a real client.
- [ ] If you use per-device rules, Lumen sees each device's real address (see below).
- [ ] The web console is still on loopback, or behind HTTPS. Sign-in over plain HTTP is only safe on the machine itself.
- [ ] If encrypted DNS is on, your certificate is valid for the name clients use. See [Encrypted DNS](encrypted-dns.md).

## Why client addresses matter

Filtering policies pick a profile by the client's **source IP address**. Anything that hides the real address breaks per-device rules, including NAT, container port mapping, proxies, and some Kubernetes load balancers. Rootless Podman and Docker bridge networks can also replace the address. Compare what Lumen sees with what you expect before relying on device profiles. See [Filtering](filtering.md#device-and-group-policies).

## If something does not work

| Symptom | Check |
| :--- | :--- |
| Timeouts from other devices | Firewall rules, the listen address, and that the port is published (containers). |
| No answer at all, only from certain devices | The client may be outside `allow_clients`. Traffic from disallowed or rate-limited clients can be dropped silently. |
| Works over UDP but not TCP (or the reverse) | Open both protocols. Large answers fall back to TCP. |
| Device rules never match | The source address is being rewritten by NAT or a proxy. |

## Related

- [Configuration reference](../reference/configuration.md#listeners)
- [Threat model](../design/threat-model.md)
- [Deployment guides](../deployment/README.md)

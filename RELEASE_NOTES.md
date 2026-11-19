# Lumen 0.8.0

Lumen 0.8.0 adds optional network management: discovery, a device and room inventory, IPAM, a FRITZ!Box import, and a complete DNSSEC and mDNS toolset. Everything new is off by default.

## Highlights

- **Network discovery, device inventory, topology, and monitoring (optional).** The **Network** module finds devices on the networks you list, keeps one identity per device across address changes (DHCP client ID, then MAC, then IP), draws topology from LLDP and SNMP, and checks availability. Devices get readable automatic names and can be organized in nested rooms.
- **Device names in Activity.** The query history shows the inventory's device name instead of the IP address. A **Names** switch turns it off.
- **FRITZ!Box import (optional, read-only).** `[network.fritzbox]` reads the host list over TR-064 and uses the names you gave devices in the box. Only devices inside your scopes are kept and nothing is ever written to the router. See the [network guide](docs/guides/network.md#fritzbox-optional).
- **IP address management (optional).** Nested subnets, VLANs, locations, and addresses with conflict detection and atomic next-free-address allocation.
- **Full DNSSEC lifecycle for your own zones.** Separate KSK/ZSK keys, pre-published successors with timer-driven handoff, and signing for dynamic and split-horizon zones.
- **Completed mDNS.** Self-publishing with probing and conflict renaming, per-service reflection filters, and optional RFC 8765 DNS Push.

## Not in this release

Linking the device inventory to filtering profiles, native ECH, and a live-tested FRITZ!Box mesh or WAN import. The FRITZ!Box import and DNS Push are tested only against local fakes, not a real box or an external client.

## Check the download

Download the archive for your system plus `SHA256SUMS`, then run:

```sh
sha256sum --check SHA256SUMS --ignore-missing
gh attestation verify lumen-v0.8.0-<platform>.<extension> --repo StruktSource/lumen-dns
```

On macOS, use `shasum -a 256 -c` with the matching `.sha256` file if `sha256sum` is not installed.

While a release is still publishing, its page lists only the platforms that are ready. `SHA256SUMS` and the final `latest` image tag appear last.

## Upgrade notes

- The state database migrates one way to its new schema on first start; back up the state file first. Config schema 1 stays compatible, and every new table is optional.
- Nothing new is enabled by an upgrade.

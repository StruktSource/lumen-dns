# Raspberry Pi

Use a 64-bit Linux OS and the `linux-arm64` archive or `linux/arm64` OCI image.
The 32-bit ARM target is not built. Follow the bare-metal or Docker guide.

Start with conservative cache and connection limits on small devices. Use wired
networking for a network resolver where possible. Confirm thermal behavior,
memory use, UDP/TCP 53 routing, DNSSEC, and IPv6 on the exact board and OS.

Native Linux ARM64 CI does not equal Raspberry Pi hardware validation. Pi support
stays planned until a real board run is recorded.

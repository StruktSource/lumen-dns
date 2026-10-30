# macOS

Use the `macos-arm64` archive on Apple silicon and `macos-amd64` on Intel. Verify
checksums, unpack, and run `lumen --config config/lumen.toml --check` before start.
The local default uses port 5353 and loopback only.

For a persistent service, create a dedicated launchd plist that runs the binary
as an unprivileged account. Port 53 requires a deliberate redirect or elevated
bind setup; do not run the whole service as root. macOS firewall and VPN software
can change UDP/TCP routing and source addresses.

Apple-silicon local tests exist. Intel runtime status depends on the configured
native GitHub job and remains build-only until it passes.

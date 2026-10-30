# Unraid

Use the standard versioned OCI image. Map host UDP/TCP 53 to container port 5353,
mount one config directory read-only at `/etc/lumen`, run as UID/GID 65532, and
drop all capabilities. Set a 15-second stop timeout.

Unraid bridge networking may hide client addresses. Host networking preserves
more source detail but broadens network access. Test both UDP and TCP, ACLs, IPv6,
and per-device policy before choosing a mode. Keep config and local list files in
the appdata share; caches do not persist.

Pin image versions and validate config before upgrades. No Unraid template ships
yet, and no real Unraid system has been tested. Status remains planned.

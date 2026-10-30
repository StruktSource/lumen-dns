# Windows

Use the matching `windows-amd64` or experimental `windows-arm64` ZIP. Verify
`SHA256SUMS`, unpack, then run:

```powershell
./lumen.exe --config ./config/lumen.toml --check
./lumen.exe --config ./config/lumen.toml
```

Allow both UDP and TCP in Windows Firewall for a network deployment. Keep the
loopback default until ACLs are reviewed. Run under a restricted service account;
a Windows service wrapper is not bundled yet. Stop with Ctrl+C for graceful
shutdown. Config reload is not implemented.

Windows AMD64 and ARM64 native GitHub jobs are configured. Their results must be
recorded before either target is called supported. Windows ARM64 is experimental.

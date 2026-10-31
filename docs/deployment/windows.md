# Windows

Use the matching `windows-amd64` or experimental `windows-arm64` ZIP. Verify
`SHA256SUMS`, unpack, then run:

```powershell
./lumen.exe --config ./config/lumen.toml --check
./lumen.exe --config ./config/lumen.toml --state ./data/state.db
```

Allow both UDP and TCP in Windows Firewall for a network deployment. Keep the
loopback default until ACLs are reviewed. Run under a restricted service account;
that account needs exclusive read/write access to `./data`. A Windows service
wrapper is not bundled yet. Use `lumenctl.exe status`, `config apply`, `reload`,
`filter refresh`, `filter rollback`, or `shutdown` with the same `--state` path.
Ctrl+C also performs graceful shutdown.

Windows AMD64 and ARM64 native GitHub jobs are configured. Their results must be
recorded before either target is called supported. Managed-control runtime is
implemented with portable SQLite but has not yet been exercised on native
Windows. Windows ARM64 is experimental.

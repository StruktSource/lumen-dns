# 🧭 Architecture

Lumen separates trusted DNS query path from management features.

```text
Client → listener → DNS parser → policy/filter → cache → resolver/upstream
                              ↓
                       bounded metrics/logs

Config / CLI / future UI → config validation → atomic runtime update
```

## Boundaries

- `lumen-proto`: DNS wire parsing and serialization.
- `lumen-resolver`: recursion, forwarding, cache, DNSSEC.
- `lumen-filter`: lists, profiles, policies, explainable decisions.
- `lumen-config`: validation and atomic configuration updates.
- `lumen-api`: future authenticated API. No network API today.
- `lumen-core`: component wiring. Binaries stay thin.

Setup enables only needed built-in modules. Future plugins need explicit
permissions and never run inside DNS parsing by default. SQLite is planned for
configuration and opt-in history; hot cache stays bounded in memory.

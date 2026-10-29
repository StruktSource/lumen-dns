# 🔒 Threat model

| Threat | Required control |
| --- | --- |
| Malformed DNS packets | Parser limits, fuzzing, timeouts, no unsafe code |
| Cache poisoning | DNSSEC, bailiwick checks, randomized query state |
| Resolver abuse | Rate limits, concurrency caps, recursion limits |
| Malicious list | HTTPS, validation, atomic update, rollback |
| Exposed management | Local default, scoped auth, audit trail, rate limits |
| Sensitive history | Logs off, configurable retention and redaction |
| Container impact | Non-root runtime, minimal image, read-only paths |

Lumen cannot make a compromised host, router, device, or upstream resolver
trustworthy. It keeps its own boundaries explicit and data local by default.

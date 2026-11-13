# Threat model

What Lumen defends against, what it trusts, and where its protection ends. Read this before exposing Lumen beyond your own computer.

For reporting a vulnerability, see the [security policy](../../SECURITY.md).

## The short version

- **Untrusted:** DNS packets, filter lists, configuration files you did not write, network clients, API requests, and imports.
- **Trusted (your responsibility):** the host, your startup config, TLS keys, root hints, trust anchors, private CA bundles, client allow-lists, key file access, the system clock, and certificate renewal.
- **Lumen's job:** bound parsing, CPU, memory, disk, and network work so hostile input cannot take the service down or leak data.
- **Not Lumen's job:** a compromised host, router, or client; an upstream operator's honesty; or the privacy of plain-text DNS to authoritative servers.

## Controls in place

### DNS input and abuse

| Threat | Control |
| :--- | :--- |
| Malformed DNS, compression loops, forged section counts | Bounded full-message decoder, strict query shape, full consumption, parser regression tests, and fuzz targets |
| Oversized packets and partial stream frames | Per-message cap, UDP oversize detection, whole-frame read and write deadlines |
| Response loops and reflection | Incoming responses and short packets dropped, loopback and client CIDR defaults, rate and work caps, UDP response ceiling |
| Idle or hostile TCP/TLS clients | Shared connection cap, TLS handshake and frame deadlines, bounded response work |
| HTTP/2 body and header floods | Header, body, window, and stream caps and deadlines; GET, POST, path, and media-type checks |
| QUIC resource exhaustion | Connection admission, transport windows, bounded streams, deadlines, no unidirectional streams or early data |
| Query floods from many client IPs | Global query slots, per-IP one-second rate windows, bounded client table, bounded UDP workers |
| DNSSEC computational load | Recursion depth limit, bounded validation cache, NSEC3 limits, outer query deadline |
| Open resolver deployment | Loopback release default; network examples use private client CIDRs and an internal-only Kubernetes Service and NetworkPolicy |

### Correct answers

| Threat | Control |
| :--- | :--- |
| Cache poisoning and bad delegations | Hickory source and query matching, random query state, case randomization, bailiwick checks, and DNSSEC |
| Recursive access to local services | Hickory's recommended authority-address filters retained. No automatic private-range exception for custom hints |
| Bad upstream or certificate impostor | Local DNSSEC validation, explicit upstream IP and TLS name, verified CA chain, timeout-only opt-in fallback, no insecure downgrade |
| Forwarding loop | Exact listener endpoints rejected, recursive and fallback deadlines bounded, NAT and split-network limits documented |
| Listener silently fails | The daemon observes background task errors, and startup binds all sockets before serving |

### Privacy and management

| Threat | Control |
| :--- | :--- |
| Query privacy | Query history is off by default. Metrics have no domain or client labels, and there is no external telemetry. Startup logs show only listener addresses |
| Saved query history (opt-in) | Administrator-only switch, with an anonymous mode that never stores the client, a 1-90 day retention (default 7), a 500,000-row cap, automatic deletion, an explicit delete action, and audit entries that never contain domains. It lives only in the state database (mode `0600`), and is not served by the management API, metrics, or webhooks |
| Persistent DNS cache (opt-in) | Off by default; separate mode `0600` SQLite file; strict entry, encoded-byte and TTL caps; no client or device fields; bounded blocking writer; expired rows pruned; corrupt files moved aside and rebuilt. The file still reveals queried names and answers to anyone who can read it |
| DNSCrypt listener (opt-in) | No TLS certificate. Long-term Ed25519 key in a `0600` file, short-lived in-memory resolver keys, forged or unknown packets dropped without a reply, `allow_clients` applied before any reply, UDP replies capped at the query size. No replay cache: a captured encrypted query can be replayed to the same resolver key until it rotates, and the answer still goes only to the claimed source |
| Operator zones, views, forwarders (opt-in) | Zones are read-only data unless a journal and `update_rules` exist. Views choose by observed client address, so a NAT or proxy hides client identity. Conditional forwarding is plain UDP/TCP and not DNSSEC-validated, so only point it at networks you trust. Operator zones bypass the response caches, so a stale or cross-view answer cannot be served from cache |
| Dynamic updates and zone transfers (opt-in) | Every update and transfer needs a valid TSIG signature (HMAC-SHA256/384/512, 300 s time window) from a key listed for that zone. Updates are also scoped per key to exact names or one subtree and to a short list of record types, at most 64 records per message and 20,000 record sets per zone. Structural and DNSSEC types, and delete-all, are refused. Transfers are TCP only, refused for zones with views, and refused when they would not fit one message. Secrets are read from files and never logged. There is no replay cache beyond the TSIG time window |
| TLS certificate renewal | A renewed pair is loaded and checked (parseable, key matches) before it replaces the served one, so a half-written file cannot take down encrypted listeners. The expiry timestamp is exported as a metric |
| Management exposure | API and metrics bind loopback only. The API requires hashed bearer tokens, scoped roles, per-token rate limits, bounded parsing, and durable audit |
| Static UI hosting | Embedded fixed routes, no filesystem paths or templates, bounded connections, strict response headers. Release HTTP binds loopback |

### Packaging and release

| Threat | Control |
| :--- | :--- |
| Container impact | Non-root UID 65532, no runtime key generation or download, minimal Debian runtime |
| Orchestrator breakout | Non-root UID, read-only root, dropped capabilities, no privilege escalation, seccomp, resource limits |
| CI or release compromise | Read-only PR permissions, no persisted checkout credentials, locked Rust dependencies, publish only on version tags after required gates |
| Artifact substitution | Per-archive SHA-256, GitHub artifact provenance, OCI provenance and SBOM. Image signing remains pending |

## Filtering

Filtering implements bounded parsers, verified HTTPS with public-IP pinning, atomic updates, and one in-memory rollback generation. Rules run before cache lookup, including for unusual wire labels. Synthetic answers clear the AD flag and use TTL zero.

- List contents are untrusted. Source paths and policy selection are administrator inputs.
- Schedules rely on the host's UTC clock.
- Query-name filtering is **not** CNAME-chain inspection and **not** a network firewall.
- Optional decision logs disclose names and client IPs only when you enable them.
- In managed mode downloaded list text is cached in a `filter-cache` folder beside the state database (Unix modes `0700` and `0600`, at most 128 files and 512 MiB). It is public data. Files that are damaged, truncated, or too large are ignored and removed, validators are stripped of control characters before they are replayed, and the decompressed size obeys the same 64 MiB list limit as a normal download.

## Management and the console

The management API uses bearer tokens, scoped roles, audit, and rate limits. It has no browser session or cookie authentication, so CSRF is not an API credential path. The web console has its own sessions, CSRF protection, lockouts, and optional two-step verification, described in the [web console guide](../guides/web-console.md). Remote exposure of either is outside the supported boundary, so keep them on loopback or behind HTTPS. Query history is optional and disabled by default. When an administrator enables it, the retention, the anonymous mode, and deletion are described in [Query history](../guides/query-history.md). Any signed-in console user can *read* the history that exists, because the Activity page is shared by design, so enable the detailed *device and address* mode only if that is acceptable for every account.

### External login (optional)

[External login](../guides/external-login.md) adds a way into the console, so it is part of the console's trust boundary and stays **off by default**.

- **What is trusted.** The identity provider and the TLS connection to it. Lumen validates the ID token's issuer, audience, expiry, issue time, and nonce, but not its signature, because the token comes straight from the token endpoint over a verified TLS connection (OpenID Connect Core 3.1.3.7). A compromised provider, or one reached through a TLS-intercepting proxy, can therefore sign anyone in. Choose a provider you run or trust, and add `ca_file` only for your own CA.
- **The callback address.** It is built from the request's `Host` header (restricted to a plain name or IP address with an optional port) and `X-Forwarded-Proto`. Neither can redirect a person anywhere: the provider only honors callback addresses registered with it, and the token request repeats the address the sign-in started with.
- **Browser binding and replay.** Each sign-in carries a one-time `state` in a short-lived `HttpOnly`, `SameSite=Lax` cookie and a PKCE verifier. A state works once, expires after 10 minutes, and at most 256 can wait. Starts and callbacks share the per-address throttle.
- **No account takeover by name.** Accounts are tied to the provider's `(issuer, subject)`, never to a username, so a provider user called `admin` gets a separate account. Linking an existing account needs the signed-in person's CSRF-protected request and finishes only in the same browser; unlinking needs the account's password.
- **Privilege.** `admin_group` makes members administrators at their first sign-in, and with `sync_role` on every sign-in. That delegates administrator rights to whoever controls the group at the provider. The last administrator is never demoted.
- **Network reach.** The issuer is operator-configured and Lumen contacts it from the host, including private addresses. There is no redirect following and no proxy use, and responses are capped at 64 KiB.
- **What is not stored or shown.** Provider tokens are never stored, and the browser only ever sees one generic failure message. Reasons go to the audit log.
- **Not covered.** Back-channel logout, so an account that is disabled at the provider keeps any console session already open until it ends (30 minutes idle, 12 hours at most) or an administrator deletes the account.

## Limits of these guarantees

- **Memory.** Caches have entry and TTL bounds, not a contractual memory ceiling. Transient cache maintenance and protocol libraries use extra memory, and rate-limit state holds IP addresses only in transient bounded memory. Apply OS or container limits for hard isolation.
- **Denial of service.** Tests exercise overload and timeout paths but do not establish resistance to every strategy.
- **Multicast DNS bridge (opt-in).** With `[mdns]` Lumen joins the mDNS groups on the listed interfaces and, for the discovery proxy, answers unicast questions from what it heard. Any device on a listed network can announce a name, so an announced name is **untrusted data**: it is stored only under `.local`, rewritten into your domain, and returned with a capped TTL and no DNSSEC; do not give such names the trust you give your own zone. Packets from a source that is not on the link, malformed packets, and records outside `.local` and the reverse zones are dropped. Memory is bounded (`max_records`) and questions put on the network are rate-limited. The **reflector** deliberately crosses network boundaries: it lets devices on one network announce to and query devices on another, which weakens VLAN isolation, and it repeats whatever it receives (rate-limited, de-duplicated). Do not reflect between networks that should stay apart.
- **Multicast DNS bridge (opt-in).** With `[mdns]` Lumen joins the mDNS groups on the listed interfaces and, for the discovery proxy, answers unicast questions from what it heard. Any device on a listed network can announce a name, so an announced name is **untrusted data**: it is stored only under `.local`, rewritten into your domain, and returned with a capped TTL and no DNSSEC; do not give such names the trust you give your own zone. Packets from a source that is not on the link, malformed packets, and records outside `.local` and the reverse zones are dropped. Memory is bounded (`max_records`) and questions put on the network are rate-limited. The **reflector** deliberately crosses network boundaries: it lets devices on one network announce to and query devices on another, which weakens VLAN isolation, and it repeats whatever it receives (rate-limited, de-duplicated). Do not reflect between networks that should stay apart.
- **DHCP (opt-in).** With `[dhcp]` Lumen listens on UDP 67 and 547 and answers anyone on the served networks, as every DHCP server does: a hostile device can exhaust a range (bounded to 65,536 addresses per scope, with 60-second offer holds) or lie about its host name. Names are cut to one safe label, a device cannot take a reserved address, and a name is published only when the lease is acknowledged. A second DHCP server on the network is a conflict Lumen cannot see, so turn the old one off. DHCP has no authentication; use switch-level protection (DHCP snooping) where you need it. A relay agent is trusted to report the right link. Reconfigure and FORCERENEW (opt-in) use the protocols' HMAC-MD5 key schemes, which prove origin but do not protect against an attacker who can read the exchange. Router Advertisements (opt-in) are sent to all nodes on the link and tell devices which prefix, DNS servers and (only if configured) default router to use, so they decide where those devices send traffic: anyone who can change the configuration can redirect a network, and a hostile device on the link can send its own advertisements regardless, which Lumen cannot prevent (use RA Guard on the switch). Lumen answers only solicitations whose source is `::` or link-local, rate-limits its answers to one every 3 seconds, and needs a raw socket, so it asks for `CAP_NET_RAW`. The failover link authenticates every frame with a shared secret and a per-connection key, but does not encrypt, so lease data and device names are visible to anyone on the path; keep it on a trusted network or a VPN. A partner that fails authentication is ignored and does not keep the standby quiet.
- **ACME (opt-in).** With `[acme]` Lumen contacts the configured certificate authority and opens a plain-HTTP challenge listener while an order runs. The listener answers only tokens of the running order, caps connections, and times out slow clients. With DNS-01 the resolver answers `TXT _acme-challenge.<name>` from memory for the length of an order and nothing else. The account key and certificate key are written with mode `0600`. A CA or network attacker able to answer for your name could obtain a certificate for it, as with any ACME client, so use a CA you trust and keep port 80 for the challenge only.
- **DNSSEC.** It authenticates signed data only. Unsigned zones can legitimately validate as insecure. Root anchors are static unless you opt in to `trust_anchor_state`; then Lumen follows RFC 5011 rollover, applies changes at restart, and trusts only keys a current anchor signed.
- **Hickory.** Its recursive implementation is upstream-experimental. External review, broader conformance, and extended soak testing remain stable-release gates. Fuzz smoke tests and a clean dependency audit are useful checks, not proof of security.
- **Supply chain.** GitHub Actions and third-party actions are part of the release trust boundary. Actions are pinned to reviewed commit IDs, but updates still need review. Artifact provenance records a build, and it does not make a compromised build safe.
- **Kubernetes.** Probes and Kind smoke tests do not prove CNI source-IP preservation, public-recursion safety, or real platform isolation.
- **Not yet done.** OCI image signing and reproducible-build comparison.

## Related

- [Security policy](../../SECURITY.md)
- [Verification record](../project/verification.md)
- [Architecture](architecture.md)

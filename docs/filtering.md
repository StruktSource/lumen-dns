# Phase 2 filtering

Filtering runs after client admission and before every resolver/cache lookup on
UDP, TCP, DoH, DoT, and DoQ. An absent `[filtering]` table permits all names.
Rules apply to the question name, including unusual DNS child labels. They do
not inspect CNAME targets returned by upstreams, HTTP paths, or application
content. A client using another DNS service can bypass this DNS policy; network
access controls belong to the operator.

## Start and inspect

```sh
cargo run --locked --bin lumen -- --config config/filtering.example.toml --check
cargo run --locked --bin lumenctl -- filter-explain --config config/filtering.example.toml --client 192.0.2.10 --domain games.example --at 75600
cargo run --locked --bin lumen -- --config config/filtering.example.toml
```

The [example](../config/filtering.example.toml) uses only reserved example domains and
inline sources. Its `family` profile selects the `adult` category; `bedtime`
selects `adult` and `games` during an overnight UTC window. Supply your own
reviewed category sources for real filtering; no third-party feed is enabled.

`filter-explain` loads the config and sources into a separate snapshot. Output
includes blocked status, winning rule/list/category, selected profile/device/group,
action, and generation. `--at` is Unix seconds; omitted means current time. It
does not query the running daemon, use its retained generation, or send a DNS
query for the explained name. HTTPS list sources still require network access.

## Rules and precedence

Rules normalize case, IDNA, and a trailing root dot. `example.com` and
`*.example.com` match that domain and descendants at label boundaries;
`=example.com` matches only that name. URL, regex, and partial-label patterns are
rejected. Manual rules live in `filtering.rules.allow` and `.block`, or a
profile's `rules` table.

First matching tier wins:

1. Active profile's manual rules.
2. Global manual rules.
3. Selected imported lists.
4. Allow when no rule matches.

Within a tier, any matching allow rule beats all matching block rules. Thus a
profile block can override a global allow, while a global manual block can
override an imported exception. Within the same action, the most specific
matching suffix wins; list order breaks ties. Explanations identify that winner.

## Client policies and schedules

Selection order: device's explicit profile, device's group profile, longest
matching subnet, then `default_profile`. Devices use explicit IPv4/IPv6 addresses;
IPv4-mapped addresses are canonicalized. Duplicate device addresses/subnets and
missing references fail validation. This is source-IP policy, not authenticated
device identity. A proxy/NAT may hide clients; forwarded HTTP headers are not
trusted for identity.

Profiles select `lists` by ID (empty means all eligible lists) and `categories`
by category ID. Lists with no category are eligible by default; categorized
lists require an active profile selecting their category. Unknown clients use
the default profile, or only uncategorized lists if no default exists.

Schedules use **UTC**, ISO weekdays Monday=1 through Sunday=7, and minutes
0–1439. Windows include their start and exclude their end. An overnight window
belongs to its start day. Multiple windows are ORed; empty means always active.
Equal start/end is rejected; use no schedules for an always-active profile.
Outside a profile's windows, only global manual rules apply: profile rules and
all imported lists for that client are inactive. For always-on parental blocks,
put them in global manual rules or use an always-active profile. UTC has no DST
adjustment; local timezone schedules are not implemented.

## Sources and parsers

Each `[[filtering.lists]]` needs a unique `id`, `format`, and exactly one of:
`path`, `url`, or `text`. Relative paths resolve beside the config. Sources load
at startup; a missing, empty, malformed, or oversized source fails startup before
listeners serve queries. Local imports require regular files. Replace local
files atomically to avoid presenting an incomplete file during refresh.

Formats:

- `domains`: one rule per line, optional `#` comment; supports exact and suffix rules.
- `hosts`: sinkhole IP then one or more domains; only loopback/unspecified IPs
  accepted. Imports become block rules, not address rewrites.
- `adblock`: `||domain^` blocks; `@@||domain^` allows. URL, cosmetic, modifier,
  and regex syntax is unsupported and counted, never widened to domain rules.
  Malformed domain-only rules fail the update. Unsupported-only lists fail.

Comments, blank lines, UTF-8 BOM, and duplicates are handled. The parser API
returns duplicate and unsupported counts. Hosts files may contain localhost
entries; omit them if localhost blocking is unwanted.

Online sources require HTTPS port 443 and valid public-root TLS certificates.
Credentials, fragments, redirects, proxies, compressed bodies, non-200 responses,
and private/special-use target IPs are rejected. DNS answers are checked and
pinned to the connection to resist rebinding. Bootstrap uses the host's DNS;
ensure it works before Lumen starts (do not depend solely on this daemon to
resolve its own list hosts). URL errors do not print URL credentials or tokens.

Limits: 8 MiB per list, 4096 bytes per line, 250000 rules total across sources
and manual tiers; 4096 manual rules per tier; 64 lists, 128 profiles/groups,
1024 devices (32 addresses each), 256 subnets, 32 schedule windows per profile.
Downloads have a 30-second outer deadline, 5-second connect timeout, and a
25-second HTTP deadline. Config remains bounded to 64 KiB. Active, previous,
and candidate snapshots coexist during updates; OS memory limits are still
needed for a hard RSS cap.

## Atomic refresh and rollback

`refresh_secs` defaults to 86400; use 60–604800 or 0 to disable periodic refresh
for a source. Every 30 seconds the daemon checks due sources. It fetches/parses
all due sources, validates the combined rule budget, builds a candidate, then
publishes one snapshot. Queries see either the old or new generation. Any
failure retains the whole live generation and prior rollback snapshot. Failed
attempts wait until the next source interval; they do not loop continuously.

On Unix, send `SIGUSR1` to the daemon PID for a forced refresh of all sources;
`SIGUSR2` swaps to the previous successful generation. Rollback pauses automatic
refresh until a successful forced refresh; this prevents immediately restoring
the list you just rejected. A second rollback swaps generations again. Only one
previous generation is retained in memory. Restart reloads configured sources;
rollback does not edit source files or persist snapshots.

With managed state enabled, every platform can queue `lumenctl filter refresh`
or `lumenctl filter rollback` through the local SQLite control store. Unix
signals remain supported. Embedded hosts can use `RunningServer.filter.refresh()`,
`refresh_due()`, `rollback()`, and `explain()`. Filter generations remain
memory-only. No unauthenticated management route is exposed.

## Block responses and privacy

`filtering.action` defaults to `{ kind = "nxdomain" }`. Profiles can override it.
Other kinds: `nodata`, `refused`, `address` with `ipv4` and/or `ipv6`, or `cname`
with `target`. Address actions return only the requested A/AAAA family; other
record types or missing families return NODATA. CNAME actions return one alias,
without resolving its target. Synthetic answers have TTL zero, no AD/signatures,
and are never written into resolver caches. They are local policy, not validated
authoritative DNS answers; independently validating clients may reject them.

Aggregate `lumen_filter_*_total` metrics count allowed/blocked decisions, refresh
success/failure, and rollbacks. No domain/client/profile labels or query history
are stored. Explicit `decision_log = true` writes names, client IPs, and decisions
to stderr; it is off by default. Retention/redaction then belongs to your log
collector. List refresh errors remain generic and preserve live policy.

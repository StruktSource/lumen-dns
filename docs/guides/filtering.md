# Filtering

Lumen can refuse to resolve names you do not want: ads, trackers, malware, or categories like adult content. It can apply different rules to different devices and at different times.

> [!NOTE]
> **No block list is preloaded.** Filtering starts empty. You choose and trust your own sources. The bundled example only uses reserved fake domains.

## How it works

Filtering runs after a client is admitted and **before** any cache or resolver work, on every transport (UDP, TCP, DoH, DoT, DoQ). With no `[filtering]` table, every name is allowed.

What it checks and what it cannot do:

- Rules apply to the **name being asked**, including unusual DNS labels.
- Rules also check every **CNAME target** in an upstream answer. A blocked target replaces the whole answer with your block action, so a tracker hidden behind an innocent-looking alias is caught. The CNAME check applies to the final response; it never edits or re-signs DNSSEC data.
- They do **not** look at URLs, HTTP paths, or app content.
- A device that uses a different DNS service can bypass this policy. Use your firewall or router for that.

## Try it safely

The example config demonstrates every feature with fake `.example` domains:

```sh
lumen --config config/filtering.example.toml --check
lumenctl filter-explain --config config/filtering.example.toml \
  --client 192.0.2.10 --domain games.example --at 75600
lumen --config config/filtering.example.toml
```

`filter-explain` builds a separate snapshot from your config and tells you whether a name would be blocked, which rule, list, and category won, which profile, device, or group was selected, the action, and the generation. It does not contact the running daemon or send a DNS query. `--at` is Unix seconds (default: now), which is handy for testing schedules. HTTPS list sources still need network access.

## Add block lists

### From the web console

Open **Filtering → Lists** and use **Quick install**. It offers the large public lists, checked against their publishers:

- Hagezi: Light, Normal, Pro, Pro++, Ultimate, Threat Intelligence (three sizes), fake shops, pop-up ads, DoH/VPN bypass, and Apple and Windows telemetry
- **Child safety**, with one category per list (see below)
- OISD small and big
- AdGuard DNS filter
- StevenBlack
- 1Hosts Lite
- Phishing Army

Three bundles (**Recommended**, **Light**, **Strict**) install a sensible combination in one click. A list installs as an ordinary list with a daily refresh, and nothing downloads until you apply. Profiles that limit themselves to named lists get the new lists added so they take effect. The page also flags any list the default profile does not use.

Installing and removing lists takes effect **right away, in the background**. You confirm, Lumen downloads, and blocking starts when the lists are ready. DNS keeps working, and lists you already have are not downloaded again. You can cancel from the progress panel; nothing changes if you do.

#### Child-safety categories

The **Child safety** group installs lists that each carry their own category, so they apply only to profiles that select the category and adults on the network are not affected:

| Category | List | Source |
| :--- | :--- | :--- |
| `adult` | Adult content | Hagezi |
| `gambling` | Betting and casino sites (large, about 627,000 rules) | Hagezi |
| `social` | Social networks and messengers | Hagezi |
| `drugs` | Drug sales and promotion | BlocklistProject |
| `piracy` | Pirate streaming and download sites | Hagezi |
| `torrent` | Torrent trackers and sites | BlocklistProject |
| `tiktok`, `youtube`, `facebook` | One platform each, so a child can keep one and lose another | BlocklistProject |

Installing one creates a profile called `child-safe` (or extends it) and adds the category to it. **Nothing applies to a device until it is in that profile**: put the child's device in a group whose profile is `child-safe`, or assign the profile on the Devices page. A schedule on the profile limits the categories to certain hours. Use **Explain** to see which list and category blocked a name. Rule counts are approximate, and the lists are community-maintained: they reduce what a child meets by accident, but they do not replace supervision.

### In the config file

Each `[[filtering.lists]]` needs a unique `id`, a `format`, and exactly one source: `path`, `url`, or `text`.

```toml
[[filtering.lists]]
id = "my-ads"
format = "adblock"
url = "https://lists.example/ads.txt"
refresh_secs = 86400
```

| Format | What it reads |
| :--- | :--- |
| `domains` | One domain per line, with optional `#` comments. Supports exact and suffix rules. |
| `hosts` | A sinkhole IP, then one or more domains. Only loopback or unspecified IPs are accepted. Entries become block rules, not address rewrites. |
| `adblock` | `\|\|domain^` blocks and `@@\|\|domain^` allows. URL, cosmetic, modifier, and regex syntax is unsupported: it is counted and never widened into domain rules. |

Good to know:

- Comments, blank lines, a UTF-8 BOM, and duplicates are handled. Hosts files may contain `localhost` entries; remove them if you do not want localhost blocked.
- Names that fail validation (for example an invalid punycode label) are skipped and counted, so one bad entry cannot sink a large public list. Skipping can only leave a name unblocked. A list with no usable rule fails.
- Relative paths resolve beside the config. A missing, empty, malformed, or oversized source fails startup before any query is served. Replace local files atomically.

### Online source requirements

Downloads must use HTTPS on port 443 with a valid public-root certificate. Lumen rejects credentials, fragments, redirects, proxies, non-200 responses (other than 304 Not Modified), and private or special-use target addresses. Lookups are pinned to the connection to resist DNS rebinding. Error messages never print URL credentials or tokens.

**Lighter downloads.** Lumen asks for compressed transfer (gzip, Brotli, deflate, or zstd) and the 64 MiB limit applies to the **decompressed** list. It remembers each list's `ETag` and `Last-Modified` and sends them back as `If-None-Match` and `If-Modified-Since`, so an unchanged list costs a `304` instead of a full download.

**Disk cache (managed mode).** With `--state`, downloaded lists are also kept in a `filter-cache` folder beside the state database (Unix mode `0700`, files `0600`; at most 128 lists and 512 MiB). After a restart a list that is still inside its `refresh_secs` is read from disk instead of downloaded, and an older one is revalidated with a `304` request. The cache holds public list text only, never credentials, and a damaged or oversized file is ignored and downloaded again. Without `--state` nothing is written to disk.

The host's DNS is used to find list servers, so make sure it works **before** Lumen starts. Do not rely only on Lumen to resolve its own list hosts.

## Rules and precedence

Manual rules go under `filtering.rules.allow` and `filtering.rules.block`, or in a profile's `rules` table.

```toml
[filtering.rules]
allow = ["safe.ads.example"]
block = ["manual.example", "=exact.example"]
```

| Pattern | Matches |
| :--- | :--- |
| `example.com` or `*.example.com` | That domain and all its subdomains, at label boundaries |
| `=example.com` | Exactly that name only |

Rules are normalized for case, international (IDNA) names, and a trailing dot. URLs, regular expressions, and partial-label patterns are rejected.

**First matching tier wins:**

1. The active profile's manual rules
2. Global manual rules
3. Selected imported lists
4. Otherwise: allow

Within a tier, any matching **allow** beats every matching **block**. So a profile block can override a global allow, and a global block can override an imported exception. Between rules of the same action, the most specific suffix wins, and list order breaks ties.

## Device and group policies

Lumen picks a profile for each client in this order:

1. The device's own profile
2. The device's group profile
3. The longest matching subnet
4. `default_profile`

```toml
[filtering]
default_profile = "family"

[[filtering.profiles]]
id = "bedtime"
categories = ["adult", "games"]

[[filtering.groups]]
id = "children"
profile = "bedtime"

[[filtering.devices]]
id = "tablet"
addresses = ["192.0.2.10", "2001:db8::10"]
group = "children"

[[filtering.subnets]]
network = "192.0.2.0/24"
profile = "family"
```

- Devices are matched by explicit IPv4 or IPv6 addresses (IPv4-mapped addresses are normalized). Duplicate addresses or subnets, and missing references, fail validation.
- This is **source-IP policy, not device identity**. NAT or proxies can hide clients, and forwarded HTTP headers are not trusted.
- A profile's `lists` selects lists by ID (empty means all eligible lists), and `categories` selects category IDs. Lists without a category are eligible by default. Categorized lists apply only when an active profile selects their category.
- Unknown clients use the default profile, or only uncategorized lists if there is none.
- You can also manage devices with [`lumenctl device`](../reference/cli.md#devices) or in the [web console](web-console.md).

## Schedules

```toml
[[filtering.profiles.schedules]]
days = [1, 2, 3, 4, 5, 6, 7]   # Monday=1 ... Sunday=7
start_minute = 1260             # 21:00 UTC
end_minute = 420                # 07:00 UTC the next day
```

- Schedules use **UTC**, with minutes 0 to 1439. There is no daylight-saving adjustment, and local time zones are not implemented.
- A window includes its start and excludes its end. An overnight window belongs to its start day.
- Several windows are combined (OR). No windows means always active. Equal start and end is rejected.
- **Outside a profile's windows, only global manual rules apply.** The profile's rules and all imported lists for that client switch off.
- For always-on blocks, use global manual rules or an always-active profile.

## Regular-expression rules

For patterns that plain domain rules cannot express, add `regex_allow` and `regex_block` next to `allow` and `block`, globally or in a profile:

```toml
[filtering.rules]
regex_block = ['ads[0-9]+\.example\.com']
regex_allow = ['ads7\.example\.com']
```

- A pattern must match the **whole** lowercase name (it is anchored for you), without the trailing dot.
- Precedence is unchanged: profile rules, then global rules, then lists, and **allow wins within each tier**. Within a tier, exact and suffix rules are checked before regular expressions.
- Limits keep matching fast and bounded: 128 expressions and 32 KiB of pattern text per rule set, 1024 bytes per pattern, one line each, and strict compiled-size limits. The engine has no backtracking, so matching time grows only with the name length. Oversized or invalid patterns are rejected when the config loads, and they count toward the manual-rule total.
- `filter-explain` shows the winning pattern as `/pattern/`.

## SafeSearch

Set `safe_search = true` on a profile to send supported search services to their documented restricted endpoints. It is off by default and applies only to clients that use that profile.

| Name asked | Answered as an alias to |
| :--- | :--- |
| `www.google.com` | `forcesafesearch.google.com` |
| `www.bing.com` | `strict.bing.com` |
| YouTube names (`www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com`, `www.youtube-nocookie.com`) | `restrictmoderate.youtube.com` |

Only these names are rewritten. Other Google or Bing country sites, other search engines, and apps that use their own DNS are not covered, so this is a household convenience and not a security boundary. A block or allow rule for the same name wins over SafeSearch. Decisions use the same category and logging rules as other filters (`category = "safe_search"`), and nothing extra is logged.

## What blocked clients see

`filtering.action` defaults to `{ kind = "nxdomain" }`, and profiles can override it.

| Kind | Reply |
| :--- | :--- |
| `nxdomain` | "Name does not exist" (default) |
| `nodata` | "Name exists, no records of this type" |
| `refused` | Query refused |
| `address` | A fixed `ipv4` and/or `ipv6` address, only for the matching A or AAAA family; other types get NODATA |
| `cname` | One alias to `target`, which is not resolved |

Synthetic answers have a TTL of zero, no DNSSEC flag or signatures, and are never cached. They are local policy, not authenticated DNS, so a client that validates DNSSEC itself may reject them.

## Updating and rolling back lists

- `refresh_secs` defaults to 86400. Use 60 to 604800, or `0` to disable periodic refresh for a source.
- Every 30 seconds Lumen checks which sources are due, fetches and parses them all, checks the combined rule budget, builds a candidate, then publishes one snapshot. **Queries see either the old or the new generation, never a mix.** Any failure keeps the whole live generation, and a failed source waits for its next interval.
- Only **one** previous generation is kept, in memory. Restarting reloads the configured sources (from the disk cache in managed mode when still fresh), and rollback never edits source files.

Ways to trigger a refresh or rollback:

| Method | Refresh | Roll back |
| :--- | :--- | :--- |
| `lumenctl` (managed mode, all platforms) | `lumenctl filter refresh --state FILE` | `lumenctl filter rollback --state FILE` |
| Unix signal | `SIGUSR1` to the daemon | `SIGUSR2` |
| Management API | `POST /v1/filter/refresh` | `POST /v1/filter/rollback` |

Rollback pauses automatic refresh until a successful forced refresh, so you do not immediately restore the list you just rejected. A second rollback swaps the generations back. Embedded Rust hosts can call `RunningServer.filter.refresh()`, `refresh_due()`, `rollback()`, and `explain()`.

## Limits and memory

| Limit | Value |
| :--- | :--- |
| List size / line length | 64 MiB / 4096 bytes |
| Total rules (all sources and manual tiers) | 4,000,000 |
| Manual rules per tier | 4096 |
| Lists / profiles and groups / devices / subnets | 64 / 128 / 1024 (32 addresses each) / 256 |
| Schedule windows per profile | 32 |
| Config file | 64 KiB |
| Download | 90-second deadline per attempt (80 seconds of HTTP), 5-second connect timeout, up to three retries on transient errors |

**Memory:** rules are stored as sorted 8-byte keys (a keyed hash of the domain), not strings. Hagezi Pro (about 213,000 rules) needs roughly 19 MiB in total. Pro, Ultimate, and the full threat-intelligence list together (about 2.4 million rules) need about 150 MiB. The previous generation stays in memory for rollback, but unchanged lists are shared between generations. Match explanations still name the rule, because Lumen walks the query's own suffixes. Use OS or container limits for a hard memory ceiling.

## Privacy and logging

Aggregate `lumen_filter_*_total` metrics count allowed and blocked decisions, refreshes, and rollbacks, with no domain, client, or profile labels. Filtering stores no query history; the separate opt-in [query history](query-history.md) does. Setting `decision_log = true` writes names, client IPs, and decisions to stderr; it is **off by default**, and retention or redaction is then up to your log collector. Refresh errors stay generic and never disturb live policy.

## Related

- [Web console](web-console.md)
- [Configuration: filtering](../reference/configuration.md#filtering)
- [Monitoring](monitoring.md)

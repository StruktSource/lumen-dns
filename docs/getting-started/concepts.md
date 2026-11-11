# Concepts

New to running your own DNS? This page explains the ideas behind Lumen in plain language. You do not need any of this to try Lumen, but it makes the other docs much easier to follow.

## What DNS does

Computers connect to numbers (IP addresses), but people use names such as `example.com`. **DNS** (the Domain Name System) is the phone book that turns names into addresses. Almost every connection your devices make starts with a DNS question.

A **DNS resolver** is the service that answers those questions for your devices. Today that is usually your router or your internet provider, and sometimes a public service. Lumen lets you run that resolver yourself.

## Why run your own

- **Privacy:** you decide who sees your DNS questions. Lumen keeps no query history unless you turn it on, and it sends no telemetry.
- **Control:** block ads, trackers, or unwanted categories for the whole network, with different rules per device.
- **Visibility:** see what the resolver is doing through aggregate metrics and a built-in web console.

## Recursive or forwarding?

A resolver can find answers in two ways. Lumen supports both, and uses only one at a time.

| Mode | How it works | Who learns your questions |
| :--- | :--- | :--- |
| **Recursive** (default) | Lumen asks the internet's own DNS servers directly, starting at the root and following the chain down to the domain's own server. | The servers along the way (root, top-level domain, and the domain's own server). No single company sees everything. |
| **Forwarding** | Lumen hands each question to a resolver you choose, such as Cloudflare or Quad9, ideally over an encrypted connection. | The provider you chose. |

Pick recursive if you want the most independence. Pick forwarding if you prefer a trusted provider or if recursion is slow on your network. See [Resolver modes](../guides/resolver-modes.md).

## DNSSEC

Normal DNS answers can be forged. **DNSSEC** adds digital signatures to DNS data so a resolver can prove an answer is genuine. Lumen checks these signatures itself, so it does not have to trust whoever passed the answer along. DNSSEC is on by default. It proves *authenticity*; it does not hide your questions from anyone. See [DNSSEC and trust anchors](../reference/dnssec-and-trust.md).

## Encrypted DNS

Classic DNS (over **UDP** and **TCP**, port 53) travels in plain text. Lumen can also speak three encrypted forms. These need a TLS certificate that you provide.

| Name | Short for | Notes |
| :--- | :--- | :--- |
| **DoT** | DNS over TLS | A dedicated encrypted port. Common on Android and routers. |
| **DoH** | DNS over HTTPS | Looks like ordinary web traffic. Common in browsers. |
| **DoQ** | DNS over QUIC | Newer, built on UDP. Fewer clients support it. |

See [Encrypted DNS](../guides/encrypted-dns.md).

## Filtering

Lumen can refuse to resolve names you do not want, such as ad servers. When a name is blocked, Lumen answers with a "does not exist" reply instead, so the app simply cannot connect.

- **Rules** are single domains you allow or block by hand.
- **Lists** are big collections of domains maintained by others. Lumen downloads and refreshes them, but ships with none enabled.
- **Profiles** bundle which lists and categories apply, such as a stricter "kids" profile.
- **Devices and groups** connect a profile to specific machines by IP address.
- **Schedules** switch a profile on only at certain hours (in UTC).

Filtering works on the name a device asks about. It cannot stop an app that uses its own DNS server. See [Filtering](../guides/filtering.md).

## Managed mode and the web console

By default Lumen reads one settings file when it starts. In **managed mode** (started with `--state`), Lumen also keeps its settings, devices, and accounts in a small local database. This unlocks:

- the **web console**, a browser interface for everything;
- **`lumenctl`**, a command-line tool that talks to the running service;
- **safe reloads**: a new configuration is checked first and rolled back if it fails.

See [Managed mode](../guides/managed-mode.md) and the [Web console](../guides/web-console.md).

## Safe defaults

Out of the box, Lumen:

- listens on **loopback only** (your own computer), so nobody else on the network can use it;
- resolves **recursively** with **DNSSEC** enabled and no outside provider;
- keeps **no query history** (you can opt in) and sends **no telemetry**;
- ships with **no block lists**, **no management API**, and **no metrics**.

You opt in to each feature deliberately.

## Glossary

| Term | Meaning |
| :--- | :--- |
| **Allowlist / CIDR** | A range of addresses written like `192.168.1.0/24`. Lumen only answers clients inside the allowed ranges. |
| **Cache** | Remembered answers, so repeated questions are fast. Lumen's DNS caches are bounded and live in memory only. In managed mode, downloaded block lists are also kept in a small bounded folder on disk so restarts are quicker. |
| **ETag** | A tag a list server sends with a download. Lumen sends it back later so an unchanged list costs a tiny "not modified" reply instead of a full download. |
| **Loopback** | The address that always means "this computer" (`127.0.0.1` or `::1`). |
| **NXDOMAIN** | The DNS reply "this name does not exist". Lumen uses it for blocked names by default. |
| **Single sign-on (SSO)** | Signing in to the console through an identity provider you already run (Authentik, Authelia, Pocket ID, and others) using OpenID Connect. Optional and off by default; see [External login](../guides/external-login.md). |
| **Root hints** | The built-in list of the internet's 13 root server groups, where recursion starts. |
| **Two-step verification (2FA)** | A second proof when signing in, from an authenticator app. Each person turns it on under **Users → My account**. |
| **Trust anchor** | The root signing key that DNSSEC validation starts from. |
| **TTL** | How long an answer may be remembered before it must be looked up again. |
| **Upstream** | A resolver that Lumen forwards questions to. |

## Next steps

- [Quick start](quick-start.md): run Lumen now.
- [Architecture](../design/architecture.md): how the parts fit together, if you are curious.

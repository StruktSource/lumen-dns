# v0.6.0 optimization audit

Audited 2026-11-11, before performance-sensitive edits. Scope: request admission,
all client transports, DNS parsing and encoding, filtering and list loading,
resolver/provider/cache paths, management/storage/console paths, and release builds.
Decisions use code-path reasoning; no throughput or latency improvement is claimed.

| Idea | Existing path and decision | Costs and limits |
| --- | --- | --- |
| Linux io_uring | Absent. Defer: Tokio sockets already multiplex bounded async tasks; WAN recursion latency is not an event-loop syscall problem. | Separate Linux runtime/buffer ownership, kernel compatibility and cancellation work. Keep one portable engine. |
| SO_REUSEPORT | Absent; TCP restart uses SO_REUSEADDR. Defer until multiple UDP receive workers are justified. | More sockets, admission fairness and shutdown coordination; no benefit to a single receiver. |
| recvmmsg/sendmmsg | Absent. Defer Linux UDP batching. | Helps bursts only; partial sends, bounded batch fairness and unsafe wrappers/dependencies add maintenance. Does not speed encrypted upstreams or authority walks. |
| Zero-copy/reusable buffers | UDP receive buffer already reused; owned packet copies keep concurrent requests independent. Keep. Transfer completed resolver response Vec instead of cloning it. | Safe ownership transfer removes one allocation/copy per catalog response. TLS, QUIC, DNS decoding still require owned buffers. No zero-copy claim. |
| jemalloc/mimalloc | Absent. Defer global allocator replacement. | Affects runtime, TLS and SQLite too; platform, RSS and packaging costs without an identified allocation pattern needing a new allocator. |
| Request arena | Absent. Reject for this release. | Hickory caches, shared recursion and async cancellation cross request lifetimes; arena ownership would complicate bounded memory. |
| Radix/trie/Bloom | Downloaded filters already use sorted flat 8-byte keyed RuleKey entries and binary search; suffix walking borrows strings. Retain. | Bloom adds memory/build work and still requires exact lookup; pointer tries worsen locality. No replacement of Hickory DNS caches. |
| Compact domain/string encoding | Compact hashes already cover downloaded lists; retain full names where DNS correctness or manual-rule explanation needs them. Avoid allocating discarded block-match domains. | Hash behavior and allow precedence unchanged. No new encoding or collision policy. |
| B-tree/flat/pointer structures | Flat filters already implemented; manual rules/device maps and bounded Hickory caches serve different paths. Keep. | No common-path case for a global tree rewrite; extra indexes duplicate memory. |
| Small nom/zerocopy parser | Existing Lumen bounded precheck plus full Hickory decoder rejects trailing data, invalid sections and excessive records. Keep. | Rewriting records, compression and DNSSEC risks correctness. Hickory Request has no production constructor from a decoded Message, so adapter re-decoding remains deferred. |
| Release compiler options | Default release already uses opt-level=3, codegen-units=16, no debug info, unwind. Enable cross-crate ThinLTO. | More link time/memory; retain codegen units for build parallelism and unwind for task-failure semantics. Fat LTO/codegen-units=1 deferred. Strip debug info is redundant; full symbol stripping harms diagnosis. |
| Native CPU/SIMD | No native flags. Keep portable artifacts. Offer separate local command below. | Native binaries can fail on other CPUs. Explicit AVX2/AVX-512 kernels lack a suitable bulk hot path; crypto remains with ring's dispatch. |

## Changes selected

- Move the finished response buffer out of the capture mutex after the catalog returns.
- Build a filter Hit only when it is an allow or can become the retained block.
- Enable portable ThinLTO without changing panic handling, minimum CPU or version.
- Split encrypted provider transport attempts into bounded deadline shares (correctness
  fix, not a benchmark claim). Keep certificate and DNSSEC checks and cancellation.

No Linux-only I/O backend, new allocator, parser replacement, arena, tree, Bloom filter,
explicit SIMD or custom crypto is included.

## Optional machine-local build

```sh
CARGO_TARGET_DIR=target/native RUSTFLAGS='-C target-cpu=native' cargo build --release --locked
```

Opt-in only. Keep these binaries on the build machine or CPUs with the same features.
CI, containers and release archives do not use this command. No native-build performance
claim or AVX requirement is made.

## Evidence and upstream contracts

- [Tokio io_uring runtime and buffer model](https://docs.rs/tokio-uring/latest/tokio_uring/)
- [Linux socket options](https://man7.org/linux/man-pages/man7/socket.7.html),
  [recvmmsg](https://man7.org/linux/man-pages/man2/recvmmsg.2.html),
  [sendmmsg](https://man7.org/linux/man-pages/man2/sendmmsg.2.html)
- [Cargo release profiles](https://doc.rust-lang.org/cargo/reference/profiles.html)
- [Rust target feature safety](https://doc.rust-lang.org/core/arch/index.html)
- [Hickory 0.26.3 resolver options](https://docs.rs/hickory-resolver/0.26.3/hickory_resolver/config/struct.ResolverOpts.html)
- [Tokio timeout cancellation](https://docs.rs/tokio/latest/tokio/time/fn.timeout.html)

Local and hosted evidence belongs in [verification](verification.md). Public-network
cold-recursion improvement and capacity remain unproven.

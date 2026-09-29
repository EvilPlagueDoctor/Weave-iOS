# VeilKnit merge: current shutdown + gossip/token index + distributed lexical library

This tree uses `VeilKnit-Daemon-Testing-WalkNodeObserved-Optimized-Diagnostics` as the base.
The shutdown-sensitive implementations from that tree were intentionally preserved.

## Added from the newer Android Distributed Lexical Library branch

- daemon-owned gossip engine v2 (`src/gossip/mod.rs`)
  - application-scoped caches
  - generic fingerprints / MinHash-style channels
  - opaque exact-search index tokens
  - required / preferred / excluded token probes
  - compact daemon-to-daemon gossip wire format
  - bounded fanout, TTLs, dedupe and claimed-source tracking
- distributed lexical library (`src/lexical_library/*`)
  - per-app named lexical libraries
  - Unicode normalization / segmentation / transliteration support
  - word/phrase statistics and associations
  - gossip hints plus durable per-app DHT pages
  - main-DHT lexical-library advertisement at subkey 12
- local API gossip and lexical commands
- console diagnostics:
  - `gossip-test-set/search/list/stats`
  - `lex-test-set/search/compare/stats`

## Shutdown behavior deliberately preserved

The following files remain the newer shutdown-base implementations, not the older copies from
the lexical branch:

- `src/dht_module/mod.rs`
- `src/walk_task/mod.rs`
- `src/network_supervisor/mod.rs`
- `src/mailbox/*`
- `src/shutdown_debug.rs`
- `src/mailbox_walk_debug.rs`

That preserves:

- active WalkSession JoinHandle ownership and cancel/abort/join fallback
- stop-aware automatic walk scheduler
- out-of-band mailbox shutdown signal
- interruptible `WalkNodeObserved`
- caller-aware cancellation of in-flight foreign DHT reads (`reply.closed()`)
- optimized/deduplicated WalkNodeObserved service fetching
- lifecycle `continue_after_timeout()` support and diagnostic watchdog behavior

## Integration-specific shutdown adjustment

The lexical library is a network-dependent Announce hook. To avoid reintroducing a shutdown
warning when several libraries are dirty:

- dirty lexical libraries are flushed with bounded concurrency of 4
- the main-DHT lexical advertisement set is published once after the flush batch
- the lexical hook budget is 10 seconds
- the Lifecycle Announce tier is 12 seconds (NodeDependent remains 18 seconds)
- watchdog remains 65 seconds

## Files intentionally changed from the shutdown base

- `Cargo.toml`
- `src/main.rs`
- `src/api/local.rs`
- `src/handshake/mod.rs`
- `src/types/mod.rs`
- `src/user_dht/mod.rs`
- `src/lifecycle/mod.rs` (Announce budget only)
- new `src/gossip/mod.rs`
- new `src/lexical_library/*`

No Rust toolchain was available in the merge environment, so this tree received static/source
validation only. A local `cargo check` / release build remains the definitive compile test.

# Android daemon backend update — Gossip + Distributed Lexical Library

This Android source tree has been updated to use the same Rust daemon core as
`VeilKnit-Daemon-Distributed-Lexical-Library.zip`, while retaining the Android JNI,
foreground-service, Binder, and Compose application layers.

## What changed

- Added the daemon-managed gossip engine and exact token index.
- Added `src/lexical_library/` with the distributed lexical-library implementation.
- Added lifecycle coordinator/shutdown modules used by the current backend.
- Updated `api/local.rs`, `handshake`, `user_dht`, `network_supervisor`, and related
  backend modules to the current versions.
- Added Rust dependencies used by lexical normalization/comparison:
  `unicode-normalization`, `unicode-segmentation`, and `deunicode`.
- Main-DHT lexical-library advertisement uses reserved subkey 12. The Android daemon's
  existing main DHT already has 251 subkeys, so this does not require a new main DHT.

## Android compatibility

No AIDL schema change was necessary. `VeilKnitApiService.transact()` forwards arbitrary
protocol-v3 JSON requests, so the new gossip and lexical actions automatically pass through
the Binder bridge.

The Android JNI bridge remains responsible for:

- daemon startup/login/signup input,
- graceful stop requests,
- GUI/console command input,
- Rust log forwarding to Kotlin,
- Android Veilid setup.

The current ConnectivityManager generation bridge remains unchanged from the supplied
Android source.

## New local API actions

The embedded Rust API now recognizes:

- `publish_gossip_object`
- `withdraw_gossip_object`
- `search_gossip`
- `list_gossip`
- `confirm_gossip_object`
- `get_gossip_stats`
- `subscribe_gossip`
- `observe_lexical`
- `withdraw_lexical_object`
- `search_lexical`
- `compare_lexical_terms`
- `get_lexical_association`
- `get_lexical_stats`

The old raw `send_gossip` action remains available.

## Built-in diagnostic commands

The Rust command surface includes:

```text
lex-test-set rust syntax dark
lex-test-search rust syntax
lex-test-compare firstname firstnam3
lex-test-stats

gossip-test-set rust syntax dark
gossip-test-search rust syntax
gossip-test-list
gossip-test-stats
```

These can be delivered through the existing Android command bridge when needed.

## Build status

This environment does not contain Rust/cargo, so the Android native library and APK were
not compiled here. Run the normal project build on the development machine:

```text
build_project.bat
```

or:

```text
./build_project.sh
```

The build invokes `cargo ndk ... build --lib` and will update `Cargo.lock` for the newly
added lexical dependencies if required.

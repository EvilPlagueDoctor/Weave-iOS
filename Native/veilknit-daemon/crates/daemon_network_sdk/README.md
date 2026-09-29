# daemon_network_sdk 0.4.0

High-level Rust SDK for applications attached to the VeilKnit daemon local API
protocol v3.

```toml
[dependencies]
daemon_network_sdk = { path = "../A_Daemon_Network/crates/daemon_network_sdk" }
tokio = { version = "1", features = ["full"] }
```

```rust
use daemon_network_sdk::{AppStoreWrite, ClientError, NetworkApp};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = match NetworkApp::builder("example.hello")
        .display_name("Hello Network")
        .connect()
        .await
    {
        Ok(app) => app,
        Err(ClientError::AuthorizationRequired(request)) => {
            println!("Approve with: {}", request.approval_command());
            request.wait().await?
        }
        Err(error) => return Err(error.into()),
    };

    println!("Connected as {}", app.local_user().identity);

    let signing = app.signing_identity().await?;
    println!("App signing key: {}", signing.public_key_hex);

    let store = app.create_store("example-store", 32).await?;
    let store = app
        .write_store(
            &store.store_id,
            Some(store.generation),
            &[AppStoreWrite { location: 0, value: b"hello".to_vec() }],
        )
        .await?;
    println!("Store {} generation {}", store.record_key, store.generation);

    Ok(())
}
```

Protocol v3 adds app-owned DHT stores, daemon-held Ed25519 app signing keys,
app-scoped reputation calls, and HMAC-SHA256 authentication. Protocol-v2
credentials must be approved again.

See `../../API_V3_NOTES.md` for the wire-level changes and limitations.

## Opaque live streams

The low-level authenticated client exposes `start_stream`, `join_stream`,
`write_stream`, `flush_stream`, `leave_stream`, `close_stream`, `list_streams`,
and `subscribe_streams`. Stream bytes are codec-agnostic. Live data travels over
authenticated routes; signed segment commitments are published in chained DHT
records for delayed public verification.

```rust,no_run
let descriptor = app
    .advanced_client()
    .start_stream(b"opaque metadata")
    .await?;
let result = app
    .advanced_client()
    .write_stream(&descriptor.stream_id, b"opaque bytes")
    .await?;
assert_eq!(result.accepted_bytes, 12);
```

Applications should share the signed `StreamDescriptor` using their own room,
profile, or invitation protocol. Viewers consume `StreamEvent::Data` as live
bytes and use later `StreamEvent::SegmentVerified` notifications according to
their latency/integrity policy.

## Account-aware credentials

The SDK now scopes automatically stored application credentials to the daemon's current
`profile_id`, which is published in `daemon_endpoint.json`.  A normal default installation
therefore stores credentials conceptually as:

```text
DaemonNetwork/credentials/<profile_id>/<app_id>.json
```

This matters when a user signs out of VeilKnit and signs in as another account. The old IPC
session closes with the old daemon. On the application's next connection attempt the SDK reads
the new endpoint/profile id and selects the credential belonging to that daemon account. If that
application has never been approved for the new account, `AuthorizationRequired` is returned and
a fresh approval request is created.

Credentials from older SDK versions used an unscoped `<app_id>.json` path. For backward
compatibility, the SDK tries a legacy credential only when no profile-scoped credential exists.
It migrates that credential into the current profile directory **only after it successfully
authenticates against the current daemon account**. A credential belonging to another account is
therefore not copied into the new account's scope.

Applications that provide an explicit `credential_path(...)` continue to own their own storage
layout and are not automatically profile-scoped.

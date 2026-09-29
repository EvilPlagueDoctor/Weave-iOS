# VeilKnit Local API v3

Protocol v3 adds the minimum daemon services needed by room/chat applications
without exposing user keys or unrestricted Veilid routing contexts.

## Breaking change

Authentication proofs now use HMAC-SHA256 with the registered 32-byte app
secret and domain `veilknit/app-auth/v2`. The local API protocol number is `3`.
Existing protocol-v2 credential files are rejected and must be reauthorized.

## New capability

- `SignAppData`

The standard application capability set now includes messaging, app-owned
storage, shared-store reads, app-scoped reputation, and app signing.

## New unauthenticated operation

- `get_api_info`

Returns protocol features and current request/value limits.

## App signing operations

- `get_app_signing_identity`
- `rotate_app_signing_key`
- `sign_app_payload`
- `verify_app_signature`

The daemon stores an Ed25519 key per application and account. Private keys never
cross the local API. Signed payloads use a caller-supplied domain plus a daemon-
defined framing prefix.

The returned public key is locally bound to the authenticated application and
account. Applications must publish or pin that public key in their room/profile
protocol before relying on it remotely.

## App-owned DHT storage operations

- `list_app_stores`
- `create_app_store`
- `read_app_store`
- `write_app_store`
- `read_public_store`

Owned stores keep the Veilid writer package in the daemon. Apps receive a public
record key, stable store ID, subkey count, and local generation.

Generation is an optimistic local guard. A multi-subkey DHT write is not atomic;
applications should commit immutable pages first and update a small manifest
last. Failed writes do not advance the local generation.

Current defaults:

- 64 owned stores per app
- 1,000 subkeys per store
- 32 KiB per value
- 256 subkeys per read
- 128 subkeys per write
- 512 KiB decoded payload per write request
- 1 MiB JSON-lines request limit

## App-scoped reputation operations

- `submit_reputation_observation`
- `retract_reputation_observation`
- `request_app_restriction`
- `revoke_app_decision`
- `get_reputation_view`
- `get_own_reputation_submissions`

The daemon attaches immutable authenticated-app/session provenance. Requested
restrictions are constrained to the requesting application. A room ban therefore
has no authority in another room or application.

## Files changed

- `src/app_services.rs` — app DHT stores and daemon-held signing keys
- `src/named_pipe_api.rs` — protocol v3 request/response surface
- `src/identity_manager.rs` — HMAC authentication and signing capability
- `src/reputation.rs` — app source-report access
- `src/main.rs` — service construction and API wiring
- `crates/daemon_network_sdk` — matching Rust client

## Mailer directory and persistent inbox additions

The bundled VeilKnit Mailer uses these authenticated actions:

- `list_known_nodes` (`ReadPublicProfiles`)
- `list_inbox` (`ReceiveMessages`)
- `read_inbox` (`ReceiveMessages`)
- `delete_inbox` (`ReceiveMessages`)

Inbox operations are filtered by the authenticated application id before message bodies are read or deleted. `veilknit.mailer` sends are routed through the mailbox service rather than the direct-message shortcut so the receiver has a durable daemon-managed inbox.

use futures::future::BoxFuture;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use veilid_core::*;
use rand_core::RngCore;
use rand_core::OsRng;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Mutex, Semaphore};
use tokio::time::timeout;
use sha2::{Sha256, Digest};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::dht_module::DHTModule;
use crate::reputation::{
    AccessLevel, ObservationDetails, ObservationInput, ObservationKind,
    ReputationModuleHandle,
};
use crate::node::Node;
use crate::network_events::{
    duration_millis, EventSeverity, NetworkEvent, NetworkEventBus, NetworkEventSource,
};
use crate::network_decode::{
    decode_bincode_limited, decode_json_limited, MAX_ROUTE_BLOB_RECORD_BYTES,
};
use crate::types::{current_timestamp, RouteBlobRecord, BLOB_LOCATION};

pub const VERSION_ID: u8 = crate::types::VERSION_ID;
const MAX_ESTABLISHED_HANDSHAKES: usize = 500;
const MAX_TOTAL_SESSIONS: usize = 2000;
const MAX_PENDING_INBOUND_HANDSHAKES: usize = 128;
const MAX_PENDING_OUTBOUND_HANDSHAKES: usize = 128;
const PENDING_SESSION_MAX_AGE_SECS: u64 = 60;
const CHECKIN_INTERVAL_SECS: u64 = 60;
pub const CHECKIN_TIMEOUT_SECS: u64 = 180;
const TIME_WINDOW: u64 = 120;

/// More than this many inbound type-1 requests from one DHT identity during
/// `HANDSHAKE_INIT_WINDOW_SECS` is treated as excessive activity.
const MAX_INBOUND_HANDSHAKE_INITS_PER_WINDOW: usize = 10;
const HANDSHAKE_INIT_WINDOW_SECS: u64 = 60;

// PATCH A: deliberately grouped so the defensive handshake changes can be
// tuned or reverted without disturbing the cryptographic redesign planned for
// the next patch.
const MAX_HANDSHAKE_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_DIRECT_APPLICATION_MESSAGE_BYTES: usize = 64 * 1024;
const DIRECT_APPLICATION_PROTOCOL_VERSION: u16 = 1;
const DIRECT_APPLICATION_TIME_WINDOW_SECS: u64 = 10 * 60;
/// Handshake-free application gossip is deliberately an untrusted hint channel.
/// It uses the peer's published Veilid private route but does not create or
/// require a VeilKnit handshake session. Applications must confirm important
/// claims through signed/application DHT state before trusting them.
const GOSSIP_APPLICATION_PROTOCOL_VERSION: u16 = 1;
// Version 2 is reserved for daemon-owned compact gossip. It base64-encodes the
// binary payload instead of serializing Vec<u8> as a large JSON integer array.
const GOSSIP_APPLICATION_COMPACT_PROTOCOL_VERSION: u16 = 2;
const GOSSIP_APPLICATION_TIME_WINDOW_SECS: u64 = 10 * 60;
const MAX_GOSSIP_MESSAGES_PER_SENDER_PER_MINUTE: usize = 120;
const MAX_GOSSIP_MESSAGES_GLOBAL_PER_MINUTE: usize = 600;
const REPUTATION_DIAGNOSTIC_COOLDOWN_SECS: u64 = 60;
const MAX_HANDSHAKE_TOKEN_BYTES: usize = 128;
const HANDSHAKE_CHALLENGE_BYTES: usize = 32;
const HANDSHAKE_SIGNATURE_BYTES: usize = 32;
const MAX_INBOUND_HANDSHAKE_JOBS: usize = 128;
const MAX_ROUTE_IMPORT_TRY_AGAIN: u8 = 6;
const MAX_HANDSHAKE_RETRIES: u8 = 3;
const HANDSHAKE_IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Message type 4 is a deliberately information-free protocol reset. It does
/// not reveal which field failed or whether the peer is locally restricted.
const HANDSHAKE_RESET_MESSAGE_TYPE: u8 = 4;
const HANDSHAKE_RESET_QUARANTINE_SECS: u64 = 5;
const HANDSHAKE_RESET_RESTART_SECS: u64 = 8;
const HANDSHAKE_RESET_WINDOW_SECS: u64 = 10 * 60;
const MAX_HANDSHAKE_RESETS_PER_PEER: usize = 3;
const HANDSHAKE_RESET_ABUSE_IGNORE_SECS: u64 = 15 * 60;
const MAX_DUPLICATE_REPLY_REPLAYS: u8 = 3;

const CHALLENGE_FAILURE_WINDOW_SECS: u64 = 24 * 60 * 60;
const CHALLENGE_REPUTATION_THRESHOLD: usize = 3;
const CHALLENGE_BAN_SUGGESTION_THRESHOLD: usize = 10;

// ============================================================================
// Encryption
// ============================================================================

/// Which cipher to use for encrypting application payloads after the handshake.
///
/// The initiator proposes a mode in their type-1 message.  The responder
/// echoes the same mode back in the type-2 reply.  If the echoed mode doesn't
/// match, the handshake is rejected - this makes the negotiation explicit and
/// easy to audit.
///
/// Adding a new variant here is the only change needed to support a new cipher;
/// implement it in `encrypt_payload` / `decrypt_payload` below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EncryptionMode {
    /// No encryption.  Payloads are sent as-is.  Useful for testing or for
    /// contexts where the Veilid private-route layer is considered sufficient.
    #[default]
    None,

    /// AES-256-GCM with a 96-bit random nonce prepended to the ciphertext.
    /// The key is the 32-byte X25519 shared secret produced during the
    /// handshake.
    ///
    /// Requires the `aes-gcm` crate:
    ///   aes-gcm = { version = "0.10", features = ["aes"] }
    Aes256Gcm,
}

/// Encrypt `plaintext` using the negotiated mode and the session key.
///
/// Returns the wire bytes (nonce ++ ciphertext for `Aes256Gcm`, or a plain
/// copy for `None`).
pub fn encrypt_payload(
    plaintext: &[u8],
    key: &[u8; 32],
    mode: EncryptionMode,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match mode {
        EncryptionMode::None => Ok(plaintext.to_vec()),

        EncryptionMode::Aes256Gcm => {
            // aes-gcm is already a hard dependency of this project (see
            // user_auth.rs), so this doesn't need to be feature-gated here.
            use aes_gcm::{
                aead::{Aead, KeyInit},
                Aes256Gcm as Cipher, Nonce,
            };

            let cipher = Cipher::new_from_slice(key)
                .map_err(|e| format!("AES key error: {e}"))?;

            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let padded = crate::security::padding::pad_for_direct_encryption(plaintext)
                .map_err(|error| format!("direct-message padding error: {error}"))?;
            let ciphertext = cipher
                .encrypt(nonce, padded.as_slice())
                .map_err(|e| format!("AES-GCM encrypt error: {e}"))?;

            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ciphertext);
            Ok(out)
        }
    }
}

/// Decrypt wire bytes produced by `encrypt_payload`.
pub fn decrypt_payload(
    wire: &[u8],
    key: &[u8; 32],
    mode: EncryptionMode,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match mode {
        EncryptionMode::None => Ok(wire.to_vec()),

        EncryptionMode::Aes256Gcm => {
            use aes_gcm::{
                aead::{Aead, KeyInit},
                Aes256Gcm as Cipher, Nonce,
            };

            if wire.len() < 12 {
                return Err("AES-GCM wire payload too short (missing nonce)".into());
            }

            let (nonce_bytes, ciphertext) = wire.split_at(12);
            let cipher = Cipher::new_from_slice(key)
                .map_err(|e| format!("AES key error: {e}"))?;

            let plaintext = cipher
                .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
                .map_err(|e| format!("AES-GCM decrypt error: {e}"))?;
            match crate::security::padding::unpad_after_decryption(&plaintext)
                .map_err(|error| format!("direct-message padding error: {error}"))?
            {
                Some(unpadded) => Ok(unpadded.to_vec()),
                // Backward compatibility with sessions created before
                // size-class padding was introduced.
                None => Ok(plaintext),
            }
        }
    }
}

// ============================================================================
// Status / State
// ============================================================================

#[derive(Clone, PartialEq, Debug)]
pub enum HandshakeStatus {
    None,
    InitSent,
    ChallengeReceived,
    Established,
    Failed,
}

/// Exact serialized wire flight retained for retransmission.
///
/// Retries must resend these bytes verbatim. Reconstructing a message can
/// accidentally change its timestamp, challenge, token, key, or signature and
/// leave the two peers in different protocol states.
#[derive(Debug, Clone)]
struct SavedHandshakeFlight {
    message_type: u8,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

impl SavedHandshakeFlight {
    fn new(message_type: u8, bytes: Vec<u8>) -> Self {
        let digest = handshake_digest(&bytes);
        Self {
            message_type,
            bytes,
            digest,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedHandshakeReply {
    flight: SavedHandshakeFlight,
    replay_count: u8,
}

#[derive(Debug, Clone)]
struct PendingHandshakeRestart {
    encryption_mode: EncryptionMode,
    verification: bool,
    maintain_connection: bool,
    restart_at: u64,
}

/// Token retained briefly after an accepted reset. Veilid's application-message
/// callback does not currently provide the incoming route id, so this token is
/// the strongest session binding available to distinguish repeated copies of
/// one genuine reset from a forged sender field.
#[derive(Debug, Clone)]
struct AcceptedResetToken {
    token: String,
    expires_at: u64,
}

pub struct HandshakeState {
    pub peer_dht: String,
    pub is_initiator: bool,

    pub peer_public_key: Option<PublicKey>,
    pub our_private_key: Option<EphemeralSecret>,
    pub our_public_key: PublicKey,

    pub route: Option<Vec<u8>>,
    pub status: HandshakeStatus,

    pub started_at: u64,
    pub last_attempt: u64,
    pub last_seen: u64,
    pub retries: u8,

    pub token: String,

    pub our_challenge: Option<Vec<u8>>,
    pub their_challenge: Option<Vec<u8>>,
    pub session_key: Option<[u8; 32]>,

    /// The encryption mode negotiated (or proposed) for this session.
    pub encryption_mode: EncryptionMode,

    /// If true, the manager sends periodic type-5 check-ins and removes the
    /// session on timeout.  Most callers should leave this false.
    pub maintain_connection: bool,

    /// Whether this was a verification-only handshake. Retained so a reset can
    /// restart the same operation rather than silently changing its purpose.
    verification: bool,

    /// Current outbound stage, already serialized. Tick retries send this
    /// exact byte vector rather than rebuilding a new protocol message.
    outgoing_flight: Option<SavedHandshakeFlight>,

    /// Hashes of received stage 1-3 packets. Repeated identical packets can be
    /// answered with the exact cached response; conflicting duplicates trigger
    /// the information-free reset.
    received_flights: HashMap<u8, [u8; 32]>,
    cached_replies: HashMap<u8, CachedHandshakeReply>,
}

impl HandshakeState {
    /// Encrypt an application payload using this session's key and mode.
    /// Returns `Err` if the session is not yet established (no key).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let key = self.session_key.ok_or("Session not yet established")?;
        encrypt_payload(plaintext, &key, self.encryption_mode)
    }

    /// Decrypt wire bytes received from the peer.
    pub fn decrypt(&self, wire: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let key = self.session_key.ok_or("Session not yet established")?;
        decrypt_payload(wire, &key, self.encryption_mode)
    }
}

// ============================================================================
// Wire message
// ============================================================================

#[derive(Serialize, Deserialize, Clone)]
pub struct HandshakeMessage {
    pub version: u8,
    /// 1 = init, 2 = welcome-reply, 3 = final, 4 = reset, 5 = check-in.
    pub message_type: u8,
    pub sender_dht: String,
    pub sender_pubkey: Vec<u8>,
    pub token: String,
    pub challenge: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub timestamp: u64,

    /// Proposed (type 1) or echoed (type 2) encryption mode.
    /// `None` on message types that don't participate in negotiation (3, 5).
    pub encryption_mode: Option<EncryptionMode>,

    /// Whether this session is intended to remain available for application
    /// traffic. Older peers omit the field and therefore behave as quick,
    /// short-lived handshakes.
    #[serde(default)]
    pub maintain_connection: bool,
}

// ============================================================================
// Authenticated direct application messages
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectApplicationEnvelope {
    protocol_version: u16,
    sender_dht: String,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirectApplicationPayload {
    protocol_version: u16,
    application_id: String,
    message_id: [u8; 16],
    sent_at: u64,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DirectApplicationMessage {
    pub application_id: String,
    pub message_id: [u8; 16],
    pub sender_dht: String,
    pub sent_at: u64,
    pub payload: Vec<u8>,
}

/// Wire envelope for handshake-free gossip. `sender_dht` is a claimed return
/// identity, not an authenticated identity. Consumers must treat all fields as
/// untrusted until independently confirmed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GossipApplicationEnvelope {
    gossip_protocol_version: u16,
    application_id: String,
    message_id: [u8; 16],
    sender_dht: String,
    sent_at: u64,
    payload: Vec<u8>,
}

/// Compact daemon-to-daemon gossip envelope. Version 1 remains unchanged for
/// application compatibility; version 2 is used by the daemon gossip engine so
/// binary frames do not inflate into JSON arrays of decimal byte values.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompactGossipApplicationEnvelope {
    gossip_protocol_version: u16,
    application_id: String,
    message_id: [u8; 16],
    sender_dht: String,
    sent_at: u64,
    payload_base64: String,
}

#[derive(Debug, Clone)]
pub struct GossipApplicationMessage {
    pub application_id: String,
    pub message_id: [u8; 16],
    pub sender_dht: String,
    pub sent_at: u64,
    pub payload: Vec<u8>,
}

// ============================================================================
// Manager
// ============================================================================

pub type EstablishedPeerHandler =
    Arc<dyn Fn(RecordKey) -> BoxFuture<'static, ()> + Send + Sync>;

pub struct HandshakeManager {
    pub sessions: HashMap<String, HandshakeState>,
    pub veilid: VeilidAPI,
    pub dht_module: DHTModule,
    pub our_dht: String,

    /// Default encryption mode used for new *outgoing* handshakes.
    /// Change this before calling `initiate_handshake` if you want a
    /// different cipher for the next session.
    pub default_encryption_mode: EncryptionMode,

    /// Optional callback used to hand newly-established peer DHT keys to the
    /// network walker's internal-list owner.
    established_peer_handler: Option<EstablishedPeerHandler>,

    /// Capability-limited reputation access for the handshake subsystem.
    reputation: ReputationModuleHandle,

    /// Optional structured event stream used by the supervisor/console/API.
    events: Option<NetworkEventBus>,

    /// Authenticated direct application messages, emitted only after the
    /// established handshake session successfully decrypts the payload.
    application_events: broadcast::Sender<DirectApplicationMessage>,

    /// Handshake-free, untrusted application gossip. The daemon only validates
    /// framing, size, timestamp, local block policy, and rate limits.
    gossip_events: broadcast::Sender<GossipApplicationMessage>,
    inbound_gossip_attempts: HashMap<String, VecDeque<u64>>,
    inbound_gossip_global_attempts: VecDeque<u64>,

    /// Recent inbound type-1 timestamps, keyed by the sender's public DHT key.
    inbound_init_attempts: HashMap<String, VecDeque<u64>>,

    /// Prevent one abusive burst from generating an observation for every
    /// packet after the threshold. At most one report is emitted per window.
    last_excessive_activity_report: HashMap<String, u64>,

    /// Per-peer reset and quarantine state is kept outside a handshake session
    /// because the session itself is discarded on reset.
    reset_receipts: HashMap<String, VecDeque<u64>>,
    reset_sends: HashMap<String, VecDeque<u64>>,
    accepted_reset_tokens: HashMap<String, AcceptedResetToken>,
    quarantined_until: HashMap<String, u64>,
    ignored_until: HashMap<String, u64>,
    pending_restarts: HashMap<String, PendingHandshakeRestart>,

    /// Cryptographically wrong challenge answers are tracked separately from
    /// timeouts and malformed/lost packets. Ordinary network failure should not
    /// damage reputation.
    challenge_failures: HashMap<String, VecDeque<u64>>,

    /// Detailed reputation reports are intentionally noisy. Remember when we
    /// last emitted one for each peer/context so a blocked peer retrying every
    /// few seconds does not bury the useful explanation in duplicate output.
    last_reputation_diagnostic: HashMap<String, u64>,
}

// ============================================================================
// Internal helpers
// ============================================================================

fn create_response(
    shared_secret: &[u8],
    initiator: &str,
    responder: &str,
    challenge: &[u8],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.update(initiator.as_bytes());
    hasher.update(responder.as_bytes());
    hasher.update(challenge);
    hasher.finalize().to_vec()
}

fn random_handshake_token() -> String {
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    hex::encode(token)
}

fn validate_handshake_message(
    msg: &HandshakeMessage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if msg.version != VERSION_ID {
        return Err(format!(
            "Unsupported handshake version {}; expected {}",
            msg.version, VERSION_ID
        )
        .into());
    }

    if !matches!(msg.message_type, 1 | 2 | 3 | HANDSHAKE_RESET_MESSAGE_TYPE | 5) {
        return Err(format!("Unknown handshake message type {}", msg.message_type).into());
    }

    if msg.sender_dht.len() > 256 {
        return Err("Sender DHT identity is too long".into());
    }
    if msg.token.is_empty() || msg.token.len() > MAX_HANDSHAKE_TOKEN_BYTES {
        return Err("Handshake token length is invalid".into());
    }

    if matches!(msg.message_type, 1 | 2 | 3) {
        if msg.sender_pubkey.len() != 32 {
            return Err("Handshake X25519 public key must be exactly 32 bytes".into());
        }
        if msg.sender_pubkey.iter().all(|byte| *byte == 0) {
            return Err("Handshake X25519 public key must not be all zero".into());
        }
    }

    let challenge_is_valid = msg
        .challenge
        .as_ref()
        .is_some_and(|challenge| challenge.len() == HANDSHAKE_CHALLENGE_BYTES);
    let signature_is_valid = msg
        .signature
        .as_ref()
        .is_some_and(|signature| signature.len() == HANDSHAKE_SIGNATURE_BYTES);

    match msg.message_type {
        1 => {
            if !challenge_is_valid || msg.signature.is_some() {
                return Err("Malformed type-1 handshake message".into());
            }
        }
        2 => {
            if !challenge_is_valid || !signature_is_valid {
                return Err("Malformed type-2 handshake message".into());
            }
        }
        3 => {
            if msg.challenge.is_some() || !signature_is_valid {
                return Err("Malformed type-3 handshake message".into());
            }
        }
        HANDSHAKE_RESET_MESSAGE_TYPE => {
            if !msg.sender_pubkey.is_empty()
                || msg.challenge.is_some()
                || msg.signature.is_some()
                || msg.encryption_mode.is_some()
                || msg.maintain_connection
            {
                return Err("Malformed handshake reset message".into());
            }
        }
        5 => {
            if msg.challenge.is_some() || msg.signature.is_some() {
                return Err("Malformed type-5 check-in message".into());
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn decode_and_validate_handshake_message(
    data: &[u8],
) -> Result<HandshakeMessage, Box<dyn std::error::Error + Send + Sync>> {
    let msg: HandshakeMessage = decode_json_limited(data, MAX_HANDSHAKE_MESSAGE_BYTES)?;
    validate_handshake_message(&msg)?;

    if msg.sender_dht.parse::<RecordKey>().is_err() {
        return Err("Invalid sender DHT identity".into());
    }

    let now = current_timestamp();
    if msg.timestamp > now.saturating_add(TIME_WINDOW) {
        return Err("Handshake message timestamp is too far in the future".into());
    }
    if msg.timestamp.saturating_add(TIME_WINDOW) < now {
        return Err("Handshake message timestamp is too old".into());
    }

    Ok(msg)
}

fn reject_all_zero_shared_secret(
    shared: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err("Rejected all-zero X25519 shared secret".into());
    }
    Ok(())
}

fn handshake_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_handshake_message(
    message: &HandshakeMessage,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_HANDSHAKE_MESSAGE_BYTES {
        return Err("Encoded handshake message exceeds protocol limit".into());
    }
    Ok(bytes)
}

async fn send_handshake_message(
    veilid: &VeilidAPI,
    route: &[u8],
    message: &HandshakeMessage,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    send_raw_private_route_message(veilid, route, encode_handshake_message(message)?).await
}

async fn send_raw_private_route_message(
    veilid: &VeilidAPI,
    route: &[u8],
    bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let route_id = veilid.import_remote_private_route(route.to_vec())?;
    let routing_context = match veilid.routing_context() {
        Ok(context) => context,
        Err(error) => {
            let _ = veilid.release_private_route(route_id);
            return Err(error.into());
        }
    };

    let result = timeout(
        HANDSHAKE_IO_TIMEOUT,
        routing_context.app_message(Target::RouteId(route_id.clone()), bytes),
    )
    .await;
    let _ = veilid.release_private_route(route_id);

    match result {
        Ok(result) => {
            result?;
            Ok(())
        }
        Err(_) => Err("Timed out sending private-route message".into()),
    }
}

async fn validate_importable_route(
    veilid: &VeilidAPI,
    route: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for attempt in 0..MAX_ROUTE_IMPORT_TRY_AGAIN {
        match veilid.import_remote_private_route(route.to_vec()) {
            Ok(route_id) => {
                let _ = veilid.release_private_route(route_id);
                return Ok(());
            }
            Err(VeilidAPIError::TryAgain { .. }) => {
                if attempt + 1 >= MAX_ROUTE_IMPORT_TRY_AGAIN {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250 * (attempt as u64 + 1))).await;
            }
            Err(error) => return Err(format!("Route import failed: {error}").into()),
        }
    }

    Err(format!(
        "Route import still returned TryAgain after {} attempts",
        MAX_ROUTE_IMPORT_TRY_AGAIN
    )
    .into())
}

// ============================================================================
// impl HandshakeManager
// ============================================================================

impl HandshakeManager {
    /// Create a new manager.
    ///
    /// ```rust
    /// let mgr = HandshakeManager::new(veilid, dht_module, our_dht_key_string, reputation_handle);
    /// // AES-256-GCM is the default for new sessions. Set the field explicitly
    /// // only when testing another supported negotiation mode.
    /// ```
    pub fn new(
        veilid: VeilidAPI,
        dht_module: DHTModule,
        our_dht: String,
        reputation: ReputationModuleHandle,
    ) -> Self {
        let (application_events, _) = broadcast::channel(512);
        let (gossip_events, _) = broadcast::channel(1024);
        Self {
            sessions: HashMap::new(),
            veilid,
            dht_module,
            our_dht,
            // Direct application traffic requires an authenticated cipher.
            // Peers that cannot negotiate it simply use mailbox fallback.
            default_encryption_mode: EncryptionMode::Aes256Gcm,
            established_peer_handler: None,
            reputation,
            events: None,
            application_events,
            gossip_events,
            inbound_gossip_attempts: HashMap::new(),
            inbound_gossip_global_attempts: VecDeque::new(),
            inbound_init_attempts: HashMap::new(),
            last_excessive_activity_report: HashMap::new(),
            reset_receipts: HashMap::new(),
            reset_sends: HashMap::new(),
            accepted_reset_tokens: HashMap::new(),
            quarantined_until: HashMap::new(),
            ignored_until: HashMap::new(),
            pending_restarts: HashMap::new(),
            challenge_failures: HashMap::new(),
            last_reputation_diagnostic: HashMap::new(),
        }
    }


    /// Attach the shared structured event stream before wrapping the manager.
    pub fn with_event_bus(mut self, events: NetworkEventBus) -> Self {
        self.events = Some(events);
        self
    }

    fn emit_handshake_started(&self, peer: &str, verification: bool) {
        if let Some(events) = &self.events {
            events.emit(
                NetworkEventSource::Handshake,
                EventSeverity::Info,
                NetworkEvent::HandshakeStarted {
                    peer: peer.to_string(),
                    verification,
                },
            );
        }
    }

    fn emit_handshake_skipped(&self, peer: &str, reason: impl Into<String>) {
        if let Some(events) = &self.events {
            events.emit(
                NetworkEventSource::Handshake,
                EventSeverity::Info,
                NetworkEvent::HandshakeSkipped {
                    peer: peer.to_string(),
                    reason: reason.into(),
                },
            );
        }
    }

    fn emit_handshake_succeeded(&self, peer: &str, duration_ms: u64) {
        if let Some(events) = &self.events {
            events.emit(
                NetworkEventSource::Handshake,
                EventSeverity::Notice,
                NetworkEvent::HandshakeSucceeded {
                    peer: peer.to_string(),
                    duration_ms,
                },
            );
        }
    }

    fn emit_handshake_failed(
        &self,
        peer: &str,
        reason: impl Into<String>,
        duration_ms: u64,
    ) {
        if let Some(events) = &self.events {
            events.emit(
                NetworkEventSource::Handshake,
                EventSeverity::Warning,
                NetworkEvent::HandshakeFailed {
                    peer: peer.to_string(),
                    reason: reason.into(),
                    duration_ms,
                },
            );
        }
    }

    /// Wrap this manager in shared async state so it can be used by the
    /// app-message callback and by normal caller code at the same time.
    pub fn into_shared(self) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(self))
    }

    /// Install the destination for peers whose handshake reaches Established.
    pub fn set_established_peer_handler<F, Fut>(&mut self, handler: F)
    where
        F: Fn(RecordKey) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.established_peer_handler = Some(Arc::new(move |peer| {
            Box::pin(handler(peer))
        }));
    }

    fn notify_established_peer(&self, peer_dht: &str) {
        let Some(handler) = self.established_peer_handler.clone() else {
            return;
        };

        let Ok(peer_key) = peer_dht.parse::<RecordKey>() else {
            crate::teprintln!("[handshake] Established peer supplied an invalid DHT key: {peer_dht}");
            return;
        };

        tokio::spawn(async move {
            handler(peer_key).await;
        });
    }

    /// PATCH A: pending sessions have their own caps. Failed or expired
    /// entries are removed first; a healthy in-progress handshake is not
    /// displaced merely because an attacker opened a newer one.
    fn reserve_pending_slot(&mut self, is_initiator: bool, now: u64) -> bool {
        let limit = if is_initiator {
            MAX_PENDING_OUTBOUND_HANDSHAKES
        } else {
            MAX_PENDING_INBOUND_HANDSHAKES
        };

        let stale: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, state)| {
                state.is_initiator == is_initiator
                    && state.status != HandshakeStatus::Established
                    && (state.status == HandshakeStatus::Failed
                        || now.saturating_sub(state.started_at)
                            >= PENDING_SESSION_MAX_AGE_SECS)
            })
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in stale {
            self.sessions.remove(&peer);
        }

        self.sessions
            .values()
            .filter(|state| {
                state.is_initiator == is_initiator
                    && state.status != HandshakeStatus::Established
            })
            .count()
            < limit
    }

    /// Start the handshake background worker.
    ///
    /// This does two things:
    ///   1. Installs `node.set_app_message_handler(...)` so every incoming
    ///      Veilid app message is fed into `process_message`.
    ///   2. Spawns a periodic tick loop for retries, check-ins, and cleanup.
    ///
    /// Keep the returned `JoinHandle` if you want to abort the tick loop during
    /// shutdown.  The app-message handler remains installed on the `Node`.
    pub fn start_background_task(
        manager: Arc<Mutex<Self>>,
        node: Arc<Node>,
    ) -> tokio::task::JoinHandle<()> {
        let message_manager = Arc::clone(&manager);
        let inbound_jobs = Arc::new(Semaphore::new(MAX_INBOUND_HANDSHAKE_JOBS));

        node.set_app_message_handler(move |data: Vec<u8>| {
            let message_manager = Arc::clone(&message_manager);
            let inbound_jobs = Arc::clone(&inbound_jobs);

            async move {
                let Ok(_permit) = inbound_jobs.try_acquire_owned() else {
                    crate::teprintln!("[handshake] Inbound worker limit reached; dropping control message");
                    return;
                };

                if data.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES {
                    crate::teprintln!(
                        "[handshake] Dropping oversized app message ({} bytes)",
                        data.len()
                    );
                    return;
                }

                if let Ok(message) = decode_and_validate_handshake_message(&data) {
                    let sender_dht = message.sender_dht.clone();
                    let mut handshake = message_manager.lock().await;
                    if let Err(err) = handshake
                        .process_validated_message(sender_dht, message, data)
                        .await
                    {
                        crate::teprintln!("[handshake] Failed to process incoming control message: {err}");
                    }
                    return;
                }

                // Gossip is intentionally recognized before the authenticated direct
                // envelope. It is an application hint channel over a Veilid private
                // route and does not create a VeilKnit handshake session. Daemon-owned
                // engine traffic uses compact v2; legacy/raw app gossip remains v1.
                if let Ok(envelope) = serde_json::from_slice::<CompactGossipApplicationEnvelope>(&data) {
                    if envelope.gossip_protocol_version == GOSSIP_APPLICATION_COMPACT_PROTOCOL_VERSION {
                        match BASE64.decode(&envelope.payload_base64) {
                            Ok(payload) if payload.len() <= MAX_DIRECT_APPLICATION_MESSAGE_BYTES / 2 => {
                                let envelope = GossipApplicationEnvelope {
                                    gossip_protocol_version: GOSSIP_APPLICATION_PROTOCOL_VERSION,
                                    application_id: envelope.application_id,
                                    message_id: envelope.message_id,
                                    sender_dht: envelope.sender_dht,
                                    sent_at: envelope.sent_at,
                                    payload,
                                };
                                let mut handshake = message_manager.lock().await;
                                if let Err(error) = handshake.process_gossip_application(envelope).await {
                                    crate::teprintln!("[gossip] Rejecting compact daemon gossip: {error}");
                                }
                            }
                            Ok(_) => crate::teprintln!("[gossip] Rejecting oversized compact daemon gossip"),
                            Err(error) => crate::teprintln!("[gossip] Rejecting invalid compact gossip payload: {error}"),
                        }
                        return;
                    }
                }
                if let Ok(envelope) = serde_json::from_slice::<GossipApplicationEnvelope>(&data) {
                    if envelope.gossip_protocol_version == GOSSIP_APPLICATION_PROTOCOL_VERSION {
                        let mut handshake = message_manager.lock().await;
                        if let Err(error) = handshake.process_gossip_application(envelope).await {
                            crate::teprintln!("[gossip] Rejecting application gossip: {error}");
                        }
                        return;
                    }
                }

                let envelope: DirectApplicationEnvelope = match serde_json::from_slice(&data) {
                    Ok(envelope) => envelope,
                    Err(error) => {
                        crate::teprintln!("[handshake] Rejecting unknown app-message envelope: {error}");
                        return;
                    }
                };
                let mut handshake = message_manager.lock().await;
                if let Err(error) = handshake.process_direct_application(envelope).await {
                    crate::teprintln!("[handshake] Rejecting direct application message: {error}");
                }
            }
        });

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(2),
            );

            loop {
                interval.tick().await;

                let mut handshake = manager.lock().await;
                handshake.tick().await;
            }
        })
    }

    /// Return true when local reputation policy blocks all network interaction
    /// with this public DHT identity. Reputation lookup failures are fail-open:
    /// a temporary local service problem should not silently partition us.
    async fn is_reputation_blocked(&self, peer_dht: &str) -> bool {
        let peer_key = match peer_dht.parse::<RecordKey>() {
            Ok(key) => key,
            Err(_) => return false,
        };

        match self.reputation.get_view(peer_key).await {
            Ok(view) => view.network_access == AccessLevel::Blocked,
            Err(error) => {
                crate::teprintln!(
                    "[handshake] Reputation lookup failed for {peer_dht}; allowing this message: {error}"
                );
                false
            }
        }
    }

    /// Emit a detailed explanation when a local reputation decision prevents
    /// inbound/outbound peer traffic. Keep this separate from the hot-path
    /// access check so ordinary allowed peers do not generate diagnostic noise.
    async fn log_reputation_block_diagnostic(&mut self, peer_dht: &str, context: &str) {
        let now = current_timestamp();
        let diagnostic_key = format!("{context}\0{peer_dht}");
        if self
            .last_reputation_diagnostic
            .get(&diagnostic_key)
            .is_some_and(|last| now.saturating_sub(*last) < REPUTATION_DIAGNOSTIC_COOLDOWN_SECS)
        {
            return;
        }
        self.last_reputation_diagnostic.insert(diagnostic_key, now);

        let peer_key = match peer_dht.parse::<RecordKey>() {
            Ok(key) => key,
            Err(error) => {
                crate::teprintln!(
                    "[reputation][diagnostic] context={context} peer={peer_dht} could not parse peer key: {error:?}"
                );
                return;
            }
        };

        match self.reputation.get_diagnostic_report(peer_key).await {
            Ok(report) => {
                crate::tprintln!(
                    "[reputation][diagnostic] context={context} peer={peer_dht} BEGIN"
                );
                for line in report.lines() {
                    crate::tprintln!("[reputation][diagnostic] {line}");
                }
                crate::tprintln!(
                    "[reputation][diagnostic] context={context} peer={peer_dht} END"
                );
            }
            Err(error) => {
                crate::teprintln!(
                    "[reputation][diagnostic] context={context} peer={peer_dht} report failed: {error}"
                );
            }
        }
    }

    fn retain_recent(values: &mut VecDeque<u64>, now: u64, window_secs: u64) {
        while values
            .front()
            .is_some_and(|timestamp| timestamp.saturating_add(window_secs) <= now)
        {
            values.pop_front();
        }
    }

    fn is_peer_ignored(&mut self, peer_dht: &str, now: u64) -> bool {
        match self.ignored_until.get(peer_dht).copied() {
            Some(until) if until > now => true,
            Some(_) => {
                self.ignored_until.remove(peer_dht);
                false
            }
            None => false,
        }
    }

    fn is_peer_quarantined(&mut self, peer_dht: &str, now: u64) -> bool {
        match self.quarantined_until.get(peer_dht).copied() {
            Some(until) if until > now => true,
            Some(_) => {
                self.quarantined_until.remove(peer_dht);
                false
            }
            None => false,
        }
    }

    fn schedule_restart_from_state(&mut self, state: &HandshakeState, now: u64) {
        if !state.is_initiator {
            return;
        }
        self.pending_restarts.insert(
            state.peer_dht.clone(),
            PendingHandshakeRestart {
                encryption_mode: state.encryption_mode,
                verification: state.verification,
                maintain_connection: state.maintain_connection,
                restart_at: now.saturating_add(HANDSHAKE_RESET_RESTART_SECS),
            },
        );
    }

    /// Send the deliberately detail-free type-4 reset over the peer route.
    ///
    /// At most three resets are sent to one peer in the rolling window. The
    /// local session is then discarded and both sides are expected to ignore
    /// the old flight for five seconds. Only the original initiator schedules
    /// a clean restart.
    async fn send_protocol_reset(
        &mut self,
        peer_dht: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let now = current_timestamp();
        let send_count = {
            let sends = self.reset_sends.entry(peer_dht.to_string()).or_default();
            Self::retain_recent(sends, now, HANDSHAKE_RESET_WINDOW_SECS);
            sends.len()
        };
        if send_count >= MAX_HANDSHAKE_RESETS_PER_PEER {
            self.ignored_until.insert(
                peer_dht.to_string(),
                now.saturating_add(HANDSHAKE_RESET_ABUSE_IGNORE_SECS),
            );
            self.sessions.remove(peer_dht);
            return Ok(());
        }

        let Some(state) = self.sessions.remove(peer_dht) else {
            return Ok(());
        };
        let route = state.route.clone();
        let reset = HandshakeMessage {
            version: VERSION_ID,
            message_type: HANDSHAKE_RESET_MESSAGE_TYPE,
            sender_dht: self.our_dht.clone(),
            sender_pubkey: Vec::new(),
            token: state.token.clone(),
            challenge: None,
            signature: None,
            timestamp: now,
            encryption_mode: None,
            maintain_connection: false,
        };

        // Count the attempt before awaiting network I/O. A broken route must not
        // allow an unlimited reset loop, and local recovery must still proceed
        // when the peer never receives our reset.
        self.reset_sends
            .entry(peer_dht.to_string())
            .or_default()
            .push_back(now);
        self.quarantined_until.insert(
            peer_dht.to_string(),
            now.saturating_add(HANDSHAKE_RESET_QUARANTINE_SECS),
        );
        self.schedule_restart_from_state(&state, now);

        if let Some(route) = route {
            let bytes = encode_handshake_message(&reset)?;
            send_raw_private_route_message(&self.veilid, &route, bytes).await?;
        }
        Ok(())
    }

    async fn handle_protocol_reset(&mut self, msg: &HandshakeMessage) {
        let now = current_timestamp();

        // Veilid's app-message callback does not expose the incoming route id.
        // A matching live-session token authenticates the first reset. Retain
        // that token briefly so duplicate reset packets can also be counted and
        // cannot evade the three-message receive limit merely because the first
        // reset already removed the session.
        let mut restart_state = None;
        let authenticated = if let Some(state) = self.sessions.remove(&msg.sender_dht) {
            if state.token == msg.token {
                self.accepted_reset_tokens.insert(
                    msg.sender_dht.clone(),
                    AcceptedResetToken {
                        token: msg.token.clone(),
                        expires_at: now.saturating_add(HANDSHAKE_RESET_WINDOW_SECS),
                    },
                );
                restart_state = Some(state);
                true
            } else {
                self.sessions.insert(msg.sender_dht.clone(), state);
                false
            }
        } else {
            self.accepted_reset_tokens
                .get(&msg.sender_dht)
                .is_some_and(|accepted| {
                    accepted.expires_at > now && accepted.token == msg.token
                })
        };
        if !authenticated {
            return;
        }

        let receipt_count = {
            let receipts = self
                .reset_receipts
                .entry(msg.sender_dht.clone())
                .or_default();
            Self::retain_recent(receipts, now, HANDSHAKE_RESET_WINDOW_SECS);
            receipts.push_back(now);
            receipts.len()
        };

        if receipt_count > MAX_HANDSHAKE_RESETS_PER_PEER {
            self.ignored_until.insert(
                msg.sender_dht.clone(),
                now.saturating_add(HANDSHAKE_RESET_ABUSE_IGNORE_SECS),
            );
            self.pending_restarts.remove(&msg.sender_dht);
            self.accepted_reset_tokens.remove(&msg.sender_dht);
            crate::tprintln!(
                "[handshake] Ignoring {} after excessive protocol resets",
                msg.sender_dht
            );
            return;
        }

        self.quarantined_until.insert(
            msg.sender_dht.clone(),
            now.saturating_add(HANDSHAKE_RESET_QUARANTINE_SECS),
        );
        if let Some(state) = restart_state.as_ref() {
            self.schedule_restart_from_state(state, now);
        }
        crate::tprintln!(
            "[handshake] Protocol reset received from {}; old flight discarded",
            msg.sender_dht
        );
    }

    async fn handle_duplicate_or_conflicting_flight(
        &mut self,
        msg: &HandshakeMessage,
        raw_bytes: &[u8],
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if !matches!(msg.message_type, 1 | 2 | 3) {
            return Ok(false);
        }

        let digest = handshake_digest(raw_bytes);
        let mut replay: Option<(Vec<u8>, Vec<u8>)> = None;
        let mut conflict = false;

        if let Some(state) = self.sessions.get_mut(&msg.sender_dht) {
            if let Some(previous) = state.received_flights.get(&msg.message_type) {
                if previous == &digest {
                    if let Some(cached) = state.cached_replies.get_mut(&msg.message_type) {
                        if cached.replay_count < MAX_DUPLICATE_REPLY_REPLAYS {
                            if let Some(route) = state.route.clone() {
                                cached.replay_count = cached.replay_count.saturating_add(1);
                                replay = Some((route, cached.flight.bytes.clone()));
                            }
                        }
                    }
                    // An identical duplicate without a cached response (for
                    // example a repeated final packet) is harmless and ignored.
                } else {
                    conflict = true;
                }
            } else {
                state.received_flights.insert(msg.message_type, digest);
                return Ok(false);
            }
        } else {
            return Ok(false);
        }

        if let Some((route, bytes)) = replay {
            send_raw_private_route_message(&self.veilid, &route, bytes).await?;
            return Ok(true);
        }
        if conflict {
            self.send_protocol_reset(&msg.sender_dht).await?;
            return Ok(true);
        }
        Ok(true)
    }

    async fn record_wrong_challenge(&mut self, peer_dht: &str) {
        let now = current_timestamp();
        let failures = self
            .challenge_failures
            .entry(peer_dht.to_string())
            .or_default();
        Self::retain_recent(failures, now, CHALLENGE_FAILURE_WINDOW_SECS);
        failures.push_back(now);
        let count = failures.len();

        let Ok(subject) = peer_dht.parse::<RecordKey>() else {
            return;
        };

        if count == CHALLENGE_REPUTATION_THRESHOLD {
            let _ = self
                .reputation
                .submit_observation(ObservationInput {
                    subject: subject.clone(),
                    kind: ObservationKind::InvalidSignature,
                    details: ObservationDetails {
                        application_code: Some(count as u32),
                        description: Some(
                            "Three cryptographically incorrect handshake challenge answers"
                                .to_string(),
                        ),
                    },
                })
                .await;
        }

        if count == CHALLENGE_BAN_SUGGESTION_THRESHOLD {
            let _ = self
                .reputation
                .submit_observation(ObservationInput {
                    subject,
                    kind: ObservationKind::DeliberateStateCorruption,
                    details: ObservationDetails {
                        application_code: Some(count as u32),
                        description: Some(
                            "Ban suggestion: ten cryptographically incorrect handshake challenge answers"
                                .to_string(),
                        ),
                    },
                })
                .await;
        }
    }

    /// Count an inbound type-1 request. Returns true when the request exceeds
    /// the allowed ten initiations per rolling minute and should be ignored.
    async fn inbound_init_is_excessive(&mut self, peer_dht: &str, now: u64) -> bool {
        let attempts = self
            .inbound_init_attempts
            .entry(peer_dht.to_string())
            .or_default();

        while attempts
            .front()
            .is_some_and(|timestamp| timestamp.saturating_add(HANDSHAKE_INIT_WINDOW_SECS) <= now)
        {
            attempts.pop_front();
        }

        attempts.push_back(now);
        let attempt_count = attempts.len();
        if attempt_count <= MAX_INBOUND_HANDSHAKE_INITS_PER_WINDOW {
            return false;
        }

        let should_report = self
            .last_excessive_activity_report
            .get(peer_dht)
            .is_none_or(|last| last.saturating_add(HANDSHAKE_INIT_WINDOW_SECS) <= now);

        if should_report {
            self.last_excessive_activity_report
                .insert(peer_dht.to_string(), now);

            if let Ok(subject) = peer_dht.parse::<RecordKey>() {
                let result = self
                    .reputation
                    .submit_observation(ObservationInput {
                        subject,
                        kind: ObservationKind::ExcessiveActivity,
                        details: ObservationDetails {
                            application_code: Some(attempt_count as u32),
                            description: Some(format!(
                                "Received {attempt_count} handshake initiation requests within {HANDSHAKE_INIT_WINDOW_SECS} seconds"
                            )),
                        },
                    })
                    .await;

                if let Err(error) = result {
                    crate::teprintln!(
                        "[handshake] Failed to submit excessive-activity observation for {peer_dht}: {error}"
                    );
                }
            }
        }

        true
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /// Start a handshake with a remote peer identified by their DHT record key.
    ///
    /// The `EncryptionMode` used is `self.default_encryption_mode` unless you
    /// pass an override via `initiate_handshake_with_mode`.
    pub async fn initiate_handshake(
        &mut self,
        target_dht: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mode = self.default_encryption_mode;
        self.initiate_handshake_internal(target_dht, mode, false, false).await
    }

    /// Start the deliberately rare identity/presence re-verification path.
    /// Callers are responsible for enforcing the 24-hour minimum interval.
    pub async fn initiate_verification_handshake(
        &mut self,
        target_dht: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mode = self.default_encryption_mode;
        self.initiate_handshake_internal(target_dht, mode, true, false).await
    }

    /// Like `initiate_handshake` but with an explicit encryption mode,
    /// overriding the manager default for this one session.
    pub async fn initiate_handshake_with_mode(
        &mut self,
        target_dht: String,
        encryption_mode: EncryptionMode,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.initiate_handshake_internal(target_dht, encryption_mode, false, false)
            .await
    }

    /// Establish a maintained session for live application traffic. Walks and
    /// one-off presence checks continue to use `initiate_handshake`, while the
    /// local application API uses this path.
    pub async fn initiate_persistent_handshake(
        &mut self,
        target_dht: String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let already_persistent = self.sessions.get(&target_dht).map_or(false, |state| {
            state.status == HandshakeStatus::Established && state.maintain_connection
        });
        if already_persistent {
            return Ok(());
        }
        if self.sessions.get(&target_dht).map_or(false, |state| {
            state.status == HandshakeStatus::Established
        }) {
            self.sessions.remove(&target_dht);
        }
        let mode = self.default_encryption_mode;
        self.initiate_handshake_internal(target_dht, mode, false, true).await
    }

    async fn initiate_handshake_internal(
        &mut self,
        target_dht: String,
        encryption_mode: EncryptionMode,
        verification: bool,
        maintain_connection: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        crate::tprintln!(
            "[handshake] Initiating with {} (mode: {:?}, verification: {})",
            target_dht, encryption_mode, verification
        );

        let now = current_timestamp();
        if self.is_peer_ignored(&target_dht, now) {
            return Err(format!("Peer {target_dht} is temporarily ignored").into());
        }
        if self.is_peer_quarantined(&target_dht, now) {
            return Err(format!("Peer {target_dht} is in handshake quarantine").into());
        }

        if self.is_reputation_blocked(&target_dht).await {
            self.log_reputation_block_diagnostic(&target_dht, "outbound_handshake_blocked")
                .await;
            self.emit_handshake_skipped(&target_dht, "Blocked by local reputation policy");
            self.sessions.remove(&target_dht);
            return Err(format!(
                "Peer {target_dht} is blocked by local reputation policy"
            )
            .into());
        }

        if let Some(state) = self.sessions.get(&target_dht) {
            if state.status == HandshakeStatus::Established {
                self.emit_handshake_skipped(&target_dht, "Already established");
                return Ok(());
            }
        }

        if self.sessions.len() >= MAX_TOTAL_SESSIONS {
            self.emit_handshake_skipped(&target_dht, "Session limit reached");
            return Ok(());
        }

        if !self.reserve_pending_slot(true, now) {
            self.emit_handshake_skipped(&target_dht, "Pending outbound limit reached");
            return Err("Outbound pending-handshake limit reached".into());
        }

        let operation_started = Instant::now();
        self.emit_handshake_started(&target_dht, verification);

        let blob = match fetch_route_blob(&self.dht_module, &target_dht).await {
            Ok(blob) => blob,
            Err(error) => {
                self.emit_handshake_failed(
                    &target_dht,
                    format!("Could not fetch route blob: {error}"),
                    duration_millis(operation_started.elapsed()),
                );
                return Err(error);
            }
        };

        let our_private = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_private);

        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);

        let msg = HandshakeMessage {
            version: VERSION_ID,
            message_type: 1,
            sender_dht: self.our_dht.clone(),
            sender_pubkey: our_public.as_bytes().to_vec(),
            token: random_handshake_token(),
            challenge: Some(challenge.to_vec()),
            signature: None,
            timestamp: now,
            encryption_mode: Some(encryption_mode),
            maintain_connection,
        };

        let initial_bytes = encode_handshake_message(&msg)?;
        if let Err(error) =
            send_raw_private_route_message(&self.veilid, &blob.blob, initial_bytes.clone()).await
        {
            self.emit_handshake_failed(
                &target_dht,
                format!("Initial send failed: {error}"),
                duration_millis(operation_started.elapsed()),
            );
            return Err(error);
        }

        self.sessions.insert(target_dht.clone(), HandshakeState {
            peer_dht: target_dht,
            is_initiator: true,
            peer_public_key: None,
            our_private_key: Some(our_private),
            our_public_key: our_public,
            route: Some(blob.blob),
            status: HandshakeStatus::InitSent,
            started_at: now,
            last_attempt: now,
            last_seen: now,
            retries: 0,
            token: msg.token,
            our_challenge: Some(challenge.to_vec()),
            their_challenge: None,
            session_key: None,
            encryption_mode,
            maintain_connection,
            verification,
            outgoing_flight: Some(SavedHandshakeFlight::new(1, initial_bytes)),
            received_flights: HashMap::new(),
            cached_replies: HashMap::new(),
        });

        Ok(())
    }

    /// Feed an incoming raw message into the state machine.
    ///
    /// Handshake control messages (types 1-3, 5) are processed automatically.
    /// Returns `None` for handshake traffic.  In the future this could return
    /// decrypted application data once you layer a messaging protocol on top.
    pub async fn process_message(
        &mut self,
        sender_dht: String,
        data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let msg = match decode_and_validate_handshake_message(&data) {
            Ok(message) => message,
            Err(error) => {
                crate::teprintln!("[handshake] Rejecting invalid control message: {error}");
                return Ok(None);
            }
        };
        self.process_validated_message(sender_dht, msg, data).await
    }

    /// Process a message whose byte envelope, field shapes, identity syntax,
    /// and timestamp have already been validated without holding shared state.
    async fn process_validated_message(
        &mut self,
        sender_dht: String,
        msg: HandshakeMessage,
        raw_bytes: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        if !sender_dht.is_empty() && sender_dht != msg.sender_dht {
            crate::teprintln!("[handshake] Sender identity mismatch in validated message");
            return Ok(None);
        }

        if msg.sender_dht == self.our_dht {
            crate::tprintln!("[handshake] Ignoring message from ourselves");
            return Ok(None);
        }

        let now = current_timestamp();
        let peer_dht = msg.sender_dht.clone();

        // NetworkInteraction bans are hard safety bans. App-scoped/user
        // moderation bans intentionally do not reach this check: those peers
        // may complete a normal handshake, while the relevant application
        // discards their content without exposing an obvious ban oracle.
        if self.is_reputation_blocked(&msg.sender_dht).await {
            crate::tprintln!("[handshake] Ignoring message from blocked peer {}", msg.sender_dht);
            self.log_reputation_block_diagnostic(&msg.sender_dht, "inbound_handshake_blocked")
                .await;
            self.sessions.remove(&msg.sender_dht);
            return Ok(None);
        }

        if self.is_peer_ignored(&msg.sender_dht, now) {
            return Ok(None);
        }

        if msg.message_type == HANDSHAKE_RESET_MESSAGE_TYPE {
            self.handle_protocol_reset(&msg).await;
            return Ok(None);
        }

        if self.is_peer_quarantined(&msg.sender_dht, now) {
            return Ok(None);
        }

        // A maintained-session upgrade is a deliberately fresh handshake.
        // Remove the completed quick session before duplicate comparison so the
        // new token is not mistaken for a conflicting retransmission.
        if msg.message_type == 1 {
            let should_upgrade = self.sessions.get(&msg.sender_dht).is_some_and(|existing| {
                existing.status == HandshakeStatus::Established
                    && msg.maintain_connection
                    && !existing.maintain_connection
            });
            if should_upgrade {
                crate::tprintln!(
                    "[handshake] Upgrading quick session with {} to a maintained application session",
                    msg.sender_dht
                );
                self.sessions.remove(&msg.sender_dht);
            }
        }

        if self
            .handle_duplicate_or_conflicting_flight(&msg, &raw_bytes)
            .await?
        {
            return Ok(None);
        }

        let raw_digest = handshake_digest(&raw_bytes);
        let result = match msg.message_type {
            1 => {
                if self.inbound_init_is_excessive(&msg.sender_dht, now).await {
                    crate::tprintln!(
                        "[handshake] Excessive initiation rate from {}; ignoring request",
                        msg.sender_dht
                    );
                    return Ok(None);
                }

                let established_count = self.sessions.values()
                    .filter(|state| state.status == HandshakeStatus::Established)
                    .count();
                if established_count >= MAX_ESTABLISHED_HANDSHAKES {
                    crate::tprintln!("[handshake] Max established sessions reached, ignoring init");
                    return Ok(None);
                }
                if self.sessions.len() >= MAX_TOTAL_SESSIONS {
                    crate::tprintln!("[handshake] Session limit reached, dropping init");
                    return Ok(None);
                }
                if !self.sessions.contains_key(&msg.sender_dht)
                    && !self.reserve_pending_slot(false, now)
                {
                    crate::tprintln!("[handshake] Pending inbound limit reached, dropping init");
                    return Ok(None);
                }

                self.handle_welcome(msg, raw_digest).await
            }
            2 => self.handle_welcome_reply(msg).await,
            3 => self.handle_final(msg).await,
            5 => self.handle_checkin(msg),
            _ => Ok(()),
        };

        if let Err(error) = result {
            let error_text = error.to_string();
            if error_text.contains("challenge response")
                || error_text.contains("Final verification")
            {
                self.record_wrong_challenge(&peer_dht).await;
            }
            crate::teprintln!(
                "[handshake] Protocol state mismatch with {}: {}",
                peer_dht,
                error_text
            );
            if let Err(reset_error) = self.send_protocol_reset(&peer_dht).await {
                crate::teprintln!(
                    "[handshake] Could not send protocol reset to {}: {}",
                    peer_dht,
                    reset_error
                );
            }
        }

        Ok(None)
    }

    pub fn subscribe_application_messages(
        &self,
    ) -> broadcast::Receiver<DirectApplicationMessage> {
        self.application_events.subscribe()
    }

    /// Subscribe to handshake-free application gossip. These messages are
    /// explicitly unverified hints; do not interpret `sender_dht` as proof of
    /// authorship without an application-level/DHT confirmation.
    pub fn subscribe_gossip_messages(
        &self,
    ) -> broadcast::Receiver<GossipApplicationMessage> {
        self.gossip_events.subscribe()
    }

    /// Send one untrusted gossip datagram using the target's published private
    /// route. This shared form deliberately releases the HandshakeManager mutex
    /// before the potentially slow DHT route lookup/network send so high-rate
    /// social gossip cannot stall handshake processing.
    pub async fn send_gossip_application_message_shared(
        manager: Arc<Mutex<Self>>,
        peer_dht: String,
        application_id: String,
        payload: Vec<u8>,
    ) -> Result<[u8; 16], Box<dyn std::error::Error + Send + Sync>> {
        let application_id = application_id.trim().to_ascii_lowercase();
        if application_id.is_empty() || application_id.len() > 256 {
            return Err("Application id length is invalid".into());
        }
        if payload.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES / 2 {
            return Err("Gossip application payload exceeds protocol limit".into());
        }
        let _ = peer_dht.parse::<RecordKey>()?;

        let (veilid, dht_module, our_dht) = {
            let manager = manager.lock().await;
            if peer_dht == manager.our_dht {
                return Err("Refusing to send gossip to our own DHT identity".into());
            }
            if manager.is_reputation_blocked(&peer_dht).await {
                return Err(format!("Peer {peer_dht} is blocked by reputation policy").into());
            }
            (manager.veilid.clone(), manager.dht_module.clone(), manager.our_dht.clone())
        };

        let mut message_id = [0u8; 16];
        OsRng.fill_bytes(&mut message_id);
        let envelope = GossipApplicationEnvelope {
            gossip_protocol_version: GOSSIP_APPLICATION_PROTOCOL_VERSION,
            application_id,
            message_id,
            sender_dht: our_dht,
            sent_at: current_timestamp(),
            payload,
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES {
            return Err("Encoded gossip application message exceeds protocol limit".into());
        }
        let route = fetch_route_blob(&dht_module, &peer_dht).await?.blob;
        send_raw_private_route_message(&veilid, &route, bytes).await?;
        Ok(message_id)
    }

    /// Daemon-internal compact variant used by the managed gossip engine. Raw
    /// application gossip deliberately keeps the original v1 JSON shape so old
    /// applications/daemons are not silently broken by this optimization.
    pub async fn send_compact_gossip_application_message_shared(
        manager: Arc<Mutex<Self>>,
        peer_dht: String,
        application_id: String,
        payload: Vec<u8>,
    ) -> Result<[u8; 16], Box<dyn std::error::Error + Send + Sync>> {
        let application_id = application_id.trim().to_ascii_lowercase();
        if application_id.is_empty() || application_id.len() > 256 {
            return Err("Application id length is invalid".into());
        }
        if payload.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES / 2 {
            return Err("Compact gossip application payload exceeds protocol limit".into());
        }
        let _ = peer_dht.parse::<RecordKey>()?;

        let (veilid, dht_module, our_dht) = {
            let manager = manager.lock().await;
            if peer_dht == manager.our_dht {
                return Err("Refusing to send gossip to our own DHT identity".into());
            }
            if manager.is_reputation_blocked(&peer_dht).await {
                return Err(format!("Peer {peer_dht} is blocked by reputation policy").into());
            }
            (manager.veilid.clone(), manager.dht_module.clone(), manager.our_dht.clone())
        };

        let mut message_id = [0u8; 16];
        OsRng.fill_bytes(&mut message_id);
        let envelope = CompactGossipApplicationEnvelope {
            gossip_protocol_version: GOSSIP_APPLICATION_COMPACT_PROTOCOL_VERSION,
            application_id,
            message_id,
            sender_dht: our_dht,
            sent_at: current_timestamp(),
            payload_base64: BASE64.encode(payload),
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES {
            return Err("Encoded compact gossip application message exceeds protocol limit".into());
        }
        let route = fetch_route_blob(&dht_module, &peer_dht).await?.blob;
        send_raw_private_route_message(&veilid, &route, bytes).await?;
        Ok(message_id)
    }

    /// Send one handshake-free application gossip datagram to an explicit
    /// private-route blob instead of resolving a peer DHT first. This is used
    /// by short-lived mailbox service requests: the route is disposable and
    /// intentionally does not reveal/require a maintained handshake session.
    pub async fn send_gossip_application_message_to_route_shared(
        manager: Arc<Mutex<Self>>,
        route_blob: Vec<u8>,
        application_id: String,
        payload: Vec<u8>,
    ) -> Result<[u8; 16], Box<dyn std::error::Error + Send + Sync>> {
        let application_id = application_id.trim().to_ascii_lowercase();
        if application_id.is_empty() || application_id.len() > 256 {
            return Err("Application id length is invalid".into());
        }
        if route_blob.is_empty() || route_blob.len() > 8 * 1024 {
            return Err("Service reply route blob is empty or too large".into());
        }
        if payload.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES / 2 {
            return Err("Gossip application payload exceeds protocol limit".into());
        }

        let (veilid, our_dht) = {
            let manager = manager.lock().await;
            (manager.veilid.clone(), manager.our_dht.clone())
        };
        let mut message_id = [0u8; 16];
        OsRng.fill_bytes(&mut message_id);
        let envelope = GossipApplicationEnvelope {
            gossip_protocol_version: GOSSIP_APPLICATION_PROTOCOL_VERSION,
            application_id,
            message_id,
            sender_dht: our_dht,
            sent_at: current_timestamp(),
            payload,
        };
        let bytes = serde_json::to_vec(&envelope)?;
        if bytes.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES {
            return Err("Encoded gossip application message exceeds protocol limit".into());
        }
        send_raw_private_route_message(&veilid, &route_blob, bytes).await?;
        Ok(message_id)
    }

    async fn process_gossip_application(
        &mut self,
        mut envelope: GossipApplicationEnvelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if envelope.gossip_protocol_version != GOSSIP_APPLICATION_PROTOCOL_VERSION {
            return Err(format!(
                "Unsupported gossip application protocol {}",
                envelope.gossip_protocol_version
            ).into());
        }
        envelope.application_id = envelope.application_id.trim().to_ascii_lowercase();
        if envelope.application_id.is_empty() || envelope.application_id.len() > 256 {
            return Err("Invalid gossip application id".into());
        }
        if envelope.payload.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES / 2 {
            return Err("Gossip payload exceeds protocol limit".into());
        }
        let _ = envelope.sender_dht.parse::<RecordKey>()?;
        if envelope.sender_dht == self.our_dht {
            return Ok(());
        }
        if self.is_reputation_blocked(&envelope.sender_dht).await {
            self.log_reputation_block_diagnostic(
                &envelope.sender_dht,
                "inbound_gossip_blocked",
            )
            .await;
            return Err("Sender is blocked by reputation policy".into());
        }

        let now = current_timestamp();
        if envelope.sent_at > now.saturating_add(GOSSIP_APPLICATION_TIME_WINDOW_SECS)
            || envelope.sent_at.saturating_add(GOSSIP_APPLICATION_TIME_WINDOW_SECS) < now
        {
            return Err("Gossip application timestamp is outside the allowed window".into());
        }
        while self
            .inbound_gossip_global_attempts
            .front()
            .is_some_and(|timestamp| timestamp.saturating_add(60) <= now)
        {
            self.inbound_gossip_global_attempts.pop_front();
        }
        if self.inbound_gossip_global_attempts.len() >= MAX_GOSSIP_MESSAGES_GLOBAL_PER_MINUTE {
            return Err("Global gossip receive rate limit exceeded".into());
        }
        self.inbound_gossip_global_attempts.push_back(now);

        let attempts = self
            .inbound_gossip_attempts
            .entry(envelope.sender_dht.clone())
            .or_default();
        while attempts
            .front()
            .is_some_and(|timestamp| timestamp.saturating_add(60) <= now)
        {
            attempts.pop_front();
        }
        if attempts.len() >= MAX_GOSSIP_MESSAGES_PER_SENDER_PER_MINUTE {
            return Err("Gossip sender exceeded the local per-minute rate limit".into());
        }
        attempts.push_back(now);

        crate::tprintln!(
            "[gossip] Application hint received: app={} claimed_sender={} bytes={}",
            envelope.application_id,
            envelope.sender_dht,
            envelope.payload.len()
        );
        let _ = self.gossip_events.send(GossipApplicationMessage {
            application_id: envelope.application_id,
            message_id: envelope.message_id,
            sender_dht: envelope.sender_dht,
            sent_at: envelope.sent_at,
            payload: envelope.payload,
        });
        Ok(())
    }

    /// Send an authenticated, encrypted application payload over an already
    /// established peer session. Callers can fall back to the mailbox when the
    /// peer is offline or a secure session is not available.
    pub async fn send_application_message(
        &self,
        peer_dht: &str,
        application_id: &str,
        payload: Vec<u8>,
    ) -> Result<[u8; 16], Box<dyn std::error::Error + Send + Sync>> {
        if application_id.trim().is_empty() || application_id.len() > 256 {
            return Err("Application id length is invalid".into());
        }
        if payload.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES / 2 {
            return Err("Direct application payload exceeds protocol limit".into());
        }
        if self.is_reputation_blocked(peer_dht).await {
            return Err(format!("Peer {peer_dht} is blocked by reputation policy").into());
        }

        let state = self
            .sessions
            .get(peer_dht)
            .ok_or_else(|| format!("No handshake session for {peer_dht}"))?;
        if state.status != HandshakeStatus::Established {
            return Err(format!("Handshake with {peer_dht} is not established").into());
        }
        if state.encryption_mode != EncryptionMode::Aes256Gcm {
            return Err("Direct application transport requires AES-256-GCM".into());
        }

        let mut message_id = [0u8; 16];
        OsRng.fill_bytes(&mut message_id);
        let inner = DirectApplicationPayload {
            protocol_version: DIRECT_APPLICATION_PROTOCOL_VERSION,
            application_id: application_id.to_string(),
            message_id,
            sent_at: current_timestamp(),
            payload,
        };
        let ciphertext = state.encrypt(&serde_json::to_vec(&inner)?)?;
        let route = match state.route.clone() {
            Some(route) => route,
            None => fetch_route_blob(&self.dht_module, peer_dht).await?.blob,
        };
        let outer = DirectApplicationEnvelope {
            protocol_version: DIRECT_APPLICATION_PROTOCOL_VERSION,
            sender_dht: self.our_dht.clone(),
            ciphertext,
        };
        let bytes = serde_json::to_vec(&outer)?;
        if bytes.len() > MAX_DIRECT_APPLICATION_MESSAGE_BYTES {
            return Err("Encoded direct application message exceeds protocol limit".into());
        }
        send_raw_private_route_message(&self.veilid, &route, bytes).await?;
        Ok(message_id)
    }

    async fn process_direct_application(
        &mut self,
        envelope: DirectApplicationEnvelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if envelope.protocol_version != DIRECT_APPLICATION_PROTOCOL_VERSION {
            return Err(format!(
                "Unsupported direct application protocol {}",
                envelope.protocol_version
            )
            .into());
        }
        let _ = envelope.sender_dht.parse::<RecordKey>()?;
        if envelope.sender_dht == self.our_dht {
            return Ok(());
        }
        if self.is_reputation_blocked(&envelope.sender_dht).await {
            self.log_reputation_block_diagnostic(
                &envelope.sender_dht,
                "inbound_direct_application_blocked",
            )
            .await;
            return Err("Sender is blocked by reputation policy".into());
        }
        let state = self
            .sessions
            .get_mut(&envelope.sender_dht)
            .ok_or_else(|| format!("No session for {}", envelope.sender_dht))?;
        if state.status != HandshakeStatus::Established {
            return Err("Direct message arrived without an established handshake".into());
        }
        if state.encryption_mode != EncryptionMode::Aes256Gcm {
            return Err("Direct message session is not authenticated encryption".into());
        }
        let plaintext = state.decrypt(&envelope.ciphertext)?;
        let inner: DirectApplicationPayload = serde_json::from_slice(&plaintext)?;
        if inner.protocol_version != DIRECT_APPLICATION_PROTOCOL_VERSION {
            return Err("Inner direct application protocol mismatch".into());
        }
        if inner.application_id.trim().is_empty() || inner.application_id.len() > 256 {
            return Err("Invalid direct application id".into());
        }
        let now = current_timestamp();
        if inner.sent_at > now.saturating_add(DIRECT_APPLICATION_TIME_WINDOW_SECS)
            || inner
                .sent_at
                .saturating_add(DIRECT_APPLICATION_TIME_WINDOW_SECS)
                < now
        {
            return Err("Direct application message timestamp is outside the allowed window".into());
        }
        state.last_seen = now;
        crate::tprintln!(
            "[api] Direct application message received: app={} sender={} bytes={}",
            inner.application_id,
            envelope.sender_dht,
            inner.payload.len()
        );
        let _ = self.application_events.send(DirectApplicationMessage {
            application_id: inner.application_id,
            message_id: inner.message_id,
            sender_dht: envelope.sender_dht,
            sent_at: inner.sent_at,
            payload: inner.payload,
        });
        Ok(())
    }

    /// Returns the session for a peer if one exists.
    pub fn session(&self, peer_dht: &str) -> Option<&HandshakeState> {
        self.sessions.get(peer_dht)
    }

    /// Returns true if a fully established session exists for this peer.
    pub fn is_established(&self, peer_dht: &str) -> bool {
        self.sessions
            .get(peer_dht)
            .map_or(false, |s| s.status == HandshakeStatus::Established)
    }

    /// Returns true only when the established session is being maintained for
    /// ongoing application traffic.
    pub fn is_persistent_established(&self, peer_dht: &str) -> bool {
        self.sessions.get(peer_dht).map_or(false, |state| {
            state.status == HandshakeStatus::Established && state.maintain_connection
        })
    }

    /// Encrypt `plaintext` for `peer_dht` using their session key and the
    /// negotiated cipher.  Returns an error if no established session exists.
    pub fn encrypt_for(
        &self,
        peer_dht: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.sessions
            .get(peer_dht)
            .ok_or_else(|| format!("No session for {peer_dht}").into())
            .and_then(|s| s.encrypt(plaintext))
    }

    /// Decrypt wire bytes from `peer_dht`.
    pub fn decrypt_from(
        &self,
        peer_dht: &str,
        wire: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        self.sessions
            .get(peer_dht)
            .ok_or_else(|| format!("No session for {peer_dht}").into())
            .and_then(|s| s.decrypt(wire))
    }

    // =========================================================================
    // Internal handlers
    // =========================================================================

    async fn handle_welcome(
        &mut self,
        msg: HandshakeMessage,
        incoming_digest: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        crate::tprintln!("[handshake] Received init from {}", msg.sender_dht);

        // The responder accepts whatever mode the initiator proposes.
        // Defaulting to None is safe: if the initiator omits the field
        // (e.g. an older peer), we just leave the session unencrypted.
        let encryption_mode = msg.encryption_mode.unwrap_or(EncryptionMode::None);
        let maintain_connection = msg.maintain_connection;

        let their_pub_bytes = <[u8; 32]>::try_from(msg.sender_pubkey.as_slice())
            .map_err(|_| "Invalid responder public-key length")?;
        if their_pub_bytes.iter().all(|byte| *byte == 0) {
            return Err("Rejected all-zero X25519 public key".into());
        }
        let their_pub = PublicKey::from(their_pub_bytes);

        let our_private = EphemeralSecret::random_from_rng(OsRng);
        let our_public = PublicKey::from(&our_private);

        let shared = our_private.diffie_hellman(&their_pub);
        reject_all_zero_shared_secret(shared.as_bytes())?;

        let their_challenge = msg
            .challenge
            .clone()
            .ok_or("Type-1 handshake message is missing its challenge")?;

        let response = create_response(
            shared.as_bytes(),
            &msg.sender_dht,
            &self.our_dht,
            &their_challenge,
        );

        let our_challenge: Vec<u8> = rand::random::<[u8; 32]>().to_vec();

        let now = current_timestamp();


        let reply = HandshakeMessage {
            version: VERSION_ID,
            message_type: 2,
            sender_dht: self.our_dht.clone(),
            sender_pubkey: our_public.as_bytes().to_vec(),
            token: msg.token.clone(),
            challenge: Some(our_challenge.clone()),
            signature: Some(response),
            timestamp: now,
            // Echo the mode back so the initiator can verify agreement.
            encryption_mode: Some(encryption_mode),
            maintain_connection,
        };

        let blob = fetch_route_blob(&self.dht_module, &msg.sender_dht).await?;

        crate::tprintln!("[handshake] Sending type 2 to {:?}", blob);

        let reply_bytes = encode_handshake_message(&reply)?;
        send_raw_private_route_message(&self.veilid, &blob.blob, reply_bytes.clone()).await?;

        let mut received_flights = HashMap::new();
        received_flights.insert(1, incoming_digest);
        let mut cached_replies = HashMap::new();
        cached_replies.insert(
            1,
            CachedHandshakeReply {
                flight: SavedHandshakeFlight::new(2, reply_bytes.clone()),
                replay_count: 0,
            },
        );

        self.sessions.insert(msg.sender_dht.clone(), HandshakeState {
            peer_dht: msg.sender_dht,
            is_initiator: false,
            peer_public_key: Some(their_pub),
            our_private_key: None,
            our_public_key: our_public,
            route: Some(blob.blob),
            status: HandshakeStatus::ChallengeReceived,
            started_at: now,
            last_attempt: now,
            last_seen: now,
            retries: 0,
            token: reply.token,
            our_challenge: Some(our_challenge),
            their_challenge: Some(their_challenge),
            session_key: Some(*shared.as_bytes()),
            encryption_mode,
            maintain_connection,
            verification: false,
            outgoing_flight: Some(SavedHandshakeFlight::new(2, reply_bytes)),
            received_flights,
            cached_replies,
        });

        Ok(())
    }

    async fn handle_welcome_reply(
        &mut self,
        msg: HandshakeMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        crate::tprintln!("[handshake] Received welcome reply from {}", msg.sender_dht);

        let state = self.sessions.get_mut(&msg.sender_dht).ok_or("No session")?;

        if !state.is_initiator || state.status != HandshakeStatus::InitSent {
            return Err("Unexpected type-2 message for current handshake state".into());
        }

        if state.token != msg.token {
            return Err("Token mismatch".into());
        }

        // Verify the responder echoed the same mode we proposed.
        if let Some(echoed_mode) = msg.encryption_mode {
            if echoed_mode != state.encryption_mode {
                return Err(format!(
                    "Encryption mode mismatch: proposed {:?}, peer echoed {:?}",
                    state.encryption_mode, echoed_mode
                ).into());
            }
        }

        let their_pub_bytes = <[u8; 32]>::try_from(msg.sender_pubkey.as_slice())
            .map_err(|_| "Invalid responder public-key length")?;
        if their_pub_bytes.iter().all(|byte| *byte == 0) {
            return Err("Rejected all-zero X25519 public key".into());
        }
        let their_pub = PublicKey::from(their_pub_bytes);

        let our_challenge = state
            .our_challenge
            .clone()
            .ok_or("Missing local handshake challenge")?;
        let signature = msg
            .signature
            .clone()
            .ok_or("Welcome reply is missing its signature")?;
        let their_challenge = msg
            .challenge
            .clone()
            .ok_or("Welcome reply is missing its challenge")?;

        let private = state.our_private_key.take().ok_or("Missing private key")?;
        let shared = private.diffie_hellman(&their_pub);
        if let Err(error) = reject_all_zero_shared_secret(shared.as_bytes()) {
            state.status = HandshakeStatus::Failed;
            return Err(error);
        }

        let expected = create_response(
            shared.as_bytes(),
            &self.our_dht,
            &msg.sender_dht,
            &our_challenge,
        );

        if signature != expected {
            state.status = HandshakeStatus::Failed;
            return Err("Invalid challenge response".into());
        }

        let response = create_response(
            shared.as_bytes(),
            &self.our_dht,
            &msg.sender_dht,
            &their_challenge,
        );

        let now = current_timestamp();

        let reply = HandshakeMessage {
            version: VERSION_ID,
            message_type: 3,
            sender_dht: self.our_dht.clone(),
            sender_pubkey: state.our_public_key.as_bytes().to_vec(),
            token: msg.token,
            challenge: None,
            signature: Some(response),
            timestamp: now,
            // Type-3 finalisation doesn't carry mode; field is unused.
            encryption_mode: None,
            maintain_connection: state.maintain_connection,
        };

        let route = state
            .route
            .as_ref()
            .ok_or("Missing route for final handshake response")?;
        let reply_bytes = encode_handshake_message(&reply)?;
        if let Err(error) =
            send_raw_private_route_message(&self.veilid, route, reply_bytes.clone()).await
        {
            state.status = HandshakeStatus::Failed;
            return Err(error);
        }

        state.cached_replies.insert(
            2,
            CachedHandshakeReply {
                flight: SavedHandshakeFlight::new(3, reply_bytes),
                replay_count: 0,
            },
        );
        state.outgoing_flight = None;
        state.status = HandshakeStatus::Established;
        state.session_key = Some(*shared.as_bytes());
        state.peer_public_key = Some(their_pub);
        state.last_attempt = now;
        state.last_seen = now;

        crate::tprintln!(
            "[handshake] Established with {} (mode: {:?})",
            msg.sender_dht, state.encryption_mode
        );

        let established_peer = msg.sender_dht.clone();
        let duration_ms = now.saturating_sub(state.started_at).saturating_mul(1_000);
        // End the mutable session borrow before calling back through `self`.
        let _ = state;
        self.emit_handshake_succeeded(&established_peer, duration_ms);
        self.notify_established_peer(&established_peer);

        Ok(())
    }

    async fn handle_final(
        &mut self,
        msg: HandshakeMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        crate::tprintln!("handle final");
        let state = self.sessions.get_mut(&msg.sender_dht).ok_or("No session")?;

        if state.is_initiator || state.status != HandshakeStatus::ChallengeReceived {
            return Err("Unexpected type-3 message for current handshake state".into());
        }

        if state.token != msg.token {
            return Err("Token mismatch".into());
        }

        let shared = state.session_key.ok_or("Missing session key")?;

        let our_challenge = state
            .our_challenge
            .as_ref()
            .ok_or("Missing local handshake challenge")?;
        let expected = create_response(
            &shared,
            &msg.sender_dht,
            &self.our_dht,
            our_challenge,
        );

        let signature = msg
            .signature
            .as_ref()
            .ok_or("Final handshake message is missing its signature")?;
        if signature != &expected {
            return Err("Final verification failed".into());
        }

        state.status = HandshakeStatus::Established;
        state.outgoing_flight = None;
        state.maintain_connection = state.maintain_connection || msg.maintain_connection;
        state.last_attempt = current_timestamp();
        state.last_seen = current_timestamp();

        crate::tprintln!(
            "[handshake] Fully established with {} (mode: {:?})",
            msg.sender_dht, state.encryption_mode
        );

        let established_peer = msg.sender_dht.clone();
        let duration_ms = current_timestamp()
            .saturating_sub(state.started_at)
            .saturating_mul(1_000);
        let _ = state;
        self.emit_handshake_succeeded(&established_peer, duration_ms);
        self.notify_established_peer(&established_peer);

        Ok(())
    }

    fn handle_checkin(
        &mut self,
        msg: HandshakeMessage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	crate::tprintln!("handle checkin");
        let state = match self.sessions.get_mut(&msg.sender_dht) {
            Some(s) => s,
            None => {
                crate::tprintln!("[handshake] Check-in from unknown sender, ignoring");
                return Ok(());
            }
        };

        if state.status != HandshakeStatus::Established {
            return Ok(());
        }

        if state.token != msg.token {
            return Err("Check-in token mismatch".into());
        }

        let now = current_timestamp();

        if msg.timestamp > now.saturating_add(TIME_WINDOW) {
            return Err("Check-in timestamp from future".into());
        }
        if msg.timestamp.saturating_add(TIME_WINDOW) < now {
            return Err("Check-in timestamp too old".into());
        }

        state.last_seen = now;

        Ok(())
    }

    // =========================================================================
    // Tick  (call on a regular interval, e.g. every few seconds)
    // =========================================================================

    /// Drive retries, periodic check-ins, and session cleanup.
    /// Call this from a background loop, e.g. every 1-5 seconds.
    pub async fn tick(&mut self) {
        let now = current_timestamp();
        let mut to_remove = Vec::new();
        let mut failures: Vec<(String, String, u64, bool)> = Vec::new();

        for (peer_dht, state) in self.sessions.iter_mut() {
            // ---- Established sessions ----------------------------------------
            if state.status == HandshakeStatus::Established {
                if state.maintain_connection {
                    let elapsed = now.saturating_sub(state.last_attempt);

                    if elapsed >= CHECKIN_INTERVAL_SECS {
                        crate::tprintln!("[handshake] Sending check-in to {}", peer_dht);
                        // Record the attempt before I/O so a rocky DHT does not
                        // cause this two-second tick loop to hammer the same peer.
                        state.last_attempt = now;

                        if let Ok(route) = fetch_route_blob(&self.dht_module, &state.peer_dht).await {
                            let msg = HandshakeMessage {
                                version: VERSION_ID,
                                message_type: 5,
                                sender_dht: self.our_dht.clone(),
                                sender_pubkey: state.our_public_key.as_bytes().to_vec(),
                                token: state.token.clone(),
                                challenge: None,
                                signature: None,
                                timestamp: now,
                                encryption_mode: None,
                                maintain_connection: state.maintain_connection,
                            };

                            if let Err(error) =
                                send_handshake_message(&self.veilid, &route.blob, &msg).await
                            {
                                crate::teprintln!(
                                    "[handshake] Check-in send failed for {}: {error}",
                                    state.peer_dht
                                );
                            }

                        }
                    }
                }

                // Timeout applies regardless of maintain_connection.
                if now.saturating_sub(state.last_seen) > CHECKIN_TIMEOUT_SECS {
                    crate::tprintln!(
                        "[handshake] Timeout with {} ({} s since last seen), removing",
                        peer_dht,
                        now.saturating_sub(state.last_seen)
                    );
                    to_remove.push(peer_dht.clone());
                }

                continue;
            }

            // ---- Stale / failed sessions -------------------------------------
            if state.status == HandshakeStatus::Failed
                || now.saturating_sub(state.started_at) > 120
            {
                let reason = if state.status == HandshakeStatus::Failed {
                    "Handshake state marked failed".to_string()
                } else {
                    "Handshake exceeded the 120-second pending-session lifetime".to_string()
                };
                failures.push((
                    peer_dht.clone(),
                    reason,
                    now.saturating_sub(state.started_at).saturating_mul(1_000),
                    false,
                ));
                crate::tprintln!("[handshake] Removing stale/failed session with {}", peer_dht);
                to_remove.push(peer_dht.clone());
                continue;
            }

            // ---- In-progress: retry logic ------------------------------------
            let elapsed = now.saturating_sub(state.last_attempt);

            if state.retries >= MAX_HANDSHAKE_RETRIES && elapsed >= 5 {
                let reason = format!(
                    "No response after {} handshake attempts",
                    state.retries.saturating_add(1)
                );
                crate::tprintln!("[handshake] Failed to establish with {}", state.peer_dht);
                failures.push((
                    peer_dht.clone(),
                    reason,
                    now.saturating_sub(state.started_at).saturating_mul(1_000),
                    true,
                ));
                state.status = HandshakeStatus::Failed;
                to_remove.push(peer_dht.clone());
                continue;
            }

            let retry_delay = 3u64.saturating_mul(1u64 << state.retries.min(4));
            if state.retries < MAX_HANDSHAKE_RETRIES && elapsed >= retry_delay {
                crate::tprintln!("[handshake] Retrying ({}) with {}", state.retries + 1, state.peer_dht);


                if let Some(route) = &state.route {
                    // Validate the route blob before spending bandwidth, then
                    // retransmit the exact serialized stage saved when it was
                    // first sent. No token, challenge, key, signature, or
                    // timestamp is regenerated during a retry.
                    if let Err(error) = validate_importable_route(&self.veilid, route).await {
                        crate::tprintln!(
                            "[handshake] Route import failed for {}: {error}",
                            state.peer_dht
                        );
                        failures.push((
                            peer_dht.clone(),
                            format!("Route validation failed: {error}"),
                            now.saturating_sub(state.started_at).saturating_mul(1_000),
                            true,
                        ));
                        state.status = HandshakeStatus::Failed;
                        to_remove.push(peer_dht.clone());
                        continue;
                    }

                    let Some(flight) = state.outgoing_flight.as_ref() else {
                        failures.push((
                            peer_dht.clone(),
                            "Missing saved handshake flight during retry".to_string(),
                            now.saturating_sub(state.started_at).saturating_mul(1_000),
                            false,
                        ));
                        state.status = HandshakeStatus::Failed;
                        to_remove.push(peer_dht.clone());
                        continue;
                    };

                    // The digest is retained with the flight so accidental
                    // in-memory mutation is detected before retransmission.
                    if handshake_digest(&flight.bytes) != flight.digest {
                        failures.push((
                            peer_dht.clone(),
                            "Saved handshake flight failed its integrity check".to_string(),
                            now.saturating_sub(state.started_at).saturating_mul(1_000),
                            false,
                        ));
                        state.status = HandshakeStatus::Failed;
                        to_remove.push(peer_dht.clone());
                        continue;
                    }

                    if let Err(error) = send_raw_private_route_message(
                        &self.veilid,
                        route,
                        flight.bytes.clone(),
                    )
                    .await
                    {
                        crate::teprintln!(
                            "[handshake] Retry send failed for {} (type {}): {error}",
                            state.peer_dht,
                            flight.message_type
                        );
                    }
                } else {
                    crate::teprintln!("[handshake] Missing route for retry with {}", state.peer_dht);
                    failures.push((
                        peer_dht.clone(),
                        "Missing route during handshake retry".to_string(),
                        now.saturating_sub(state.started_at).saturating_mul(1_000),
                        true,
                    ));
                    state.status = HandshakeStatus::Failed;
                    to_remove.push(peer_dht.clone());
                    continue;
                }

                state.retries = state.retries.saturating_add(1);
                state.last_attempt = now;
            }
        }

        for peer in to_remove {
            self.sessions.remove(&peer);
        }

        for (peer, reason, duration_ms, ordinary_unavailable) in failures {
            self.emit_handshake_failed(&peer, reason.clone(), duration_ms);
            if ordinary_unavailable {
                if let Ok(subject) = peer.parse::<RecordKey>() {
                    if let Err(error) = self
                        .reputation
                        .submit_observation(ObservationInput {
                            subject,
                            kind: ObservationKind::HandshakeUnavailable,
                            details: ObservationDetails {
                                application_code: None,
                                description: Some(reason.clone()),
                            },
                        })
                        .await
                    {
                        crate::teprintln!(
                            "[handshake] Could not record ordinary handshake failure for {peer}: {error}"
                        );
                    }
                }
            }
        }

        self.inbound_init_attempts.retain(|_, attempts| {
            while attempts
                .front()
                .is_some_and(|timestamp| timestamp.saturating_add(HANDSHAKE_INIT_WINDOW_SECS) <= now)
            {
                attempts.pop_front();
            }
            !attempts.is_empty()
        });
        self.last_excessive_activity_report.retain(|_, reported_at| {
            reported_at.saturating_add(HANDSHAKE_INIT_WINDOW_SECS) > now
        });

        for values in self.reset_receipts.values_mut() {
            Self::retain_recent(values, now, HANDSHAKE_RESET_WINDOW_SECS);
        }
        self.reset_receipts.retain(|_, values| !values.is_empty());
        self.accepted_reset_tokens
            .retain(|_, accepted| accepted.expires_at > now);
        for values in self.reset_sends.values_mut() {
            Self::retain_recent(values, now, HANDSHAKE_RESET_WINDOW_SECS);
        }
        self.reset_sends.retain(|_, values| !values.is_empty());
        for values in self.challenge_failures.values_mut() {
            Self::retain_recent(values, now, CHALLENGE_FAILURE_WINDOW_SECS);
        }
        self.challenge_failures.retain(|_, values| !values.is_empty());
        self.quarantined_until.retain(|_, until| *until > now);
        self.ignored_until.retain(|_, until| *until > now);

        let due_restarts: Vec<(String, PendingHandshakeRestart)> = self
            .pending_restarts
            .iter()
            .filter(|(_, restart)| restart.restart_at <= now)
            .map(|(peer, restart)| (peer.clone(), restart.clone()))
            .collect();
        for (peer, restart) in due_restarts {
            self.pending_restarts.remove(&peer);
            if self.is_peer_ignored(&peer, now) || self.is_peer_quarantined(&peer, now) {
                continue;
            }
            if let Err(error) = self
                .initiate_handshake_internal(
                    peer.clone(),
                    restart.encryption_mode,
                    restart.verification,
                    restart.maintain_connection,
                )
                .await
            {
                crate::teprintln!(
                    "[handshake] Clean restart with {} failed: {}",
                    peer,
                    error
                );
            }
        }
    }
}


// ============================================================================
// DHT route lookup
// ============================================================================

/// Read a peer's published private-route blob from their main DHT.
///
/// This is stored as a `RouteBlobRecord` at `types::BLOB_LOCATION`. The peer's
/// DHT isn't one of ours, so this goes through `DHTModule::read_foreign_subkey`
/// rather than the `dht_package`-indexed read/write calls, which only know
/// about DHTs we created or imported ourselves.
async fn fetch_route_blob(
    dht_module: &DHTModule,
    target_dht: &str,
) -> Result<RouteBlobRecord, Box<dyn std::error::Error + Send + Sync>> {
    let record_key: RecordKey = target_dht
        .parse()
        .map_err(|_| format!("Invalid target DHT record key: {target_dht}"))?;

    let bytes = timeout(
        HANDSHAKE_IO_TIMEOUT,
        dht_module.read_foreign_subkey(record_key, BLOB_LOCATION, true),
    )
    .await
    .map_err(|_| format!("Timed out reading route blob for {target_dht}"))?
    .map_err(|e| format!("No route blob published at subkey {BLOB_LOCATION} for {target_dht}: {e:?}"))?;

    let record: RouteBlobRecord = decode_bincode_limited(
        &bytes,
        MAX_ROUTE_BLOB_RECORD_BYTES,
    )?;

    if record.blob.is_empty() || record.blob.len() > MAX_ROUTE_BLOB_RECORD_BYTES {
        return Err("Published route blob has an invalid size".into());
    }

    Ok(record)
}

// ============================================================================
// Utility
// ============================================================================

/// Extract the sender's DHT address from a raw message without fully parsing it.
pub fn extract_sender_dht(data: &[u8]) -> Option<String> {
    decode_json_limited::<HandshakeMessage>(data, MAX_HANDSHAKE_MESSAGE_BYTES)
        .ok()
        .map(|m| m.sender_dht)
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    fn valid_type_one() -> HandshakeMessage {
        HandshakeMessage {
            version: VERSION_ID,
            message_type: 1,
            sender_dht: "VLD0:test".to_string(),
            sender_pubkey: vec![1u8; 32],
            token: "test-token".to_string(),
            challenge: Some(vec![2u8; HANDSHAKE_CHALLENGE_BYTES]),
            signature: None,
            timestamp: 1,
            encryption_mode: Some(EncryptionMode::Aes256Gcm),
            maintain_connection: false,
        }
    }

    #[test]
    fn rejects_wrong_protocol_version() {
        let mut message = valid_type_one();
        message.version = VERSION_ID.wrapping_add(1);
        assert!(validate_handshake_message(&message).is_err());
    }

    #[test]
    fn rejects_missing_type_one_challenge() {
        let mut message = valid_type_one();
        message.challenge = None;
        assert!(validate_handshake_message(&message).is_err());
    }

    #[test]
    fn rejects_wrong_x25519_key_length() {
        let mut message = valid_type_one();
        message.sender_pubkey.pop();
        assert!(validate_handshake_message(&message).is_err());
    }

    #[test]
    fn accepts_well_formed_type_one_shape() {
        assert!(validate_handshake_message(&valid_type_one()).is_ok());
    }

    #[test]
    fn reset_contains_no_reason_or_crypto_metadata() {
        let reset = HandshakeMessage {
            version: VERSION_ID,
            message_type: HANDSHAKE_RESET_MESSAGE_TYPE,
            sender_dht: "VLD0:test".to_string(),
            sender_pubkey: Vec::new(),
            token: "session-token".to_string(),
            challenge: None,
            signature: None,
            timestamp: 1,
            encryption_mode: None,
            maintain_connection: false,
        };
        assert!(validate_handshake_message(&reset).is_ok());
        let encoded = encode_handshake_message(&reset).expect("reset should serialize");
        let text = String::from_utf8(encoded).expect("handshake JSON is UTF-8");
        assert!(!text.contains("reason"));
    }

    #[test]
    fn saved_flight_keeps_exact_wire_bytes() {
        let bytes = encode_handshake_message(&valid_type_one()).expect("message should serialize");
        let saved = SavedHandshakeFlight::new(1, bytes.clone());
        assert_eq!(saved.bytes, bytes);
        assert_eq!(saved.digest, handshake_digest(&saved.bytes));
    }
}

//! Local application API transport.
//!
//! Windows uses a named pipe. Unix builds use a Unix-domain socket with the
//! same newline-delimited JSON protocol so client libraries can share almost
//! all code. Each request and response occupies one UTF-8 JSON line.
//!
//! Protocol version 3 provides capability-checked mailbox send/receive, a
//! filtered per-application message stream, and token-protected first-run app
//! authorization. Applications never receive another application's plaintext
//! and cannot choose the application id placed in an outgoing envelope.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(any(target_os = "android", target_os = "ios"))]
use std::sync::{
    atomic::{AtomicU64, Ordering as AtomicOrdering},
    mpsc as std_mpsc,
    Mutex as StdMutex,
    OnceLock,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{watch, Mutex, Semaphore},
    task::{JoinHandle, JoinSet},
};

#[cfg(any(target_os = "android", target_os = "ios"))]
use tokio::sync::oneshot;
use veilid_core::RecordKey;

use crate::{
    app::{
        directory::{
            AppDirectoryManager, AppRootLookupQueueState, APP_ROOT_CACHE_TTL_SECS,
            APP_ROOT_NEGATIVE_CACHE_TTL_SECS,
        },
        discovery::{AppPeerTier, AppRootCacheState, APP_DISCOVERY_MAX_API_RESULTS},
        visible_names::AppVisibleNameManager,
    },
    blob_store::{
        BlobDescriptor, BlobStoreError, BlobStoreManager, BlobUploadStatus,
        BLOB_MAX_APPEND_BYTES, BLOB_MAX_BYTES,
    },
    private_app_storage::{
        PrivateAppStorageManager, PrivateBlobDescriptor, PrivateRetention,
        PrivateStorageError, PrivateStorageUsage, PrivateValueDescriptor,
        DEFAULT_PRIVATE_CACHE_LIMIT_BYTES, MAX_EPHEMERAL_TTL_SECS,
        MAX_PRIVATE_BLOB_APPEND_BYTES, MAX_PRIVATE_BLOB_BYTES,
        MAX_PRIVATE_BLOB_READ_BYTES, MAX_PRIVATE_VALUE_BYTES, MIN_EPHEMERAL_TTL_SECS,
    },
    gossip::{
        derive_index_tokens, GossipAppStats, GossipConfirmationLevel, GossipError, GossipEvent,
        GossipFingerprint, GossipFingerprintProbe, GossipIndexToken, GossipManager,
        GossipProbePolarity, GossipPublishRequest, GossipRecord, GossipSearchHit,
        GossipSearchQuery, GossipTokenMatchMode, GossipTokenPolarity, GossipTokenProbe,
        GossipVerificationState, GOSSIP_DEFAULT_NETWORK_WAIT_MS, GOSSIP_DEFAULT_TTL_SECS,
        GOSSIP_ENGINE_NAMESPACE_STREAMS, GOSSIP_MAX_CUSTOM_PAYLOAD_BYTES,
        GOSSIP_MAX_FINGERPRINT_BYTES, GOSSIP_MAX_FINGERPRINTS, GOSSIP_MAX_INDEX_PROBES,
        GOSSIP_MAX_INDEX_TERM_BYTES, GOSSIP_MAX_INDEX_TOKENS, GOSSIP_MAX_QUERY_RESULTS,
        GOSSIP_MAX_TTL_SECS,
    },
    stream_transport::{
        same_stream_application_family, StreamDescriptor, StreamEvent,
        StreamSegmentCommitment, StreamSummary,
        StreamTransportError, StreamTransportManager, StreamWriteResult,
        STREAM_INTERNAL_APPLICATION_ID, STREAM_MAX_WRITE_BYTES, STREAM_PACKET_BYTES,
    },
    app_services::{
        AppServiceError, AppSignatureResult, AppSigningIdentity, AppSigningManager,
        AppStorageManager, AppStoreDescriptor, AppStoreReadValue,
        MAX_APP_SIGNATURE_DOMAIN_BYTES, MAX_APP_SIGNATURE_PAYLOAD_BYTES,
        MAX_APP_STORE_READS_PER_REQUEST, MAX_APP_STORE_SUBKEYS,
        MAX_APP_STORE_VALUE_BYTES, MAX_APP_STORE_WRITES_PER_REQUEST,
        MAX_APP_STORE_WRITE_BYTES_PER_REQUEST, MAX_APP_STORES_PER_APP,
    },
    console_log,
    lexical_library::{
        AssociationMetrics, LexicalError, LexicalLibraryManager, LexicalLibraryStats,
        LexicalObserveRequest, LexicalObserveResult, LexicalSearchResult, WordSimilarity,
        LEXICAL_ACTIVE_WINDOW_DAYS, LEXICAL_DEFAULT_LAYER, LEXICAL_DEFAULT_LIBRARY_NAME,
        LEXICAL_MAX_PRETOKENIZED_TERMS, LEXICAL_MAX_SEARCH_TERMS, LEXICAL_MAX_TEXT_BYTES,
    },
    handshake::HandshakeManager,
    identity_manager::{
        AppAuthResponse, AppCapability, AppCapabilitySet, AppCredential, AppSessionToken, IdentityManager,
    },
    mailbox::{
        CustodianMessageObservation, MailboxEvent, MailboxManager,
        OutgoingMessageObservationReport, OutgoingMessageRequest, ServiceRequest,
        ServiceRequestPublishRequest,
    },
    network_events::NetworkEventEnvelope,
    node_list::NodeVerificationState,
    network_supervisor::{NetworkStatus, NetworkSupervisor},
    reputation::{
        AppId, AppSourceReport, BanScope, DecisionId, ObservationDetails,
        ObservationId, ObservationInput, ObservationKind, ReputationManager, ReputationView,
    },
    types::{current_timestamp, CAPABILITY_MAILBOX, USER_PRESENCE_STALE_AFTER_SECS},
    walk_task::{AppSearchStartState, WalkConfig, WalkStartResult, WalkStatus, WalkTask},
};

pub const LOCAL_API_PROTOCOL_VERSION: u16 = 3;
pub const MAX_API_MESSAGE_BYTES: usize = 8 * 1024;

/// Ceiling on publishing this app's root record to the directory.
///
/// Generous, because a healthy publish on a slow mobile link can take a while, but finite so
/// that an offline node produces an error the caller can show instead of a hung binder call.
const APP_ROOT_PUBLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
const MAX_API_REQUEST_LINE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_APPLICATION_MESSAGES: usize = 16_384;
const MAX_PENDING_APPLICATION_MESSAGES_PER_APP: usize = 4_096;
const MAX_SEEN_APPLICATION_MESSAGES: usize = 32_768;
const REGISTRATION_REQUEST_TTL_SECS: u64 = 15 * 60;
const REGISTRATION_RESULT_TTL_SECS: u64 = 10 * 60;
const MAX_PENDING_REGISTRATION_REQUESTS: usize = 256;
const MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION: usize = 16;
// Global lane limits matter because the SDK normally opens one IPC connection
// per request. Delivery work cannot consume the slots reserved for room/app
// control operations such as create, join, status, and authorization.
const MAX_IN_FLIGHT_CONTROL_REQUESTS: usize = 12;
const MAX_IN_FLIGHT_DELIVERY_REQUESTS: usize = 8;
const LOCAL_API_REQUEST_TIMEOUT: Duration = Duration::from_secs(150);
const BACKLOG_WARNING_AFTER_SECS: u64 = 60;
const BACKLOG_REPEAT_SECS: u64 = 5 * 60;
const MAX_BACKLOG_LOG_ENTRIES: usize = 24;
const MAX_APP_RECOMMENDED_NODES: usize = 256;
const APP_ACTIVITY_MIN_LEASE_SECS: u64 = 30;
const APP_ACTIVITY_MAX_LEASE_SECS: u64 = 10 * 60;

// Android's embedded host can use the exact protocol-v3 request dispatcher without
// traversing Binder + a filesystem Unix-domain socket. We keep the socket listener for
// standalone/compatibility clients, but Weave talks to this in-memory duplex transport.
#[cfg(any(target_os = "android", target_os = "ios"))]
const EMBEDDED_BRIDGE_BUFFER_BYTES: usize = 2 * 1024 * 1024;
#[cfg(any(target_os = "android", target_os = "ios"))]
const EMBEDDED_SUBSCRIPTION_QUEUE_LINES: usize = 4096;
#[cfg(any(target_os = "android", target_os = "ios"))]
static EMBEDDED_CONTEXT: OnceLock<StdMutex<Option<LocalApiContext>>> = OnceLock::new();
#[cfg(any(target_os = "android", target_os = "ios"))]
static EMBEDDED_RUNTIME: OnceLock<StdMutex<Option<tokio::runtime::Handle>>> = OnceLock::new();
#[cfg(any(target_os = "android", target_os = "ios"))]
static EMBEDDED_SUBSCRIPTIONS: OnceLock<StdMutex<HashMap<u64, EmbeddedSubscriptionControl>>> = OnceLock::new();
#[cfg(any(target_os = "android", target_os = "ios"))]
static EMBEDDED_NEXT_SUBSCRIPTION_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(any(target_os = "android", target_os = "ios"))]
struct EmbeddedSubscriptionControl {
    queue: Arc<StdMutex<VecDeque<String>>>,
    cancel: Option<oneshot::Sender<()>>,
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn embedded_context_slot() -> &'static StdMutex<Option<LocalApiContext>> {
    EMBEDDED_CONTEXT.get_or_init(|| StdMutex::new(None))
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn embedded_runtime_slot() -> &'static StdMutex<Option<tokio::runtime::Handle>> {
    EMBEDDED_RUNTIME.get_or_init(|| StdMutex::new(None))
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn embedded_subscriptions() -> &'static StdMutex<HashMap<u64, EmbeddedSubscriptionControl>> {
    EMBEDDED_SUBSCRIPTIONS.get_or_init(|| StdMutex::new(HashMap::new()))
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn embedded_error_json(message: impl Into<String>) -> String {
    serde_json::to_string(&ApiResponseEnvelope::<()> {
        protocol_version: LOCAL_API_PROTOCOL_VERSION,
        request_id: 0,
        ok: false,
        result: None,
        error: Some(ApiErrorBody {
            code: "embedded_bridge_error",
            message: message.into(),
        }),
    })
    .unwrap_or_else(|_| r#"{"protocol_version":3,"request_id":0,"ok":false,"error":{"code":"embedded_bridge_error","message":"serialization failed"}}"#.to_string())
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn install_embedded_bridge(context: LocalApiContext) {
    *embedded_context_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(context);
    *embedded_runtime_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(tokio::runtime::Handle::current());
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn clear_embedded_bridge() {
    *embedded_context_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    *embedded_runtime_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;

    let mut subscriptions = embedded_subscriptions()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for (_, mut control) in subscriptions.drain() {
        if let Some(cancel) = control.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

/// Execute one existing protocol-v3 request over an in-memory Tokio duplex stream.
/// The dispatcher, authentication, capability checks, timeout lanes and result encoding are
/// therefore exactly the same as the standalone local API; only the transport is different.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn embedded_transact(request_json: String) -> String {
    if request_json.len() > MAX_API_REQUEST_LINE_BYTES {
        return embedded_error_json(format!(
            "request line is {} bytes; maximum is {} bytes",
            request_json.len(), MAX_API_REQUEST_LINE_BYTES
        ));
    }

    let context = embedded_context_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let runtime = embedded_runtime_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let (Some(context), Some(runtime)) = (context, runtime) else {
        return embedded_error_json("embedded VeilKnit API is not ready");
    };

    let (reply_tx, reply_rx) = std_mpsc::sync_channel::<String>(1);
    runtime.spawn(async move {
        let (client, server) = tokio::io::duplex(EMBEDDED_BRIDGE_BUFFER_BYTES);
        let server_task = tokio::spawn(async move {
            let _ = handle_connection(server, context).await;
        });
        let (read_half, mut write_half) = tokio::io::split(client);
        let mut reader = BufReader::new(read_half).lines();

        let result = async {
            write_half.write_all(request_json.as_bytes()).await?;
            write_half.write_all(b"\n").await?;
            write_half.flush().await?;
            write_half.shutdown().await?;
            match tokio::time::timeout(LOCAL_API_REQUEST_TIMEOUT + Duration::from_secs(5), reader.next_line()).await {
                Ok(Ok(Some(line))) => Ok(line),
                Ok(Ok(None)) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "embedded API closed without a response")),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "embedded API response timed out")),
            }
        }
        .await;

        let _ = reply_tx.send(match result {
            Ok(line) => line,
            Err(error) => embedded_error_json(error.to_string()),
        });
        let _ = server_task.await;
    });

    reply_rx
        .recv_timeout(LOCAL_API_REQUEST_TIMEOUT + Duration::from_secs(10))
        .unwrap_or_else(|_| embedded_error_json("embedded API response timed out"))
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn embedded_recover_app_credential(app_id_text: String) -> String {
    let context = embedded_context_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let runtime = embedded_runtime_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let (Some(context), Some(runtime)) = (context, runtime) else {
        return serde_json::json!({
            "ok": false,
            "error": "embedded VeilKnit API is not ready",
        })
        .to_string();
    };

    let app_id = match AppId::new(app_id_text) {
        Ok(app_id) => app_id,
        Err(error) => {
            return serde_json::json!({
                "ok": false,
                "error": format!("invalid application id: {error}"),
            })
            .to_string();
        }
    };

    let identities = context.identities.clone();
    let (reply_tx, reply_rx) = std_mpsc::sync_channel::<String>(1);
    runtime.spawn(async move {
        let payload = match identities.rotate_app_credential(&app_id).await {
            Ok(credential) => serde_json::json!({
                "ok": true,
                "app_id": credential.app_id.to_string(),
                "secret_hex": hex::encode(credential.secret_bytes()),
                "credential_generation": credential.credential_generation,
            })
            .to_string(),
            Err(error) => serde_json::json!({
                "ok": false,
                "error": error.to_string(),
            })
            .to_string(),
        };
        let _ = reply_tx.send(payload);
    });

    reply_rx.recv_timeout(Duration::from_secs(10)).unwrap_or_else(|_| {
        serde_json::json!({
            "ok": false,
            "error": "embedded credential recovery timed out",
        })
        .to_string()
    })
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn embedded_subscribe(request_json: String) -> u64 {
    let context = embedded_context_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let runtime = embedded_runtime_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let (Some(context), Some(runtime)) = (context, runtime) else {
        return 0;
    };

    let id = EMBEDDED_NEXT_SUBSCRIPTION_ID.fetch_add(1, AtomicOrdering::Relaxed);
    let queue = Arc::new(StdMutex::new(VecDeque::<String>::new()));
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();
    embedded_subscriptions()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(
            id,
            EmbeddedSubscriptionControl {
                queue: queue.clone(),
                cancel: Some(cancel_tx),
            },
        );

    runtime.spawn(async move {
        let (client, server) = tokio::io::duplex(EMBEDDED_BRIDGE_BUFFER_BYTES);
        let server_task = tokio::spawn(async move {
            let _ = handle_connection(server, context).await;
        });
        let (read_half, mut write_half) = tokio::io::split(client);
        let mut reader = BufReader::new(read_half).lines();

        let write_result = async {
            write_half.write_all(request_json.as_bytes()).await?;
            write_half.write_all(b"\n").await?;
            // Match the standalone LocalSocket subscription transport: keep the request side
            // open for the lifetime of the stream. Half-closing a Tokio duplex stream here made
            // the embedded path subtly different from Android's old socket bridge.
            write_half.flush().await
        }
        .await;

        if let Err(error) = write_result {
            let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
            q.push_back(embedded_error_json(error.to_string()));
        } else {
            loop {
                tokio::select! {
                    _ = &mut cancel_rx => break,
                    line = reader.next_line() => {
                        match line {
                            Ok(Some(line)) => {
                                let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
                                q.push_back(line);
                                while q.len() > EMBEDDED_SUBSCRIPTION_QUEUE_LINES {
                                    q.pop_front();
                                }
                            }
                            Ok(None) => break,
                            Err(error) => {
                                let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
                                q.push_back(embedded_error_json(error.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }

        server_task.abort();
        let mut subscriptions = embedded_subscriptions()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(control) = subscriptions.get_mut(&id) {
            control.cancel = None;
        }
    });

    id
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn embedded_drain_subscription(id: u64) -> Vec<String> {
    let queue = {
        let subscriptions = embedded_subscriptions()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        subscriptions.get(&id).map(|control| control.queue.clone())
    };
    let Some(queue) = queue else { return Vec::new(); };
    let mut queue = queue.lock().unwrap_or_else(|error| error.into_inner());
    queue.drain(..).collect()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn embedded_subscription_active(id: u64) -> bool {
    embedded_subscriptions()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .get(&id)
        .map(|control| control.cancel.is_some())
        .unwrap_or(false)
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn embedded_profile_id() -> String {
    embedded_context_slot()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .map(|context| context.profile_id.clone())
        .unwrap_or_default()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
pub fn embedded_unsubscribe(id: u64) {
    let mut subscriptions = embedded_subscriptions()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(mut control) = subscriptions.remove(&id) {
        if let Some(cancel) = control.cancel.take() {
            let _ = cancel.send(());
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_app_peer_limit() -> usize {
    APP_DISCOVERY_MAX_API_RESULTS
}

fn default_recommendation_ttl() -> u64 {
    10 * 60
}

fn default_activity_lease() -> u64 {
    90
}

fn default_stream_relay_capacity() -> u16 {
    2
}

fn default_gossip_network_wait_ms() -> u64 {
    GOSSIP_DEFAULT_NETWORK_WAIT_MS
}

fn default_gossip_result_limit() -> usize {
    24
}

fn default_lexical_library_name() -> String { LEXICAL_DEFAULT_LIBRARY_NAME.to_string() }
fn default_lexical_layer() -> String { LEXICAL_DEFAULT_LAYER.to_string() }
fn default_lexical_window_days() -> u16 { LEXICAL_ACTIVE_WINDOW_DAYS }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppActivityLevel {
    Inactive,
    Background,
    Interactive,
    Realtime,
}

impl AppActivityLevel {
    fn interval_secs(self) -> u64 {
        match self {
            Self::Inactive => u64::MAX,
            Self::Background => 120,
            Self::Interactive => 45,
            Self::Realtime => 20,
        }
    }

    fn hop_count(self) -> usize {
        match self {
            Self::Inactive => 0,
            Self::Background => 3,
            Self::Interactive => 5,
            Self::Realtime => 8,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ApiRequestEnvelope {
    pub protocol_version: u16,
    pub request_id: u64,
    #[serde(flatten)]
    pub request: ApiRequest,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ApiRequest {
    Ping,
    GetApiInfo,
    GetStatus {
        session_token: String,
    },
    GetIdentity {
        session_token: String,
    },
    BeginAuthentication {
        app_id: String,
        requested_capabilities: Vec<AppCapability>,
    },
    FinishAuthentication {
        app_id: String,
        challenge_id: u64,
        proof_hex: String,
    },
    SubscribeEvents {
        session_token: String,
    },
    SendMessage {
        session_token: String,
        recipient_main_dht: String,
        payload_base64: String,
        #[serde(default)]
        conversation_id_hex: Option<String>,
        #[serde(default)]
        expires_at: Option<u64>,
        #[serde(default)]
        await_response: bool,
        /// When false, skip the maintained direct-handshake shortcut and queue
        /// the message through the persistent mailbox. Background Rooms traffic
        /// uses this so dozens of inactive rooms do not maintain live sessions.
        #[serde(default = "default_true")]
        prefer_direct: bool,
    },
    /// Send a best-effort, handshake-free application gossip datagram over the
    /// target's published Veilid private route. The receiver treats the claimed
    /// sender and payload as unverified hints until app/DHT confirmation.
    SendGossip {
        session_token: String,
        recipient_main_dht: String,
        payload_base64: String,
    },
    /// Publish one compact daemon-managed gossip hint for this authenticated
    /// application. The app id is derived from the session token.
    PublishGossipObject {
        session_token: String,
        object: ApiGossipPublishObject,
    },
    WithdrawGossipObject {
        session_token: String,
        namespace: String,
        object_id: String,
        #[serde(default)]
        generation: Option<u64>,
    },
    SearchGossip {
        session_token: String,
        query: ApiGossipSearchQuery,
        #[serde(default)]
        query_network: bool,
        #[serde(default = "default_gossip_network_wait_ms")]
        network_wait_ms: u64,
    },
    ListGossip {
        session_token: String,
        #[serde(default)]
        namespace: Option<String>,
        #[serde(default = "default_gossip_result_limit")]
        limit: usize,
    },
    ConfirmGossipObject {
        session_token: String,
        namespace: String,
        object_id: String,
        generation: u64,
        level: GossipConfirmationLevel,
        #[serde(default = "default_true")]
        matches_authoritative: bool,
    },
    GetGossipStats {
        session_token: String,
    },
    SubscribeGossip {
        session_token: String,
    },
    /// Feed text or already-separated terms into this app's daemon-owned lexical library.
    ObserveLexical {
        session_token: String,
        #[serde(default = "default_lexical_library_name")] library_name: String,
        #[serde(default = "default_lexical_layer")] layer: String,
        object_id: String,
        generation: u64,
        field_id: String,
        #[serde(default)] text: Option<String>,
        #[serde(default)] terms: Vec<String>,
        #[serde(default)] authoritative_pointer: Option<String>,
        #[serde(default = "default_true")] publish_posting_hint: bool,
    },
    WithdrawLexicalObject {
        session_token: String,
        #[serde(default = "default_lexical_library_name")] library_name: String,
        object_id: String,
        #[serde(default)] generation: Option<u64>,
    },
    SearchLexical {
        session_token: String,
        #[serde(default = "default_lexical_library_name")] library_name: String,
        #[serde(default = "default_lexical_layer")] layer: String,
        terms: Vec<String>,
        #[serde(default = "default_lexical_window_days")] window_days: u16,
        #[serde(default)] query_network: bool,
    },
    CompareLexicalTerms { session_token: String, left: String, right: String },
    GetLexicalAssociation {
        session_token: String,
        #[serde(default = "default_lexical_library_name")] library_name: String,
        #[serde(default = "default_lexical_layer")] layer: String,
        left: String,
        right: String,
        #[serde(default = "default_lexical_window_days")] window_days: u16,
    },
    GetLexicalStats {
        session_token: String,
        #[serde(default = "default_lexical_library_name")] library_name: String,
    },
    TriggerMessageRetrieval {
        session_token: String,
    },
    GetMailboxStatus {
        session_token: String,
    },
    /// Publish a deliberately public, short-lived rendezvous request into the
    /// mailbox network. The daemon creates/owns a disposable private reply route.
    PublishServiceRequest {
        session_token: String,
        intended_host_main_dht: String,
        service_id_hex: String,
        service_manifest_hash_hex: String,
        instance_id_hex: String,
        payload_base64: String,
        #[serde(default)]
        delegation_allowed: bool,
        #[serde(default)]
        spectators_allowed: bool,
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    WithdrawServiceRequest {
        session_token: String,
        request_id_hex: String,
    },
    /// Subscribe to public rendezvous requests for one or more opaque service ids.
    SubscribeServiceRequests {
        session_token: String,
        service_ids_hex: Vec<String>,
    },
    /// Reply directly to the requester's disposable private route without
    /// establishing a daemon handshake.
    SendServiceReply {
        session_token: String,
        request_id_hex: String,
        reply_route_blob_base64: String,
        payload_base64: String,
    },
    ListKnownNodes {
        session_token: String,
    },
    /// Return a rotating page of directly verified users of the authenticated
    /// application. The app id is always derived from the session token.
    ListAppPeers {
        session_token: String,
        #[serde(default = "default_app_peer_limit")]
        limit: usize,
        #[serde(default = "default_true")]
        start_search: bool,
    },
    /// Register or replace this authenticated app's root DHT in the local
    /// daemon-owned App Directory. The app id always comes from the session.
    RegisterAppRoot {
        session_token: String,
        root_dht: String,
    },
    ClearAppRoot {
        session_token: String,
    },
    /// Return cached root state immediately. If the cache is absent or stale,
    /// optionally queue a bounded two-read lookup without holding IPC open.
    GetAppRoot {
        session_token: String,
        peer_main_dht: String,
        #[serde(default = "default_true")]
        start_lookup: bool,
    },
    /// Suggest identities that became relevant through the app's own signed
    /// data (for example, a Rooms membership manifest). The daemon treats them
    /// only as unverified candidates and performs its normal DHT/reputation
    /// checks before promoting them.
    RecommendNodes {
        session_token: String,
        nodes: Vec<String>,
        #[serde(default)]
        context: Option<String>,
        #[serde(default = "default_recommendation_ttl")]
        ttl_seconds: u64,
    },
    /// Renewable activity lease. Apps request a service level rather than
    /// being allowed to loop unrestricted walk commands. Leases disappear
    /// automatically when the app stops renewing them.
    SetAppActivity {
        session_token: String,
        level: AppActivityLevel,
        #[serde(default)]
        relevant_nodes: Vec<String>,
        #[serde(default = "default_activity_lease")]
        lease_seconds: u64,
    },
    GetOperationBacklog {
        session_token: String,
    },
    ListInbox {
        session_token: String,
    },
    ReadInbox {
        session_token: String,
        message_id_hex: String,
    },
    DeleteInbox {
        session_token: String,
        message_id_hex: String,
    },
    GetNetworkDiagnostics {
        session_token: String,
    },
    StartDiagnosticWalk {
        session_token: String,
        hop_count: usize,
    },
    PostMailboxProbe {
        session_token: String,
        recipient_main_dht: String,
        payload_base64: String,
        #[serde(default)]
        expires_at: Option<u64>,
    },
    GetMailboxProbeStatus {
        session_token: String,
        message_id_hex: String,
    },
    ListMailboxProbeReports {
        session_token: String,
    },
    SubscribeMessages {
        session_token: String,
    },
    RequestAppRegistration {
        app_id: String,
        display_name: String,
        requested_capabilities: Vec<AppCapability>,
        request_token_hex: String,
    },
    GetAppRegistrationStatus {
        registration_request_id: u64,
        request_token_hex: String,
    },
    GetAppSigningIdentity {
        session_token: String,
    },
    RotateAppSigningKey {
        session_token: String,
    },
    SignAppPayload {
        session_token: String,
        domain: String,
        payload_base64: String,
    },
    VerifyAppSignature {
        session_token: String,
        public_key_hex: String,
        domain: String,
        payload_base64: String,
        signature_hex: String,
    },
    ListAppStores {
        session_token: String,
    },
    CreateAppStore {
        session_token: String,
        name: String,
        subkey_count: u16,
        #[serde(default = "default_true")]
        initialize: bool,
    },
    ReadAppStore {
        session_token: String,
        store_id: String,
        locations: Vec<u32>,
        #[serde(default)]
        force_refresh: bool,
    },
    WriteAppStore {
        session_token: String,
        store_id: String,
        #[serde(default)]
        expected_generation: Option<u64>,
        writes: Vec<ApiStoreWrite>,
    },
    ReadPublicStore {
        session_token: String,
        record_key: String,
        locations: Vec<u32>,
        #[serde(default)]
        force_refresh: bool,
    },

    // Local-only encrypted app vault. Account/profile and APP_ID are derived from the
    // authenticated daemon session; callers cannot choose either namespace.
    PutPrivateValue {
        session_token: String,
        key: String,
        value_base64: String,
        #[serde(default)]
        retention: PrivateRetention,
        #[serde(default)]
        ttl_seconds: Option<u64>,
    },
    GetPrivateValue { session_token: String, key: String },
    ListPrivateValues { session_token: String },
    DeletePrivateValue { session_token: String, key: String },
    RenewPrivateValue {
        session_token: String, key: String, retention: PrivateRetention,
        #[serde(default)] ttl_seconds: Option<u64>,
    },
    BeginPrivateBlob {
        session_token: String, content_type: String,
        #[serde(default)] retention: PrivateRetention,
        #[serde(default)] ttl_seconds: Option<u64>,
    },
    AppendPrivateBlob { session_token: String, blob_id: String, data_base64: String },
    FinishPrivateBlob { session_token: String, blob_id: String },
    AbortPrivateBlob { session_token: String, blob_id: String },
    ListPrivateBlobs { session_token: String },
    DeletePrivateBlob { session_token: String, blob_id: String },
    ReadPrivateBlobRange { session_token: String, blob_id: String, offset: u64, length: u64 },
    RenewPrivateBlob {
        session_token: String, blob_id: String, retention: PrivateRetention,
        #[serde(default)] ttl_seconds: Option<u64>,
    },
    GetPrivateStorageUsage { session_token: String },

    BeginBlobUpload {
        session_token: String,
        content_type: String,
    },
    AppendBlobUpload {
        session_token: String,
        upload_id: String,
        data_base64: String,
    },
    FinishBlobUpload {
        session_token: String,
        upload_id: String,
        #[serde(default)]
        expected_sha256_hex: Option<String>,
    },
    AbortBlobUpload {
        session_token: String,
        upload_id: String,
    },
    ListBlobs {
        session_token: String,
    },
    DeleteBlob {
        session_token: String,
        blob_id: String,
    },
    ReadBlobRange {
        session_token: String,
        root_record_key: String,
        offset: u64,
        length: u64,
        #[serde(default)]
        force_refresh: bool,
    },
    StartStream {
        session_token: String,
        opaque_metadata_base64: String,
    },
    JoinStream {
        session_token: String,
        descriptor: StreamDescriptor,
        #[serde(default = "default_stream_relay_capacity")]
        relay_capacity: u16,
    },
    WriteStream {
        session_token: String,
        stream_id: String,
        data_base64: String,
    },
    FlushStream {
        session_token: String,
        stream_id: String,
    },
    LeaveStream {
        session_token: String,
        stream_id: String,
    },
    CloseStream {
        session_token: String,
        stream_id: String,
        #[serde(default)]
        reason: Option<String>,
    },
    ListStreams {
        session_token: String,
    },
    SubscribeStreams {
        session_token: String,
    },
    SubmitReputationObservation {
        session_token: String,
        subject_main_dht: String,
        kind: ObservationKind,
        #[serde(default)]
        application_code: Option<u32>,
        #[serde(default)]
        description: Option<String>,
    },
    RetractReputationObservation {
        session_token: String,
        subject_main_dht: String,
        observation_id: u64,
    },
    RequestAppRestriction {
        session_token: String,
        subject_main_dht: String,
        restriction_action: ApiRestrictionAction,
        reason: String,
        #[serde(default)]
        expires_at: Option<u64>,
    },
    RevokeAppDecision {
        session_token: String,
        subject_main_dht: String,
        decision_id: u64,
    },
    GetReputationView {
        session_token: String,
        subject_main_dht: String,
    },
    GetOwnReputationSubmissions {
        session_token: String,
    },
    SaveSessionLog {
        session_token: String,
        path: Option<String>,
    },
}

#[derive(Debug, Clone, Copy)]
enum ApiWorkLane {
    Control,
    Delivery,
}

impl ApiWorkLane {
    fn waiting_stage(self) -> &'static str {
        match self {
            Self::Control => "waiting_for_control_slot",
            Self::Delivery => "waiting_for_delivery_slot",
        }
    }
}

impl ApiRequest {
    /// Stable, non-sensitive operation label used by backlog diagnostics. The
    /// implementation deliberately does not format the request itself because
    /// it may contain session tokens, message payloads, or recovery material.
    fn action_name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::GetApiInfo => "get_api_info",
            Self::GetStatus { .. } => "get_status",
            Self::GetIdentity { .. } => "get_identity",
            Self::BeginAuthentication { .. } => "begin_authentication",
            Self::FinishAuthentication { .. } => "finish_authentication",
            Self::SubscribeEvents { .. } => "subscribe_events",
            Self::SendMessage { .. } => "send_message",
            Self::SendGossip { .. } => "send_gossip",
            Self::PublishGossipObject { .. } => "publish_gossip_object",
            Self::WithdrawGossipObject { .. } => "withdraw_gossip_object",
            Self::SearchGossip { .. } => "search_gossip",
            Self::ListGossip { .. } => "list_gossip",
            Self::ConfirmGossipObject { .. } => "confirm_gossip_object",
            Self::GetGossipStats { .. } => "get_gossip_stats",
            Self::SubscribeGossip { .. } => "subscribe_gossip",
            Self::ObserveLexical { .. } => "observe_lexical",
            Self::WithdrawLexicalObject { .. } => "withdraw_lexical_object",
            Self::SearchLexical { .. } => "search_lexical",
            Self::CompareLexicalTerms { .. } => "compare_lexical_terms",
            Self::GetLexicalAssociation { .. } => "get_lexical_association",
            Self::GetLexicalStats { .. } => "get_lexical_stats",
            Self::TriggerMessageRetrieval { .. } => "trigger_message_retrieval",
            Self::GetMailboxStatus { .. } => "get_mailbox_status",
            Self::PublishServiceRequest { .. } => "publish_service_request",
            Self::WithdrawServiceRequest { .. } => "withdraw_service_request",
            Self::SubscribeServiceRequests { .. } => "subscribe_service_requests",
            Self::SendServiceReply { .. } => "send_service_reply",
            Self::ListKnownNodes { .. } => "list_known_nodes",
            Self::ListAppPeers { .. } => "list_app_peers",
            Self::RegisterAppRoot { .. } => "register_app_root",
            Self::ClearAppRoot { .. } => "clear_app_root",
            Self::GetAppRoot { .. } => "get_app_root",
            Self::RecommendNodes { .. } => "recommend_nodes",
            Self::SetAppActivity { .. } => "set_app_activity",
            Self::GetOperationBacklog { .. } => "get_operation_backlog",
            Self::ListInbox { .. } => "list_inbox",
            Self::ReadInbox { .. } => "read_inbox",
            Self::DeleteInbox { .. } => "delete_inbox",
            Self::SubscribeMessages { .. } => "subscribe_messages",
            Self::RequestAppRegistration { .. } => "request_app_registration",
            Self::GetAppRegistrationStatus { .. } => "get_app_registration_status",
            Self::GetAppSigningIdentity { .. } => "get_app_signing_identity",
            Self::RotateAppSigningKey { .. } => "rotate_app_signing_key",
            Self::SignAppPayload { .. } => "sign_app_payload",
            Self::VerifyAppSignature { .. } => "verify_app_signature",
            Self::ListAppStores { .. } => "list_app_stores",
            Self::CreateAppStore { .. } => "create_app_store",
            Self::ReadAppStore { .. } => "read_app_store",
            Self::WriteAppStore { .. } => "write_app_store",
            Self::ReadPublicStore { .. } => "read_public_store",
            Self::PutPrivateValue { .. } => "put_private_value",
            Self::GetPrivateValue { .. } => "get_private_value",
            Self::ListPrivateValues { .. } => "list_private_values",
            Self::DeletePrivateValue { .. } => "delete_private_value",
            Self::RenewPrivateValue { .. } => "renew_private_value",
            Self::BeginPrivateBlob { .. } => "begin_private_blob",
            Self::AppendPrivateBlob { .. } => "append_private_blob",
            Self::FinishPrivateBlob { .. } => "finish_private_blob",
            Self::AbortPrivateBlob { .. } => "abort_private_blob",
            Self::ListPrivateBlobs { .. } => "list_private_blobs",
            Self::DeletePrivateBlob { .. } => "delete_private_blob",
            Self::ReadPrivateBlobRange { .. } => "read_private_blob_range",
            Self::RenewPrivateBlob { .. } => "renew_private_blob",
            Self::GetPrivateStorageUsage { .. } => "get_private_storage_usage",
            Self::BeginBlobUpload { .. } => "begin_blob_upload",
            Self::AppendBlobUpload { .. } => "append_blob_upload",
            Self::FinishBlobUpload { .. } => "finish_blob_upload",
            Self::AbortBlobUpload { .. } => "abort_blob_upload",
            Self::ListBlobs { .. } => "list_blobs",
            Self::DeleteBlob { .. } => "delete_blob",
            Self::ReadBlobRange { .. } => "read_blob_range",
            Self::StartStream { .. } => "start_stream",
            Self::JoinStream { .. } => "join_stream",
            Self::WriteStream { .. } => "write_stream",
            Self::FlushStream { .. } => "flush_stream",
            Self::LeaveStream { .. } => "leave_stream",
            Self::CloseStream { .. } => "close_stream",
            Self::ListStreams { .. } => "list_streams",
            Self::SubscribeStreams { .. } => "subscribe_streams",
            Self::SubmitReputationObservation { .. } => "submit_reputation_observation",
            Self::RetractReputationObservation { .. } => "retract_reputation_observation",
            Self::RequestAppRestriction { .. } => "request_app_restriction",
            Self::RevokeAppDecision { .. } => "revoke_app_decision",
            Self::GetReputationView { .. } => "get_reputation_view",
            Self::GetOwnReputationSubmissions { .. } => "get_own_reputation_submissions",
            Self::SaveSessionLog { .. } => "save_session_log",
            Self::GetNetworkDiagnostics { .. } => "get_network_diagnostics",
            Self::StartDiagnosticWalk { .. } => "start_diagnostic_walk",
            Self::PostMailboxProbe { .. } => "post_mailbox_probe",
            Self::GetMailboxProbeStatus { .. } => "get_mailbox_probe_status",
            Self::ListMailboxProbeReports { .. } => "list_mailbox_probe_reports",
        }
    }

    fn work_lane(&self) -> ApiWorkLane {
        if matches!(self,
            Self::SendMessage { .. }
                | Self::SendGossip { .. }
                | Self::PublishGossipObject { .. }
                | Self::WithdrawGossipObject { .. }
                | Self::SearchGossip { query_network: true, .. }
                | Self::ObserveLexical { .. }
                | Self::WithdrawLexicalObject { .. }
                | Self::SearchLexical { query_network: true, .. }
                | Self::PublishServiceRequest { .. }
                | Self::SendServiceReply { .. }
                | Self::AppendBlobUpload { .. }
                | Self::FinishBlobUpload { .. }
                | Self::StartStream { .. }
                | Self::WriteStream { .. }
                | Self::FlushStream { .. }
        ) {
            ApiWorkLane::Delivery
        } else {
            ApiWorkLane::Control
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ApiStoreWrite {
    pub location: u32,
    pub value_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiGossipFingerprintInput {
    pub channel: String,
    pub algorithm: String,
    pub version: u16,
    pub bytes_base64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiGossipIndexTermsInput {
    /// Application-chosen token family such as `tags`, `language`, or `capability`.
    pub index: String,
    /// Clear text exists only on the local IPC boundary. The daemon normalizes
    /// and hashes these terms before cache storage or network transmission.
    pub terms: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiGossipPublishObject {
    pub namespace: String,
    pub object_id: String,
    pub generation: u64,
    #[serde(default)]
    pub authoritative_pointer: Option<String>,
    #[serde(default)]
    pub fingerprints: Vec<ApiGossipFingerprintInput>,
    /// Optional exact-search terms. Raw terms are never copied into the gossip record.
    #[serde(default)]
    pub indexes: Vec<ApiGossipIndexTermsInput>,
    #[serde(default)]
    pub custom_payload_base64: String,
    #[serde(default)]
    pub flags: u32,
    #[serde(default = "default_gossip_ttl_secs")]
    pub ttl_seconds: u64,
}

fn default_gossip_ttl_secs() -> u64 {
    GOSSIP_DEFAULT_TTL_SECS
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiGossipFingerprintProbe {
    pub channel: String,
    pub algorithm: String,
    pub version: u16,
    pub bytes_base64: String,
    #[serde(default = "default_gossip_probe_weight")]
    pub weight: u16,
    #[serde(default = "default_gossip_probe_polarity")]
    pub polarity: GossipProbePolarity,
}

fn default_gossip_probe_weight() -> u16 {
    100
}

fn default_gossip_probe_polarity() -> GossipProbePolarity {
    GossipProbePolarity::Similar
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiGossipTokenProbeInput {
    pub index: String,
    pub terms: Vec<String>,
    #[serde(default = "default_gossip_token_polarity")]
    pub polarity: GossipTokenPolarity,
    #[serde(default = "default_gossip_token_match_mode")]
    pub match_mode: GossipTokenMatchMode,
    #[serde(default = "default_gossip_probe_weight")]
    pub weight: u16,
}

fn default_gossip_token_polarity() -> GossipTokenPolarity {
    GossipTokenPolarity::Required
}

fn default_gossip_token_match_mode() -> GossipTokenMatchMode {
    GossipTokenMatchMode::All
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiGossipSearchQuery {
    pub namespace: String,
    #[serde(default)]
    pub probes: Vec<ApiGossipFingerprintProbe>,
    #[serde(default)]
    pub token_probes: Vec<ApiGossipTokenProbeInput>,
    #[serde(default = "default_gossip_result_limit")]
    pub limit: usize,
    #[serde(default)]
    pub min_score_milli: Option<u16>,
    #[serde(default)]
    pub include_withdrawn: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiGossipFingerprint {
    pub channel: String,
    pub algorithm: String,
    pub version: u16,
    pub bytes_base64: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiGossipRecord {
    pub namespace: String,
    pub object_id: String,
    pub generation: u64,
    pub origin_main_dht: String,
    pub published_at: u64,
    pub expires_at: u64,
    pub authoritative_pointer: Option<String>,
    pub fingerprints: Vec<ApiGossipFingerprint>,
    /// Opaque 128-bit digests only; original terms are intentionally not returned.
    pub index_tokens_hex: Vec<String>,
    pub custom_payload_base64: String,
    pub flags: u32,
    pub withdrawn: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiGossipSearchHit {
    pub record: ApiGossipRecord,
    pub score: f32,
    pub matched_index_tokens: usize,
    pub verification: GossipVerificationState,
    pub claimed_source_count: usize,
    pub conflicting_claim_count: usize,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub last_verified_at: Option<u64>,
    pub last_verified_generation: Option<u64>,
}

impl From<GossipRecord> for ApiGossipRecord {
    fn from(record: GossipRecord) -> Self {
        Self {
            namespace: record.namespace,
            object_id: record.object_id,
            generation: record.generation,
            origin_main_dht: record.origin_main_dht,
            published_at: record.published_at,
            expires_at: record.expires_at,
            authoritative_pointer: record.authoritative_pointer,
            fingerprints: record
                .fingerprints
                .into_iter()
                .map(|fingerprint| ApiGossipFingerprint {
                    channel: fingerprint.channel,
                    algorithm: fingerprint.algorithm,
                    version: fingerprint.version,
                    bytes_base64: BASE64.encode(fingerprint.bytes),
                })
                .collect(),
            index_tokens_hex: record
                .index_tokens
                .into_iter()
                .map(|token| hex::encode(token.digest))
                .collect(),
            custom_payload_base64: BASE64.encode(record.custom_payload),
            flags: record.flags,
            withdrawn: record.withdrawn,
        }
    }
}

impl From<GossipSearchHit> for ApiGossipSearchHit {
    fn from(hit: GossipSearchHit) -> Self {
        Self {
            record: hit.record.into(),
            score: hit.score,
            matched_index_tokens: hit.matched_index_tokens,
            verification: hit.verification,
            claimed_source_count: hit.claimed_source_count,
            conflicting_claim_count: hit.conflicting_claim_count,
            first_seen_at: hit.first_seen_at,
            last_seen_at: hit.last_seen_at,
            last_verified_at: hit.last_verified_at,
            last_verified_generation: hit.last_verified_generation,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ApiGossipEventMessage {
    pub protocol_version: u16,
    pub stream: &'static str,
    pub event: GossipEvent,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiRestrictionAction {
    Restrict,
    Ban,
}

#[derive(Debug, Serialize)]
pub struct ApiResponseEnvelope<T: Serialize> {
    pub protocol_version: u16,
    pub request_id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiErrorBody>,
}

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiCustodianObservation {
    pub custodian_main_dht: String,
    pub custodian_mailbox_dht: String,
    pub mailbox_generation: u64,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub trust_weight: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiMailboxObservationReport {
    pub message_id_hex: String,
    pub posted_at: u64,
    pub observations: Vec<ApiCustodianObservation>,
    pub raw_recent_custodian_count: u32,
    pub trust_weighted_recent_count: f32,
    pub first_observation_at: Option<u64>,
    pub last_observation_at: Option<u64>,
    pub last_walk_coverage_estimate: f32,
    pub replication_health_score: f32,
}

impl From<OutgoingMessageObservationReport> for ApiMailboxObservationReport {
    fn from(report: OutgoingMessageObservationReport) -> Self {
        let first_observation_at = report
            .observations
            .iter()
            .map(|observation| observation.first_seen_at)
            .min();
        Self {
            message_id_hex: hex::encode(report.message_id),
            posted_at: report.posted_at,
            observations: report
                .observations
                .into_iter()
                .map(ApiCustodianObservation::from)
                .collect(),
            raw_recent_custodian_count: report.raw_recent_custodian_count,
            trust_weighted_recent_count: report.trust_weighted_recent_count,
            first_observation_at,
            last_observation_at: report.last_observation_at,
            last_walk_coverage_estimate: report.last_walk_coverage_estimate,
            replication_health_score: report.replication_health_score,
        }
    }
}

impl From<CustodianMessageObservation> for ApiCustodianObservation {
    fn from(observation: CustodianMessageObservation) -> Self {
        Self {
            custodian_main_dht: observation.custodian_main_dht.to_string(),
            custodian_mailbox_dht: observation.custodian_mailbox_dht.to_string(),
            mailbox_generation: observation.mailbox_generation,
            first_seen_at: observation.first_seen_at,
            last_seen_at: observation.last_seen_at,
            trust_weight: observation.trust_weight,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApiResult {
    Pong,
    ApiInfo {
        protocol_version: u16,
        authentication_proof: &'static str,
        features: Vec<&'static str>,
        max_message_bytes: usize,
        max_store_value_bytes: usize,
        max_store_subkeys: u16,
        max_stores_per_app: usize,
        max_store_reads_per_request: usize,
        max_store_writes_per_request: usize,
        max_store_write_bytes_per_request: usize,
        max_signature_payload_bytes: usize,
        max_signature_domain_bytes: usize,
        max_blob_append_bytes: usize,
        max_blob_bytes: u64,
        max_private_value_bytes: usize,
        max_private_blob_append_bytes: usize,
        max_private_blob_read_bytes: u64,
        max_private_blob_bytes: u64,
        private_ephemeral_ttl_min_seconds: u64,
        private_ephemeral_ttl_max_seconds: u64,
        private_cache_limit_bytes: u64,
        max_stream_write_bytes: usize,
        stream_packet_bytes: usize,
        max_gossip_custom_payload_bytes: usize,
        max_gossip_fingerprints: usize,
        max_gossip_fingerprint_bytes: usize,
        max_gossip_index_tokens: usize,
        max_gossip_index_term_bytes: usize,
        max_gossip_index_probe_groups: usize,
        max_gossip_query_results: usize,
        max_gossip_ttl_seconds: u64,
        max_lexical_text_bytes: usize,
        max_lexical_pretokenized_terms: usize,
        max_lexical_search_terms: usize,
        lexical_default_window_days: u16,
    },
    Status {
        status: NetworkStatus,
    },
    Identity {
        /// Deprecated compatibility name. It now contains the app-scoped
        /// visible alias rather than the account login name.
        username: String,
        display_name: String,
        profile_id: String,
        main_dht: String,
    },
    AuthenticationChallenge {
        app_id: String,
        challenge_id: u64,
        nonce_hex: String,
        issued_at: u64,
        expires_at: u64,
        credential_generation: u64,
        requested_capabilities: Vec<AppCapability>,
    },
    AuthenticationSucceeded {
        app_id: String,
        session_id: String,
        session_token_hex: String,
        authenticated_at: u64,
        expires_at: u64,
        capabilities: Vec<AppCapability>,
    },
    EventSubscriptionStarted,
    ApplicationMessageSubscriptionStarted {
        app_id: String,
    },
    MessageQueued {
        message_id_hex: String,
    },
    ServiceRequestPublished {
        request_id_hex: String,
        expires_at: u64,
    },
    ServiceRequestWithdrawn {
        request_id_hex: String,
    },
    ServiceRequestSubscriptionStarted {
        service_ids_hex: Vec<String>,
    },
    ServiceReplySent {
        request_id_hex: String,
        message_id_hex: String,
    },
    MessageRetrievalScheduled,
    MailboxStatus {
        mailbox_dht: Option<String>,
        mail_send_dht: Option<String>,
        mail_response_dht: String,
        receive_key_epoch: u64,
        pending_page_sets: usize,
        outgoing_message_count: usize,
        outgoing_service_request_count: usize,
        recent_service_request_count: usize,
        awaiting_response_count: usize,
        stored_inbox_count: usize,
        unread_inbox_count: usize,
        known_custodian_count: usize,
    },
    NetworkDiagnostics {
        sampled_at: u64,
        discovered_total: usize,
        verified_nodes: usize,
        candidate_nodes: usize,
        authenticated_nodes: usize,
        online_nodes: usize,
        offline_or_stale_nodes: usize,
        seen_within_hour: usize,
        seen_within_day: usize,
        latest_walk_snapshot_count: usize,
        known_custodian_count: usize,
    },
    DiagnosticWalkStarted {
        requested_hops: usize,
        already_running: bool,
    },
    MailboxProbeQueued {
        message_id_hex: String,
        posted_at: u64,
    },
    MailboxProbeStatus {
        report: Option<ApiMailboxObservationReport>,
    },
    MailboxProbeReports {
        reports: Vec<ApiMailboxObservationReport>,
    },
    KnownNodes {
        sampled_at: u64,
        nodes: Vec<ApiKnownNode>,
    },
    AppPeers {
        app_id: String,
        sampled_at: u64,
        cache_generation: u64,
        total_cached: usize,
        peers: Vec<ApiAppPeer>,
        search_state: String,
    },
    AppRootRegistered {
        app_id: String,
        root_dht: String,
        directory_dht: String,
        generation: u64,
        updated_at: u64,
    },
    AppRootCleared {
        app_id: String,
        directory_dht: String,
        generation: u64,
        updated_at: u64,
    },
    AppRoot {
        app_id: String,
        peer_main_dht: String,
        root_dht: Option<String>,
        status: String,
        checked_at: u64,
        directory_generation: u64,
    },
    NodesRecommended {
        submitted: usize,
        new_candidates: usize,
        already_known: usize,
        expires_at: u64,
    },
    AppActivityLease {
        level: AppActivityLevel,
        expires_at: u64,
        effective_interval_secs: Option<u64>,
        effective_hops: usize,
        relevant_node_count: usize,
    },
    OperationBacklog {
        sampled_at: u64,
        operations: Vec<ApiBacklogOperation>,
    },
    InboxMessages {
        messages: Vec<ApiInboxSummary>,
    },
    InboxMessage {
        message: ApiInboxMessage,
    },
    InboxMessageDeleted {
        message_id_hex: String,
    },
    AppRegistrationPending {
        request_id: u64,
        app_id: String,
        display_name: String,
        requested_at: u64,
        expires_at: u64,
    },
    AppRegistrationStillPending {
        request_id: u64,
    },
    AppRegistrationApproved {
        protocol_version: u16,
        endpoint: String,
        app_id: String,
        display_name: String,
        secret_hex: String,
        credential_generation: u64,
    },
    AppRegistrationRejected {
        request_id: u64,
        reason: String,
    },
    AppRegistrationExpired {
        request_id: u64,
    },
    AppSigningIdentity {
        identity: AppSigningIdentity,
    },
    AppPayloadSigned {
        signature: AppSignatureResult,
    },
    AppSignatureVerified {
        valid: bool,
    },
    AppStores {
        stores: Vec<AppStoreDescriptor>,
    },
    AppStoreCreated {
        store: AppStoreDescriptor,
    },
    AppStoreRead {
        store: AppStoreDescriptor,
        values: Vec<AppStoreReadValue>,
    },
    AppStoreWritten {
        store: AppStoreDescriptor,
    },
    PublicStoreRead {
        record_key: String,
        values: Vec<AppStoreReadValue>,
    },
    PrivateValueStored { value: PrivateValueDescriptor },
    PrivateValueRead { value: PrivateValueDescriptor, value_base64: String },
    PrivateValueMissing { key: String },
    PrivateValues { values: Vec<PrivateValueDescriptor> },
    PrivateValueDeleted { key: String, deleted: bool },
    PrivateValueRenewed { value: PrivateValueDescriptor },
    PrivateBlobStarted { blob: PrivateBlobDescriptor },
    PrivateBlobAppended { blob: PrivateBlobDescriptor },
    PrivateBlobFinished { blob: PrivateBlobDescriptor },
    PrivateBlobAborted { blob_id: String, aborted: bool },
    PrivateBlobs { blobs: Vec<PrivateBlobDescriptor> },
    PrivateBlobDeleted { blob_id: String, deleted: bool },
    PrivateBlobRangeRead { blob: PrivateBlobDescriptor, offset: u64, data_base64: String },
    PrivateBlobRenewed { blob: PrivateBlobDescriptor },
    PrivateStorageUsage { usage: PrivateStorageUsage },
    BlobUploadStarted { upload: BlobUploadStatus },
    BlobUploadAppended { upload: BlobUploadStatus },
    BlobUploadFinished { blob: BlobDescriptor },
    BlobUploadAborted { upload_id: String },
    Blobs { blobs: Vec<BlobDescriptor> },
    BlobDeleted { blob_id: String },
    BlobRangeRead {
        blob: BlobDescriptor,
        offset: u64,
        data_base64: String,
    },
    GossipPublished {
        hit: ApiGossipSearchHit,
    },
    GossipWithdrawn {
        hit: ApiGossipSearchHit,
    },
    GossipSearchResults {
        query_id_hex: String,
        network_peers_contacted: usize,
        hits: Vec<ApiGossipSearchHit>,
    },
    GossipObjects {
        hits: Vec<ApiGossipSearchHit>,
    },
    GossipConfirmed {
        hit: ApiGossipSearchHit,
    },
    GossipStats {
        stats: GossipAppStats,
    },
    GossipSubscriptionStarted {
        app_id: String,
    },
    LexicalObserved { result: LexicalObserveResult },
    LexicalObjectWithdrawn { object_id: String },
    LexicalSearchResults { result: LexicalSearchResult },
    LexicalTermComparison { similarity: WordSimilarity },
    LexicalAssociation { metrics: AssociationMetrics },
    LexicalStats { stats: LexicalLibraryStats },
    StreamStarted {
        descriptor: StreamDescriptor,
    },
    StreamJoinPending {
        stream_id: String,
    },
    StreamWriteAccepted {
        result: StreamWriteResult,
    },
    StreamFlushed {
        commitment: Option<StreamSegmentCommitment>,
    },
    StreamLeft {
        stream_id: String,
    },
    StreamClosed {
        stream_id: String,
    },
    Streams {
        streams: Vec<StreamSummary>,
    },
    StreamSubscriptionStarted {
        app_id: String,
    },
    ReputationObservationSubmitted {
        observation_id: u64,
    },
    ReputationObservationRetracted,
    AppRestrictionRequested {
        decision_id: u64,
    },
    AppDecisionRevoked,
    ReputationView {
        view: ReputationView,
    },
    OwnReputationSubmissions {
        report: AppSourceReport,
    },
    SessionLogSaved {
        path: String,
        lines: usize,
    },
}

#[derive(Debug, Serialize)]
pub struct ApiNetworkEventMessage {
    pub protocol_version: u16,
    pub stream: &'static str,
    pub event: NetworkEventEnvelope,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiApplicationMessage {
    pub application_id: String,
    pub message_id_hex: String,
    pub sender_main_dht: String,
    pub recipient_main_dht: String,
    pub posted_at: u64,
    pub expires_at: u64,
    /// `mailbox`, `direct`, or `gossip`. Gossip is deliberately unverified.
    pub delivery_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id_hex: Option<String>,
    pub payload_base64: String,
}


#[derive(Debug, Clone, Serialize)]
pub struct ApiKnownNode {
    pub main_dht: String,
    pub verified: bool,
    pub verification_state: String,
    pub presence_state: String,
    pub last_seen: u64,
    pub last_online: u64,
    pub mailbox_capable: bool,
    pub application_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiAppPeer {
    pub main_dht: String,
    pub first_discovered_at: u64,
    pub last_directly_verified_at: u64,
    pub last_returned_at: u64,
    pub return_count: u32,
    pub tier: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_root_dht: Option<String>,
    pub app_root_checked_at: u64,
    pub app_directory_generation: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiBacklogOperation {
    pub operation_id: u64,
    pub request_id: u64,
    pub action: String,
    pub queued_for_secs: u64,
    pub running_for_secs: Option<u64>,
    pub stage: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiInboxSummary {
    pub message_id_hex: String,
    pub sender_main_dht: String,
    pub posted_at: u64,
    pub received_at: u64,
    pub plaintext_len: usize,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiInboxMessage {
    pub message_id_hex: String,
    pub sender_main_dht: String,
    pub recipient_main_dht: String,
    pub posted_at: u64,
    pub received_at: u64,
    pub expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id_hex: Option<String>,
    pub payload_base64: String,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiServiceRequest {
    pub request_id_hex: String,
    pub requester_main_dht: String,
    pub intended_host_main_dht: String,
    pub service_id_hex: String,
    pub service_manifest_hash_hex: String,
    pub instance_id_hex: String,
    pub reply_route_blob_base64: String,
    pub payload_base64: String,
    pub delegation_allowed: bool,
    pub spectators_allowed: bool,
    pub posted_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Serialize)]
pub struct ApiServiceRequestEventMessage {
    pub protocol_version: u16,
    pub stream: &'static str,
    pub event: ApiServiceRequest,
}

fn api_service_request(request: &ServiceRequest) -> ApiServiceRequest {
    ApiServiceRequest {
        request_id_hex: hex::encode(request.request_id),
        requester_main_dht: request.requester_main_dht.to_string(),
        intended_host_main_dht: request.intended_host_main_dht.to_string(),
        service_id_hex: hex::encode(request.service_id),
        service_manifest_hash_hex: hex::encode(request.service_manifest_hash),
        instance_id_hex: hex::encode(request.instance_id),
        reply_route_blob_base64: BASE64.encode(&request.reply_route_blob),
        payload_base64: BASE64.encode(&request.public_payload),
        delegation_allowed: request.delegation_allowed,
        spectators_allowed: request.spectators_allowed,
        posted_at: request.posted_at,
        expires_at: request.expires_at,
    }
}

fn service_request_visible_to_local_node(
    request: &ServiceRequest,
    service_ids: &HashSet<[u8; 32]>,
    own_main_dht: &str,
) -> bool {
    service_ids.contains(&request.service_id)
        && (request.delegation_allowed
            || request.intended_host_main_dht.to_string() == own_main_dht)
        && request.expires_at > crate::types::current_timestamp()
}

const SERVICE_REPLY_PREFIX: &[u8] = b"veilknit-service-reply-v1\0";

fn encode_service_reply_payload(request_id: [u8; 32], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SERVICE_REPLY_PREFIX.len() + 32 + payload.len());
    out.extend_from_slice(SERVICE_REPLY_PREFIX);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(payload);
    out
}

fn decode_service_reply_payload(payload: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    if payload.len() < SERVICE_REPLY_PREFIX.len() + 32
        || !payload.starts_with(SERVICE_REPLY_PREFIX)
    {
        return None;
    }
    let mut request_id = [0u8; 32];
    request_id.copy_from_slice(
        &payload[SERVICE_REPLY_PREFIX.len()..SERVICE_REPLY_PREFIX.len() + 32],
    );
    Some((
        request_id,
        payload[SERVICE_REPLY_PREFIX.len() + 32..].to_vec(),
    ))
}

#[derive(Debug, Serialize)]
pub struct ApiApplicationEventMessage {
    pub protocol_version: u16,
    pub stream: &'static str,
    pub event: ApiApplicationMessage,
}

#[derive(Debug, Serialize)]
pub struct ApiStreamEventMessage {
    pub protocol_version: u16,
    pub stream: &'static str,
    pub event: StreamEvent,
}

#[derive(Default)]
struct AppMessageHubState {
    queues: HashMap<String, VecDeque<ApiApplicationMessage>>,
    arrival_order: VecDeque<(String, String)>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    pending_count: usize,
}

struct AppMessageHub {
    state: Mutex<AppMessageHubState>,
    events: tokio::sync::broadcast::Sender<ApiApplicationMessage>,
}

/// Application names are exact network identifiers. Callers may include a
/// protocol generation in the name itself, for example
/// `veilknit.veilyshort.v1`. No legacy numeric or platform aliasing remains.
fn canonical_application_id(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

impl AppMessageHub {
    fn new() -> Self {
        let (events, _) = tokio::sync::broadcast::channel(1024);
        Self {
            state: Mutex::new(AppMessageHubState::default()),
            events,
        }
    }

    async fn publish(&self, mut message: ApiApplicationMessage) {
        message.application_id = canonical_application_id(&message.application_id);
        let app_id = message.application_id.clone();
        let key = application_message_key(&message);
        {
            let mut state = self.state.lock().await;
            if !state.seen.insert(key.clone()) {
                return;
            }
            state.seen_order.push_back(key.clone());
            while state.seen_order.len() > MAX_SEEN_APPLICATION_MESSAGES {
                if let Some(expired) = state.seen_order.pop_front() {
                    state.seen.remove(&expired);
                }
            }

            let queue = state.queues.entry(app_id.clone()).or_default();
            queue.push_back(message.clone());
            state.arrival_order.push_back((app_id.clone(), key));
            state.pending_count = state.pending_count.saturating_add(1);

            while state
                .queues
                .get(&app_id)
                .map_or(0, VecDeque::len)
                > MAX_PENDING_APPLICATION_MESSAGES_PER_APP
            {
                if let Some(removed) = state
                    .queues
                    .get_mut(&app_id)
                    .and_then(VecDeque::pop_front)
                {
                    state.pending_count = state.pending_count.saturating_sub(1);
                    let removed_key = application_message_key(&removed);
                    remove_arrival_marker(&mut state.arrival_order, &app_id, &removed_key);
                }
            }

            while state.pending_count > MAX_PENDING_APPLICATION_MESSAGES {
                let Some((old_app, old_key)) = state.arrival_order.pop_front() else {
                    state.pending_count = 0;
                    break;
                };
                let removed = state.queues.get_mut(&old_app).and_then(|queue| {
                    queue
                        .iter()
                        .position(|message| application_message_key(message) == old_key)
                        .and_then(|position| queue.remove(position))
                });
                if removed.is_some() {
                    state.pending_count = state.pending_count.saturating_sub(1);
                }
                if state.queues.get(&old_app).is_some_and(VecDeque::is_empty) {
                    state.queues.remove(&old_app);
                }
            }
        }
        let _ = self.events.send(message);
    }

    async fn subscribe_and_snapshot(
        &self,
        app_id: &str,
    ) -> (
        tokio::sync::broadcast::Receiver<ApiApplicationMessage>,
        Vec<ApiApplicationMessage>,
    ) {
        let app_id = canonical_application_id(app_id);
        let state = self.state.lock().await;
        let receiver = self.events.subscribe();
        let pending = state
            .queues
            .get(&app_id)
            .map(|queue| queue.iter().cloned().collect())
            .unwrap_or_default();
        (receiver, pending)
    }

    async fn acknowledge(&self, app_id: &str, key: &str) {
        let app_id = canonical_application_id(app_id);
        let mut state = self.state.lock().await;
        let removed = state.queues.get_mut(&app_id).and_then(|queue| {
            queue
                .iter()
                .position(|message| application_message_key(message) == key)
                .and_then(|position| queue.remove(position))
        });
        if removed.is_some() {
            state.pending_count = state.pending_count.saturating_sub(1);
            remove_arrival_marker(&mut state.arrival_order, &app_id, key);
        }
        if state.queues.get(&app_id).is_some_and(VecDeque::is_empty) {
            state.queues.remove(&app_id);
        }
    }
}


#[derive(Debug, Clone)]
pub struct PendingAppRegistration {
    pub request_id: u64,
    pub app_id: String,
    pub display_name: String,
    pub requested_capabilities: Vec<AppCapability>,
    pub requested_at: u64,
    pub expires_at: u64,
}

#[derive(Clone)]
enum RegistrationDecision {
    Pending,
    Approved {
        credential: AppCredential,
        decided_at: u64,
    },
    Rejected {
        reason: String,
        decided_at: u64,
    },
}

#[derive(Clone)]
struct RegistrationRequestState {
    summary: PendingAppRegistration,
    request_token: [u8; 32],
    decision: RegistrationDecision,
}

struct AppRegistrationHubState {
    next_request_id: u64,
    requests: HashMap<u64, RegistrationRequestState>,
}

impl Default for AppRegistrationHubState {
    fn default() -> Self {
        Self {
            next_request_id: 1,
            requests: HashMap::new(),
        }
    }
}

#[derive(Clone)]
enum RegistrationStatusSnapshot {
    Pending,
    Approved {
        credential: AppCredential,
        summary: PendingAppRegistration,
    },
    Rejected(String),
    Expired,
}

struct AppRegistrationHub {
    state: Mutex<AppRegistrationHubState>,
}

impl AppRegistrationHub {
    fn new() -> Self {
        Self {
            state: Mutex::new(AppRegistrationHubState::default()),
        }
    }

    async fn request(
        &self,
        app_id: AppId,
        display_name: String,
        requested_capabilities: AppCapabilitySet,
        request_token: [u8; 32],
    ) -> Result<PendingAppRegistration, (&'static str, String)> {
        let display_name = display_name.trim().to_string();
        if display_name.is_empty() || display_name.len() > 256 {
            return Err((
                "invalid_display_name",
                "display name must contain 1 to 256 bytes".to_string(),
            ));
        }
        if !requested_capabilities.is_subset_of(&AppCapabilitySet::standard_app()) {
            return Err((
                "capability_denied",
                "first-run authorization may request only standard application capabilities"
                    .to_string(),
            ));
        }

        let now = current_timestamp();
        let mut state = self.state.lock().await;
        cleanup_registration_requests(&mut state, now);
        let app_id_text = app_id.to_string();

        // Retrying the exact same authorization handshake is idempotent.
        if let Some(existing) = state.requests.values().find(|request| {
            request.summary.app_id == app_id_text
                && request.request_token == request_token
                && matches!(&request.decision, RegistrationDecision::Pending)
        }) {
            return Ok(existing.summary.clone());
        }

        // A new token for the same canonical app supersedes every older
        // pending request. This prevents accidentally approving a stale token
        // and also keeps the GUI to one actionable row per app. The old
        // requester can still poll its request id and receive the rejection.
        for request in state.requests.values_mut() {
            if request.summary.app_id == app_id_text
                && matches!(&request.decision, RegistrationDecision::Pending)
            {
                request.decision = RegistrationDecision::Rejected {
                    reason: "superseded by a newer authorization request for this application"
                        .to_string(),
                    decided_at: now,
                };
            }
        }

        let pending_count = state
            .requests
            .values()
            .filter(|request| matches!(&request.decision, RegistrationDecision::Pending))
            .count();
        if pending_count >= MAX_PENDING_REGISTRATION_REQUESTS {
            return Err((
                "too_many_registration_requests",
                "the daemon has too many pending application authorization requests".to_string(),
            ));
        }

        let request_id = state.next_request_id;
        state.next_request_id = state.next_request_id.saturating_add(1).max(1);
        let summary = PendingAppRegistration {
            request_id,
            app_id: app_id_text,
            display_name,
            requested_capabilities: requested_capabilities.iter().collect(),
            requested_at: now,
            expires_at: now.saturating_add(REGISTRATION_REQUEST_TTL_SECS),
        };
        state.requests.insert(
            request_id,
            RegistrationRequestState {
                summary: summary.clone(),
                request_token,
                decision: RegistrationDecision::Pending,
            },
        );
        Ok(summary)
    }

    async fn pending(&self) -> Vec<PendingAppRegistration> {
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        cleanup_registration_requests(&mut state, now);

        // Defensive de-duplication: even if a future migration or race ever
        // leaves two pending rows for one app, only its newest request is
        // presented as actionable.
        let mut latest: HashMap<String, PendingAppRegistration> = HashMap::new();
        for request in state
            .requests
            .values()
            .filter(|request| matches!(&request.decision, RegistrationDecision::Pending))
        {
            let summary = request.summary.clone();
            match latest.get(&summary.app_id) {
                Some(existing) if existing.request_id >= summary.request_id => {}
                _ => {
                    latest.insert(summary.app_id.clone(), summary);
                }
            }
        }
        let mut requests: Vec<_> = latest.into_values().collect();
        requests.sort_by(|left, right| left.app_id.cmp(&right.app_id));
        requests
    }

    async fn approve(
        &self,
        request_id: u64,
        identities: &IdentityManager,
    ) -> Result<(PendingAppRegistration, AppCredential), String> {
        let request = {
            let now = current_timestamp();
            let mut state = self.state.lock().await;
            cleanup_registration_requests(&mut state, now);
            let request = state
                .requests
                .get(&request_id)
                .ok_or_else(|| format!("registration request {request_id} was not found"))?;
            if !matches!(&request.decision, RegistrationDecision::Pending) {
                return Err(format!("registration request {request_id} is no longer pending"));
            }
            request.summary.clone()
        };

        let app_id = AppId::new(request.app_id.clone()).map_err(|error| error.to_string())?;
        let capabilities = AppCapabilitySet::new(request.requested_capabilities.iter().copied());
        let credential = identities
            .register_app_with_capabilities(app_id, request.display_name.clone(), capabilities)
            .await
            .map_err(|error| error.to_string())?;

        let mut state = self.state.lock().await;
        let stored = state
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| format!("registration request {request_id} expired during approval"))?;
        stored.decision = RegistrationDecision::Approved {
            credential: credential.clone(),
            decided_at: current_timestamp(),
        };
        Ok((request, credential))
    }

    async fn reject(&self, request_id: u64, reason: String) -> Result<(), String> {
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        cleanup_registration_requests(&mut state, now);
        let stored = state
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| format!("registration request {request_id} was not found"))?;
        if !matches!(&stored.decision, RegistrationDecision::Pending) {
            return Err(format!("registration request {request_id} is no longer pending"));
        }
        stored.decision = RegistrationDecision::Rejected {
            reason: if reason.trim().is_empty() {
                "rejected by the local user".to_string()
            } else {
                reason.trim().to_string()
            },
            decided_at: now,
        };
        Ok(())
    }

    async fn status(
        &self,
        request_id: u64,
        request_token: &[u8; 32],
    ) -> Result<RegistrationStatusSnapshot, (&'static str, String)> {
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        cleanup_registration_requests(&mut state, now);
        let Some(request) = state.requests.get(&request_id) else {
            return Ok(RegistrationStatusSnapshot::Expired);
        };
        if !constant_time_token_eq(&request.request_token, request_token) {
            return Err((
                "registration_token_mismatch",
                "the authorization request token is invalid".to_string(),
            ));
        }
        Ok(match &request.decision {
            RegistrationDecision::Pending => RegistrationStatusSnapshot::Pending,
            RegistrationDecision::Approved { credential, .. } => {
                RegistrationStatusSnapshot::Approved {
                    credential: credential.clone(),
                    summary: request.summary.clone(),
                }
            }
            RegistrationDecision::Rejected { reason, .. } => {
                RegistrationStatusSnapshot::Rejected(reason.clone())
            }
        })
    }
}

fn cleanup_registration_requests(state: &mut AppRegistrationHubState, now: u64) {
    state.requests.retain(|_, request| match &request.decision {
        RegistrationDecision::Pending => request.summary.expires_at > now,
        RegistrationDecision::Approved { decided_at, .. }
        | RegistrationDecision::Rejected { decided_at, .. } => {
            decided_at.saturating_add(REGISTRATION_RESULT_TTL_SECS) > now
        }
    });
}

fn constant_time_token_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[derive(Debug, Clone)]
struct BacklogEntry {
    operation_id: u64,
    request_id: u64,
    action: String,
    queued_at: u64,
    started_at: Option<u64>,
    stage: String,
}

#[derive(Default)]
struct BacklogState {
    next_id: u64,
    entries: HashMap<u64, BacklogEntry>,
    warning_active: bool,
    last_warning_at: u64,
}

#[derive(Clone, Default)]
struct OperationBacklog {
    state: Arc<Mutex<BacklogState>>,
}

impl OperationBacklog {
    async fn queued(&self, request_id: u64, action: &str) -> u64 {
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        state.next_id = state.next_id.saturating_add(1).max(1);
        let operation_id = state.next_id;
        state.entries.insert(operation_id, BacklogEntry {
            operation_id,
            request_id,
            action: action.to_string(),
            queued_at: now,
            started_at: None,
            stage: "waiting_for_api_slot".to_string(),
        });
        operation_id
    }

    async fn started(&self, operation_id: u64) {
        let now = current_timestamp();
        if let Some(entry) = self.state.lock().await.entries.get_mut(&operation_id) {
            entry.started_at = Some(now);
            entry.stage = "processing".to_string();
        }
    }

    async fn stage(&self, operation_id: u64, stage: impl Into<String>) {
        if let Some(entry) = self.state.lock().await.entries.get_mut(&operation_id) {
            entry.stage = stage.into();
        }
    }

    async fn finished(&self, operation_id: u64) {
        self.state.lock().await.entries.remove(&operation_id);
    }

    async fn snapshot(&self) -> Vec<ApiBacklogOperation> {
        let now = current_timestamp();
        let state = self.state.lock().await;
        let mut operations: Vec<_> = state.entries.values().map(|entry| ApiBacklogOperation {
            operation_id: entry.operation_id,
            request_id: entry.request_id,
            action: entry.action.clone(),
            queued_for_secs: now.saturating_sub(entry.queued_at),
            running_for_secs: entry.started_at.map(|started| now.saturating_sub(started)),
            stage: entry.stage.clone(),
        }).collect();
        operations.sort_by(|left, right| right.queued_for_secs.cmp(&left.queued_for_secs));
        operations
    }
}

async fn run_backlog_watchdog(
    backlog: OperationBacklog,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(15));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = ticker.tick() => {
                let now = current_timestamp();
                let snapshot = backlog.snapshot().await;
                let oldest = snapshot.first().map(|entry| entry.queued_for_secs).unwrap_or(0);
                let mut state = backlog.state.lock().await;
                if oldest >= BACKLOG_WARNING_AFTER_SECS {
                    let should_log = !state.warning_active
                        || now.saturating_sub(state.last_warning_at) >= BACKLOG_REPEAT_SECS;
                    if should_log {
                        state.warning_active = true;
                        state.last_warning_at = now;
                        drop(state);
                        crate::teprintln!(
                            "[backlog] Local API backlog remains uncleared: {} operation(s), oldest={}s",
                            snapshot.len(),
                            oldest
                        );
                        for operation in snapshot.iter().take(MAX_BACKLOG_LOG_ENTRIES) {
                            crate::teprintln!(
                                "[backlog] op={} request={} action={} queued={}s running={:?} stage={}",
                                operation.operation_id,
                                operation.request_id,
                                operation.action,
                                operation.queued_for_secs,
                                operation.running_for_secs,
                                operation.stage,
                            );
                        }
                    }
                } else if state.warning_active {
                    state.warning_active = false;
                    state.last_warning_at = now;
                    drop(state);
                    crate::tprintln!("[backlog] Local API backlog cleared.");
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct AppActivityLease {
    app_id: String,
    level: AppActivityLevel,
    expires_at: u64,
    next_due_at: u64,
    relevant_nodes: Vec<RecordKey>,
}

#[derive(Clone)]
struct AppActivityHub {
    walker: Option<WalkTask>,
    leases: Arc<Mutex<HashMap<String, AppActivityLease>>>,
    // Kept separately from leases so toggling inactive/realtime cannot reset
    // the daemon-enforced cooldown and turn the API into a "walk now" loop.
    last_started_at: Arc<Mutex<HashMap<String, u64>>>,
}

impl AppActivityHub {
    fn new(walker: Option<WalkTask>) -> Self {
        Self {
            walker,
            leases: Arc::new(Mutex::new(HashMap::new())),
            last_started_at: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn set_lease(
        &self,
        app_id: String,
        level: AppActivityLevel,
        relevant_nodes: Vec<RecordKey>,
        lease_seconds: u64,
    ) -> (u64, usize) {
        let now = current_timestamp();
        let mut leases = self.leases.lock().await;
        if level == AppActivityLevel::Inactive {
            leases.remove(&app_id);
            return (now, 0);
        }
        let expires_at = now.saturating_add(
            lease_seconds.clamp(APP_ACTIVITY_MIN_LEASE_SECS, APP_ACTIVITY_MAX_LEASE_SECS),
        );
        let relevant_count = relevant_nodes.len();
        let previous_due = leases.get(&app_id).map(|lease| lease.next_due_at);
        let last_started = self
            .last_started_at
            .lock()
            .await
            .get(&app_id)
            .copied();
        let daemon_cooldown = last_started
            .map(|started| started.saturating_add(level.interval_secs()))
            .unwrap_or(now);
        leases.insert(app_id.clone(), AppActivityLease {
            app_id,
            level,
            expires_at,
            // Renewals extend the lease and update its targets, but cannot pull
            // the next run earlier than the existing schedule/cooldown.
            next_due_at: previous_due.unwrap_or(daemon_cooldown).max(daemon_cooldown),
            relevant_nodes,
        });
        (expires_at, relevant_count)
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = ticker.tick() => {
                    let Some(walker) = &self.walker else { continue; };
                    let now = current_timestamp();
                    let due = {
                        let mut leases = self.leases.lock().await;
                        leases.retain(|_, lease| lease.expires_at > now);
                        let due: Vec<_> = leases
                            .values()
                            .filter(|lease| lease.next_due_at <= now)
                            .cloned()
                            .collect();
                        for selected in &due {
                            if let Some(stored) = leases.get_mut(&selected.app_id) {
                                stored.next_due_at = now.saturating_add(selected.level.interval_secs());
                            }
                        }
                        due
                    };
                    if due.is_empty() { continue; }
                    if matches!(walker.current_walk_status().await, Some(WalkStatus::Running { .. })) {
                        continue;
                    }

                    // All currently due apps share one bounded walk. This keeps
                    // battery/network cost bounded when several apps are open.
                    let level = due.iter().map(|lease| lease.level).max_by_key(|level| match level {
                        AppActivityLevel::Inactive => 0,
                        AppActivityLevel::Background => 1,
                        AppActivityLevel::Interactive => 2,
                        AppActivityLevel::Realtime => 3,
                    }).unwrap_or(AppActivityLevel::Background);
                    let mut app_ids = Vec::new();
                    let mut relevant_by_text = HashMap::<String, RecordKey>::new();
                    for lease in &due {
                        app_ids.push(lease.app_id.clone());
                        for node in walker.active_app_nodes(&lease.app_id).await
                            .into_iter().chain(lease.relevant_nodes.clone())
                        {
                            relevant_by_text.insert(node.to_string(), node);
                        }
                    }
                    let relevant: Vec<_> = relevant_by_text.into_values().collect();
                    if relevant.is_empty() { continue; }
                    let config = WalkConfig::focused(level.hop_count(), relevant)
                        .with_event_reason(format!("app-focused activity for {}", app_ids.join(",")));
                    match walker.start_walk(config).await {
                        Ok(WalkStartResult::Started(_)) => {
                            let mut last_started = self.last_started_at.lock().await;
                            for app_id in &app_ids {
                                last_started.insert(app_id.clone(), now);
                            }
                            crate::tprintln!(
                                "[walk] Started one bounded app-focused walk for {} active app(s) ({:?}).",
                                app_ids.len(), level
                            );
                        }
                        Ok(WalkStartResult::AlreadyRunning(_)) => {}
                        Err(error) => crate::teprintln!(
                            "[walk] Could not start combined app-focused walk for {:?}: {}",
                            app_ids, error
                        ),
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
struct LocalApiContext {
    supervisor: NetworkSupervisor,
    identities: IdentityManager,
    reputation: ReputationManager,
    app_directory: Option<AppDirectoryManager>,
    app_storage: Option<AppStorageManager>,
    private_storage: Option<PrivateAppStorageManager>,
    blob_store: Option<BlobStoreManager>,
    stream_transport: Option<StreamTransportManager>,
    gossip: GossipManager,
    lexical: Option<LexicalLibraryManager>,
    app_signing: Option<AppSigningManager>,
    mailbox: Option<Arc<MailboxManager>>,
    walk_task: Option<WalkTask>,
    handshake: Arc<Mutex<HandshakeManager>>,
    app_messages: Arc<AppMessageHub>,
    registrations: Arc<AppRegistrationHub>,
    visible_names: AppVisibleNameManager,
    mailbox_probe_ids: Arc<Mutex<HashMap<String, HashSet<[u8; 32]>>>>,
    backlog: OperationBacklog,
    app_activity: AppActivityHub,
    control_permits: Arc<Semaphore>,
    delivery_permits: Arc<Semaphore>,
    endpoint: String,
    username: String,
    profile_id: String,
    main_dht: String,
}

#[derive(Clone)]
pub struct LocalApiHandle {
    endpoint: String,
    identities: IdentityManager,
    registrations: Arc<AppRegistrationHub>,
    private_storage: Option<PrivateAppStorageManager>,
    shutdown: watch::Sender<bool>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl LocalApiHandle {
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn pending_registration_requests(&self) -> Vec<PendingAppRegistration> {
        self.registrations.pending().await
    }

    pub async fn approve_registration(
        &self,
        request_id: u64,
    ) -> Result<PendingAppRegistration, String> {
        let (request, credential) = self
            .registrations
            .approve(request_id, &self.identities)
            .await?;
        crate::tprintln!(
            "[api][app] Authorization approved: #{} {} ({})",
            request.request_id,
            request.app_id,
            request.display_name
        );
        if let Err(error) = save_approved_credential(
            &credential,
            &request.display_name,
            &self.endpoint,
        ) {
            crate::teprintln!(
                "[api] Application {} was approved, but its automatic credential file could not be saved: {}",
                request.app_id,
                error
            );
        }
        Ok(request)
    }

    pub async fn reject_registration(
        &self,
        request_id: u64,
        reason: impl Into<String>,
    ) -> Result<(), String> {
        let reason = reason.into();
        let result = self.registrations.reject(request_id, reason.clone()).await;
        match &result {
            Ok(()) => crate::tprintln!(
                "[api][app] Authorization rejected: #{request_id} reason={}",
                if reason.trim().is_empty() { "local user rejection" } else { reason.trim() }
            ),
            Err(error) => crate::teprintln!(
                "[api][app] Could not reject authorization #{request_id}: {error}"
            ),
        }
        result
    }

    pub async fn shutdown(&self) {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        clear_embedded_bridge();
        // Stop accepting useful work first, then make DeleteOnShutdown entries unreachable
        // without waiting for recursive deletion of large chunk trees.
        let _ = self.shutdown.send(true);
        if let Some(storage) = &self.private_storage {
            match storage.prepare_shutdown().await {
                Ok(count) if count > 0 => crate::tprintln!("[private-storage] expired {count} delete-on-shutdown object(s)"),
                Ok(_) => {},
                Err(error) => crate::teprintln!("[private-storage] shutdown manifest update failed: {error}"),
            }
        }
        let tasks = std::mem::take(&mut *self.tasks.lock().await);
        for task in tasks {
            let _ = task.await;
        }
    }
}

pub fn default_endpoint(username: &str) -> String {
    let safe: String = username
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    #[cfg(windows)]
    {
        format!(r"\\.\pipe\veilid-network-{safe}")
    }
    #[cfg(not(windows))]
    {
        let directory = std::env::var_os("VEILKNIT_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        directory
            .join(format!("veilid-network-{safe}.sock"))
            .to_string_lossy()
            .into_owned()
    }
}



#[derive(Serialize)]
struct SavedApprovedCredentialFile<'a> {
    protocol_version: u16,
    endpoint: &'a str,
    app_id: String,
    display_name: &'a str,
    secret_hex: String,
    credential_generation: u64,
}

fn save_approved_credential(
    credential: &AppCredential,
    display_name: &str,
    endpoint: &str,
) -> io::Result<()> {
    let safe_name: String = credential
        .app_id
        .to_string()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let document = SavedApprovedCredentialFile {
        protocol_version: LOCAL_API_PROTOCOL_VERSION,
        endpoint,
        app_id: credential.app_id.to_string(),
        display_name,
        secret_hex: hex::encode(credential.secret_bytes()),
        credential_generation: credential.credential_generation,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');

    let mut paths = vec![
        PathBuf::from("app_credentials").join(format!("{safe_name}.json")),
    ];
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        paths.insert(
            0,
            PathBuf::from(local_app_data)
                .join("DaemonNetwork")
                .join("credentials")
                .join(format!("{safe_name}.json")),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".daemon_network")
                .join("credentials")
                .join(format!("{safe_name}.json")),
        );
    }

    let mut first_error = None;
    let mut wrote_any = false;
    for path in paths {
        let result = (|| -> io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &bytes)
        })();
        match result {
            Ok(()) => wrote_any = true,
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    if wrote_any {
        Ok(())
    } else {
        Err(first_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "no credential path was writable")
        }))
    }
}

#[derive(Serialize)]
struct EndpointDiscoveryFile<'a> {
    protocol_version: u16,
    endpoint: &'a str,
    username: &'a str,
    profile_id: &'a str,
}

fn write_endpoint_discovery(endpoint: &str, username: &str, profile_id: &str) -> io::Result<()> {
    let document = EndpointDiscoveryFile {
        protocol_version: LOCAL_API_PROTOCOL_VERSION,
        endpoint,
        username,
        profile_id,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');

    let mut paths = vec![PathBuf::from("app_credentials").join("daemon_endpoint.json")];
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        paths.push(
            PathBuf::from(local_app_data)
                .join("DaemonNetwork")
                .join("daemon_endpoint.json"),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".daemon_network")
                .join("daemon_endpoint.json"),
        );
    }

    let mut first_error = None;
    let mut wrote_any = false;
    for path in paths {
        let result = (|| -> io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &bytes)
        })();
        match result {
            Ok(()) => wrote_any = true,
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }
    }
    if wrote_any {
        Ok(())
    } else {
        Err(first_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "no endpoint discovery path was writable")
        }))
    }
}

pub fn spawn_local_api(
    endpoint: String,
    supervisor: NetworkSupervisor,
    identities: IdentityManager,
    mailbox: Option<Arc<MailboxManager>>,
    walk_task: Option<WalkTask>,
    handshake: Arc<Mutex<HandshakeManager>>,
    username: String,
    profile_id: String,
    main_dht: String,
    reputation: ReputationManager,
    app_directory: Option<AppDirectoryManager>,
    app_storage: Option<AppStorageManager>,
    private_storage: Option<PrivateAppStorageManager>,
    blob_store: Option<BlobStoreManager>,
    app_signing: Option<AppSigningManager>,
    gossip: GossipManager,
    lexical: Option<LexicalLibraryManager>,
    visible_names: AppVisibleNameManager,
) -> io::Result<LocalApiHandle> {
    let (shutdown, shutdown_rx) = watch::channel(false);
    let app_messages = Arc::new(AppMessageHub::new());
    let registrations = Arc::new(AppRegistrationHub::new());
    let stream_transport = match (app_storage.clone(), app_signing.clone()) {
        (Some(storage), Some(signing)) => Some(StreamTransportManager::new(
            storage,
            signing,
            handshake.clone(),
            main_dht.clone(),
        )),
        _ => None,
    };
    spawn_application_message_bridges(
        mailbox.clone(),
        handshake.clone(),
        app_messages.clone(),
        main_dht.clone(),
        shutdown.subscribe(),
    );
    let backlog = OperationBacklog::default();
    let app_activity = AppActivityHub::new(walk_task.clone());
    let context = LocalApiContext {
        supervisor,
        identities: identities.clone(),
        reputation,
        app_directory,
        app_storage,
        private_storage: private_storage.clone(),
        blob_store,
        stream_transport: stream_transport.clone(),
        gossip: gossip.clone(),
        lexical,
        app_signing,
        mailbox,
        walk_task,
        handshake,
        app_messages,
        registrations: registrations.clone(),
        visible_names,
        mailbox_probe_ids: Arc::new(Mutex::new(HashMap::new())),
        backlog: backlog.clone(),
        app_activity: app_activity.clone(),
        control_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_CONTROL_REQUESTS)),
        delivery_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_DELIVERY_REQUESTS)),
        endpoint: endpoint.clone(),
        username: username.clone(),
        profile_id: profile_id.clone(),
        main_dht,
    };
    if let Err(error) = write_endpoint_discovery(&endpoint, &username, &profile_id) {
        crate::teprintln!("[api] Could not write endpoint discovery file: {error}");
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    install_embedded_bridge(context.clone());
    let listener_task = tokio::spawn(run_listener(endpoint.clone(), context, shutdown_rx));
    let backlog_task = tokio::spawn(run_backlog_watchdog(backlog, shutdown.subscribe()));
    let activity_task = tokio::spawn(app_activity.run(shutdown.subscribe()));
    let gossip_task = gossip.spawn_bridge(shutdown.subscribe());
    let stream_task = stream_transport.map(|manager| manager.spawn_bridge(shutdown.subscribe()));
    let private_storage_task = private_storage.as_ref().map(|manager| manager.spawn_maintenance(shutdown.subscribe()));
    let mut tasks = vec![listener_task, backlog_task, activity_task, gossip_task];
    if let Some(task) = stream_task { tasks.push(task); }
    if let Some(task) = private_storage_task { tasks.push(task); }
    Ok(LocalApiHandle {
        endpoint,
        identities,
        registrations,
        private_storage,
        shutdown,
        tasks: Arc::new(Mutex::new(tasks)),
    })
}

#[cfg(windows)]
async fn run_listener(
    endpoint: String,
    context: LocalApiContext,
    mut shutdown: watch::Receiver<bool>,
) {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut first = true;
    loop {
        let server = match ServerOptions::new()
            .first_pipe_instance(first)
            .create(&endpoint)
        {
            Ok(server) => server,
            Err(error) => {
                crate::teprintln!("[api] Could not create named pipe {endpoint}: {error}");
                return;
            }
        };
        first = false;

        tokio::select! {
            _ = shutdown.changed() => break,
            result = server.connect() => {
                match result {
                    Ok(()) => {
                        let context = context.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_connection(server, context).await {
                                crate::teprintln!("[api] Named-pipe connection ended with error: {error}");
                            }
                        });
                    }
                    Err(error) => crate::teprintln!("[api] Named-pipe connection failed: {error}"),
                }
            }
        }
    }
}

#[cfg(unix)]
async fn run_listener(
    endpoint: String,
    context: LocalApiContext,
    mut shutdown: watch::Receiver<bool>,
) {
    use tokio::net::UnixListener;

    let path = PathBuf::from(&endpoint);
    let _ = std::fs::remove_file(&path);
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            crate::teprintln!("[api] Could not create Unix socket {endpoint}: {error}");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            result = listener.accept() => match result {
                Ok((stream, _)) => {
                    let context = context.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_connection(stream, context).await {
                            crate::teprintln!("[api] Local API connection ended with error: {error}");
                        }
                    });
                }
                Err(error) => crate::teprintln!("[api] Local API accept failed: {error}"),
            }
        }
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(not(any(windows, unix)))]
async fn run_listener(
    endpoint: String,
    _context: LocalApiContext,
    _shutdown: watch::Receiver<bool>,
) {
    crate::teprintln!("[api] Local IPC is not supported on this platform: {endpoint}");
}

async fn handle_connection<S>(stream: S, context: LocalApiContext) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(write_half));
    let mut lines = BufReader::new(read_half).lines();
    let permits = Arc::new(Semaphore::new(MAX_IN_FLIGHT_REQUESTS_PER_CONNECTION));
    let mut tasks = JoinSet::new();

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_API_REQUEST_LINE_BYTES {
            let mut writer = writer.lock().await;
            write_error(
                &mut *writer,
                0,
                "request_too_large",
                format!(
                    "request line is {} bytes; maximum is {} bytes",
                    line.len(),
                    MAX_API_REQUEST_LINE_BYTES
                ),
            )
            .await?;
            continue;
        }
        let request: ApiRequestEnvelope = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                let mut writer = writer.lock().await;
                write_error(&mut *writer, 0, "invalid_json", error.to_string()).await?;
                continue;
            }
        };
        if request.protocol_version != LOCAL_API_PROTOCOL_VERSION {
            let mut writer = writer.lock().await;
            write_error(
                &mut *writer,
                request.request_id,
                "unsupported_protocol",
                format!(
                    "client requested version {}; service supports {}",
                    request.protocol_version, LOCAL_API_PROTOCOL_VERSION
                ),
            )
            .await?;
            continue;
        }

        let is_subscription = matches!(
            &request.request,
            ApiRequest::SubscribeEvents { .. }
                | ApiRequest::SubscribeMessages { .. }
                | ApiRequest::SubscribeServiceRequests { .. }
                | ApiRequest::SubscribeGossip { .. }
                | ApiRequest::SubscribeStreams { .. }
        );
        if is_subscription {
            while let Some(joined) = tasks.join_next().await {
                if let Err(error) = joined {
                    crate::teprintln!("[api] Request task ended unexpectedly: {error}");
                }
            }
            let result = process_request(request.request, &context, None).await;
            let mut writer = writer.lock().await;
            write_process_result(&mut *writer, request.request_id, result, &context).await?;
            return Ok(());
        }

        let action = request.request.action_name();
        let lane = request.request.work_lane();
        let operation_id = context.backlog.queued(request.request_id, action).await;
        let permit = match permits.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                context.backlog.finished(operation_id).await;
                return Ok(());
            }
        };
        context.backlog.stage(operation_id, lane.waiting_stage()).await;
        let lane_permit = match lane {
            ApiWorkLane::Control => context.control_permits.clone().acquire_owned().await,
            ApiWorkLane::Delivery => context.delivery_permits.clone().acquire_owned().await,
        };
        let lane_permit = match lane_permit {
            Ok(permit) => permit,
            Err(_) => {
                context.backlog.finished(operation_id).await;
                return Ok(());
            }
        };
        context.backlog.started(operation_id).await;
        let context = context.clone();
        let writer = writer.clone();
        let request_id = request.request_id;
        tasks.spawn(async move {
            let _permit = permit;
            let _lane_permit = lane_permit;
            let result = match tokio::time::timeout(
                LOCAL_API_REQUEST_TIMEOUT,
                process_request(request.request, &context, Some(operation_id)),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    context.backlog.stage(operation_id, "timed_out").await;
                    Err((
                        "request_timeout",
                        format!(
                            "daemon request exceeded {} seconds",
                            LOCAL_API_REQUEST_TIMEOUT.as_secs()
                        ),
                    ))
                }
            };
            let mut writer = writer.lock().await;
            if let Err(error) =
                write_process_result(&mut *writer, request_id, result, &context).await
            {
                crate::teprintln!("[api] Could not write response for request {request_id}: {error}");
            }
            drop(writer);
            context.backlog.finished(operation_id).await;
        });
    }

    while let Some(joined) = tasks.join_next().await {
        if let Err(error) = joined {
            crate::teprintln!("[api] Request task ended unexpectedly: {error}");
        }
    }
    Ok(())
}

async fn write_process_result<W>(
    writer: &mut W,
    request_id: u64,
    result: Result<ProcessResult, (&'static str, String)>,
    context: &LocalApiContext,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match result {
        Ok(ProcessResult::Response(result)) => {
            write_ok(writer, request_id, result).await?;
        }
        Ok(ProcessResult::SubscribeNetwork(mut events)) => {
            write_ok(
                writer,
                request_id,
                ApiResult::EventSubscriptionStarted,
            )
            .await?;
            loop {
                match events.recv().await {
                    Ok(event) => {
                        write_json_line(
                            writer,
                            &ApiNetworkEventMessage {
                                protocol_version: LOCAL_API_PROTOCOL_VERSION,
                                stream: "network_events",
                                event,
                            },
                        )
                        .await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::teprintln!("[api] Event subscriber lagged by {skipped} event(s)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
        Ok(ProcessResult::SubscribeMessages {
            app_id,
            pending,
            mut live,
        }) => {
            let app_id_text = canonical_application_id(&app_id.to_string());
            write_ok(
                writer,
                request_id,
                ApiResult::ApplicationMessageSubscriptionStarted {
                    app_id: app_id_text.clone(),
                },
            )
            .await?;
            let mut delivered = HashSet::new();
            for message in pending {
                let key = application_message_key(&message);
                write_application_event(writer, message).await?;
                delivered.insert(key.clone());
                context.app_messages.acknowledge(&app_id_text, &key).await;
            }
            loop {
                match live.recv().await {
                    Ok(message) if message.application_id == app_id_text => {
                        let key = application_message_key(&message);
                        if delivered.insert(key.clone()) {
                            write_application_event(writer, message).await?;
                        }
                        context.app_messages.acknowledge(&app_id_text, &key).await;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::teprintln!("[api] Application message subscriber lagged by {skipped} event(s)");
                        let (_, pending) = context
                            .app_messages
                            .subscribe_and_snapshot(&app_id_text)
                            .await;
                        for message in pending {
                            let key = application_message_key(&message);
                            if delivered.insert(key.clone()) {
                                write_application_event(writer, message).await?;
                            }
                            context.app_messages.acknowledge(&app_id_text, &key).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
        Ok(ProcessResult::SubscribeServiceRequests {
            service_ids,
            own_main_dht,
            pending,
            mut live,
        }) => {
            let mut ids_hex: Vec<_> = service_ids.iter().map(|id| hex::encode(id)).collect();
            ids_hex.sort();
            write_ok(
                writer,
                request_id,
                ApiResult::ServiceRequestSubscriptionStarted {
                    service_ids_hex: ids_hex,
                },
            )
            .await?;
            let mut delivered = HashSet::new();
            for request in pending {
                if service_request_visible_to_local_node(&request, &service_ids, &own_main_dht)
                    && delivered.insert(request.request_id)
                {
                    write_json_line(
                        writer,
                        &ApiServiceRequestEventMessage {
                            protocol_version: LOCAL_API_PROTOCOL_VERSION,
                            stream: "service_requests",
                            event: api_service_request(&request),
                        },
                    )
                    .await?;
                }
            }
            loop {
                match live.recv().await {
                    Ok(MailboxEvent::ServiceRequestDiscovered(request)) => {
                        if service_request_visible_to_local_node(
                            &request,
                            &service_ids,
                            &own_main_dht,
                        ) && delivered.insert(request.request_id)
                        {
                            write_json_line(
                                writer,
                                &ApiServiceRequestEventMessage {
                                    protocol_version: LOCAL_API_PROTOCOL_VERSION,
                                    stream: "service_requests",
                                    event: api_service_request(&request),
                                },
                            )
                            .await?;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::teprintln!(
                            "[api] Service request subscriber lagged by {skipped} event(s)"
                        );
                        if let Some(mailbox) = &context.mailbox {
                            if let Ok(snapshot) = mailbox.list_service_requests().await {
                                for request in snapshot {
                                    if service_request_visible_to_local_node(
                                        &request,
                                        &service_ids,
                                        &own_main_dht,
                                    ) && delivered.insert(request.request_id)
                                    {
                                        write_json_line(
                                            writer,
                                            &ApiServiceRequestEventMessage {
                                                protocol_version: LOCAL_API_PROTOCOL_VERSION,
                                                stream: "service_requests",
                                                event: api_service_request(&request),
                                            },
                                        )
                                        .await?;
                                    }
                                }
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
        Ok(ProcessResult::SubscribeGossip { app_id, mut live }) => {
            write_ok(
                writer,
                request_id,
                ApiResult::GossipSubscriptionStarted {
                    app_id: app_id.clone(),
                },
            )
            .await?;
            loop {
                match live.recv().await {
                    Ok(event) if event.application_id() == app_id.as_str() => {
                        write_json_line(
                            writer,
                            &ApiGossipEventMessage {
                                protocol_version: LOCAL_API_PROTOCOL_VERSION,
                                stream: "gossip_events",
                                event,
                            },
                        )
                        .await?;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::teprintln!("[api] Gossip subscriber lagged by {skipped} event(s)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
        Ok(ProcessResult::SubscribeStreams { app_id, mut live }) => {
            write_ok(
                writer,
                request_id,
                ApiResult::StreamSubscriptionStarted {
                    app_id: app_id.clone(),
                },
            )
            .await?;
            loop {
                match live.recv().await {
                    Ok(event) if same_stream_application_family(event.application_id(), &app_id) => {
                        write_json_line(
                            writer,
                            &ApiStreamEventMessage {
                                protocol_version: LOCAL_API_PROTOCOL_VERSION,
                                stream: "stream_events",
                                event,
                            },
                        )
                        .await?;
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::teprintln!("[api] Stream subscriber lagged by {skipped} event(s)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
        Err((code, message)) => {
            crate::teprintln!(
                "[api] Request {request_id} failed: {code}: {message}"
            );
            write_error(writer, request_id, code, message).await?;
        }
    }
    Ok(())
}

enum ProcessResult {
    Response(ApiResult),
    SubscribeNetwork(tokio::sync::broadcast::Receiver<NetworkEventEnvelope>),
    SubscribeMessages {
        app_id: AppId,
        pending: Vec<ApiApplicationMessage>,
        live: tokio::sync::broadcast::Receiver<ApiApplicationMessage>,
    },
    SubscribeServiceRequests {
        service_ids: HashSet<[u8; 32]>,
        own_main_dht: String,
        pending: Vec<ServiceRequest>,
        live: tokio::sync::broadcast::Receiver<MailboxEvent>,
    },
    SubscribeStreams {
        app_id: String,
        live: tokio::sync::broadcast::Receiver<StreamEvent>,
    },
    SubscribeGossip {
        app_id: String,
        live: tokio::sync::broadcast::Receiver<GossipEvent>,
    },
}

async fn process_request(
    request: ApiRequest,
    context: &LocalApiContext,
    operation_id: Option<u64>,
) -> Result<ProcessResult, (&'static str, String)> {
    match request {
        ApiRequest::Ping => Ok(ProcessResult::Response(ApiResult::Pong)),
        ApiRequest::GetApiInfo => Ok(ProcessResult::Response(ApiResult::ApiInfo {
            protocol_version: LOCAL_API_PROTOCOL_VERSION,
            authentication_proof: "hmac_sha256",
            features: vec![
                "application_messaging",
                "application_gossip_v1",
                "daemon_gossip_engine_v2",
                "gossip_fingerprint_search_v1",
                "gossip_token_index_v1",
                "gossip_stream_discovery_v1",
                "distributed_lexical_library_v1",
                "lexical_epoch_statistics_v1",
                "lexical_word_association_v1",
                "lexical_script_fuzzy_matching_v1",
                "mailbox_delivery",
                "delegatable_service_requests_v1",
                "network_event_stream",
                "application_signing",
                "application_owned_dht_storage",
                "encrypted_private_app_storage_v1",
                "encrypted_private_chunked_blobs_v1",
                "private_storage_retention_v1",
                "public_dht_reads",
                "known_node_directory",
                "app_peer_discovery_v1",
                "app_directory_roots_v1",
                "persistent_application_inbox",
                "application_scoped_reputation",
                "mailbox_probe_diagnostics",
                "network_topology_diagnostics",
                "manual_diagnostic_walks",
                "application_scoped_display_names",
                "app_node_recommendations",
                "renewable_app_activity_leases",
                "operation_backlog_diagnostics",
                "chained_blob_store_v1",
                "routed_stream_transport_v1",
                "signed_stream_commitments_v1",
                "viewer_relay_fanout_v1",
            ],
            max_message_bytes: MAX_API_MESSAGE_BYTES,
            max_store_value_bytes: MAX_APP_STORE_VALUE_BYTES,
            max_store_subkeys: MAX_APP_STORE_SUBKEYS,
            max_stores_per_app: MAX_APP_STORES_PER_APP,
            max_store_reads_per_request: MAX_APP_STORE_READS_PER_REQUEST,
            max_store_writes_per_request: MAX_APP_STORE_WRITES_PER_REQUEST,
            max_store_write_bytes_per_request: MAX_APP_STORE_WRITE_BYTES_PER_REQUEST,
            max_signature_payload_bytes: MAX_APP_SIGNATURE_PAYLOAD_BYTES,
            max_signature_domain_bytes: MAX_APP_SIGNATURE_DOMAIN_BYTES,
            max_blob_append_bytes: BLOB_MAX_APPEND_BYTES,
            max_blob_bytes: BLOB_MAX_BYTES,
            max_private_value_bytes: MAX_PRIVATE_VALUE_BYTES,
            max_private_blob_append_bytes: MAX_PRIVATE_BLOB_APPEND_BYTES,
            max_private_blob_read_bytes: MAX_PRIVATE_BLOB_READ_BYTES,
            max_private_blob_bytes: MAX_PRIVATE_BLOB_BYTES,
            private_ephemeral_ttl_min_seconds: MIN_EPHEMERAL_TTL_SECS,
            private_ephemeral_ttl_max_seconds: MAX_EPHEMERAL_TTL_SECS,
            private_cache_limit_bytes: DEFAULT_PRIVATE_CACHE_LIMIT_BYTES,
            max_stream_write_bytes: STREAM_MAX_WRITE_BYTES,
            stream_packet_bytes: STREAM_PACKET_BYTES,
            max_gossip_custom_payload_bytes: GOSSIP_MAX_CUSTOM_PAYLOAD_BYTES,
            max_gossip_fingerprints: GOSSIP_MAX_FINGERPRINTS,
            max_gossip_fingerprint_bytes: GOSSIP_MAX_FINGERPRINT_BYTES,
            max_gossip_index_tokens: GOSSIP_MAX_INDEX_TOKENS,
            max_gossip_index_term_bytes: GOSSIP_MAX_INDEX_TERM_BYTES,
            max_gossip_index_probe_groups: GOSSIP_MAX_INDEX_PROBES,
            max_gossip_query_results: GOSSIP_MAX_QUERY_RESULTS,
            max_gossip_ttl_seconds: GOSSIP_MAX_TTL_SECS,
            max_lexical_text_bytes: LEXICAL_MAX_TEXT_BYTES,
            max_lexical_pretokenized_terms: LEXICAL_MAX_PRETOKENIZED_TERMS,
            max_lexical_search_terms: LEXICAL_MAX_SEARCH_TERMS,
            lexical_default_window_days: LEXICAL_ACTIVE_WINDOW_DAYS,
        })),
        ApiRequest::GetStatus { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SubscribeNetworkStatus)
                .map_err(identity_error)?;
            Ok(ProcessResult::Response(ApiResult::Status {
                status: context.supervisor.status().await,
            }))
        }
        ApiRequest::GetIdentity { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            if context.main_dht.is_empty() {
                crate::teprintln!(
                    "[api][app] {} requested identity while the main DHT is unavailable",
                    session.app_id()
                );
            }
            let display_name = context.visible_names.name_for(session.app_id()).await;
            Ok(ProcessResult::Response(ApiResult::Identity {
                // Keep the historical field for existing SDKs, but never leak
                // the login username through it.
                username: display_name.clone(),
                display_name,
                profile_id: context.profile_id.clone(),
                main_dht: context.main_dht.clone(),
            }))
        }
        ApiRequest::BeginAuthentication {
            app_id,
            requested_capabilities,
        } => {
            let app_id = AppId::new(app_id).map_err(|error| ("invalid_app_id", error.to_string()))?;
            let requested = AppCapabilitySet::new(requested_capabilities);
            let challenge = context
                .identities
                .begin_app_auth_with_capabilities(&app_id, requested)
                .await
                .map_err(identity_error)?;
            crate::tprintln!(
                "[api][app] Authentication challenge issued: app={} challenge={} expires_at={}",
                challenge.app_id,
                challenge.challenge_id,
                challenge.expires_at
            );
            Ok(ProcessResult::Response(ApiResult::AuthenticationChallenge {
                app_id: challenge.app_id.to_string(),
                challenge_id: challenge.challenge_id,
                nonce_hex: hex::encode(challenge.nonce),
                issued_at: challenge.issued_at,
                expires_at: challenge.expires_at,
                credential_generation: challenge.credential_generation,
                requested_capabilities: challenge.requested_capabilities.iter().collect(),
            }))
        }
        ApiRequest::FinishAuthentication {
            app_id,
            challenge_id,
            proof_hex,
        } => {
            let app_id = AppId::new(app_id).map_err(|error| ("invalid_app_id", error.to_string()))?;
            let proof = decode_fixed::<32>(&proof_hex, "invalid_proof")?;
            let session = context
                .identities
                .finish_app_auth(AppAuthResponse {
                    app_id,
                    challenge_id,
                    proof,
                })
                .await
                .map_err(identity_error)?;
            crate::tprintln!(
                "[api][app] Authenticated: app={} session={} expires_at={} main_dht_available={}",
                session.app_id(),
                session.session_id(),
                session.expires_at(),
                !context.main_dht.is_empty()
            );
            Ok(ProcessResult::Response(ApiResult::AuthenticationSucceeded {
                app_id: session.app_id().to_string(),
                session_id: session.session_id().to_string(),
                session_token_hex: hex::encode(session.session_token().as_bytes()),
                authenticated_at: session.authenticated_at(),
                expires_at: session.expires_at(),
                capabilities: session.capabilities().iter().collect(),
            }))
        }
        ApiRequest::SubscribeEvents { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SubscribeNetworkStatus)
                .map_err(identity_error)?;
            Ok(ProcessResult::SubscribeNetwork(context.supervisor.subscribe()))
        }
        ApiRequest::SendMessage {
            session_token,
            recipient_main_dht,
            payload_base64,
            conversation_id_hex,
            expires_at,
            await_response,
            prefer_direct,
        } => {
            let delivery_started = Instant::now();
            if let Some(operation_id) = operation_id {
                context.backlog.stage(operation_id, "authenticating_app").await;
            }
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let recipient_main_dht: RecordKey = recipient_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let plaintext = BASE64
                .decode(payload_base64)
                .map_err(|error| ("invalid_payload", error.to_string()))?;
            let payload_len = plaintext.len();
            if payload_len > MAX_API_MESSAGE_BYTES {
                return Err((
                    "message_too_large",
                    format!(
                        "payload is {} bytes; maximum is {} bytes",
                        plaintext.len(),
                        MAX_API_MESSAGE_BYTES
                    ),
                ));
            }
            let conversation_id = conversation_id_hex
                .as_deref()
                .map(|value| decode_fixed::<32>(value, "invalid_conversation_id"))
                .transpose()?;
            let recipient_text = recipient_main_dht.to_string();
            let application_id = canonical_application_id(&session.app_id().to_string());
            if prefer_direct && application_id != "veilknit.mailer" {
                if let Some(operation_id) = operation_id {
                    context.backlog.stage(operation_id, "direct_handshake_delivery").await;
                }
                crate::tprintln!(
                    "[delivery] request={:?} app={} recipient={} stage=direct_started",
                    operation_id,
                    application_id,
                    recipient_text
                );
                match try_direct_send(
                    context.handshake.clone(),
                    recipient_text.clone(),
                    application_id.clone(),
                    plaintext.clone(),
                )
                .await
                {
                Ok(message_id) => {
                    crate::tprintln!(
                        "[delivery] request={:?} app={} recipient={} stage=direct_queued bytes={} elapsed_ms={}",
                        operation_id,
                        application_id,
                        recipient_text,
                        payload_len,
                        delivery_started.elapsed().as_millis()
                    );
                    return Ok(ProcessResult::Response(ApiResult::MessageQueued {
                        message_id_hex: hex::encode(message_id),
                    }));
                }
                Err(error) => {
                    crate::tprintln!(
                        "[delivery] request={:?} app={} recipient={} stage=direct_unavailable elapsed_ms={} detail={}",
                        operation_id,
                        application_id,
                        recipient_text,
                        delivery_started.elapsed().as_millis(),
                        error
                    );
                    if let Some(operation_id) = operation_id {
                        context.backlog.stage(operation_id, "mailbox_fallback").await;
                    }
                }
                }
            }

            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let app_mailbox = mailbox
                .authenticated_app_handle(&session)
                .map_err(|error| ("mailbox_auth_failed", error.to_string()))?;
            if let Some(operation_id) = operation_id {
                context.backlog.stage(operation_id, "mailbox_network_commit").await;
            }
            let message_id = app_mailbox
                .submit_outgoing_message(OutgoingMessageRequest {
                    application_id: application_id.clone(),
                    recipient_main_dht,
                    plaintext,
                    expires_at,
                    conversation_id,
                    proposed_conversation_dht: None,
                    await_response,
                })
                .await
                .map_err(|error| ("message_send_failed", error.to_string()))?;
            crate::tprintln!(
                "[delivery] request={:?} app={} recipient={} stage=mailbox_queued bytes={} elapsed_ms={}",
                operation_id,
                application_id,
                recipient_text,
                payload_len,
                delivery_started.elapsed().as_millis()
            );
            Ok(ProcessResult::Response(ApiResult::MessageQueued {
                message_id_hex: hex::encode(message_id),
            }))
        }
        ApiRequest::SendGossip {
            session_token,
            recipient_main_dht,
            payload_base64,
        } => {
            if let Some(operation_id) = operation_id {
                context.backlog.stage(operation_id, "gossip_route_delivery").await;
            }
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let recipient: RecordKey = recipient_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let payload = BASE64
                .decode(payload_base64)
                .map_err(|error| ("invalid_payload", error.to_string()))?;
            if payload.len() > MAX_API_MESSAGE_BYTES {
                return Err((
                    "message_too_large",
                    format!(
                        "gossip payload is {} bytes; maximum is {} bytes",
                        payload.len(),
                        MAX_API_MESSAGE_BYTES
                    ),
                ));
            }
            let application_id = canonical_application_id(&session.app_id().to_string());
            let message_id = try_gossip_send(
                context.handshake.clone(),
                recipient.to_string(),
                application_id,
                payload,
            )
            .await
            .map_err(|error| ("gossip_send_failed", error))?;
            Ok(ProcessResult::Response(ApiResult::MessageQueued {
                message_id_hex: hex::encode(message_id),
            }))
        }
        ApiRequest::PublishGossipObject { session_token, object } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let request = decode_api_gossip_publish(&app_id, object)?;
            let hit = context
                .gossip
                .publish(&app_id, request)
                .await
                .map_err(gossip_error)?;
            Ok(ProcessResult::Response(ApiResult::GossipPublished {
                hit: hit.into(),
            }))
        }
        ApiRequest::WithdrawGossipObject {
            session_token,
            namespace,
            object_id,
            generation,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let hit = context
                .gossip
                .withdraw(&app_id, &namespace, &object_id, generation)
                .await
                .map_err(gossip_error)?;
            Ok(ProcessResult::Response(ApiResult::GossipWithdrawn {
                hit: hit.into(),
            }))
        }
        ApiRequest::SearchGossip {
            session_token,
            query,
            query_network,
            network_wait_ms,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            if query_network {
                session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            }
            let app_id = canonical_application_id(&session.app_id().to_string());
            let query = decode_api_gossip_query(&app_id, query)?;
            let (query_id_hex, network_peers_contacted, hits) = context
                .gossip
                .search(&app_id, query, query_network, network_wait_ms)
                .await
                .map_err(gossip_error)?;
            Ok(ProcessResult::Response(ApiResult::GossipSearchResults {
                query_id_hex,
                network_peers_contacted,
                hits: hits.into_iter().map(Into::into).collect(),
            }))
        }
        ApiRequest::ListGossip {
            session_token,
            namespace,
            limit,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let hits = context
                .gossip
                .list_recent(&app_id, namespace.as_deref(), limit)
                .await
                .map_err(gossip_error)?;
            Ok(ProcessResult::Response(ApiResult::GossipObjects {
                hits: hits.into_iter().map(Into::into).collect(),
            }))
        }
        ApiRequest::ConfirmGossipObject {
            session_token,
            namespace,
            object_id,
            generation,
            level,
            matches_authoritative,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            // Confirmation records what the application learned after doing its
            // own authoritative check. It is intentionally not tied to the
            // legacy `ReadPublicProfiles` capability because gossip namespaces
            // are generic and may point at rooms, videos, listings, etc.
            let app_id = canonical_application_id(&session.app_id().to_string());
            let hit = context
                .gossip
                .confirm(
                    &app_id,
                    &namespace,
                    &object_id,
                    generation,
                    level,
                    matches_authoritative,
                )
                .await
                .map_err(gossip_error)?;
            Ok(ProcessResult::Response(ApiResult::GossipConfirmed {
                hit: hit.into(),
            }))
        }
        ApiRequest::GetGossipStats { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let stats = context.gossip.stats(&app_id).await.map_err(gossip_error)?;
            Ok(ProcessResult::Response(ApiResult::GossipStats { stats }))
        }
        ApiRequest::SubscribeGossip { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            context
                .gossip
                .activate_application(&app_id)
                .await
                .map_err(gossip_error)?;
            Ok(ProcessResult::SubscribeGossip {
                app_id,
                live: context.gossip.subscribe(),
            })
        }
        ApiRequest::ObserveLexical { session_token, library_name, layer, object_id, generation, field_id, text, terms, authoritative_pointer, publish_posting_hint } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            let lexical = context.lexical.as_ref().ok_or_else(|| ("service_unavailable", "lexical library service is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let result = lexical.observe(&app_id, LexicalObserveRequest { library_name, layer, object_id, generation, field_id, text, pretokenized_terms: terms, authoritative_pointer, publish_posting_hint }).await.map_err(lexical_error)?;
            Ok(ProcessResult::Response(ApiResult::LexicalObserved { result }))
        }
        ApiRequest::WithdrawLexicalObject { session_token, library_name, object_id, generation } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            let lexical = context.lexical.as_ref().ok_or_else(|| ("service_unavailable", "lexical library service is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            lexical.withdraw_object(&app_id, &library_name, &object_id, generation).await.map_err(lexical_error)?;
            Ok(ProcessResult::Response(ApiResult::LexicalObjectWithdrawn { object_id }))
        }
        ApiRequest::SearchLexical { session_token, library_name, layer, terms, window_days, query_network } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            if query_network { session.require_capability(AppCapability::SendMessages).map_err(identity_error)?; }
            let lexical = context.lexical.as_ref().ok_or_else(|| ("service_unavailable", "lexical library service is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let result = lexical.search(&app_id, &library_name, &layer, &terms, window_days, query_network).await.map_err(lexical_error)?;
            Ok(ProcessResult::Response(ApiResult::LexicalSearchResults { result }))
        }
        ApiRequest::CompareLexicalTerms { session_token, left, right } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let lexical = context.lexical.as_ref().ok_or_else(|| ("service_unavailable", "lexical library service is unavailable".to_string()))?;
            Ok(ProcessResult::Response(ApiResult::LexicalTermComparison { similarity: lexical.compare_terms(&left, &right) }))
        }
        ApiRequest::GetLexicalAssociation { session_token, library_name, layer, left, right, window_days } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let lexical = context.lexical.as_ref().ok_or_else(|| ("service_unavailable", "lexical library service is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let metrics = lexical.association_metrics(&app_id, &library_name, &layer, &left, &right, window_days).await.map_err(lexical_error)?;
            Ok(ProcessResult::Response(ApiResult::LexicalAssociation { metrics }))
        }
        ApiRequest::GetLexicalStats { session_token, library_name } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let lexical = context.lexical.as_ref().ok_or_else(|| ("service_unavailable", "lexical library service is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let stats = lexical.stats(&app_id, &library_name).await.map_err(lexical_error)?;
            Ok(ProcessResult::Response(ApiResult::LexicalStats { stats }))
        }
        ApiRequest::TriggerMessageRetrieval { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReceiveMessages)
                .map_err(identity_error)?;
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            mailbox
                .retrieve_our_mail()
                .await
                .map_err(|error| ("retrieval_failed", error.to_string()))?;
            Ok(ProcessResult::Response(ApiResult::MessageRetrievalScheduled))
        }
        ApiRequest::GetMailboxStatus { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReceiveMessages)
                .map_err(identity_error)?;
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let status = mailbox
                .status()
                .await
                .map_err(|error| ("mailbox_status_failed", error.to_string()))?;
            Ok(ProcessResult::Response(ApiResult::MailboxStatus {
                mailbox_dht: status.mailbox_dht.map(|key| key.to_string()),
                mail_send_dht: status.mail_send_dht.map(|key| key.to_string()),
                mail_response_dht: status.mail_response_dht.to_string(),
                receive_key_epoch: status.receive_key_epoch,
                pending_page_sets: status.pending_page_sets,
                outgoing_message_count: status.outgoing_message_count,
                outgoing_service_request_count: status.outgoing_service_request_count,
                recent_service_request_count: status.recent_service_request_count,
                awaiting_response_count: status.awaiting_response_count,
                stored_inbox_count: status.stored_inbox_count,
                unread_inbox_count: status.unread_inbox_count,
                known_custodian_count: status.known_custodian_count,
            }))
        }
        ApiRequest::PublishServiceRequest {
            session_token,
            intended_host_main_dht,
            service_id_hex,
            service_manifest_hash_hex,
            instance_id_hex,
            payload_base64,
            delegation_allowed,
            spectators_allowed,
            ttl_seconds,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let host: RecordKey = intended_host_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let service_id = decode_fixed::<32>(&service_id_hex, "invalid_service_id")?;
            let service_manifest_hash =
                decode_fixed::<32>(&service_manifest_hash_hex, "invalid_service_manifest_hash")?;
            let instance_id = decode_fixed::<32>(&instance_id_hex, "invalid_instance_id")?;
            let public_payload = BASE64
                .decode(payload_base64)
                .map_err(|error| ("invalid_payload", error.to_string()))?;
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let app_mailbox = mailbox
                .authenticated_app_handle(&session)
                .map_err(|error| ("mailbox_auth_failed", error.to_string()))?;
            let published = app_mailbox
                .publish_service_request(ServiceRequestPublishRequest {
                    intended_host_main_dht: host,
                    service_id,
                    service_manifest_hash,
                    instance_id,
                    public_payload,
                    delegation_allowed,
                    spectators_allowed,
                    ttl_secs: ttl_seconds,
                })
                .await
                .map_err(|error| ("service_request_publish_failed", error.to_string()))?;
            Ok(ProcessResult::Response(ApiResult::ServiceRequestPublished {
                request_id_hex: hex::encode(published.request_id),
                expires_at: published.expires_at,
            }))
        }
        ApiRequest::WithdrawServiceRequest {
            session_token,
            request_id_hex,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let request_id = decode_fixed::<32>(&request_id_hex, "invalid_service_request_id")?;
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let app_mailbox = mailbox
                .authenticated_app_handle(&session)
                .map_err(|error| ("mailbox_auth_failed", error.to_string()))?;
            app_mailbox
                .withdraw_service_request(request_id)
                .await
                .map_err(|error| ("service_request_withdraw_failed", error.to_string()))?;
            Ok(ProcessResult::Response(ApiResult::ServiceRequestWithdrawn {
                request_id_hex,
            }))
        }
        ApiRequest::SubscribeServiceRequests {
            session_token,
            service_ids_hex,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReceiveMessages)
                .map_err(identity_error)?;
            if service_ids_hex.is_empty() || service_ids_hex.len() > 64 {
                return Err((
                    "invalid_service_subscription",
                    "subscribe_service_requests requires between 1 and 64 service ids".to_string(),
                ));
            }
            let mut service_ids = HashSet::new();
            for service_id_hex in service_ids_hex {
                service_ids.insert(decode_fixed::<32>(&service_id_hex, "invalid_service_id")?);
            }
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let live = mailbox.subscribe();
            let pending = mailbox
                .list_service_requests()
                .await
                .map_err(|error| ("service_request_list_failed", error.to_string()))?;
            Ok(ProcessResult::SubscribeServiceRequests {
                service_ids,
                own_main_dht: context.main_dht.clone(),
                pending,
                live,
            })
        }
        ApiRequest::SendServiceReply {
            session_token,
            request_id_hex,
            reply_route_blob_base64,
            payload_base64,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let request_id = decode_fixed::<32>(&request_id_hex, "invalid_service_request_id")?;
            let route_blob = BASE64
                .decode(reply_route_blob_base64)
                .map_err(|error| ("invalid_reply_route", error.to_string()))?;
            let payload = BASE64
                .decode(payload_base64)
                .map_err(|error| ("invalid_payload", error.to_string()))?;
            if payload.len() > MAX_API_MESSAGE_BYTES.saturating_sub(128) {
                return Err((
                    "message_too_large",
                    format!("service reply payload is {} bytes", payload.len()),
                ));
            }
            let application_id = canonical_application_id(&session.app_id().to_string());
            let wrapped = encode_service_reply_payload(request_id, &payload);
            let message_id = try_gossip_route_send(
                context.handshake.clone(),
                route_blob,
                application_id,
                wrapped,
            )
            .await
            .map_err(|error| ("service_reply_send_failed", error))?;
            Ok(ProcessResult::Response(ApiResult::ServiceReplySent {
                request_id_hex,
                message_id_hex: hex::encode(message_id),
            }))
        }
        ApiRequest::ListKnownNodes { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReadPublicProfiles)
                .map_err(identity_error)?;
            let walker = context
                .walk_task
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "network walker is unavailable".to_string()))?;
            let now = current_timestamp();
            let list = walker.get_internal_list_copy().await;
            let mut nodes: Vec<ApiKnownNode> = list
                .entries
                .into_iter()
                .map(|entry| ApiKnownNode {
                    main_dht: entry.their_address.to_string(),
                    verified: true,
                    verification_state: match entry.verification_state {
                        NodeVerificationState::Advertised => "Advertised",
                        NodeVerificationState::DhtVerified => "DHT verified",
                        NodeVerificationState::Authenticated => "Authenticated",
                    }
                    .to_string(),
                    presence_state: entry.presence_state_at(now).label().to_string(),
                    last_seen: entry.last_seen,
                    last_online: entry.last_online,
                    mailbox_capable: entry.capability_flags & CAPABILITY_MAILBOX != 0,
                    application_ids: entry.application_ids,
                })
                .collect();
            nodes.extend(list.candidates.into_iter().map(|candidate| ApiKnownNode {
                main_dht: candidate.their_address.to_string(),
                verified: false,
                verification_state: "Advertised candidate".to_string(),
                presence_state: "Unknown".to_string(),
                last_seen: 0,
                last_online: 0,
                mailbox_capable: false,
                application_ids: Vec::new(),
            }));
            nodes.sort_by(|left, right| {
                right
                    .verified
                    .cmp(&left.verified)
                    .then_with(|| right.last_seen.cmp(&left.last_seen))
                    .then_with(|| left.main_dht.cmp(&right.main_dht))
            });
            nodes.dedup_by(|left, right| left.main_dht == right.main_dht);
            Ok(ProcessResult::Response(ApiResult::KnownNodes {
                sampled_at: now,
                nodes,
            }))
        }
        ApiRequest::ListAppPeers {
            session_token,
            limit,
            start_search,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReadPublicProfiles)
                .map_err(identity_error)?;
            let walker = context
                .walk_task
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "network walker is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let page = walker.list_app_peers(&app_id, limit).await;
            let search_state = if start_search {
                match walker.start_app_search(app_id.clone(), 16).await {
                    Ok(AppSearchStartState::Started) => "started".to_string(),
                    Ok(AppSearchStartState::QueuedAfterActiveWalk) => {
                        "queued_after_active_walk".to_string()
                    }
                    Ok(AppSearchStartState::AlreadyQueued) => "already_queued".to_string(),
                    Err(error) => format!("not_started: {error}"),
                }
            } else {
                "not_requested".to_string()
            };
            let peers = page
                .peers
                .into_iter()
                .map(|peer| ApiAppPeer {
                    main_dht: peer.main_dht.to_string(),
                    first_discovered_at: peer.first_discovered_at,
                    last_directly_verified_at: peer.last_directly_verified_at,
                    last_returned_at: peer.last_returned_at,
                    return_count: peer.return_count,
                    tier: match peer.tier {
                        AppPeerTier::Recent => "recent",
                        AppPeerTier::Archive => "archive",
                    },
                    app_root_dht: peer.app_root_dht.map(|root| root.to_string()),
                    app_root_checked_at: peer.app_root_checked_at,
                    app_directory_generation: peer.app_directory_generation,
                })
                .collect();
            Ok(ProcessResult::Response(ApiResult::AppPeers {
                app_id,
                sampled_at: current_timestamp(),
                cache_generation: page.generation,
                total_cached: page.total_cached,
                peers,
                search_state,
            }))
        }
        ApiRequest::RegisterAppRoot { session_token, root_dht } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ManageOwnStorage)
                .map_err(identity_error)?;
            let manager = context.app_directory.as_ref().ok_or_else(|| {
                ("service_unavailable", "app directory service is unavailable".to_string())
            })?;
            let root_dht = root_dht
                .parse::<RecordKey>()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            // Bounded on purpose. This publishes to the app directory DHT, and on a node
            // that has gone offline the call otherwise never returns - the client is a
            // blocking binder transaction, so an unbounded await here parks the calling
            // app's thread indefinitely with no way to recover but a restart.
            let update = match tokio::time::timeout(
                APP_ROOT_PUBLISH_TIMEOUT,
                manager.set_own_app_root(&app_id, root_dht),
            )
            .await
            {
                Ok(result) => result.map_err(|error| ("app_directory_error", error))?,
                Err(_) => {
                    //crate::net_health::record_result(Some("TryAgain: offline, try again later"));
                    return Err((
                        "app_directory_timeout",
                        format!(
                            "publishing the app root did not complete within {} seconds; the node may be offline",
                            APP_ROOT_PUBLISH_TIMEOUT.as_secs()
                        ),
                    ));
                }
            };
            Ok(ProcessResult::Response(ApiResult::AppRootRegistered {
                app_id: update.app_id,
                root_dht: update.root_dht.expect("set app root always returns a root").to_string(),
                directory_dht: update.directory_dht.to_string(),
                generation: update.generation,
                updated_at: update.updated_at,
            }))
        }
        ApiRequest::ClearAppRoot { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ManageOwnStorage)
                .map_err(identity_error)?;
            let manager = context.app_directory.as_ref().ok_or_else(|| {
                ("service_unavailable", "app directory service is unavailable".to_string())
            })?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let update = manager
                .clear_own_app_root(&app_id)
                .await
                .map_err(|error| ("app_directory_error", error))?;
            Ok(ProcessResult::Response(ApiResult::AppRootCleared {
                app_id: update.app_id,
                directory_dht: update.directory_dht.to_string(),
                generation: update.generation,
                updated_at: update.updated_at,
            }))
        }
        ApiRequest::GetAppRoot {
            session_token,
            peer_main_dht,
            start_lookup,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReadPublicProfiles)
                .map_err(identity_error)?;
            let walker = context.walk_task.as_ref().ok_or_else(|| {
                ("service_unavailable", "network walker is unavailable".to_string())
            })?;
            let peer = peer_main_dht
                .parse::<RecordKey>()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let cached = walker
                .app_root_cache_state(&app_id, &peer)
                .await
                .ok_or_else(|| {
                    (
                        "peer_not_in_app_cache",
                        "peer has not been directly verified for this authenticated app".to_string(),
                    )
                })?;
            let now = current_timestamp();
            let (root_dht, checked_at, directory_generation, base_status, cache_ttl) = match cached {
                AppRootCacheState::Unknown => (None, 0, 0, "unknown", 0),
                AppRootCacheState::Found {
                    root_dht,
                    checked_at,
                    directory_generation,
                } => (
                    Some(root_dht.to_string()),
                    checked_at,
                    directory_generation,
                    "found",
                    APP_ROOT_CACHE_TTL_SECS,
                ),
                AppRootCacheState::NotPublished {
                    checked_at,
                    directory_generation,
                } => (
                    None,
                    checked_at,
                    directory_generation,
                    "not_published",
                    APP_ROOT_NEGATIVE_CACHE_TTL_SECS,
                ),
            };
            let stale = checked_at == 0 || checked_at.saturating_add(cache_ttl) < now;
            let status = if stale && start_lookup {
                match context.app_directory.as_ref() {
                    Some(manager) => {
                        match manager
                            .queue_peer_root_lookup(
                                app_id.clone(),
                                peer.clone(),
                                walker.app_discovery_cache(),
                            )
                            .await
                        {
                            AppRootLookupQueueState::Queued => {
                                if checked_at == 0 { "lookup_queued" } else { "stale_lookup_queued" }
                            }
                            AppRootLookupQueueState::AlreadyPending => {
                                if checked_at == 0 { "lookup_in_progress" } else { "stale_lookup_in_progress" }
                            }
                            AppRootLookupQueueState::QueueFull => {
                                if checked_at == 0 { "lookup_queue_full" } else { "stale_lookup_queue_full" }
                            }
                        }
                    }
                    None => "lookup_unavailable",
                }
            } else if stale {
                if checked_at == 0 { "unknown" } else { "stale" }
            } else {
                base_status
            };
            Ok(ProcessResult::Response(ApiResult::AppRoot {
                app_id,
                peer_main_dht: peer.to_string(),
                root_dht,
                status: status.to_string(),
                checked_at,
                directory_generation,
            }))
        }
        ApiRequest::RecommendNodes {
            session_token,
            nodes,
            context: recommendation_context,
            ttl_seconds,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReadPublicProfiles)
                .map_err(identity_error)?;
            if nodes.len() > MAX_APP_RECOMMENDED_NODES {
                return Err((
                    "too_many_nodes",
                    format!(
                        "{} node recommendations were supplied; maximum is {}",
                        nodes.len(),
                        MAX_APP_RECOMMENDED_NODES
                    ),
                ));
            }
            let mut parsed = Vec::with_capacity(nodes.len());
            let mut seen = HashSet::new();
            for node in nodes {
                let key: RecordKey = node
                    .parse()
                    .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
                if seen.insert(key.to_string()) {
                    parsed.push(key);
                }
            }
            let walker = context
                .walk_task
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "network walker is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let report = walker
                .recommend_app_nodes(app_id.clone(), parsed, ttl_seconds)
                .await
                .map_err(|error| ("node_recommendation_failed", error.to_string()))?;
            crate::tprintln!(
                "[api] App {} recommended {} relevant node(s){}; {} new candidate(s), {} already known",
                app_id,
                report.submitted,
                recommendation_context
                    .as_deref()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!(" for {}", value))
                    .unwrap_or_default(),
                report.new_candidates,
                report.already_known,
            );
            Ok(ProcessResult::Response(ApiResult::NodesRecommended {
                submitted: report.submitted,
                new_candidates: report.new_candidates,
                already_known: report.already_known,
                expires_at: report.expires_at,
            }))
        }
        ApiRequest::SetAppActivity {
            session_token,
            level,
            relevant_nodes,
            lease_seconds,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SubscribeNetworkStatus)
                .map_err(identity_error)?;
            if relevant_nodes.len() > MAX_APP_RECOMMENDED_NODES {
                return Err((
                    "too_many_nodes",
                    format!(
                        "{} relevant nodes were supplied; maximum is {}",
                        relevant_nodes.len(),
                        MAX_APP_RECOMMENDED_NODES
                    ),
                ));
            }
            let app_id = canonical_application_id(&session.app_id().to_string());
            let mut parsed = Vec::with_capacity(relevant_nodes.len());
            let mut seen = HashSet::new();
            for node in relevant_nodes {
                let key: RecordKey = node
                    .parse()
                    .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
                if seen.insert(key.to_string()) {
                    parsed.push(key);
                }
            }
            if level != AppActivityLevel::Inactive {
                if let Some(walker) = &context.walk_task {
                    walker
                        .recommend_app_nodes(app_id.clone(), parsed.clone(), lease_seconds)
                        .await
                        .map_err(|error| ("node_recommendation_failed", error.to_string()))?;
                }
            }
            let (expires_at, relevant_node_count) = context
                .app_activity
                .set_lease(app_id.clone(), level, parsed, lease_seconds)
                .await;
            crate::tprintln!(
                "[api] App activity lease: app={} level={:?} expires_at={} relevant_nodes={}",
                app_id,
                level,
                expires_at,
                relevant_node_count
            );
            Ok(ProcessResult::Response(ApiResult::AppActivityLease {
                level,
                expires_at,
                effective_interval_secs: (level != AppActivityLevel::Inactive)
                    .then_some(level.interval_secs()),
                effective_hops: level.hop_count(),
                relevant_node_count,
            }))
        }
        ApiRequest::GetOperationBacklog { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ManageApplications)
                .map_err(identity_error)?;
            Ok(ProcessResult::Response(ApiResult::OperationBacklog {
                sampled_at: current_timestamp(),
                operations: context.backlog.snapshot().await,
            }))
        }
        ApiRequest::ListInbox { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReceiveMessages)
                .map_err(identity_error)?;
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let messages = mailbox
                .list_inbox()
                .await
                .map_err(|error| ("inbox_list_failed", error.to_string()))?
                .into_iter()
                .filter(|message| canonical_application_id(&message.application_id) == app_id)
                .map(|message| ApiInboxSummary {
                    message_id_hex: hex::encode(message.message_id),
                    sender_main_dht: message.sender_main_dht.to_string(),
                    posted_at: message.posted_at,
                    received_at: message.received_at,
                    plaintext_len: message.plaintext_len,
                    read: message.read,
                })
                .collect();
            Ok(ProcessResult::Response(ApiResult::InboxMessages { messages }))
        }
        ApiRequest::ReadInbox {
            session_token,
            message_id_hex,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReceiveMessages)
                .map_err(identity_error)?;
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let message_id = decode_fixed::<32>(&message_id_hex, "invalid_message_id")?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let belongs_to_app = mailbox
                .list_inbox()
                .await
                .map_err(|error| ("inbox_list_failed", error.to_string()))?
                .into_iter()
                .any(|message| {
                    message.message_id == message_id
                        && canonical_application_id(&message.application_id) == app_id
                });
            if !belongs_to_app {
                return Err(("message_not_found", "message was not found in this application's inbox".to_string()));
            }
            let message = mailbox
                .read_inbox(message_id)
                .await
                .map_err(|error| ("inbox_read_failed", error.to_string()))?;
            Ok(ProcessResult::Response(ApiResult::InboxMessage {
                message: ApiInboxMessage {
                    message_id_hex: hex::encode(message.message_id),
                    sender_main_dht: message.sender_main_dht.to_string(),
                    recipient_main_dht: message.recipient_main_dht.to_string(),
                    posted_at: message.posted_at,
                    received_at: message.received_at,
                    expires_at: message.expires_at,
                    conversation_id_hex: message.conversation_id.map(hex::encode),
                    payload_base64: BASE64.encode(message.plaintext),
                    read: message.read,
                },
            }))
        }
        ApiRequest::DeleteInbox {
            session_token,
            message_id_hex,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReceiveMessages)
                .map_err(identity_error)?;
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let message_id = decode_fixed::<32>(&message_id_hex, "invalid_message_id")?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            let belongs_to_app = mailbox
                .list_inbox()
                .await
                .map_err(|error| ("inbox_list_failed", error.to_string()))?
                .into_iter()
                .any(|message| {
                    message.message_id == message_id
                        && canonical_application_id(&message.application_id) == app_id
                });
            if !belongs_to_app {
                return Err(("message_not_found", "message was not found in this application's inbox".to_string()));
            }
            mailbox
                .delete_inbox(message_id)
                .await
                .map_err(|error| ("inbox_delete_failed", error.to_string()))?;
            Ok(ProcessResult::Response(ApiResult::InboxMessageDeleted {
                message_id_hex,
            }))
        }
        ApiRequest::GetNetworkDiagnostics { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SubscribeNetworkStatus)
                .map_err(identity_error)?;
            let walker = context
                .walk_task
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "network walker is unavailable".to_string()))?;
            let now = current_timestamp();
            let list = walker.get_internal_list_copy().await;
            let verified_nodes = list.entries.len();
            let candidate_nodes = list.candidates.len();
            let authenticated_nodes = list
                .entries
                .iter()
                .filter(|entry| entry.verification_state >= NodeVerificationState::Authenticated)
                .count();
            let online_nodes = list
                .entries
                .iter()
                .filter(|entry| {
                    entry.advertised_online
                        && entry.last_online != 0
                        && now.saturating_sub(entry.last_online) <= USER_PRESENCE_STALE_AFTER_SECS
                })
                .count();
            let seen_within_hour = list
                .entries
                .iter()
                .filter(|entry| entry.last_seen != 0 && now.saturating_sub(entry.last_seen) <= 60 * 60)
                .count();
            let seen_within_day = list
                .entries
                .iter()
                .filter(|entry| entry.last_seen != 0 && now.saturating_sub(entry.last_seen) <= 24 * 60 * 60)
                .count();
            let latest_walk_snapshot_count = walker.last_snapshots().await.len();
            let known_custodian_count = match &context.mailbox {
                Some(mailbox) => mailbox
                    .status()
                    .await
                    .map(|status| status.known_custodian_count)
                    .unwrap_or(0),
                None => 0,
            };
            Ok(ProcessResult::Response(ApiResult::NetworkDiagnostics {
                sampled_at: now,
                discovered_total: verified_nodes.saturating_add(candidate_nodes),
                verified_nodes,
                candidate_nodes,
                authenticated_nodes,
                online_nodes,
                offline_or_stale_nodes: verified_nodes.saturating_sub(online_nodes),
                seen_within_hour,
                seen_within_day,
                latest_walk_snapshot_count,
                known_custodian_count,
            }))
        }
        ApiRequest::StartDiagnosticWalk { session_token, hop_count } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SubscribeNetworkStatus)
                .map_err(identity_error)?;
            if !(1..=50).contains(&hop_count) {
                return Err((
                    "invalid_hop_count",
                    "diagnostic hop_count must be between 1 and 50".to_string(),
                ));
            }
            let walker = context
                .walk_task
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "network walker is unavailable".to_string()))?;
            let config = WalkConfig::random(hop_count)
                .with_event_reason(format!("manual diagnostic walk for {}", session.app_id()));
            let already_running = match walker
                .start_walk(config)
                .await
                .map_err(|error| ("walk_failed", error.to_string()))?
            {
                WalkStartResult::Started(_) => false,
                WalkStartResult::AlreadyRunning(_) => true,
            };
            Ok(ProcessResult::Response(ApiResult::DiagnosticWalkStarted {
                requested_hops: hop_count,
                already_running,
            }))
        }
        ApiRequest::PostMailboxProbe {
            session_token,
            recipient_main_dht,
            payload_base64,
            expires_at,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let recipient_main_dht = recipient_main_dht
                .parse::<RecordKey>()
                .map_err(|error| ("invalid_recipient", error.to_string()))?;
            let plaintext = BASE64
                .decode(payload_base64.as_bytes())
                .map_err(|error| ("invalid_payload", error.to_string()))?;
            if plaintext.len() > MAX_API_MESSAGE_BYTES {
                return Err((
                    "message_too_large",
                    format!("message payload exceeds {} bytes", MAX_API_MESSAGE_BYTES),
                ));
            }
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let app_mailbox = mailbox
                .authenticated_app_handle(&session)
                .map_err(|error| ("mailbox_auth_failed", error.to_string()))?;
            let application_id = canonical_application_id(&session.app_id().to_string());
            let posted_at = current_timestamp();
            let message_id = app_mailbox
                .submit_outgoing_message(OutgoingMessageRequest {
                    application_id: application_id.clone(),
                    recipient_main_dht: recipient_main_dht.clone(),
                    plaintext,
                    expires_at,
                    conversation_id: None,
                    proposed_conversation_dht: None,
                    await_response: false,
                })
                .await
                .map_err(|error| ("mailbox_probe_failed", error.to_string()))?;
            context
                .mailbox_probe_ids
                .lock()
                .await
                .entry(application_id.clone())
                .or_default()
                .insert(message_id);
            crate::tprintln!(
                "[api] Mailbox probe queued: app={} recipient={} message={}",
                application_id,
                recipient_main_dht,
                hex::encode(message_id)
            );
            Ok(ProcessResult::Response(ApiResult::MailboxProbeQueued {
                message_id_hex: hex::encode(message_id),
                posted_at,
            }))
        }
        ApiRequest::GetMailboxProbeStatus {
            session_token,
            message_id_hex,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let message_id = decode_fixed::<32>(&message_id_hex, "invalid_message_id")?;
            let application_id = canonical_application_id(&session.app_id().to_string());
            let allowed = context
                .mailbox_probe_ids
                .lock()
                .await
                .get(&application_id)
                .is_some_and(|ids| ids.contains(&message_id));
            if !allowed {
                return Err((
                    "unknown_probe",
                    "that mailbox probe was not created by this authenticated app session".to_string(),
                ));
            }
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let report = mailbox
                .observation_report(message_id)
                .await
                .map_err(|error| ("mailbox_probe_status_failed", error.to_string()))?
                .map(ApiMailboxObservationReport::from);
            Ok(ProcessResult::Response(ApiResult::MailboxProbeStatus { report }))
        }
        ApiRequest::ListMailboxProbeReports { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SendMessages)
                .map_err(identity_error)?;
            let application_id = canonical_application_id(&session.app_id().to_string());
            let ids = context
                .mailbox_probe_ids
                .lock()
                .await
                .get(&application_id)
                .cloned()
                .unwrap_or_default();
            let mailbox = context
                .mailbox
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "mailbox service is unavailable".to_string()))?;
            let reports = mailbox
                .observation_reports()
                .await
                .map_err(|error| ("mailbox_probe_status_failed", error.to_string()))?
                .into_iter()
                .filter(|report| ids.contains(&report.message_id))
                .map(ApiMailboxObservationReport::from)
                .collect();
            Ok(ProcessResult::Response(ApiResult::MailboxProbeReports { reports }))
        }
        ApiRequest::SubscribeMessages { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReceiveMessages)
                .map_err(identity_error)?;
            let app_id = session.app_id().clone();
            let (live, pending) = context
                .app_messages
                .subscribe_and_snapshot(&app_id.to_string())
                .await;
            Ok(ProcessResult::SubscribeMessages {
                app_id,
                pending,
                live,
            })
        }
        ApiRequest::RequestAppRegistration {
            app_id,
            display_name,
            requested_capabilities,
            request_token_hex,
        } => {
            let app_id = AppId::new(app_id).map_err(|error| ("invalid_app_id", error.to_string()))?;
            if context
                .identities
                .list_apps()
                .await
                .into_iter()
                .any(|registration| registration.app_id == app_id)
            {
                return Err((
                    "app_already_registered",
                    format!(
                        "application {} is already registered; use app-rotate if its credential was lost",
                        app_id
                    ),
                ));
            }
            let request_token = decode_fixed::<32>(
                &request_token_hex,
                "invalid_registration_token",
            )?;
            let requested = AppCapabilitySet::new(requested_capabilities);
            let pending = context
                .registrations
                .request(app_id, display_name, requested, request_token)
                .await?;
            crate::tprintln!(
                "[api] Application authorization requested: #{} {} ({})",
                pending.request_id,
                pending.app_id,
                pending.display_name
            );
            Ok(ProcessResult::Response(ApiResult::AppRegistrationPending {
                request_id: pending.request_id,
                app_id: pending.app_id,
                display_name: pending.display_name,
                requested_at: pending.requested_at,
                expires_at: pending.expires_at,
            }))
        }
        ApiRequest::GetAppRegistrationStatus {
            registration_request_id,
            request_token_hex,
        } => {
            let request_token = decode_fixed::<32>(
                &request_token_hex,
                "invalid_registration_token",
            )?;
            let result = match context
                .registrations
                .status(registration_request_id, &request_token)
                .await?
            {
                RegistrationStatusSnapshot::Pending => {
                    ApiResult::AppRegistrationStillPending { request_id: registration_request_id }
                }
                RegistrationStatusSnapshot::Approved {
                    credential,
                    summary,
                } => ApiResult::AppRegistrationApproved {
                    protocol_version: LOCAL_API_PROTOCOL_VERSION,
                    endpoint: context.endpoint.clone(),
                    app_id: credential.app_id.to_string(),
                    display_name: summary.display_name,
                    secret_hex: hex::encode(credential.secret_bytes()),
                    credential_generation: credential.credential_generation,
                },
                RegistrationStatusSnapshot::Rejected(reason) => {
                    ApiResult::AppRegistrationRejected { request_id: registration_request_id, reason }
                }
                RegistrationStatusSnapshot::Expired => {
                    ApiResult::AppRegistrationExpired { request_id: registration_request_id }
                }
            };
            Ok(ProcessResult::Response(result))
        }
        ApiRequest::GetAppSigningIdentity { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SignAppData)
                .map_err(identity_error)?;
            let signing = context
                .app_signing
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app signing service is unavailable".to_string()))?;
            let identity = signing
                .identity(&session, &context.main_dht)
                .await
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::AppSigningIdentity { identity }))
        }
        ApiRequest::RotateAppSigningKey { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SignAppData)
                .map_err(identity_error)?;
            let signing = context
                .app_signing
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app signing service is unavailable".to_string()))?;
            let identity = signing
                .rotate(&session, &context.main_dht)
                .await
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::AppSigningIdentity { identity }))
        }
        ApiRequest::SignAppPayload {
            session_token,
            domain,
            payload_base64,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SignAppData)
                .map_err(identity_error)?;
            let payload = BASE64
                .decode(payload_base64)
                .map_err(|error| ("invalid_payload", error.to_string()))?;
            let signing = context
                .app_signing
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app signing service is unavailable".to_string()))?;
            let signature = signing
                .sign(&session, domain, &payload)
                .await
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::AppPayloadSigned { signature }))
        }
        ApiRequest::VerifyAppSignature {
            session_token,
            public_key_hex,
            domain,
            payload_base64,
            signature_hex,
        } => {
            let _session = authenticate_token(&context.identities, &session_token).await?;
            let public_key = decode_fixed::<32>(&public_key_hex, "invalid_public_key")?;
            let signature = decode_fixed::<64>(&signature_hex, "invalid_signature")?;
            let payload = BASE64
                .decode(payload_base64)
                .map_err(|error| ("invalid_payload", error.to_string()))?;
            let valid = AppSigningManager::verify(&public_key, &domain, &payload, &signature)
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::AppSignatureVerified { valid }))
        }
        ApiRequest::ListAppStores { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReadOwnStorage)
                .map_err(identity_error)?;
            let storage = context
                .app_storage
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app storage service is unavailable".to_string()))?;
            let stores = storage.list_stores(&session).await;
            Ok(ProcessResult::Response(ApiResult::AppStores { stores }))
        }
        ApiRequest::CreateAppStore {
            session_token,
            name,
            subkey_count,
            initialize,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ManageOwnStorage)
                .map_err(identity_error)?;
            let storage = context
                .app_storage
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app storage service is unavailable".to_string()))?;
            let store = storage
                .create_store(&session, name, subkey_count, initialize)
                .await
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::AppStoreCreated { store }))
        }
        ApiRequest::ReadAppStore {
            session_token,
            store_id,
            locations,
            force_refresh,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReadOwnStorage)
                .map_err(identity_error)?;
            let storage = context
                .app_storage
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app storage service is unavailable".to_string()))?;
            let (store, values) = storage
                .read_own(&session, &store_id, locations, force_refresh)
                .await
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::AppStoreRead { store, values }))
        }
        ApiRequest::WriteAppStore {
            session_token,
            store_id,
            expected_generation,
            writes,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ManageOwnStorage)
                .map_err(identity_error)?;
            let writes = writes
                .into_iter()
                .map(|write| {
                    BASE64
                        .decode(write.value_base64)
                        .map(|value| (write.location, value))
                        .map_err(|error| ("invalid_store_value", error.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let storage = context
                .app_storage
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app storage service is unavailable".to_string()))?;
            let store = storage
                .write_own(&session, &store_id, expected_generation, writes)
                .await
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::AppStoreWritten { store }))
        }
        ApiRequest::ReadPublicStore {
            session_token,
            record_key,
            locations,
            force_refresh,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ReadPublicProfiles)
                .map_err(identity_error)?;
            let parsed: RecordKey = record_key
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let storage = context
                .app_storage
                .as_ref()
                .ok_or_else(|| ("service_unavailable", "app storage service is unavailable".to_string()))?;
            let values = storage
                .read_public(parsed, locations, force_refresh)
                .await
                .map_err(app_service_error)?;
            Ok(ProcessResult::Response(ApiResult::PublicStoreRead { record_key, values }))
        }
        ApiRequest::PutPrivateValue { session_token, key, value_base64, retention, ttl_seconds } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let value = BASE64.decode(value_base64).map_err(|e| ("invalid_private_value", e.to_string()))?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let value = storage.put_value(&session, &key, &value, retention, ttl_seconds).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateValueStored { value }))
        }
        ApiRequest::GetPrivateValue { session_token, key } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReadOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            match storage.get_value(&session, &key).await.map_err(private_storage_error)? {
                Some((value, bytes)) => Ok(ProcessResult::Response(ApiResult::PrivateValueRead { value, value_base64: BASE64.encode(bytes) })),
                None => Ok(ProcessResult::Response(ApiResult::PrivateValueMissing { key })),
            }
        }
        ApiRequest::ListPrivateValues { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReadOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let values = storage.list_values(&session).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateValues { values }))
        }
        ApiRequest::DeletePrivateValue { session_token, key } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let deleted = storage.delete_value(&session, &key).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateValueDeleted { key, deleted }))
        }
        ApiRequest::RenewPrivateValue { session_token, key, retention, ttl_seconds } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let value = storage.renew_value(&session, &key, retention, ttl_seconds).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateValueRenewed { value }))
        }
        ApiRequest::BeginPrivateBlob { session_token, content_type, retention, ttl_seconds } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let blob = storage.begin_blob(&session, &content_type, retention, ttl_seconds).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobStarted { blob }))
        }
        ApiRequest::AppendPrivateBlob { session_token, blob_id, data_base64 } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let data = BASE64.decode(data_base64).map_err(|e| ("invalid_private_blob_data", e.to_string()))?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let blob = storage.append_blob(&session, &blob_id, &data).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobAppended { blob }))
        }
        ApiRequest::FinishPrivateBlob { session_token, blob_id } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let blob = storage.finish_blob(&session, &blob_id).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobFinished { blob }))
        }
        ApiRequest::AbortPrivateBlob { session_token, blob_id } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let aborted = storage.abort_blob(&session, &blob_id).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobAborted { blob_id, aborted }))
        }
        ApiRequest::ListPrivateBlobs { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReadOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let blobs = storage.list_blobs(&session).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobs { blobs }))
        }
        ApiRequest::DeletePrivateBlob { session_token, blob_id } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let deleted = storage.delete_blob(&session, &blob_id).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobDeleted { blob_id, deleted }))
        }
        ApiRequest::ReadPrivateBlobRange { session_token, blob_id, offset, length } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReadOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let (blob, data) = storage.read_blob_range(&session, &blob_id, offset, length).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobRangeRead { blob, offset, data_base64: BASE64.encode(data) }))
        }
        ApiRequest::RenewPrivateBlob { session_token, blob_id, retention, ttl_seconds } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let blob = storage.renew_blob(&session, &blob_id, retention, ttl_seconds).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateBlobRenewed { blob }))
        }
        ApiRequest::GetPrivateStorageUsage { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReadOwnStorage).map_err(identity_error)?;
            let storage = context.private_storage.as_ref().ok_or_else(|| ("service_unavailable", "private app storage is unavailable".to_string()))?;
            let usage = storage.usage(&session).await.map_err(private_storage_error)?;
            Ok(ProcessResult::Response(ApiResult::PrivateStorageUsage { usage }))
        }
        ApiRequest::BeginBlobUpload { session_token, content_type } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let blobs = context.blob_store.as_ref().ok_or_else(|| (
                "service_unavailable", "blob store service is unavailable".to_string()
            ))?;
            let upload = blobs.begin_upload(&session, content_type).await.map_err(blob_store_error)?;
            Ok(ProcessResult::Response(ApiResult::BlobUploadStarted { upload }))
        }
        ApiRequest::AppendBlobUpload { session_token, upload_id, data_base64 } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let data = BASE64.decode(data_base64).map_err(|e| ("invalid_blob_data", e.to_string()))?;
            let blobs = context.blob_store.as_ref().ok_or_else(|| (
                "service_unavailable", "blob store service is unavailable".to_string()
            ))?;
            let upload = blobs.append(&session, &upload_id, &data).await.map_err(blob_store_error)?;
            Ok(ProcessResult::Response(ApiResult::BlobUploadAppended { upload }))
        }
        ApiRequest::FinishBlobUpload { session_token, upload_id, expected_sha256_hex } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let expected = expected_sha256_hex
                .map(|value| decode_fixed::<32>(&value, "invalid_blob_hash"))
                .transpose()?;
            let blobs = context.blob_store.as_ref().ok_or_else(|| (
                "service_unavailable", "blob store service is unavailable".to_string()
            ))?;
            let blob = blobs.finish(&session, &upload_id, expected).await.map_err(blob_store_error)?;
            Ok(ProcessResult::Response(ApiResult::BlobUploadFinished { blob }))
        }
        ApiRequest::AbortBlobUpload { session_token, upload_id } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let blobs = context.blob_store.as_ref().ok_or_else(|| (
                "service_unavailable", "blob store service is unavailable".to_string()
            ))?;
            blobs.abort(&session, &upload_id).await.map_err(blob_store_error)?;
            Ok(ProcessResult::Response(ApiResult::BlobUploadAborted { upload_id }))
        }
        ApiRequest::ListBlobs { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReadOwnStorage).map_err(identity_error)?;
            let blobs = context.blob_store.as_ref().ok_or_else(|| (
                "service_unavailable", "blob store service is unavailable".to_string()
            ))?;
            Ok(ProcessResult::Response(ApiResult::Blobs { blobs: blobs.list(&session).await }))
        }
        ApiRequest::DeleteBlob { session_token, blob_id } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            let blobs = context.blob_store.as_ref().ok_or_else(|| ("service_unavailable", "blob store service is unavailable".to_string()))?;
            blobs.delete(&session, &blob_id).await.map_err(blob_store_error)?;
            Ok(ProcessResult::Response(ApiResult::BlobDeleted { blob_id }))
        }
        ApiRequest::ReadBlobRange { session_token, root_record_key, offset, length, force_refresh } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReadPublicProfiles).map_err(identity_error)?;
            let parsed: RecordKey = root_record_key.parse()
                .map_err(|e| ("invalid_record_key", format!("{e:?}")))?;
            let blobs = context.blob_store.as_ref().ok_or_else(|| (
                "service_unavailable", "blob store service is unavailable".to_string()
            ))?;
            let (blob, data) = blobs.read_public_range(parsed, offset, length, force_refresh)
                .await.map_err(blob_store_error)?;
            Ok(ProcessResult::Response(ApiResult::BlobRangeRead {
                blob, offset, data_base64: BASE64.encode(data),
            }))
        }
        ApiRequest::StartStream { session_token, opaque_metadata_base64 } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            session.require_capability(AppCapability::ManageOwnStorage).map_err(identity_error)?;
            session.require_capability(AppCapability::SignAppData).map_err(identity_error)?;
            let metadata = BASE64.decode(opaque_metadata_base64)
                .map_err(|error| ("invalid_stream_metadata", error.to_string()))?;
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            let descriptor = streams.start_stream(&session, metadata).await.map_err(stream_transport_error)?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            if let Err(error) = context
                .gossip
                .publish_system_record(&app_id, stream_gossip_record(&descriptor))
                .await
            {
                crate::teprintln!("[stream] Could not publish gossip discovery hint: {error}");
            }
            Ok(ProcessResult::Response(ApiResult::StreamStarted { descriptor }))
        }
        ApiRequest::JoinStream { session_token, descriptor, relay_capacity } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            session.require_capability(AppCapability::ReadPublicProfiles).map_err(identity_error)?;
            let stream_id = descriptor.stream_id.clone();
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            streams.join_stream(&session, descriptor, relay_capacity).await.map_err(stream_transport_error)?;
            Ok(ProcessResult::Response(ApiResult::StreamJoinPending { stream_id }))
        }
        ApiRequest::WriteStream { session_token, stream_id, data_base64 } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            let data = BASE64.decode(data_base64)
                .map_err(|error| ("invalid_stream_data", error.to_string()))?;
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            let result = streams.write_stream(&session, &stream_id, &data).await.map_err(stream_transport_error)?;
            Ok(ProcessResult::Response(ApiResult::StreamWriteAccepted { result }))
        }
        ApiRequest::FlushStream { session_token, stream_id } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            let commitment = streams.flush_stream(&session, &stream_id).await.map_err(stream_transport_error)?;
            Ok(ProcessResult::Response(ApiResult::StreamFlushed { commitment }))
        }
        ApiRequest::LeaveStream { session_token, stream_id } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            streams.leave_stream(&session, &stream_id).await.map_err(stream_transport_error)?;
            Ok(ProcessResult::Response(ApiResult::StreamLeft { stream_id }))
        }
        ApiRequest::CloseStream { session_token, stream_id, reason } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::SendMessages).map_err(identity_error)?;
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            streams.close_stream(
                &session,
                &stream_id,
                reason.unwrap_or_else(|| "closed by the source application".to_string()),
            ).await.map_err(stream_transport_error)?;
            let app_id = canonical_application_id(&session.app_id().to_string());
            if let Err(error) = context
                .gossip
                .withdraw_system(&app_id, GOSSIP_ENGINE_NAMESPACE_STREAMS, &stream_id, None)
                .await
            {
                crate::teprintln!("[stream] Could not withdraw gossip discovery hint: {error}");
            }
            Ok(ProcessResult::Response(ApiResult::StreamClosed { stream_id }))
        }
        ApiRequest::ListStreams { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            Ok(ProcessResult::Response(ApiResult::Streams {
                streams: streams.list_streams(&session).await,
            }))
        }
        ApiRequest::SubscribeStreams { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session.require_capability(AppCapability::ReceiveMessages).map_err(identity_error)?;
            let streams = context.stream_transport.as_ref().ok_or_else(|| (
                "service_unavailable", "stream transport is unavailable".to_string()
            ))?;
            Ok(ProcessResult::SubscribeStreams {
                app_id: session.app_id().to_string(),
                live: streams.subscribe(),
            })
        }
        ApiRequest::SubmitReputationObservation {
            session_token,
            subject_main_dht,
            kind,
            application_code,
            description,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SubmitReputation)
                .map_err(identity_error)?;
            let subject: RecordKey = subject_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let handle = session
                .reputation_handle(&context.reputation)
                .map_err(identity_error)?;
            let observation_id = handle
                .submit_observation(ObservationInput {
                    subject,
                    kind,
                    details: ObservationDetails {
                        application_code,
                        description,
                    },
                })
                .await
                .map_err(reputation_error)?;
            Ok(ProcessResult::Response(ApiResult::ReputationObservationSubmitted {
                observation_id: observation_id.0,
            }))
        }
        ApiRequest::RetractReputationObservation {
            session_token,
            subject_main_dht,
            observation_id,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::InspectOwnReputationSubmissions)
                .map_err(identity_error)?;
            let subject: RecordKey = subject_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let handle = session
                .reputation_handle(&context.reputation)
                .map_err(identity_error)?;
            handle
                .retract_observation(subject, ObservationId(observation_id))
                .await
                .map_err(reputation_error)?;
            Ok(ProcessResult::Response(ApiResult::ReputationObservationRetracted))
        }
        ApiRequest::RequestAppRestriction {
            session_token,
            subject_main_dht,
            restriction_action,
            reason,
            expires_at,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::RequestAppScopedRestriction)
                .map_err(identity_error)?;
            let subject: RecordKey = subject_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let handle = session
                .reputation_handle(&context.reputation)
                .map_err(identity_error)?;
            let scope = BanScope::App(session.app_id().clone());
            let decision_id = match restriction_action {
                ApiRestrictionAction::Restrict => handle
                    .request_restriction(subject, scope, reason, expires_at)
                    .await,
                ApiRestrictionAction::Ban => handle
                    .request_ban(subject, scope, reason, expires_at)
                    .await,
            }
            .map_err(reputation_error)?;
            Ok(ProcessResult::Response(ApiResult::AppRestrictionRequested {
                decision_id: decision_id.0,
            }))
        }
        ApiRequest::RevokeAppDecision {
            session_token,
            subject_main_dht,
            decision_id,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::InspectOwnReputationSubmissions)
                .map_err(identity_error)?;
            let subject: RecordKey = subject_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let handle = session
                .reputation_handle(&context.reputation)
                .map_err(identity_error)?;
            handle
                .revoke_decision(subject, DecisionId(decision_id))
                .await
                .map_err(reputation_error)?;
            Ok(ProcessResult::Response(ApiResult::AppDecisionRevoked))
        }
        ApiRequest::GetReputationView {
            session_token,
            subject_main_dht,
        } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::SubmitReputation)
                .map_err(identity_error)?;
            let subject: RecordKey = subject_main_dht
                .parse()
                .map_err(|error| ("invalid_record_key", format!("{error:?}")))?;
            let handle = session
                .reputation_handle(&context.reputation)
                .map_err(identity_error)?;
            let view = handle.get_view(subject).await.map_err(reputation_error)?;
            Ok(ProcessResult::Response(ApiResult::ReputationView { view }))
        }
        ApiRequest::GetOwnReputationSubmissions { session_token } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::InspectOwnReputationSubmissions)
                .map_err(identity_error)?;
            let handle = session
                .reputation_handle(&context.reputation)
                .map_err(identity_error)?;
            let report = handle
                .get_own_source_report()
                .await
                .map_err(reputation_error)?;
            Ok(ProcessResult::Response(ApiResult::OwnReputationSubmissions { report }))
        }
        ApiRequest::SaveSessionLog { session_token, path } => {
            let session = authenticate_token(&context.identities, &session_token).await?;
            session
                .require_capability(AppCapability::ManageApplications)
                .map_err(identity_error)?;
            let saved = console_log::save_session_log(path.as_deref())
                .map_err(|error| ("log_save_failed", error.to_string()))?;
            Ok(ProcessResult::Response(ApiResult::SessionLogSaved {
                path: saved.path.display().to_string(),
                lines: saved.lines,
            }))
        }
    }
}

fn spawn_application_message_bridges(
    mailbox: Option<Arc<MailboxManager>>,
    handshake: Arc<Mutex<HandshakeManager>>,
    hub: Arc<AppMessageHub>,
    our_main_dht: String,
    shutdown: watch::Receiver<bool>,
) {
    if let Some(mailbox) = mailbox {
        let mut events = mailbox.subscribe();
        let hub = hub.clone();
        let mut shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    event = events.recv() => match event {
                        Ok(MailboxEvent::MailDecrypted(message)) => {
                            hub.publish(ApiApplicationMessage {
                                application_id: message.application_id,
                                message_id_hex: hex::encode(message.message.message_id),
                                sender_main_dht: message.message.sender_main_dht.to_string(),
                                recipient_main_dht: message.message.recipient_main_dht.to_string(),
                                posted_at: message.message.posted_at,
                                expires_at: message.message.expires_at,
                                delivery_kind: "mailbox",
                                conversation_id_hex: message.message.conversation_id.map(hex::encode),
                                payload_base64: BASE64.encode(message.plaintext),
                            }).await;
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            crate::teprintln!("[api] Mailbox inbox bridge lagged by {skipped} event(s)");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        });
    }

    let mut shutdown = shutdown;
    tokio::spawn(async move {
        let (mut events, mut gossip_events) = {
            let manager = handshake.lock().await;
            (
                manager.subscribe_application_messages(),
                manager.subscribe_gossip_messages(),
            )
        };
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                event = events.recv() => match event {
                    Ok(message) if message.application_id == STREAM_INTERNAL_APPLICATION_ID => {}
                    Ok(message) => {
                        hub.publish(ApiApplicationMessage {
                            application_id: message.application_id,
                            message_id_hex: hex::encode(message.message_id),
                            sender_main_dht: message.sender_dht,
                            recipient_main_dht: our_main_dht.clone(),
                            posted_at: message.sent_at,
                            expires_at: message.sent_at.saturating_add(10 * 60),
                            delivery_kind: "direct",
                            conversation_id_hex: None,
                            payload_base64: BASE64.encode(message.payload),
                        }).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::teprintln!("[api] Direct inbox bridge lagged by {skipped} event(s)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                event = gossip_events.recv() => match event {
                    Ok(message) if crate::gossip::is_engine_frame(&message.payload) => {}
                    Ok(message) => {
                        let (delivery_kind, conversation_id_hex, payload) =
                            match decode_service_reply_payload(&message.payload) {
                                Some((request_id, payload)) => (
                                    "service_reply",
                                    Some(hex::encode(request_id)),
                                    payload,
                                ),
                                None => ("gossip", None, message.payload),
                            };
                        hub.publish(ApiApplicationMessage {
                            application_id: message.application_id,
                            message_id_hex: hex::encode(message.message_id),
                            sender_main_dht: message.sender_dht,
                            recipient_main_dht: our_main_dht.clone(),
                            posted_at: message.sent_at,
                            expires_at: message.sent_at.saturating_add(10 * 60),
                            delivery_kind,
                            conversation_id_hex,
                            payload_base64: BASE64.encode(payload),
                        }).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        crate::teprintln!("[api] Gossip inbox bridge lagged by {skipped} event(s)");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    });
}

fn decode_api_gossip_publish(
    application_id: &str,
    object: ApiGossipPublishObject,
) -> Result<GossipPublishRequest, (&'static str, String)> {
    let mut fingerprints = Vec::with_capacity(object.fingerprints.len());
    for fingerprint in object.fingerprints {
        let bytes = BASE64
            .decode(fingerprint.bytes_base64)
            .map_err(|error| ("invalid_gossip_fingerprint", error.to_string()))?;
        fingerprints.push(GossipFingerprint {
            channel: fingerprint.channel,
            algorithm: fingerprint.algorithm,
            version: fingerprint.version,
            bytes,
        });
    }
    let mut index_tokens: Vec<GossipIndexToken> = Vec::new();
    for index in &object.indexes {
        let derived = derive_index_tokens(
            application_id,
            &object.namespace,
            &index.index,
            index.terms.iter().map(String::as_str),
        )
        .map_err(|error| ("invalid_gossip_index", error.to_string()))?;
        for token in derived {
            if !index_tokens.contains(&token) {
                index_tokens.push(token);
            }
        }
        if index_tokens.len() > GOSSIP_MAX_INDEX_TOKENS {
            return Err((
                "invalid_gossip_index",
                format!("at most {GOSSIP_MAX_INDEX_TOKENS} unique index tokens are allowed"),
            ));
        }
    }
    let custom_payload = if object.custom_payload_base64.is_empty() {
        Vec::new()
    } else {
        BASE64
            .decode(object.custom_payload_base64)
            .map_err(|error| ("invalid_gossip_payload", error.to_string()))?
    };
    Ok(GossipPublishRequest {
        namespace: object.namespace,
        object_id: object.object_id,
        generation: object.generation,
        authoritative_pointer: object.authoritative_pointer,
        fingerprints,
        index_tokens,
        custom_payload,
        flags: object.flags,
        ttl_seconds: object.ttl_seconds,
    })
}

fn decode_api_gossip_query(
    application_id: &str,
    query: ApiGossipSearchQuery,
) -> Result<GossipSearchQuery, (&'static str, String)> {
    let mut probes = Vec::with_capacity(query.probes.len());
    for probe in query.probes {
        let bytes = BASE64
            .decode(probe.bytes_base64)
            .map_err(|error| ("invalid_gossip_probe", error.to_string()))?;
        probes.push(GossipFingerprintProbe {
            channel: probe.channel,
            algorithm: probe.algorithm,
            version: probe.version,
            bytes,
            weight: probe.weight,
            polarity: probe.polarity,
        });
    }
    let mut token_probes = Vec::with_capacity(query.token_probes.len());
    for probe in query.token_probes {
        let tokens = derive_index_tokens(
            application_id,
            &query.namespace,
            &probe.index,
            probe.terms.iter().map(String::as_str),
        )
        .map_err(|error| ("invalid_gossip_index", error.to_string()))?;
        token_probes.push(GossipTokenProbe {
            tokens,
            polarity: probe.polarity,
            match_mode: probe.match_mode,
            weight: probe.weight,
        });
    }
    Ok(GossipSearchQuery {
        namespace: query.namespace,
        probes,
        token_probes,
        limit: query.limit,
        min_score_milli: query.min_score_milli,
        include_withdrawn: query.include_withdrawn,
    })
}

fn lexical_error(error: LexicalError) -> (&'static str, String) {
    let code = match error {
        LexicalError::InvalidInput(_) => "invalid_lexical_input",
        LexicalError::LibraryNotFound => "lexical_library_not_found",
        LexicalError::Storage(_) => "lexical_storage_error",
        LexicalError::Dht(_) => "lexical_dht_error",
        LexicalError::Gossip(_) => "lexical_gossip_error",
    };
    (code, error.to_string())
}

fn gossip_error(error: GossipError) -> (&'static str, String) {
    let code = match error {
        GossipError::InvalidApplicationId => "invalid_gossip_application",
        GossipError::InvalidNamespace | GossipError::ReservedNamespace => "invalid_gossip_namespace",
        GossipError::InvalidObjectId => "invalid_gossip_object_id",
        GossipError::InvalidPointer => "invalid_gossip_pointer",
        GossipError::TooManyFingerprints | GossipError::InvalidFingerprint(_) => "invalid_gossip_fingerprint",
        GossipError::TooManyIndexTokens | GossipError::InvalidIndex(_) => "invalid_gossip_index",
        GossipError::CustomPayloadTooLarge => "gossip_payload_too_large",
        GossipError::InvalidTtl => "invalid_gossip_ttl",
        GossipError::InvalidQuery(_) => "invalid_gossip_query",
        GossipError::ObjectNotFound => "gossip_object_not_found",
        GossipError::GenerationMismatch => "gossip_generation_mismatch",
        GossipError::NotLocallyPublished => "gossip_object_not_owned",
        GossipError::Wire(_) => "gossip_wire_error",
        GossipError::Transport(_) => "gossip_transport_failed",
    };
    (code, error.to_string())
}

fn stream_gossip_record(descriptor: &StreamDescriptor) -> GossipRecord {
    GossipRecord {
        namespace: GOSSIP_ENGINE_NAMESPACE_STREAMS.to_string(),
        object_id: descriptor.stream_id.clone(),
        generation: descriptor.generation,
        origin_main_dht: descriptor.streamer_main_dht.clone(),
        published_at: descriptor.created_at,
        expires_at: current_timestamp().saturating_add(GOSSIP_MAX_TTL_SECS),
        authoritative_pointer: Some(descriptor.commitment_root_record_key.clone()),
        fingerprints: Vec::new(),
        index_tokens: Vec::new(),
        custom_payload: Vec::new(),
        flags: 0,
        withdrawn: false,
    }
}

fn application_message_key(message: &ApiApplicationMessage) -> String {
    format!(
        "{}\0{}\0{}",
        message.application_id, message.sender_main_dht, message.message_id_hex
    )
}

fn remove_arrival_marker(
    arrival_order: &mut VecDeque<(String, String)>,
    app_id: &str,
    key: &str,
) {
    if let Some(position) = arrival_order
        .iter()
        .position(|(queued_app, queued_key)| queued_app == app_id && queued_key == key)
    {
        arrival_order.remove(position);
    }
}

async fn try_gossip_route_send(
    handshake: Arc<Mutex<HandshakeManager>>,
    route_blob: Vec<u8>,
    application_id: String,
    payload: Vec<u8>,
) -> Result<[u8; 16], String> {
    HandshakeManager::send_gossip_application_message_to_route_shared(
        handshake,
        route_blob,
        application_id,
        payload,
    )
    .await
    .map_err(|error| error.to_string())
}

async fn try_gossip_send(
    handshake: Arc<Mutex<HandshakeManager>>,
    recipient: String,
    application_id: String,
    payload: Vec<u8>,
) -> Result<[u8; 16], String> {
    HandshakeManager::send_gossip_application_message_shared(
        handshake,
        recipient,
        application_id,
        payload,
    )
    .await
    .map_err(|error| error.to_string())
}

async fn try_direct_send(
    handshake: Arc<Mutex<HandshakeManager>>,
    recipient: String,
    application_id: String,
    payload: Vec<u8>,
) -> Result<[u8; 16], String> {
    let already_established = handshake
        .lock()
        .await
        .is_persistent_established(&recipient);
    if !already_established {
        {
            let mut manager = handshake.lock().await;
            manager
                .initiate_persistent_handshake(recipient.clone())
                .await
                .map_err(|error| error.to_string())?;
        }
        for _ in 0..15 {
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            if handshake.lock().await.is_established(&recipient) {
                break;
            }
        }
        if handshake.lock().await.is_established(&recipient) {
            // The initiator marks its side established immediately after the
            // final control packet is sent. Give the responder a brief chance
            // to process that packet before application data follows it.
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    let manager = handshake.lock().await;
    manager
        .send_application_message(&recipient, &application_id, payload)
        .await
        .map_err(|error| error.to_string())
}

async fn write_application_event<W: AsyncWrite + Unpin>(
    writer: &mut W,
    event: ApiApplicationMessage,
) -> io::Result<()> {
    write_json_line(
        writer,
        &ApiApplicationEventMessage {
            protocol_version: LOCAL_API_PROTOCOL_VERSION,
            stream: "application_messages",
            event,
        },
    )
    .await
}

async fn authenticate_token(
    identities: &IdentityManager,
    token_hex: &str,
) -> Result<crate::identity_manager::AuthenticatedAppSession, (&'static str, String)> {
    let token = AppSessionToken::from_bytes(decode_fixed::<32>(
        token_hex,
        "invalid_session_token",
    )?);
    identities
        .authenticate_session(&token)
        .await
        .map_err(identity_error)
}

fn decode_fixed<const N: usize>(
    value: &str,
    code: &'static str,
) -> Result<[u8; N], (&'static str, String)> {
    let bytes = hex::decode(value).map_err(|error| (code, error.to_string()))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| (code, format!("expected {N} bytes, received {}", bytes.len())))
}

fn identity_error(error: crate::identity_manager::IdentityError) -> (&'static str, String) {
    ("authentication_failed", error.to_string())
}

fn private_storage_error(error: PrivateStorageError) -> (&'static str, String) {
    ("private_storage_error", error.to_string())
}

fn blob_store_error(error: BlobStoreError) -> (&'static str, String) {
    let code = match error {
        BlobStoreError::InvalidUploadId => "invalid_blob_upload_id",
        BlobStoreError::UploadNotFound | BlobStoreError::BlobNotFound => "blob_not_found",
        BlobStoreError::UploadAlreadyFinished => "blob_upload_finished",
        BlobStoreError::InvalidContentType => "invalid_content_type",
        BlobStoreError::EmptyAppend | BlobStoreError::AppendTooLarge(_) => "invalid_blob_append",
        BlobStoreError::BlobTooLarge(_) | BlobStoreError::TooManySegments => "blob_too_large",
        BlobStoreError::IntegrityMismatch => "blob_integrity_mismatch",
        BlobStoreError::RangeOutsideBlob => "invalid_blob_range",
        BlobStoreError::InvalidManifest(_) => "invalid_blob_manifest",
        BlobStoreError::Persistence(_) | BlobStoreError::Storage(_) => "blob_store_error",
    };
    (code, error.to_string())
}
fn stream_transport_error(error: StreamTransportError) -> (&'static str, String) {
    let code = match error {
        StreamTransportError::InvalidStreamId => "invalid_stream_id",
        StreamTransportError::StreamNotFound => "stream_not_found",
        StreamTransportError::StreamAlreadyClosed => "stream_closed",
        StreamTransportError::NotStreamOwner => "stream_not_owned",
        StreamTransportError::InvalidDescriptor(_) => "invalid_stream_descriptor",
        StreamTransportError::InvalidMetadata => "invalid_stream_metadata",
        StreamTransportError::InvalidCloseReason => "invalid_stream_close_reason",
        StreamTransportError::EmptyWrite => "empty_stream_write",
        StreamTransportError::WriteTooLarge(_) => "stream_write_too_large",
        StreamTransportError::ViewerLimitReached => "stream_viewer_limit",
        StreamTransportError::CommitmentBacklogFull => "stream_commitment_backlog_full",
        StreamTransportError::JoinRejected(_) => "stream_join_rejected",
        StreamTransportError::Transport(_) => "stream_transport_failed",
        StreamTransportError::Storage(_) => "stream_commitment_storage_failed",
        StreamTransportError::Serialization(_) => "stream_serialization_failed",
        StreamTransportError::Integrity(_) => "stream_integrity_failed",
    };
    (code, error.to_string())
}


fn app_service_error(error: AppServiceError) -> (&'static str, String) {
    ("app_service_error", error.to_string())
}

fn reputation_error(error: crate::reputation::ReputationError) -> (&'static str, String) {
    ("reputation_error", error.to_string())
}

async fn write_ok<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    request_id: u64,
    result: T,
) -> io::Result<()> {
    write_json_line(
        writer,
        &ApiResponseEnvelope {
            protocol_version: LOCAL_API_PROTOCOL_VERSION,
            request_id,
            ok: true,
            result: Some(result),
            error: None,
        },
    )
    .await
}

async fn write_error<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u64,
    code: &'static str,
    message: String,
) -> io::Result<()> {
    write_json_line(
        writer,
        &ApiResponseEnvelope::<()> {
            protocol_version: LOCAL_API_PROTOCOL_VERSION,
            request_id,
            ok: false,
            result: None,
            error: Some(ApiErrorBody { code, message }),
        },
    )
    .await
}

async fn write_json_line<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

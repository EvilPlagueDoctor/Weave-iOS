//! High-level Rust SDK for applications connected to the Daemon Network.
//!
//! Most applications only need [`NetworkApp`], [`NetworkIdentity`], and
//! [`MessageStream`]. The SDK discovers the daemon endpoint, locates stored
//! credentials, performs challenge-response authentication, and chooses the
//! daemon's live or offline delivery path automatically.
//!
//! ```no_run
//! use daemon_network_sdk::{ClientError, NetworkApp};
//!
//! # async fn example() -> Result<(), ClientError> {
//! let app = NetworkApp::connect("example.hello").await?;
//! println!("Connected as {}", app.local_user().identity);
//! # Ok(())
//! # }
//! ```

use std::{
    fmt,
    path::{Path, PathBuf},
    pin::Pin,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures::{stream, StreamExt};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, Lines,
};

pub const PROTOCOL_VERSION: u16 = 3;
const PROOF_DOMAIN: &[u8] = b"veilknit/app-auth/v2";

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite + ?Sized> AsyncReadWrite for T {}
type IpcStream = Pin<Box<dyn AsyncReadWrite + Send>>;

#[derive(Debug)]
pub enum ClientError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Hex(hex::FromHexError),
    Protocol { code: String, message: String },
    InvalidCredential(String),
    CredentialNotFound { app_id: String },
    DaemonEndpointNotFound,
    AuthorizationRequired(Box<AuthorizationRequest>),
    AuthorizationRejected(String),
    AuthorizationExpired(u64),
    AuthorizationTimedOut,
    InvalidIdentity(String),
    UnexpectedResponse(String),
    SubscriptionClosed,
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "IPC error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Hex(error) => write!(formatter, "hex error: {error}"),
            Self::Protocol { code, message } => write!(formatter, "API error {code}: {message}"),
            Self::InvalidCredential(message) => write!(formatter, "invalid credential: {message}"),
            Self::CredentialNotFound { app_id } => write!(
                formatter,
                "no stored credential was found for application {app_id}"
            ),
            Self::DaemonEndpointNotFound => write!(
                formatter,
                "the daemon endpoint could not be discovered; start the daemon first"
            ),
            Self::AuthorizationRequired(request) => write!(
                formatter,
                "application authorization is required; approve request #{} with `{}`",
                request.request_id(),
                request.approval_command()
            ),
            Self::AuthorizationRejected(reason) => {
                write!(formatter, "application authorization was rejected: {reason}")
            }
            Self::AuthorizationExpired(request_id) => write!(
                formatter,
                "application authorization request #{request_id} expired"
            ),
            Self::AuthorizationTimedOut => write!(formatter, "application authorization timed out"),
            Self::InvalidIdentity(message) => write!(formatter, "invalid network identity: {message}"),
            Self::UnexpectedResponse(message) => write!(formatter, "unexpected API response: {message}"),
            Self::SubscriptionClosed => write!(formatter, "message subscription closed"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<std::io::Error> for ClientError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<hex::FromHexError> for ClientError {
    fn from(value: hex::FromHexError) -> Self {
        Self::Hex(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialFile {
    pub protocol_version: u16,
    pub endpoint: String,
    pub app_id: String,
    pub display_name: String,
    pub secret_hex: String,
    pub credential_generation: u64,
}

impl CredentialFile {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let bytes = std::fs::read(path)?;
        let credential: Self = serde_json::from_slice(&bytes)?;
        if credential.protocol_version != PROTOCOL_VERSION {
            return Err(ClientError::InvalidCredential(format!(
                "credential targets protocol {}, client supports {}",
                credential.protocol_version, PROTOCOL_VERSION
            )));
        }
        let secret = hex::decode(&credential.secret_hex)?;
        if secret.len() != 32 {
            return Err(ClientError::InvalidCredential(format!(
                "secret must contain 32 bytes, found {}",
                secret.len()
            )));
        }
        Ok(credential)
    }

    /// Save this credential atomically enough for ordinary desktop use.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ClientError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        std::fs::write(&temporary, bytes)?;
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    fn secret(&self) -> Result<[u8; 32], ClientError> {
        let bytes = hex::decode(&self.secret_hex)?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            ClientError::InvalidCredential(format!(
                "secret must contain 32 bytes, found {}",
                bytes.len()
            ))
        })
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum AppCapability {
    SendMessages,
    ReceiveMessages,
    ManageOwnStorage,
    ReadOwnStorage,
    ReadPublicProfiles,
    SubscribeNetworkStatus,
    SubmitReputation,
    RequestAppScopedRestriction,
    InspectOwnReputationSubmissions,
    SignAppData,
    InspectNodes,
    InspectReputation,
    ModifyBans,
    RetractAppReputation,
    InspectDht,
    ControlWalker,
    ManageApplications,
}

#[derive(Debug, Clone)]
pub struct ApiSession {
    pub app_id: String,
    pub session_id: String,
    pub token_hex: String,
    pub authenticated_at: u64,
    pub expires_at: u64,
    pub capabilities: Vec<AppCapability>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LocalIdentity {
    /// Compatibility alias returned by older daemon API revisions.
    pub username: String,
    pub display_name: String,
    pub profile_id: String,
    pub main_dht: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MailboxStatus {
    pub mailbox_dht: Option<String>,
    pub mail_send_dht: Option<String>,
    pub mail_response_dht: String,
    pub receive_key_epoch: u64,
    pub pending_page_sets: usize,
    pub outgoing_message_count: usize,
    #[serde(default)]
    pub outgoing_service_request_count: usize,
    #[serde(default)]
    pub recent_service_request_count: usize,
    pub awaiting_response_count: usize,
    pub known_custodian_count: usize,
}

/// Receipt returned when the daemon publishes a short-lived, deliberately
/// public/delegatable service request through the mailbox layer.
#[derive(Debug, Clone)]
pub struct PublishedServiceRequest {
    pub request_id: [u8; 32],
    pub request_id_hex: String,
    pub expires_at: u64,
}

/// One verified public service-request hint discovered by the daemon.
///
/// The payload and reply route are intentionally public to mailbox custodians.
/// Applications must still verify the requester/widget/service policy before
/// acting on a delegated request.
#[derive(Debug, Clone, Deserialize)]
pub struct IncomingServiceRequest {
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

impl IncomingServiceRequest {
    pub fn request_id(&self) -> Result<[u8; 32], ClientError> {
        decode_fixed::<32>(&self.request_id_hex, "service request id")
    }

    pub fn service_id(&self) -> Result<[u8; 32], ClientError> {
        decode_fixed::<32>(&self.service_id_hex, "service id")
    }

    pub fn service_manifest_hash(&self) -> Result<[u8; 32], ClientError> {
        decode_fixed::<32>(&self.service_manifest_hash_hex, "service manifest hash")
    }

    pub fn instance_id(&self) -> Result<[u8; 32], ClientError> {
        decode_fixed::<32>(&self.instance_id_hex, "service instance id")
    }

    pub fn payload(&self) -> Result<Vec<u8>, ClientError> {
        BASE64.decode(&self.payload_base64).map_err(|error| {
            ClientError::UnexpectedResponse(format!("invalid service payload base64: {error}"))
        })
    }

    pub fn reply_route_blob(&self) -> Result<Vec<u8>, ClientError> {
        BASE64.decode(&self.reply_route_blob_base64).map_err(|error| {
            ClientError::UnexpectedResponse(format!("invalid service reply route base64: {error}"))
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppPeer {
    pub main_dht: String,
    pub first_discovered_at: u64,
    pub last_directly_verified_at: u64,
    pub last_returned_at: u64,
    pub return_count: u32,
    pub tier: String,
    #[serde(default)]
    pub app_root_dht: Option<String>,
    #[serde(default)]
    pub app_root_checked_at: u64,
    #[serde(default)]
    pub app_directory_generation: u64,
}

#[derive(Debug, Clone)]
pub struct AppRootRegistration {
    pub app_id: String,
    pub root_dht: Option<String>,
    pub directory_dht: String,
    pub generation: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone)]
pub struct AppRootLookup {
    pub app_id: String,
    pub peer_main_dht: String,
    pub root_dht: Option<String>,
    pub status: String,
    pub checked_at: u64,
    pub directory_generation: u64,
}

#[derive(Debug, Clone)]
pub struct AppPeerPage {
    pub app_id: String,
    pub sampled_at: u64,
    pub cache_generation: u64,
    pub total_cached: usize,
    pub peers: Vec<AppPeer>,
    pub search_state: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppActivityLevel {
    Inactive,
    Background,
    Interactive,
    Realtime,
}

#[derive(Debug, Clone)]
pub struct NodeRecommendationReport {
    pub submitted: usize,
    pub new_candidates: usize,
    pub already_known: usize,
    pub expires_at: u64,
}

#[derive(Debug, Clone)]
pub struct AppActivityLease {
    pub level: AppActivityLevel,
    pub expires_at: u64,
    pub effective_interval_secs: Option<u64>,
    pub effective_hops: usize,
    pub relevant_node_count: usize,
}

#[derive(Debug, Clone)]
pub struct SavedSessionLog {
    pub path: String,
    pub lines: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiInfo {
    pub protocol_version: u16,
    pub authentication_proof: String,
    pub features: Vec<String>,
    pub max_message_bytes: usize,
    pub max_store_value_bytes: usize,
    pub max_store_subkeys: u16,
    pub max_stores_per_app: usize,
    pub max_store_reads_per_request: usize,
    pub max_store_writes_per_request: usize,
    pub max_store_write_bytes_per_request: usize,
    pub max_signature_payload_bytes: usize,
    pub max_signature_domain_bytes: usize,
    pub max_blob_append_bytes: usize,
    pub max_blob_bytes: u64,
    pub max_stream_write_bytes: usize,
    pub stream_packet_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSigningIdentity {
    pub application_id: String,
    pub main_dht: String,
    pub key_generation: u64,
    pub public_key_hex: String,
    pub created_at: u64,
    pub binding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSignature {
    pub application_id: String,
    pub key_generation: u64,
    pub public_key_hex: String,
    pub domain: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStoreDescriptor {
    pub store_id: String,
    pub application_id: String,
    pub name: String,
    pub record_key: String,
    pub subkey_count: u16,
    pub generation: u64,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStoreValue {
    pub location: u32,
    pub value_base64: Option<String>,
    pub is_null: bool,
    pub error: Option<String>,
}

impl AppStoreValue {
    pub fn value(&self) -> Result<Option<Vec<u8>>, ClientError> {
        self.value_base64
            .as_deref()
            .map(|value| BASE64.decode(value).map_err(|error| {
                ClientError::UnexpectedResponse(format!("invalid store value base64: {error}"))
            }))
            .transpose()
    }
}

#[derive(Debug, Clone)]
pub struct AppStoreRead {
    pub store: AppStoreDescriptor,
    pub values: Vec<AppStoreValue>,
}

#[derive(Debug, Clone)]
pub struct PublicStoreRead {
    pub record_key: String,
    pub values: Vec<AppStoreValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateRetention {
    Persistent,
    Cache,
    Temporary,
    DeleteOnShutdown,
}

impl Default for PrivateRetention {
    fn default() -> Self { Self::Persistent }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateValueDescriptor {
    pub key: String,
    pub bytes: u64,
    pub retention: PrivateRetention,
    pub expires_at: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_accessed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateBlobDescriptor {
    pub blob_id: String,
    pub content_type: String,
    pub total_bytes: u64,
    pub chunk_count: usize,
    pub complete: bool,
    pub retention: PrivateRetention,
    pub expires_at: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_accessed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateStorageUsage {
    pub value_count: usize,
    pub value_bytes: u64,
    pub blob_count: usize,
    pub blob_bytes: u64,
    pub cache_bytes: u64,
    pub cache_limit_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct PrivateBlobRange {
    pub blob: PrivateBlobDescriptor,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobDescriptor {
    pub blob_id: String,
    pub root_record_key: String,
    pub content_type: String,
    pub total_bytes: u64,
    pub segment_count: u32,
    pub sha256_hex: String,
    pub created_at: u64,
    pub finalized_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobUploadStatus {
    pub upload_id: String,
    pub blob_id: String,
    pub root_record_key: String,
    pub content_type: String,
    pub committed_bytes: u64,
    pub segment_count: u32,
    pub finalized: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct BlobRange {
    pub blob: BlobDescriptor,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamDescriptor {
    pub version: u16,
    pub stream_id: String,
    pub application_id: String,
    pub streamer_main_dht: String,
    pub generation: u64,
    pub commitment_root_record_key: String,
    pub signing_public_key_hex: String,
    pub signing_key_generation: u64,
    pub opaque_metadata_base64: String,
    pub packet_bytes: u32,
    pub packets_per_segment: u32,
    pub created_at: u64,
    pub signature_hex: String,
}

impl StreamDescriptor {
    pub fn opaque_metadata(&self) -> Result<Vec<u8>, ClientError> {
        BASE64.decode(&self.opaque_metadata_base64).map_err(|error| {
            ClientError::UnexpectedResponse(format!("invalid stream metadata base64: {error}"))
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamRole {
    Streamer,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSummary {
    pub descriptor: StreamDescriptor,
    pub role: StreamRole,
    pub running: bool,
    pub viewer_count: usize,
    pub direct_child_count: usize,
    pub parent_main_dht: Option<String>,
    pub standby_parent_main_dht: Option<String>,
    pub next_sequence: u64,
    pub current_segment: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamWriteResult {
    pub stream_id: String,
    pub accepted_bytes: usize,
    pub emitted_packets: usize,
    pub audience_count: usize,
    pub transmitted: bool,
    pub next_sequence: u64,
    pub current_segment: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSegmentCommitment {
    pub segment_number: u64,
    pub first_sequence: u64,
    pub packet_count: u32,
    pub payload_bytes: u64,
    pub sha256: [u8; 32],
    pub previous_commitment_hash: [u8; 32],
    pub published_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamCommitmentHint {
    pub stream_id: String,
    pub generation: u64,
    pub segment_number: u64,
    pub record_key: String,
    pub page_location: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamEvent {
    Started {
        application_id: String,
        descriptor: StreamDescriptor,
    },
    JoinPending {
        application_id: String,
        stream_id: String,
        streamer_main_dht: String,
    },
    ViewerJoined {
        application_id: String,
        stream_id: String,
        viewer_main_dht: String,
        parent_main_dht: String,
        viewer_count: usize,
    },
    Joined {
        application_id: String,
        descriptor: StreamDescriptor,
        parent_main_dht: String,
        standby_parent_main_dht: Option<String>,
    },
    TopologyChanged {
        application_id: String,
        stream_id: String,
        parent_main_dht: Option<String>,
        child_count: usize,
    },
    Data {
        application_id: String,
        stream_id: String,
        generation: u64,
        sequence: u64,
        segment_number: u64,
        packet_index: u32,
        retransmission: bool,
        payload_base64: String,
    },
    SegmentCommitted {
        application_id: String,
        stream_id: String,
        commitment: StreamSegmentCommitment,
        hint: StreamCommitmentHint,
    },
    SegmentVerified {
        application_id: String,
        stream_id: String,
        segment_number: u64,
        sha256_hex: String,
    },
    SegmentMissingPackets {
        application_id: String,
        stream_id: String,
        segment_number: u64,
        missing_packet_indices: Vec<u32>,
    },
    IntegrityFailure {
        application_id: String,
        stream_id: String,
        segment_number: u64,
        detail: String,
    },
    ViewerLeft {
        application_id: String,
        stream_id: String,
        viewer_main_dht: String,
        viewer_count: usize,
    },
    Ended {
        application_id: String,
        stream_id: String,
        reason: String,
    },
    Warning {
        application_id: String,
        stream_id: String,
        detail: String,
    },
}

impl StreamEvent {
    pub fn data(&self) -> Result<Option<Vec<u8>>, ClientError> {
        match self {
            Self::Data { payload_base64, .. } => BASE64
                .decode(payload_base64)
                .map(Some)
                .map_err(|error| {
                    ClientError::UnexpectedResponse(format!(
                        "invalid stream packet base64: {error}"
                    ))
                }),
            _ => Ok(None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppStoreWrite {
    pub location: u32,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AppRestrictionAction {
    Restrict,
    Ban,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum ObservationKind {
    InteractionSucceeded,
    InteractionFailed,
    UsefulService,
    ExcessiveActivity,
    RepetitiveActivity,
    SuspiciousCoordination,
    MessageDelivered,
    MessageRejected,
    UnsolicitedMessage,
    Spam,
    Harassment,
    ValidDhtResponse,
    InvalidDhtResponse,
    InvalidSignature,
    ImpossibleProtocolState,
    MalformedProtocolMessage,
    DeliberateStateCorruption,
    FutureTimestampClaim,
    ConflictingAccountCreationClaim,
    SuspiciousCreationBurst,
    Reachable,
    Unreachable,
    StableAvailability,
    AppBanRequested,
    UserMarkedHarmful,
    UserMarkedTrusted,
    HandshakeUnavailable,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IncomingApplicationMessage {
    pub application_id: String,
    pub message_id_hex: String,
    pub sender_main_dht: String,
    pub recipient_main_dht: String,
    pub posted_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub delivery_kind: Option<String>,
    pub conversation_id_hex: Option<String>,
    pub payload_base64: String,
}

impl IncomingApplicationMessage {
    pub fn payload(&self) -> Result<Vec<u8>, ClientError> {
        BASE64.decode(&self.payload_base64).map_err(|error| {
            ClientError::UnexpectedResponse(format!("invalid payload base64: {error}"))
        })
    }
}

#[derive(Clone)]
pub struct NetworkApiClient {
    endpoint: String,
    session: ApiSession,
    next_request_id: std::sync::Arc<AtomicU64>,
}

impl NetworkApiClient {
    pub async fn authenticate(
        credential: &CredentialFile,
        requested_capabilities: Vec<AppCapability>,
    ) -> Result<Self, ClientError> {
        let next_request_id = std::sync::Arc::new(AtomicU64::new(1));
        let begin_id = next_request_id.fetch_add(1, Ordering::Relaxed);
        let begin = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": begin_id,
            "action": "begin_authentication",
            "app_id": credential.app_id,
            "requested_capabilities": requested_capabilities,
        });
        let begin_response = send_request(&credential.endpoint, &begin).await?;
        let challenge = match begin_response.result {
            Some(ApiResult::AuthenticationChallenge {
                app_id,
                challenge_id,
                nonce_hex,
                issued_at,
                expires_at,
                credential_generation,
                requested_capabilities,
            }) => AuthChallenge {
                app_id,
                challenge_id,
                nonce: decode_fixed::<32>(&nonce_hex, "challenge nonce")?,
                issued_at,
                expires_at,
                credential_generation,
                requested_capabilities,
            },
            other => {
                return Err(ClientError::UnexpectedResponse(format!(
                    "expected authentication challenge, received {other:?}"
                )))
            }
        };
        if challenge.app_id != credential.app_id {
            return Err(ClientError::InvalidCredential(
                "challenge app id does not match credential".to_string(),
            ));
        }
        if challenge.credential_generation != credential.credential_generation {
            return Err(ClientError::InvalidCredential(format!(
                "credential generation {} does not match daemon generation {}",
                credential.credential_generation, challenge.credential_generation
            )));
        }
        let proof = compute_proof(&credential.secret()?, &challenge);
        let finish_id = next_request_id.fetch_add(1, Ordering::Relaxed);
        let finish = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": finish_id,
            "action": "finish_authentication",
            "app_id": credential.app_id,
            "challenge_id": challenge.challenge_id,
            "proof_hex": hex::encode(proof),
        });
        let finish_response = send_request(&credential.endpoint, &finish).await?;
        let session = match finish_response.result {
            Some(ApiResult::AuthenticationSucceeded {
                app_id,
                session_id,
                session_token_hex,
                authenticated_at,
                expires_at,
                capabilities,
            }) => ApiSession {
                app_id,
                session_id,
                token_hex: session_token_hex,
                authenticated_at,
                expires_at,
                capabilities,
            },
            other => {
                return Err(ClientError::UnexpectedResponse(format!(
                    "expected authentication success, received {other:?}"
                )))
            }
        };
        Ok(Self {
            endpoint: credential.endpoint.clone(),
            session,
            next_request_id,
        })
    }

    pub fn session(&self) -> &ApiSession {
        &self.session
    }

    pub async fn ping(endpoint: &str) -> Result<(), ClientError> {
        let request = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": 1,
            "action": "ping",
        });
        let response = send_request(endpoint, &request).await?;
        match response.result {
            Some(ApiResult::Pong) => Ok(()),
            other => Err(ClientError::UnexpectedResponse(format!(
                "expected pong, received {other:?}"
            ))),
        }
    }

    pub async fn api_info(endpoint: &str) -> Result<ApiInfo, ClientError> {
        let request = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": 1,
            "action": "get_api_info",
        });
        match send_request(endpoint, &request).await?.into_result()? {
            ApiResult::ApiInfo {
                protocol_version,
                authentication_proof,
                features,
                max_message_bytes,
                max_store_value_bytes,
                max_store_subkeys,
                max_stores_per_app,
                max_store_reads_per_request,
                max_store_writes_per_request,
                max_store_write_bytes_per_request,
                max_signature_payload_bytes,
                max_signature_domain_bytes,
                max_blob_append_bytes,
                max_blob_bytes,
                max_stream_write_bytes,
                stream_packet_bytes,
                ..
            } => Ok(ApiInfo {
                protocol_version,
                authentication_proof,
                features,
                max_message_bytes,
                max_store_value_bytes,
                max_store_subkeys,
                max_stores_per_app,
                max_store_reads_per_request,
                max_store_writes_per_request,
                max_store_write_bytes_per_request,
                max_signature_payload_bytes,
                max_signature_domain_bytes,
                max_blob_append_bytes,
                max_blob_bytes,
                max_stream_write_bytes,
                stream_packet_bytes,
            }),
            other => Err(unexpected("API information", other)),
        }
    }

    pub async fn identity(&self) -> Result<LocalIdentity, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "get_identity",
                "session_token": self.session.token_hex,
            }))
            .await?;
        match result {
            ApiResult::Identity {
                username,
                display_name,
                profile_id,
                main_dht,
            } => Ok(LocalIdentity {
                username,
                display_name,
                profile_id,
                main_dht,
            }),
            other => Err(unexpected("identity", other)),
        }
    }

    pub async fn network_status(&self) -> Result<serde_json::Value, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "get_status",
                "session_token": self.session.token_hex,
            }))
            .await?;
        match result {
            ApiResult::Status { status } => Ok(status),
            other => Err(unexpected("network status", other)),
        }
    }

    pub async fn save_session_log(
        &self,
        path: Option<&str>,
    ) -> Result<SavedSessionLog, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "save_session_log",
                "session_token": self.session.token_hex,
                "path": path,
            }))
            .await?;
        match result {
            ApiResult::SessionLogSaved { path, lines } => {
                Ok(SavedSessionLog { path, lines })
            }
            other => Err(unexpected("saved session log", other)),
        }
    }

    pub async fn subscribe_network_events(
        &self,
    ) -> Result<NetworkEventSubscription, ClientError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "action": "subscribe_events",
            "session_token": self.session.token_hex,
        });
        let mut stream = connect(&self.endpoint).await?;
        write_json_line(&mut stream, &request).await?;
        let mut lines = BufReader::new(stream).lines();
        let ack_line = lines
            .next_line()
            .await?
            .ok_or(ClientError::SubscriptionClosed)?;
        let ack: ApiResponseEnvelope = serde_json::from_str(&ack_line)?;
        match ack.into_result()? {
            ApiResult::EventSubscriptionStarted => Ok(NetworkEventSubscription { lines }),
            other => Err(unexpected("event subscription acknowledgement", other)),
        }
    }

    pub async fn send_message(
        &self,
        recipient_main_dht: &str,
        payload: &[u8],
        conversation_id: Option<&[u8; 32]>,
        expires_at: Option<u64>,
        await_response: bool,
    ) -> Result<String, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "send_message",
                "session_token": self.session.token_hex,
                "recipient_main_dht": recipient_main_dht,
                "payload_base64": BASE64.encode(payload),
                "conversation_id_hex": conversation_id.map(hex::encode),
                "expires_at": expires_at,
                "await_response": await_response,
            }))
            .await?;
        match result {
            ApiResult::MessageQueued { message_id_hex } => Ok(message_id_hex),
            other => Err(unexpected("message queued", other)),
        }
    }

    /// Send a best-effort, handshake-free application gossip datagram. The
    /// remote daemon exposes it as `delivery_kind = gossip`; it is not an
    /// authenticated VeilKnit handshake message and must be DHT-confirmed by
    /// the application before being treated as authoritative.
    pub async fn send_gossip_message(
        &self,
        recipient_main_dht: &str,
        payload: &[u8],
    ) -> Result<String, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "send_gossip",
                "session_token": self.session.token_hex,
                "recipient_main_dht": recipient_main_dht,
                "payload_base64": BASE64.encode(payload),
            }))
            .await?;
        match result {
            ApiResult::MessageQueued { message_id_hex } => Ok(message_id_hex),
            other => Err(unexpected("gossip message queued", other)),
        }
    }

    /// Publish a short-lived, intentionally public mailbox service request.
    ///
    /// `service_id`, `service_manifest_hash`, and `instance_id` are opaque
    /// 32-byte application values. The daemon owns a disposable reply route
    /// for the lifetime of the request. Ordinary private mailbox messages are
    /// not affected by this API.
    pub async fn publish_service_request(
        &self,
        intended_host_main_dht: &str,
        service_id: &[u8; 32],
        service_manifest_hash: &[u8; 32],
        instance_id: &[u8; 32],
        payload: &[u8],
        delegation_allowed: bool,
        spectators_allowed: bool,
        ttl_seconds: Option<u64>,
    ) -> Result<PublishedServiceRequest, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "publish_service_request",
                "session_token": self.session.token_hex,
                "intended_host_main_dht": intended_host_main_dht,
                "service_id_hex": hex::encode(service_id),
                "service_manifest_hash_hex": hex::encode(service_manifest_hash),
                "instance_id_hex": hex::encode(instance_id),
                "payload_base64": BASE64.encode(payload),
                "delegation_allowed": delegation_allowed,
                "spectators_allowed": spectators_allowed,
                "ttl_seconds": ttl_seconds,
            }))
            .await?;
        match result {
            ApiResult::ServiceRequestPublished {
                request_id_hex,
                expires_at,
            } => {
                let request_id = decode_fixed::<32>(&request_id_hex, "service request id")?;
                Ok(PublishedServiceRequest {
                    request_id,
                    request_id_hex,
                    expires_at,
                })
            }
            other => Err(unexpected("service request published", other)),
        }
    }

    /// Withdraw one of this node's still-live public service requests.
    pub async fn withdraw_service_request(
        &self,
        request_id: &[u8; 32],
    ) -> Result<(), ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "withdraw_service_request",
                "session_token": self.session.token_hex,
                "request_id_hex": hex::encode(request_id),
            }))
            .await?;
        match result {
            ApiResult::ServiceRequestWithdrawn { request_id_hex }
                if request_id_hex == hex::encode(request_id) => Ok(()),
            other => Err(unexpected("service request withdrawn", other)),
        }
    }

    /// Send a best-effort reply to the disposable route embedded in a service
    /// request. The requester receives it on the normal application-message
    /// stream with `delivery_kind = service_reply` and the request ID as the
    /// conversation ID.
    pub async fn send_service_reply(
        &self,
        request_id: &[u8; 32],
        reply_route_blob: &[u8],
        payload: &[u8],
    ) -> Result<String, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "send_service_reply",
                "session_token": self.session.token_hex,
                "request_id_hex": hex::encode(request_id),
                "reply_route_blob_base64": BASE64.encode(reply_route_blob),
                "payload_base64": BASE64.encode(payload),
            }))
            .await?;
        match result {
            ApiResult::ServiceReplySent {
                request_id_hex,
                message_id_hex,
            } if request_id_hex == hex::encode(request_id) => Ok(message_id_hex),
            other => Err(unexpected("service reply sent", other)),
        }
    }

    /// Subscribe to one or more opaque service IDs. Initial cached matches are
    /// emitted first, followed by newly verified mailbox discoveries.
    pub async fn subscribe_service_requests(
        &self,
        service_ids: &[[u8; 32]],
    ) -> Result<ServiceRequestSubscription, ClientError> {
        if service_ids.is_empty() || service_ids.len() > 64 {
            return Err(ClientError::UnexpectedResponse(
                "service request subscription requires between 1 and 64 service ids".to_string(),
            ));
        }
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let service_ids_hex: Vec<String> = service_ids.iter().map(|id| hex::encode(id)).collect();
        let request = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "action": "subscribe_service_requests",
            "session_token": self.session.token_hex,
            "service_ids_hex": service_ids_hex,
        });
        let mut stream = connect(&self.endpoint).await?;
        write_json_line(&mut stream, &request).await?;
        let mut lines = BufReader::new(stream).lines();
        let ack_line = lines
            .next_line()
            .await?
            .ok_or(ClientError::SubscriptionClosed)?;
        let ack: ApiResponseEnvelope = serde_json::from_str(&ack_line)?;
        match ack.into_result()? {
            ApiResult::ServiceRequestSubscriptionStarted { service_ids_hex: ack_ids }
                if ack_ids.len() == service_ids.len() =>
            {
                Ok(ServiceRequestSubscription { lines })
            }
            other => Err(unexpected("service request subscription acknowledgement", other)),
        }
    }

    pub async fn trigger_message_retrieval(&self) -> Result<(), ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "trigger_message_retrieval",
                "session_token": self.session.token_hex,
            }))
            .await?;
        match result {
            ApiResult::MessageRetrievalScheduled => Ok(()),
            other => Err(unexpected("retrieval scheduled", other)),
        }
    }

    pub async fn mailbox_status(&self) -> Result<MailboxStatus, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "get_mailbox_status",
                "session_token": self.session.token_hex,
            }))
            .await?;
        match result {
            ApiResult::MailboxStatus {
                mailbox_dht,
                mail_send_dht,
                mail_response_dht,
                receive_key_epoch,
                pending_page_sets,
                outgoing_message_count,
                outgoing_service_request_count,
                recent_service_request_count,
                awaiting_response_count,
                known_custodian_count,
            } => Ok(MailboxStatus {
                mailbox_dht,
                mail_send_dht,
                mail_response_dht,
                receive_key_epoch,
                pending_page_sets,
                outgoing_message_count,
                outgoing_service_request_count,
                recent_service_request_count,
                awaiting_response_count,
                known_custodian_count,
            }),
            other => Err(unexpected("mailbox status", other)),
        }
    }

    /// Return up to 1,000 rotating, directly verified peers for this
    /// authenticated application. When `start_search` is true, the daemon also
    /// queues a Bloom-filter-guided discovery walk and returns immediately.
    pub async fn list_app_peers(
        &self,
        limit: usize,
        start_search: bool,
    ) -> Result<AppPeerPage, ClientError> {
        let result = self
            .request(serde_json::json!({
                "action": "list_app_peers",
                "session_token": self.session.token_hex,
                "limit": limit,
                "start_search": start_search,
            }))
            .await?;
        match result {
            ApiResult::AppPeers {
                app_id,
                sampled_at,
                cache_generation,
                total_cached,
                peers,
                search_state,
            } => Ok(AppPeerPage {
                app_id,
                sampled_at,
                cache_generation,
                total_cached,
                peers,
                search_state,
            }),
            other => Err(unexpected("app peer page", other)),
        }
    }

    /// Feed app-layer discoveries back to VeilKnit as unverified candidates.
    pub async fn recommend_nodes(
        &self,
        nodes: &[String],
        context: Option<&str>,
        ttl_seconds: u64,
    ) -> Result<NodeRecommendationReport, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "recommend_nodes",
                "session_token": self.session.token_hex,
                "nodes": nodes,
                "context": context,
                "ttl_seconds": ttl_seconds,
            }))
            .await?
        {
            ApiResult::NodesRecommended {
                submitted, new_candidates, already_known, expires_at,
            } => Ok(NodeRecommendationReport {
                submitted, new_candidates, already_known, expires_at,
            }),
            other => Err(unexpected("node recommendation report", other)),
        }
    }

    /// Request a renewable app-focused discovery lease from the daemon.
    pub async fn set_app_activity(
        &self,
        level: AppActivityLevel,
        relevant_nodes: &[String],
        lease_seconds: u64,
    ) -> Result<AppActivityLease, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "set_app_activity",
                "session_token": self.session.token_hex,
                "level": level,
                "relevant_nodes": relevant_nodes,
                "lease_seconds": lease_seconds,
            }))
            .await?
        {
            ApiResult::AppActivityLease {
                level, expires_at, effective_interval_secs, effective_hops, relevant_node_count,
            } => Ok(AppActivityLease {
                level, expires_at, effective_interval_secs, effective_hops, relevant_node_count,
            }),
            other => Err(unexpected("app activity lease", other)),
        }
    }

    /// Publish or replace this authenticated application's root DHT. The daemon
    /// derives the app id from the session token and owns the directory writer.
    pub async fn register_app_root(
        &self,
        root_dht: &str,
    ) -> Result<AppRootRegistration, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "register_app_root",
                "session_token": self.session.token_hex,
                "root_dht": root_dht,
            }))
            .await?
        {
            ApiResult::AppRootRegistered {
                app_id,
                root_dht,
                directory_dht,
                generation,
                updated_at,
            } => Ok(AppRootRegistration {
                app_id,
                root_dht: Some(root_dht),
                directory_dht,
                generation,
                updated_at,
            }),
            other => Err(unexpected("app root registration", other)),
        }
    }

    pub async fn clear_app_root(&self) -> Result<AppRootRegistration, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "clear_app_root",
                "session_token": self.session.token_hex,
            }))
            .await?
        {
            ApiResult::AppRootCleared {
                app_id,
                directory_dht,
                generation,
                updated_at,
            } => Ok(AppRootRegistration {
                app_id,
                root_dht: None,
                directory_dht,
                generation,
                updated_at,
            }),
            other => Err(unexpected("app root cleared", other)),
        }
    }

    /// Read the currently cached root state and optionally queue a lazy remote
    /// resolution. Queued/in-progress/queue-full states are intentionally
    /// non-blocking; call again later or use a subsequently returned AppPeer.
    pub async fn get_app_root(
        &self,
        peer_main_dht: &str,
        start_lookup: bool,
    ) -> Result<AppRootLookup, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "get_app_root",
                "session_token": self.session.token_hex,
                "peer_main_dht": peer_main_dht,
                "start_lookup": start_lookup,
            }))
            .await?
        {
            ApiResult::AppRoot {
                app_id,
                peer_main_dht,
                root_dht,
                status,
                checked_at,
                directory_generation,
            } => Ok(AppRootLookup {
                app_id,
                peer_main_dht,
                root_dht,
                status,
                checked_at,
                directory_generation,
            }),
            other => Err(unexpected("app root lookup", other)),
        }
    }

    pub async fn app_signing_identity(&self) -> Result<AppSigningIdentity, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "get_app_signing_identity",
                "session_token": self.session.token_hex,
            }))
            .await?
        {
            ApiResult::AppSigningIdentity { identity } => Ok(identity),
            other => Err(unexpected("app signing identity", other)),
        }
    }

    pub async fn rotate_app_signing_key(&self) -> Result<AppSigningIdentity, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "rotate_app_signing_key",
                "session_token": self.session.token_hex,
            }))
            .await?
        {
            ApiResult::AppSigningIdentity { identity } => Ok(identity),
            other => Err(unexpected("rotated app signing identity", other)),
        }
    }

    pub async fn sign_app_payload(
        &self,
        domain: &str,
        payload: &[u8],
    ) -> Result<AppSignature, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "sign_app_payload",
                "session_token": self.session.token_hex,
                "domain": domain,
                "payload_base64": BASE64.encode(payload),
            }))
            .await?
        {
            ApiResult::AppPayloadSigned { signature } => Ok(signature),
            other => Err(unexpected("app payload signature", other)),
        }
    }

    pub async fn verify_app_signature(
        &self,
        public_key_hex: &str,
        domain: &str,
        payload: &[u8],
        signature_hex: &str,
    ) -> Result<bool, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "verify_app_signature",
                "session_token": self.session.token_hex,
                "public_key_hex": public_key_hex,
                "domain": domain,
                "payload_base64": BASE64.encode(payload),
                "signature_hex": signature_hex,
            }))
            .await?
        {
            ApiResult::AppSignatureVerified { valid } => Ok(valid),
            other => Err(unexpected("signature verification", other)),
        }
    }

    pub async fn list_app_stores(&self) -> Result<Vec<AppStoreDescriptor>, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "list_app_stores",
                "session_token": self.session.token_hex,
            }))
            .await?
        {
            ApiResult::AppStores { stores } => Ok(stores),
            other => Err(unexpected("application stores", other)),
        }
    }

    pub async fn create_app_store(
        &self,
        name: &str,
        subkey_count: u16,
        initialize: bool,
    ) -> Result<AppStoreDescriptor, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "create_app_store",
                "session_token": self.session.token_hex,
                "name": name,
                "subkey_count": subkey_count,
                "initialize": initialize,
            }))
            .await?
        {
            ApiResult::AppStoreCreated { store } => Ok(store),
            other => Err(unexpected("created application store", other)),
        }
    }

    pub async fn read_app_store(
        &self,
        store_id: &str,
        locations: &[u32],
        force_refresh: bool,
    ) -> Result<AppStoreRead, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "read_app_store",
                "session_token": self.session.token_hex,
                "store_id": store_id,
                "locations": locations,
                "force_refresh": force_refresh,
            }))
            .await?
        {
            ApiResult::AppStoreRead { store, values } => Ok(AppStoreRead { store, values }),
            other => Err(unexpected("application store read", other)),
        }
    }

    pub async fn write_app_store(
        &self,
        store_id: &str,
        expected_generation: Option<u64>,
        writes: &[AppStoreWrite],
    ) -> Result<AppStoreDescriptor, ClientError> {
        let writes: Vec<_> = writes
            .iter()
            .map(|write| serde_json::json!({
                "location": write.location,
                "value_base64": BASE64.encode(&write.value),
            }))
            .collect();
        match self
            .request(serde_json::json!({
                "action": "write_app_store",
                "session_token": self.session.token_hex,
                "store_id": store_id,
                "expected_generation": expected_generation,
                "writes": writes,
            }))
            .await?
        {
            ApiResult::AppStoreWritten { store } => Ok(store),
            other => Err(unexpected("application store write", other)),
        }
    }

    pub async fn read_public_store(
        &self,
        record_key: &str,
        locations: &[u32],
        force_refresh: bool,
    ) -> Result<PublicStoreRead, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "read_public_store",
                "session_token": self.session.token_hex,
                "record_key": record_key,
                "locations": locations,
                "force_refresh": force_refresh,
            }))
            .await?
        {
            ApiResult::PublicStoreRead { record_key, values } => {
                Ok(PublicStoreRead { record_key, values })
            }
            other => Err(unexpected("public store read", other)),
        }
    }

    /// Store a small, local-only encrypted value in this account + APP_ID vault.
    pub async fn put_private_value(
        &self,
        key: &str,
        value: &[u8],
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateValueDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "put_private_value",
            "session_token": self.session.token_hex,
            "key": key,
            "value_base64": BASE64.encode(value),
            "retention": retention,
            "ttl_seconds": ttl_seconds,
        })).await? {
            ApiResult::PrivateValueStored { value } => Ok(value),
            other => Err(unexpected("private value stored", other)),
        }
    }

    pub async fn get_private_value(
        &self,
        key: &str,
    ) -> Result<Option<(PrivateValueDescriptor, Vec<u8>)>, ClientError> {
        match self.request(serde_json::json!({
            "action": "get_private_value",
            "session_token": self.session.token_hex,
            "key": key,
        })).await? {
            ApiResult::PrivateValueRead { value, value_base64 } => Ok(Some((
                value,
                BASE64.decode(value_base64).map_err(|e| ClientError::UnexpectedResponse(format!("invalid private value base64: {e}")))?,
            ))),
            ApiResult::PrivateValueMissing { .. } => Ok(None),
            other => Err(unexpected("private value read", other)),
        }
    }

    pub async fn list_private_values(&self) -> Result<Vec<PrivateValueDescriptor>, ClientError> {
        match self.request(serde_json::json!({
            "action": "list_private_values",
            "session_token": self.session.token_hex,
        })).await? {
            ApiResult::PrivateValues { values } => Ok(values),
            other => Err(unexpected("private value list", other)),
        }
    }

    pub async fn delete_private_value(&self, key: &str) -> Result<bool, ClientError> {
        match self.request(serde_json::json!({
            "action": "delete_private_value",
            "session_token": self.session.token_hex,
            "key": key,
        })).await? {
            ApiResult::PrivateValueDeleted { deleted, .. } => Ok(deleted),
            other => Err(unexpected("private value delete", other)),
        }
    }

    pub async fn renew_private_value(
        &self,
        key: &str,
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateValueDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "renew_private_value",
            "session_token": self.session.token_hex,
            "key": key,
            "retention": retention,
            "ttl_seconds": ttl_seconds,
        })).await? {
            ApiResult::PrivateValueRenewed { value } => Ok(value),
            other => Err(unexpected("private value renewal", other)),
        }
    }

    pub async fn begin_private_blob(
        &self,
        content_type: &str,
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateBlobDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "begin_private_blob",
            "session_token": self.session.token_hex,
            "content_type": content_type,
            "retention": retention,
            "ttl_seconds": ttl_seconds,
        })).await? {
            ApiResult::PrivateBlobStarted { blob } => Ok(blob),
            other => Err(unexpected("private blob start", other)),
        }
    }

    pub async fn append_private_blob(&self, blob_id: &str, data: &[u8]) -> Result<PrivateBlobDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "append_private_blob",
            "session_token": self.session.token_hex,
            "blob_id": blob_id,
            "data_base64": BASE64.encode(data),
        })).await? {
            ApiResult::PrivateBlobAppended { blob } => Ok(blob),
            other => Err(unexpected("private blob append", other)),
        }
    }

    pub async fn finish_private_blob(&self, blob_id: &str) -> Result<PrivateBlobDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "finish_private_blob",
            "session_token": self.session.token_hex,
            "blob_id": blob_id,
        })).await? {
            ApiResult::PrivateBlobFinished { blob } => Ok(blob),
            other => Err(unexpected("private blob finish", other)),
        }
    }

    pub async fn abort_private_blob(&self, blob_id: &str) -> Result<bool, ClientError> {
        match self.request(serde_json::json!({
            "action": "abort_private_blob",
            "session_token": self.session.token_hex,
            "blob_id": blob_id,
        })).await? {
            ApiResult::PrivateBlobAborted { aborted, .. } => Ok(aborted),
            other => Err(unexpected("private blob abort", other)),
        }
    }

    pub async fn delete_private_blob(&self, blob_id: &str) -> Result<bool, ClientError> {
        match self.request(serde_json::json!({
            "action": "delete_private_blob",
            "session_token": self.session.token_hex,
            "blob_id": blob_id,
        })).await? {
            ApiResult::PrivateBlobDeleted { deleted, .. } => Ok(deleted),
            other => Err(unexpected("private blob delete", other)),
        }
    }

    pub async fn list_private_blobs(&self) -> Result<Vec<PrivateBlobDescriptor>, ClientError> {
        match self.request(serde_json::json!({
            "action": "list_private_blobs",
            "session_token": self.session.token_hex,
        })).await? {
            ApiResult::PrivateBlobs { blobs } => Ok(blobs),
            other => Err(unexpected("private blob list", other)),
        }
    }

    pub async fn read_private_blob_range(
        &self,
        blob_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<PrivateBlobRange, ClientError> {
        match self.request(serde_json::json!({
            "action": "read_private_blob_range",
            "session_token": self.session.token_hex,
            "blob_id": blob_id,
            "offset": offset,
            "length": length,
        })).await? {
            ApiResult::PrivateBlobRangeRead { blob, offset, data_base64 } => Ok(PrivateBlobRange {
                blob,
                offset,
                data: BASE64.decode(data_base64).map_err(|e| ClientError::UnexpectedResponse(format!("invalid private blob range base64: {e}")))?,
            }),
            other => Err(unexpected("private blob range", other)),
        }
    }

    pub async fn renew_private_blob(
        &self,
        blob_id: &str,
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateBlobDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "renew_private_blob",
            "session_token": self.session.token_hex,
            "blob_id": blob_id,
            "retention": retention,
            "ttl_seconds": ttl_seconds,
        })).await? {
            ApiResult::PrivateBlobRenewed { blob } => Ok(blob),
            other => Err(unexpected("private blob renewal", other)),
        }
    }

    pub async fn private_storage_usage(&self) -> Result<PrivateStorageUsage, ClientError> {
        match self.request(serde_json::json!({
            "action": "get_private_storage_usage",
            "session_token": self.session.token_hex,
        })).await? {
            ApiResult::PrivateStorageUsage { usage } => Ok(usage),
            other => Err(unexpected("private storage usage", other)),
        }
    }

    /// Upload an in-memory blob to local encrypted storage in bounded chunks.
    pub async fn put_private_blob(
        &self,
        content_type: &str,
        data: &[u8],
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateBlobDescriptor, ClientError> {
        let started = self.begin_private_blob(content_type, retention, ttl_seconds).await?;
        let blob_id = started.blob_id.clone();
        let result = async {
            for chunk in data.chunks(256 * 1024) {
                self.append_private_blob(&blob_id, chunk).await?;
            }
            self.finish_private_blob(&blob_id).await
        }.await;
        if result.is_err() {
            let _ = self.abort_private_blob(&blob_id).await;
        }
        result
    }

    /// Start a resumable opaque-byte upload. The daemon does not inspect or
    /// decode the supplied content type; it is metadata for the application.
    pub async fn begin_blob_upload(&self, content_type: &str) -> Result<BlobUploadStatus, ClientError> {
        match self.request(serde_json::json!({
            "action": "begin_blob_upload",
            "session_token": self.session.token_hex,
            "content_type": content_type,
        })).await? {
            ApiResult::BlobUploadStarted { upload } => Ok(upload),
            other => Err(unexpected("blob upload start", other)),
        }
    }

    /// Append bytes to an upload. Large inputs should be sent in pieces no
    /// larger than the daemon's advertised `max_blob_append_bytes` value.
    pub async fn append_blob_upload(&self, upload_id: &str, data: &[u8]) -> Result<BlobUploadStatus, ClientError> {
        match self.request(serde_json::json!({
            "action": "append_blob_upload",
            "session_token": self.session.token_hex,
            "upload_id": upload_id,
            "data_base64": BASE64.encode(data),
        })).await? {
            ApiResult::BlobUploadAppended { upload } => Ok(upload),
            other => Err(unexpected("blob upload append", other)),
        }
    }

    /// Feed an asynchronous byte source into the blob store without loading
    /// the entire object into memory. The helper computes SHA-256 locally and
    /// asks the daemon to verify the final object before publishing it.
    pub async fn upload_blob_reader<R>(
        &self,
        content_type: &str,
        reader: &mut R,
    ) -> Result<BlobDescriptor, ClientError>
    where
        R: AsyncRead + Unpin,
    {
        let upload = self.begin_blob_upload(content_type).await?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 384 * 1024];
        loop {
            let read = reader.read(&mut buffer).await?;
            if read == 0 { break; }
            hasher.update(&buffer[..read]);
            if let Err(error) = self.append_blob_upload(&upload.upload_id, &buffer[..read]).await {
                let _ = self.abort_blob_upload(&upload.upload_id).await;
                return Err(error);
            }
        }
        let digest = hex::encode(hasher.finalize());
        self.finish_blob_upload(&upload.upload_id, Some(&digest)).await
    }

    pub async fn finish_blob_upload(
        &self,
        upload_id: &str,
        expected_sha256_hex: Option<&str>,
    ) -> Result<BlobDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "finish_blob_upload",
            "session_token": self.session.token_hex,
            "upload_id": upload_id,
            "expected_sha256_hex": expected_sha256_hex,
        })).await? {
            ApiResult::BlobUploadFinished { blob } => Ok(blob),
            other => Err(unexpected("blob upload finish", other)),
        }
    }

    pub async fn abort_blob_upload(&self, upload_id: &str) -> Result<(), ClientError> {
        match self.request(serde_json::json!({
            "action": "abort_blob_upload",
            "session_token": self.session.token_hex,
            "upload_id": upload_id,
        })).await? {
            ApiResult::BlobUploadAborted { .. } => Ok(()),
            other => Err(unexpected("blob upload abort", other)),
        }
    }

    pub async fn list_blobs(&self) -> Result<Vec<BlobDescriptor>, ClientError> {
        match self.request(serde_json::json!({
            "action": "list_blobs",
            "session_token": self.session.token_hex,
        })).await? {
            ApiResult::Blobs { blobs } => Ok(blobs),
            other => Err(unexpected("blob list", other)),
        }
    }

    /// Download a complete blob in bounded range requests. The daemon
    /// verifies the final digest when the complete object is read.
    pub async fn download_blob(&self, root_record_key: &str) -> Result<(BlobDescriptor, Vec<u8>), ClientError> {
        let metadata = self.read_blob_range(root_record_key, 0, 0, true).await?;
        let total = metadata.blob.total_bytes;
        if total > usize::MAX as u64 {
            return Err(ClientError::UnexpectedResponse("blob is too large for this process".into()));
        }
        // A single complete read lets the daemon verify SHA-256 across the
        // entire chain. Apps that need bounded memory should call
        // `read_blob_range` repeatedly and verify `sha256_hex` themselves.
        let complete = self.read_blob_range(root_record_key, 0, total, false).await?;
        Ok((complete.blob, complete.data))
    }

    pub async fn delete_blob(&self, blob_id: &str) -> Result<(), ClientError> {
        match self.request(serde_json::json!({
            "action": "delete_blob",
            "session_token": self.session.token_hex,
            "blob_id": blob_id,
        })).await? {
            ApiResult::BlobDeleted { .. } => Ok(()),
            other => Err(unexpected("blob delete", other)),
        }
    }

    pub async fn read_blob_range(
        &self,
        root_record_key: &str,
        offset: u64,
        length: u64,
        force_refresh: bool,
    ) -> Result<BlobRange, ClientError> {
        match self.request(serde_json::json!({
            "action": "read_blob_range",
            "session_token": self.session.token_hex,
            "root_record_key": root_record_key,
            "offset": offset,
            "length": length,
            "force_refresh": force_refresh,
        })).await? {
            ApiResult::BlobRangeRead { blob, offset, data_base64 } => Ok(BlobRange {
                blob,
                offset,
                data: BASE64.decode(data_base64).map_err(|e| {
                    ClientError::UnexpectedResponse(format!("invalid blob range base64: {e}"))
                })?,
            }),
            other => Err(unexpected("blob range", other)),
        }
    }

    /// Start an opaque live stream. The returned descriptor is safe to
    /// publish through the application's own room/profile protocol.
    pub async fn start_stream(
        &self,
        opaque_metadata: &[u8],
    ) -> Result<StreamDescriptor, ClientError> {
        match self.request(serde_json::json!({
            "action": "start_stream",
            "session_token": self.session.token_hex,
            "opaque_metadata_base64": BASE64.encode(opaque_metadata),
        })).await? {
            ApiResult::StreamStarted { descriptor } => Ok(descriptor),
            other => Err(unexpected("stream descriptor", other)),
        }
    }

    /// Request admission to a stream. Completion is reported through
    /// [`StreamSubscription`] because the streamer may need to establish or
    /// assign relay sessions first.
    pub async fn join_stream(
        &self,
        descriptor: &StreamDescriptor,
        relay_capacity: u16,
    ) -> Result<String, ClientError> {
        match self.request(serde_json::json!({
            "action": "join_stream",
            "session_token": self.session.token_hex,
            "descriptor": descriptor,
            "relay_capacity": relay_capacity,
        })).await? {
            ApiResult::StreamJoinPending { stream_id } => Ok(stream_id),
            other => Err(unexpected("stream join acknowledgement", other)),
        }
    }

    /// Feed opaque bytes into a live stream. When no viewer is present the
    /// daemon deliberately emits no route traffic.
    pub async fn write_stream(
        &self,
        stream_id: &str,
        data: &[u8],
    ) -> Result<StreamWriteResult, ClientError> {
        match self.request(serde_json::json!({
            "action": "write_stream",
            "session_token": self.session.token_hex,
            "stream_id": stream_id,
            "data_base64": BASE64.encode(data),
        })).await? {
            ApiResult::StreamWriteAccepted { result } => Ok(result),
            other => Err(unexpected("stream write result", other)),
        }
    }

    /// Publish a signed commitment for the current partial segment. Apps
    /// should call this at useful media/application boundaries or every few
    /// seconds; full 32-packet segments are committed automatically.
    pub async fn flush_stream(
        &self,
        stream_id: &str,
    ) -> Result<Option<StreamSegmentCommitment>, ClientError> {
        match self.request(serde_json::json!({
            "action": "flush_stream",
            "session_token": self.session.token_hex,
            "stream_id": stream_id,
        })).await? {
            ApiResult::StreamFlushed { commitment } => Ok(commitment),
            other => Err(unexpected("stream flush result", other)),
        }
    }

    pub async fn leave_stream(&self, stream_id: &str) -> Result<(), ClientError> {
        match self.request(serde_json::json!({
            "action": "leave_stream",
            "session_token": self.session.token_hex,
            "stream_id": stream_id,
        })).await? {
            ApiResult::StreamLeft { .. } => Ok(()),
            other => Err(unexpected("stream leave result", other)),
        }
    }

    pub async fn close_stream(
        &self,
        stream_id: &str,
        reason: Option<&str>,
    ) -> Result<(), ClientError> {
        match self.request(serde_json::json!({
            "action": "close_stream",
            "session_token": self.session.token_hex,
            "stream_id": stream_id,
            "reason": reason,
        })).await? {
            ApiResult::StreamClosed { .. } => Ok(()),
            other => Err(unexpected("stream close result", other)),
        }
    }

    pub async fn list_streams(&self) -> Result<Vec<StreamSummary>, ClientError> {
        match self.request(serde_json::json!({
            "action": "list_streams",
            "session_token": self.session.token_hex,
        })).await? {
            ApiResult::Streams { streams } => Ok(streams),
            other => Err(unexpected("stream list", other)),
        }
    }

    pub async fn subscribe_streams(&self) -> Result<StreamSubscription, ClientError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "action": "subscribe_streams",
            "session_token": self.session.token_hex,
        });
        let mut stream = connect(&self.endpoint).await?;
        write_json_line(&mut stream, &request).await?;
        let mut lines = BufReader::new(stream).lines();
        let ack_line = lines
            .next_line()
            .await?
            .ok_or(ClientError::SubscriptionClosed)?;
        let ack: ApiResponseEnvelope = serde_json::from_str(&ack_line)?;
        match ack.into_result()? {
            ApiResult::StreamSubscriptionStarted { app_id }
                if app_id == self.session.app_id =>
            {
                Ok(StreamSubscription { lines })
            }
            other => Err(unexpected("stream subscription acknowledgement", other)),
        }
    }

    pub async fn submit_reputation_observation(
        &self,
        subject: &NetworkIdentity,
        kind: ObservationKind,
        application_code: Option<u32>,
        description: Option<&str>,
    ) -> Result<u64, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "submit_reputation_observation",
                "session_token": self.session.token_hex,
                "subject_main_dht": subject.as_str(),
                "kind": kind,
                "application_code": application_code,
                "description": description,
            }))
            .await?
        {
            ApiResult::ReputationObservationSubmitted { observation_id } => Ok(observation_id),
            other => Err(unexpected("reputation observation id", other)),
        }
    }

    pub async fn retract_reputation_observation(
        &self,
        subject: &NetworkIdentity,
        observation_id: u64,
    ) -> Result<(), ClientError> {
        match self
            .request(serde_json::json!({
                "action": "retract_reputation_observation",
                "session_token": self.session.token_hex,
                "subject_main_dht": subject.as_str(),
                "observation_id": observation_id,
            }))
            .await?
        {
            ApiResult::ReputationObservationRetracted => Ok(()),
            other => Err(unexpected("reputation observation retraction", other)),
        }
    }

    pub async fn request_app_restriction(
        &self,
        subject: &NetworkIdentity,
        action: AppRestrictionAction,
        reason: &str,
        expires_at: Option<u64>,
    ) -> Result<u64, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "request_app_restriction",
                "session_token": self.session.token_hex,
                "subject_main_dht": subject.as_str(),
                "restriction_action": action,
                "reason": reason,
                "expires_at": expires_at,
            }))
            .await?
        {
            ApiResult::AppRestrictionRequested { decision_id } => Ok(decision_id),
            other => Err(unexpected("app restriction decision", other)),
        }
    }

    pub async fn revoke_app_decision(
        &self,
        subject: &NetworkIdentity,
        decision_id: u64,
    ) -> Result<(), ClientError> {
        match self
            .request(serde_json::json!({
                "action": "revoke_app_decision",
                "session_token": self.session.token_hex,
                "subject_main_dht": subject.as_str(),
                "decision_id": decision_id,
            }))
            .await?
        {
            ApiResult::AppDecisionRevoked => Ok(()),
            other => Err(unexpected("app decision revocation", other)),
        }
    }

    pub async fn reputation_view(
        &self,
        subject: &NetworkIdentity,
    ) -> Result<serde_json::Value, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "get_reputation_view",
                "session_token": self.session.token_hex,
                "subject_main_dht": subject.as_str(),
            }))
            .await?
        {
            ApiResult::ReputationView { view } => Ok(view),
            other => Err(unexpected("reputation view", other)),
        }
    }

    pub async fn own_reputation_submissions(&self) -> Result<serde_json::Value, ClientError> {
        match self
            .request(serde_json::json!({
                "action": "get_own_reputation_submissions",
                "session_token": self.session.token_hex,
            }))
            .await?
        {
            ApiResult::OwnReputationSubmissions { report } => Ok(report),
            other => Err(unexpected("own reputation submissions", other)),
        }
    }

    pub async fn subscribe_messages(&self) -> Result<MessageSubscription, ClientError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = serde_json::json!({
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "action": "subscribe_messages",
            "session_token": self.session.token_hex,
        });
        let mut stream = connect(&self.endpoint).await?;
        write_json_line(&mut stream, &request).await?;
        let mut lines = BufReader::new(stream).lines();
        let ack_line = lines
            .next_line()
            .await?
            .ok_or(ClientError::SubscriptionClosed)?;
        let ack: ApiResponseEnvelope = serde_json::from_str(&ack_line)?;
        match ack.into_result()? {
            ApiResult::ApplicationMessageSubscriptionStarted { app_id }
                if app_id == self.session.app_id =>
            {
                Ok(MessageSubscription { lines })
            }
            other => Err(unexpected("application-message subscription acknowledgement", other)),
        }
    }

    async fn request(&self, fields: serde_json::Value) -> Result<ApiResult, ClientError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut object = fields.as_object().cloned().ok_or_else(|| {
            ClientError::UnexpectedResponse("request fields must be a JSON object".to_string())
        })?;
        object.insert("protocol_version".to_string(), PROTOCOL_VERSION.into());
        object.insert("request_id".to_string(), request_id.into());
        send_request(&self.endpoint, &serde_json::Value::Object(object))
            .await?
            .into_result()
    }
}

pub struct MessageSubscription {
    lines: Lines<BufReader<IpcStream>>,
}

impl MessageSubscription {
    pub async fn next(&mut self) -> Result<IncomingApplicationMessage, ClientError> {
        loop {
            let line = self
                .lines
                .next_line()
                .await?
                .ok_or(ClientError::SubscriptionClosed)?;
            let event: ApplicationStreamEnvelope = serde_json::from_str(&line)?;
            if event.protocol_version != PROTOCOL_VERSION {
                return Err(ClientError::UnexpectedResponse(format!(
                    "stream protocol changed to {}",
                    event.protocol_version
                )));
            }
            if event.stream == "application_messages" {
                return Ok(event.event);
            }
        }
    }
}

/// Streaming subscription for deliberately public/delegatable service requests.
pub struct ServiceRequestSubscription {
    lines: Lines<BufReader<IpcStream>>,
}

impl ServiceRequestSubscription {
    pub async fn next(&mut self) -> Result<IncomingServiceRequest, ClientError> {
        loop {
            let line = self
                .lines
                .next_line()
                .await?
                .ok_or(ClientError::SubscriptionClosed)?;
            let event: ServiceRequestStreamEnvelope = serde_json::from_str(&line)?;
            if event.protocol_version != PROTOCOL_VERSION {
                return Err(ClientError::UnexpectedResponse(format!(
                    "stream protocol changed to {}",
                    event.protocol_version
                )));
            }
            if event.stream == "service_requests" {
                return Ok(event.event);
            }
        }
    }
}

pub struct StreamSubscription {
    lines: Lines<BufReader<IpcStream>>,
}

impl StreamSubscription {
    pub async fn next(&mut self) -> Result<StreamEvent, ClientError> {
        loop {
            let line = self
                .lines
                .next_line()
                .await?
                .ok_or(ClientError::SubscriptionClosed)?;
            let event: StreamEventEnvelope = serde_json::from_str(&line)?;
            if event.protocol_version != PROTOCOL_VERSION {
                return Err(ClientError::UnexpectedResponse(format!(
                    "stream protocol changed to {}",
                    event.protocol_version
                )));
            }
            if event.stream == "stream_events" {
                return Ok(event.event);
            }
        }
    }
}

pub struct NetworkEventSubscription {
    lines: Lines<BufReader<IpcStream>>,
}

impl NetworkEventSubscription {
    pub async fn next(&mut self) -> Result<serde_json::Value, ClientError> {
        loop {
            let line = self
                .lines
                .next_line()
                .await?
                .ok_or(ClientError::SubscriptionClosed)?;
            let event: NetworkStreamEnvelope = serde_json::from_str(&line)?;
            if event.protocol_version != PROTOCOL_VERSION {
                return Err(ClientError::UnexpectedResponse(format!(
                    "stream protocol changed to {}",
                    event.protocol_version
                )));
            }
            if event.stream == "network_events" {
                return Ok(event.event);
            }
        }
    }
}


/// An opaque network address used by applications.
///
/// The SDK deliberately keeps the underlying DHT record key as a validated
/// value instead of making every application manipulate free-form strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NetworkIdentity(String);

impl NetworkIdentity {
    /// Parse an identity copied from another user or returned by the daemon.
    pub fn parse(value: impl Into<String>) -> Result<Self, ClientError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ClientError::InvalidIdentity("identity is empty".to_string()));
        }
        if trimmed.len() > 1024 {
            return Err(ClientError::InvalidIdentity(
                "identity is longer than 1024 bytes".to_string(),
            ));
        }
        if trimmed.chars().any(char::is_whitespace) || !trimmed.contains(':') {
            return Err(ClientError::InvalidIdentity(
                "identity is not a typed network key".to_string(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Return the shareable textual form.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return a compact prefix suitable for logs and simple interfaces.
    pub fn short_id(&self) -> String {
        if self.0.chars().count() <= 20 {
            return self.0.clone();
        }
        format!("{}...", self.0.chars().take(17).collect::<String>())
    }
}

impl fmt::Display for NetworkIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for NetworkIdentity {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for NetworkIdentity {
    type Err = ClientError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// The currently logged-in daemon user.
#[derive(Debug, Clone)]
pub struct LocalUser {
    pub username: String,
    pub identity: NetworkIdentity,
}

/// Options for one application message.
#[derive(Debug, Clone, Default)]
pub struct MessageOptions {
    pub conversation_id: Option<[u8; 32]>,
    pub expires_at: Option<u64>,
    pub await_response: bool,
}

/// Confirmation that the daemon accepted a message for delivery.
#[derive(Debug, Clone)]
pub struct MessageReceipt {
    pub message_id: String,
    pub recipient: NetworkIdentity,
    pub conversation_id: Option<[u8; 32]>,
}

/// Receipt for a request/response conversation.
#[derive(Debug, Clone)]
pub struct RequestReceipt {
    pub message: MessageReceipt,
    pub conversation_id: [u8; 32],
}

/// One recipient's result from [`NetworkApp::broadcast`].
#[derive(Debug, Clone)]
pub struct BroadcastDelivery {
    pub recipient: NetworkIdentity,
    pub message_id: Option<String>,
    pub error: Option<String>,
}

impl BroadcastDelivery {
    pub fn succeeded(&self) -> bool {
        self.error.is_none()
    }
}

/// A high-level, fully decoded public service request.
#[derive(Debug, Clone)]
pub struct ServiceRequest {
    pub request_id: [u8; 32],
    pub requester: NetworkIdentity,
    pub intended_host: NetworkIdentity,
    pub service_id: [u8; 32],
    pub service_manifest_hash: [u8; 32],
    pub instance_id: [u8; 32],
    pub reply_route_blob: Vec<u8>,
    pub payload: Vec<u8>,
    pub delegation_allowed: bool,
    pub spectators_allowed: bool,
    pub posted_at: u64,
    pub expires_at: u64,
}

impl ServiceRequest {
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.payload)
    }
}

/// High-level stream of service requests matching an application's chosen
/// opaque service IDs.
pub struct ServiceRequestStream {
    inner: ServiceRequestSubscription,
}

impl ServiceRequestStream {
    pub async fn next(&mut self) -> Result<ServiceRequest, ClientError> {
        let request = self.inner.next().await?;
        // Decode fields that borrow the complete wire object before moving its
        // owned strings into the high-level identity wrappers.
        let request_id = request.request_id()?;
        let service_id = request.service_id()?;
        let service_manifest_hash = request.service_manifest_hash()?;
        let instance_id = request.instance_id()?;
        let reply_route_blob = request.reply_route_blob()?;
        let payload = request.payload()?;
        Ok(ServiceRequest {
            request_id,
            requester: NetworkIdentity::parse(request.requester_main_dht)?,
            intended_host: NetworkIdentity::parse(request.intended_host_main_dht)?,
            service_id,
            service_manifest_hash,
            instance_id,
            reply_route_blob,
            payload,
            delegation_allowed: request.delegation_allowed,
            spectators_allowed: request.spectators_allowed,
            posted_at: request.posted_at,
            expires_at: request.expires_at,
        })
    }
}

/// A fully decoded application message.
#[derive(Debug, Clone)]
pub struct IncomingMessage {
    pub application_id: String,
    pub message_id: String,
    pub sender: NetworkIdentity,
    pub recipient: NetworkIdentity,
    pub posted_at: u64,
    pub expires_at: u64,
    pub delivery_kind: String,
    pub conversation_id: Option<[u8; 32]>,
    pub payload: Vec<u8>,
}

impl IncomingMessage {
    /// Decode the payload as UTF-8.
    pub fn text(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.payload)
    }
}

/// A message subscription filtered to the authenticated application ID.
pub struct MessageStream {
    inner: MessageSubscription,
}

impl MessageStream {
    /// Wait for the next live or offline-delivered application message.
    pub async fn next(&mut self) -> Result<IncomingMessage, ClientError> {
        let message = self.inner.next().await?;
        let payload = message.payload()?;
        let conversation_id = message
            .conversation_id_hex
            .as_deref()
            .map(|value| decode_fixed::<32>(value, "conversation id"))
            .transpose()?;
        Ok(IncomingMessage {
            application_id: message.application_id,
            message_id: message.message_id_hex,
            sender: NetworkIdentity::parse(message.sender_main_dht)?,
            recipient: NetworkIdentity::parse(message.recipient_main_dht)?,
            posted_at: message.posted_at,
            expires_at: message.expires_at,
            delivery_kind: message.delivery_kind.unwrap_or_else(|| "legacy".to_string()),
            conversation_id,
            payload,
        })
    }
}

/// A stream of daemon-wide status events available to authorized apps.
pub struct NetworkEventStream {
    inner: NetworkEventSubscription,
}

impl NetworkEventStream {
    pub async fn next(&mut self) -> Result<serde_json::Value, ClientError> {
        self.inner.next().await
    }
}

/// Default capabilities requested by ordinary messaging applications.
pub fn default_app_capabilities() -> Vec<AppCapability> {
    vec![
        AppCapability::SendMessages,
        AppCapability::ReceiveMessages,
        AppCapability::ManageOwnStorage,
        AppCapability::ReadOwnStorage,
        AppCapability::ReadPublicProfiles,
        AppCapability::SubscribeNetworkStatus,
        AppCapability::SubmitReputation,
        AppCapability::RequestAppScopedRestriction,
        AppCapability::InspectOwnReputationSubmissions,
        AppCapability::SignAppData,
    ]
}

/// High-level application connection.
///
/// This is the main SDK type. It hides named pipes, challenge-response
/// authentication, raw session tokens, and the choice between direct and
/// mailbox delivery.
#[derive(Clone)]
pub struct NetworkApp {
    client: Arc<NetworkApiClient>,
    local_user: LocalUser,
    profile_id: String,
}

impl NetworkApp {
    /// Connect using automatic endpoint and credential discovery.
    ///
    /// On first run this returns [`ClientError::AuthorizationRequired`]. The
    /// contained [`AuthorizationRequest`] can wait for the user to approve the
    /// request from the daemon console.
    pub async fn connect(app_id: impl Into<String>) -> Result<Self, ClientError> {
        NetworkAppBuilder::new(app_id).connect().await
    }

    /// Start a configurable connection builder.
    pub fn builder(app_id: impl Into<String>) -> NetworkAppBuilder {
        NetworkAppBuilder::new(app_id)
    }

    async fn from_credential(
        mut credential: CredentialFile,
        endpoint_override: Option<String>,
        requested_capabilities: Vec<AppCapability>,
    ) -> Result<Self, ClientError> {
        if let Some(endpoint) = endpoint_override {
            credential.endpoint = endpoint;
        }
        let client = Arc::new(
            NetworkApiClient::authenticate(&credential, requested_capabilities).await?,
        );
        let identity = client.identity().await?;
        let profile_id = identity.profile_id;
        let local_user = LocalUser {
            username: identity.username,
            identity: NetworkIdentity::parse(identity.main_dht)?,
        };
        Ok(Self { client, local_user, profile_id })
    }

    /// The authenticated application's ID.
    pub fn app_id(&self) -> &str {
        &self.client.session().app_id
    }

    /// The daemon user and opaque network identity.
    pub fn local_user(&self) -> &LocalUser {
        &self.local_user
    }

    /// Opaque daemon account/network-profile identifier for this authenticated connection.
    /// Applications can compare this across reconnects to detect an account switch without
    /// relying on a public username.
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Send bytes to one network identity.
    pub async fn send(
        &self,
        recipient: &NetworkIdentity,
        payload: impl AsRef<[u8]>,
    ) -> Result<MessageReceipt, ClientError> {
        self.send_with_options(recipient, payload, MessageOptions::default())
            .await
    }

    /// Send UTF-8 text to one network identity.
    pub async fn send_text(
        &self,
        recipient: &NetworkIdentity,
        text: impl AsRef<str>,
    ) -> Result<MessageReceipt, ClientError> {
        self.send(recipient, text.as_ref().as_bytes()).await
    }

    /// Send with an explicit conversation ID, expiration, or response flag.
    pub async fn send_with_options(
        &self,
        recipient: &NetworkIdentity,
        payload: impl AsRef<[u8]>,
        options: MessageOptions,
    ) -> Result<MessageReceipt, ClientError> {
        let message_id = self
            .client
            .send_message(
                recipient.as_str(),
                payload.as_ref(),
                options.conversation_id.as_ref(),
                options.expires_at,
                options.await_response,
            )
            .await?;
        Ok(MessageReceipt {
            message_id,
            recipient: recipient.clone(),
            conversation_id: options.conversation_id,
        })
    }

    /// Send the same payload to many recipients with bounded concurrency.
    pub async fn broadcast<I>(
        &self,
        recipients: I,
        payload: impl AsRef<[u8]>,
    ) -> Vec<BroadcastDelivery>
    where
        I: IntoIterator<Item = NetworkIdentity>,
    {
        let payload = Arc::new(payload.as_ref().to_vec());
        let app = self.clone();
        stream::iter(recipients)
            .map(move |recipient| {
                let app = app.clone();
                let payload = payload.clone();
                async move {
                    match app.send(&recipient, payload.as_slice()).await {
                        Ok(receipt) => BroadcastDelivery {
                            recipient,
                            message_id: Some(receipt.message_id),
                            error: None,
                        },
                        Err(error) => BroadcastDelivery {
                            recipient,
                            message_id: None,
                            error: Some(error.to_string()),
                        },
                    }
                }
            })
            .buffer_unordered(16)
            .collect()
            .await
    }

    /// Send one handshake-free gossip hint. Unlike `send`, this never starts a
    /// VeilKnit handshake and never falls back to mailbox delivery.
    pub async fn gossip(
        &self,
        recipient: &NetworkIdentity,
        payload: impl AsRef<[u8]>,
    ) -> Result<MessageReceipt, ClientError> {
        let message_id = self
            .client
            .send_gossip_message(recipient.as_str(), payload.as_ref())
            .await?;
        Ok(MessageReceipt {
            message_id,
            recipient: recipient.clone(),
            conversation_id: None,
        })
    }

    /// Start a request/response conversation with a random conversation ID.
    pub async fn request(
        &self,
        recipient: &NetworkIdentity,
        payload: impl AsRef<[u8]>,
    ) -> Result<RequestReceipt, ClientError> {
        let mut conversation_id = [0u8; 32];
        OsRng.fill_bytes(&mut conversation_id);
        let message = self
            .send_with_options(
                recipient,
                payload,
                MessageOptions {
                    conversation_id: Some(conversation_id),
                    expires_at: None,
                    await_response: true,
                },
            )
            .await?;
        Ok(RequestReceipt {
            message,
            conversation_id,
        })
    }

    /// Reply to a received request while preserving its conversation ID.
    pub async fn respond(
        &self,
        request: &IncomingMessage,
        payload: impl AsRef<[u8]>,
    ) -> Result<MessageReceipt, ClientError> {
        let conversation_id = request.conversation_id.ok_or_else(|| {
            ClientError::UnexpectedResponse(
                "the incoming message does not contain a conversation id".to_string(),
            )
        })?;
        self.send_with_options(
            &request.sender,
            payload,
            MessageOptions {
                conversation_id: Some(conversation_id),
                expires_at: None,
                await_response: false,
            },
        )
        .await
    }

    /// Subscribe to messages addressed to this application.
    pub async fn subscribe(&self) -> Result<MessageStream, ClientError> {
        Ok(MessageStream {
            inner: self.client.subscribe_messages().await?,
        })
    }

    /// Publish a short-lived public/delegatable service request. The daemon
    /// creates and owns the disposable reply route automatically.
    pub async fn publish_service_request(
        &self,
        intended_host: &NetworkIdentity,
        service_id: [u8; 32],
        service_manifest_hash: [u8; 32],
        instance_id: [u8; 32],
        payload: impl AsRef<[u8]>,
        delegation_allowed: bool,
        spectators_allowed: bool,
        ttl_seconds: Option<u64>,
    ) -> Result<PublishedServiceRequest, ClientError> {
        self.client
            .publish_service_request(
                intended_host.as_str(),
                &service_id,
                &service_manifest_hash,
                &instance_id,
                payload.as_ref(),
                delegation_allowed,
                spectators_allowed,
                ttl_seconds,
            )
            .await
    }

    /// Withdraw a live service request and release its disposable reply route.
    pub async fn withdraw_service_request(
        &self,
        request_id: [u8; 32],
    ) -> Result<(), ClientError> {
        self.client.withdraw_service_request(&request_id).await
    }

    /// Subscribe to public service requests for one or more opaque service IDs.
    pub async fn service_requests(
        &self,
        service_ids: &[[u8; 32]],
    ) -> Result<ServiceRequestStream, ClientError> {
        Ok(ServiceRequestStream {
            inner: self.client.subscribe_service_requests(service_ids).await?,
        })
    }

    /// Reply to a discovered service request over its short-lived public route.
    /// The requester will receive a normal application message tagged
    /// `delivery_kind = service_reply`.
    pub async fn reply_to_service_request(
        &self,
        request: &ServiceRequest,
        payload: impl AsRef<[u8]>,
    ) -> Result<String, ClientError> {
        self.client
            .send_service_reply(
                &request.request_id,
                &request.reply_route_blob,
                payload.as_ref(),
            )
            .await
    }

    /// Request an immediate offline-mail scan.
    pub async fn retrieve_mail(&self) -> Result<(), ClientError> {
        self.client.trigger_message_retrieval().await
    }

    /// Read mailbox health and queue counts.
    pub async fn mailbox_status(&self) -> Result<MailboxStatus, ClientError> {
        self.client.mailbox_status().await
    }

    /// Return the daemon-held public signing identity for this application.
    pub async fn signing_identity(&self) -> Result<AppSigningIdentity, ClientError> {
        self.client.app_signing_identity().await
    }

    /// Rotate this application's daemon-held signing key.
    pub async fn rotate_signing_key(&self) -> Result<AppSigningIdentity, ClientError> {
        self.client.rotate_app_signing_key().await
    }

    /// Sign canonical application bytes under a domain-separated Ed25519 key.
    pub async fn sign(
        &self,
        domain: &str,
        payload: impl AsRef<[u8]>,
    ) -> Result<AppSignature, ClientError> {
        self.client.sign_app_payload(domain, payload.as_ref()).await
    }

    /// Ask the daemon to verify a signature created by any application key.
    pub async fn verify_signature(
        &self,
        public_key_hex: &str,
        domain: &str,
        payload: impl AsRef<[u8]>,
        signature_hex: &str,
    ) -> Result<bool, ClientError> {
        self.client
            .verify_app_signature(
                public_key_hex,
                domain,
                payload.as_ref(),
                signature_hex,
            )
            .await
    }

    pub async fn stores(&self) -> Result<Vec<AppStoreDescriptor>, ClientError> {
        self.client.list_app_stores().await
    }

    pub async fn create_store(
        &self,
        name: &str,
        subkey_count: u16,
    ) -> Result<AppStoreDescriptor, ClientError> {
        self.client.create_app_store(name, subkey_count, true).await
    }

    pub async fn read_store(
        &self,
        store_id: &str,
        locations: &[u32],
        force_refresh: bool,
    ) -> Result<AppStoreRead, ClientError> {
        self.client
            .read_app_store(store_id, locations, force_refresh)
            .await
    }

    pub async fn write_store(
        &self,
        store_id: &str,
        expected_generation: Option<u64>,
        writes: &[AppStoreWrite],
    ) -> Result<AppStoreDescriptor, ClientError> {
        self.client
            .write_app_store(store_id, expected_generation, writes)
            .await
    }

    pub async fn read_public_store(
        &self,
        record_key: &str,
        locations: &[u32],
        force_refresh: bool,
    ) -> Result<PublicStoreRead, ClientError> {
        self.client
            .read_public_store(record_key, locations, force_refresh)
            .await
    }

    pub async fn observe_reputation(
        &self,
        subject: &NetworkIdentity,
        kind: ObservationKind,
        application_code: Option<u32>,
        description: Option<&str>,
    ) -> Result<u64, ClientError> {
        self.client
            .submit_reputation_observation(subject, kind, application_code, description)
            .await
    }

    pub async fn request_restriction(
        &self,
        subject: &NetworkIdentity,
        action: AppRestrictionAction,
        reason: &str,
        expires_at: Option<u64>,
    ) -> Result<u64, ClientError> {
        self.client
            .request_app_restriction(subject, action, reason, expires_at)
            .await
    }

    /// Read the daemon's current network status as structured JSON.
    pub async fn status(&self) -> Result<serde_json::Value, ClientError> {
        self.client.network_status().await
    }

    /// Subscribe to daemon network events.
    pub async fn events(&self) -> Result<NetworkEventStream, ClientError> {
        Ok(NetworkEventStream {
            inner: self.client.subscribe_network_events().await?,
        })
    }

    /// Access the low-level authenticated client for protocol features not yet
    /// wrapped by `NetworkApp`.
    pub fn advanced_client(&self) -> &NetworkApiClient {
        self.client.as_ref()
    }
}

/// Builder used when an app needs a display name, custom capabilities, or a
/// non-default endpoint/credential location.
#[derive(Debug, Clone)]
pub struct NetworkAppBuilder {
    app_id: String,
    display_name: String,
    capabilities: Vec<AppCapability>,
    credential_path: Option<PathBuf>,
    endpoint: Option<String>,
}

impl NetworkAppBuilder {
    pub fn new(app_id: impl Into<String>) -> Self {
        let app_id = app_id.into();
        Self {
            display_name: app_id.clone(),
            app_id,
            capabilities: default_app_capabilities(),
            credential_path: None,
            endpoint: None,
        }
    }

    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = display_name.into();
        self
    }

    pub fn capabilities(mut self, capabilities: impl IntoIterator<Item = AppCapability>) -> Self {
        self.capabilities = capabilities.into_iter().collect();
        self
    }

    pub fn credential_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.credential_path = Some(path.into());
        self
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub async fn connect(self) -> Result<NetworkApp, ClientError> {
        validate_app_id(&self.app_id)?;
        if self.display_name.trim().is_empty() || self.display_name.len() > 256 {
            return Err(ClientError::InvalidCredential(
                "application display name must contain 1 to 256 bytes".to_string(),
            ));
        }

        // Endpoint discovery also tells us which daemon account/profile is currently active.
        // Credentials are therefore stored under that profile instead of globally by app id.
        // Switching daemon accounts makes an already-running app authenticate as a completely
        // different local user rather than accidentally presenting the previous account's key.
        let discovered = match &self.endpoint {
            Some(explicit) => discover_endpoint_info()
                .ok()
                .filter(|value| value.endpoint == *explicit),
            None => Some(discover_endpoint_info()?),
        };
        let endpoint = self
            .endpoint
            .clone()
            .or_else(|| discovered.as_ref().map(|value| value.endpoint.clone()))
            .ok_or(ClientError::DaemonEndpointNotFound)?;
        let profile_id = discovered
            .as_ref()
            .map(|value| value.profile_id.trim())
            .filter(|value| !value.is_empty());

        // An explicitly supplied credential path remains authoritative for applications that
        // intentionally manage their own credential storage.
        if let Some(path) = self.credential_path.as_ref().filter(|path| path.exists()) {
            let credential = CredentialFile::load(path)?;
            if credential.app_id != self.app_id {
                return Err(ClientError::InvalidCredential(format!(
                    "credential belongs to {}, not {}", credential.app_id, self.app_id
                )));
            }
            return NetworkApp::from_credential(
                credential,
                Some(endpoint.clone()),
                self.capabilities.clone(),
            )
            .await;
        }

        if self.credential_path.is_none() {
            if let Some(profile_id) = profile_id {
                if let Some(path) = find_profile_credential_path(&self.app_id, profile_id) {
                    let credential = CredentialFile::load(&path)?;
                    if credential.app_id != self.app_id {
                        return Err(ClientError::InvalidCredential(format!(
                            "credential belongs to {}, not {}", credential.app_id, self.app_id
                        )));
                    }
                    return NetworkApp::from_credential(
                        credential,
                        Some(endpoint.clone()),
                        self.capabilities.clone(),
                    )
                    .await;
                }

                // Migration path for credentials created before profile scoping existed.  We only
                // migrate the legacy credential after it successfully authenticates against the
                // currently active daemon account. A credential from another account is ignored.
                if let Some(path) = find_legacy_credential_path(&self.app_id) {
                    if let Ok(credential) = CredentialFile::load(&path) {
                        if credential.app_id == self.app_id {
                            if let Ok(app) = NetworkApp::from_credential(
                                credential.clone(),
                                Some(endpoint.clone()),
                                self.capabilities.clone(),
                            )
                            .await
                            {
                                let scoped = preferred_profile_credential_path(&self.app_id, profile_id);
                                credential.save(&scoped)?;
                                return Ok(app);
                            }
                        }
                    }
                }
            } else if let Some(path) = find_legacy_credential_path(&self.app_id) {
                let credential = CredentialFile::load(&path)?;
                if credential.app_id != self.app_id {
                    return Err(ClientError::InvalidCredential(format!(
                        "credential belongs to {}, not {}", credential.app_id, self.app_id
                    )));
                }
                return NetworkApp::from_credential(
                    credential,
                    Some(endpoint.clone()),
                    self.capabilities.clone(),
                )
                .await;
            }
        }

        let mut request_token = [0u8; 32];
        OsRng.fill_bytes(&mut request_token);
        let pending = request_app_registration(
            &endpoint,
            &self.app_id,
            &self.display_name,
            &self.capabilities,
            &request_token,
        )
        .await
        .map_err(|error| match error {
            ClientError::Protocol { code, .. } if code == "app_already_registered" => {
                ClientError::CredentialNotFound {
                    app_id: self.app_id.clone(),
                }
            }
            other => other,
        })?;
        let save_path = self.credential_path.unwrap_or_else(|| {
            profile_id
                .map(|profile| preferred_profile_credential_path(&self.app_id, profile))
                .unwrap_or_else(|| preferred_credential_path(&self.app_id))
        });
        Err(ClientError::AuthorizationRequired(Box::new(
            AuthorizationRequest {
                endpoint,
                app_id: self.app_id,
                display_name: self.display_name,
                capabilities: self.capabilities,
                request_id: pending.request_id,
                request_token,
                requested_at: pending.requested_at,
                expires_at: pending.expires_at,
                credential_path: save_path,
            },
        )))
    }
}

#[derive(Debug, Clone)]
struct PendingRegistrationWire {
    request_id: u64,
    requested_at: u64,
    expires_at: u64,
}

/// A first-run request waiting for approval in the daemon console.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    endpoint: String,
    app_id: String,
    display_name: String,
    capabilities: Vec<AppCapability>,
    request_id: u64,
    request_token: [u8; 32],
    requested_at: u64,
    expires_at: u64,
    credential_path: PathBuf,
}

impl AuthorizationRequest {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn app_id(&self) -> &str {
        &self.app_id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn requested_at(&self) -> u64 {
        self.requested_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn approval_command(&self) -> String {
        format!("app-approve {}", self.request_id)
    }

    pub fn credential_path(&self) -> &Path {
        &self.credential_path
    }

    /// Poll until the local user approves, rejects, or lets the request expire.
    pub async fn wait(self) -> Result<NetworkApp, ClientError> {
        self.wait_timeout(Duration::from_secs(15 * 60)).await
    }

    /// Poll for approval for at most `timeout`.
    pub async fn wait_timeout(self, timeout: Duration) -> Result<NetworkApp, ClientError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match get_app_registration_status(
                &self.endpoint,
                self.request_id,
                &self.request_token,
            )
            .await?
            {
                RegistrationStatusWire::Pending => {}
                RegistrationStatusWire::Approved(credential) => {
                    credential.save(&self.credential_path)?;
                    return NetworkApp::from_credential(
                        credential,
                        Some(self.endpoint.clone()),
                        self.capabilities.clone(),
                    )
                    .await;
                }
                RegistrationStatusWire::Rejected(reason) => {
                    return Err(ClientError::AuthorizationRejected(reason));
                }
                RegistrationStatusWire::Expired => {
                    return Err(ClientError::AuthorizationExpired(self.request_id));
                }
            }
            if std::time::Instant::now() >= deadline {
                return Err(ClientError::AuthorizationTimedOut);
            }
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    }
}

#[derive(Debug)]
enum RegistrationStatusWire {
    Pending,
    Approved(CredentialFile),
    Rejected(String),
    Expired,
}

async fn request_app_registration(
    endpoint: &str,
    app_id: &str,
    display_name: &str,
    capabilities: &[AppCapability],
    request_token: &[u8; 32],
) -> Result<PendingRegistrationWire, ClientError> {
    let request = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "request_id": 1,
        "action": "request_app_registration",
        "app_id": app_id,
        "display_name": display_name,
        "requested_capabilities": capabilities,
        "request_token_hex": hex::encode(request_token),
    });
    match send_request(endpoint, &request).await?.into_result()? {
        ApiResult::AppRegistrationPending {
            request_id,
            requested_at,
            expires_at,
            ..
        } => Ok(PendingRegistrationWire {
            request_id,
            requested_at,
            expires_at,
        }),
        other => Err(unexpected("pending application registration", other)),
    }
}

async fn get_app_registration_status(
    endpoint: &str,
    request_id: u64,
    request_token: &[u8; 32],
) -> Result<RegistrationStatusWire, ClientError> {
    let request = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "request_id": 1,
        "action": "get_app_registration_status",
        "registration_request_id": request_id,
        "request_token_hex": hex::encode(request_token),
    });
    match send_request(endpoint, &request).await?.into_result()? {
        ApiResult::AppRegistrationStillPending { .. } => Ok(RegistrationStatusWire::Pending),
        ApiResult::AppRegistrationApproved {
            protocol_version,
            endpoint,
            app_id,
            display_name,
            secret_hex,
            credential_generation,
        } => Ok(RegistrationStatusWire::Approved(CredentialFile {
            protocol_version,
            endpoint,
            app_id,
            display_name,
            secret_hex,
            credential_generation,
        })),
        ApiResult::AppRegistrationRejected { reason, .. } => {
            Ok(RegistrationStatusWire::Rejected(reason))
        }
        ApiResult::AppRegistrationExpired { .. } => Ok(RegistrationStatusWire::Expired),
        other => Err(unexpected("application registration status", other)),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct EndpointDiscoveryFile {
    protocol_version: u16,
    endpoint: String,
    #[serde(default)]
    profile_id: String,
}

fn validate_app_id(app_id: &str) -> Result<(), ClientError> {
    let app_id = app_id.trim();
    if app_id.is_empty() || app_id.len() > 128 {
        return Err(ClientError::InvalidCredential(
            "application id must contain 1 to 128 bytes".to_string(),
        ));
    }
    if !app_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'))
    {
        return Err(ClientError::InvalidCredential(
            "application id may contain only letters, numbers, '.', '-', and '_'".to_string(),
        ));
    }
    Ok(())
}

fn safe_app_id(app_id: &str) -> String {
    app_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn profile_credential_filename(app_id: &str) -> String {
    format!("{}.json", safe_app_id(app_id))
}

fn preferred_profile_credential_path(app_id: &str, profile_id: &str) -> PathBuf {
    let profile = safe_app_id(profile_id);
    let filename = profile_credential_filename(app_id);
    if let Some(directory) = std::env::var_os("DAEMON_NETWORK_CREDENTIAL_DIR") {
        return PathBuf::from(directory).join(profile).join(filename);
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("DaemonNetwork")
            .join("credentials")
            .join(profile)
            .join(filename);
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".daemon_network")
            .join("credentials")
            .join(profile)
            .join(filename);
    }
    PathBuf::from("app_credentials").join(profile).join(filename)
}

fn profile_credential_search_paths(app_id: &str, profile_id: &str) -> Vec<PathBuf> {
    let profile = safe_app_id(profile_id);
    let filename = profile_credential_filename(app_id);
    let mut paths = Vec::new();
    if let Some(directory) = std::env::var_os("DAEMON_NETWORK_CREDENTIAL_DIR") {
        paths.push(PathBuf::from(directory).join(&profile).join(&filename));
    }
    paths.push(PathBuf::from("app_credentials").join(&profile).join(&filename));
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            paths.push(parent.join("app_credentials").join(&profile).join(&filename));
        }
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        paths.push(
            PathBuf::from(local_app_data)
                .join("DaemonNetwork")
                .join("credentials")
                .join(&profile)
                .join(&filename),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".daemon_network")
                .join("credentials")
                .join(&profile)
                .join(&filename),
        );
    }
    deduplicate_paths(paths)
}

fn find_profile_credential_path(app_id: &str, profile_id: &str) -> Option<PathBuf> {
    profile_credential_search_paths(app_id, profile_id)
        .into_iter()
        .find(|path| path.is_file())
}

// Legacy unscoped paths are retained only for migration/backward compatibility.
fn find_legacy_credential_path(app_id: &str) -> Option<PathBuf> {
    credential_search_paths(app_id)
        .into_iter()
        .find(|path| path.is_file())
}

fn preferred_credential_path(app_id: &str) -> PathBuf {
    if let Some(directory) = std::env::var_os("DAEMON_NETWORK_CREDENTIAL_DIR") {
        return PathBuf::from(directory).join(format!("{}.json", safe_app_id(app_id)));
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("DaemonNetwork")
            .join("credentials")
            .join(format!("{}.json", safe_app_id(app_id)));
    }
    PathBuf::from("app_credentials").join(format!("{}.json", safe_app_id(app_id)))
}

fn credential_search_paths(app_id: &str) -> Vec<PathBuf> {
    let filename = format!("{}.json", safe_app_id(app_id));
    let mut paths = Vec::new();
    if let Some(path) = std::env::var_os("DAEMON_NETWORK_CREDENTIAL") {
        paths.push(PathBuf::from(path));
    }
    if let Some(directory) = std::env::var_os("DAEMON_NETWORK_CREDENTIAL_DIR") {
        paths.push(PathBuf::from(directory).join(&filename));
    }
    paths.push(PathBuf::from("app_credentials").join(&filename));
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            paths.push(parent.join("app_credentials").join(&filename));
        }
    }
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        paths.push(
            PathBuf::from(local_app_data)
                .join("DaemonNetwork")
                .join("credentials")
                .join(&filename),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        paths.push(
            PathBuf::from(home)
                .join(".daemon_network")
                .join("credentials")
                .join(&filename),
        );
    }
    deduplicate_paths(paths)
}

fn discover_endpoint_info() -> Result<EndpointDiscoveryFile, ClientError> {
    // An explicit endpoint environment variable predates account-aware discovery. If a normal
    // discovery file matches it, retain the profile id; otherwise return an unscoped endpoint.
    if let Ok(endpoint) = std::env::var("DAEMON_NETWORK_ENDPOINT") {
        if !endpoint.trim().is_empty() {
            for path in endpoint_discovery_paths() {
                let Ok(bytes) = std::fs::read(&path) else { continue; };
                let Ok(discovery) = serde_json::from_slice::<EndpointDiscoveryFile>(&bytes) else { continue; };
                if discovery.protocol_version == PROTOCOL_VERSION && discovery.endpoint == endpoint {
                    return Ok(discovery);
                }
            }
            return Ok(EndpointDiscoveryFile {
                protocol_version: PROTOCOL_VERSION,
                endpoint,
                profile_id: String::new(),
            });
        }
    }
    for path in endpoint_discovery_paths() {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(discovery) = serde_json::from_slice::<EndpointDiscoveryFile>(&bytes) else {
            continue;
        };
        if discovery.protocol_version == PROTOCOL_VERSION && !discovery.endpoint.trim().is_empty() {
            return Ok(discovery);
        }
    }
    Err(ClientError::DaemonEndpointNotFound)
}


fn endpoint_discovery_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("app_credentials").join("daemon_endpoint.json")];
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            paths.push(parent.join("app_credentials").join("daemon_endpoint.json"));
        }
    }
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
    deduplicate_paths(paths)
}

fn deduplicate_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique = Vec::new();
    for path in paths {
        if !unique.iter().any(|existing: &PathBuf| existing == &path) {
            unique.push(path);
        }
    }
    unique
}

/// Low-level types retained for advanced clients and compatibility.
pub mod advanced {
    pub use super::{
        ApiSession, CredentialFile, IncomingApplicationMessage, MessageSubscription,
        NetworkApiClient, NetworkEventSubscription, StreamSubscription,
    };
}

#[derive(Debug, Deserialize)]
struct ApiResponseEnvelope {
    protocol_version: u16,
    request_id: u64,
    ok: bool,
    result: Option<ApiResult>,
    error: Option<ApiErrorBody>,
}

impl ApiResponseEnvelope {
    fn into_result(self) -> Result<ApiResult, ClientError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ClientError::UnexpectedResponse(format!(
                "daemon protocol {}, client protocol {}",
                self.protocol_version, PROTOCOL_VERSION
            )));
        }
        if self.ok {
            self.result.ok_or_else(|| {
                ClientError::UnexpectedResponse(format!(
                    "request {} succeeded without a result",
                    self.request_id
                ))
            })
        } else {
            let error = self.error.unwrap_or(ApiErrorBody {
                code: "unknown_error".to_string(),
                message: "daemon returned an error without details".to_string(),
            });
            Err(ClientError::Protocol {
                code: error.code,
                message: error.message,
            })
        }
    }
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ApiResult {
    Pong,
    ApiInfo {
        protocol_version: u16,
        authentication_proof: String,
        features: Vec<String>,
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
        max_stream_write_bytes: usize,
        stream_packet_bytes: usize,
    },
    Status {
        status: serde_json::Value,
    },
    Identity {
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
        #[serde(default)]
        outgoing_service_request_count: usize,
        #[serde(default)]
        recent_service_request_count: usize,
        awaiting_response_count: usize,
        known_custodian_count: usize,
    },
    AppPeers {
        app_id: String,
        sampled_at: u64,
        cache_generation: u64,
        total_cached: usize,
        peers: Vec<AppPeer>,
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
        signature: AppSignature,
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
        values: Vec<AppStoreValue>,
    },
    AppStoreWritten {
        store: AppStoreDescriptor,
    },
    PublicStoreRead {
        record_key: String,
        values: Vec<AppStoreValue>,
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
    BlobRangeRead { blob: BlobDescriptor, offset: u64, data_base64: String },
    StreamStarted { descriptor: StreamDescriptor },
    StreamJoinPending { stream_id: String },
    StreamWriteAccepted { result: StreamWriteResult },
    StreamFlushed { commitment: Option<StreamSegmentCommitment> },
    StreamLeft { stream_id: String },
    StreamClosed { stream_id: String },
    Streams { streams: Vec<StreamSummary> },
    StreamSubscriptionStarted { app_id: String },
    ReputationObservationSubmitted {
        observation_id: u64,
    },
    ReputationObservationRetracted,
    AppRestrictionRequested {
        decision_id: u64,
    },
    AppDecisionRevoked,
    ReputationView {
        view: serde_json::Value,
    },
    OwnReputationSubmissions {
        report: serde_json::Value,
    },
    SessionLogSaved {
        path: String,
        lines: usize,
    },
}

#[derive(Debug, Deserialize)]
struct ApplicationStreamEnvelope {
    protocol_version: u16,
    stream: String,
    event: IncomingApplicationMessage,
}

#[derive(Debug, Deserialize)]
struct StreamEventEnvelope {
    protocol_version: u16,
    stream: String,
    event: StreamEvent,
}

#[derive(Debug, Deserialize)]
struct ServiceRequestStreamEnvelope {
    protocol_version: u16,
    stream: String,
    event: IncomingServiceRequest,
}

#[derive(Debug, Deserialize)]
struct NetworkStreamEnvelope {
    protocol_version: u16,
    stream: String,
    event: serde_json::Value,
}

#[derive(Debug)]
struct AuthChallenge {
    app_id: String,
    challenge_id: u64,
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    credential_generation: u64,
    requested_capabilities: Vec<AppCapability>,
}

fn compute_proof(secret: &[u8; 32], challenge: &AuthChallenge) -> [u8; 32] {
    let mut input = Vec::with_capacity(PROOF_DOMAIN.len() + challenge.app_id.len() + 128);
    input.extend_from_slice(PROOF_DOMAIN);
    input.extend_from_slice(&(challenge.app_id.len() as u32).to_le_bytes());
    input.extend_from_slice(challenge.app_id.as_bytes());
    input.extend_from_slice(&challenge.challenge_id.to_le_bytes());
    input.extend_from_slice(&challenge.nonce);
    input.extend_from_slice(&challenge.issued_at.to_le_bytes());
    input.extend_from_slice(&challenge.expires_at.to_le_bytes());
    input.extend_from_slice(&challenge.credential_generation.to_le_bytes());
    input.extend_from_slice(&(challenge.requested_capabilities.len() as u32).to_le_bytes());
    for capability in &challenge.requested_capabilities {
        input.extend_from_slice(format!("{capability:?}").as_bytes());
        input.push(0);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts 32-byte keys");
    mac.update(&input);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], ClientError> {
    let bytes = hex::decode(value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        ClientError::UnexpectedResponse(format!(
            "{label} must be {N} bytes, received {}",
            bytes.len()
        ))
    })
}

fn unexpected(expected: &str, actual: ApiResult) -> ClientError {
    ClientError::UnexpectedResponse(format!("expected {expected}, received {actual:?}"))
}

async fn send_request(
    endpoint: &str,
    request: &serde_json::Value,
) -> Result<ApiResponseEnvelope, ClientError> {
    let mut stream = connect(endpoint).await?;
    write_json_line(&mut stream, request).await?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).await?;
    if line.is_empty() {
        return Err(ClientError::UnexpectedResponse(
            "daemon closed the connection without a response".to_string(),
        ));
    }
    let response: ApiResponseEnvelope = serde_json::from_str(&line)?;
    if !response.ok {
        let error = response.error.as_ref().map_or_else(
            || ("unknown_error".to_string(), "no details".to_string()),
            |error| (error.code.clone(), error.message.clone()),
        );
        return Err(ClientError::Protocol {
            code: error.0,
            message: error.1,
        });
    }
    Ok(response)
}

async fn write_json_line(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &serde_json::Value,
) -> Result<(), ClientError> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(windows)]
async fn connect(endpoint: &str) -> Result<IpcStream, ClientError> {
    use tokio::{net::windows::named_pipe::ClientOptions, time::Duration};

    let mut last_error = None;
    for _ in 0..40 {
        match ClientOptions::new().open(endpoint) {
            Ok(stream) => return Ok(Box::pin(stream)),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(2) | Some(231) | Some(536)
                ) =>
            {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(ClientError::Io(error)),
        }
    }
    Err(ClientError::Io(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "named pipe was not available")
    })))
}

#[cfg(unix)]
async fn connect(endpoint: &str) -> Result<IpcStream, ClientError> {
    Ok(Box::pin(tokio::net::UnixStream::connect(endpoint).await?))
}

#[cfg(not(any(windows, unix)))]
async fn connect(_endpoint: &str) -> Result<IpcStream, ClientError> {
    Err(ClientError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "local IPC is not supported on this platform",
    )))
}

//! Codec-agnostic live byte streaming over authenticated Veilid routes.
//!
//! The stream transport deliberately does not know whether an application is
//! sending video, audio, a game-state feed, or another byte sequence. The app
//! provides opaque bytes; the daemon packetizes them, maintains a bounded relay
//! tree, retransmits recent packets, and publishes signed segment commitments
//! into chained, size-safe DHT records.
//!
//! Version-one topology deliberately keeps admission authoritative: every
//! viewer first authenticates directly with the original streamer. Once
//! admitted, continuous data may flow through other viewers so the source's
//! upload cost does not grow linearly with the audience.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt,
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bincode::Options;
use futures::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{broadcast, watch, Mutex, Notify};
use uuid::Uuid;
use veilid_core::RecordKey;

use crate::{
    app_services::{
        AppServiceError, AppSigningManager, AppStorageManager, AppStoreReadValue,
    },
    handshake::{DirectApplicationMessage, HandshakeManager},
    identity_manager::AuthenticatedAppSession,
    types::current_timestamp,
};

/// Reserved direct-message application namespace. It is consumed by the
/// daemon and never delivered to ordinary application message subscriptions.
pub const STREAM_INTERNAL_APPLICATION_ID: &str = "veilknit.stream.v1";

const STREAM_PROTOCOL_VERSION: u16 = 1;
const STREAM_DESCRIPTOR_DOMAIN: &str = "veilknit.stream.descriptor.v1";
const STREAM_RECORD_HEADER_DOMAIN: &str = "veilknit.stream.record-header.v1";
const STREAM_COMMITMENT_PAGE_DOMAIN: &str = "veilknit.stream.commitment-page.v1";
const STREAM_SEGMENT_HASH_DOMAIN: &[u8] = b"veilknit.stream.segment-hash.v1";
const STREAM_RECORD_MAGIC: [u8; 4] = *b"VKST";

pub const STREAM_PACKET_BYTES: usize = 24 * 1024;
pub const STREAM_MAX_WRITE_BYTES: usize = 512 * 1024;
pub const STREAM_PACKETS_PER_SEGMENT: u32 = 32;
pub const STREAM_COMMITMENT_SUBKEYS: u16 = 64;
pub const STREAM_COMMITMENT_PAGES_PER_RECORD: u32 = 63;
pub const STREAM_COMMITMENTS_PER_PAGE: usize = 16;
pub const STREAM_MAX_METADATA_BYTES: usize = 8 * 1024;
pub const STREAM_MAX_CLOSE_REASON_BYTES: usize = 256;
pub const STREAM_MAX_VIEWERS: usize = 256;
pub const STREAM_MAX_RELAY_CHILDREN: u16 = 4;
pub const STREAM_SOURCE_DIRECT_CHILDREN: usize = 2;
pub const STREAM_RETRANSMIT_SEGMENTS: u64 = 8;
pub const STREAM_RECEIVED_SEGMENT_WINDOW: u64 = 16;
pub const STREAM_MAX_SEGMENT_AHEAD: u64 = 64;
pub const STREAM_MAX_PENDING_COMMITMENTS: usize = 4_096;
pub const STREAM_MAX_RETRANSMIT_INDICES: usize = 64;
const STREAM_JOIN_TIMEOUT_SECS: u64 = 30;
const STREAM_CLOSED_RETENTION_SECS: u64 = 120;
const STREAM_SEND_CONCURRENCY: usize = 8;
const STREAM_MAX_WIRE_BYTES: usize = 32 * 1024;
const STREAM_MAX_SERIALIZED_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub enum StreamTransportError {
    InvalidStreamId,
    StreamNotFound,
    StreamAlreadyClosed,
    NotStreamOwner,
    InvalidDescriptor(String),
    InvalidMetadata,
    InvalidCloseReason,
    EmptyWrite,
    WriteTooLarge(usize),
    ViewerLimitReached,
    CommitmentBacklogFull,
    JoinRejected(String),
    Transport(String),
    Storage(AppServiceError),
    Serialization(String),
    Integrity(String),
}

impl fmt::Display for StreamTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStreamId => write!(formatter, "stream id is malformed"),
            Self::StreamNotFound => write!(formatter, "stream was not found"),
            Self::StreamAlreadyClosed => write!(formatter, "stream is already closed"),
            Self::NotStreamOwner => write!(formatter, "application does not own this stream"),
            Self::InvalidDescriptor(reason) => write!(formatter, "invalid stream descriptor: {reason}"),
            Self::InvalidMetadata => write!(formatter, "stream metadata exceeds the configured limit"),
            Self::InvalidCloseReason => write!(
                formatter,
                "stream close reason exceeds the configured limit"
            ),
            Self::EmptyWrite => write!(formatter, "stream write contains no bytes"),
            Self::WriteTooLarge(size) => write!(
                formatter,
                "stream write is {size} bytes; maximum is {STREAM_MAX_WRITE_BYTES}"
            ),
            Self::ViewerLimitReached => write!(formatter, "stream viewer limit reached"),
            Self::CommitmentBacklogFull => write!(
                formatter,
                "stream commitment backlog reached its safety limit"
            ),
            Self::JoinRejected(reason) => write!(formatter, "stream join was rejected: {reason}"),
            Self::Transport(reason) => write!(formatter, "stream route operation failed: {reason}"),
            Self::Storage(error) => write!(formatter, "stream commitment storage failed: {error}"),
            Self::Serialization(reason) => write!(formatter, "stream serialization failed: {reason}"),
            Self::Integrity(reason) => write!(formatter, "stream integrity verification failed: {reason}"),
        }
    }
}

impl std::error::Error for StreamTransportError {}

impl From<AppServiceError> for StreamTransportError {
    fn from(value: AppServiceError) -> Self {
        Self::Storage(value)
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UnsignedStreamDescriptor {
    version: u16,
    stream_id: String,
    application_id: String,
    streamer_main_dht: String,
    generation: u64,
    commitment_root_record_key: String,
    signing_public_key_hex: String,
    signing_key_generation: u64,
    opaque_metadata_base64: String,
    packet_bytes: u32,
    packets_per_segment: u32,
    created_at: u64,
}

impl StreamDescriptor {
    fn unsigned(&self) -> UnsignedStreamDescriptor {
        UnsignedStreamDescriptor {
            version: self.version,
            stream_id: self.stream_id.clone(),
            application_id: self.application_id.clone(),
            streamer_main_dht: self.streamer_main_dht.clone(),
            generation: self.generation,
            commitment_root_record_key: self.commitment_root_record_key.clone(),
            signing_public_key_hex: self.signing_public_key_hex.clone(),
            signing_key_generation: self.signing_key_generation,
            opaque_metadata_base64: self.opaque_metadata_base64.clone(),
            packet_bytes: self.packet_bytes,
            packets_per_segment: self.packets_per_segment,
            created_at: self.created_at,
        }
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
    pub fn application_id(&self) -> &str {
        match self {
            Self::Started { application_id, .. }
            | Self::JoinPending { application_id, .. }
            | Self::ViewerJoined { application_id, .. }
            | Self::Joined { application_id, .. }
            | Self::TopologyChanged { application_id, .. }
            | Self::Data { application_id, .. }
            | Self::SegmentCommitted { application_id, .. }
            | Self::SegmentVerified { application_id, .. }
            | Self::SegmentMissingPackets { application_id, .. }
            | Self::IntegrityFailure { application_id, .. }
            | Self::ViewerLeft { application_id, .. }
            | Self::Ended { application_id, .. }
            | Self::Warning { application_id, .. } => application_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StreamPacketWire {
    stream_id: String,
    generation: u64,
    sequence: u64,
    segment_number: u64,
    packet_index: u32,
    retransmission: bool,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum StreamWireMessage {
    JoinRequest {
        descriptor: StreamDescriptor,
        viewer_main_dht: String,
        relay_capacity: u16,
        requested_at: u64,
    },
    JoinAccepted {
        descriptor: StreamDescriptor,
        parent_main_dht: String,
        standby_parent_main_dht: Option<String>,
        latest_sequence: u64,
        latest_segment: u64,
    },
    JoinRejected {
        stream_id: String,
        generation: u64,
        reason: String,
    },
    AssignChild {
        stream_id: String,
        generation: u64,
        child_main_dht: String,
    },
    ParentAssignment {
        stream_id: String,
        generation: u64,
        parent_main_dht: String,
        standby_parent_main_dht: Option<String>,
    },
    Packet(StreamPacketWire),
    CommitmentHint(StreamCommitmentHint),
    RetransmitRequest {
        stream_id: String,
        generation: u64,
        segment_number: u64,
        packet_indices: Vec<u32>,
    },
    Leave {
        stream_id: String,
        generation: u64,
        viewer_main_dht: String,
    },
    End {
        stream_id: String,
        generation: u64,
        reason: String,
    },
}

impl StreamWireMessage {
    fn is_data_plane(&self) -> bool {
        matches!(
            self,
            Self::Packet(_)
                | Self::CommitmentHint(_)
                | Self::Leave { .. }
                | Self::End { .. }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitmentPageUnsigned {
    version: u16,
    stream_id: String,
    generation: u64,
    record_index: u32,
    page_index: u32,
    commitments: Vec<StreamSegmentCommitment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedCommitmentPage {
    unsigned: CommitmentPageUnsigned,
    signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitmentRecordHeaderUnsigned {
    magic: [u8; 4],
    version: u16,
    stream_id: String,
    generation: u64,
    record_index: u32,
    root_record_key: String,
    first_segment: u64,
    next_record_key: Option<String>,
    descriptor: Option<StreamDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedCommitmentRecordHeader {
    unsigned: CommitmentRecordHeaderUnsigned,
    signature_hex: String,
}

#[derive(Debug, Clone)]
struct CommitmentRecordState {
    store_id: String,
    record_key: String,
    record_index: u32,
    page_index: u32,
    first_segment: u64,
    page_commitments: Vec<StreamSegmentCommitment>,
}

#[derive(Debug, Clone)]
struct PendingSegmentState {
    segment_number: u64,
    first_sequence: u64,
    packet_count: u32,
    payload_bytes: u64,
    sha256: [u8; 32],
}

#[derive(Debug, Clone)]
struct ParticipantState {
    parent_main_dht: String,
    children: HashSet<String>,
    relay_capacity: u16,
    depth: u16,
    joined_at: u64,
}

#[derive(Debug, Clone)]
struct OutgoingStreamState {
    owner: AuthenticatedAppSession,
    descriptor: StreamDescriptor,
    running: bool,
    closed_at: Option<u64>,
    participants: HashMap<String, ParticipantState>,
    direct_children: HashSet<String>,
    next_sequence: u64,
    current_segment: u64,
    current_packets: Vec<StreamPacketWire>,
    packet_cache: VecDeque<StreamPacketWire>,
    pending_segments: VecDeque<PendingSegmentState>,
    commitment_records: Vec<CommitmentRecordState>,
    previous_commitment_hash: [u8; 32],
}

#[derive(Debug, Clone, Default)]
struct ReceivedSegmentState {
    packets: BTreeMap<u32, StreamPacketWire>,
    hint: Option<StreamCommitmentHint>,
    verified: bool,
    last_retransmit_at: u64,
}

#[derive(Debug, Clone)]
struct IncomingStreamState {
    application_id: String,
    descriptor: StreamDescriptor,
    running: bool,
    closed_at: Option<u64>,
    relay_capacity: u16,
    parent_main_dht: Option<String>,
    standby_parent_main_dht: Option<String>,
    children: HashSet<String>,
    packet_cache: VecDeque<StreamPacketWire>,
    received_segments: HashMap<u64, ReceivedSegmentState>,
    verified_commitment_hashes: BTreeMap<u64, [u8; 32]>,
    latest_sequence: u64,
    latest_segment: u64,
    join_requested_at: u64,
}

#[derive(Default)]
struct StreamTransportState {
    outgoing: HashMap<String, OutgoingStreamState>,
    incoming: HashMap<String, IncomingStreamState>,
}

#[derive(Clone)]
pub struct StreamTransportManager {
    storage: AppStorageManager,
    signing: AppSigningManager,
    handshake: Arc<Mutex<HandshakeManager>>,
    main_dht: String,
    state: Arc<Mutex<StreamTransportState>>,
    commitment_gate: Arc<Mutex<()>>,
    commitment_notify: Arc<Notify>,
    send_error_last_logged: Arc<Mutex<HashMap<String, u64>>>,
    events: broadcast::Sender<StreamEvent>,
}

impl StreamTransportManager {
    pub fn new(
        storage: AppStorageManager,
        signing: AppSigningManager,
        handshake: Arc<Mutex<HandshakeManager>>,
        main_dht: String,
    ) -> Self {
        let (events, _) = broadcast::channel(2048);
        Self {
            storage,
            signing,
            handshake,
            main_dht,
            state: Arc::new(Mutex::new(StreamTransportState::default())),
            commitment_gate: Arc::new(Mutex::new(())),
            commitment_notify: Arc::new(Notify::new()),
            send_error_last_logged: Arc::new(Mutex::new(HashMap::new())),
            events,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<StreamEvent> {
        self.events.subscribe()
    }

    /// Consume the daemon-reserved direct-message namespace. Ordinary app
    /// messages remain handled by the normal local API bridge.
    pub fn spawn_bridge(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            let mut messages = manager
                .handshake
                .lock()
                .await
                .subscribe_application_messages();

            // DHT publication is deliberately isolated from the route-message
            // receiver. A slow commitment write must not prevent packet,
            // retransmission, join, or topology messages from being handled.
            let commitment_manager = manager.clone();
            let mut commitment_shutdown = shutdown.clone();
            let commitment_task = tokio::spawn(async move {
                let mut retry =
                    tokio::time::interval(std::time::Duration::from_secs(30));
                retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = commitment_shutdown.changed() => break,
                        _ = retry.tick() => commitment_manager.commit_all_pending().await,
                        _ = commitment_manager.commitment_notify.notified() => {
                            commitment_manager.commit_all_pending().await;
                        }
                    }
                }
            });

            let mut maintenance =
                tokio::time::interval(std::time::Duration::from_secs(10));
            maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = maintenance.tick() => {
                        manager.expire_pending_joins().await;
                        manager.expire_closed_streams().await;
                        let verifier = manager.clone();
                        tokio::spawn(async move {
                            verifier.verify_ready_segments().await;
                        });
                    }
                    message = messages.recv() => match message {
                        Ok(message) if message.application_id == STREAM_INTERNAL_APPLICATION_ID => {
                            if let Err(error) = manager.process_direct_message(message).await {
                                crate::teprintln!("[stream] Rejected stream message: {error}");
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            crate::teprintln!("[stream] Direct stream bridge lagged by {skipped} message(s)");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
            commitment_task.abort();
            let _ = commitment_task.await;
        })
    }

    pub async fn start_stream(
        &self,
        app: &AuthenticatedAppSession,
        opaque_metadata: Vec<u8>,
    ) -> Result<StreamDescriptor, StreamTransportError> {
        if opaque_metadata.len() > STREAM_MAX_METADATA_BYTES {
            return Err(StreamTransportError::InvalidMetadata);
        }
        let stream_id = Uuid::new_v4().simple().to_string();
        let generation = 1;
        let created_at = current_timestamp();
        let store = self
            .storage
            .create_internal_store(
                app,
                format!("stream:{stream_id}:commitments:0"),
                STREAM_COMMITMENT_SUBKEYS,
            )
            .await?;
        let identity = self.signing.identity(app, &self.main_dht).await?;
        let unsigned = UnsignedStreamDescriptor {
            version: STREAM_PROTOCOL_VERSION,
            stream_id: stream_id.clone(),
            application_id: app.app_id().to_string(),
            streamer_main_dht: self.main_dht.clone(),
            generation,
            commitment_root_record_key: store.record_key.clone(),
            signing_public_key_hex: identity.public_key_hex,
            signing_key_generation: identity.key_generation,
            opaque_metadata_base64: BASE64.encode(opaque_metadata),
            packet_bytes: STREAM_PACKET_BYTES as u32,
            packets_per_segment: STREAM_PACKETS_PER_SEGMENT,
            created_at,
        };
        let descriptor_signature = self
            .signing
            .sign(
                app,
                STREAM_DESCRIPTOR_DOMAIN.to_string(),
                &serialize(&unsigned)?,
            )
            .await?;
        let descriptor = StreamDescriptor {
            version: unsigned.version,
            stream_id: unsigned.stream_id,
            application_id: unsigned.application_id,
            streamer_main_dht: unsigned.streamer_main_dht,
            generation: unsigned.generation,
            commitment_root_record_key: unsigned.commitment_root_record_key,
            signing_public_key_hex: unsigned.signing_public_key_hex,
            signing_key_generation: unsigned.signing_key_generation,
            opaque_metadata_base64: unsigned.opaque_metadata_base64,
            packet_bytes: unsigned.packet_bytes,
            packets_per_segment: unsigned.packets_per_segment,
            created_at: unsigned.created_at,
            signature_hex: descriptor_signature.signature_hex,
        };
        self.verify_descriptor(&descriptor)?;

        let header = self
            .signed_record_header(
                app,
                CommitmentRecordHeaderUnsigned {
                    magic: STREAM_RECORD_MAGIC,
                    version: STREAM_PROTOCOL_VERSION,
                    stream_id: stream_id.clone(),
                    generation,
                    record_index: 0,
                    root_record_key: store.record_key.clone(),
                    first_segment: 0,
                    next_record_key: None,
                    descriptor: Some(descriptor.clone()),
                },
            )
            .await?;
        self.write_store_value(app, &store.store_id, 0, &header).await?;

        let outgoing = OutgoingStreamState {
            owner: app.clone(),
            descriptor: descriptor.clone(),
            running: true,
            closed_at: None,
            participants: HashMap::new(),
            direct_children: HashSet::new(),
            next_sequence: 0,
            current_segment: 0,
            current_packets: Vec::new(),
            packet_cache: VecDeque::new(),
            pending_segments: VecDeque::new(),
            commitment_records: vec![CommitmentRecordState {
                store_id: store.store_id,
                record_key: store.record_key,
                record_index: 0,
                page_index: 0,
                first_segment: 0,
                page_commitments: Vec::new(),
            }],
            previous_commitment_hash: [0; 32],
        };
        self.state
            .lock()
            .await
            .outgoing
            .insert(stream_id.clone(), outgoing);
        self.emit(StreamEvent::Started {
            application_id: app.app_id().to_string(),
            descriptor: descriptor.clone(),
        });
        Ok(descriptor)
    }

    pub async fn join_stream(
        &self,
        app: &AuthenticatedAppSession,
        descriptor: StreamDescriptor,
        relay_capacity: u16,
    ) -> Result<(), StreamTransportError> {
        self.verify_descriptor(&descriptor)?;
        if !same_stream_application_family(&descriptor.application_id, &app.app_id().to_string()) {
            return Err(StreamTransportError::InvalidDescriptor(
                "stream application family does not match the authenticated app".into(),
            ));
        }
        if descriptor.streamer_main_dht == self.main_dht {
            return Err(StreamTransportError::InvalidDescriptor(
                "cannot join our own outgoing stream as a viewer".into(),
            ));
        }
        let relay_capacity = relay_capacity.min(STREAM_MAX_RELAY_CHILDREN);
        let stream_id = descriptor.stream_id.clone();
        self.state.lock().await.incoming.insert(
            stream_id.clone(),
            IncomingStreamState {
                application_id: app.app_id().to_string(),
                descriptor: descriptor.clone(),
                running: true,
                closed_at: None,
                relay_capacity,
                parent_main_dht: None,
                standby_parent_main_dht: None,
                children: HashSet::new(),
                packet_cache: VecDeque::new(),
                received_segments: HashMap::new(),
                verified_commitment_hashes: BTreeMap::new(),
                latest_sequence: 0,
                latest_segment: 0,
                join_requested_at: current_timestamp(),
            },
        );
        self.emit(StreamEvent::JoinPending {
            application_id: app.app_id().to_string(),
            stream_id: stream_id.clone(),
            streamer_main_dht: descriptor.streamer_main_dht.clone(),
        });

        // Establishing the initial source session can take several handshake
        // retries. Keep the local API responsive and report completion or
        // failure through the stream subscription.
        let manager = self.clone();
        let source = descriptor.streamer_main_dht.clone();
        tokio::spawn(async move {
            let result = manager
                .send_wire(
                    &source,
                    StreamWireMessage::JoinRequest {
                        descriptor,
                        viewer_main_dht: manager.main_dht.clone(),
                        relay_capacity,
                        requested_at: current_timestamp(),
                    },
                )
                .await;
            if let Err(error) = result {
                let removed = manager.state.lock().await.incoming.remove(&stream_id);
                if let Some(stream) = removed {
                    manager.emit(StreamEvent::Ended {
                        application_id: stream.application_id,
                        stream_id,
                        reason: format!("stream join could not reach the source: {error}"),
                    });
                }
            }
        });
        Ok(())
    }

    pub async fn write_stream(
        &self,
        app: &AuthenticatedAppSession,
        stream_id: &str,
        data: &[u8],
    ) -> Result<StreamWriteResult, StreamTransportError> {
        validate_stream_id(stream_id)?;
        if data.is_empty() {
            return Err(StreamTransportError::EmptyWrite);
        }
        if data.len() > STREAM_MAX_WRITE_BYTES {
            return Err(StreamTransportError::WriteTooLarge(data.len()));
        }

        let (audience_count, running) = {
            let state = self.state.lock().await;
            let stream = state
                .outgoing
                .get(stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            ensure_stream_owner(app, stream)?;
            (stream.participants.len(), stream.running)
        };
        if !running {
            return Err(StreamTransportError::StreamAlreadyClosed);
        }

        // A live source is allowed to keep producing while nobody is
        // watching, but the daemon deliberately discards those bytes. This
        // prevents an unattended stream from consuming route bandwidth or DHT
        // commitment space.
        if audience_count == 0 {
            let state = self.state.lock().await;
            let stream = state
                .outgoing
                .get(stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            return Ok(StreamWriteResult {
                stream_id: stream_id.to_string(),
                accepted_bytes: data.len(),
                emitted_packets: 0,
                audience_count: 0,
                transmitted: false,
                next_sequence: stream.next_sequence,
                current_segment: stream.current_segment,
            });
        }

        let mut emitted_packets = 0usize;
        let mut sealed_any_segment = false;
        for chunk in data.chunks(STREAM_PACKET_BYTES) {
            let (packet, children, sealed_segment) = {
                let mut state = self.state.lock().await;
                let stream = state
                    .outgoing
                    .get_mut(stream_id)
                    .ok_or(StreamTransportError::StreamNotFound)?;
                ensure_stream_owner(app, stream)?;
                if !stream.running {
                    return Err(StreamTransportError::StreamAlreadyClosed);
                }
                if stream.pending_segments.len() >= STREAM_MAX_PENDING_COMMITMENTS
                    && stream.current_packets.len().saturating_add(1)
                        >= STREAM_PACKETS_PER_SEGMENT as usize
                {
                    return Err(StreamTransportError::CommitmentBacklogFull);
                }

                let segment_number = stream.current_segment;
                let packet = StreamPacketWire {
                    stream_id: stream_id.to_string(),
                    generation: stream.descriptor.generation,
                    sequence: stream.next_sequence,
                    segment_number,
                    packet_index: stream.current_packets.len() as u32,
                    retransmission: false,
                    payload: chunk.to_vec(),
                };
                stream.next_sequence = stream.next_sequence.saturating_add(1);
                stream.current_packets.push(packet.clone());
                cache_packet(&mut stream.packet_cache, packet.clone(), segment_number);
                let children = stream.direct_children.iter().cloned().collect::<Vec<_>>();
                let sealed_segment =
                    stream.current_packets.len() as u32 >= STREAM_PACKETS_PER_SEGMENT
                        && seal_current_segment(stream);
                (packet, children, sealed_segment)
            };

            // Route delivery is intentionally independent from DHT
            // commitment publication. A slow DHT write must never hold the
            // live packetizer on the same segment number.
            self.send_wire_many(children, StreamWireMessage::Packet(packet))
                .await;
            emitted_packets = emitted_packets.saturating_add(1);
            sealed_any_segment |= sealed_segment;
        }

        if sealed_any_segment {
            self.commitment_notify.notify_one();
        }

        let state = self.state.lock().await;
        let stream = state
            .outgoing
            .get(stream_id)
            .ok_or(StreamTransportError::StreamNotFound)?;
        Ok(StreamWriteResult {
            stream_id: stream_id.to_string(),
            accepted_bytes: data.len(),
            emitted_packets,
            audience_count: stream.participants.len(),
            transmitted: emitted_packets > 0,
            next_sequence: stream.next_sequence,
            current_segment: stream.current_segment,
        })
    }

    pub async fn flush_stream(
        &self,
        app: &AuthenticatedAppSession,
        stream_id: &str,
    ) -> Result<Option<StreamSegmentCommitment>, StreamTransportError> {
        validate_stream_id(stream_id)?;
        let sealed = {
            let mut state = self.state.lock().await;
            let stream = state
                .outgoing
                .get_mut(stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            ensure_stream_owner(app, stream)?;
            if !stream.current_packets.is_empty()
                && stream.pending_segments.len() >= STREAM_MAX_PENDING_COMMITMENTS
            {
                return Err(StreamTransportError::CommitmentBacklogFull);
            }
            seal_current_segment(stream)
        };
        if sealed {
            self.commitment_notify.notify_one();
        }

        // Flush is the one API call that deliberately waits for the signed DHT
        // commitment. Normal writes only enqueue commitment work.
        self.commit_pending_segments(stream_id).await
    }

    pub async fn leave_stream(
        &self,
        app: &AuthenticatedAppSession,
        stream_id: &str,
    ) -> Result<(), StreamTransportError> {
        validate_stream_id(stream_id)?;
        let incoming = {
            let mut state = self.state.lock().await;
            let incoming = state.incoming.remove(stream_id).ok_or(StreamTransportError::StreamNotFound)?;
            if incoming.application_id != app.app_id().to_string() {
                state.incoming.insert(stream_id.to_string(), incoming);
                return Err(StreamTransportError::NotStreamOwner);
            }
            incoming
        };
        let message = StreamWireMessage::Leave {
            stream_id: stream_id.to_string(),
            generation: incoming.descriptor.generation,
            viewer_main_dht: self.main_dht.clone(),
        };
        let mut recipients = vec![incoming.descriptor.streamer_main_dht.clone()];
        if let Some(parent) = incoming.parent_main_dht {
            if !recipients.contains(&parent) {
                recipients.push(parent);
            }
        }
        self.send_wire_many(recipients, message).await;
        Ok(())
    }

    pub async fn close_stream(
        &self,
        app: &AuthenticatedAppSession,
        stream_id: &str,
        reason: String,
    ) -> Result<(), StreamTransportError> {
        validate_stream_id(stream_id)?;
        if reason.as_bytes().len() > STREAM_MAX_CLOSE_REASON_BYTES {
            return Err(StreamTransportError::InvalidCloseReason);
        }
        let (application_id, generation, children, sealed) = {
            let mut state = self.state.lock().await;
            let stream = state
                .outgoing
                .get_mut(stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            ensure_stream_owner(app, stream)?;
            if !stream.running {
                return Err(StreamTransportError::StreamAlreadyClosed);
            }
            if !stream.current_packets.is_empty()
                && stream.pending_segments.len() >= STREAM_MAX_PENDING_COMMITMENTS
            {
                return Err(StreamTransportError::CommitmentBacklogFull);
            }
            stream.running = false;
            stream.closed_at = Some(current_timestamp());
            let sealed = seal_current_segment(stream);
            (
                stream.descriptor.application_id.clone(),
                stream.descriptor.generation,
                stream.direct_children.iter().cloned().collect::<Vec<_>>(),
                sealed,
            )
        };
        if sealed {
            self.commitment_notify.notify_one();
        }
        // Closing the live route must not wait for a possibly slow DHT
        // publication. The final commitment remains in the retry queue.
        self.send_wire_many(
            children,
            StreamWireMessage::End {
                stream_id: stream_id.to_string(),
                generation,
                reason: reason.clone(),
            },
        )
        .await;
        self.emit(StreamEvent::Ended {
            application_id,
            stream_id: stream_id.to_string(),
            reason,
        });
        Ok(())
    }

    pub async fn list_streams(&self, app: &AuthenticatedAppSession) -> Vec<StreamSummary> {
        let app_id = app.app_id().to_string();
        let state = self.state.lock().await;
        let mut result = Vec::new();
        for stream in state.outgoing.values().filter(|stream| stream.descriptor.application_id == app_id) {
            result.push(StreamSummary {
                descriptor: stream.descriptor.clone(),
                role: StreamRole::Streamer,
                running: stream.running,
                viewer_count: stream.participants.len(),
                direct_child_count: stream.direct_children.len(),
                parent_main_dht: None,
                standby_parent_main_dht: None,
                next_sequence: stream.next_sequence,
                current_segment: stream.current_segment,
            });
        }
        for stream in state.incoming.values().filter(|stream| stream.application_id == app_id) {
            result.push(StreamSummary {
                descriptor: stream.descriptor.clone(),
                role: StreamRole::Viewer,
                running: stream.running,
                viewer_count: 0,
                direct_child_count: stream.children.len(),
                parent_main_dht: stream.parent_main_dht.clone(),
                standby_parent_main_dht: stream.standby_parent_main_dht.clone(),
                next_sequence: stream.latest_sequence.saturating_add(1),
                current_segment: stream.latest_segment,
            });
        }
        result.sort_by(|left, right| left.descriptor.created_at.cmp(&right.descriptor.created_at));
        result
    }

    async fn process_direct_message(
        &self,
        message: DirectApplicationMessage,
    ) -> Result<(), StreamTransportError> {
        let wire: StreamWireMessage = deserialize(&message.payload)?;
        match wire {
            StreamWireMessage::JoinRequest {
                descriptor,
                viewer_main_dht,
                relay_capacity,
                requested_at,
            } => {
                let stream_id = descriptor.stream_id.clone();
                let generation = descriptor.generation;
                match self
                    .handle_join_request(
                        &message.sender_dht,
                        descriptor,
                        viewer_main_dht,
                        relay_capacity,
                        requested_at,
                    )
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let _ = self
                            .send_wire(
                                &message.sender_dht,
                                StreamWireMessage::JoinRejected {
                                    stream_id,
                                    generation,
                                    reason: "the stream source did not accept this viewer"
                                        .to_string(),
                                },
                            )
                            .await;
                        Err(error)
                    }
                }
            }
            StreamWireMessage::JoinAccepted {
                descriptor,
                parent_main_dht,
                standby_parent_main_dht,
                latest_sequence,
                latest_segment,
            } => {
                self.handle_join_accepted(
                    &message.sender_dht,
                    descriptor,
                    parent_main_dht,
                    standby_parent_main_dht,
                    latest_sequence,
                    latest_segment,
                )
                .await
            }
            StreamWireMessage::JoinRejected {
                stream_id,
                generation,
                reason,
            } => self.handle_join_rejected(&message.sender_dht, &stream_id, generation, reason).await,
            StreamWireMessage::AssignChild {
                stream_id,
                generation,
                child_main_dht,
            } => self.handle_assign_child(&message.sender_dht, &stream_id, generation, child_main_dht).await,
            StreamWireMessage::ParentAssignment {
                stream_id,
                generation,
                parent_main_dht,
                standby_parent_main_dht,
            } => self.handle_parent_assignment(
                &message.sender_dht,
                &stream_id,
                generation,
                parent_main_dht,
                standby_parent_main_dht,
            ).await,
            StreamWireMessage::Packet(packet) => self.handle_packet(&message.sender_dht, packet).await,
            StreamWireMessage::CommitmentHint(hint) => self.handle_commitment_hint(&message.sender_dht, hint).await,
            StreamWireMessage::RetransmitRequest {
                stream_id,
                generation,
                segment_number,
                packet_indices,
            } => self.handle_retransmit_request(
                &message.sender_dht,
                &stream_id,
                generation,
                segment_number,
                packet_indices,
            ).await,
            StreamWireMessage::Leave {
                stream_id,
                generation,
                viewer_main_dht,
            } => self.handle_leave(&message.sender_dht, &stream_id, generation, viewer_main_dht).await,
            StreamWireMessage::End {
                stream_id,
                generation,
                reason,
            } => self.handle_end(&message.sender_dht, &stream_id, generation, reason).await,
        }
    }

    async fn handle_join_request(
        &self,
        sender: &str,
        descriptor: StreamDescriptor,
        viewer_main_dht: String,
        relay_capacity: u16,
        requested_at: u64,
    ) -> Result<(), StreamTransportError> {
        if sender != viewer_main_dht {
            return Err(StreamTransportError::InvalidDescriptor(
                "join sender does not match the viewer identity".into(),
            ));
        }
        let now = current_timestamp();
        if requested_at.saturating_add(STREAM_JOIN_TIMEOUT_SECS) < now
            || requested_at > now.saturating_add(5 * 60)
        {
            return Err(StreamTransportError::JoinRejected("join request expired".into()));
        }
        self.verify_descriptor(&descriptor)?;
        if descriptor.streamer_main_dht != self.main_dht {
            return Err(StreamTransportError::InvalidDescriptor(
                "join request targets a different streamer".into(),
            ));
        }

        let selection = {
            let mut state = self.state.lock().await;
            let stream = state
                .outgoing
                .get_mut(&descriptor.stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            if stream.descriptor.generation != descriptor.generation || !stream.running {
                return Err(StreamTransportError::StreamAlreadyClosed);
            }
            if stream.participants.len() >= STREAM_MAX_VIEWERS {
                return Err(StreamTransportError::ViewerLimitReached);
            }
            if let Some(existing) = stream.participants.get(&viewer_main_dht) {
                let standby = choose_standby(stream, &existing.parent_main_dht, &viewer_main_dht);
                (
                    existing.parent_main_dht.clone(),
                    standby,
                    stream.descriptor.clone(),
                    stream.next_sequence,
                    stream.current_segment,
                    stream.participants.len(),
                    existing.parent_main_dht != self.main_dht,
                    true,
                )
            } else {
                let (parent, depth) = choose_parent(stream, &self.main_dht);
                let standby = choose_standby(stream, &parent, &viewer_main_dht);
                if parent == self.main_dht {
                    stream.direct_children.insert(viewer_main_dht.clone());
                } else if let Some(parent_state) = stream.participants.get_mut(&parent) {
                    parent_state.children.insert(viewer_main_dht.clone());
                }
                stream.participants.insert(
                    viewer_main_dht.clone(),
                    ParticipantState {
                        parent_main_dht: parent.clone(),
                        children: HashSet::new(),
                        relay_capacity: relay_capacity.min(STREAM_MAX_RELAY_CHILDREN),
                        depth,
                        joined_at: current_timestamp(),
                    },
                );
                (
                    parent.clone(),
                    standby,
                    stream.descriptor.clone(),
                    stream.next_sequence,
                    stream.current_segment,
                    stream.participants.len(),
                    parent != self.main_dht,
                    false,
                )
            }
        };

        let (
            parent,
            standby,
            canonical_descriptor,
            latest_sequence,
            latest_segment,
            viewer_count,
            assign_parent,
            was_existing,
        ) = selection;
        if assign_parent {
            if let Err(error) = self
                .send_wire(
                    &parent,
                    StreamWireMessage::AssignChild {
                        stream_id: descriptor.stream_id.clone(),
                        generation: descriptor.generation,
                        child_main_dht: viewer_main_dht.clone(),
                    },
                )
                .await
            {
                if !was_existing {
                    let mut state = self.state.lock().await;
                    if let Some(stream) = state.outgoing.get_mut(&descriptor.stream_id) {
                        stream.participants.remove(&viewer_main_dht);
                        for participant in stream.participants.values_mut() {
                            participant.children.remove(&viewer_main_dht);
                        }
                    }
                }
                return Err(error);
            }
        }
        if let Err(error) = self
            .send_wire(
                &viewer_main_dht,
                StreamWireMessage::JoinAccepted {
                    descriptor: canonical_descriptor.clone(),
                    parent_main_dht: parent.clone(),
                    standby_parent_main_dht: standby.clone(),
                    latest_sequence,
                    latest_segment,
                },
            )
            .await
        {
            if !was_existing {
                let mut state = self.state.lock().await;
                if let Some(stream) = state.outgoing.get_mut(&descriptor.stream_id) {
                    stream.participants.remove(&viewer_main_dht);
                    stream.direct_children.remove(&viewer_main_dht);
                    for participant in stream.participants.values_mut() {
                        participant.children.remove(&viewer_main_dht);
                    }
                }
            }
            return Err(error);
        }
        self.emit(StreamEvent::ViewerJoined {
            application_id: canonical_descriptor.application_id,
            stream_id: canonical_descriptor.stream_id,
            viewer_main_dht,
            parent_main_dht: parent,
            viewer_count,
        });
        Ok(())
    }

    async fn handle_join_accepted(
        &self,
        sender: &str,
        descriptor: StreamDescriptor,
        parent_main_dht: String,
        standby_parent_main_dht: Option<String>,
        latest_sequence: u64,
        latest_segment: u64,
    ) -> Result<(), StreamTransportError> {
        self.verify_descriptor(&descriptor)?;
        if sender != descriptor.streamer_main_dht {
            return Err(StreamTransportError::InvalidDescriptor(
                "join acceptance did not come from the original streamer".into(),
            ));
        }
        let application_id = {
            let mut state = self.state.lock().await;
            let stream = state
                .incoming
                .get_mut(&descriptor.stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            if stream.descriptor.generation != descriptor.generation {
                return Err(StreamTransportError::InvalidDescriptor("generation changed during join".into()));
            }
            stream.descriptor = descriptor.clone();
            stream.parent_main_dht = Some(parent_main_dht.clone());
            stream.standby_parent_main_dht = standby_parent_main_dht.clone();
            stream.latest_sequence = latest_sequence.saturating_sub(1);
            stream.latest_segment = latest_segment;
            stream.application_id.clone()
        };
        if parent_main_dht != self.main_dht && parent_main_dht != descriptor.streamer_main_dht {
            spawn_session_ensure(self.handshake.clone(), parent_main_dht.clone());
        }
        self.emit(StreamEvent::Joined {
            application_id,
            descriptor,
            parent_main_dht,
            standby_parent_main_dht,
        });
        Ok(())
    }

    async fn handle_join_rejected(
        &self,
        sender: &str,
        stream_id: &str,
        generation: u64,
        reason: String,
    ) -> Result<(), StreamTransportError> {
        if reason.as_bytes().len() > STREAM_MAX_CLOSE_REASON_BYTES {
            return Err(StreamTransportError::InvalidDescriptor(
                "stream rejection text exceeds the configured limit".into(),
            ));
        }
        let removed = {
            let mut state = self.state.lock().await;
            let Some(stream) = state.incoming.get(stream_id) else {
                return Ok(());
            };
            if stream.descriptor.streamer_main_dht != sender || stream.descriptor.generation != generation {
                return Err(StreamTransportError::InvalidDescriptor("invalid join rejection source".into()));
            }
            state.incoming.remove(stream_id)
        };
        if let Some(stream) = removed {
            self.emit(StreamEvent::Ended {
                application_id: stream.application_id,
                stream_id: stream_id.to_string(),
                reason,
            });
        }
        Ok(())
    }

    async fn handle_assign_child(
        &self,
        sender: &str,
        stream_id: &str,
        generation: u64,
        child_main_dht: String,
    ) -> Result<(), StreamTransportError> {
        let (application_id, child_count) = {
            let mut state = self.state.lock().await;
            let stream = state.incoming.get_mut(stream_id).ok_or(StreamTransportError::StreamNotFound)?;
            if stream.descriptor.streamer_main_dht != sender || stream.descriptor.generation != generation {
                return Err(StreamTransportError::InvalidDescriptor("child assignment was not issued by the streamer".into()));
            }
            if !stream.children.contains(&child_main_dht)
                && stream.children.len() >= stream.relay_capacity as usize
            {
                return Err(StreamTransportError::JoinRejected(
                    "relay has no remaining child capacity".into(),
                ));
            }
            stream.children.insert(child_main_dht.clone());
            (stream.application_id.clone(), stream.children.len())
        };
        spawn_session_ensure(self.handshake.clone(), child_main_dht.clone());
        self.emit(StreamEvent::TopologyChanged {
            application_id,
            stream_id: stream_id.to_string(),
            parent_main_dht: None,
            child_count,
        });
        Ok(())
    }

    async fn handle_parent_assignment(
        &self,
        sender: &str,
        stream_id: &str,
        generation: u64,
        parent_main_dht: String,
        standby_parent_main_dht: Option<String>,
    ) -> Result<(), StreamTransportError> {
        let (application_id, child_count) = {
            let mut state = self.state.lock().await;
            let stream = state.incoming.get_mut(stream_id).ok_or(StreamTransportError::StreamNotFound)?;
            if stream.descriptor.streamer_main_dht != sender || stream.descriptor.generation != generation {
                return Err(StreamTransportError::InvalidDescriptor("parent assignment was not issued by the streamer".into()));
            }
            stream.parent_main_dht = Some(parent_main_dht.clone());
            stream.standby_parent_main_dht = standby_parent_main_dht;
            (stream.application_id.clone(), stream.children.len())
        };
        spawn_session_ensure(self.handshake.clone(), parent_main_dht.clone());
        self.emit(StreamEvent::TopologyChanged {
            application_id,
            stream_id: stream_id.to_string(),
            parent_main_dht: Some(parent_main_dht),
            child_count,
        });
        Ok(())
    }

    async fn handle_packet(
        &self,
        sender: &str,
        packet: StreamPacketWire,
    ) -> Result<(), StreamTransportError> {
        let (application_id, children, already_seen) = {
            let mut state = self.state.lock().await;
            let stream = state.incoming.get_mut(&packet.stream_id).ok_or(StreamTransportError::StreamNotFound)?;
            if stream.descriptor.generation != packet.generation || !stream.running {
                return Err(StreamTransportError::InvalidDescriptor("packet generation is not active".into()));
            }
            if packet.payload.is_empty()
                || packet.payload.len() > STREAM_PACKET_BYTES
                || packet.packet_index >= STREAM_PACKETS_PER_SEGMENT
            {
                return Err(StreamTransportError::InvalidDescriptor(
                    "stream packet sizing is invalid".into(),
                ));
            }
            if packet.segment_number
                > stream.latest_segment.saturating_add(STREAM_MAX_SEGMENT_AHEAD)
                || packet
                    .segment_number
                    .saturating_add(STREAM_RECEIVED_SEGMENT_WINDOW)
                    < stream.latest_segment
            {
                return Err(StreamTransportError::InvalidDescriptor(
                    "stream packet segment is outside the receive window".into(),
                ));
            }
            let upstream_allowed = stream.parent_main_dht.as_deref() == Some(sender)
                || stream.standby_parent_main_dht.as_deref() == Some(sender)
                || stream.descriptor.streamer_main_dht == sender;
            if !upstream_allowed {
                return Err(StreamTransportError::InvalidDescriptor("packet did not come from an assigned upstream peer".into()));
            }
            let segment = stream.received_segments.entry(packet.segment_number).or_default();
            let replace_retransmission = segment
                .packets
                .get(&packet.packet_index)
                .is_some_and(|existing| {
                    packet.retransmission
                        && (existing.sequence != packet.sequence
                            || existing.payload != packet.payload)
                });
            let already_seen =
                segment.packets.contains_key(&packet.packet_index) && !replace_retransmission;
            if !already_seen {
                segment.packets.insert(packet.packet_index, packet.clone());
                segment.verified = false;
                stream.latest_sequence = stream.latest_sequence.max(packet.sequence);
                stream.latest_segment = stream.latest_segment.max(packet.segment_number);
                cache_packet(&mut stream.packet_cache, packet.clone(), packet.segment_number);
            }
            (
                stream.application_id.clone(),
                stream.children.iter().filter(|child| child.as_str() != sender).cloned().collect::<Vec<_>>(),
                already_seen,
            )
        };
        if already_seen {
            return Ok(());
        }
        self.emit(StreamEvent::Data {
            application_id: application_id.clone(),
            stream_id: packet.stream_id.clone(),
            generation: packet.generation,
            sequence: packet.sequence,
            segment_number: packet.segment_number,
            packet_index: packet.packet_index,
            retransmission: packet.retransmission,
            payload_base64: BASE64.encode(&packet.payload),
        });
        let forwarder = self.clone();
        let forwarded_packet = packet.clone();
        tokio::spawn(async move {
            forwarder
                .send_wire_many(children, StreamWireMessage::Packet(forwarded_packet))
                .await;
        });
        let verifier = self.clone();
        let verify_stream_id = packet.stream_id.clone();
        let verify_segment = packet.segment_number;
        tokio::spawn(async move {
            if let Err(error) = verifier
                .try_verify_received_segment(&verify_stream_id, verify_segment)
                .await
            {
                crate::teprintln!(
                    "[stream] Could not verify stream {} segment {}: {}",
                    verify_stream_id,
                    verify_segment,
                    error
                );
            }
        });
        Ok(())
    }

    async fn handle_commitment_hint(
        &self,
        sender: &str,
        hint: StreamCommitmentHint,
    ) -> Result<(), StreamTransportError> {
        if !(1..=STREAM_COMMITMENT_PAGES_PER_RECORD).contains(&hint.page_location) {
            return Err(StreamTransportError::InvalidDescriptor(
                "commitment hint subkey is outside the record schema".into(),
            ));
        }
        let (children, valid_source) = {
            let mut state = self.state.lock().await;
            let stream = state.incoming.get_mut(&hint.stream_id).ok_or(StreamTransportError::StreamNotFound)?;
            let valid_source = stream.parent_main_dht.as_deref() == Some(sender)
                || stream.standby_parent_main_dht.as_deref() == Some(sender)
                || stream.descriptor.streamer_main_dht == sender;
            if valid_source {
                stream.received_segments.entry(hint.segment_number).or_default().hint = Some(hint.clone());
            }
            (stream.children.iter().filter(|child| child.as_str() != sender).cloned().collect::<Vec<_>>(), valid_source)
        };
        if !valid_source {
            return Err(StreamTransportError::InvalidDescriptor("commitment hint came from an unrelated peer".into()));
        }
        let forwarder = self.clone();
        let forwarded_hint = hint.clone();
        tokio::spawn(async move {
            forwarder
                .send_wire_many(
                    children,
                    StreamWireMessage::CommitmentHint(forwarded_hint),
                )
                .await;
        });
        let verifier = self.clone();
        let verify_stream_id = hint.stream_id.clone();
        let verify_segment = hint.segment_number;
        tokio::spawn(async move {
            if let Err(error) = verifier
                .try_verify_received_segment(&verify_stream_id, verify_segment)
                .await
            {
                crate::teprintln!(
                    "[stream] Could not verify stream {} segment {}: {}",
                    verify_stream_id,
                    verify_segment,
                    error
                );
            }
        });
        Ok(())
    }

    async fn try_verify_received_segment(
        &self,
        stream_id: &str,
        segment_number: u64,
    ) -> Result<(), StreamTransportError> {
        let (
            application_id,
            descriptor,
            packets,
            hint,
            parent,
            standby_parent,
            already_verified,
        ) = {
            let state = self.state.lock().await;
            let stream = state
                .incoming
                .get(stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            let segment = stream
                .received_segments
                .get(&segment_number)
                .cloned()
                .unwrap_or_default();
            (
                stream.application_id.clone(),
                stream.descriptor.clone(),
                segment.packets,
                segment.hint,
                stream.parent_main_dht.clone(),
                stream.standby_parent_main_dht.clone(),
                segment.verified,
            )
        };
        if already_verified {
            return Ok(());
        }
        let Some(hint) = hint else {
            return Ok(());
        };

        let commitment = self
            .read_and_verify_commitment_page(&descriptor, &hint)
            .await?;
        let missing = missing_packet_indices(&packets, commitment.packet_count);
        if !missing.is_empty() {
            let now = current_timestamp();
            let should_request = {
                let mut state = self.state.lock().await;
                state
                    .incoming
                    .get_mut(stream_id)
                    .and_then(|stream| stream.received_segments.get_mut(&segment_number))
                    .is_some_and(|segment| {
                        if now.saturating_sub(segment.last_retransmit_at) >= 2 {
                            segment.last_retransmit_at = now;
                            true
                        } else {
                            false
                        }
                    })
            };
            if should_request {
                self.emit(StreamEvent::SegmentMissingPackets {
                    application_id: application_id.clone(),
                    stream_id: stream_id.to_string(),
                    segment_number,
                    missing_packet_indices: missing.clone(),
                });
                if let Some(parent) = parent {
                    self.send_wire(
                        &parent,
                        StreamWireMessage::RetransmitRequest {
                            stream_id: stream_id.to_string(),
                            generation: descriptor.generation,
                            segment_number,
                            packet_indices: missing
                                .into_iter()
                                .take(STREAM_MAX_RETRANSMIT_INDICES)
                                .collect(),
                        },
                    )
                    .await?;
                }
            }
            return Ok(());
        }

        let computed = hash_received_packets(&packets, commitment.packet_count)?;
        if computed != commitment.sha256 {
            self.emit(StreamEvent::IntegrityFailure {
                application_id: application_id.clone(),
                stream_id: stream_id.to_string(),
                segment_number,
                detail:
                    "received packet bytes do not match the streamer's signed DHT commitment"
                        .into(),
            });

            // A whole-segment hash cannot identify which relay packet was
            // modified. Request a clean copy from the standby path, or from
            // the original source when no independent standby is available.
            let recovery_peer = standby_parent
                .filter(|peer| Some(peer.as_str()) != parent.as_deref())
                .or_else(|| {
                    (Some(descriptor.streamer_main_dht.as_str()) != parent.as_deref())
                        .then(|| descriptor.streamer_main_dht.clone())
                });
            if let Some(recovery_peer) = recovery_peer {
                let _ = self
                    .send_wire(
                        &recovery_peer,
                        StreamWireMessage::RetransmitRequest {
                            stream_id: stream_id.to_string(),
                            generation: descriptor.generation,
                            segment_number,
                            packet_indices: (0..commitment.packet_count).collect(),
                        },
                    )
                    .await;
            }
            return Err(StreamTransportError::Integrity(
                "segment hash mismatch".into(),
            ));
        }

        let commitment_hash = hash_serialized(&commitment)?;
        let chain_ready = {
            let state = self.state.lock().await;
            let stream = state
                .incoming
                .get(stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            if segment_number == 0 {
                if commitment.previous_commitment_hash != [0; 32] {
                    return Err(StreamTransportError::Integrity(
                        "first commitment does not begin a valid chain".into(),
                    ));
                }
                true
            } else if let Some(previous_hash) =
                stream.verified_commitment_hashes.get(&segment_number.saturating_sub(1))
            {
                if commitment.previous_commitment_hash != *previous_hash {
                    return Err(StreamTransportError::Integrity(
                        "stream commitment chain is broken".into(),
                    ));
                }
                true
            } else {
                false
            }
        };
        if !chain_ready {
            // The bytes and signed commitment are valid, but an earlier
            // segment must be verified before this link in the hash chain can
            // be accepted. The maintenance verifier will revisit it.
            return Ok(());
        }

        {
            let mut state = self.state.lock().await;
            if let Some(stream) = state.incoming.get_mut(stream_id) {
                if let Some(segment) = stream.received_segments.get_mut(&segment_number) {
                    segment.verified = true;
                }
                stream
                    .verified_commitment_hashes
                    .insert(segment_number, commitment_hash);
                let oldest_kept =
                    segment_number.saturating_sub(STREAM_RECEIVED_SEGMENT_WINDOW);
                stream
                    .received_segments
                    .retain(|number, _| *number >= oldest_kept);
                stream
                    .verified_commitment_hashes
                    .retain(|number, _| *number >= oldest_kept.saturating_sub(1));
            }
        }
        self.emit(StreamEvent::SegmentVerified {
            application_id,
            stream_id: stream_id.to_string(),
            segment_number,
            sha256_hex: hex::encode(computed),
        });
        Ok(())
    }

    async fn verify_ready_segments(&self) {
        let pending = {
            let state = self.state.lock().await;
            state
                .incoming
                .iter()
                .flat_map(|(stream_id, stream)| {
                    stream
                        .received_segments
                        .iter()
                        .filter(|(_, segment)| !segment.verified && segment.hint.is_some())
                        .map(|(segment_number, _)| (stream_id.clone(), *segment_number))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        for (stream_id, segment_number) in pending {
            if let Err(error) = self
                .try_verify_received_segment(&stream_id, segment_number)
                .await
            {
                if matches!(&error, StreamTransportError::Integrity(_)) {
                    crate::teprintln!(
                        "[stream] Deferred verification rejected stream {} segment {}: {}",
                        stream_id,
                        segment_number,
                        error
                    );
                }
            }
        }
    }

    async fn handle_retransmit_request(
        &self,
        sender: &str,
        stream_id: &str,
        generation: u64,
        segment_number: u64,
        mut packet_indices: Vec<u32>,
    ) -> Result<(), StreamTransportError> {
        packet_indices.sort_unstable();
        packet_indices.dedup();
        packet_indices.retain(|index| *index < STREAM_PACKETS_PER_SEGMENT);
        packet_indices.truncate(STREAM_MAX_RETRANSMIT_INDICES);
        if packet_indices.is_empty() {
            return Ok(());
        }
        let (packets, upstream) = {
            let state = self.state.lock().await;
            if let Some(stream) = state.outgoing.get(stream_id) {
                if stream.descriptor.generation != generation {
                    return Err(StreamTransportError::InvalidDescriptor("retransmission generation mismatch".into()));
                }
                if !stream.participants.contains_key(sender) {
                    return Err(StreamTransportError::InvalidDescriptor(
                        "retransmission requester is not an admitted viewer".into(),
                    ));
                }
                (
                    find_cached_packets(&stream.packet_cache, segment_number, &packet_indices),
                    None,
                )
            } else if let Some(stream) = state.incoming.get(stream_id) {
                if stream.descriptor.generation != generation {
                    return Err(StreamTransportError::InvalidDescriptor("retransmission generation mismatch".into()));
                }
                if !stream.children.contains(sender) {
                    return Err(StreamTransportError::InvalidDescriptor(
                        "retransmission requester is not an assigned child".into(),
                    ));
                }
                (
                    find_cached_packets(&stream.packet_cache, segment_number, &packet_indices),
                    stream.parent_main_dht.clone(),
                )
            } else {
                return Err(StreamTransportError::StreamNotFound);
            }
        };
        let found_indices = packets.iter().map(|packet| packet.packet_index).collect::<HashSet<_>>();
        for mut packet in packets {
            packet.retransmission = true;
            let _ = self.send_wire(sender, StreamWireMessage::Packet(packet)).await;
        }
        let missing = packet_indices
            .into_iter()
            .filter(|index| !found_indices.contains(index))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            if let Some(upstream) = upstream {
                if upstream != sender {
                    let _ = self
                        .send_wire(
                            &upstream,
                            StreamWireMessage::RetransmitRequest {
                                stream_id: stream_id.to_string(),
                                generation,
                                segment_number,
                                packet_indices: missing,
                            },
                        )
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn handle_leave(
        &self,
        sender: &str,
        stream_id: &str,
        generation: u64,
        viewer_main_dht: String,
    ) -> Result<(), StreamTransportError> {
        enum LeavePath {
            Source(ReassignmentResult),
            Relay {
                application_id: String,
                streamer_main_dht: String,
                child_count: usize,
            },
        }

        let path = {
            let mut state = self.state.lock().await;
            if let Some(stream) = state.outgoing.get_mut(stream_id) {
                if stream.descriptor.generation != generation {
                    return Err(StreamTransportError::InvalidDescriptor(
                        "leave generation mismatch".into(),
                    ));
                }
                if !stream.participants.contains_key(&viewer_main_dht) {
                    return Ok(());
                }
                if sender != viewer_main_dht {
                    let valid_parent = stream
                        .participants
                        .get(&viewer_main_dht)
                        .is_some_and(|viewer| viewer.parent_main_dht == sender);
                    if !valid_parent {
                        return Err(StreamTransportError::InvalidDescriptor(
                            "invalid leave source".into(),
                        ));
                    }
                }
                LeavePath::Source(remove_participant_and_reassign(
                    stream,
                    &self.main_dht,
                    &viewer_main_dht,
                ))
            } else if let Some(stream) = state.incoming.get_mut(stream_id) {
                if stream.descriptor.generation != generation
                    || sender != viewer_main_dht
                    || !stream.children.remove(&viewer_main_dht)
                {
                    return Err(StreamTransportError::InvalidDescriptor(
                        "leave did not come from an assigned relay child".into(),
                    ));
                }
                LeavePath::Relay {
                    application_id: stream.application_id.clone(),
                    streamer_main_dht: stream.descriptor.streamer_main_dht.clone(),
                    child_count: stream.children.len(),
                }
            } else {
                return Err(StreamTransportError::StreamNotFound);
            }
        };

        match path {
            LeavePath::Source(reassignments) => {
                for (child, parent, standby) in &reassignments.assignments {
                    if parent != &self.main_dht {
                        let _ = self
                            .send_wire(
                                parent,
                                StreamWireMessage::AssignChild {
                                    stream_id: stream_id.to_string(),
                                    generation,
                                    child_main_dht: child.clone(),
                                },
                            )
                            .await;
                    }
                    let _ = self
                        .send_wire(
                            child,
                            StreamWireMessage::ParentAssignment {
                                stream_id: stream_id.to_string(),
                                generation,
                                parent_main_dht: parent.clone(),
                                standby_parent_main_dht: standby.clone(),
                            },
                        )
                        .await;
                }
                self.emit(StreamEvent::ViewerLeft {
                    application_id: reassignments.application_id,
                    stream_id: stream_id.to_string(),
                    viewer_main_dht,
                    viewer_count: reassignments.viewer_count,
                });
            }
            LeavePath::Relay {
                application_id,
                streamer_main_dht,
                child_count,
            } => {
                // The viewer also sends directly to the streamer, but relaying
                // this control message provides a second path if that session
                // vanished at the same moment the viewer departed.
                let _ = self
                    .send_wire(
                        &streamer_main_dht,
                        StreamWireMessage::Leave {
                            stream_id: stream_id.to_string(),
                            generation,
                            viewer_main_dht: viewer_main_dht.clone(),
                        },
                    )
                    .await;
                self.emit(StreamEvent::TopologyChanged {
                    application_id,
                    stream_id: stream_id.to_string(),
                    parent_main_dht: None,
                    child_count,
                });
            }
        }
        Ok(())
    }

    async fn handle_end(
        &self,
        sender: &str,
        stream_id: &str,
        generation: u64,
        reason: String,
    ) -> Result<(), StreamTransportError> {
        if reason.as_bytes().len() > STREAM_MAX_CLOSE_REASON_BYTES {
            return Err(StreamTransportError::InvalidDescriptor(
                "stream end text exceeds the configured limit".into(),
            ));
        }
        let (application_id, children) = {
            let mut state = self.state.lock().await;
            let stream = state.incoming.get_mut(stream_id).ok_or(StreamTransportError::StreamNotFound)?;
            let upstream_allowed = stream.parent_main_dht.as_deref() == Some(sender)
                || stream.descriptor.streamer_main_dht == sender;
            if !upstream_allowed || stream.descriptor.generation != generation {
                return Err(StreamTransportError::InvalidDescriptor("invalid stream end source".into()));
            }
            stream.running = false;
            stream.closed_at = Some(current_timestamp());
            (stream.application_id.clone(), stream.children.iter().cloned().collect::<Vec<_>>())
        };
        self.send_wire_many(
            children,
            StreamWireMessage::End {
                stream_id: stream_id.to_string(),
                generation,
                reason: reason.clone(),
            },
        ).await;
        self.emit(StreamEvent::Ended {
            application_id,
            stream_id: stream_id.to_string(),
            reason,
        });
        Ok(())
    }

    async fn commit_all_pending(&self) {
        let stream_ids = {
            let state = self.state.lock().await;
            state
                .outgoing
                .iter()
                .filter(|(_, stream)| !stream.pending_segments.is_empty())
                .map(|(stream_id, _)| stream_id.clone())
                .collect::<Vec<_>>()
        };
        for stream_id in stream_ids {
            if let Err(error) = self.commit_pending_segments(&stream_id).await {
                crate::teprintln!(
                    "[stream] Commitment publication for stream {} is still pending: {}",
                    stream_id,
                    error
                );
            }
        }
    }

    async fn commit_pending_segments(
        &self,
        stream_id: &str,
    ) -> Result<Option<StreamSegmentCommitment>, StreamTransportError> {
        let _gate = self.commitment_gate.lock().await;
        let mut last_committed = None;

        loop {
            let (owner, descriptor, pending, previous_hash, children) = {
                let state = self.state.lock().await;
                let stream = state
                    .outgoing
                    .get(stream_id)
                    .ok_or(StreamTransportError::StreamNotFound)?;
                let Some(pending) = stream.pending_segments.front().cloned() else {
                    break;
                };
                (
                    stream.owner.clone(),
                    stream.descriptor.clone(),
                    pending,
                    stream.previous_commitment_hash,
                    stream.direct_children.iter().cloned().collect::<Vec<_>>(),
                )
            };

            let commitment = StreamSegmentCommitment {
                segment_number: pending.segment_number,
                first_sequence: pending.first_sequence,
                packet_count: pending.packet_count,
                payload_bytes: pending.payload_bytes,
                sha256: pending.sha256,
                previous_commitment_hash: previous_hash,
                published_at: current_timestamp(),
            };
            let commitment_hash = hash_serialized(&commitment)?;
            let (hint, event_app_id) = self
                .append_commitment_page(&owner, &descriptor, commitment.clone())
                .await?;

            {
                let mut state = self.state.lock().await;
                let stream = state
                    .outgoing
                    .get_mut(stream_id)
                    .ok_or(StreamTransportError::StreamNotFound)?;
                let still_front = stream
                    .pending_segments
                    .front()
                    .is_some_and(|queued| queued.segment_number == pending.segment_number);
                if !still_front {
                    return Err(StreamTransportError::Integrity(
                        "stream commitment queue changed while publishing".into(),
                    ));
                }
                stream.pending_segments.pop_front();
                stream.previous_commitment_hash = commitment_hash;
            }

            self.send_wire_many(
                children,
                StreamWireMessage::CommitmentHint(hint.clone()),
            )
            .await;
            self.emit(StreamEvent::SegmentCommitted {
                application_id: event_app_id,
                stream_id: stream_id.to_string(),
                commitment: commitment.clone(),
                hint,
            });
            last_committed = Some(commitment);
        }

        Ok(last_committed)
    }

    async fn append_commitment_page(
        &self,
        app: &AuthenticatedAppSession,
        descriptor: &StreamDescriptor,
        commitment: StreamSegmentCommitment,
    ) -> Result<(StreamCommitmentHint, String), StreamTransportError> {
        let need_new_record = {
            let state = self.state.lock().await;
            let stream = state
                .outgoing
                .get(&descriptor.stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            let record = stream
                .commitment_records
                .last()
                .ok_or(StreamTransportError::StreamNotFound)?;
            record.page_index >= STREAM_COMMITMENT_PAGES_PER_RECORD
                && record.page_commitments.is_empty()
        };
        if need_new_record {
            self.create_next_commitment_record(
                app,
                descriptor,
                commitment.segment_number,
            )
            .await?;
        }

        // Build the next page value without mutating local page state. If the
        // DHT write fails, the queued commitment can be retried without being
        // duplicated in the page.
        let (record_key, store_id, record_index, page_index, page_commitments) = {
            let state = self.state.lock().await;
            let stream = state
                .outgoing
                .get(&descriptor.stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            let record = stream
                .commitment_records
                .last()
                .ok_or(StreamTransportError::StreamNotFound)?;
            let mut page_commitments = record.page_commitments.clone();
            page_commitments.push(commitment.clone());
            (
                record.record_key.clone(),
                record.store_id.clone(),
                record.record_index,
                record.page_index,
                page_commitments,
            )
        };

        let unsigned = CommitmentPageUnsigned {
            version: STREAM_PROTOCOL_VERSION,
            stream_id: descriptor.stream_id.clone(),
            generation: descriptor.generation,
            record_index,
            page_index,
            commitments: page_commitments.clone(),
        };
        let signed = self
            .signing
            .sign(
                app,
                STREAM_COMMITMENT_PAGE_DOMAIN.to_string(),
                &serialize(&unsigned)?,
            )
            .await?;
        let page = SignedCommitmentPage {
            unsigned,
            signature_hex: signed.signature_hex,
        };
        let location = page_index.saturating_add(1);
        self.write_store_value(app, &store_id, location, &page)
            .await?;

        {
            let mut state = self.state.lock().await;
            let stream = state
                .outgoing
                .get_mut(&descriptor.stream_id)
                .ok_or(StreamTransportError::StreamNotFound)?;
            let record = stream
                .commitment_records
                .last_mut()
                .ok_or(StreamTransportError::StreamNotFound)?;
            if record.store_id != store_id || record.page_index != page_index {
                return Err(StreamTransportError::Integrity(
                    "commitment page moved while its DHT write was active".into(),
                ));
            }
            if page_commitments.len() >= STREAM_COMMITMENTS_PER_PAGE {
                record.page_commitments.clear();
                record.page_index = record.page_index.saturating_add(1);
            } else {
                record.page_commitments = page_commitments;
            }
        }

        Ok((
            StreamCommitmentHint {
                stream_id: descriptor.stream_id.clone(),
                generation: descriptor.generation,
                segment_number: commitment.segment_number,
                record_key,
                page_location: location,
            },
            descriptor.application_id.clone(),
        ))
    }

    async fn create_next_commitment_record(
        &self,
        app: &AuthenticatedAppSession,
        descriptor: &StreamDescriptor,
        first_segment: u64,
    ) -> Result<(), StreamTransportError> {
        let (previous_store_id, previous_header_unsigned, next_index) = {
            let state = self.state.lock().await;
            let stream = state.outgoing.get(&descriptor.stream_id).ok_or(StreamTransportError::StreamNotFound)?;
            let previous = stream.commitment_records.last().ok_or(StreamTransportError::StreamNotFound)?;
            (
                previous.store_id.clone(),
                CommitmentRecordHeaderUnsigned {
                    magic: STREAM_RECORD_MAGIC,
                    version: STREAM_PROTOCOL_VERSION,
                    stream_id: descriptor.stream_id.clone(),
                    generation: descriptor.generation,
                    record_index: previous.record_index,
                    root_record_key: descriptor.commitment_root_record_key.clone(),
                    first_segment: previous.first_segment,
                    next_record_key: None,
                    descriptor: (previous.record_index == 0).then(|| descriptor.clone()),
                },
                previous.record_index.saturating_add(1),
            )
        };
        let store = self.storage.create_internal_store(
            app,
            format!("stream:{}:commitments:{next_index}", descriptor.stream_id),
            STREAM_COMMITMENT_SUBKEYS,
        ).await?;
        let next_header = self.signed_record_header(
            app,
            CommitmentRecordHeaderUnsigned {
                magic: STREAM_RECORD_MAGIC,
                version: STREAM_PROTOCOL_VERSION,
                stream_id: descriptor.stream_id.clone(),
                generation: descriptor.generation,
                record_index: next_index,
                root_record_key: descriptor.commitment_root_record_key.clone(),
                first_segment,
                next_record_key: None,
                descriptor: None,
            },
        ).await?;
        self.write_store_value(app, &store.store_id, 0, &next_header).await?;

        let mut linked_previous = previous_header_unsigned;
        linked_previous.next_record_key = Some(store.record_key.clone());
        let linked_header = self.signed_record_header(app, linked_previous).await?;
        self.write_store_value(app, &previous_store_id, 0, &linked_header).await?;
        self.state
            .lock()
            .await
            .outgoing
            .get_mut(&descriptor.stream_id)
            .ok_or(StreamTransportError::StreamNotFound)?
            .commitment_records
            .push(CommitmentRecordState {
                store_id: store.store_id,
                record_key: store.record_key,
                record_index: next_index,
                page_index: 0,
                first_segment,
                page_commitments: Vec::new(),
            });
        Ok(())
    }

    async fn read_and_verify_commitment_page(
        &self,
        descriptor: &StreamDescriptor,
        hint: &StreamCommitmentHint,
    ) -> Result<StreamSegmentCommitment, StreamTransportError> {
        if hint.stream_id != descriptor.stream_id || hint.generation != descriptor.generation {
            return Err(StreamTransportError::Integrity("commitment hint identifies another stream".into()));
        }
        if !(1..=STREAM_COMMITMENT_PAGES_PER_RECORD).contains(&hint.page_location) {
            return Err(StreamTransportError::Integrity(
                "commitment hint subkey is outside the record schema".into(),
            ));
        }
        let record_key: RecordKey = hint
            .record_key
            .parse()
            .map_err(|error| StreamTransportError::Integrity(format!("invalid commitment record key: {error:?}")))?;
        let mut values = self.storage.read_public(record_key, vec![hint.page_location], true).await?;
        let value = values.pop().ok_or_else(|| StreamTransportError::Integrity("commitment page is missing".into()))?;
        let page: SignedCommitmentPage = deserialize(&decode_store_value(value)?)?;
        if page.unsigned.stream_id != descriptor.stream_id || page.unsigned.generation != descriptor.generation {
            return Err(StreamTransportError::Integrity("commitment page stream identity mismatch".into()));
        }
        if page.unsigned.page_index.saturating_add(1) != hint.page_location
            || page.unsigned.commitments.is_empty()
            || page.unsigned.commitments.len() > STREAM_COMMITMENTS_PER_PAGE
        {
            return Err(StreamTransportError::Integrity(
                "commitment page shape is invalid".into(),
            ));
        }
        verify_signed_bytes(
            &descriptor.signing_public_key_hex,
            STREAM_COMMITMENT_PAGE_DOMAIN,
            &serialize(&page.unsigned)?,
            &page.signature_hex,
        )?;
        let commitment = page
            .unsigned
            .commitments
            .into_iter()
            .find(|commitment| commitment.segment_number == hint.segment_number)
            .ok_or_else(|| {
                StreamTransportError::Integrity(
                    "commitment page does not contain the announced segment".into(),
                )
            })?;
        if commitment.packet_count == 0
            || commitment.packet_count > STREAM_PACKETS_PER_SEGMENT
            || commitment.payload_bytes
                > u64::from(commitment.packet_count)
                    .saturating_mul(STREAM_PACKET_BYTES as u64)
        {
            return Err(StreamTransportError::Integrity(
                "commitment packet sizing is invalid".into(),
            ));
        }
        Ok(commitment)
    }

    async fn signed_record_header(
        &self,
        app: &AuthenticatedAppSession,
        unsigned: CommitmentRecordHeaderUnsigned,
    ) -> Result<SignedCommitmentRecordHeader, StreamTransportError> {
        let signed = self.signing.sign(
            app,
            STREAM_RECORD_HEADER_DOMAIN.to_string(),
            &serialize(&unsigned)?,
        ).await?;
        Ok(SignedCommitmentRecordHeader {
            unsigned,
            signature_hex: signed.signature_hex,
        })
    }

    async fn write_store_value<T: Serialize>(
        &self,
        app: &AuthenticatedAppSession,
        store_id: &str,
        location: u32,
        value: &T,
    ) -> Result<(), StreamTransportError> {
        let bytes = serialize(value)?;
        self.storage.write_own(app, store_id, None, vec![(location, bytes)]).await?;
        Ok(())
    }

    fn verify_descriptor(&self, descriptor: &StreamDescriptor) -> Result<(), StreamTransportError> {
        validate_stream_id(&descriptor.stream_id)?;
        if descriptor.version != STREAM_PROTOCOL_VERSION {
            return Err(StreamTransportError::InvalidDescriptor(format!(
                "unsupported stream protocol {}",
                descriptor.version
            )));
        }
        descriptor
            .streamer_main_dht
            .parse::<RecordKey>()
            .map_err(|error| StreamTransportError::InvalidDescriptor(format!("invalid streamer key: {error:?}")))?;
        descriptor
            .commitment_root_record_key
            .parse::<RecordKey>()
            .map_err(|error| StreamTransportError::InvalidDescriptor(format!("invalid commitment root: {error:?}")))?;
        let metadata = BASE64
            .decode(&descriptor.opaque_metadata_base64)
            .map_err(|error| StreamTransportError::InvalidDescriptor(format!("invalid metadata encoding: {error}")))?;
        if metadata.len() > STREAM_MAX_METADATA_BYTES {
            return Err(StreamTransportError::InvalidMetadata);
        }
        if descriptor.packet_bytes != STREAM_PACKET_BYTES as u32
            || descriptor.packets_per_segment != STREAM_PACKETS_PER_SEGMENT
        {
            return Err(StreamTransportError::InvalidDescriptor(
                "unsupported packet or segment sizing".into(),
            ));
        }
        verify_signed_bytes(
            &descriptor.signing_public_key_hex,
            STREAM_DESCRIPTOR_DOMAIN,
            &serialize(&descriptor.unsigned())?,
            &descriptor.signature_hex,
        )
    }

    async fn send_wire(
        &self,
        peer: &str,
        message: StreamWireMessage,
    ) -> Result<(), StreamTransportError> {
        let data_plane = message.is_data_plane();
        let bytes = serialize(&message)?;
        if bytes.len() > STREAM_MAX_WIRE_BYTES {
            return Err(StreamTransportError::Serialization(format!(
                "encoded stream message is {} bytes; route limit is {}",
                bytes.len(),
                STREAM_MAX_WIRE_BYTES
            )));
        }
        if !data_plane {
            ensure_session(self.handshake.clone(), peer).await?;
        }
        self.handshake
            .lock()
            .await
            .send_application_message(peer, STREAM_INTERNAL_APPLICATION_ID, bytes)
            .await
            .map(|_| ())
            .map_err(|error| StreamTransportError::Transport(error.to_string()))
    }

    async fn send_wire_many(&self, peers: Vec<String>, message: StreamWireMessage) {
        let manager = self.clone();
        stream::iter(peers)
            .map(move |peer| {
                let manager = manager.clone();
                let message = message.clone();
                async move {
                    if let Err(error) = manager.send_wire(&peer, message).await {
                        manager.log_send_failure(&peer, &error).await;
                    }
                }
            })
            .buffer_unordered(STREAM_SEND_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
    }

    async fn log_send_failure(
        &self,
        peer: &str,
        error: &StreamTransportError,
    ) {
        let now = current_timestamp();
        let should_log = {
            let mut logged = self.send_error_last_logged.lock().await;
            let last = logged.get(peer).copied().unwrap_or(0);
            if now.saturating_sub(last) >= 30 {
                logged.insert(peer.to_string(), now);
                true
            } else {
                false
            }
        };
        if should_log {
            crate::teprintln!(
                "[stream] Could not send stream traffic to {}: {}",
                peer,
                error
            );
        }
    }

    fn emit(&self, event: StreamEvent) {
        let _ = self.events.send(event);
    }

    async fn expire_pending_joins(&self) {
        let now = current_timestamp();
        let expired = {
            let mut state = self.state.lock().await;
            let expired_ids = state
                .incoming
                .iter()
                .filter(|(_, stream)| {
                    stream.parent_main_dht.is_none()
                        && stream.join_requested_at.saturating_add(STREAM_JOIN_TIMEOUT_SECS) < now
                })
                .map(|(stream_id, _)| stream_id.clone())
                .collect::<Vec<_>>();
            expired_ids
                .into_iter()
                .filter_map(|stream_id| state.incoming.remove(&stream_id).map(|stream| (stream_id, stream)))
                .collect::<Vec<_>>()
        };
        for (stream_id, stream) in expired {
            self.emit(StreamEvent::Ended {
                application_id: stream.application_id,
                stream_id,
                reason: "stream join timed out".into(),
            });
        }
    }

    async fn expire_closed_streams(&self) {
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        for stream in state.outgoing.values_mut() {
            if stream
                .closed_at
                .is_some_and(|closed_at| {
                    now.saturating_sub(closed_at) >= STREAM_CLOSED_RETENTION_SECS
                })
            {
                stream.packet_cache.clear();
                stream.current_packets.clear();
                if stream.pending_segments.is_empty() {
                    stream.participants.clear();
                    stream.direct_children.clear();
                }
            }
        }
        state.outgoing.retain(|_, stream| {
            stream.running
                || !stream.pending_segments.is_empty()
                || stream
                    .closed_at
                    .is_none_or(|closed_at| {
                        now.saturating_sub(closed_at) < STREAM_CLOSED_RETENTION_SECS
                    })
        });
        state.incoming.retain(|_, stream| {
            stream.running
                || stream
                    .closed_at
                    .is_none_or(|closed_at| {
                        now.saturating_sub(closed_at) < STREAM_CLOSED_RETENTION_SECS
                    })
        });
    }
}

fn seal_current_segment(stream: &mut OutgoingStreamState) -> bool {
    if stream.current_packets.is_empty() {
        return false;
    }
    let segment_number = stream.current_segment;
    let packets = std::mem::take(&mut stream.current_packets);
    let first_sequence = packets.first().map_or(0, |packet| packet.sequence);
    let packet_count = packets.len() as u32;
    let payload_bytes = packets
        .iter()
        .map(|packet| packet.payload.len() as u64)
        .sum();
    let sha256 = hash_packet_sequence(&packets);
    stream.pending_segments.push_back(PendingSegmentState {
        segment_number,
        first_sequence,
        packet_count,
        payload_bytes,
        sha256,
    });
    stream.current_segment = stream.current_segment.saturating_add(1);
    true
}

struct ReassignmentResult {
    application_id: String,
    viewer_count: usize,
    assignments: Vec<(String, String, Option<String>)>,
}

fn remove_participant_and_reassign(
    stream: &mut OutgoingStreamState,
    source_main_dht: &str,
    viewer_main_dht: &str,
) -> ReassignmentResult {
    let removed = stream.participants.remove(viewer_main_dht);
    stream.direct_children.remove(viewer_main_dht);
    for participant in stream.participants.values_mut() {
        participant.children.remove(viewer_main_dht);
    }
    let orphaned = removed
        .map(|participant| participant.children.into_iter().collect::<Vec<_>>())
        .unwrap_or_default();
    let mut assignments = Vec::new();
    for child in orphaned {
        if !stream.participants.contains_key(&child) {
            continue;
        }

        // Reattach an orphan directly to the source first. Choosing another
        // orphan as its new parent can create a relay cycle when several
        // siblings lose the same parent simultaneously. A later topology
        // rebalance may move it outward again once the tree is stable.
        let parent = source_main_dht.to_string();
        let standby = choose_standby(stream, &parent, &child);
        stream.direct_children.insert(child.clone());
        if let Some(child_state) = stream.participants.get_mut(&child) {
            child_state.parent_main_dht = parent.clone();
            child_state.depth = 1;
        }
        assignments.push((child, parent, standby));
    }
    ReassignmentResult {
        application_id: stream.descriptor.application_id.clone(),
        viewer_count: stream.participants.len(),
        assignments,
    }
}

fn choose_parent(stream: &OutgoingStreamState, source_main_dht: &str) -> (String, u16) {
    choose_parent_excluding(stream, source_main_dht, "")
}

fn choose_parent_excluding(
    stream: &OutgoingStreamState,
    source_main_dht: &str,
    excluded: &str,
) -> (String, u16) {
    let mut candidates = stream
        .participants
        .iter()
        .filter(|(peer, participant)| {
            peer.as_str() != excluded
                && participant.relay_capacity > participant.children.len() as u16
        })
        .map(|(peer, participant)| {
            (
                participant.depth,
                participant.children.len(),
                participant.joined_at,
                peer.clone(),
            )
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.cmp(right));
    if let Some((depth, _, _, peer)) = candidates.into_iter().next() {
        return (peer, depth.saturating_add(1));
    }
    if stream.direct_children.len() < STREAM_SOURCE_DIRECT_CHILDREN {
        return (source_main_dht.to_string(), 1);
    }
    // A source remains the fallback when viewers decline relay duty. This is
    // less scalable, but refusing a second viewer would be worse behavior.
    (source_main_dht.to_string(), 1)
}

fn choose_standby(
    stream: &OutgoingStreamState,
    parent: &str,
    _viewer: &str,
) -> Option<String> {
    // Every viewer authenticates with the original source during admission.
    // Keeping that source as the standby makes retransmission authorization
    // unambiguous without teaching unrelated relays about viewers they do not
    // currently serve.
    (parent != stream.descriptor.streamer_main_dht)
        .then(|| stream.descriptor.streamer_main_dht.clone())
}

/// Diagnostic clients can operate several cryptographic profiles while still
/// participating in one application protocol. The `::profile::` suffix is a
/// local credential/profile discriminator and is not a separate wire protocol.
pub(crate) fn same_stream_application_family(left: &str, right: &str) -> bool {
    fn family(value: &str) -> &str {
        value.split_once("::profile::").map(|(base, _)| base).unwrap_or(value)
    }
    family(left) == family(right)
}

fn ensure_stream_owner(
    app: &AuthenticatedAppSession,
    stream: &OutgoingStreamState,
) -> Result<(), StreamTransportError> {
    if stream.descriptor.application_id == app.app_id().to_string() {
        Ok(())
    } else {
        Err(StreamTransportError::NotStreamOwner)
    }
}

fn validate_stream_id(stream_id: &str) -> Result<(), StreamTransportError> {
    Uuid::parse_str(stream_id)
        .map(|_| ())
        .map_err(|_| StreamTransportError::InvalidStreamId)
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, StreamTransportError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(STREAM_MAX_SERIALIZED_BYTES)
        .serialize(value)
        .map_err(|error| StreamTransportError::Serialization(error.to_string()))
}

fn deserialize<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, StreamTransportError> {
    if bytes.len() as u64 > STREAM_MAX_SERIALIZED_BYTES {
        return Err(StreamTransportError::Serialization(
            "encoded stream value exceeds the decoder limit".into(),
        ));
    }
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(STREAM_MAX_SERIALIZED_BYTES)
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|error| StreamTransportError::Serialization(error.to_string()))
}

fn verify_signed_bytes(
    public_key_hex: &str,
    domain: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), StreamTransportError> {
    let public_key = decode_fixed::<32>(public_key_hex, "public key")?;
    let signature = decode_fixed::<64>(signature_hex, "signature")?;
    let valid = AppSigningManager::verify(&public_key, domain, payload, &signature)?;
    if valid {
        Ok(())
    } else {
        Err(StreamTransportError::Integrity("signature verification failed".into()))
    }
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], StreamTransportError> {
    let bytes = hex::decode(value)
        .map_err(|error| StreamTransportError::Integrity(format!("invalid {label}: {error}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        StreamTransportError::Integrity(format!(
            "{label} must contain {N} bytes, found {}",
            bytes.len()
        ))
    })
}

fn hash_packet_sequence(packets: &[StreamPacketWire]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STREAM_SEGMENT_HASH_DOMAIN);
    if let Some(first) = packets.first() {
        hasher.update((first.stream_id.len() as u32).to_le_bytes());
        hasher.update(first.stream_id.as_bytes());
        hasher.update(first.generation.to_le_bytes());
        hasher.update(first.segment_number.to_le_bytes());
    }
    for packet in packets {
        hasher.update(packet.sequence.to_le_bytes());
        hasher.update(packet.packet_index.to_le_bytes());
        hasher.update((packet.payload.len() as u32).to_le_bytes());
        hasher.update(&packet.payload);
    }
    hasher.finalize().into()
}

fn hash_received_packets(
    packets: &BTreeMap<u32, StreamPacketWire>,
    expected_count: u32,
) -> Result<[u8; 32], StreamTransportError> {
    if packets.len() != expected_count as usize {
        return Err(StreamTransportError::Integrity("segment packet count is incomplete".into()));
    }
    let ordered = (0..expected_count)
        .map(|index| packets.get(&index).cloned().ok_or_else(|| {
            StreamTransportError::Integrity(format!("segment packet {index} is missing"))
        }))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(hash_packet_sequence(&ordered))
}

fn hash_serialized<T: Serialize>(value: &T) -> Result<[u8; 32], StreamTransportError> {
    let bytes = serialize(value)?;
    Ok(Sha256::digest(bytes).into())
}

fn missing_packet_indices(
    packets: &BTreeMap<u32, StreamPacketWire>,
    expected_count: u32,
) -> Vec<u32> {
    (0..expected_count)
        .filter(|index| !packets.contains_key(index))
        .collect()
}

fn cache_packet(
    cache: &mut VecDeque<StreamPacketWire>,
    packet: StreamPacketWire,
    current_segment: u64,
) {
    cache.push_back(packet);
    let oldest_segment = current_segment.saturating_sub(STREAM_RETRANSMIT_SEGMENTS);
    while cache.front().is_some_and(|packet| packet.segment_number < oldest_segment) {
        cache.pop_front();
    }
}

fn find_cached_packets(
    cache: &VecDeque<StreamPacketWire>,
    segment_number: u64,
    packet_indices: &[u32],
) -> Vec<StreamPacketWire> {
    let wanted = packet_indices.iter().copied().collect::<HashSet<_>>();
    cache
        .iter()
        .filter(|packet| {
            packet.segment_number == segment_number && wanted.contains(&packet.packet_index)
        })
        .cloned()
        .collect()
}

fn decode_store_value(value: AppStoreReadValue) -> Result<Vec<u8>, StreamTransportError> {
    if let Some(error) = value.error {
        return Err(StreamTransportError::Integrity(error));
    }
    if value.is_null {
        return Err(StreamTransportError::Integrity(format!(
            "commitment subkey {} is null",
            value.location
        )));
    }
    let encoded = value.value_base64.ok_or_else(|| {
        StreamTransportError::Integrity(format!(
            "commitment subkey {} has no value",
            value.location
        ))
    })?;
    BASE64
        .decode(encoded)
        .map_err(|error| StreamTransportError::Integrity(error.to_string()))
}

fn spawn_session_ensure(
    handshake: Arc<Mutex<HandshakeManager>>,
    peer: String,
) {
    tokio::spawn(async move {
        if let Err(error) = ensure_session(handshake, &peer).await {
            crate::teprintln!(
                "[stream] Could not prepare relay session with {}: {}",
                peer,
                error
            );
        }
    });
}

async fn ensure_session(
    handshake: Arc<Mutex<HandshakeManager>>,
    peer: &str,
) -> Result<(), StreamTransportError> {
    if handshake.lock().await.is_persistent_established(peer) {
        return Ok(());
    }
    {
        let mut manager = handshake.lock().await;
        manager
            .initiate_persistent_handshake(peer.to_string())
            .await
            .map_err(|error| StreamTransportError::Transport(error.to_string()))?;
    }
    for _ in 0..150 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        if handshake.lock().await.is_established(peer) {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            return Ok(());
        }
    }
    Err(StreamTransportError::Transport(format!(
        "handshake with {peer} did not become established"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_profiles_share_stream_family_but_not_other_apps() {
        assert!(same_stream_application_family(
            "veilknit.veilyshort",
            "veilknit.veilyshort::profile::second",
        ));
        assert!(same_stream_application_family(
            "veilknit.veilyshort::profile::first",
            "veilknit.veilyshort::profile::second",
        ));
        assert!(!same_stream_application_family(
            "veilknit.veilyshort",
            "another.application::profile::second",
        ));
    }

    #[test]
    fn configured_packet_sizes_fit_direct_transport() {
        assert!(STREAM_PACKET_BYTES < 32 * 1024);
        assert_eq!(STREAM_COMMITMENT_SUBKEYS, 64);
        assert_eq!(STREAM_COMMITMENT_PAGES_PER_RECORD, 63);
    }

    #[test]
    fn packet_hash_is_stable_and_order_sensitive() {
        let packet_a = StreamPacketWire {
            stream_id: "a".into(),
            generation: 1,
            sequence: 1,
            segment_number: 0,
            packet_index: 0,
            retransmission: false,
            payload: b"hello".to_vec(),
        };
        let mut packet_b = packet_a.clone();
        packet_b.sequence = 2;
        packet_b.packet_index = 1;
        packet_b.payload = b"world".to_vec();
        assert_ne!(
            hash_packet_sequence(&[packet_a.clone(), packet_b.clone()]),
            hash_packet_sequence(&[packet_b, packet_a])
        );
    }

    #[test]
    fn missing_packet_detection_is_exact() {
        let mut packets = BTreeMap::new();
        packets.insert(0, StreamPacketWire {
            stream_id: "a".into(), generation: 1, sequence: 1,
            segment_number: 0, packet_index: 0, retransmission: false,
            payload: vec![1],
        });
        packets.insert(2, StreamPacketWire {
            stream_id: "a".into(), generation: 1, sequence: 3,
            segment_number: 0, packet_index: 2, retransmission: false,
            payload: vec![3],
        });
        assert_eq!(missing_packet_indices(&packets, 3), vec![1]);
    }

    #[test]
    fn maximum_packet_fits_the_route_payload_budget() {
        let message = StreamWireMessage::Packet(StreamPacketWire {
            stream_id: Uuid::nil().simple().to_string(),
            generation: 1,
            sequence: 0,
            segment_number: 0,
            packet_index: 0,
            retransmission: false,
            payload: vec![0x5a; STREAM_PACKET_BYTES],
        });
        let encoded = serialize(&message).expect("packet should serialize");
        assert!(encoded.len() <= STREAM_MAX_WIRE_BYTES);
    }

    #[test]
    fn full_commitment_page_is_well_below_a_size_safe_subkey() {
        let commitments = (0..STREAM_COMMITMENTS_PER_PAGE)
            .map(|segment_number| StreamSegmentCommitment {
                segment_number: segment_number as u64,
                first_sequence: segment_number as u64
                    * u64::from(STREAM_PACKETS_PER_SEGMENT),
                packet_count: STREAM_PACKETS_PER_SEGMENT,
                payload_bytes: STREAM_PACKET_BYTES as u64
                    * u64::from(STREAM_PACKETS_PER_SEGMENT),
                sha256: [segment_number as u8; 32],
                previous_commitment_hash: [0; 32],
                published_at: 1,
            })
            .collect();
        let page = SignedCommitmentPage {
            unsigned: CommitmentPageUnsigned {
                version: STREAM_PROTOCOL_VERSION,
                stream_id: Uuid::nil().simple().to_string(),
                generation: 1,
                record_index: 0,
                page_index: 0,
                commitments,
            },
            signature_hex: "00".repeat(64),
        };
        let encoded = serialize(&page).expect("page should serialize");
        assert!(encoded.len() < 12 * 1024);
    }

}

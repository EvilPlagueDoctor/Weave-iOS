//! Daemon-owned, application-scoped gossip discovery.
//!
//! Gossip is deliberately a fast *hint* plane, never an authoritative data
//! source. Applications publish compact records that point at durable DHT/blob
//! state. The daemon keeps one bounded in-memory cache per application,
//! deduplicates repeated claims, tracks claimed provenance, scores generic
//! fingerprints, and fans useful hints out to a few directly discovered peers.
//!
//! The network wire format is private to the daemon. Application-specific
//! custom data remains opaque bytes and is tightly bounded so gossip cannot
//! quietly turn into a second bulk-transfer mechanism.

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use rand::{seq::SliceRandom, thread_rng};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch, Mutex};
use veilid_core::RecordKey;

use crate::{
    handshake::{GossipApplicationMessage, HandshakeManager},
    types::current_timestamp,
    walk_task::WalkTask,
};

pub const GOSSIP_ENGINE_VERSION: u16 = 2;
pub const GOSSIP_ENGINE_NAMESPACE_STREAMS: &str = "_veilknit.stream";

pub const GOSSIP_DEFAULT_TTL_SECS: u64 = 30 * 60;
pub const GOSSIP_MAX_TTL_SECS: u64 = 24 * 60 * 60;
pub const GOSSIP_MAX_NAMESPACE_BYTES: usize = 64;
pub const GOSSIP_MAX_OBJECT_ID_BYTES: usize = 256;
pub const GOSSIP_MAX_POINTER_BYTES: usize = 512;
pub const GOSSIP_MAX_CUSTOM_PAYLOAD_BYTES: usize = 1024;
pub const GOSSIP_MAX_FINGERPRINTS: usize = 8;
pub const GOSSIP_MAX_FINGERPRINT_CHANNEL_BYTES: usize = 48;
pub const GOSSIP_MAX_FINGERPRINT_ALGORITHM_BYTES: usize = 48;
pub const GOSSIP_MAX_FINGERPRINT_BYTES: usize = 256;
pub const GOSSIP_MAX_QUERY_PROBES: usize = 8;
pub const GOSSIP_MAX_INDEX_TOKENS: usize = 32;
pub const GOSSIP_MAX_INDEX_PROBES: usize = 8;
pub const GOSSIP_MAX_INDEX_TOKENS_PER_PROBE: usize = 16;
pub const GOSSIP_MAX_INDEX_NAME_BYTES: usize = 48;
pub const GOSSIP_MAX_INDEX_TERM_BYTES: usize = 128;
pub const GOSSIP_INDEX_TOKEN_BYTES: usize = 16;
/// Reserved application used only by the daemon's manual two-node diagnostic.
pub const GOSSIP_TEST_APPLICATION_ID: &str = "veilknit.daemon.gossip-index-test.v1";
pub const GOSSIP_TEST_NAMESPACE: &str = "gossip-index-test";
pub const GOSSIP_TEST_INDEX_NAME: &str = "words";
pub const GOSSIP_MAX_QUERY_RESULTS: usize = 32;
pub const GOSSIP_MAX_ENTRIES_PER_APP: usize = 2048;
pub const GOSSIP_MAX_ENTRIES_GLOBAL: usize = 8192;
pub const GOSSIP_MAX_CLAIMED_SOURCES: usize = 32;
pub const GOSSIP_PUBLISH_FANOUT: usize = 6;
pub const GOSSIP_RELAY_FANOUT: usize = 3;
pub const GOSSIP_QUERY_FANOUT: usize = 6;
pub const GOSSIP_DEFAULT_NETWORK_WAIT_MS: u64 = 250;
pub const GOSSIP_MAX_NETWORK_WAIT_MS: u64 = 1500;
const GOSSIP_MAX_QUERY_RESPONSE_RECORDS: usize = 3;
const GOSSIP_MAX_RELAY_HOPS: u8 = 3;
const GOSSIP_MAINTENANCE_SECS: u64 = 30;
const GOSSIP_QUERY_RESPONSE_COOLDOWN_SECS: u64 = 10;
const GOSSIP_MAX_FUTURE_SKEW_SECS: u64 = 10 * 60;
const GOSSIP_WIRE_PREFIX: &[u8] = b"\0veilknit-gossip-engine-v1\0";
const GOSSIP_WIRE_MAX_BYTES: usize = 12 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipVerificationState {
    /// One or more unverified gossip claims only.
    Unverified,
    /// Multiple *claimed* sources repeated the same hint. The source identity
    /// is not cryptographically authenticated by the gossip transport.
    MultiSourceHint,
    /// The local application confirmed that the authoritative pointer exists.
    PointerConfirmed,
    /// The local application read the authoritative object and confirmed this
    /// generation/claim.
    AuthoritativeVerified,
    /// This local application published the record itself.
    LocalPublished,
    /// Same object/generation arrived with incompatible claims, or an app
    /// explicitly rejected the current gossip claim after an authoritative read.
    Conflicting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipConfirmationLevel {
    PointerConfirmed,
    AuthoritativeVerified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipFingerprint {
    /// Semantic dimension chosen by the application, for example `content`,
    /// `layout`, `activity`, or `interaction`.
    pub channel: String,
    /// Comparison algorithm. The daemon recognizes `minhash16`, `hamming`, and
    /// `exact`. Unknown names remain usable as opaque equality fingerprints.
    pub algorithm: String,
    pub version: u16,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GossipIndexToken {
    /// 128-bit BLAKE3-derived token. The clear-text term is never placed on the
    /// daemon-managed gossip wire. The digest is scoped by application id,
    /// object namespace, and application-chosen index name.
    pub digest: [u8; GOSSIP_INDEX_TOKEN_BYTES],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GossipTokenPolarity {
    Required,
    Preferred,
    Exclude,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GossipTokenMatchMode {
    All,
    Any,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipTokenProbe {
    pub tokens: Vec<GossipIndexToken>,
    pub polarity: GossipTokenPolarity,
    pub match_mode: GossipTokenMatchMode,
    /// Used only for preferred-token ranking. Required/excluded groups are hard
    /// filters, but keeping one bounded field makes the wire format uniform.
    pub weight: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipRecord {
    pub namespace: String,
    pub object_id: String,
    pub generation: u64,
    /// Claimed origin identity. This is useful routing metadata, not proof.
    pub origin_main_dht: String,
    pub published_at: u64,
    pub expires_at: u64,
    /// Usually a DHT/blob root that can be checked independently.
    pub authoritative_pointer: Option<String>,
    pub fingerprints: Vec<GossipFingerprint>,
    /// Opaque exact-search tokens. Clear-text words never leave the local API.
    #[serde(default)]
    pub index_tokens: Vec<GossipIndexToken>,
    /// App-defined fast-preview data. The daemon does not interpret it.
    pub custom_payload: Vec<u8>,
    pub flags: u32,
    /// Tombstones propagate removal/update invalidation without carrying the
    /// old preview/fingerprint payload forever.
    pub withdrawn: bool,
}

#[derive(Debug, Clone)]
pub struct GossipPublishRequest {
    pub namespace: String,
    pub object_id: String,
    pub generation: u64,
    pub authoritative_pointer: Option<String>,
    pub fingerprints: Vec<GossipFingerprint>,
    pub index_tokens: Vec<GossipIndexToken>,
    pub custom_payload: Vec<u8>,
    pub flags: u32,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipProbePolarity {
    Similar,
    Avoid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipFingerprintProbe {
    pub channel: String,
    pub algorithm: String,
    pub version: u16,
    pub bytes: Vec<u8>,
    /// Integer weight avoids unstable wire-level floating-point policy. Zero is
    /// rejected; applications can use 1..=1000 for practical weighting.
    pub weight: u16,
    pub polarity: GossipProbePolarity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipSearchQuery {
    pub namespace: String,
    pub probes: Vec<GossipFingerprintProbe>,
    #[serde(default)]
    pub token_probes: Vec<GossipTokenProbe>,
    pub limit: usize,
    /// 0..=1000. When absent, all locally rankable records are eligible.
    pub min_score_milli: Option<u16>,
    #[serde(default)]
    pub include_withdrawn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipSearchHit {
    pub record: GossipRecord,
    pub score: f32,
    /// Number of distinct index tokens from this query that the object matched.
    pub matched_index_tokens: usize,
    pub verification: GossipVerificationState,
    pub claimed_source_count: usize,
    pub conflicting_claim_count: usize,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub last_verified_at: Option<u64>,
    pub last_verified_generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipAppStats {
    pub application_id: String,
    pub object_count: usize,
    pub locally_published_count: usize,
    pub conflicting_count: usize,
    pub total_custom_payload_bytes: usize,
    pub total_index_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GossipEvent {
    ObjectUpdated {
        application_id: String,
        namespace: String,
        object_id: String,
        generation: u64,
        verification: GossipVerificationState,
    },
    ObjectWithdrawn {
        application_id: String,
        namespace: String,
        object_id: String,
        generation: u64,
    },
    ConflictObserved {
        application_id: String,
        namespace: String,
        object_id: String,
        generation: u64,
    },
    QueryMerged {
        application_id: String,
        query_id_hex: String,
        accepted_records: usize,
    },
}

impl GossipEvent {
    pub fn application_id(&self) -> &str {
        match self {
            Self::ObjectUpdated { application_id, .. }
            | Self::ObjectWithdrawn { application_id, .. }
            | Self::ConflictObserved { application_id, .. }
            | Self::QueryMerged { application_id, .. } => application_id,
        }
    }
}

#[derive(Debug)]
pub enum GossipError {
    InvalidApplicationId,
    InvalidNamespace,
    ReservedNamespace,
    InvalidObjectId,
    InvalidPointer,
    TooManyFingerprints,
    InvalidFingerprint(String),
    TooManyIndexTokens,
    InvalidIndex(String),
    CustomPayloadTooLarge,
    InvalidTtl,
    InvalidQuery(String),
    ObjectNotFound,
    GenerationMismatch,
    NotLocallyPublished,
    Wire(String),
    Transport(String),
}

impl fmt::Display for GossipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidApplicationId => write!(formatter, "application id is invalid"),
            Self::InvalidNamespace => write!(formatter, "gossip namespace is invalid"),
            Self::ReservedNamespace => write!(formatter, "gossip namespace is daemon-reserved"),
            Self::InvalidObjectId => write!(formatter, "gossip object id is invalid"),
            Self::InvalidPointer => write!(formatter, "authoritative pointer is invalid"),
            Self::TooManyFingerprints => write!(formatter, "too many gossip fingerprints"),
            Self::InvalidFingerprint(reason) => write!(formatter, "invalid gossip fingerprint: {reason}"),
            Self::TooManyIndexTokens => write!(formatter, "too many gossip index tokens"),
            Self::InvalidIndex(reason) => write!(formatter, "invalid gossip index: {reason}"),
            Self::CustomPayloadTooLarge => write!(formatter, "gossip custom payload is too large"),
            Self::InvalidTtl => write!(formatter, "gossip TTL is invalid"),
            Self::InvalidQuery(reason) => write!(formatter, "invalid gossip query: {reason}"),
            Self::ObjectNotFound => write!(formatter, "gossip object was not found"),
            Self::GenerationMismatch => write!(formatter, "gossip generation does not match the cached claim"),
            Self::NotLocallyPublished => write!(formatter, "gossip object is not locally published"),
            Self::Wire(reason) => write!(formatter, "gossip wire error: {reason}"),
            Self::Transport(reason) => write!(formatter, "gossip transport error: {reason}"),
        }
    }
}

impl std::error::Error for GossipError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GossipWireEnvelope {
    version: u16,
    message: GossipWireMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum GossipWireMessage {
    Record {
        record: GossipRecord,
        hops_remaining: u8,
    },
    Query {
        query_id: [u8; 16],
        query: GossipSearchQuery,
    },
    QueryResponse {
        query_id: [u8; 16],
        records: Vec<GossipRecord>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct GossipObjectKey {
    namespace: String,
    object_id: String,
}

impl GossipObjectKey {
    fn new(namespace: &str, object_id: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
            object_id: object_id.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct GossipCacheEntry {
    record: GossipRecord,
    digest: [u8; 32],
    first_seen_at: u64,
    last_seen_at: u64,
    last_verified_at: Option<u64>,
    last_verified_generation: Option<u64>,
    verification: GossipVerificationState,
    supporting_claimed_sources: HashSet<String>,
    conflicting_digests: HashSet<[u8; 32]>,
    locally_published: bool,
}

#[derive(Default)]
struct AppGossipState {
    entries: HashMap<GossipObjectKey, GossipCacheEntry>,
    /// Local inverted index from an opaque exact-search token to cached object keys.
    /// This is rebuildable/disposable just like the gossip cache itself.
    token_index: HashMap<GossipIndexToken, HashSet<GossipObjectKey>>,
}

#[derive(Default)]
struct GossipState {
    apps: HashMap<String, AppGossipState>,
    // The raw gossip transport is intentionally unauthenticated. Even though
    // queries are only answered for directly discovered same-app peers, a
    // claimed identity could still be spoofed. A per-app/per-peer cooldown
    // therefore bounds reflection/amplification from daemon-managed queries.
    query_response_last: HashMap<(String, String), u64>,
}

#[derive(Clone)]
pub struct GossipManager {
    state: Arc<Mutex<GossipState>>,
    handshake: Arc<Mutex<HandshakeManager>>,
    walk_task: Option<WalkTask>,
    main_dht: String,
    events: broadcast::Sender<GossipEvent>,
}

impl GossipManager {
    pub fn new(
        handshake: Arc<Mutex<HandshakeManager>>,
        walk_task: Option<WalkTask>,
        main_dht: String,
    ) -> Self {
        let (events, _) = broadcast::channel(1024);
        Self {
            state: Arc::new(Mutex::new(GossipState::default())),
            handshake,
            walk_task,
            main_dht,
            events,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<GossipEvent> {
        self.events.subscribe()
    }

    /// Mark an authenticated local application's gossip partition as relevant.
    /// Incoming engine frames for never-activated apps are ignored so remote
    /// peers cannot manufacture arbitrary app ids and consume the global cache.
    pub async fn activate_application(&self, application_id: &str) -> Result<(), GossipError> {
        validate_application_id(application_id)?;
        self.state
            .lock()
            .await
            .apps
            .entry(application_id.to_string())
            .or_default();
        Ok(())
    }

    /// Start the daemon-owned inbound bridge plus cheap expiry maintenance.
    pub fn spawn_bridge(&self, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        let handshake = self.handshake.clone();
        tokio::spawn(async move {
            let mut messages = {
                let manager = handshake.lock().await;
                manager.subscribe_gossip_messages()
            };
            let mut maintenance = tokio::time::interval(std::time::Duration::from_secs(
                GOSSIP_MAINTENANCE_SECS,
            ));
            maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = maintenance.tick() => manager.prune_expired().await,
                    message = messages.recv() => match message {
                        Ok(message) if is_engine_frame(&message.payload) => {
                            if let Err(error) = manager.process_incoming(message).await {
                                crate::teprintln!("[gossip-engine] rejected frame: {error}");
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            crate::teprintln!("[gossip-engine] inbound bridge lagged by {skipped} frame(s)");
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
        })
    }

    pub async fn publish(
        &self,
        application_id: &str,
        request: GossipPublishRequest,
    ) -> Result<GossipSearchHit, GossipError> {
        validate_application_id(application_id)?;
        validate_namespace(&request.namespace, false)?;
        validate_publish_request(&request)?;
        let now = current_timestamp();
        let record = GossipRecord {
            namespace: request.namespace,
            object_id: request.object_id,
            generation: request.generation,
            origin_main_dht: self.main_dht.clone(),
            published_at: now,
            expires_at: now.saturating_add(request.ttl_seconds),
            authoritative_pointer: request.authoritative_pointer,
            fingerprints: request.fingerprints,
            index_tokens: request.index_tokens,
            custom_payload: request.custom_payload,
            flags: request.flags,
            withdrawn: false,
        };
        self.publish_record_internal(application_id, record, false).await
    }

    /// Daemon-only publication path used for generic system hints such as
    /// stream discovery. Reserved namespaces are accepted here.
    pub async fn publish_system_record(
        &self,
        application_id: &str,
        mut record: GossipRecord,
    ) -> Result<GossipSearchHit, GossipError> {
        validate_application_id(application_id)?;
        validate_record(&record, true)?;
        let now = current_timestamp();
        record.origin_main_dht = self.main_dht.clone();
        record.published_at = now;
        record.expires_at = record.expires_at.max(now.saturating_add(1));
        self.publish_record_internal(application_id, record, true).await
    }

    async fn publish_record_internal(
        &self,
        application_id: &str,
        record: GossipRecord,
        allow_reserved: bool,
    ) -> Result<GossipSearchHit, GossipError> {
        validate_record(&record, allow_reserved)?;
        let ingest = self
            .ingest_record(application_id, record.clone(), &self.main_dht, true)
            .await?;
        if ingest.forwardable {
            self.fanout_record(application_id, record, None, GOSSIP_MAX_RELAY_HOPS)
                .await;
        }
        Ok(ingest.hit)
    }

    pub async fn withdraw(
        &self,
        application_id: &str,
        namespace: &str,
        object_id: &str,
        requested_generation: Option<u64>,
    ) -> Result<GossipSearchHit, GossipError> {
        self.withdraw_internal(application_id, namespace, object_id, requested_generation, false).await
    }

    pub async fn withdraw_system(
        &self,
        application_id: &str,
        namespace: &str,
        object_id: &str,
        requested_generation: Option<u64>,
    ) -> Result<GossipSearchHit, GossipError> {
        self.withdraw_internal(application_id, namespace, object_id, requested_generation, true).await
    }

    async fn withdraw_internal(
        &self,
        application_id: &str,
        namespace: &str,
        object_id: &str,
        requested_generation: Option<u64>,
        allow_reserved: bool,
    ) -> Result<GossipSearchHit, GossipError> {
        validate_application_id(application_id)?;
        validate_namespace(namespace, allow_reserved)?;
        validate_object_id(object_id)?;
        let now = current_timestamp();
        let record = {
            let state = self.state.lock().await;
            let app = state.apps.get(application_id).ok_or(GossipError::ObjectNotFound)?;
            let entry = app
                .entries
                .get(&GossipObjectKey::new(namespace, object_id))
                .ok_or(GossipError::ObjectNotFound)?;
            if !entry.locally_published {
                return Err(GossipError::NotLocallyPublished);
            }
            let generation = requested_generation
                .unwrap_or_else(|| entry.record.generation.saturating_add(1))
                .max(entry.record.generation.saturating_add(1));
            GossipRecord {
                namespace: namespace.to_string(),
                object_id: object_id.to_string(),
                generation,
                origin_main_dht: self.main_dht.clone(),
                published_at: now,
                expires_at: now.saturating_add(GOSSIP_DEFAULT_TTL_SECS),
                authoritative_pointer: entry.record.authoritative_pointer.clone(),
                fingerprints: Vec::new(),
                index_tokens: Vec::new(),
                custom_payload: Vec::new(),
                flags: entry.record.flags,
                withdrawn: true,
            }
        };
        self.publish_record_internal(application_id, record, allow_reserved).await
    }

    pub async fn confirm(
        &self,
        application_id: &str,
        namespace: &str,
        object_id: &str,
        generation: u64,
        level: GossipConfirmationLevel,
        matches_authoritative: bool,
    ) -> Result<GossipSearchHit, GossipError> {
        validate_application_id(application_id)?;
        validate_namespace(namespace, true)?;
        validate_object_id(object_id)?;
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        let app = state.apps.get_mut(application_id).ok_or(GossipError::ObjectNotFound)?;
        let entry = app
            .entries
            .get_mut(&GossipObjectKey::new(namespace, object_id))
            .ok_or(GossipError::ObjectNotFound)?;
        if entry.record.generation != generation {
            return Err(GossipError::GenerationMismatch);
        }
        if matches_authoritative {
            entry.last_verified_at = Some(now);
            entry.last_verified_generation = Some(generation);
            if !entry.locally_published {
                entry.verification = match level {
                    GossipConfirmationLevel::PointerConfirmed => GossipVerificationState::PointerConfirmed,
                    GossipConfirmationLevel::AuthoritativeVerified => GossipVerificationState::AuthoritativeVerified,
                };
            }
        } else {
            entry.verification = GossipVerificationState::Conflicting;
        }
        let hit = hit_from_entry(entry, 1.0, 0);
        let event = if matches_authoritative {
            GossipEvent::ObjectUpdated {
                application_id: application_id.to_string(),
                namespace: namespace.to_string(),
                object_id: object_id.to_string(),
                generation,
                verification: entry.verification,
            }
        } else {
            GossipEvent::ConflictObserved {
                application_id: application_id.to_string(),
                namespace: namespace.to_string(),
                object_id: object_id.to_string(),
                generation,
            }
        };
        drop(state);
        let _ = self.events.send(event);
        Ok(hit)
    }

    pub async fn search_local(
        &self,
        application_id: &str,
        query: &GossipSearchQuery,
    ) -> Result<Vec<GossipSearchHit>, GossipError> {
        validate_application_id(application_id)?;
        validate_query(query)?;
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        let app = state.apps.entry(application_id.to_string()).or_default();
        Ok(search_app_state(app, query, now))
    }

    /// Search locally, optionally ask a small rotating set of directly
    /// discovered same-app peers, wait briefly, then rank the merged cache.
    /// Late replies are still ingested and become visible on the next call/event.
    pub async fn search(
        &self,
        application_id: &str,
        query: GossipSearchQuery,
        query_network: bool,
        network_wait_ms: u64,
    ) -> Result<(String, usize, Vec<GossipSearchHit>), GossipError> {
        validate_application_id(application_id)?;
        validate_query(&query)?;
        self.activate_application(application_id).await?;
        let mut query_id = [0u8; 16];
        OsRng.fill_bytes(&mut query_id);
        let query_id_hex = hex::encode(query_id);
        let mut contacted = 0;
        if query_network {
            contacted = self.fanout_query(application_id, query_id, query.clone()).await;
            if contacted > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(
                    network_wait_ms.min(GOSSIP_MAX_NETWORK_WAIT_MS),
                ))
                .await;
            }
        }
        let hits = self.search_local(application_id, &query).await?;
        Ok((query_id_hex, contacted, hits))
    }

    pub async fn list_recent(
        &self,
        application_id: &str,
        namespace: Option<&str>,
        limit: usize,
    ) -> Result<Vec<GossipSearchHit>, GossipError> {
        validate_application_id(application_id)?;
        if let Some(namespace) = namespace {
            validate_namespace(namespace, true)?;
        }
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        let app = state.apps.entry(application_id.to_string()).or_default();
        let mut hits: Vec<_> = app
            .entries
            .values()
            .filter(|entry| entry.record.expires_at > now)
            .filter(|entry| namespace.map_or(true, |value| entry.record.namespace == value))
            .map(|entry| hit_from_entry(entry, 0.0, 0))
            .collect();
        hits.sort_by(|left, right| {
            right
                .record
                .published_at
                .cmp(&left.record.published_at)
                .then_with(|| right.last_seen_at.cmp(&left.last_seen_at))
        });
        hits.truncate(limit.clamp(1, GOSSIP_MAX_QUERY_RESULTS));
        Ok(hits)
    }

    pub async fn stats(&self, application_id: &str) -> Result<GossipAppStats, GossipError> {
        validate_application_id(application_id)?;
        let now = current_timestamp();
        let mut state = self.state.lock().await;
        let app = state.apps.entry(application_id.to_string()).or_default();
        let entries: Vec<_> = app.entries.values().filter(|entry| entry.record.expires_at > now).collect();
        Ok(GossipAppStats {
            application_id: application_id.to_string(),
            object_count: entries.len(),
            locally_published_count: entries.iter().filter(|entry| entry.locally_published).count(),
            conflicting_count: entries
                .iter()
                .filter(|entry| entry.verification == GossipVerificationState::Conflicting)
                .count(),
            total_custom_payload_bytes: entries.iter().map(|entry| entry.record.custom_payload.len()).sum(),
            total_index_tokens: entries.iter().map(|entry| entry.record.index_tokens.len()).sum(),
        })
    }

    async fn process_incoming(&self, message: GossipApplicationMessage) -> Result<(), GossipError> {
        validate_application_id(&message.application_id)?;
        if !self.is_application_active(&message.application_id).await {
            return Ok(());
        }
        let wire = decode_wire(&message.payload)?;
        match wire.message {
            GossipWireMessage::Record {
                record,
                hops_remaining,
            } => {
                validate_record(&record, true)?;
                let ingest = self
                    .ingest_record(
                        &message.application_id,
                        record.clone(),
                        &message.sender_dht,
                        false,
                    )
                    .await?;
                if ingest.forwardable && hops_remaining > 0 {
                    self.fanout_record(
                        &message.application_id,
                        record,
                        Some(&message.sender_dht),
                        hops_remaining.saturating_sub(1),
                    )
                    .await;
                }
            }
            GossipWireMessage::Query { query_id, query } => {
                validate_query(&query)?;
                if !self.is_known_app_peer(&message.application_id, &message.sender_dht).await {
                    return Ok(());
                }
                if !self
                    .allow_query_response(&message.application_id, &message.sender_dht)
                    .await
                {
                    return Ok(());
                }
                let mut hits = self.search_local(&message.application_id, &query).await?;
                hits.truncate(GOSSIP_MAX_QUERY_RESPONSE_RECORDS);
                let mut records = Vec::new();
                for hit in hits {
                    let mut candidate = records.clone();
                    candidate.push(hit.record);
                    if encode_wire(GossipWireMessage::QueryResponse {
                        query_id,
                        records: candidate.clone(),
                    })
                    .is_err()
                    {
                        break;
                    }
                    records = candidate;
                }
                let frame = encode_wire(GossipWireMessage::QueryResponse { query_id, records })?;
                let _ = HandshakeManager::send_compact_gossip_application_message_shared(
                    self.handshake.clone(),
                    message.sender_dht,
                    message.application_id,
                    frame,
                )
                .await;
            }
            GossipWireMessage::QueryResponse { query_id, records } => {
                let mut accepted = 0usize;
                for record in records.into_iter().take(GOSSIP_MAX_QUERY_RESPONSE_RECORDS) {
                    if validate_record(&record, true).is_err() {
                        continue;
                    }
                    if self
                        .ingest_record(
                            &message.application_id,
                            record,
                            &message.sender_dht,
                            false,
                        )
                        .await
                        .is_ok()
                    {
                        accepted += 1;
                    }
                }
                let _ = self.events.send(GossipEvent::QueryMerged {
                    application_id: message.application_id,
                    query_id_hex: hex::encode(query_id),
                    accepted_records: accepted,
                });
            }
        }
        Ok(())
    }

    async fn ingest_record(
        &self,
        application_id: &str,
        record: GossipRecord,
        claimed_source: &str,
        local_publish: bool,
    ) -> Result<IngestResult, GossipError> {
        validate_record(&record, true)?;
        let now = current_timestamp();
        if record.expires_at <= now {
            return Err(GossipError::Wire("record already expired".into()));
        }
        let digest = record_digest(&record)?;
        let key = GossipObjectKey::new(&record.namespace, &record.object_id);
        let mut state = self.state.lock().await;
        prune_state_locked(&mut state, now);
        let app = state.apps.entry(application_id.to_string()).or_default();
        let mut forwardable = false;
        let mut event = None;
        match app.entries.get_mut(&key) {
            None => {
                let mut sources = HashSet::new();
                if !claimed_source.is_empty() {
                    sources.insert(claimed_source.to_string());
                }
                let verification = if local_publish {
                    GossipVerificationState::LocalPublished
                } else {
                    GossipVerificationState::Unverified
                };
                app.entries.insert(
                    key.clone(),
                    GossipCacheEntry {
                        record: record.clone(),
                        digest,
                        first_seen_at: now,
                        last_seen_at: now,
                        last_verified_at: local_publish.then_some(now),
                        last_verified_generation: local_publish.then_some(record.generation),
                        verification,
                        supporting_claimed_sources: sources,
                        conflicting_digests: HashSet::new(),
                        locally_published: local_publish,
                    },
                );
                forwardable = true;
                event = Some(if record.withdrawn {
                    GossipEvent::ObjectWithdrawn {
                        application_id: application_id.to_string(),
                        namespace: record.namespace.clone(),
                        object_id: record.object_id.clone(),
                        generation: record.generation,
                    }
                } else {
                    GossipEvent::ObjectUpdated {
                        application_id: application_id.to_string(),
                        namespace: record.namespace.clone(),
                        object_id: record.object_id.clone(),
                        generation: record.generation,
                        verification,
                    }
                });
            }
            Some(entry) if entry.locally_published && !local_publish => {
                // Gossip is not allowed to replace this device's own published
                // state. A remote claim can still alert the app that something
                // disagrees, including a supposedly newer generation.
                entry.last_seen_at = now;
                if digest != entry.digest || record.generation != entry.record.generation {
                    entry.conflicting_digests.insert(digest);
                    event = Some(GossipEvent::ConflictObserved {
                        application_id: application_id.to_string(),
                        namespace: record.namespace.clone(),
                        object_id: record.object_id.clone(),
                        generation: record.generation,
                    });
                }
            }
            Some(entry) if record.generation > entry.record.generation => {
                // A newer generation is an update *hint*. Verification of an
                // older generation is intentionally not inherited.
                entry.record = record.clone();
                entry.digest = digest;
                entry.last_seen_at = now;
                if local_publish {
                    entry.last_verified_at = Some(now);
                    entry.last_verified_generation = Some(record.generation);
                }
                entry.verification = if local_publish {
                    GossipVerificationState::LocalPublished
                } else {
                    GossipVerificationState::Unverified
                };
                entry.supporting_claimed_sources.clear();
                if !claimed_source.is_empty() {
                    entry.supporting_claimed_sources.insert(claimed_source.to_string());
                }
                entry.conflicting_digests.clear();
                entry.locally_published = local_publish;
                forwardable = true;
                event = Some(if record.withdrawn {
                    GossipEvent::ObjectWithdrawn {
                        application_id: application_id.to_string(),
                        namespace: record.namespace.clone(),
                        object_id: record.object_id.clone(),
                        generation: record.generation,
                    }
                } else {
                    GossipEvent::ObjectUpdated {
                        application_id: application_id.to_string(),
                        namespace: record.namespace.clone(),
                        object_id: record.object_id.clone(),
                        generation: record.generation,
                        verification: entry.verification,
                    }
                });
            }
            Some(entry) if record.generation < entry.record.generation => {
                // Old gossip must never roll back a newer cached claim.
                entry.last_seen_at = now;
            }
            Some(entry) if digest == entry.digest => {
                entry.last_seen_at = now;
                if entry.supporting_claimed_sources.len() < GOSSIP_MAX_CLAIMED_SOURCES
                    && !claimed_source.is_empty()
                {
                    entry.supporting_claimed_sources.insert(claimed_source.to_string());
                }
                if local_publish {
                    entry.locally_published = true;
                    entry.last_verified_at = Some(now);
                    entry.last_verified_generation = Some(record.generation);
                    entry.verification = GossipVerificationState::LocalPublished;
                } else if entry.verification == GossipVerificationState::Unverified
                    && entry.supporting_claimed_sources.len() >= 2
                {
                    entry.verification = GossipVerificationState::MultiSourceHint;
                }
            }
            Some(entry) => {
                entry.last_seen_at = now;
                entry.conflicting_digests.insert(digest);
                entry.verification = GossipVerificationState::Conflicting;
                event = Some(GossipEvent::ConflictObserved {
                    application_id: application_id.to_string(),
                    namespace: record.namespace.clone(),
                    object_id: record.object_id.clone(),
                    generation: record.generation,
                });
            }
        }
        rebuild_token_index(app);
        enforce_capacity_locked(&mut state);
        let hit = state
            .apps
            .get(application_id)
            .and_then(|app| app.entries.get(&key))
            .map(|entry| hit_from_entry(entry, 1.0, 0))
            .ok_or(GossipError::ObjectNotFound)?;
        drop(state);
        if let Some(event) = event {
            let _ = self.events.send(event);
        }
        Ok(IngestResult { hit, forwardable })
    }

    async fn fanout_record(
        &self,
        application_id: &str,
        record: GossipRecord,
        exclude_peer: Option<&str>,
        hops_remaining: u8,
    ) {
        let frame = match encode_wire(GossipWireMessage::Record {
            record,
            hops_remaining: hops_remaining.min(GOSSIP_MAX_RELAY_HOPS),
        }) {
            Ok(frame) => frame,
            Err(error) => {
                crate::teprintln!("[gossip-engine] could not encode record: {error}");
                return;
            }
        };
        let fanout = if exclude_peer.is_some() {
            GOSSIP_RELAY_FANOUT
        } else {
            GOSSIP_PUBLISH_FANOUT
        };
        let peers = self.select_peers(application_id, fanout, exclude_peer).await;
        for peer in peers {
            let handshake = self.handshake.clone();
            let app_id = application_id.to_string();
            let payload = frame.clone();
            tokio::spawn(async move {
                if let Err(error) = HandshakeManager::send_compact_gossip_application_message_shared(
                    handshake,
                    peer,
                    app_id,
                    payload,
                )
                .await
                {
                    crate::teprintln!("[gossip-engine] record fanout failed: {error}");
                }
            });
        }
    }

    async fn fanout_query(
        &self,
        application_id: &str,
        query_id: [u8; 16],
        query: GossipSearchQuery,
    ) -> usize {
        let frame = match encode_wire(GossipWireMessage::Query { query_id, query }) {
            Ok(frame) => frame,
            Err(error) => {
                crate::teprintln!("[gossip-engine] could not encode query: {error}");
                return 0;
            }
        };
        let peers = self.select_peers(application_id, GOSSIP_QUERY_FANOUT, None).await;
        let count = peers.len();
        for peer in peers {
            let handshake = self.handshake.clone();
            let app_id = application_id.to_string();
            let payload = frame.clone();
            tokio::spawn(async move {
                if let Err(error) = HandshakeManager::send_compact_gossip_application_message_shared(
                    handshake,
                    peer,
                    app_id,
                    payload,
                )
                .await
                {
                    crate::teprintln!("[gossip-engine] query fanout failed: {error}");
                }
            });
        }
        count
    }

    async fn select_peers(
        &self,
        application_id: &str,
        limit: usize,
        exclude_peer: Option<&str>,
    ) -> Vec<String> {
        let Some(walk_task) = &self.walk_task else {
            return Vec::new();
        };
        let mut peers: Vec<String> = if application_id == GOSSIP_TEST_APPLICATION_ID {
            // The built-in diagnostic has no installed/approved app identity, so
            // it deliberately uses the daemon's already-verified topology as its
            // peer set. This exception is never reachable through app IPC.
            walk_task
                .get_internal_list_copy()
                .await
                .entries
                .into_iter()
                .map(|entry| entry.their_address.to_string())
                .collect()
        } else {
            walk_task
                .list_app_peers(application_id, (limit * 4).clamp(1, 64))
                .await
                .peers
                .into_iter()
                .map(|peer| peer.main_dht.to_string())
                .collect()
        };
        peers.retain(|peer| peer != &self.main_dht);
        peers.retain(|peer| exclude_peer.map_or(true, |excluded| peer != excluded));
        peers.shuffle(&mut thread_rng());
        peers.truncate(limit);
        peers
    }

    async fn is_application_active(&self, application_id: &str) -> bool {
        self.state.lock().await.apps.contains_key(application_id)
    }

    async fn is_known_app_peer(&self, application_id: &str, peer: &str) -> bool {
        let Some(walk_task) = &self.walk_task else {
            return false;
        };
        if application_id == GOSSIP_TEST_APPLICATION_ID {
            return walk_task
                .get_internal_list_copy()
                .await
                .entries
                .into_iter()
                .any(|candidate| candidate.their_address.to_string() == peer);
        }
        walk_task
            .list_app_peers(application_id, 256)
            .await
            .peers
            .into_iter()
            .any(|candidate| candidate.main_dht.to_string() == peer)
    }

    async fn allow_query_response(&self, application_id: &str, claimed_peer: &str) -> bool {
        let now = current_timestamp();
        let key = (application_id.to_string(), claimed_peer.to_string());
        let mut state = self.state.lock().await;
        if state
            .query_response_last
            .get(&key)
            .is_some_and(|last| now.saturating_sub(*last) < GOSSIP_QUERY_RESPONSE_COOLDOWN_SECS)
        {
            return false;
        }
        state.query_response_last.insert(key, now);
        true
    }

    async fn prune_expired(&self) {
        let mut state = self.state.lock().await;
        prune_state_locked(&mut state, current_timestamp());
    }
}

struct IngestResult {
    hit: GossipSearchHit,
    forwardable: bool,
}

pub fn is_engine_frame(payload: &[u8]) -> bool {
    payload.starts_with(GOSSIP_WIRE_PREFIX)
}

fn encode_wire(message: GossipWireMessage) -> Result<Vec<u8>, GossipError> {
    let envelope = GossipWireEnvelope {
        version: GOSSIP_ENGINE_VERSION,
        message,
    };
    let encoded = bincode::serialize(&envelope).map_err(|error| GossipError::Wire(error.to_string()))?;
    if encoded.len().saturating_add(GOSSIP_WIRE_PREFIX.len()) > GOSSIP_WIRE_MAX_BYTES {
        return Err(GossipError::Wire("encoded frame exceeds gossip-engine limit".into()));
    }
    let mut output = Vec::with_capacity(GOSSIP_WIRE_PREFIX.len() + encoded.len());
    output.extend_from_slice(GOSSIP_WIRE_PREFIX);
    output.extend_from_slice(&encoded);
    Ok(output)
}

fn decode_wire(payload: &[u8]) -> Result<GossipWireEnvelope, GossipError> {
    if !is_engine_frame(payload) {
        return Err(GossipError::Wire("missing gossip-engine prefix".into()));
    }
    if payload.len() > GOSSIP_WIRE_MAX_BYTES {
        return Err(GossipError::Wire("frame exceeds gossip-engine limit".into()));
    }
    let envelope: GossipWireEnvelope = bincode::deserialize(&payload[GOSSIP_WIRE_PREFIX.len()..])
        .map_err(|error| GossipError::Wire(error.to_string()))?;
    if envelope.version != GOSSIP_ENGINE_VERSION {
        return Err(GossipError::Wire(format!(
            "unsupported gossip-engine version {}",
            envelope.version
        )));
    }
    Ok(envelope)
}

/// Convert one application-supplied exact-search term into the opaque token
/// that is stored/gossiped. This is pseudonymous indexing, not secrecy: a peer
/// that guesses a term can derive the same digest and test for it. App/namespace
/// scoping prevents one global token dictionary from correlating unrelated apps.
pub fn derive_index_token(
    application_id: &str,
    namespace: &str,
    index_name: &str,
    term: &str,
) -> Result<GossipIndexToken, GossipError> {
    validate_application_id(application_id)?;
    validate_namespace(namespace, true)?;
    validate_index_name(index_name)?;
    let normalized = normalize_index_term(term)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"veilknit-gossip-index-token-v1\0");
    hasher.update(application_id.trim().to_ascii_lowercase().as_bytes());
    hasher.update(b"\0");
    hasher.update(namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update(index_name.to_ascii_lowercase().as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized.as_bytes());
    let hash = hasher.finalize();
    let mut digest = [0u8; GOSSIP_INDEX_TOKEN_BYTES];
    digest.copy_from_slice(&hash.as_bytes()[..GOSSIP_INDEX_TOKEN_BYTES]);
    Ok(GossipIndexToken { digest })
}

pub fn derive_index_tokens<I, S>(
    application_id: &str,
    namespace: &str,
    index_name: &str,
    terms: I,
) -> Result<Vec<GossipIndexToken>, GossipError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut unique = HashSet::new();
    let mut tokens = Vec::new();
    for term in terms {
        let token = derive_index_token(application_id, namespace, index_name, term.as_ref())?;
        if unique.insert(token) {
            tokens.push(token);
        }
        if tokens.len() > GOSSIP_MAX_INDEX_TOKENS {
            return Err(GossipError::TooManyIndexTokens);
        }
    }
    Ok(tokens)
}

fn validate_index_name(index_name: &str) -> Result<(), GossipError> {
    let trimmed = index_name.trim();
    if trimmed.is_empty()
        || trimmed.len() > GOSSIP_MAX_INDEX_NAME_BYTES
        || !trimmed.is_ascii()
        || trimmed
            .chars()
            .any(|value| value.is_ascii_control() || value.is_ascii_whitespace())
    {
        return Err(GossipError::InvalidIndex("index name is invalid".into()));
    }
    Ok(())
}

fn normalize_index_term(term: &str) -> Result<String, GossipError> {
    if term.chars().any(|value| value.is_control()) {
        return Err(GossipError::InvalidIndex("index term contains a control character".into()));
    }
    // This is protocol-level normalization only. Stemming, synonyms, language
    // parsing, and deciding which words to index remain application policy.
    let collapsed = term.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized = collapsed.to_lowercase();
    if normalized.is_empty() || normalized.as_bytes().len() > GOSSIP_MAX_INDEX_TERM_BYTES {
        return Err(GossipError::InvalidIndex(format!(
            "index term must be 1..={GOSSIP_MAX_INDEX_TERM_BYTES} UTF-8 bytes after normalization"
        )));
    }
    Ok(normalized)
}

fn validate_index_tokens(tokens: &[GossipIndexToken]) -> Result<(), GossipError> {
    if tokens.len() > GOSSIP_MAX_INDEX_TOKENS {
        return Err(GossipError::TooManyIndexTokens);
    }
    Ok(())
}

fn validate_application_id(application_id: &str) -> Result<(), GossipError> {
    let trimmed = application_id.trim();
    if trimmed.is_empty() || trimmed.len() > 256 || !trimmed.is_ascii() {
        return Err(GossipError::InvalidApplicationId);
    }
    Ok(())
}

fn validate_namespace(namespace: &str, allow_reserved: bool) -> Result<(), GossipError> {
    if namespace.is_empty()
        || namespace.len() > GOSSIP_MAX_NAMESPACE_BYTES
        || !namespace.is_ascii()
        || namespace.chars().any(|value| value.is_ascii_control() || value.is_ascii_whitespace())
    {
        return Err(GossipError::InvalidNamespace);
    }
    if !allow_reserved && namespace.starts_with("_veilknit.") {
        return Err(GossipError::ReservedNamespace);
    }
    Ok(())
}

fn validate_object_id(object_id: &str) -> Result<(), GossipError> {
    if object_id.is_empty()
        || object_id.len() > GOSSIP_MAX_OBJECT_ID_BYTES
        || object_id.chars().any(|value| value.is_control())
    {
        return Err(GossipError::InvalidObjectId);
    }
    Ok(())
}

fn validate_fingerprint(fingerprint: &GossipFingerprint) -> Result<(), GossipError> {
    validate_fingerprint_parts(
        &fingerprint.channel,
        &fingerprint.algorithm,
        &fingerprint.bytes,
    )?;
    if fingerprint.algorithm.eq_ignore_ascii_case("minhash16") && fingerprint.bytes.len() % 2 != 0 {
        return Err(GossipError::InvalidFingerprint(
            "minhash16 byte length must be even".into(),
        ));
    }
    Ok(())
}

fn validate_probe(probe: &GossipFingerprintProbe) -> Result<(), GossipError> {
    validate_fingerprint_parts(&probe.channel, &probe.algorithm, &probe.bytes)?;
    if probe.weight == 0 || probe.weight > 1000 {
        return Err(GossipError::InvalidQuery(
            "fingerprint probe weight must be 1..=1000".into(),
        ));
    }
    if probe.algorithm.eq_ignore_ascii_case("minhash16") && probe.bytes.len() % 2 != 0 {
        return Err(GossipError::InvalidQuery(
            "minhash16 probe byte length must be even".into(),
        ));
    }
    Ok(())
}

fn validate_fingerprint_parts(channel: &str, algorithm: &str, bytes: &[u8]) -> Result<(), GossipError> {
    if channel.is_empty()
        || channel.len() > GOSSIP_MAX_FINGERPRINT_CHANNEL_BYTES
        || !channel.is_ascii()
        || channel.chars().any(|value| value.is_ascii_control() || value.is_ascii_whitespace())
    {
        return Err(GossipError::InvalidFingerprint("channel is invalid".into()));
    }
    if algorithm.is_empty()
        || algorithm.len() > GOSSIP_MAX_FINGERPRINT_ALGORITHM_BYTES
        || !algorithm.is_ascii()
        || algorithm.chars().any(|value| value.is_ascii_control() || value.is_ascii_whitespace())
    {
        return Err(GossipError::InvalidFingerprint("algorithm is invalid".into()));
    }
    if bytes.is_empty() || bytes.len() > GOSSIP_MAX_FINGERPRINT_BYTES {
        return Err(GossipError::InvalidFingerprint(format!(
            "fingerprint bytes must be 1..={GOSSIP_MAX_FINGERPRINT_BYTES}"
        )));
    }
    if algorithm.eq_ignore_ascii_case("minhash16") && bytes.len() % 2 != 0 {
        return Err(GossipError::InvalidFingerprint(
            "minhash16 fingerprints must contain whole 16-bit positions".into(),
        ));
    }
    Ok(())
}

fn validate_publish_request(request: &GossipPublishRequest) -> Result<(), GossipError> {
    validate_object_id(&request.object_id)?;
    if let Some(pointer) = &request.authoritative_pointer {
        validate_pointer(pointer)?;
    }
    if request.fingerprints.len() > GOSSIP_MAX_FINGERPRINTS {
        return Err(GossipError::TooManyFingerprints);
    }
    for fingerprint in &request.fingerprints {
        validate_fingerprint(fingerprint)?;
    }
    validate_index_tokens(&request.index_tokens)?;
    if request.custom_payload.len() > GOSSIP_MAX_CUSTOM_PAYLOAD_BYTES {
        return Err(GossipError::CustomPayloadTooLarge);
    }
    if request.ttl_seconds == 0 || request.ttl_seconds > GOSSIP_MAX_TTL_SECS {
        return Err(GossipError::InvalidTtl);
    }
    Ok(())
}

fn validate_record(record: &GossipRecord, allow_reserved: bool) -> Result<(), GossipError> {
    validate_namespace(&record.namespace, allow_reserved)?;
    validate_object_id(&record.object_id)?;
    // The claimed origin is routing metadata rather than proof, but it still
    // has to be shaped like a real Veilid record key before we cache/relay it.
    if record.origin_main_dht.len() > GOSSIP_MAX_POINTER_BYTES
        || record.origin_main_dht.chars().any(|value| value.is_control())
    {
        return Err(GossipError::InvalidPointer);
    }
    let _ = record
        .origin_main_dht
        .parse::<RecordKey>()
        .map_err(|_| GossipError::InvalidPointer)?;
    if let Some(pointer) = &record.authoritative_pointer {
        validate_pointer(pointer)?;
    }
    if record.fingerprints.len() > GOSSIP_MAX_FINGERPRINTS {
        return Err(GossipError::TooManyFingerprints);
    }
    for fingerprint in &record.fingerprints {
        validate_fingerprint(fingerprint)?;
    }
    validate_index_tokens(&record.index_tokens)?;
    if record.custom_payload.len() > GOSSIP_MAX_CUSTOM_PAYLOAD_BYTES {
        return Err(GossipError::CustomPayloadTooLarge);
    }
    if record.expires_at <= record.published_at
        || record.expires_at.saturating_sub(record.published_at) > GOSSIP_MAX_TTL_SECS
    {
        return Err(GossipError::InvalidTtl);
    }
    let now = current_timestamp();
    if record.published_at > now.saturating_add(GOSSIP_MAX_FUTURE_SKEW_SECS) {
        return Err(GossipError::Wire("record publication time is too far in the future".into()));
    }
    if record.withdrawn
        && (!record.fingerprints.is_empty()
            || !record.index_tokens.is_empty()
            || !record.custom_payload.is_empty())
    {
        return Err(GossipError::Wire(
            "withdrawn records cannot carry fingerprints/index tokens/custom payload".into(),
        ));
    }
    Ok(())
}

fn validate_pointer(pointer: &str) -> Result<(), GossipError> {
    if pointer.is_empty() || pointer.len() > GOSSIP_MAX_POINTER_BYTES || pointer.chars().any(|value| value.is_control()) {
        return Err(GossipError::InvalidPointer);
    }
    // Version one deliberately permits future opaque pointer schemes. When it
    // looks like a bare Veilid record key, parsing is useful but not mandatory.
    Ok(())
}

fn validate_query(query: &GossipSearchQuery) -> Result<(), GossipError> {
    validate_namespace(&query.namespace, true)?;
    if query.probes.len() > GOSSIP_MAX_QUERY_PROBES {
        return Err(GossipError::InvalidQuery(format!(
            "at most {GOSSIP_MAX_QUERY_PROBES} fingerprint probes are allowed"
        )));
    }
    if query.limit == 0 || query.limit > GOSSIP_MAX_QUERY_RESULTS {
        return Err(GossipError::InvalidQuery(format!(
            "result limit must be 1..={GOSSIP_MAX_QUERY_RESULTS}"
        )));
    }
    if query.min_score_milli.is_some_and(|score| score > 1000) {
        return Err(GossipError::InvalidQuery(
            "minimum score must be 0..=1000".into(),
        ));
    }
    for probe in &query.probes {
        validate_probe(probe)?;
    }
    if query.token_probes.len() > GOSSIP_MAX_INDEX_PROBES {
        return Err(GossipError::InvalidQuery(format!(
            "at most {GOSSIP_MAX_INDEX_PROBES} token probe groups are allowed"
        )));
    }
    let mut total_tokens = 0usize;
    for probe in &query.token_probes {
        if probe.tokens.is_empty() || probe.tokens.len() > GOSSIP_MAX_INDEX_TOKENS_PER_PROBE {
            return Err(GossipError::InvalidQuery(format!(
                "each token probe must contain 1..={GOSSIP_MAX_INDEX_TOKENS_PER_PROBE} tokens"
            )));
        }
        if probe.weight == 0 || probe.weight > 1000 {
            return Err(GossipError::InvalidQuery(
                "token probe weight must be 1..=1000".into(),
            ));
        }
        total_tokens = total_tokens.saturating_add(probe.tokens.len());
    }
    if total_tokens > GOSSIP_MAX_INDEX_TOKENS {
        return Err(GossipError::InvalidQuery(format!(
            "a query may reference at most {GOSSIP_MAX_INDEX_TOKENS} index tokens"
        )));
    }
    Ok(())
}

fn record_digest(record: &GossipRecord) -> Result<[u8; 32], GossipError> {
    let encoded = bincode::serialize(record).map_err(|error| GossipError::Wire(error.to_string()))?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

fn hit_from_entry(entry: &GossipCacheEntry, score: f32, matched_index_tokens: usize) -> GossipSearchHit {
    GossipSearchHit {
        record: entry.record.clone(),
        score,
        matched_index_tokens,
        verification: entry.verification,
        claimed_source_count: entry.supporting_claimed_sources.len(),
        conflicting_claim_count: entry.conflicting_digests.len(),
        first_seen_at: entry.first_seen_at,
        last_seen_at: entry.last_seen_at,
        last_verified_at: entry.last_verified_at,
        last_verified_generation: entry.last_verified_generation,
    }
}

fn search_app_state(
    app: &AppGossipState,
    query: &GossipSearchQuery,
    now: u64,
) -> Vec<GossipSearchHit> {
    let minimum = query.min_score_milli.map(|value| value as f32 / 1000.0);
    // Required exact-token probes use the local inverted index to avoid scanning
    // the whole per-app gossip cache. Preferred/excluded probes are then applied
    // while ranking/filtering the narrowed candidate set.
    let candidate_keys = token_index_candidates(app, &query.token_probes)
        .unwrap_or_else(|| app.entries.keys().cloned().collect());
    let mut hits: Vec<_> = candidate_keys
        .into_iter()
        .filter_map(|key| app.entries.get(&key))
        .filter(|entry| entry.record.expires_at > now)
        .filter(|entry| entry.record.namespace == query.namespace)
        .filter(|entry| query.include_withdrawn || !entry.record.withdrawn)
        .filter_map(|entry| {
            let (token_ok, matched_index_tokens) = token_filters_match(entry, &query.token_probes);
            if !token_ok {
                return None;
            }
            let score = score_entry(entry, &query.probes, &query.token_probes, now);
            if minimum.is_some_and(|minimum| score < minimum) {
                return None;
            }
            Some(hit_from_entry(entry, score, matched_index_tokens))
        })
        .collect();
    hits.sort_by(compare_hits);
    hits.truncate(query.limit);
    hits
}

fn token_index_candidates(
    app: &AppGossipState,
    probes: &[GossipTokenProbe],
) -> Option<HashSet<GossipObjectKey>> {
    let required: Vec<_> = probes
        .iter()
        .filter(|probe| probe.polarity == GossipTokenPolarity::Required)
        .collect();
    if required.is_empty() {
        return None;
    }

    let mut candidates: Option<HashSet<GossipObjectKey>> = None;
    for probe in required {
        let mut group: Option<HashSet<GossipObjectKey>> = None;
        for token in &probe.tokens {
            let keys = app.token_index.get(token).cloned().unwrap_or_default();
            group = Some(match (group, probe.match_mode) {
                (None, _) => keys,
                (Some(mut existing), GossipTokenMatchMode::Any) => {
                    existing.extend(keys);
                    existing
                }
                (Some(existing), GossipTokenMatchMode::All) => {
                    existing.intersection(&keys).cloned().collect()
                }
            });
        }
        let group = group.unwrap_or_default();
        candidates = Some(match candidates {
            None => group,
            Some(existing) => existing.intersection(&group).cloned().collect(),
        });
        if candidates.as_ref().is_some_and(|set| set.is_empty()) {
            break;
        }
    }
    candidates
}

fn compare_hits(left: &GossipSearchHit, right: &GossipSearchHit) -> Ordering {
    right
        .score
        .partial_cmp(&left.score)
        .unwrap_or(Ordering::Equal)
        .then_with(|| verification_rank(right.verification).cmp(&verification_rank(left.verification)))
        .then_with(|| right.record.generation.cmp(&left.record.generation))
        .then_with(|| right.last_seen_at.cmp(&left.last_seen_at))
}

fn verification_rank(state: GossipVerificationState) -> u8 {
    match state {
        GossipVerificationState::Conflicting => 0,
        GossipVerificationState::Unverified => 1,
        GossipVerificationState::MultiSourceHint => 2,
        GossipVerificationState::PointerConfirmed => 3,
        GossipVerificationState::AuthoritativeVerified => 4,
        GossipVerificationState::LocalPublished => 5,
    }
}

fn token_probe_match_count(entry: &GossipCacheEntry, probe: &GossipTokenProbe) -> usize {
    let available: HashSet<_> = entry.record.index_tokens.iter().copied().collect();
    probe.tokens.iter().filter(|token| available.contains(token)).count()
}

fn token_probe_group_matches(entry: &GossipCacheEntry, probe: &GossipTokenProbe) -> bool {
    let matched = token_probe_match_count(entry, probe);
    match probe.match_mode {
        GossipTokenMatchMode::All => matched == probe.tokens.len(),
        GossipTokenMatchMode::Any => matched > 0,
    }
}

fn token_filters_match(entry: &GossipCacheEntry, probes: &[GossipTokenProbe]) -> (bool, usize) {
    let mut matched_tokens = HashSet::new();
    for probe in probes {
        let available: HashSet<_> = entry.record.index_tokens.iter().copied().collect();
        for token in &probe.tokens {
            if available.contains(token) {
                matched_tokens.insert(*token);
            }
        }
        let group_matches = token_probe_group_matches(entry, probe);
        match probe.polarity {
            GossipTokenPolarity::Required if !group_matches => return (false, matched_tokens.len()),
            GossipTokenPolarity::Exclude if group_matches => return (false, matched_tokens.len()),
            _ => {}
        }
    }
    (true, matched_tokens.len())
}

fn score_entry(
    entry: &GossipCacheEntry,
    probes: &[GossipFingerprintProbe],
    token_probes: &[GossipTokenProbe],
    now: u64,
) -> f32 {
    let has_required_tokens = token_probes
        .iter()
        .any(|probe| probe.polarity == GossipTokenPolarity::Required);
    let preferred: Vec<_> = token_probes
        .iter()
        .filter(|probe| probe.polarity == GossipTokenPolarity::Preferred)
        .collect();

    let fingerprint_score = if probes.is_empty() {
        None
    } else {
        let mut positive_weight = 0f32;
        let mut positive_score = 0f32;
        let mut negative_weight = 0f32;
        let mut negative_score = 0f32;
        for probe in probes {
            let weight = probe.weight as f32;
            let best = entry
                .record
                .fingerprints
                .iter()
                .filter(|fingerprint| {
                    fingerprint.channel == probe.channel
                        && fingerprint.algorithm.eq_ignore_ascii_case(&probe.algorithm)
                        && fingerprint.version == probe.version
                })
                .map(|fingerprint| fingerprint_similarity(fingerprint, probe))
                .fold(0.0f32, f32::max);
            match probe.polarity {
                GossipProbePolarity::Similar => {
                    positive_weight += weight;
                    positive_score += best * weight;
                }
                GossipProbePolarity::Avoid => {
                    negative_weight += weight;
                    negative_score += best * weight;
                }
            }
        }
        let positive = if positive_weight > 0.0 {
            positive_score / positive_weight
        } else {
            0.5
        };
        let negative = if negative_weight > 0.0 {
            negative_score / negative_weight
        } else {
            0.0
        };
        Some((positive * (1.0 - negative)).clamp(0.0, 1.0))
    };

    let preferred_score = if preferred.is_empty() {
        None
    } else {
        let mut weighted = 0.0f32;
        let mut total_weight = 0.0f32;
        for probe in preferred {
            let matched = token_probe_match_count(entry, probe) as f32;
            let fraction = match probe.match_mode {
                GossipTokenMatchMode::All => matched / probe.tokens.len() as f32,
                GossipTokenMatchMode::Any => {
                    if matched > 0.0 { 1.0 } else { 0.0 }
                }
            };
            weighted += fraction * probe.weight as f32;
            total_weight += probe.weight as f32;
        }
        Some(if total_weight > 0.0 { weighted / total_weight } else { 0.0 })
    };

    match (fingerprint_score, preferred_score) {
        (Some(fingerprint), Some(tokens)) => (fingerprint * 0.70 + tokens * 0.30).clamp(0.0, 1.0),
        (Some(fingerprint), None) => fingerprint,
        (None, Some(tokens)) => tokens,
        (None, None) if has_required_tokens => 1.0,
        (None, None) => {
            // Browse mode: recency is useful, but still does not imply trust.
            let age = now.saturating_sub(entry.last_seen_at);
            (1.0 - (age as f32 / GOSSIP_MAX_TTL_SECS as f32)).clamp(0.0, 1.0)
        }
    }
}

fn fingerprint_similarity(fingerprint: &GossipFingerprint, probe: &GossipFingerprintProbe) -> f32 {
    let left = &fingerprint.bytes;
    let right = &probe.bytes;
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    if fingerprint.algorithm.eq_ignore_ascii_case("minhash16") {
        // A shorter signature must not be able to score 1.0 by matching only
        // one or two positions of a longer signature. Algorithm+version imply
        // one fixed representation, so mismatched lengths are non-matches.
        if left.len() != right.len() || left.len() % 2 != 0 {
            return 0.0;
        }
        let count = left.len() / 2;
        if count == 0 {
            return 0.0;
        }
        let equal = (0..count)
            .filter(|index| {
                let offset = index * 2;
                left[offset..offset + 2] == right[offset..offset + 2]
            })
            .count();
        return equal as f32 / count as f32;
    }
    if fingerprint.algorithm.eq_ignore_ascii_case("hamming") {
        if left.len() != right.len() {
            return 0.0;
        }
        let count = left.len();
        if count == 0 {
            return 0.0;
        }
        let differing_bits: u32 = left
            .iter()
            .zip(right.iter())
            .take(count)
            .map(|(left, right)| (left ^ right).count_ones())
            .sum();
        let total_bits = (count * 8) as f32;
        return (1.0 - differing_bits as f32 / total_bits).clamp(0.0, 1.0);
    }
    // `exact` and unknown/custom algorithms are deliberately conservative:
    // the daemon does not invent semantics for bytes it does not understand.
    if left == right { 1.0 } else { 0.0 }
}

fn rebuild_token_index(app: &mut AppGossipState) {
    app.token_index.clear();
    for (key, entry) in &app.entries {
        if entry.record.withdrawn {
            continue;
        }
        for token in &entry.record.index_tokens {
            app.token_index
                .entry(*token)
                .or_default()
                .insert(key.clone());
        }
    }
}

fn prune_state_locked(state: &mut GossipState, now: u64) {
    for app in state.apps.values_mut() {
        app.entries.retain(|_, entry| entry.record.expires_at > now);
        rebuild_token_index(app);
    }
    state.query_response_last.retain(|_, last| {
        now.saturating_sub(*last) < GOSSIP_MAX_TTL_SECS
    });
}

fn enforce_capacity_locked(state: &mut GossipState) {
    for app in state.apps.values_mut() {
        while app.entries.len() > GOSSIP_MAX_ENTRIES_PER_APP {
            if let Some(key) = eviction_candidate(app) {
                app.entries.remove(&key);
            } else {
                break;
            }
        }
    }
    while state.apps.values().map(|app| app.entries.len()).sum::<usize>() > GOSSIP_MAX_ENTRIES_GLOBAL {
        let candidate = state
            .apps
            .iter()
            .flat_map(|(app_id, app)| {
                app.entries.iter().map(move |(key, entry)| {
                    (app_id.clone(), key.clone(), entry.locally_published, entry.last_seen_at)
                })
            })
            // Never choose a local publication while any remotely learned
            // entry exists. Local publications are bounded by the per-app cap.
            .min_by_key(|(_, _, local, last_seen)| (*local, *last_seen));
        let Some((app_id, key, _, _)) = candidate else {
            break;
        };
        if let Some(app) = state.apps.get_mut(&app_id) {
            app.entries.remove(&key);
        }
    }
    for app in state.apps.values_mut() {
        rebuild_token_index(app);
    }
}

fn eviction_candidate(app: &AppGossipState) -> Option<GossipObjectKey> {
    app.entries
        .iter()
        .min_by_key(|(_, entry)| (entry.locally_published, entry.last_seen_at))
        .map(|(key, _)| key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minhash_similarity_is_position_equality() {
        let fingerprint = GossipFingerprint {
            channel: "content".into(),
            algorithm: "minhash16".into(),
            version: 1,
            bytes: vec![1, 0, 2, 0, 3, 0, 4, 0],
        };
        let probe = GossipFingerprintProbe {
            channel: "content".into(),
            algorithm: "minhash16".into(),
            version: 1,
            bytes: vec![1, 0, 9, 0, 3, 0, 8, 0],
            weight: 100,
            polarity: GossipProbePolarity::Similar,
        };
        assert!((fingerprint_similarity(&fingerprint, &probe) - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn minhash_length_mismatch_does_not_get_a_perfect_short_match() {
        let fingerprint = GossipFingerprint {
            channel: "content".into(),
            algorithm: "minhash16".into(),
            version: 1,
            bytes: vec![1, 0, 2, 0, 3, 0, 4, 0],
        };
        let probe = GossipFingerprintProbe {
            channel: "content".into(),
            algorithm: "minhash16".into(),
            version: 1,
            bytes: vec![1, 0],
            weight: 100,
            polarity: GossipProbePolarity::Similar,
        };
        assert_eq!(fingerprint_similarity(&fingerprint, &probe), 0.0);
    }

    #[test]
    fn index_tokens_are_deterministic_but_scoped() {
        let a = derive_index_token("app.one", "widget", "tags", "  Rust  ").unwrap();
        let b = derive_index_token("app.one", "widget", "tags", "rust").unwrap();
        let other_app = derive_index_token("app.two", "widget", "tags", "rust").unwrap();
        let other_namespace = derive_index_token("app.one", "profile", "tags", "rust").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, other_app);
        assert_ne!(a, other_namespace);
    }

    #[test]
    fn token_filters_support_required_and_excluded_groups() {
        let rust = derive_index_token("app.one", "widget", "tags", "rust").unwrap();
        let dark = derive_index_token("app.one", "widget", "tags", "dark").unwrap();
        let spam = derive_index_token("app.one", "widget", "tags", "spam").unwrap();
        let now = current_timestamp();
        let record = GossipRecord {
            namespace: "widget".into(),
            object_id: "object-a".into(),
            generation: 1,
            origin_main_dht: "VLD0:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            published_at: now,
            expires_at: now + 60,
            authoritative_pointer: None,
            fingerprints: Vec::new(),
            index_tokens: vec![rust, dark],
            custom_payload: Vec::new(),
            flags: 0,
            withdrawn: false,
        };
        let entry = GossipCacheEntry {
            digest: [0; 32],
            record,
            first_seen_at: now,
            last_seen_at: now,
            last_verified_at: None,
            last_verified_generation: None,
            verification: GossipVerificationState::Unverified,
            supporting_claimed_sources: HashSet::new(),
            conflicting_digests: HashSet::new(),
            locally_published: false,
        };
        let required = GossipTokenProbe {
            tokens: vec![rust, dark],
            polarity: GossipTokenPolarity::Required,
            match_mode: GossipTokenMatchMode::All,
            weight: 100,
        };
        let exclude = GossipTokenProbe {
            tokens: vec![spam],
            polarity: GossipTokenPolarity::Exclude,
            match_mode: GossipTokenMatchMode::Any,
            weight: 100,
        };
        assert_eq!(token_filters_match(&entry, &[required.clone(), exclude]), (true, 2));

        let mut app = AppGossipState::default();
        app.entries.insert(GossipObjectKey::new("widget", "object-a"), entry);
        rebuild_token_index(&mut app);
        let candidates = token_index_candidates(&app, &[required]).unwrap();
        assert!(candidates.contains(&GossipObjectKey::new("widget", "object-a")));
    }

    #[test]
    fn engine_frame_is_prefix_scoped() {
        assert!(is_engine_frame(b"\0veilknit-gossip-engine-v1\0hello"));
        assert!(!is_engine_frame(b"ordinary app gossip"));
    }
}

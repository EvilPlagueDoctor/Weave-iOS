//! Local, persistent reputation service for public DHT identities.
//!
//! The subject of every reputation entry is a node's public DHT `RecordKey`.
//! Apps and core modules submit observations; only this service classifies a
//! node and resolves the effective local policy. Reputation data is never
//! exchanged with unrelated network nodes.
//!
//! Persistence is stored in the authenticated user's encrypted store through
//! `UserAuth`. The service is intentionally separate from `InternalNodeList`:
//! a reputation entry may outlive a discovered-node entry, and subscribers can
//! maintain a small local cache of the effective ban/restriction state.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{self, MissedTickBehavior};
use veilid_core::RecordKey;

use crate::types::current_timestamp;
use crate::user_auth::{AuthError, UserAuth, UserSession};

// ============================================================================
// Configuration defaults
// ============================================================================

/// Legacy monolithic key kept only for one-time migration from early builds.
pub const REPUTATION_STORE_KEY: &str = "reputation_state";
pub const REPUTATION_METADATA_KEY: &str = "reputation_metadata";
const REPUTATION_SHARD_KEY_PREFIX: &str = "reputation_shard";
const REPUTATION_STORE_VERSION: u32 = 1;
const REPUTATION_SHARD_COUNT: usize = 256;

pub const MAX_RECENT_OBSERVATIONS_PER_NODE: usize = 64;
pub const RECENT_OBSERVATION_MAX_AGE_SECS: u64 = 30 * 24 * 60 * 60;
pub const MAX_SUMMARY_ENTRIES: usize = 100_000;

/// This is a target rather than an unsafe hard cap. Entries that have not yet
/// reached an age where they are eligible for collection are never evicted
/// merely because a Sybil flood pushed the table past this number.
pub const MIN_GC_ELIGIBLE_AGE_SECS: u64 = 30 * 24 * 60 * 60;

pub const NORMAL_ENTRY_MAX_IDLE_SECS: u64 = 180 * 24 * 60 * 60;
pub const VALUABLE_ENTRY_MAX_IDLE_SECS: u64 = 365 * 24 * 60 * 60;
pub const SUSPICIOUS_ENTRY_MAX_IDLE_SECS: u64 = 365 * 24 * 60 * 60;
pub const APP_BAN_MAX_IDLE_SECS: u64 = 2 * 365 * 24 * 60 * 60;
pub const AUTOMATIC_BAN_MAX_IDLE_SECS: u64 = 5 * 365 * 24 * 60 * 60;

const AUTO_FLUSH_INTERVAL: Duration = Duration::from_secs(2);
const DEFAULT_COMMAND_BUFFER: usize = 256;
const DEFAULT_SUBSCRIPTION_BUFFER: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 512;

const CLASSIFIER_MODULE_NAME: &str = "reputation_classifier";

// ============================================================================
// Stable local authority identities
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppId(pub String);

impl AppId {
    pub fn new(value: impl Into<String>) -> Result<Self, ReputationError> {
        let value = value.into();
        let canonical = value.trim().to_ascii_lowercase();
        if canonical.is_empty()
            || canonical.len() > 256
            || canonical.chars().any(char::is_control)
            || canonical.chars().any(char::is_whitespace)
        {
            return Err(ReputationError::InvalidAppId);
        }
        Ok(Self(canonical))
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CoreModuleId(pub String);

impl CoreModuleId {
    pub fn new(value: impl Into<String>) -> Result<Self, ReputationError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 256 {
            return Err(ReputationError::InvalidModuleId);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for CoreModuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthorityId {
    User,
    CoreModule(CoreModuleId),
    App(AppId),
}

impl AuthorityId {
    fn is_app(&self) -> bool {
        matches!(self, Self::App(_))
    }
}

// ============================================================================
// Observations
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObservationId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObservationKind {
    // General interaction
    InteractionSucceeded,
    InteractionFailed,
    UsefulService,
    ExcessiveActivity,
    RepetitiveActivity,
    SuspiciousCoordination,

    // Messaging
    MessageDelivered,
    MessageRejected,
    UnsolicitedMessage,
    Spam,
    Harassment,

    // DHT/network correctness
    ValidDhtResponse,
    InvalidDhtResponse,
    InvalidSignature,
    ImpossibleProtocolState,
    MalformedProtocolMessage,
    DeliberateStateCorruption,
    FutureTimestampClaim,
    ConflictingAccountCreationClaim,
    SuspiciousCreationBurst,

    // Availability
    Reachable,
    Unreachable,
    StableAvailability,

    // Explicit application request. Prefer `request_ban` when a scope and
    // durable decision are needed; this category remains useful as evidence.
    AppBanRequested,

    // Direct user sentiment. User bans/allows should normally use the
    // decision/override APIs, while these can provide softer evidence.
    UserMarkedHarmful,
    UserMarkedTrusted,

    // Appended after all Patch-C variants to preserve bincode enum indexes.
    // Ordinary handshake unavailability is common and carries only a tiny
    // reliability cost with no suspicion/integrity implication.
    HandshakeUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservationDetails {
    pub application_code: Option<u32>,
    pub description: Option<String>,
}

impl ObservationDetails {
    fn validate(&self) -> Result<(), ReputationError> {
        if self
            .description
            .as_ref()
            .is_some_and(|text| text.len() > MAX_DESCRIPTION_BYTES)
        {
            return Err(ReputationError::DescriptionTooLong);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationInput {
    pub subject: RecordKey,
    pub kind: ObservationKind,
    pub details: ObservationDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSessionProvenance {
    pub session_id: String,
    pub credential_generation: u64,
    pub authenticated_at: u64,
}

#[derive(Debug, Clone)]
struct ObservationProvenance {
    authority: AuthorityId,
    app_session: Option<AppSessionProvenance>,
}

impl ObservationProvenance {
    fn authority(authority: AuthorityId) -> Self {
        Self {
            authority,
            app_session: None,
        }
    }

    fn app(app_id: AppId, app_session: AppSessionProvenance) -> Self {
        Self {
            authority: AuthorityId::App(app_id),
            app_session: Some(app_session),
        }
    }
}

/// One retained reputation observation. Source fields are private and are set
/// only by host-minted handles, making the source provenance immutable after
/// submission. Retraction changes whether evidence contributes to policy; it
/// never rewrites who originally supplied it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationObservation {
    pub id: ObservationId,
    pub subject: RecordKey,
    source: AuthorityId,
    pub kind: ObservationKind,
    pub details: ObservationDetails,
    pub observed_at: u64,
    retracted_at: Option<u64>,
    // Appended to the Patch-C persisted JSON layout so older stored observations
    // deserialize with a default while new observations retain session-level
    // provenance.
    #[serde(default)]
    app_session: Option<AppSessionProvenance>,
}

impl ReputationObservation {
    pub fn source(&self) -> &AuthorityId {
        &self.source
    }

    pub fn app_session(&self) -> Option<&AppSessionProvenance> {
        self.app_session.as_ref()
    }

    pub fn retracted_at(&self) -> Option<u64> {
        self.retracted_at
    }

    pub fn is_active(&self) -> bool {
        self.retracted_at.is_none()
    }
}

/// Compatibility alias for Patch B/C callers.
pub type StoredObservation = ReputationObservation;

// ============================================================================
// Classification, bans, decisions, and effective views
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReputationClass {
    New,
    NormalUser,
    GoodCitizen,
    ReliableServer,
    AutomatedBenign,
    SuspiciousAutomation,
    LikelySybil,
    Abusive,
    TamperedProtocol,
    NetworkBanned,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BanScope {
    App(AppId),
    AllApps,
    NetworkInteraction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionAction {
    Restrict,
    Ban,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecisionStatus {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DecisionId(pub u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationDecision {
    pub id: DecisionId,
    pub subject: RecordKey,
    pub source: AuthorityId,
    pub action: DecisionAction,

    /// Scope requested by the source.
    pub requested_scope: BanScope,

    /// Scope this local reputation service currently permits the decision to
    /// enforce. App requests are initially constrained to the requesting app.
    pub effective_scope: BanScope,

    pub reason: String,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub status: DecisionStatus,
    pub revoked_at: Option<u64>,
}

impl ReputationDecision {
    fn is_active_at(&self, now: u64) -> bool {
        self.status == DecisionStatus::Active
            && self.expires_at.is_none_or(|expiry| expiry > now)
    }

    fn is_permanent(&self) -> bool {
        self.expires_at.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserOverrideMode {
    /// Override automatic/app/module policy and allow interaction.
    Allow,

    /// Permit interaction but retain conservative local restrictions.
    AllowRestricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOverrideRecord {
    pub mode: UserOverrideMode,
    pub created_at: u64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessLevel {
    Allowed,
    Restricted,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReputationFlags(pub u32);

impl ReputationFlags {
    pub const NONE: Self = Self(0);
    pub const BANNED: Self = Self(1 << 0);
    pub const RESTRICTED: Self = Self(1 << 1);
    pub const CROSS_APP_CONCERN: Self = Self(1 << 2);
    pub const USER_OVERRIDE: Self = Self(1 << 3);
    pub const SUSPECTED_SYBIL: Self = Self(1 << 4);
    pub const AUTOMATED: Self = Self(1 << 5);
    pub const USEFUL_SERVER: Self = Self(1 << 6);
    pub const TAMPERED_PROTOCOL: Self = Self(1 << 7);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSummary {
    pub class: ReputationClass,
    pub confidence: u8,
    pub reliability: u8,
    pub usefulness: u8,
    pub suspicion: u8,
    pub automation_likelihood: u8,
    pub sybil_likelihood: u8,
    pub integrity_risk: u8,
    pub abuse_risk: u8,
    pub observation_count: u64,
    pub distinct_sources: u16,
    pub first_observed: u64,
    pub last_observed: u64,
    pub last_changed: u64,
    pub flags: ReputationFlags,
}

impl ReputationSummary {
    fn new(now: u64) -> Self {
        Self {
            class: ReputationClass::New,
            confidence: 0,
            reliability: 0,
            usefulness: 0,
            suspicion: 0,
            automation_likelihood: 0,
            sybil_likelihood: 0,
            integrity_risk: 0,
            abuse_risk: 0,
            observation_count: 0,
            distinct_sources: 0,
            first_observed: now,
            last_observed: now,
            last_changed: now,
            flags: ReputationFlags::NONE,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationView {
    pub subject: RecordKey,
    pub class: ReputationClass,
    pub confidence: u8,
    pub network_access: AccessLevel,
    pub app_access: Option<AccessLevel>,
    pub visibility_weight: u8,
    pub flags: ReputationFlags,
    pub last_observed: u64,
}

/// Small denormalized status suitable for caching beside a node-list entry.
/// Treat this only as a cache: subscription notices should keep it fresh, and
/// the reputation service remains authoritative.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationCacheHint {
    pub class: ReputationClass,
    pub network_access: AccessLevel,
    pub visibility_weight: u8,
    pub flags: ReputationFlags,
    pub updated_at: u64,
}

impl From<&ReputationView> for ReputationCacheHint {
    fn from(view: &ReputationView) -> Self {
        Self {
            class: view.class,
            network_access: view.network_access,
            visibility_weight: view.visibility_weight,
            flags: view.flags,
            updated_at: current_timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationDossier {
    pub subject: RecordKey,
    pub summary: ReputationSummary,
    pub recent_observations: Vec<ReputationObservation>,
    pub decisions: Vec<ReputationDecision>,
    pub user_override: Option<UserOverrideRecord>,
    pub historical_sources: Vec<HistoricalSourceSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSourceRetractionRecord {
    pub app_id: AppId,
    pub retracted_at: u64,
    pub active_observations_retracted: usize,
    pub historical_observations_retracted: u64,
    pub decisions_revoked: usize,
    pub affected_subjects: usize,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppHistoricalSubjectReport {
    pub subject: RecordKey,
    pub observation_count: u64,
    pub retracted_observation_count: u64,
    pub first_observed: u64,
    pub last_observed: u64,
    pub last_retracted_at: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSourceReport {
    pub app_id: AppId,
    pub active_recent_observations: usize,
    pub retracted_recent_observations: usize,
    pub compacted_historical_observations: u64,
    pub retracted_historical_observations: u64,
    pub active_decisions: usize,
    pub affected_subjects: usize,
    /// Full retained observations whose immutable provenance names this app.
    pub recent_observations: Vec<ReputationObservation>,
    /// Per-subject summaries for observations old enough to have been compacted.
    pub historical_subjects: Vec<AppHistoricalSubjectReport>,
    pub decisions: Vec<ReputationDecision>,
    pub retractions: Vec<AppSourceRetractionRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRetractionReport {
    pub app_id: AppId,
    pub active_observations_retracted: usize,
    pub historical_observations_retracted: u64,
    pub decisions_revoked: usize,
    pub affected_subjects: usize,
}

// ============================================================================
// Compact historical aggregates
// ============================================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
struct ScoreDelta {
    reliability: i64,
    usefulness: i64,
    suspicion: i64,
    automation: i64,
    sybil: i64,
    integrity: i64,
    abuse: i64,
    count: u64,
    impossible_protocol_events: u32,
    invalid_signature_events: u32,
    deliberate_corruption_events: u32,
}

impl ScoreDelta {
    fn add_assign(&mut self, rhs: Self) {
        self.reliability = self.reliability.saturating_add(rhs.reliability);
        self.usefulness = self.usefulness.saturating_add(rhs.usefulness);
        self.suspicion = self.suspicion.saturating_add(rhs.suspicion);
        self.automation = self.automation.saturating_add(rhs.automation);
        self.sybil = self.sybil.saturating_add(rhs.sybil);
        self.integrity = self.integrity.saturating_add(rhs.integrity);
        self.abuse = self.abuse.saturating_add(rhs.abuse);
        self.count = self.count.saturating_add(rhs.count);
        self.impossible_protocol_events = self
            .impossible_protocol_events
            .saturating_add(rhs.impossible_protocol_events);
        self.invalid_signature_events = self
            .invalid_signature_events
            .saturating_add(rhs.invalid_signature_events);
        self.deliberate_corruption_events = self
            .deliberate_corruption_events
            .saturating_add(rhs.deliberate_corruption_events);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HistoricalAggregate {
    /// Contributions that still participate in reputation calculation.
    totals: ScoreDelta,
    first_observed: u64,
    last_observed: u64,

    /// Provenance-preserving archive of contributions retracted by the user.
    /// New observations from the same source can accumulate in `totals`
    /// without reviving this archived influence.
    #[serde(default)]
    retracted_totals: ScoreDelta,
    #[serde(default)]
    retracted_first_observed: u64,
    #[serde(default)]
    retracted_last_observed: u64,
    #[serde(default)]
    last_retracted_at: Option<u64>,
}

impl HistoricalAggregate {
    fn retract_active(&mut self, retracted_at: u64) -> u64 {
        let count = self.totals.count;
        if count == 0 {
            return 0;
        }

        self.retracted_totals.add_assign(self.totals);
        if self.retracted_first_observed == 0 {
            self.retracted_first_observed = self.first_observed;
        } else if self.first_observed != 0 {
            self.retracted_first_observed = self
                .retracted_first_observed
                .min(self.first_observed);
        }
        self.retracted_last_observed = self
            .retracted_last_observed
            .max(self.last_observed);
        self.last_retracted_at = Some(retracted_at);

        self.totals = ScoreDelta::default();
        self.first_observed = 0;
        self.last_observed = 0;
        count
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalSourceSummary {
    pub source: AuthorityId,
    pub observation_count: u64,
    pub retracted_observation_count: u64,
    pub first_observed: u64,
    pub last_observed: u64,
    pub last_retracted_at: Option<u64>,
}

// JSON object keys must be strings, while AuthorityId is an enum. Persist this
// map as a sequence of key/value pairs so fresh, unscored peers cannot trigger
// a repeating persistence failure merely by creating an observation source.
mod authority_history_map {
    use super::{AuthorityId, HistoricalAggregate};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S>(
        value: &HashMap<AuthorityId, HistoricalAggregate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<(&AuthorityId, &HistoricalAggregate)> = value.iter().collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<AuthorityId, HistoricalAggregate>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<(AuthorityId, HistoricalAggregate)>::deserialize(deserializer)?;
        Ok(entries.into_iter().collect())
    }
}

// ============================================================================
// Persistent entry/store
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReputationEntry {
    subject: RecordKey,
    summary: ReputationSummary,
    recent_observations: VecDeque<StoredObservation>,
    #[serde(with = "authority_history_map")]
    historical_by_source: HashMap<AuthorityId, HistoricalAggregate>,
    decisions: Vec<ReputationDecision>,
    user_override: Option<UserOverrideRecord>,
    last_touched: u64,
}



impl ReputationEntry {
    fn new(subject: RecordKey, now: u64) -> Self {
        Self {
            subject,
            summary: ReputationSummary::new(now),
            recent_observations: VecDeque::new(),
            historical_by_source: HashMap::new(),
            decisions: Vec::new(),
            user_override: None,
            last_touched: now,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppSourcePolicy {
    Enabled,
    Ignored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReputationMetadata {
    version: u32,
    next_observation_id: u64,
    next_decision_id: u64,
    app_source_policies: HashMap<AppId, AppSourcePolicy>,
    #[serde(default)]
    app_source_retractions: Vec<AppSourceRetractionRecord>,
}

impl Default for ReputationMetadata {
    fn default() -> Self {
        Self {
            version: REPUTATION_STORE_VERSION,
            next_observation_id: 1,
            next_decision_id: 1,
            app_source_policies: HashMap::new(),
            app_source_retractions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReputationShard {
    entries: HashMap<String, ReputationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReputationStore {
    version: u32,
    next_observation_id: u64,
    next_decision_id: u64,
    entries: HashMap<String, ReputationEntry>,
    app_source_policies: HashMap<AppId, AppSourcePolicy>,
    #[serde(default)]
    app_source_retractions: Vec<AppSourceRetractionRecord>,
}

impl Default for ReputationStore {
    fn default() -> Self {
        Self {
            version: REPUTATION_STORE_VERSION,
            next_observation_id: 1,
            next_decision_id: 1,
            entries: HashMap::new(),
            app_source_policies: HashMap::new(),
            app_source_retractions: Vec::new(),
        }
    }
}

impl ReputationStore {
    fn app_source_enabled(&self, app_id: &AppId) -> bool {
        self.app_source_policies
            .get(app_id)
            .copied()
            .unwrap_or(AppSourcePolicy::Enabled)
            == AppSourcePolicy::Enabled
    }

    fn source_enabled(&self, source: &AuthorityId) -> bool {
        match source {
            AuthorityId::App(app_id) => self.app_source_enabled(app_id),
            AuthorityId::User | AuthorityId::CoreModule(_) => true,
        }
    }

    fn next_observation_id(&mut self) -> ObservationId {
        let id = ObservationId(self.next_observation_id);
        self.next_observation_id = self.next_observation_id.saturating_add(1).max(1);
        id
    }

    fn next_decision_id(&mut self) -> DecisionId {
        let id = DecisionId(self.next_decision_id);
        self.next_decision_id = self.next_decision_id.saturating_add(1).max(1);
        id
    }
}

fn reputation_shard_index(subject_key: &str) -> u8 {
    blake3::hash(subject_key.as_bytes()).as_bytes()[0]
}

fn reputation_shard_key(index: u8) -> String {
    format!("{REPUTATION_SHARD_KEY_PREFIX}_{index:02x}")
}

fn store_metadata(store: &ReputationStore) -> ReputationMetadata {
    ReputationMetadata {
        version: store.version,
        next_observation_id: store.next_observation_id,
        next_decision_id: store.next_decision_id,
        app_source_policies: store.app_source_policies.clone(),
        app_source_retractions: store.app_source_retractions.clone(),
    }
}

fn load_sharded_store(
    user_auth: &UserAuth,
    session: &UserSession,
) -> Result<(ReputationStore, bool), ReputationError> {
    // Prefer the sharded format whenever its metadata exists. The legacy
    // monolithic file may remain on disk after migration, so checking it first
    // would incorrectly resurrect stale data on every later startup.
    if let Some(metadata) = user_auth
        .read_user_encrypted::<ReputationMetadata>(session, REPUTATION_METADATA_KEY)?
    {
        if metadata.version != REPUTATION_STORE_VERSION {
            return Err(ReputationError::StoreVersionUnsupported(metadata.version));
        }

        let mut entries = HashMap::new();
        for index in 0..REPUTATION_SHARD_COUNT {
            let key = reputation_shard_key(index as u8);
            if let Some(shard) =
                user_auth.read_user_encrypted::<ReputationShard>(session, &key)?
            {
                entries.extend(shard.entries);
            }
        }

        return Ok((
            ReputationStore {
                version: metadata.version,
                next_observation_id: metadata.next_observation_id.max(1),
                next_decision_id: metadata.next_decision_id.max(1),
                entries,
                app_source_policies: metadata.app_source_policies,
                app_source_retractions: metadata.app_source_retractions,
            },
            false,
        ));
    }

    // One-time compatibility path for the first monolithic implementation.
    if let Some(store) =
        user_auth.read_user_encrypted::<ReputationStore>(session, REPUTATION_STORE_KEY)?
    {
        if store.version != REPUTATION_STORE_VERSION {
            return Err(ReputationError::StoreVersionUnsupported(store.version));
        }
        return Ok((store, true));
    }

    Ok((ReputationStore::default(), false))
}

// ============================================================================
// Subscription API
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationEventKind {
    SummaryChanged,
    RestrictionChanged,
    BanApplied,
    BanRemoved,
    UserOverrideChanged,
    SourcePolicyChanged,
    EvidenceRetracted,
    EntryRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationEventMask(pub u32);

impl ReputationEventMask {
    pub const SUMMARY_CHANGED: Self = Self(1 << 0);
    pub const RESTRICTION_CHANGED: Self = Self(1 << 1);
    pub const BAN_APPLIED: Self = Self(1 << 2);
    pub const BAN_REMOVED: Self = Self(1 << 3);
    pub const USER_OVERRIDE_CHANGED: Self = Self(1 << 4);
    pub const SOURCE_POLICY_CHANGED: Self = Self(1 << 5);
    pub const EVIDENCE_RETRACTED: Self = Self(1 << 6);
    pub const ENTRY_REMOVED: Self = Self(1 << 7);
    pub const ALL: Self = Self(u32::MAX);

    fn contains(self, kind: ReputationEventKind) -> bool {
        let bit = match kind {
            ReputationEventKind::SummaryChanged => Self::SUMMARY_CHANGED.0,
            ReputationEventKind::RestrictionChanged => Self::RESTRICTION_CHANGED.0,
            ReputationEventKind::BanApplied => Self::BAN_APPLIED.0,
            ReputationEventKind::BanRemoved => Self::BAN_REMOVED.0,
            ReputationEventKind::UserOverrideChanged => Self::USER_OVERRIDE_CHANGED.0,
            ReputationEventKind::SourcePolicyChanged => Self::SOURCE_POLICY_CHANGED.0,
            ReputationEventKind::EvidenceRetracted => Self::EVIDENCE_RETRACTED.0,
            ReputationEventKind::EntryRemoved => Self::ENTRY_REMOVED.0,
        };
        self.0 & bit != 0
    }
}

#[derive(Debug, Clone)]
pub struct SubscriptionFilter {
    pub subjects: Option<Vec<RecordKey>>,
    pub events: ReputationEventMask,
    pub minimum_suspicion: Option<u8>,
}

impl Default for SubscriptionFilter {
    fn default() -> Self {
        Self {
            subjects: None,
            events: ReputationEventMask::ALL,
            minimum_suspicion: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReputationNotice {
    pub kind: ReputationEventKind,
    pub subject: RecordKey,
    pub view: Option<ReputationView>,
}

pub struct ReputationSubscription {
    rx: mpsc::Receiver<ReputationNotice>,
}

impl ReputationSubscription {
    pub async fn recv(&mut self) -> Option<ReputationNotice> {
        self.rx.recv().await
    }
}

struct Subscriber {
    subjects: Option<HashSet<String>>,
    events: ReputationEventMask,
    minimum_suspicion: Option<u8>,
    app_context: Option<AppId>,
    tx: mpsc::Sender<ReputationNotice>,
}

// ============================================================================
// Public errors
// ============================================================================

#[derive(Debug)]
pub enum ReputationError {
    ChannelClosed,
    InvalidAppId,
    InvalidModuleId,
    DescriptionTooLong,
    ReasonTooLong,
    InvalidExpiry,
    PermissionDenied,
    EntryNotFound,
    ObservationNotFoundOrCompacted,
    DecisionNotFound,
    StoreVersionUnsupported(u32),
    Persistence(String),
}

impl fmt::Display for ReputationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelClosed => write!(f, "reputation service channel closed"),
            Self::InvalidAppId => write!(f, "invalid app id"),
            Self::InvalidModuleId => write!(f, "invalid core-module id"),
            Self::DescriptionTooLong => write!(f, "observation description is too long"),
            Self::ReasonTooLong => write!(f, "decision reason is too long"),
            Self::InvalidExpiry => write!(f, "decision expiry must be in the future"),
            Self::PermissionDenied => write!(f, "operation is not permitted for this authority"),
            Self::EntryNotFound => write!(f, "reputation entry not found"),
            Self::ObservationNotFoundOrCompacted => write!(
                f,
                "observation was not found or has already been compacted into historical data"
            ),
            Self::DecisionNotFound => write!(f, "reputation decision not found"),
            Self::StoreVersionUnsupported(version) => {
                write!(f, "unsupported reputation store version {version}")
            }
            Self::Persistence(message) => write!(f, "reputation persistence error: {message}"),
        }
    }
}

impl std::error::Error for ReputationError {}

impl From<AuthError> for ReputationError {
    fn from(value: AuthError) -> Self {
        Self::Persistence(value.to_string())
    }
}

// ============================================================================
// Commands and public handles
// ============================================================================

enum ReputationCommand {
    SubmitObservation {
        source: ObservationProvenance,
        input: ObservationInput,
        reply: oneshot::Sender<Result<ObservationId, ReputationError>>,
    },
    RetractOwnObservation {
        source: AuthorityId,
        subject: RecordKey,
        observation_id: ObservationId,
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    RetractAnyObservation {
        subject: RecordKey,
        observation_id: ObservationId,
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    RequestDecision {
        source: AuthorityId,
        subject: RecordKey,
        action: DecisionAction,
        scope: BanScope,
        reason: String,
        expires_at: Option<u64>,
        reply: oneshot::Sender<Result<DecisionId, ReputationError>>,
    },
    RevokeOwnDecision {
        source: AuthorityId,
        subject: RecordKey,
        decision_id: DecisionId,
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    RevokeAnyDecision {
        subject: RecordKey,
        decision_id: DecisionId,
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    SetUserOverride {
        subject: RecordKey,
        mode: UserOverrideMode,
        note: Option<String>,
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    ClearUserOverride {
        subject: RecordKey,
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    GetView {
        subject: RecordKey,
        app_context: Option<AppId>,
        reply: oneshot::Sender<Result<ReputationView, ReputationError>>,
    },
    GetDossier {
        subject: RecordKey,
        reply: oneshot::Sender<Result<ReputationDossier, ReputationError>>,
    },
    GetDiagnosticReport {
        subject: RecordKey,
        reply: oneshot::Sender<Result<String, ReputationError>>,
    },
    GetAppSourceReport {
        app_id: AppId,
        reply: oneshot::Sender<Result<AppSourceReport, ReputationError>>,
    },
    RetractAppSource {
        app_id: AppId,
        reason: String,
        reply: oneshot::Sender<Result<AppRetractionReport, ReputationError>>,
    },
    Subscribe {
        app_context: Option<AppId>,
        filter: SubscriptionFilter,
        reply: oneshot::Sender<Result<ReputationSubscription, ReputationError>>,
    },
    SetAppSourcePolicy {
        app_id: AppId,
        policy: AppSourcePolicy,
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    DeleteAppSourceData {
        app_id: AppId,
        reply: oneshot::Sender<Result<usize, ReputationError>>,
    },
    RunGarbageCollection {
        reply: oneshot::Sender<Result<usize, ReputationError>>,
    },
    Flush {
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), ReputationError>>,
    },
}

#[derive(Clone)]
pub struct ReputationManager {
    tx: mpsc::Sender<ReputationCommand>,
}

impl ReputationManager {
    /// Load the encrypted reputation store and start the actor.
    pub fn spawn(
        user_auth: Arc<UserAuth>,
        session: Arc<UserSession>,
    ) -> Result<Self, ReputationError> {
        let (store, migrate_monolithic_store) =
            load_sharded_store(&user_auth, &session)?;

        let (tx, rx) = mpsc::channel(DEFAULT_COMMAND_BUFFER);
        tokio::spawn(reputation_task(
            rx,
            user_auth,
            session,
            store,
            migrate_monolithic_store,
        ));
        Ok(Self { tx })
    }

    pub fn user_handle(&self) -> ReputationUserHandle {
        ReputationUserHandle {
            tx: self.tx.clone(),
        }
    }

    /// Mint an app-bound handle only from an `AuthenticatedAppSession`.
    /// `pub(crate)` prevents plugins/API callers from claiming an arbitrary
    /// app id and fabricating observation provenance.
    pub(crate) fn authenticated_app_handle_with_session(
        &self,
        app_id: AppId,
        session_id: String,
        credential_generation: u64,
        authenticated_at: u64,
    ) -> ReputationAppHandle {
        ReputationAppHandle {
            provenance: ObservationProvenance::app(
                app_id,
                AppSessionProvenance {
                    session_id,
                    credential_generation,
                    authenticated_at,
                },
            ),
            tx: self.tx.clone(),
        }
    }

    /// TEMPORARY TRUSTED-PROCESS API. A caller with a ReputationManager can
    /// currently claim any module id; do not expose this across an app/plugin
    /// boundary until the permanent capability authority is implemented.
    pub fn core_module_handle(&self, module_id: CoreModuleId) -> ReputationModuleHandle {
        ReputationModuleHandle {
            module_id,
            tx: self.tx.clone(),
        }
    }

    pub async fn shutdown(&self) -> Result<(), ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::Shutdown { reply: reply_tx })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }
}

#[derive(Clone)]
pub struct ReputationAppHandle {
    provenance: ObservationProvenance,
    tx: mpsc::Sender<ReputationCommand>,
}

impl ReputationAppHandle {
    pub fn app_id(&self) -> &AppId {
        match &self.provenance.authority {
            AuthorityId::App(app_id) => app_id,
            _ => unreachable!("ReputationAppHandle must contain app provenance"),
        }
    }

    pub async fn submit_observation(
        &self,
        input: ObservationInput,
    ) -> Result<ObservationId, ReputationError> {
        send_observation(&self.tx, self.provenance.clone(), input).await
    }

    pub async fn retract_observation(
        &self,
        subject: RecordKey,
        observation_id: ObservationId,
    ) -> Result<(), ReputationError> {
        retract_own_observation(
            &self.tx,
            AuthorityId::App(self.app_id().clone()),
            subject,
            observation_id,
        )
        .await
    }

    pub async fn request_ban(
        &self,
        subject: RecordKey,
        scope: BanScope,
        reason: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Result<DecisionId, ReputationError> {
        request_decision(
            &self.tx,
            AuthorityId::App(self.app_id().clone()),
            subject,
            DecisionAction::Ban,
            scope,
            reason.into(),
            expires_at,
        )
        .await
    }

    pub async fn request_restriction(
        &self,
        subject: RecordKey,
        scope: BanScope,
        reason: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Result<DecisionId, ReputationError> {
        request_decision(
            &self.tx,
            AuthorityId::App(self.app_id().clone()),
            subject,
            DecisionAction::Restrict,
            scope,
            reason.into(),
            expires_at,
        )
        .await
    }

    pub async fn revoke_decision(
        &self,
        subject: RecordKey,
        decision_id: DecisionId,
    ) -> Result<(), ReputationError> {
        revoke_own_decision(
            &self.tx,
            AuthorityId::App(self.app_id().clone()),
            subject,
            decision_id,
        )
        .await
    }

    pub async fn get_view(&self, subject: RecordKey) -> Result<ReputationView, ReputationError> {
        get_view(&self.tx, subject, Some(self.app_id().clone())).await
    }

    pub async fn subscribe(
        &self,
        filter: SubscriptionFilter,
    ) -> Result<ReputationSubscription, ReputationError> {
        subscribe(&self.tx, Some(self.app_id().clone()), filter).await
    }

    pub async fn get_own_source_report(&self) -> Result<AppSourceReport, ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::GetAppSourceReport {
                app_id: self.app_id().clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }
}

#[derive(Clone)]
pub struct ReputationModuleHandle {
    module_id: CoreModuleId,
    tx: mpsc::Sender<ReputationCommand>,
}

impl ReputationModuleHandle {
    pub fn module_id(&self) -> &CoreModuleId {
        &self.module_id
    }

    pub async fn submit_observation(
        &self,
        input: ObservationInput,
    ) -> Result<ObservationId, ReputationError> {
        send_observation(
            &self.tx,
            ObservationProvenance::authority(AuthorityId::CoreModule(self.module_id.clone())),
            input,
        )
        .await
    }

    pub async fn retract_observation(
        &self,
        subject: RecordKey,
        observation_id: ObservationId,
    ) -> Result<(), ReputationError> {
        retract_own_observation(
            &self.tx,
            AuthorityId::CoreModule(self.module_id.clone()),
            subject,
            observation_id,
        )
        .await
    }

    pub async fn request_ban(
        &self,
        subject: RecordKey,
        scope: BanScope,
        reason: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Result<DecisionId, ReputationError> {
        request_decision(
            &self.tx,
            AuthorityId::CoreModule(self.module_id.clone()),
            subject,
            DecisionAction::Ban,
            scope,
            reason.into(),
            expires_at,
        )
        .await
    }

    pub async fn request_restriction(
        &self,
        subject: RecordKey,
        scope: BanScope,
        reason: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Result<DecisionId, ReputationError> {
        request_decision(
            &self.tx,
            AuthorityId::CoreModule(self.module_id.clone()),
            subject,
            DecisionAction::Restrict,
            scope,
            reason.into(),
            expires_at,
        )
        .await
    }

    pub async fn revoke_decision(
        &self,
        subject: RecordKey,
        decision_id: DecisionId,
    ) -> Result<(), ReputationError> {
        revoke_own_decision(
            &self.tx,
            AuthorityId::CoreModule(self.module_id.clone()),
            subject,
            decision_id,
        )
        .await
    }

    pub async fn get_view(&self, subject: RecordKey) -> Result<ReputationView, ReputationError> {
        get_view(&self.tx, subject, None).await
    }

    /// Produce a human-readable, read-only explanation of the reputation
    /// state for one peer. This is intended for daemon diagnostics rather
    /// than policy decisions: callers must continue to use `get_view()` as
    /// the authoritative access check.
    pub async fn get_diagnostic_report(
        &self,
        subject: RecordKey,
    ) -> Result<String, ReputationError> {
        get_diagnostic_report(&self.tx, subject).await
    }

    pub async fn subscribe(
        &self,
        filter: SubscriptionFilter,
    ) -> Result<ReputationSubscription, ReputationError> {
        subscribe(&self.tx, None, filter).await
    }
}

#[derive(Clone)]
pub struct ReputationUserHandle {
    tx: mpsc::Sender<ReputationCommand>,
}

impl ReputationUserHandle {
    pub async fn submit_observation(
        &self,
        input: ObservationInput,
    ) -> Result<ObservationId, ReputationError> {
        send_observation(
            &self.tx,
            ObservationProvenance::authority(AuthorityId::User),
            input,
        )
        .await
    }

    pub async fn retract_observation(
        &self,
        subject: RecordKey,
        observation_id: ObservationId,
    ) -> Result<(), ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::RetractAnyObservation {
                subject,
                observation_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    pub async fn ban(
        &self,
        subject: RecordKey,
        scope: BanScope,
        reason: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Result<DecisionId, ReputationError> {
        request_decision(
            &self.tx,
            AuthorityId::User,
            subject,
            DecisionAction::Ban,
            scope,
            reason.into(),
            expires_at,
        )
        .await
    }

    pub async fn restrict(
        &self,
        subject: RecordKey,
        scope: BanScope,
        reason: impl Into<String>,
        expires_at: Option<u64>,
    ) -> Result<DecisionId, ReputationError> {
        request_decision(
            &self.tx,
            AuthorityId::User,
            subject,
            DecisionAction::Restrict,
            scope,
            reason.into(),
            expires_at,
        )
        .await
    }

    pub async fn revoke_decision(
        &self,
        subject: RecordKey,
        decision_id: DecisionId,
    ) -> Result<(), ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::RevokeAnyDecision {
                subject,
                decision_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    pub async fn set_override(
        &self,
        subject: RecordKey,
        mode: UserOverrideMode,
        note: Option<String>,
    ) -> Result<(), ReputationError> {
        if note.as_ref().is_some_and(|text| text.len() > MAX_DESCRIPTION_BYTES) {
            return Err(ReputationError::DescriptionTooLong);
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::SetUserOverride {
                subject,
                mode,
                note,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    pub async fn clear_override(&self, subject: RecordKey) -> Result<(), ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::ClearUserOverride {
                subject,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    pub async fn get_view(
        &self,
        subject: RecordKey,
        app_context: Option<AppId>,
    ) -> Result<ReputationView, ReputationError> {
        get_view(&self.tx, subject, app_context).await
    }

    pub async fn get_dossier(
        &self,
        subject: RecordKey,
    ) -> Result<ReputationDossier, ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::GetDossier {
                subject,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    /// Produce the same detailed read-only explanation used by automatic
    /// handshake diagnostics, but under explicit local-user control. This is
    /// intentionally separate from policy mutation APIs: asking for an
    /// explanation never changes reputation state.
    pub async fn get_diagnostic_report(
        &self,
        subject: RecordKey,
    ) -> Result<String, ReputationError> {
        get_diagnostic_report(&self.tx, subject).await
    }

    pub async fn subscribe(
        &self,
        filter: SubscriptionFilter,
        app_context: Option<AppId>,
    ) -> Result<ReputationSubscription, ReputationError> {
        subscribe(&self.tx, app_context, filter).await
    }

    pub async fn set_app_source_policy(
        &self,
        app_id: AppId,
        policy: AppSourcePolicy,
    ) -> Result<(), ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::SetAppSourcePolicy {
                app_id,
                policy,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    /// Legacy API name. To preserve immutable provenance, this retracts the
    /// app's influence rather than physically deleting its source history.
    pub async fn delete_app_source_data(
        &self,
        app_id: AppId,
    ) -> Result<usize, ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::DeleteAppSourceData {
                app_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    pub async fn get_app_source_report(
        &self,
        app_id: AppId,
    ) -> Result<AppSourceReport, ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::GetAppSourceReport {
                app_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    /// Remove one app's influence without rewriting or physically deleting the
    /// source history. Recent observations are marked retracted, compacted
    /// aggregates are archived outside scoring, and app decisions are revoked.
    pub async fn retract_app_source(
        &self,
        app_id: AppId,
        reason: impl Into<String>,
    ) -> Result<AppRetractionReport, ReputationError> {
        let reason = reason.into();
        if reason.len() > MAX_DESCRIPTION_BYTES {
            return Err(ReputationError::ReasonTooLong);
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::RetractAppSource {
                app_id,
                reason,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    pub async fn run_garbage_collection(&self) -> Result<usize, ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::RunGarbageCollection { reply: reply_tx })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }

    pub async fn flush(&self) -> Result<(), ReputationError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ReputationCommand::Flush { reply: reply_tx })
            .await
            .map_err(|_| ReputationError::ChannelClosed)?;
        reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
    }
}

async fn send_observation(
    tx: &mpsc::Sender<ReputationCommand>,
    source: ObservationProvenance,
    input: ObservationInput,
) -> Result<ObservationId, ReputationError> {
    input.details.validate()?;
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(ReputationCommand::SubmitObservation {
        source,
        input,
        reply: reply_tx,
    })
    .await
    .map_err(|_| ReputationError::ChannelClosed)?;
    reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
}

async fn retract_own_observation(
    tx: &mpsc::Sender<ReputationCommand>,
    source: AuthorityId,
    subject: RecordKey,
    observation_id: ObservationId,
) -> Result<(), ReputationError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(ReputationCommand::RetractOwnObservation {
        source,
        subject,
        observation_id,
        reply: reply_tx,
    })
    .await
    .map_err(|_| ReputationError::ChannelClosed)?;
    reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
}

async fn request_decision(
    tx: &mpsc::Sender<ReputationCommand>,
    source: AuthorityId,
    subject: RecordKey,
    action: DecisionAction,
    scope: BanScope,
    reason: String,
    expires_at: Option<u64>,
) -> Result<DecisionId, ReputationError> {
    if reason.len() > MAX_DESCRIPTION_BYTES {
        return Err(ReputationError::ReasonTooLong);
    }
    if expires_at.is_some_and(|expiry| expiry <= current_timestamp()) {
        return Err(ReputationError::InvalidExpiry);
    }

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(ReputationCommand::RequestDecision {
        source,
        subject,
        action,
        scope,
        reason,
        expires_at,
        reply: reply_tx,
    })
    .await
    .map_err(|_| ReputationError::ChannelClosed)?;
    reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
}

async fn revoke_own_decision(
    tx: &mpsc::Sender<ReputationCommand>,
    source: AuthorityId,
    subject: RecordKey,
    decision_id: DecisionId,
) -> Result<(), ReputationError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(ReputationCommand::RevokeOwnDecision {
        source,
        subject,
        decision_id,
        reply: reply_tx,
    })
    .await
    .map_err(|_| ReputationError::ChannelClosed)?;
    reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
}

async fn get_view(
    tx: &mpsc::Sender<ReputationCommand>,
    subject: RecordKey,
    app_context: Option<AppId>,
) -> Result<ReputationView, ReputationError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(ReputationCommand::GetView {
        subject,
        app_context,
        reply: reply_tx,
    })
    .await
    .map_err(|_| ReputationError::ChannelClosed)?;
    reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
}

async fn get_diagnostic_report(
    tx: &mpsc::Sender<ReputationCommand>,
    subject: RecordKey,
) -> Result<String, ReputationError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(ReputationCommand::GetDiagnosticReport {
        subject,
        reply: reply_tx,
    })
    .await
    .map_err(|_| ReputationError::ChannelClosed)?;
    reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
}

async fn subscribe(
    tx: &mpsc::Sender<ReputationCommand>,
    app_context: Option<AppId>,
    filter: SubscriptionFilter,
) -> Result<ReputationSubscription, ReputationError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(ReputationCommand::Subscribe {
        app_context,
        filter,
        reply: reply_tx,
    })
    .await
    .map_err(|_| ReputationError::ChannelClosed)?;
    reply_rx.await.map_err(|_| ReputationError::ChannelClosed)?
}

// ============================================================================
// Background task
// ============================================================================

struct RuntimeState {
    store: ReputationStore,
    subscribers: Vec<Subscriber>,
    dirty_metadata: bool,
    dirty_shards: HashSet<u8>,

    /// A deterministic serialization failure should not fill the log every two
    /// seconds. Dirty state remains retained, but periodic retries are backed
    /// off and identical errors are logged only once until the condition
    /// changes or persistence succeeds.
    periodic_persist_retry_after: u64,
    last_periodic_persist_error: Option<String>,
}

impl RuntimeState {
    fn mark_subject_dirty(&mut self, subject: &RecordKey) {
        self.dirty_shards
            .insert(reputation_shard_index(&subject.to_string()));
    }

    fn mark_subject_key_dirty(&mut self, subject_key: &str) {
        self.dirty_shards
            .insert(reputation_shard_index(subject_key));
    }

    fn mark_metadata_dirty(&mut self) {
        self.dirty_metadata = true;
    }

    fn mark_all_shards_dirty(&mut self) {
        self.dirty_shards
            .extend((0..REPUTATION_SHARD_COUNT).map(|index| index as u8));
    }
}

async fn reputation_task(
    mut rx: mpsc::Receiver<ReputationCommand>,
    user_auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    mut store: ReputationStore,
    migrate_monolithic_store: bool,
) {
    let now = current_timestamp();
    repair_loaded_store(&mut store, now);

    let mut state = RuntimeState {
        store,
        subscribers: Vec::new(),
        dirty_metadata: migrate_monolithic_store,
        dirty_shards: HashSet::new(),
        periodic_persist_retry_after: 0,
        last_periodic_persist_error: None,
    };
    if migrate_monolithic_store {
        state.mark_all_shards_dirty();
    }

    let mut flush_interval = time::interval(AUTO_FLUSH_INTERVAL);
    flush_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Consume the immediate first tick so routine observations are not written
    // twice at startup.
    flush_interval.tick().await;

    loop {
        tokio::select! {
            maybe_command = rx.recv() => {
                let Some(command) = maybe_command else {
                    let _ = persist_if_dirty(&user_auth, &session, &mut state);
                    break;
                };

                let should_exit = handle_command(
                    command,
                    &user_auth,
                    &session,
                    &mut state,
                );

                if should_exit {
                    break;
                }
            }
            _ = flush_interval.tick() => {
                let now = current_timestamp();
                if now < state.periodic_persist_retry_after {
                    continue;
                }

                match persist_if_dirty(&user_auth, &session, &mut state) {
                    Ok(()) => {
                        state.periodic_persist_retry_after = 0;
                        state.last_periodic_persist_error = None;
                    }
                    Err(error) => {
                        let message = error.to_string();
                        if state.last_periodic_persist_error.as_deref() != Some(message.as_str()) {
                            crate::teprintln!("[reputation] periodic persistence failed: {message}");
                        }
                        state.last_periodic_persist_error = Some(message);
                        state.periodic_persist_retry_after = now.saturating_add(60);
                    }
                }
            }
        }
    }
}

fn handle_command(
    command: ReputationCommand,
    user_auth: &UserAuth,
    session: &UserSession,
    state: &mut RuntimeState,
) -> bool {
    match command {
        ReputationCommand::SubmitObservation { source, input, reply } => {
            let result = submit_observation(state, source, input).and_then(|outcome| {
                if outcome.automatic_ban_added {
                    persist_if_dirty(user_auth, session, state)?;
                }
                Ok(outcome.id)
            });
            let _ = reply.send(result);
        }
        ReputationCommand::RetractOwnObservation {
            source,
            subject,
            observation_id,
            reply,
        } => {
            let result = retract_observation(state, &subject, observation_id, Some(&source))
                .and_then(|_| persist_if_dirty(user_auth, session, state));
            let _ = reply.send(result);
        }
        ReputationCommand::RetractAnyObservation {
            subject,
            observation_id,
            reply,
        } => {
            let result = retract_observation(state, &subject, observation_id, None)
                .and_then(|_| persist_if_dirty(user_auth, session, state));
            let _ = reply.send(result);
        }
        ReputationCommand::RequestDecision {
            source,
            subject,
            action,
            scope,
            reason,
            expires_at,
            reply,
        } => {
            let result = create_decision(
                state,
                source,
                subject,
                action,
                scope,
                reason,
                expires_at,
            )
            .and_then(|id| {
                persist_if_dirty(user_auth, session, state)?;
                Ok(id)
            });
            let _ = reply.send(result);
        }
        ReputationCommand::RevokeOwnDecision {
            source,
            subject,
            decision_id,
            reply,
        } => {
            let result = revoke_decision(state, &subject, decision_id, Some(&source))
                .and_then(|_| persist_if_dirty(user_auth, session, state));
            let _ = reply.send(result);
        }
        ReputationCommand::RevokeAnyDecision {
            subject,
            decision_id,
            reply,
        } => {
            let result = revoke_decision(state, &subject, decision_id, None)
                .and_then(|_| persist_if_dirty(user_auth, session, state));
            let _ = reply.send(result);
        }
        ReputationCommand::SetUserOverride {
            subject,
            mode,
            note,
            reply,
        } => {
            let result = set_user_override(state, subject, mode, note)
                .and_then(|_| persist_if_dirty(user_auth, session, state));
            let _ = reply.send(result);
        }
        ReputationCommand::ClearUserOverride { subject, reply } => {
            let result = clear_user_override(state, &subject)
                .and_then(|_| persist_if_dirty(user_auth, session, state));
            let _ = reply.send(result);
        }
        ReputationCommand::GetView {
            subject,
            app_context,
            reply,
        } => {
            let result = build_view(&state.store, &subject, app_context.as_ref());
            let _ = reply.send(result);
        }
        ReputationCommand::GetDossier { subject, reply } => {
            let result = build_dossier(&state.store, &subject);
            let _ = reply.send(result);
        }
        ReputationCommand::GetDiagnosticReport { subject, reply } => {
            let result = build_diagnostic_report(&state.store, &subject);
            let _ = reply.send(result);
        }
        ReputationCommand::GetAppSourceReport { app_id, reply } => {
            let _ = reply.send(Ok(get_app_source_report(state, &app_id)));
        }
        ReputationCommand::RetractAppSource {
            app_id,
            reason,
            reply,
        } => {
            let result = retract_app_source(state, app_id, reason).and_then(|report| {
                persist_if_dirty(user_auth, session, state)?;
                Ok(report)
            });
            let _ = reply.send(result);
        }
        ReputationCommand::Subscribe {
            app_context,
            filter,
            reply,
        } => {
            let subjects = filter.subjects.map(|items| {
                items
                    .into_iter()
                    .map(|record_key| record_key.to_string())
                    .collect()
            });
            let (tx, rx) = mpsc::channel(DEFAULT_SUBSCRIPTION_BUFFER);
            state.subscribers.push(Subscriber {
                subjects,
                events: filter.events,
                minimum_suspicion: filter.minimum_suspicion,
                app_context,
                tx,
            });
            let _ = reply.send(Ok(ReputationSubscription { rx }));
        }
        ReputationCommand::SetAppSourcePolicy {
            app_id,
            policy,
            reply,
        } => {
            let result = set_app_source_policy(state, app_id, policy)
                .and_then(|_| persist_if_dirty(user_auth, session, state));
            let _ = reply.send(result);
        }
        ReputationCommand::DeleteAppSourceData { app_id, reply } => {
            let result = delete_app_source_data(state, &app_id).and_then(|count| {
                persist_if_dirty(user_auth, session, state)?;
                Ok(count)
            });
            let _ = reply.send(result);
        }
        ReputationCommand::RunGarbageCollection { reply } => {
            let removed = run_garbage_collection(state, current_timestamp());
            let result = persist_if_dirty(user_auth, session, state).map(|_| removed);
            let _ = reply.send(result);
        }
        ReputationCommand::Flush { reply } => {
            let _ = reply.send(persist_if_dirty(user_auth, session, state));
        }
        ReputationCommand::Shutdown { reply } => {
            let result = persist_if_dirty(user_auth, session, state);
            let _ = reply.send(result);
            return true;
        }
    }

    false
}

// ============================================================================
// Mutation helpers
// ============================================================================

struct SubmitOutcome {
    id: ObservationId,
    automatic_ban_added: bool,
}

fn submit_observation(
    state: &mut RuntimeState,
    provenance: ObservationProvenance,
    input: ObservationInput,
) -> Result<SubmitOutcome, ReputationError> {
    input.details.validate()?;
    let now = current_timestamp();
    let id = state.store.next_observation_id();
    let key = input.subject.to_string();

    let entry = state
        .store
        .entries
        .entry(key)
        .or_insert_with(|| ReputationEntry::new(input.subject.clone(), now));

    let ObservationProvenance {
        authority,
        app_session,
    } = provenance;

    compact_recent_observations(entry, now);
    compact_source_observation_quota(entry, &authority);

    while entry.recent_observations.len() >= MAX_RECENT_OBSERVATIONS_PER_NODE {
        if let Some(old) = entry.recent_observations.pop_front() {
            fold_observation(entry, old);
        }
    }

    entry.recent_observations.push_back(ReputationObservation {
        id,
        subject: input.subject.clone(),
        source: authority,
        app_session,
        kind: input.kind,
        details: input.details,
        observed_at: now,
        retracted_at: None,
    });
    entry.last_touched = now;

    let automatic_ban_added =
        ensure_automatic_integrity_ban(&mut state.store, &input.subject, now);
    recompute_subject(&mut state.store, &input.subject, now);
    state.mark_subject_dirty(&input.subject);
    state.mark_metadata_dirty();
    emit_notice(
        state,
        &input.subject,
        ReputationEventKind::SummaryChanged,
    );
    if automatic_ban_added {
        emit_notice(state, &input.subject, ReputationEventKind::BanApplied);
    }

    Ok(SubmitOutcome {
        id,
        automatic_ban_added,
    })
}

fn retract_observation(
    state: &mut RuntimeState,
    subject: &RecordKey,
    observation_id: ObservationId,
    required_source: Option<&AuthorityId>,
) -> Result<(), ReputationError> {
    let now = current_timestamp();
    let key = subject.to_string();
    let entry = state
        .store
        .entries
        .get_mut(&key)
        .ok_or(ReputationError::EntryNotFound)?;

    let observation = entry
        .recent_observations
        .iter_mut()
        .find(|observation| observation.id == observation_id)
        .ok_or(ReputationError::ObservationNotFoundOrCompacted)?;

    if required_source.is_some_and(|source| source != &observation.source) {
        return Err(ReputationError::PermissionDenied);
    }

    observation.retracted_at = Some(now);
    entry.last_touched = now;
    recompute_subject(&mut state.store, subject, now);
    state.mark_subject_dirty(subject);
    emit_notice(state, subject, ReputationEventKind::EvidenceRetracted);
    Ok(())
}

fn create_decision(
    state: &mut RuntimeState,
    source: AuthorityId,
    subject: RecordKey,
    action: DecisionAction,
    requested_scope: BanScope,
    reason: String,
    expires_at: Option<u64>,
) -> Result<DecisionId, ReputationError> {
    if reason.len() > MAX_DESCRIPTION_BYTES {
        return Err(ReputationError::ReasonTooLong);
    }

    let now = current_timestamp();
    if expires_at.is_some_and(|expiry| expiry <= now) {
        return Err(ReputationError::InvalidExpiry);
    }

    validate_scope_for_source(&source, &requested_scope)?;
    let effective_scope = effective_scope_for_source(&source, &requested_scope);
    let id = state.store.next_decision_id();
    let key = subject.to_string();
    let entry = state
        .store
        .entries
        .entry(key)
        .or_insert_with(|| ReputationEntry::new(subject.clone(), now));

    entry.decisions.push(ReputationDecision {
        id,
        subject: subject.clone(),
        source,
        action,
        requested_scope,
        effective_scope,
        reason,
        created_at: now,
        expires_at,
        status: DecisionStatus::Active,
        revoked_at: None,
    });
    entry.last_touched = now;

    recompute_subject(&mut state.store, &subject, now);
    state.mark_subject_dirty(&subject);
    state.mark_metadata_dirty();
    let event_kind = match action {
        DecisionAction::Ban => ReputationEventKind::BanApplied,
        DecisionAction::Restrict => ReputationEventKind::RestrictionChanged,
    };
    emit_notice(state, &subject, event_kind);
    Ok(id)
}

fn revoke_decision(
    state: &mut RuntimeState,
    subject: &RecordKey,
    decision_id: DecisionId,
    required_source: Option<&AuthorityId>,
) -> Result<(), ReputationError> {
    let now = current_timestamp();
    let entry = state
        .store
        .entries
        .get_mut(&subject.to_string())
        .ok_or(ReputationError::EntryNotFound)?;

    let decision = entry
        .decisions
        .iter_mut()
        .find(|decision| decision.id == decision_id)
        .ok_or(ReputationError::DecisionNotFound)?;

    if required_source.is_some_and(|source| source != &decision.source) {
        return Err(ReputationError::PermissionDenied);
    }

    let action = decision.action;
    decision.status = DecisionStatus::Revoked;
    decision.revoked_at = Some(now);
    entry.last_touched = now;

    recompute_subject(&mut state.store, subject, now);
    state.mark_subject_dirty(subject);
    let event_kind = match action {
        DecisionAction::Ban => ReputationEventKind::BanRemoved,
        DecisionAction::Restrict => ReputationEventKind::RestrictionChanged,
    };
    emit_notice(state, subject, event_kind);
    Ok(())
}

fn set_user_override(
    state: &mut RuntimeState,
    subject: RecordKey,
    mode: UserOverrideMode,
    note: Option<String>,
) -> Result<(), ReputationError> {
    if note.as_ref().is_some_and(|text| text.len() > MAX_DESCRIPTION_BYTES) {
        return Err(ReputationError::DescriptionTooLong);
    }

    let now = current_timestamp();
    let entry = state
        .store
        .entries
        .entry(subject.to_string())
        .or_insert_with(|| ReputationEntry::new(subject.clone(), now));
    entry.user_override = Some(UserOverrideRecord {
        mode,
        created_at: now,
        note,
    });
    entry.last_touched = now;

    recompute_subject(&mut state.store, &subject, now);
    state.mark_subject_dirty(&subject);
    emit_notice(
        state,
        &subject,
        ReputationEventKind::UserOverrideChanged,
    );
    Ok(())
}

fn clear_user_override(
    state: &mut RuntimeState,
    subject: &RecordKey,
) -> Result<(), ReputationError> {
    let now = current_timestamp();
    let entry = state
        .store
        .entries
        .get_mut(&subject.to_string())
        .ok_or(ReputationError::EntryNotFound)?;
    entry.user_override = None;
    entry.last_touched = now;

    recompute_subject(&mut state.store, subject, now);
    state.mark_subject_dirty(subject);
    emit_notice(
        state,
        subject,
        ReputationEventKind::UserOverrideChanged,
    );
    Ok(())
}

fn get_app_source_report(state: &RuntimeState, app_id: &AppId) -> AppSourceReport {
    let source = AuthorityId::App(app_id.clone());
    let mut active_recent_observations = 0usize;
    let mut retracted_recent_observations = 0usize;
    let mut compacted_historical_observations = 0u64;
    let mut retracted_historical_observations = 0u64;
    let mut active_decisions = 0usize;
    let mut affected_subjects = 0usize;
    let mut recent_observations = Vec::new();
    let mut historical_subjects = Vec::new();
    let mut decisions = Vec::new();

    for entry in state.store.entries.values() {
        let mut affected = false;
        for observation in &entry.recent_observations {
            if observation.source == source {
                affected = true;
                if observation.is_active() {
                    active_recent_observations += 1;
                } else {
                    retracted_recent_observations += 1;
                }
                recent_observations.push(observation.clone());
            }
        }
        if let Some(history) = entry.historical_by_source.get(&source) {
            compacted_historical_observations = compacted_historical_observations
                .saturating_add(history.totals.count);
            retracted_historical_observations = retracted_historical_observations
                .saturating_add(history.retracted_totals.count);
            historical_subjects.push(AppHistoricalSubjectReport {
                subject: entry.subject.clone(),
                observation_count: history.totals.count,
                retracted_observation_count: history.retracted_totals.count,
                first_observed: history.first_observed,
                last_observed: history.last_observed,
                last_retracted_at: history.last_retracted_at,
            });
            affected = true;
        }
        for decision in entry.decisions.iter().filter(|decision| decision.source == source) {
            if decision.status == DecisionStatus::Active {
                active_decisions += 1;
            }
            decisions.push(decision.clone());
            affected = true;
        }
        if affected {
            affected_subjects += 1;
        }
    }

    recent_observations.sort_by(|a, b| {
        b.observed_at
            .cmp(&a.observed_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    historical_subjects.sort_by(|a, b| a.subject.to_string().cmp(&b.subject.to_string()));
    decisions.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));

    AppSourceReport {
        app_id: app_id.clone(),
        active_recent_observations,
        retracted_recent_observations,
        compacted_historical_observations,
        retracted_historical_observations,
        active_decisions,
        affected_subjects,
        recent_observations,
        historical_subjects,
        decisions,
        retractions: state
            .store
            .app_source_retractions
            .iter()
            .filter(|record| &record.app_id == app_id)
            .cloned()
            .collect(),
    }
}

fn retract_app_source(
    state: &mut RuntimeState,
    app_id: AppId,
    reason: String,
) -> Result<AppRetractionReport, ReputationError> {
    if reason.len() > MAX_DESCRIPTION_BYTES {
        return Err(ReputationError::ReasonTooLong);
    }

    let source = AuthorityId::App(app_id.clone());
    let now = current_timestamp();
    let mut active_observations_retracted = 0usize;
    let mut historical_observations_retracted = 0u64;
    let mut decisions_revoked = 0usize;
    let mut changed_subjects = Vec::new();

    for entry in state.store.entries.values_mut() {
        let mut changed = false;
        for observation in &mut entry.recent_observations {
            if observation.source == source && observation.retracted_at.is_none() {
                observation.retracted_at = Some(now);
                active_observations_retracted += 1;
                changed = true;
            }
        }

        if let Some(history) = entry.historical_by_source.get_mut(&source) {
            let retracted = history.retract_active(now);
            if retracted != 0 {
                historical_observations_retracted = historical_observations_retracted
                    .saturating_add(retracted);
                changed = true;
            }
        }

        for decision in &mut entry.decisions {
            if decision.source == source && decision.status == DecisionStatus::Active {
                decision.status = DecisionStatus::Revoked;
                decision.revoked_at = Some(now);
                decisions_revoked += 1;
                changed = true;
            }
        }

        if changed {
            entry.last_touched = now;
            changed_subjects.push(entry.subject.clone());
        }
    }

    let affected_subjects = changed_subjects.len();
    state.store.app_source_retractions.push(AppSourceRetractionRecord {
        app_id: app_id.clone(),
        retracted_at: now,
        active_observations_retracted,
        historical_observations_retracted,
        decisions_revoked,
        affected_subjects,
        reason,
    });
    state.mark_metadata_dirty();

    for subject in &changed_subjects {
        state.mark_subject_dirty(subject);
        recompute_subject(&mut state.store, subject, now);
        emit_notice(state, subject, ReputationEventKind::EvidenceRetracted);
    }

    Ok(AppRetractionReport {
        app_id,
        active_observations_retracted,
        historical_observations_retracted,
        decisions_revoked,
        affected_subjects,
    })
}

fn set_app_source_policy(
    state: &mut RuntimeState,
    app_id: AppId,
    policy: AppSourcePolicy,
) -> Result<(), ReputationError> {
    state.store.app_source_policies.insert(app_id, policy);
    let now = current_timestamp();
    let subjects: Vec<RecordKey> = state
        .store
        .entries
        .values()
        .map(|entry| entry.subject.clone())
        .collect();

    for subject in &subjects {
        recompute_subject(&mut state.store, subject, now);
        emit_notice(
            state,
            subject,
            ReputationEventKind::SourcePolicyChanged,
        );
    }
    state.mark_metadata_dirty();
    Ok(())
}

fn delete_app_source_data(
    state: &mut RuntimeState,
    app_id: &AppId,
) -> Result<usize, ReputationError> {
    let report = retract_app_source(
        state,
        app_id.clone(),
        "Legacy delete request converted to provenance-preserving retraction".to_string(),
    )?;
    state.store.app_source_policies.remove(app_id);
    state.mark_metadata_dirty();
    Ok(report.affected_subjects)
}

fn validate_scope_for_source(
    source: &AuthorityId,
    requested_scope: &BanScope,
) -> Result<(), ReputationError> {
    if let (AuthorityId::App(source_app), BanScope::App(target_app)) = (source, requested_scope) {
        if source_app != target_app {
            return Err(ReputationError::PermissionDenied);
        }
    }
    Ok(())
}

fn effective_scope_for_source(source: &AuthorityId, requested: &BanScope) -> BanScope {
    match source {
        AuthorityId::App(app_id) => BanScope::App(app_id.clone()),
        AuthorityId::User | AuthorityId::CoreModule(_) => requested.clone(),
    }
}

// ============================================================================
// Classification
// ============================================================================

fn contribution_for(source: &AuthorityId, kind: ObservationKind) -> ScoreDelta {
    let mut delta = match kind {
        ObservationKind::InteractionSucceeded => ScoreDelta {
            reliability: 6,
            count: 1,
            ..Default::default()
        },
        ObservationKind::InteractionFailed => ScoreDelta {
            reliability: -4,
            suspicion: 2,
            count: 1,
            ..Default::default()
        },
        ObservationKind::UsefulService => ScoreDelta {
            reliability: 4,
            usefulness: 12,
            count: 1,
            ..Default::default()
        },
        ObservationKind::ExcessiveActivity => ScoreDelta {
            suspicion: 8,
            automation: 8,
            count: 1,
            ..Default::default()
        },
        ObservationKind::RepetitiveActivity => ScoreDelta {
            suspicion: 3,
            automation: 12,
            count: 1,
            ..Default::default()
        },
        ObservationKind::SuspiciousCoordination => ScoreDelta {
            suspicion: 15,
            automation: 8,
            sybil: 18,
            count: 1,
            ..Default::default()
        },
        ObservationKind::MessageDelivered => ScoreDelta {
            reliability: 5,
            usefulness: 2,
            count: 1,
            ..Default::default()
        },
        ObservationKind::MessageRejected => ScoreDelta {
            reliability: -2,
            suspicion: 2,
            count: 1,
            ..Default::default()
        },
        ObservationKind::UnsolicitedMessage => ScoreDelta {
            suspicion: 8,
            abuse: 5,
            count: 1,
            ..Default::default()
        },
        ObservationKind::Spam => ScoreDelta {
            suspicion: 12,
            automation: 6,
            abuse: 15,
            count: 1,
            ..Default::default()
        },
        ObservationKind::Harassment => ScoreDelta {
            suspicion: 10,
            abuse: 18,
            count: 1,
            ..Default::default()
        },
        ObservationKind::ValidDhtResponse => ScoreDelta {
            reliability: 6,
            count: 1,
            ..Default::default()
        },
        ObservationKind::InvalidDhtResponse => ScoreDelta {
            reliability: -8,
            suspicion: 8,
            integrity: 10,
            count: 1,
            ..Default::default()
        },
        ObservationKind::InvalidSignature => ScoreDelta {
            reliability: -20,
            suspicion: 20,
            integrity: 35,
            count: 1,
            invalid_signature_events: 1,
            ..Default::default()
        },
        ObservationKind::ImpossibleProtocolState => ScoreDelta {
            reliability: -30,
            suspicion: 35,
            integrity: 60,
            count: 1,
            impossible_protocol_events: 1,
            ..Default::default()
        },
        ObservationKind::MalformedProtocolMessage => ScoreDelta {
            reliability: -5,
            suspicion: 5,
            integrity: 4,
            count: 1,
            ..Default::default()
        },
        ObservationKind::DeliberateStateCorruption => ScoreDelta {
            reliability: -40,
            suspicion: 45,
            integrity: 75,
            abuse: 20,
            count: 1,
            deliberate_corruption_events: 1,
            ..Default::default()
        },
        ObservationKind::FutureTimestampClaim => ScoreDelta {
            reliability: -12,
            suspicion: 18,
            sybil: 10,
            integrity: 15,
            count: 1,
            ..Default::default()
        },
        ObservationKind::ConflictingAccountCreationClaim => ScoreDelta {
            reliability: -10,
            suspicion: 15,
            sybil: 5,
            integrity: 20,
            count: 1,
            ..Default::default()
        },
        ObservationKind::SuspiciousCreationBurst => ScoreDelta {
            reliability: -30,
            suspicion: 45,
            automation: 20,
            sybil: 70,
            integrity: 35,
            count: 1,
            ..Default::default()
        },
        ObservationKind::Reachable => ScoreDelta {
            reliability: 4,
            count: 1,
            ..Default::default()
        },
        ObservationKind::Unreachable => ScoreDelta {
            reliability: -2,
            count: 1,
            ..Default::default()
        },
        ObservationKind::HandshakeUnavailable => ScoreDelta {
            reliability: -1,
            count: 1,
            ..Default::default()
        },
        ObservationKind::StableAvailability => ScoreDelta {
            reliability: 8,
            usefulness: 6,
            count: 1,
            ..Default::default()
        },
        ObservationKind::AppBanRequested => ScoreDelta {
            suspicion: 8,
            abuse: 5,
            count: 1,
            ..Default::default()
        },
        ObservationKind::UserMarkedHarmful => ScoreDelta {
            suspicion: 20,
            abuse: 15,
            count: 1,
            ..Default::default()
        },
        ObservationKind::UserMarkedTrusted => ScoreDelta {
            reliability: 18,
            usefulness: 6,
            suspicion: -10,
            count: 1,
            ..Default::default()
        },
    };

    let weight_percent = match source {
        AuthorityId::User => 140,
        AuthorityId::CoreModule(_) => 100,
        AuthorityId::App(_) => 45,
    };

    delta.reliability = scale(delta.reliability, weight_percent);
    delta.usefulness = scale(delta.usefulness, weight_percent);
    delta.suspicion = scale(delta.suspicion, weight_percent);
    delta.automation = scale(delta.automation, weight_percent);
    delta.sybil = scale(delta.sybil, weight_percent);
    delta.integrity = scale(delta.integrity, weight_percent);
    delta.abuse = scale(delta.abuse, weight_percent);

    // Only trusted core observations can directly satisfy the automatic
    // protocol-tampering thresholds. App reports still affect suspicion.
    if source.is_app() {
        delta.impossible_protocol_events = 0;
        delta.invalid_signature_events = 0;
        delta.deliberate_corruption_events = 0;
    }

    delta
}

fn scale(value: i64, percent: i64) -> i64 {
    value.saturating_mul(percent) / 100
}

fn cap_source_contribution(source: &AuthorityId, mut delta: ScoreDelta) -> ScoreDelta {
    let (axis_cap, count_cap) = match source {
        // One app may strongly affect its own app-specific decision, but its
        // general reputation evidence is capped so report spam cannot dominate
        // the shared local classifier. Independent app sources still add up.
        AuthorityId::App(_) => (60i64, 16u64),
        AuthorityId::CoreModule(_) => (255i64, 64u64),
        AuthorityId::User => (180i64, 32u64),
    };

    delta.reliability = delta.reliability.clamp(-axis_cap, axis_cap);
    delta.usefulness = delta.usefulness.clamp(-axis_cap, axis_cap);
    delta.suspicion = delta.suspicion.clamp(-axis_cap, axis_cap);
    delta.automation = delta.automation.clamp(-axis_cap, axis_cap);
    delta.sybil = delta.sybil.clamp(-axis_cap, axis_cap);
    delta.integrity = delta.integrity.clamp(-axis_cap, axis_cap);
    delta.abuse = delta.abuse.clamp(-axis_cap, axis_cap);
    delta.count = delta.count.min(count_cap);
    delta
}

fn ensure_automatic_integrity_ban(
    store: &mut ReputationStore,
    subject: &RecordKey,
    now: u64,
) -> bool {
    let key = subject.to_string();
    let Some(entry) = store.entries.get(&key) else {
        return false;
    };

    let mut core_counts = ScoreDelta::default();
    for (source, aggregate) in &entry.historical_by_source {
        if matches!(source, AuthorityId::CoreModule(_)) {
            core_counts.add_assign(aggregate.totals);
        }
    }
    for observation in &entry.recent_observations {
        if observation.is_active()
            && matches!(&observation.source, AuthorityId::CoreModule(_))
        {
            core_counts.add_assign(contribution_for(&observation.source, observation.kind));
        }
    }

    let should_ban = core_counts.deliberate_corruption_events >= 2
        || core_counts.impossible_protocol_events >= 3
        || core_counts.invalid_signature_events >= 6
        || (core_counts.deliberate_corruption_events >= 1
            && core_counts.impossible_protocol_events >= 1);

    if !should_ban {
        return false;
    }

    let classifier = AuthorityId::CoreModule(CoreModuleId(CLASSIFIER_MODULE_NAME.to_string()));
    let already_present = entry.decisions.iter().any(|decision| {
        decision.source == classifier
            && decision.action == DecisionAction::Ban
            && decision.effective_scope == BanScope::NetworkInteraction
            && decision.is_active_at(now)
    });

    if already_present {
        return false;
    }

    let id = store.next_decision_id();
    let Some(entry) = store.entries.get_mut(&key) else {
        return false;
    };
    entry.decisions.push(ReputationDecision {
        id,
        subject: subject.clone(),
        source: classifier,
        action: DecisionAction::Ban,
        requested_scope: BanScope::NetworkInteraction,
        effective_scope: BanScope::NetworkInteraction,
        reason: "Repeated locally verified protocol states consistent with tampering".into(),
        created_at: now,
        expires_at: None,
        status: DecisionStatus::Active,
        revoked_at: None,
    });
    true
}

fn recompute_subject(store: &mut ReputationStore, subject: &RecordKey, now: u64) {
    let source_policies = store.app_source_policies.clone();
    let Some(entry) = store.entries.get_mut(&subject.to_string()) else {
        return;
    };

    expire_decisions(entry, now);
    compact_recent_observations(entry, now);

    let previous_class = entry.summary.class;
    let mut totals = ScoreDelta::default();
    let mut source_totals: HashMap<AuthorityId, ScoreDelta> = HashMap::new();
    let mut source_times: HashMap<AuthorityId, (u64, u64)> = HashMap::new();
    let mut sources = HashSet::new();
    let mut first_observed = u64::MAX;
    let mut last_observed = 0u64;

    let source_enabled = |source: &AuthorityId| match source {
        AuthorityId::App(app_id) => source_policies
            .get(app_id)
            .copied()
            .unwrap_or(AppSourcePolicy::Enabled)
            == AppSourcePolicy::Enabled,
        AuthorityId::User | AuthorityId::CoreModule(_) => true,
    };

    for (source, aggregate) in &entry.historical_by_source {
        if !source_enabled(source) {
            continue;
        }
        source_totals
            .entry(source.clone())
            .or_default()
            .add_assign(aggregate.totals);
        let times = source_times
            .entry(source.clone())
            .or_insert((aggregate.first_observed, aggregate.last_observed));
        if aggregate.first_observed != 0 {
            times.0 = if times.0 == 0 {
                aggregate.first_observed
            } else {
                times.0.min(aggregate.first_observed)
            };
        }
        times.1 = times.1.max(aggregate.last_observed);
    }

    for observation in &entry.recent_observations {
        if !observation.is_active() || !source_enabled(&observation.source) {
            continue;
        }
        source_totals
            .entry(observation.source.clone())
            .or_default()
            .add_assign(contribution_for(&observation.source, observation.kind));
        let times = source_times
            .entry(observation.source.clone())
            .or_insert((observation.observed_at, observation.observed_at));
        times.0 = times.0.min(observation.observed_at);
        times.1 = times.1.max(observation.observed_at);
    }

    for (source, source_delta) in source_totals {
        let capped = cap_source_contribution(&source, source_delta);
        totals.add_assign(capped);
        sources.insert(source.clone());
        if let Some((source_first, source_last)) = source_times.get(&source) {
            if *source_first != 0 {
                first_observed = first_observed.min(*source_first);
            }
            last_observed = last_observed.max(*source_last);
        }
    }

    let reliability = normalized_score(totals.reliability);
    let usefulness = normalized_score(totals.usefulness);
    let suspicion = normalized_score(totals.suspicion);
    let automation = normalized_score(totals.automation);
    let sybil = normalized_score(totals.sybil);
    let integrity = normalized_score(totals.integrity);
    let abuse = normalized_score(totals.abuse);

    let active_decisions: Vec<&ReputationDecision> = entry
        .decisions
        .iter()
        .filter(|decision| {
            decision.is_active_at(now) && source_enabled(&decision.source)
        })
        .collect();

    let network_banned = active_decisions.iter().any(|decision| {
        decision.action == DecisionAction::Ban
            && decision.effective_scope == BanScope::NetworkInteraction
    });

    let class = if network_banned {
        ReputationClass::NetworkBanned
    } else if integrity >= 140 {
        ReputationClass::TamperedProtocol
    } else if sybil >= 110 {
        ReputationClass::LikelySybil
    } else if abuse >= 110 {
        ReputationClass::Abusive
    } else if automation >= 90 && suspicion >= 55 {
        ReputationClass::SuspiciousAutomation
    } else if automation >= 90 && usefulness >= 55 && suspicion < 55 {
        ReputationClass::AutomatedBenign
    } else if reliability >= 110 && usefulness >= 75 && suspicion < 50 {
        ReputationClass::ReliableServer
    } else if reliability >= 70 && suspicion < 40 {
        ReputationClass::GoodCitizen
    } else if totals.count == 0 {
        ReputationClass::New
    } else {
        ReputationClass::NormalUser
    };

    let mut flags = ReputationFlags::NONE;
    if network_banned {
        flags.insert(ReputationFlags::BANNED);
    }
    if class == ReputationClass::LikelySybil {
        flags.insert(ReputationFlags::SUSPECTED_SYBIL);
    }
    if matches!(
        class,
        ReputationClass::AutomatedBenign | ReputationClass::SuspiciousAutomation
    ) {
        flags.insert(ReputationFlags::AUTOMATED);
    }
    if class == ReputationClass::ReliableServer {
        flags.insert(ReputationFlags::USEFUL_SERVER);
    }
    if class == ReputationClass::TamperedProtocol {
        flags.insert(ReputationFlags::TAMPERED_PROTOCOL);
    }
    if entry.user_override.is_some() {
        flags.insert(ReputationFlags::USER_OVERRIDE);
    }
    if active_decisions.iter().any(|decision| {
        decision.source.is_app() && decision.requested_scope != decision.effective_scope
    }) {
        flags.insert(ReputationFlags::CROSS_APP_CONCERN);
    }
    if active_decisions
        .iter()
        .any(|decision| decision.action == DecisionAction::Restrict)
    {
        flags.insert(ReputationFlags::RESTRICTED);
    }

    let confidence = ((totals.count.min(24) * 8)
        .saturating_add((sources.len().min(7) as u64) * 9))
    .min(255) as u8;

    entry.summary = ReputationSummary {
        class,
        confidence,
        reliability,
        usefulness,
        suspicion,
        automation_likelihood: automation,
        sybil_likelihood: sybil,
        integrity_risk: integrity,
        abuse_risk: abuse,
        observation_count: totals.count,
        distinct_sources: sources.len().min(u16::MAX as usize) as u16,
        first_observed: if first_observed == u64::MAX {
            0
        } else {
            first_observed
        },
        last_observed,
        last_changed: if previous_class != class {
            now
        } else {
            entry.summary.last_changed
        },
        flags,
    };
}

fn normalized_score(raw: i64) -> u8 {
    raw.clamp(0, 255) as u8
}

fn recent_observation_limit_for_source(source: &AuthorityId) -> usize {
    match source {
        AuthorityId::App(_) => 16,
        AuthorityId::CoreModule(_) => 32,
        AuthorityId::User => 32,
    }
}

fn compact_source_observation_quota(
    entry: &mut ReputationEntry,
    source: &AuthorityId,
) {
    let limit = recent_observation_limit_for_source(source);
    while entry
        .recent_observations
        .iter()
        .filter(|observation| &observation.source == source)
        .count()
        >= limit
    {
        let Some(index) = entry
            .recent_observations
            .iter()
            .position(|observation| &observation.source == source)
        else {
            break;
        };
        if let Some(observation) = entry.recent_observations.remove(index) {
            fold_observation(entry, observation);
        }
    }
}

fn compact_recent_observations(entry: &mut ReputationEntry, now: u64) {
    let cutoff = now.saturating_sub(RECENT_OBSERVATION_MAX_AGE_SECS);

    loop {
        let should_fold = entry
            .recent_observations
            .front()
            .is_some_and(|observation| observation.observed_at < cutoff);
        if !should_fold {
            break;
        }
        if let Some(observation) = entry.recent_observations.pop_front() {
            fold_observation(entry, observation);
        }
    }
}

fn fold_observation(entry: &mut ReputationEntry, observation: StoredObservation) {
    let contribution = contribution_for(&observation.source, observation.kind);
    let aggregate = entry
        .historical_by_source
        .entry(observation.source)
        .or_default();

    if let Some(retracted_at) = observation.retracted_at {
        // Retraction removes influence, not provenance. Preserve compacted
        // source/count/timing information in the non-scoring archive.
        aggregate.retracted_totals.add_assign(contribution);
        if aggregate.retracted_first_observed == 0 {
            aggregate.retracted_first_observed = observation.observed_at;
        } else {
            aggregate.retracted_first_observed = aggregate
                .retracted_first_observed
                .min(observation.observed_at);
        }
        aggregate.retracted_last_observed = aggregate
            .retracted_last_observed
            .max(observation.observed_at);
        aggregate.last_retracted_at = Some(
            aggregate
                .last_retracted_at
                .unwrap_or(0)
                .max(retracted_at),
        );
        return;
    }

    aggregate.totals.add_assign(contribution);
    if aggregate.first_observed == 0 {
        aggregate.first_observed = observation.observed_at;
    } else {
        aggregate.first_observed = aggregate.first_observed.min(observation.observed_at);
    }
    aggregate.last_observed = aggregate.last_observed.max(observation.observed_at);
}

fn expire_decisions(entry: &mut ReputationEntry, now: u64) {
    for decision in &mut entry.decisions {
        if decision.status == DecisionStatus::Active
            && decision.expires_at.is_some_and(|expiry| expiry <= now)
        {
            decision.status = DecisionStatus::Expired;
        }
    }
}

// ============================================================================
// Views and dossiers
// ============================================================================

fn build_view(
    store: &ReputationStore,
    subject: &RecordKey,
    app_context: Option<&AppId>,
) -> Result<ReputationView, ReputationError> {
    let Some(entry) = store.entries.get(&subject.to_string()) else {
        return Ok(ReputationView {
            subject: subject.clone(),
            class: ReputationClass::New,
            confidence: 0,
            network_access: AccessLevel::Restricted,
            app_access: app_context.map(|_| AccessLevel::Restricted),
            visibility_weight: 25,
            flags: ReputationFlags::RESTRICTED,
            last_observed: 0,
        });
    };
    let now = current_timestamp();

    // Unknown and lightly-observed identities start on probation. This makes
    // returning identities pay a small re-entry cost after their old entry has
    // legitimately aged out, without treating them as malicious.
    let probation = entry.summary.confidence < 24;
    let mut network_access = if probation {
        AccessLevel::Restricted
    } else {
        AccessLevel::Allowed
    };
    let mut app_access = app_context.map(|_| {
        if probation {
            AccessLevel::Restricted
        } else {
            AccessLevel::Allowed
        }
    });

    for decision in entry.decisions.iter().filter(|decision| {
        decision.is_active_at(now) && store.source_enabled(&decision.source)
    }) {
        let requested_level = match decision.action {
            DecisionAction::Restrict => AccessLevel::Restricted,
            DecisionAction::Ban => AccessLevel::Blocked,
        };

        match &decision.effective_scope {
            BanScope::NetworkInteraction => {
                network_access = strongest_access(network_access, requested_level);
                if let Some(level) = &mut app_access {
                    *level = strongest_access(*level, requested_level);
                }
            }
            BanScope::AllApps => {
                if let Some(level) = &mut app_access {
                    *level = strongest_access(*level, requested_level);
                }
            }
            BanScope::App(app_id) => {
                if app_context == Some(app_id) {
                    if let Some(level) = &mut app_access {
                        *level = strongest_access(*level, requested_level);
                    }
                }
            }
        }
    }

    // Independent broad-ban requests from apps are useful evidence, but apps
    // cannot directly block core network interaction. Corroboration instead
    // creates a derived cross-app policy: three independent apps restrict
    // exposure; five plus substantial abuse evidence block app interaction.
    let broad_app_ban_sources: HashSet<&AppId> = entry
        .decisions
        .iter()
        .filter(|decision| {
            decision.is_active_at(now)
                && decision.action == DecisionAction::Ban
                && matches!(
                    &decision.requested_scope,
                    BanScope::AllApps | BanScope::NetworkInteraction
                )
                && store.source_enabled(&decision.source)
        })
        .filter_map(|decision| match &decision.source {
            AuthorityId::App(app_id) => Some(app_id),
            AuthorityId::User | AuthorityId::CoreModule(_) => None,
        })
        .collect();

    if let Some(level) = &mut app_access {
        if broad_app_ban_sources.len() >= 5 && entry.summary.abuse_risk >= 70 {
            *level = strongest_access(*level, AccessLevel::Blocked);
        } else if broad_app_ban_sources.len() >= 3 {
            *level = strongest_access(*level, AccessLevel::Restricted);
        }
    }

    if let Some(user_override) = &entry.user_override {
        match user_override.mode {
            UserOverrideMode::Allow => {
                network_access = AccessLevel::Allowed;
                if let Some(level) = &mut app_access {
                    *level = AccessLevel::Allowed;
                }
            }
            UserOverrideMode::AllowRestricted => {
                network_access = AccessLevel::Restricted;
                if let Some(level) = &mut app_access {
                    *level = AccessLevel::Restricted;
                }
            }
        }
    }

    let visibility_weight = visibility_weight(entry, network_access, app_access);
    let mut flags = entry.summary.flags;
    if network_access == AccessLevel::Blocked || app_access == Some(AccessLevel::Blocked) {
        flags.insert(ReputationFlags::BANNED);
    }
    if network_access == AccessLevel::Restricted
        || app_access == Some(AccessLevel::Restricted)
    {
        flags.insert(ReputationFlags::RESTRICTED);
    }

    Ok(ReputationView {
        subject: subject.clone(),
        class: entry.summary.class,
        confidence: entry.summary.confidence,
        network_access,
        app_access,
        visibility_weight,
        flags,
        last_observed: entry.summary.last_observed,
    })
}

fn strongest_access(left: AccessLevel, right: AccessLevel) -> AccessLevel {
    use AccessLevel::*;
    match (left, right) {
        (Blocked, _) | (_, Blocked) => Blocked,
        (Restricted, _) | (_, Restricted) => Restricted,
        _ => Allowed,
    }
}

fn visibility_weight(
    entry: &ReputationEntry,
    network_access: AccessLevel,
    app_access: Option<AccessLevel>,
) -> u8 {
    if network_access == AccessLevel::Blocked || app_access == Some(AccessLevel::Blocked) {
        return 0;
    }

    let mut weight = 100i16;
    weight -= (entry.summary.suspicion as i16 * 40) / 255;
    weight -= (entry.summary.sybil_likelihood as i16 * 35) / 255;
    weight += (entry.summary.usefulness as i16 * 20) / 255;

    if entry.summary.flags.contains(ReputationFlags::CROSS_APP_CONCERN) {
        weight -= 15;
    }
    if network_access == AccessLevel::Restricted
        || app_access == Some(AccessLevel::Restricted)
    {
        weight = weight.min(35);
    }

    weight.clamp(0, 100) as u8
}

fn build_dossier(
    store: &ReputationStore,
    subject: &RecordKey,
) -> Result<ReputationDossier, ReputationError> {
    let entry = store
        .entries
        .get(&subject.to_string())
        .ok_or(ReputationError::EntryNotFound)?;

    let mut historical_sources: Vec<_> = entry
        .historical_by_source
        .iter()
        .map(|(source, aggregate)| HistoricalSourceSummary {
            source: source.clone(),
            observation_count: aggregate.totals.count,
            retracted_observation_count: aggregate.retracted_totals.count,
            first_observed: aggregate.first_observed,
            last_observed: aggregate.last_observed,
            last_retracted_at: aggregate.last_retracted_at,
        })
        .collect();
    historical_sources.sort_by(|a, b| a.source.cmp(&b.source));

    Ok(ReputationDossier {
        subject: entry.subject.clone(),
        summary: entry.summary.clone(),
        recent_observations: entry.recent_observations.iter().cloned().collect(),
        decisions: entry.decisions.clone(),
        user_override: entry.user_override.clone(),
        historical_sources,
    })
}

fn format_score_delta(delta: ScoreDelta) -> String {
    format!(
        "reliability={} usefulness={} suspicion={} automation={} sybil={} integrity={} abuse={} count={} impossible={} invalid_signature={} deliberate_corruption={}",
        delta.reliability,
        delta.usefulness,
        delta.suspicion,
        delta.automation,
        delta.sybil,
        delta.integrity,
        delta.abuse,
        delta.count,
        delta.impossible_protocol_events,
        delta.invalid_signature_events,
        delta.deliberate_corruption_events,
    )
}

fn format_authority(source: &AuthorityId) -> String {
    match source {
        AuthorityId::User => "user".to_string(),
        AuthorityId::CoreModule(module) => format!("core:{}", module.0),
        AuthorityId::App(app) => format!("app:{}", app.0),
    }
}

/// Build a detailed, read-only explanation of why a subject currently has its
/// reputation state. This deliberately exposes both score inputs and policy
/// decisions because a blocked network peer is caused by policy, not merely by
/// a low numeric score.
fn build_diagnostic_report(
    store: &ReputationStore,
    subject: &RecordKey,
) -> Result<String, ReputationError> {
    let entry = store
        .entries
        .get(&subject.to_string())
        .ok_or(ReputationError::EntryNotFound)?;
    let now = current_timestamp();
    let view = build_view(store, subject, None)?;

    let mut lines = Vec::new();
    lines.push(format!(
        "subject={} class={:?} confidence={} network_access={:?} visibility={} flags=0x{:08x}",
        subject,
        entry.summary.class,
        entry.summary.confidence,
        view.network_access,
        view.visibility_weight,
        entry.summary.flags.0,
    ));
    lines.push(format!(
        "scores reliability={} usefulness={} suspicion={} automation={} sybil={} integrity={} abuse={} observations={} distinct_sources={} first_observed={} last_observed={} last_changed={}",
        entry.summary.reliability,
        entry.summary.usefulness,
        entry.summary.suspicion,
        entry.summary.automation_likelihood,
        entry.summary.sybil_likelihood,
        entry.summary.integrity_risk,
        entry.summary.abuse_risk,
        entry.summary.observation_count,
        entry.summary.distinct_sources,
        entry.summary.first_observed,
        entry.summary.last_observed,
        entry.summary.last_changed,
    ));

    let source_enabled = |source: &AuthorityId| match source {
        AuthorityId::App(app_id) => store.source_enabled(source)
            && store
                .app_source_policies
                .get(app_id)
                .copied()
                .unwrap_or(AppSourcePolicy::Enabled)
                == AppSourcePolicy::Enabled,
        AuthorityId::User | AuthorityId::CoreModule(_) => true,
    };

    let mut decisions: Vec<_> = entry.decisions.iter().collect();
    decisions.sort_by_key(|decision| decision.id);
    if decisions.is_empty() {
        lines.push("decisions none".to_string());
    } else {
        for decision in decisions {
            let enabled = source_enabled(&decision.source);
            let active = decision.is_active_at(now) && enabled;
            lines.push(format!(
                "decision id={} active={} status={:?} source={} action={:?} requested_scope={:?} effective_scope={:?} created_at={} age_s={} expires_at={:?} reason={:?}",
                decision.id.0,
                active,
                decision.status,
                format_authority(&decision.source),
                decision.action,
                decision.requested_scope,
                decision.effective_scope,
                decision.created_at,
                now.saturating_sub(decision.created_at),
                decision.expires_at,
                decision.reason,
            ));
        }
    }

    if let Some(override_record) = &entry.user_override {
        lines.push(format!(
            "user_override mode={:?} created_at={} age_s={} note={:?}",
            override_record.mode,
            override_record.created_at,
            now.saturating_sub(override_record.created_at),
            override_record.note,
        ));
    }

    let mut source_totals: HashMap<AuthorityId, ScoreDelta> = HashMap::new();
    let mut source_first: HashMap<AuthorityId, u64> = HashMap::new();
    let mut source_last: HashMap<AuthorityId, u64> = HashMap::new();
    let mut source_recent: HashMap<AuthorityId, u64> = HashMap::new();
    let mut source_historical: HashMap<AuthorityId, u64> = HashMap::new();

    for (source, aggregate) in &entry.historical_by_source {
        if !source_enabled(source) {
            continue;
        }
        source_totals
            .entry(source.clone())
            .or_default()
            .add_assign(aggregate.totals);
        source_historical.insert(source.clone(), aggregate.totals.count);
        if aggregate.first_observed != 0 {
            source_first
                .entry(source.clone())
                .and_modify(|value| *value = (*value).min(aggregate.first_observed))
                .or_insert(aggregate.first_observed);
        }
        source_last
            .entry(source.clone())
            .and_modify(|value| *value = (*value).max(aggregate.last_observed))
            .or_insert(aggregate.last_observed);
    }

    for observation in &entry.recent_observations {
        if !observation.is_active() || !source_enabled(&observation.source) {
            continue;
        }
        source_totals
            .entry(observation.source.clone())
            .or_default()
            .add_assign(contribution_for(&observation.source, observation.kind));
        *source_recent.entry(observation.source.clone()).or_default() += 1;
        source_first
            .entry(observation.source.clone())
            .and_modify(|value| *value = (*value).min(observation.observed_at))
            .or_insert(observation.observed_at);
        source_last
            .entry(observation.source.clone())
            .and_modify(|value| *value = (*value).max(observation.observed_at))
            .or_insert(observation.observed_at);
    }

    let mut sources: Vec<_> = source_totals.into_iter().collect();
    sources.sort_by(|(left, _), (right, _)| left.cmp(right));
    if sources.is_empty() {
        lines.push("score_sources none".to_string());
    } else {
        for (source, raw) in sources {
            let capped = cap_source_contribution(&source, raw);
            let first = source_first.get(&source).copied().unwrap_or(0);
            let last = source_last.get(&source).copied().unwrap_or(0);
            let recent = source_recent.get(&source).copied().unwrap_or(0);
            let historical = source_historical.get(&source).copied().unwrap_or(0);
            lines.push(format!(
                "score_source source={} raw=[{}] capped=[{}] recent_active={} historical_active={} first_observed={} last_observed={} last_age_s={}",
                format_authority(&source),
                format_score_delta(raw),
                format_score_delta(capped),
                recent,
                historical,
                first,
                last,
                if last == 0 { 0 } else { now.saturating_sub(last) },
            ));

            if historical > 0 && last != 0 && now.saturating_sub(last) > RECENT_OBSERVATION_MAX_AGE_SECS {
                lines.push(format!(
                    "warning source={} has score-active historical evidence older than {} days; compacted historical totals do not age-decay on their own",
                    format_authority(&source),
                    RECENT_OBSERVATION_MAX_AGE_SECS / (24 * 60 * 60),
                ));
            }
        }
    }

    let mut core_integrity = ScoreDelta::default();
    for (source, aggregate) in &entry.historical_by_source {
        if matches!(source, AuthorityId::CoreModule(_)) {
            core_integrity.add_assign(aggregate.totals);
        }
    }
    for observation in &entry.recent_observations {
        if observation.is_active()
            && matches!(&observation.source, AuthorityId::CoreModule(_))
        {
            core_integrity.add_assign(contribution_for(&observation.source, observation.kind));
        }
    }
    lines.push(format!(
        "automatic_integrity_counters deliberate_corruption={} impossible_protocol={} invalid_signature={}",
        core_integrity.deliberate_corruption_events,
        core_integrity.impossible_protocol_events,
        core_integrity.invalid_signature_events,
    ));

    let active_recent: Vec<_> = entry
        .recent_observations
        .iter()
        .filter(|observation| observation.is_active())
        .collect();
    if active_recent.is_empty() {
        lines.push("recent_observations none".to_string());
    } else {
        for observation in active_recent.iter().rev().take(24).rev() {
            let delta = contribution_for(&observation.source, observation.kind);
            lines.push(format!(
                "observation id={} source={} kind={:?} observed_at={} age_s={} delta=[{}] application_code={:?} description={:?}",
                observation.id.0,
                format_authority(&observation.source),
                observation.kind,
                observation.observed_at,
                now.saturating_sub(observation.observed_at),
                format_score_delta(delta),
                observation.details.application_code,
                observation.details.description,
            ));
        }
        if active_recent.len() > 24 {
            lines.push(format!(
                "recent_observations omitted={} (showing newest 24)",
                active_recent.len() - 24
            ));
        }
    }

    Ok(lines.join("\n"))
}

// ============================================================================
// Notifications
// ============================================================================

fn emit_notice(state: &mut RuntimeState, subject: &RecordKey, kind: ReputationEventKind) {
    let subject_key = subject.to_string();
    let store = &state.store;

    state.subscribers.retain_mut(|subscriber| {
        if !subscriber.events.contains(kind) {
            return !subscriber.tx.is_closed();
        }
        if subscriber
            .subjects
            .as_ref()
            .is_some_and(|subjects| !subjects.contains(&subject_key))
        {
            return !subscriber.tx.is_closed();
        }

        let view = build_view(store, subject, subscriber.app_context.as_ref()).ok();
        if subscriber.minimum_suspicion.is_some_and(|minimum| {
            store
                .entries
                .get(&subject_key)
                .is_some_and(|entry| entry.summary.suspicion < minimum)
        }) {
            return !subscriber.tx.is_closed();
        }

        match subscriber.tx.try_send(ReputationNotice {
            kind,
            subject: subject.clone(),
            view,
        }) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    });
}

fn emit_entry_removed(state: &mut RuntimeState, subject: &RecordKey) {
    let subject_key = subject.to_string();
    state.subscribers.retain_mut(|subscriber| {
        if !subscriber.events.contains(ReputationEventKind::EntryRemoved) {
            return !subscriber.tx.is_closed();
        }
        if subscriber
            .subjects
            .as_ref()
            .is_some_and(|subjects| !subjects.contains(&subject_key))
        {
            return !subscriber.tx.is_closed();
        }

        match subscriber.tx.try_send(ReputationNotice {
            kind: ReputationEventKind::EntryRemoved,
            subject: subject.clone(),
            view: None,
        }) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    });
}

// ============================================================================
// Garbage collection
// ============================================================================

fn run_garbage_collection(state: &mut RuntimeState, now: u64) -> usize {
    let subjects: Vec<RecordKey> = state
        .store
        .entries
        .values()
        .map(|entry| entry.subject.clone())
        .collect();
    for subject in &subjects {
        recompute_subject(&mut state.store, subject, now);
    }

    let mut candidates: Vec<(String, u64, i64)> = state
        .store
        .entries
        .iter()
        .filter_map(|(key, entry)| {
            let idle = now.saturating_sub(entry.last_touched);
            let max_idle = entry_max_idle(entry, now);
            if idle < MIN_GC_ELIGIBLE_AGE_SECS || idle < max_idle {
                return None;
            }
            if has_permanent_user_state(entry, now) {
                return None;
            }
            Some((key.clone(), idle, retention_value(entry, now)))
        })
        .collect();

    // Lowest-value and longest-idle entries are removed first.
    candidates.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| b.1.cmp(&a.1)));

    let over_target = state
        .store
        .entries
        .len()
        .saturating_sub(MAX_SUMMARY_ENTRIES);

    let mut selected = HashSet::new();
    for (index, (key, _, _)) in candidates.iter().enumerate() {
        // Stale entries past their class-specific lifetime can be collected
        // even below the target. If above target, remove at least enough
        // eligible entries to return toward the target.
        if index < over_target || is_stale_by_policy(&state.store.entries[key], now) {
            selected.insert(key.clone());
        }
    }

    let mut removed_subjects = Vec::new();
    for key in selected {
        if let Some(entry) = state.store.entries.remove(&key) {
            removed_subjects.push(entry.subject);
        }
    }

    for subject in &removed_subjects {
        emit_entry_removed(state, subject);
    }

    for subject in &removed_subjects {
        state.mark_subject_dirty(subject);
    }
    removed_subjects.len()
}

fn entry_max_idle(entry: &ReputationEntry, now: u64) -> u64 {
    let active_decisions: Vec<&ReputationDecision> = entry
        .decisions
        .iter()
        .filter(|decision| decision.is_active_at(now))
        .collect();

    if active_decisions.iter().any(|decision| {
        decision.source == AuthorityId::User && decision.is_permanent()
    }) {
        return u64::MAX;
    }

    if active_decisions.iter().any(|decision| {
        decision.is_permanent()
            && decision.effective_scope == BanScope::NetworkInteraction
    }) {
        return AUTOMATIC_BAN_MAX_IDLE_SECS;
    }

    if active_decisions
        .iter()
        .any(|decision| matches!(&decision.source, AuthorityId::App(_)))
    {
        return APP_BAN_MAX_IDLE_SECS;
    }

    match entry.summary.class {
        ReputationClass::ReliableServer | ReputationClass::GoodCitizen => {
            VALUABLE_ENTRY_MAX_IDLE_SECS
        }
        ReputationClass::LikelySybil
        | ReputationClass::Abusive
        | ReputationClass::SuspiciousAutomation
        | ReputationClass::TamperedProtocol => SUSPICIOUS_ENTRY_MAX_IDLE_SECS,
        _ => NORMAL_ENTRY_MAX_IDLE_SECS,
    }
}

fn is_stale_by_policy(entry: &ReputationEntry, now: u64) -> bool {
    now.saturating_sub(entry.last_touched) >= entry_max_idle(entry, now)
}

fn has_permanent_user_state(entry: &ReputationEntry, now: u64) -> bool {
    entry.user_override.is_some()
        || entry.decisions.iter().any(|decision| {
            decision.source == AuthorityId::User
                && decision.is_permanent()
                && decision.is_active_at(now)
        })
}

fn retention_value(entry: &ReputationEntry, now: u64) -> i64 {
    let mut value = 0i64;
    value += entry.summary.usefulness as i64 * 3;
    value += entry.summary.confidence as i64;
    value += entry.summary.suspicion as i64 * 2;
    value += entry.summary.integrity_risk as i64 * 3;
    value += entry.summary.observation_count.min(255) as i64;

    for decision in entry
        .decisions
        .iter()
        .filter(|decision| decision.is_active_at(now))
    {
        value += match (&decision.source, decision.action) {
            (AuthorityId::User, _) => 10_000,
            (_, DecisionAction::Ban) => 2_000,
            (_, DecisionAction::Restrict) => 500,
        };
    }
    value
}

// ============================================================================
// Persistence and load repair
// ============================================================================

fn persist_if_dirty(
    user_auth: &UserAuth,
    session: &UserSession,
    state: &mut RuntimeState,
) -> Result<(), ReputationError> {
    if !state.dirty_metadata && state.dirty_shards.is_empty() {
        return Ok(());
    }

    // Shards are written before metadata. During legacy migration, the old
    // monolithic snapshot therefore remains authoritative until every shard
    // has landed. During normal operation, load repair advances any counter
    // that lagged behind an already-written observation/decision ID.
    let dirty_shards: Vec<u8> = state.dirty_shards.iter().copied().collect();
    for shard_index in &dirty_shards {
        let entries = state
            .store
            .entries
            .iter()
            .filter(|(key, _)| reputation_shard_index(key) == *shard_index)
            .map(|(key, entry)| (key.clone(), entry.clone()))
            .collect();
        let shard = ReputationShard { entries };
        user_auth.write_user_encrypted(
            session,
            &reputation_shard_key(*shard_index),
            &shard,
        )?;
    }

    if state.dirty_metadata {
        let metadata = store_metadata(&state.store);
        user_auth.write_user_encrypted(
            session,
            REPUTATION_METADATA_KEY,
            &metadata,
        )?;
    }

    state.dirty_metadata = false;
    for shard_index in dirty_shards {
        state.dirty_shards.remove(&shard_index);
    }
    Ok(())
}

fn repair_loaded_store(store: &mut ReputationStore, now: u64) {
    let max_observation_id = store
        .entries
        .values()
        .flat_map(|entry| entry.recent_observations.iter())
        .map(|observation| observation.id.0)
        .max()
        .unwrap_or(0);
    let max_decision_id = store
        .entries
        .values()
        .flat_map(|entry| entry.decisions.iter())
        .map(|decision| decision.id.0)
        .max()
        .unwrap_or(0);

    store.next_observation_id = store
        .next_observation_id
        .max(max_observation_id.saturating_add(1))
        .max(1);
    store.next_decision_id = store
        .next_decision_id
        .max(max_decision_id.saturating_add(1))
        .max(1);

    let subjects: Vec<RecordKey> = store
        .entries
        .values()
        .map(|entry| entry.subject.clone())
        .collect();

    for subject in subjects {
        recompute_subject(store, &subject, now);
    }
}

#[cfg(test)]
mod patch_d_provenance_tests {
    use super::*;

    const TEST_KEY: &str = "VLD0:Ql5L4_BYpaHtBECl5khtcSIW-lAnnC5vV5PIZCl7vAs:9C9jBokYTHBBBaq7aev39a9ujPVCCzGLE0-Tx_N7FyQ";

    #[derive(Serialize)]
    struct LegacyStoredObservationV1 {
        id: ObservationId,
        subject: RecordKey,
        source: AuthorityId,
        kind: ObservationKind,
        details: ObservationDetails,
        observed_at: u64,
        retracted_at: Option<u64>,
    }

    #[derive(Serialize)]
    enum LegacyObservationKindV1 {
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
    }

    #[test]
    fn patch_c_json_observation_layout_deserializes_without_session_provenance() {
        let subject: RecordKey = TEST_KEY.parse().unwrap();
        let legacy = LegacyStoredObservationV1 {
            id: ObservationId(7),
            subject: subject.clone(),
            source: AuthorityId::App(AppId("legacy-app".to_string())),
            kind: ObservationKind::UsefulService,
            details: ObservationDetails::default(),
            observed_at: 123,
            retracted_at: None,
        };

        let bytes = serde_json::to_vec(&legacy).unwrap();
        let decoded: ReputationObservation = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.id, ObservationId(7));
        assert_eq!(decoded.subject, subject);
        assert!(decoded.app_session().is_none());
        assert!(decoded.is_active());
    }

    #[test]
    fn new_observation_variant_is_appended_after_patch_c_indexes() {
        let bytes = bincode::serialize(&LegacyObservationKindV1::UserMarkedTrusted).unwrap();
        let decoded: ObservationKind = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, ObservationKind::UserMarkedTrusted);
    }

    #[test]
    fn historical_retraction_archives_influence_without_erasing_source_counts() {
        let mut aggregate = HistoricalAggregate {
            totals: ScoreDelta {
                reliability: 5,
                count: 3,
                ..ScoreDelta::default()
            },
            first_observed: 10,
            last_observed: 20,
            ..HistoricalAggregate::default()
        };

        assert_eq!(aggregate.retract_active(30), 3);
        assert_eq!(aggregate.totals.count, 0);
        assert_eq!(aggregate.retracted_totals.count, 3);
        assert_eq!(aggregate.retracted_totals.reliability, 5);
        assert_eq!(aggregate.retracted_first_observed, 10);
        assert_eq!(aggregate.retracted_last_observed, 20);
        assert_eq!(aggregate.last_retracted_at, Some(30));
        assert_eq!(aggregate.retract_active(40), 0);
        assert_eq!(aggregate.retracted_totals.count, 3);
    }


    #[test]
    fn reputation_entry_with_structured_authority_keys_serializes_to_json() {
        let subject: RecordKey = TEST_KEY.parse().unwrap();
        let mut entry = ReputationEntry::new(subject, 100);
        entry.historical_by_source.insert(
            AuthorityId::App(AppId("rooms".to_string())),
            HistoricalAggregate {
                totals: ScoreDelta {
                    reliability: 2,
                    count: 1,
                    ..ScoreDelta::default()
                },
                first_observed: 90,
                last_observed: 100,
                ..HistoricalAggregate::default()
            },
        );
        entry.historical_by_source.insert(
            AuthorityId::CoreModule(CoreModuleId("handshake".to_string())),
            HistoricalAggregate::default(),
        );

        let json = serde_json::to_vec(&entry).expect("structured keys serialize as entries");
        let decoded: ReputationEntry =
            serde_json::from_slice(&json).expect("entry round-trips");
        assert_eq!(decoded.historical_by_source.len(), 2);
    }

    #[test]
    fn ordinary_handshake_failure_is_only_a_tiny_reliability_cost() {
        let delta = contribution_for(
            &AuthorityId::CoreModule(CoreModuleId("handshake".to_string())),
            ObservationKind::HandshakeUnavailable,
        );
        assert_eq!(delta.reliability, -1);
        assert_eq!(delta.suspicion, 0);
        assert_eq!(delta.integrity, 0);
        assert_eq!(delta.abuse, 0);
    }
}

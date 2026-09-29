// node_list.rs
//
// In-memory topology state for network discovery.
//
// Patch B deliberately separates identities learned through somebody else's
// routing table from identities we have contacted directly:
//
//   CandidateEntry / Advertised
//       -> direct DHT read -> ListEntry / DhtVerified
//       -> authenticated handshake -> ListEntry / Authenticated
//
// Only ListEntry values at DhtVerified or Authenticated may be republished.
// Remote observation timestamps are retained only as bounded claims; they are
// never copied into our local first/last-seen timestamps.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use veilid_core::RecordKey;

use crate::{
    app::discovery::app_fingerprint,
    types::{
        current_timestamp, KeyInt, RecordTableEntry, APP_DISCOVERY_ACTIVITY_TTL_SECS,
        PUBLIC_METADATA_MAX_FUTURE_SKEW_SECS, USER_PRESENCE_STALE_AFTER_SECS, CAPABILITY_MAILBOX,
    },
};

// ============================================================================
// Bootstrap and topology policy
// ============================================================================

/// Used only when an account does not yet have saved topology state.
pub const DEFAULT_BOOTSTRAP_DHTS: &[&str] = &[
    "VLD0:Ql5L4_BYpaHtBECl5khtcSIW-lAnnC5vV5PIZCl7vAs:9C9jBokYTHBBBaq7aev39a9ujPVCCzGLE0-Tx_N7FyQ",
    "VLD0:KrstLQEVgZ_MmFrsu7X_WSVMm4n5BXSnX5UvGF1E3EE:YPt6Ym5S2DXpwNyjkVgMgbiXKtn2vZSnF1Me8ESzz3s",
    "VLD0:qshUK5zVzIHg8dWfUSxkNRgBLNW_raHtb7p-vkgXPyM:FGmx1nvBk8gLIRlQBjTeI40iMmVYg3cMwlhwXkL7d-w",
    "VLD0:I9T8NP2GWb4vunxVv2V0JOjyD_lZ59ImMg8CnOvN4z0:ca9vj_ECFFSzUwMPUHElolQ_q-EqsZ8m-bLtROL-q4Y",
    "VLD0:iTSsX9dTxOQTscWBOJuT4ki9YF1SMtobgc3TrjNQcG4:ozKa2wGPPY1-tAf4wrNXcgMJvdCPqU0Srx9cB502UFc",
];

pub const MAX_ADVERTISERS_PER_NODE: usize = 32;
pub const MAX_CREATION_CLAIMS_PER_NODE: usize = 32;
pub const MAX_CANDIDATE_FAILURE_BACKOFF_SECS: u64 = 6 * 60 * 60;
pub const UNDER_REPLICATED_MIN_ACCOUNT_AGE_SECS: u64 = 30 * 24 * 60 * 60;
pub const RECENT_DIRECT_VERIFICATION_SECS: u64 = 7 * 24 * 60 * 60;
pub const PUBLISH_RANDOM_ROTATION_SECS: u64 = 60 * 60;
pub const MAX_FUTURE_CREATION_EVENTS: usize = 1_024;

// ============================================================================
// Verification and claim records
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NodeVerificationState {
    Advertised,
    DhtVerified,
    Authenticated,
}

impl Default for NodeVerificationState {
    fn default() -> Self {
        Self::Advertised
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvertiserObservation {
    pub advertiser: RecordKey,
    pub first_reported_at: u64,
    pub last_reported_at: u64,
    pub report_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountCreationClaim {
    pub claimed_created_at: u64,
    pub first_observed_at: u64,
    pub last_observed_at: u64,
    /// `None` means the value was read directly from the subject's own DHT.
    pub reported_by: Option<RecordKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FutureCreationEvent {
    pub node: RecordKey,
    pub claimed_created_at: u64,
    pub first_detected_at: u64,
    #[serde(default)]
    pub cluster_ban_requested: bool,
}

// ============================================================================
// Unverified candidate pool
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateEntry {
    pub their_address: RecordKey,
    pub first_advertised_at: u64,
    pub last_advertised_at: u64,
    #[serde(default)]
    pub advertisers: Vec<AdvertiserObservation>,
    #[serde(default)]
    pub account_creation_claims: Vec<AccountCreationClaim>,
    #[serde(default)]
    pub failed_verifications: u16,
    #[serde(default)]
    pub last_verification_failure_at: u64,
    #[serde(default)]
    pub next_verification_attempt_at: u64,
}

impl CandidateEntry {
    pub fn new(their_address: RecordKey, now: u64) -> Self {
        Self {
            their_address,
            first_advertised_at: now,
            last_advertised_at: now,
            advertisers: Vec::new(),
            account_creation_claims: Vec::new(),
            failed_verifications: 0,
            last_verification_failure_at: 0,
            next_verification_attempt_at: 0,
        }
    }

    fn add_advertiser(&mut self, advertiser: &RecordKey, now: u64) {
        if let Some(existing) = self
            .advertisers
            .iter_mut()
            .find(|source| &source.advertiser == advertiser)
        {
            existing.last_reported_at = now;
            existing.report_count = existing.report_count.saturating_add(1);
            return;
        }

        if self.advertisers.len() >= MAX_ADVERTISERS_PER_NODE {
            self.advertisers.sort_by_key(|source| source.last_reported_at);
            self.advertisers.remove(0);
        }

        self.advertisers.push(AdvertiserObservation {
            advertiser: advertiser.clone(),
            first_reported_at: now,
            last_reported_at: now,
            report_count: 1,
        });
    }

    fn add_creation_claim(
        &mut self,
        claimed_created_at: u64,
        reported_by: Option<RecordKey>,
        now: u64,
    ) {
        if claimed_created_at == 0 {
            return;
        }

        if let Some(existing) = self.account_creation_claims.iter_mut().find(|claim| {
            claim.claimed_created_at == claimed_created_at && claim.reported_by == reported_by
        }) {
            existing.last_observed_at = now;
            return;
        }

        if self.account_creation_claims.len() >= MAX_CREATION_CLAIMS_PER_NODE {
            self.account_creation_claims
                .sort_by_key(|claim| claim.last_observed_at);
            self.account_creation_claims.remove(0);
        }

        self.account_creation_claims.push(AccountCreationClaim {
            claimed_created_at,
            first_observed_at: now,
            last_observed_at: now,
            reported_by,
        });
    }

    fn mark_verification_failed(&mut self, now: u64) {
        self.failed_verifications = self.failed_verifications.saturating_add(1);
        self.last_verification_failure_at = now;

        let exponent = self.failed_verifications.saturating_sub(1).min(12) as u32;
        let delay = 30u64
            .saturating_mul(1u64.checked_shl(exponent).unwrap_or(u64::MAX))
            .min(MAX_CANDIDATE_FAILURE_BACKOFF_SECS);
        self.next_verification_attempt_at = now.saturating_add(delay);
    }

    pub fn is_due_at(&self, now: u64) -> bool {
        self.next_verification_attempt_at <= now
    }
}

#[derive(Debug, Clone, Default)]
pub struct CandidateInsertReport {
    pub accepted: Vec<RecordKey>,
    pub new_candidates: usize,
    pub refreshed: usize,
    pub ignored_by_source_limit: usize,
    pub implausible_creation_claims: Vec<RecordKey>,
}

// ============================================================================
// Directly verified/authenticated node list
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodePresenceState {
    Online,
    ExplicitlyOffline,
    StaleOnlineClaim,
    NeedsRefresh,
    Unknown,
}

impl NodePresenceState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Online => "Online",
            Self::ExplicitlyOffline => "Explicitly offline",
            Self::StaleOnlineClaim => "Stale online claim",
            Self::NeedsRefresh => "Needs refresh",
            Self::Unknown => "Unknown",
        }
    }
}

/// A cached presence claim is trusted for one normal heartbeat-stale window.
/// Once the direct read itself is older than this, the cached claim is no
/// longer reinterpreted as a newly observed online/offline result.
pub const NODE_PRESENCE_CACHE_TRUST_SECS: u64 = USER_PRESENCE_STALE_AFTER_SECS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListEntry {
    pub their_address: RecordKey,

    /// Local metadata-change time. Never imported from a remote table.
    pub last_update: u64,
    /// Deprecated wire-compatibility fields. The passive mailbox module uses
    /// complete RecordKeys and never reads or publishes numeric mailbox ranges.
    pub mailbox_range: (u32, u32),
    pub mailbox_inlist: [u64; 4],
    pub routingtable_minhash: [u64; 4],

    /// Local direct-observation timestamps. Never imported from another node.
    pub first_seen: u64,
    pub last_seen: u64,

    #[serde(default)]
    pub verification_state: NodeVerificationState,
    #[serde(default)]
    pub first_advertised_at: u64,
    #[serde(default)]
    pub last_advertised_at: u64,
    #[serde(default)]
    pub last_direct_dht_read_at: u64,
    #[serde(default)]
    pub last_authenticated_at: u64,
    #[serde(default)]
    pub advertisers: Vec<AdvertiserObservation>,

    /// Creation time read directly from this node's own UserInfo record.
    #[serde(default)]
    pub account_created_at: Option<u64>,
    /// Independent historical claims, including the direct claim (`None`
    /// reporter) and claims repeated by other verified nodes.
    #[serde(default)]
    pub account_creation_claims: Vec<AccountCreationClaim>,

    /// Result of the most recent direct attempt to read presence subkey 0.
    #[serde(default)]
    pub presence_checked_at: u64,
    #[serde(default)]
    pub presence_read_succeeded: bool,

    /// Directly advertised presence data.
    #[serde(default)]
    pub advertised_online: bool,
    #[serde(default)]
    pub last_online: u64,
    #[serde(default)]
    pub last_login: u64,
    #[serde(default)]
    pub status_updated_at: u64,
    #[serde(default)]
    pub protocol_version: u8,

    /// Directly advertised node/app capabilities from main-DHT subkey 10.
    #[serde(default)]
    pub capability_flags: u64,
    #[serde(default)]
    pub application_ids: Vec<String>,
    #[serde(default)]
    pub app_info_updated_at: u64,

    /// Legacy local indices retained only for saved-data compatibility. New
    /// topology code uses full advertiser RecordKeys above.
    #[serde(default)]
    pub seen_in: Vec<u16>,
}

impl ListEntry {
    pub fn new(their_address: RecordKey) -> Self {
        let now = current_timestamp();
        Self {
            their_address,
            last_update: now,
            mailbox_range: (0, 0),
            mailbox_inlist: [0; 4],
            routingtable_minhash: [0; 4],
            first_seen: 0,
            last_seen: 0,
            verification_state: NodeVerificationState::Advertised,
            first_advertised_at: now,
            last_advertised_at: now,
            last_direct_dht_read_at: 0,
            last_authenticated_at: 0,
            advertisers: Vec::new(),
            account_created_at: None,
            account_creation_claims: Vec::new(),
            presence_checked_at: 0,
            presence_read_succeeded: false,
            advertised_online: false,
            last_online: 0,
            last_login: 0,
            status_updated_at: 0,
            protocol_version: 0,
            capability_flags: 0,
            application_ids: Vec::new(),
            app_info_updated_at: 0,
            seen_in: Vec::new(),
        }
    }

    pub fn is_publishable(&self) -> bool {
        self.verification_state >= NodeVerificationState::DhtVerified
    }

    pub fn mark_dht_verified(&mut self, now: u64, account_created_at: Option<u64>) {
        if self.first_seen == 0 {
            self.first_seen = now;
        }
        self.last_seen = now;
        self.last_update = now;
        self.last_direct_dht_read_at = now;
        self.verification_state = self
            .verification_state
            .max(NodeVerificationState::DhtVerified);

        if let Some(created_at) = account_created_at.filter(|value| *value != 0) {
            self.account_created_at = Some(created_at);
            self.add_creation_claim(created_at, None, now);
        }
    }

    pub fn mark_authenticated(&mut self, now: u64) {
        if self.first_seen == 0 {
            self.first_seen = now;
        }
        self.last_seen = now;
        self.last_update = now;
        self.last_authenticated_at = now;
        self.verification_state = NodeVerificationState::Authenticated;
    }

    pub fn touch_reachable(&mut self, now: u64) {
        if self.first_seen == 0 {
            self.first_seen = now;
        }
        self.last_seen = now;
    }

    pub fn mark_presence_checked(&mut self, now: u64, read_succeeded: bool) {
        self.presence_checked_at = now;
        self.presence_read_succeeded = read_succeeded;
    }

    pub fn presence_state_at(&self, now: u64) -> NodePresenceState {
        if self.presence_checked_at == 0 || !self.presence_read_succeeded {
            return NodePresenceState::Unknown;
        }

        if now.saturating_sub(self.presence_checked_at) > NODE_PRESENCE_CACHE_TRUST_SECS {
            return NodePresenceState::NeedsRefresh;
        }

        if !self.advertised_online {
            NodePresenceState::ExplicitlyOffline
        } else if self.is_advertised_online_at(now) {
            NodePresenceState::Online
        } else {
            NodePresenceState::StaleOnlineClaim
        }
    }

    pub fn is_advertised_online_at(&self, now: u64) -> bool {
        self.advertised_online
            && now.saturating_sub(self.last_online) <= USER_PRESENCE_STALE_AFTER_SECS
    }

    fn add_advertiser_observation(&mut self, observation: AdvertiserObservation) {
        if let Some(existing) = self
            .advertisers
            .iter_mut()
            .find(|source| source.advertiser == observation.advertiser)
        {
            existing.first_reported_at = existing
                .first_reported_at
                .min(observation.first_reported_at);
            existing.last_reported_at = existing
                .last_reported_at
                .max(observation.last_reported_at);
            existing.report_count = existing
                .report_count
                .saturating_add(observation.report_count);
            return;
        }

        if self.advertisers.len() >= MAX_ADVERTISERS_PER_NODE {
            self.advertisers.sort_by_key(|source| source.last_reported_at);
            self.advertisers.remove(0);
        }
        self.advertisers.push(observation);
    }

    pub fn add_creation_claim(
        &mut self,
        claimed_created_at: u64,
        reported_by: Option<RecordKey>,
        now: u64,
    ) {
        if claimed_created_at == 0 {
            return;
        }

        if let Some(existing) = self.account_creation_claims.iter_mut().find(|claim| {
            claim.claimed_created_at == claimed_created_at && claim.reported_by == reported_by
        }) {
            existing.last_observed_at = now;
            return;
        }

        if self.account_creation_claims.len() >= MAX_CREATION_CLAIMS_PER_NODE {
            self.account_creation_claims
                .sort_by_key(|claim| claim.last_observed_at);
            self.account_creation_claims.remove(0);
        }
        self.account_creation_claims.push(AccountCreationClaim {
            claimed_created_at,
            first_observed_at: now,
            last_observed_at: now,
            reported_by,
        });
    }

    pub fn account_creation_is_contested(&self) -> bool {
        let Some(direct) = self.account_created_at else {
            return false;
        };
        self.account_creation_claims
            .iter()
            .any(|claim| claim.claimed_created_at != direct)
    }

    pub fn to_record_table_entry(&self) -> RecordTableEntry {
        let now = current_timestamp();
        let app_cutoff = now.saturating_sub(APP_DISCOVERY_ACTIVITY_TTL_SECS);
        let mut app_bloom = crate::types::AppBloomFilter::default();
        if self.app_info_updated_at >= app_cutoff {
            for app_id in &self.application_ids {
                app_bloom.insert(app_fingerprint(app_id));
            }
        }

        RecordTableEntry {
            their_address: self.their_address.clone(),
            account_created_at: self.account_created_at.unwrap_or(0),
            last_update: self.last_update,
            app_bloom,
            mailbox_range: (0, 0),
            mailbox_inlist: [0; 4],
            routingtable_minhash: self.routingtable_minhash,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            seen_in: Vec::new(),
        }
    }
}

// ============================================================================
// Internal topology state
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkSummary {
    pub verified_nodes: usize,
    pub candidate_nodes: usize,
    pub authenticated_nodes: usize,
    pub online: usize,
    pub explicitly_offline: usize,
    pub stale_online_claim: usize,
    pub needs_refresh: usize,
    pub unknown: usize,
    pub presence_reads_ok: usize,
    pub presence_reads_failed: usize,
    pub presence_never_checked: usize,
    pub active_app_headers: usize,
    pub mailbox_capable: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InternalNodeList {
    pub entries: Vec<ListEntry>,
    #[serde(default)]
    pub candidates: Vec<CandidateEntry>,
    #[serde(default)]
    pub future_creation_events: Vec<FutureCreationEvent>,

    /// Rebuildable caches. Serialized copies are ignored and reconstructed.
    #[serde(default)]
    pub address_to_index: HashMap<String, usize>,
    #[serde(default)]
    pub candidate_to_index: HashMap<String, usize>,
}

impl InternalNodeList {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            candidates: Vec::new(),
            future_creation_events: Vec::new(),
            address_to_index: HashMap::new(),
            candidate_to_index: HashMap::new(),
        }
    }

    pub fn new_with_bootstrap() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut list = Self::new();
        let now = current_timestamp();
        for bootstrap in DEFAULT_BOOTSTRAP_DHTS {
            let bootstrap_key: RecordKey = bootstrap.parse()?;
            list.ensure_candidate(bootstrap_key, now);
        }
        Ok(list)
    }

    /// Rebuild indices and conservatively migrate Patch-A lists. Any old entry
    /// that lacks proof of a direct DHT read or handshake is moved back to the
    /// unverified candidate pool instead of being trusted for republication.
    pub fn rebuild_index(&mut self) {
        let now = current_timestamp();
        let mut verified = Vec::with_capacity(self.entries.len());
        let old_entries = std::mem::take(&mut self.entries);

        for mut entry in old_entries {
            entry.mailbox_range = (0, 0);
            entry.mailbox_inlist = [0; 4];
            entry.seen_in.clear();

            let has_direct_evidence = entry.last_direct_dht_read_at != 0
                || entry.last_authenticated_at != 0
                || entry.verification_state >= NodeVerificationState::DhtVerified;

            if has_direct_evidence {
                if entry.verification_state == NodeVerificationState::Advertised {
                    entry.verification_state = if entry.last_authenticated_at != 0 {
                        NodeVerificationState::Authenticated
                    } else {
                        NodeVerificationState::DhtVerified
                    };
                }
                verified.push(entry);
            } else {
                let mut candidate = CandidateEntry::new(entry.their_address, now);
                candidate.first_advertised_at = if entry.first_advertised_at == 0 {
                    now
                } else {
                    entry.first_advertised_at
                };
                candidate.last_advertised_at = if entry.last_advertised_at == 0 {
                    now
                } else {
                    entry.last_advertised_at
                };
                candidate.advertisers = entry.advertisers;
                candidate.account_creation_claims = entry.account_creation_claims;
                self.candidates.push(candidate);
            }
        }

        self.entries = verified;
        self.address_to_index.clear();
        self.candidate_to_index.clear();

        let mut seen = HashSet::new();
        self.entries.retain(|entry| seen.insert(entry.their_address.to_string()));
        for (idx, entry) in self.entries.iter().enumerate() {
            self.address_to_index
                .insert(entry.their_address.to_string(), idx);
        }

        let verified_keys: HashSet<String> = self.address_to_index.keys().cloned().collect();
        let mut candidate_seen = HashSet::new();
        self.candidates.retain(|candidate| {
            let key = candidate.their_address.to_string();
            !verified_keys.contains(&key) && candidate_seen.insert(key)
        });
        for (idx, candidate) in self.candidates.iter().enumerate() {
            self.candidate_to_index
                .insert(candidate.their_address.to_string(), idx);
        }

        // Keep the built-in bootstrap identities available for both new and
        // existing accounts unless they have already been directly verified.
        for bootstrap in DEFAULT_BOOTSTRAP_DHTS {
            if let Ok(key) = bootstrap.parse::<RecordKey>() {
                self.ensure_candidate(key, now);
            }
        }
    }

    pub fn get_index(&self, address: &RecordKey) -> Option<usize> {
        self.address_to_index.get(&address.to_string()).copied()
    }

    pub fn get_candidate_index(&self, address: &RecordKey) -> Option<usize> {
        self.candidate_to_index.get(&address.to_string()).copied()
    }

    pub fn get_by_address(&self, address: &RecordKey) -> Option<&ListEntry> {
        self.entries.get(self.get_index(address)?)
    }

    pub fn get_by_address_mut(&mut self, address: &RecordKey) -> Option<&mut ListEntry> {
        let idx = self.get_index(address)?;
        self.entries.get_mut(idx)
    }

    pub fn ensure_candidate(&mut self, address: RecordKey, now: u64) -> usize {
        if let Some(idx) = self.get_candidate_index(&address) {
            return idx;
        }
        if self.get_index(&address).is_some() {
            return usize::MAX;
        }

        let idx = self.candidates.len();
        self.candidates.push(CandidateEntry::new(address.clone(), now));
        self.candidate_to_index.insert(address.to_string(), idx);
        idx
    }

    fn ensure_verified_entry(&mut self, address: RecordKey) -> usize {
        if let Some(idx) = self.get_index(&address) {
            return idx;
        }
        let idx = self.entries.len();
        self.entries.push(ListEntry::new(address.clone()));
        self.address_to_index.insert(address.to_string(), idx);
        idx
    }

    fn remove_candidate(&mut self, address: &RecordKey) -> Option<CandidateEntry> {
        let idx = self.candidate_to_index.remove(&address.to_string())?;
        let removed = self.candidates.swap_remove(idx);
        if let Some(moved) = self.candidates.get(idx) {
            self.candidate_to_index
                .insert(moved.their_address.to_string(), idx);
        }
        Some(removed)
    }

    pub fn promote_dht_verified(
        &mut self,
        address: RecordKey,
        account_created_at: Option<u64>,
        now: u64,
    ) -> usize {
        let candidate = self.remove_candidate(&address);
        let idx = self.ensure_verified_entry(address);
        let entry = &mut self.entries[idx];

        if let Some(candidate) = candidate {
            entry.first_advertised_at = if entry.first_advertised_at == 0 {
                candidate.first_advertised_at
            } else {
                entry.first_advertised_at.min(candidate.first_advertised_at)
            };
            entry.last_advertised_at = entry
                .last_advertised_at
                .max(candidate.last_advertised_at);
            for advertiser in candidate.advertisers {
                entry.add_advertiser_observation(advertiser);
            }
            for claim in candidate.account_creation_claims {
                entry.add_creation_claim(
                    claim.claimed_created_at,
                    claim.reported_by,
                    claim.last_observed_at,
                );
            }
        }

        entry.mark_dht_verified(now, account_created_at);
        idx
    }

    pub fn mark_authenticated(&mut self, address: RecordKey, now: u64) -> usize {
        let candidate = self.remove_candidate(&address);
        let idx = self.ensure_verified_entry(address);
        let entry = &mut self.entries[idx];

        if let Some(candidate) = candidate {
            entry.first_advertised_at = if entry.first_advertised_at == 0 {
                candidate.first_advertised_at
            } else {
                entry.first_advertised_at.min(candidate.first_advertised_at)
            };
            entry.last_advertised_at = entry
                .last_advertised_at
                .max(candidate.last_advertised_at);
            for advertiser in candidate.advertisers {
                entry.add_advertiser_observation(advertiser);
            }
            for claim in candidate.account_creation_claims {
                entry.add_creation_claim(
                    claim.claimed_created_at,
                    claim.reported_by,
                    claim.last_observed_at,
                );
            }
        }

        entry.mark_authenticated(now);
        idx
    }

    pub fn mark_verification_failed(&mut self, address: &RecordKey, now: u64) {
        if let Some(idx) = self.get_candidate_index(address) {
            self.candidates[idx].mark_verification_failed(now);
        }
    }

    /// Remove a previously verified entry from the publishable set after a
    /// directly read identity record violates a hard invariant. Historical
    /// advertiser/creation claims are retained in the candidate pool, but the
    /// impossible direct value itself is not accepted as a creation claim.
    pub fn quarantine_failed_direct_verification(&mut self, address: &RecordKey, now: u64) {
        let previous = self.remove_by_address(address);
        let idx = self.ensure_candidate(address.clone(), now);
        if idx == usize::MAX {
            return;
        }

        let candidate = &mut self.candidates[idx];
        if let Some(previous) = previous {
            candidate.first_advertised_at = if previous.first_advertised_at == 0 {
                candidate.first_advertised_at
            } else {
                candidate.first_advertised_at.min(previous.first_advertised_at)
            };
            candidate.last_advertised_at = candidate
                .last_advertised_at
                .max(previous.last_advertised_at);

            for observation in previous.advertisers {
                candidate.add_advertiser(&observation.advertiser, observation.last_reported_at);
            }
            for claim in previous.account_creation_claims {
                candidate.add_creation_claim(
                    claim.claimed_created_at,
                    claim.reported_by,
                    claim.last_observed_at,
                );
            }
        }
        candidate.mark_verification_failed(now);
    }

    /// Build a cheap, time-aware snapshot for local dashboards. This is
    /// intentionally derived from structured topology state rather than parsed
    /// console text, so Online/Stale/Needs-refresh transitions remain correct
    /// even when no new log line has been emitted.
    pub fn network_summary_at(&self, now: u64) -> NetworkSummary {
        let mut summary = NetworkSummary {
            verified_nodes: self.entries.len(),
            candidate_nodes: self.candidates.len(),
            ..NetworkSummary::default()
        };
        let app_cutoff = now.saturating_sub(APP_DISCOVERY_ACTIVITY_TTL_SECS);

        for entry in &self.entries {
            if entry.verification_state == NodeVerificationState::Authenticated {
                summary.authenticated_nodes += 1;
            }
            match entry.presence_state_at(now) {
                NodePresenceState::Online => summary.online += 1,
                NodePresenceState::ExplicitlyOffline => summary.explicitly_offline += 1,
                NodePresenceState::StaleOnlineClaim => summary.stale_online_claim += 1,
                NodePresenceState::NeedsRefresh => summary.needs_refresh += 1,
                NodePresenceState::Unknown => summary.unknown += 1,
            }
            if entry.presence_checked_at == 0 {
                summary.presence_never_checked += 1;
            } else if entry.presence_read_succeeded {
                summary.presence_reads_ok += 1;
            } else {
                summary.presence_reads_failed += 1;
            }
            if entry.app_info_updated_at >= app_cutoff && !entry.application_ids.is_empty() {
                summary.active_app_headers += 1;
            }
            if entry.capability_flags & CAPABILITY_MAILBOX != 0 {
                summary.mailbox_capable += 1;
            }
        }
        summary
    }

    /// Count currently active canonical application advertisements among the
    /// curated verified node list. These counts are useful for a dashboard,
    /// but remain distinct from the broader disposable app-discovery cache.
    pub fn observed_application_counts_at(&self, now: u64) -> Vec<(String, usize)> {
        let cutoff = now.saturating_sub(APP_DISCOVERY_ACTIVITY_TTL_SECS);
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for entry in &self.entries {
            if !entry.is_publishable() || entry.app_info_updated_at < cutoff {
                continue;
            }
            for app_id in &entry.application_ids {
                *counts.entry(app_id.clone()).or_default() += 1;
            }
        }
        let mut counts: Vec<_> = counts.into_iter().collect();
        counts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        counts
    }

    pub fn verified_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.is_publishable())
            .count()
    }

    /// Scale how much one advertiser may inject as the directly verified
    /// network grows. The early network can depend heavily on one or two
    /// bootstraps; a mature network demands much broader source diversity.
    pub fn adaptive_candidate_limit_per_advertiser(&self) -> usize {
        match self.verified_count() {
            0..=2 => 256,
            3..=5 => 201,
            6..=25 => 128,
            26..=100 => 64,
            _ => 32,
        }
    }

    pub fn add_advertised_candidates(
        &mut self,
        advertiser: &RecordKey,
        advertised: Vec<RecordTableEntry>,
        own_dht: &RecordKey,
        now: u64,
    ) -> CandidateInsertReport {
        let mut report = CandidateInsertReport::default();
        let per_source_limit = self.adaptive_candidate_limit_per_advertiser();
        let existing_from_source = self
            .candidates
            .iter()
            .filter(|candidate| {
                candidate
                    .advertisers
                    .iter()
                    .any(|source| &source.advertiser == advertiser)
            })
            .count();
        let mut remaining_new = per_source_limit.saturating_sub(existing_from_source);

        let mut deduplicated: HashMap<String, RecordTableEntry> = HashMap::new();
        for entry in advertised {
            if &entry.their_address == own_dht || &entry.their_address == advertiser {
                continue;
            }
            deduplicated
                .entry(entry.their_address.to_string())
                .or_insert(entry);
        }

        // Deterministic sampling prevents a remote peer from controlling which
        // values survive the source cap merely by ordering its serialized list.
        let epoch = now / PUBLISH_RANDOM_ROTATION_SECS;
        let mut entries: Vec<RecordTableEntry> = deduplicated.into_values().collect();
        entries.sort_by_key(|entry| topology_hash(advertiser, &entry.their_address, epoch));

        let latest_allowed = now.saturating_add(PUBLIC_METADATA_MAX_FUTURE_SKEW_SECS);

        for remote in entries {
            let address = remote.their_address.clone();
            let plausible_claim = (remote.account_created_at != 0
                && remote.account_created_at <= latest_allowed)
                .then_some(remote.account_created_at);

            if remote.account_created_at > latest_allowed {
                report.implausible_creation_claims.push(address.clone());
            }

            if let Some(idx) = self.get_index(&address) {
                let entry = &mut self.entries[idx];
                entry.last_advertised_at = entry.last_advertised_at.max(now);
                entry.add_advertiser_observation(AdvertiserObservation {
                    advertiser: advertiser.clone(),
                    first_reported_at: now,
                    last_reported_at: now,
                    report_count: 1,
                });
                if let Some(claim) = plausible_claim {
                    entry.add_creation_claim(claim, Some(advertiser.clone()), now);
                }
                report.refreshed += 1;
                continue;
            }

            if let Some(idx) = self.get_candidate_index(&address) {
                let candidate = &mut self.candidates[idx];
                candidate.last_advertised_at = now;
                candidate.add_advertiser(advertiser, now);
                if let Some(claim) = plausible_claim {
                    candidate.add_creation_claim(claim, Some(advertiser.clone()), now);
                }
                report.refreshed += 1;
                if candidate.is_due_at(now) {
                    report.accepted.push(address);
                }
                continue;
            }

            if remaining_new == 0 {
                report.ignored_by_source_limit += 1;
                continue;
            }

            let idx = self.ensure_candidate(address.clone(), now);
            if idx == usize::MAX {
                continue;
            }
            let candidate = &mut self.candidates[idx];
            candidate.add_advertiser(advertiser, now);
            if let Some(claim) = plausible_claim {
                candidate.add_creation_claim(claim, Some(advertiser.clone()), now);
            }
            remaining_new -= 1;
            report.new_candidates += 1;
            report.accepted.push(address);
        }

        report
    }

    pub fn candidate_targets(&self, own_dht: &RecordKey) -> Vec<RecordKey> {
        let now = current_timestamp();
        let mut targets = Vec::with_capacity(self.candidates.len() + self.entries.len());

        // Unverified candidates are intentionally included so a walk can turn
        // advertisements into direct evidence. Favor source-diverse candidates
        // and those not currently in failure backoff.
        let mut candidates: Vec<&CandidateEntry> = self
            .candidates
            .iter()
            .filter(|candidate| &candidate.their_address != own_dht && candidate.is_due_at(now))
            .collect();
        candidates.sort_by(|a, b| {
            b.advertisers
                .len()
                .cmp(&a.advertisers.len())
                .then_with(|| a.failed_verifications.cmp(&b.failed_verifications))
                .then_with(|| b.last_advertised_at.cmp(&a.last_advertised_at))
        });
        targets.extend(
            candidates
                .into_iter()
                .map(|candidate| candidate.their_address.clone()),
        );

        let mut verified: Vec<&ListEntry> = self
            .entries
            .iter()
            .filter(|entry| &entry.their_address != own_dht && entry.is_publishable())
            .collect();
        verified.sort_by(|a, b| {
            b.is_advertised_online_at(now)
                .cmp(&a.is_advertised_online_at(now))
                .then_with(|| b.last_authenticated_at.cmp(&a.last_authenticated_at))
                .then_with(|| b.last_direct_dht_read_at.cmp(&a.last_direct_dht_read_at))
        });
        targets.extend(verified.into_iter().map(|entry| entry.their_address.clone()));
        targets
    }

    /// Build the mixed, publishable routing-table composition:
    /// 40% closest, 20% spread across farther distance buckets, 20% recently
    /// authenticated, 10% credible under-replicated, and 10% rotating random.
    pub fn record_table_entries_for_publish(
        &self,
        own_dht: &RecordKey,
        limit: usize,
    ) -> Vec<RecordTableEntry> {
        if limit == 0 {
            return Vec::new();
        }

        let now = current_timestamp();
        let Some(own_key) = KeyInt::from_record_key(own_dht) else {
            return self
                .entries
                .iter()
                .filter(|entry| entry.is_publishable() && &entry.their_address != own_dht)
                .take(limit)
                .map(ListEntry::to_record_table_entry)
                .collect();
        };

        let publishable: Vec<&ListEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.is_publishable() && &entry.their_address != own_dht)
            .collect();

        let mut by_distance: Vec<(&ListEntry, KeyInt)> = publishable
            .iter()
            .filter_map(|entry| {
                KeyInt::from_record_key(&entry.their_address)
                    .map(|key| (*entry, own_key.xor_dist(&key)))
            })
            .collect();
        by_distance.sort_by(|(_, left), (_, right)| left.cmp(right));

        let closest_quota = limit.saturating_mul(40) / 100;
        let far_quota = limit.saturating_mul(20) / 100;
        let authenticated_quota = limit.saturating_mul(20) / 100;
        let under_replicated_quota = limit.saturating_mul(10) / 100;
        let random_quota = limit
            .saturating_sub(closest_quota)
            .saturating_sub(far_quota)
            .saturating_sub(authenticated_quota)
            .saturating_sub(under_replicated_quota);

        let mut selected = Vec::<&ListEntry>::with_capacity(limit);
        let mut selected_keys = HashSet::<String>::new();

        select_unique(
            by_distance.iter().take(closest_quota).map(|(entry, _)| *entry),
            closest_quota,
            &mut selected,
            &mut selected_keys,
        );

        // Quantile sampling spreads this slice over the rest of the keyspace
        // rather than selecting only the absolute farthest tail.
        let remaining_distance = by_distance.len().saturating_sub(closest_quota);
        if remaining_distance != 0 && far_quota != 0 {
            let spread = (0..far_quota).filter_map(|slot| {
                let offset = ((slot + 1) * remaining_distance) / (far_quota + 1);
                by_distance
                    .get(closest_quota + offset.min(remaining_distance - 1))
                    .map(|(entry, _)| *entry)
            });
            select_unique(
                spread,
                far_quota,
                &mut selected,
                &mut selected_keys,
            );
        }

        let mut authenticated = publishable.clone();
        authenticated.sort_by(|a, b| {
            b.last_authenticated_at
                .cmp(&a.last_authenticated_at)
                .then_with(|| b.last_direct_dht_read_at.cmp(&a.last_direct_dht_read_at))
        });
        select_unique(
            authenticated.into_iter().filter(|entry| entry.last_authenticated_at != 0),
            authenticated_quota,
            &mut selected,
            &mut selected_keys,
        );

        let mut under_replicated: Vec<&ListEntry> = publishable
            .iter()
            .copied()
            .filter(|entry| {
                let old_enough = entry.account_created_at.is_some_and(|created_at| {
                    now.saturating_sub(created_at) >= UNDER_REPLICATED_MIN_ACCOUNT_AGE_SECS
                });
                let recently_verified = now.saturating_sub(entry.last_direct_dht_read_at)
                    <= RECENT_DIRECT_VERIFICATION_SECS
                    || now.saturating_sub(entry.last_authenticated_at)
                        <= RECENT_DIRECT_VERIFICATION_SECS;
                old_enough && recently_verified && !entry.account_creation_is_contested()
            })
            .collect();
        under_replicated.sort_by(|a, b| {
            a.advertisers
                .len()
                .cmp(&b.advertisers.len())
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        });
        select_unique(
            under_replicated,
            under_replicated_quota,
            &mut selected,
            &mut selected_keys,
        );

        let epoch = now / PUBLISH_RANDOM_ROTATION_SECS;
        let mut random = publishable.clone();
        random.sort_by_key(|entry| topology_hash(own_dht, &entry.their_address, epoch));
        select_unique(
            random,
            random_quota,
            &mut selected,
            &mut selected_keys,
        );

        // Fill any unused quota from the healthiest recently verified entries.
        let mut fallback = publishable;
        fallback.sort_by(|a, b| {
            b.last_authenticated_at
                .max(b.last_direct_dht_read_at)
                .cmp(&a.last_authenticated_at.max(a.last_direct_dht_read_at))
                .then_with(|| b.advertisers.len().cmp(&a.advertisers.len()))
        });
        select_unique(
            fallback,
            limit.saturating_sub(selected.len()),
            &mut selected,
            &mut selected_keys,
        );

        selected
            .into_iter()
            .take(limit)
            .map(ListEntry::to_record_table_entry)
            .collect()
    }

    pub fn truncate_to_budget(&mut self, max_entries: usize) {
        if self.entries.len() <= max_entries {
            return;
        }
        self.entries.sort_by(|a, b| {
            b.verification_state
                .cmp(&a.verification_state)
                .then_with(|| b.last_authenticated_at.cmp(&a.last_authenticated_at))
                .then_with(|| b.last_direct_dht_read_at.cmp(&a.last_direct_dht_read_at))
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        });
        self.entries.truncate(max_entries);
        self.rebuild_index();
    }

    pub fn truncate_candidates_to_budget(&mut self, max_candidates: usize) {
        if self.candidates.len() <= max_candidates {
            return;
        }
        self.candidates.sort_by(|a, b| {
            b.advertisers
                .len()
                .cmp(&a.advertisers.len())
                .then_with(|| a.failed_verifications.cmp(&b.failed_verifications))
                .then_with(|| b.last_advertised_at.cmp(&a.last_advertised_at))
        });
        self.candidates.truncate(max_candidates);
        self.rebuild_index();
    }

    /// Record a directly verified future creation timestamp. Once a cohort of
    /// distinct nodes reaches the threshold inside the observation window, the
    /// newly implicated identities are returned for a temporary network ban.
    pub fn record_future_creation_event(
        &mut self,
        node: RecordKey,
        claimed_created_at: u64,
        now: u64,
        cohort_window_secs: u64,
        cohort_threshold: usize,
    ) -> Vec<RecordKey> {
        self.future_creation_events.retain(|event| {
            now.saturating_sub(event.first_detected_at) <= cohort_window_secs
        });

        if let Some(existing) = self
            .future_creation_events
            .iter_mut()
            .find(|event| event.node == node)
        {
            existing.claimed_created_at = claimed_created_at;
        } else {
            if self.future_creation_events.len() >= MAX_FUTURE_CREATION_EVENTS {
                self.future_creation_events
                    .sort_by_key(|event| event.first_detected_at);
                self.future_creation_events.remove(0);
            }
            self.future_creation_events.push(FutureCreationEvent {
                node,
                claimed_created_at,
                first_detected_at: now,
                cluster_ban_requested: false,
            });
        }

        if self.future_creation_events.len() < cohort_threshold {
            return Vec::new();
        }

        let mut newly_flagged = Vec::new();
        for event in &mut self.future_creation_events {
            if !event.cluster_ban_requested {
                event.cluster_ban_requested = true;
                newly_flagged.push(event.node.clone());
            }
        }
        newly_flagged
    }

    pub fn remove_by_address(&mut self, address: &RecordKey) -> Option<ListEntry> {
        let remove_idx = self.address_to_index.remove(&address.to_string())?;
        let removed = self.entries.swap_remove(remove_idx);
        if let Some(moved) = self.entries.get(remove_idx) {
            self.address_to_index
                .insert(moved.their_address.to_string(), remove_idx);
        }
        Some(removed)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn candidate_len(&self) -> usize {
        self.candidates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.candidates.is_empty()
    }
}

impl Default for InternalNodeList {
    fn default() -> Self {
        Self::new()
    }
}

fn topology_hash(source: &RecordKey, target: &RecordKey, epoch: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(source.to_string().as_bytes());
    hasher.update(&[0]);
    hasher.update(target.to_string().as_bytes());
    hasher.update(&epoch.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn select_unique<'a>(
    entries: impl IntoIterator<Item = &'a ListEntry>,
    quota: usize,
    selected: &mut Vec<&'a ListEntry>,
    selected_keys: &mut HashSet<String>,
) {
    if quota == 0 {
        return;
    }
    let start = selected.len();
    for entry in entries {
        if selected.len().saturating_sub(start) >= quota {
            break;
        }
        if selected_keys.insert(entry.their_address.to_string()) {
            selected.push(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_ONE: &str = "VLD0:Ql5L4_BYpaHtBECl5khtcSIW-lAnnC5vV5PIZCl7vAs:9C9jBokYTHBBBaq7aev39a9ujPVCCzGLE0-Tx_N7FyQ";
    const KEY_TWO: &str = "VLD0:_kOiks1ZUX1EWMHhhCW8VVkHFiA8dAHZi8FwjPfPluA:zn52H-kRgsgzeVYabmSf4D15el-73HwVJ6o84RipMPc";
    const KEY_THREE: &str = "VLD0:oo6O7ARQzIFY1WpCexdvjPQIHnnIGM4GbE0inFgIpSo:AjUYaMkyRdqK6OqVpH5toKtekBiQQ197N27DQBaT0s0";

    fn key(value: &str) -> RecordKey {
        value.parse().unwrap()
    }

    #[test]
    fn built_in_bootstrap_list_contains_project_node() {
        assert!(DEFAULT_BOOTSTRAP_DHTS.contains(&"VLD0:qshUK5zVzIHg8dWfUSxkNRgBLNW_raHtb7p-vkgXPyM:FGmx1nvBk8gLIRlQBjTeI40iMmVYg3cMwlhwXkL7d-w"));
        assert!(DEFAULT_BOOTSTRAP_DHTS.contains(&"VLD0:iTSsX9dTxOQTscWBOJuT4ki9YF1SMtobgc3TrjNQcG4:ozKa2wGPPY1-tAf4wrNXcgMJvdCPqU0Srx9cB502UFc"));
    }

    #[test]
    fn advertised_nodes_are_not_publishable() {
        let own = key(KEY_ONE);
        let remote = key(KEY_TWO);
        let mut list = InternalNodeList::new();
        list.ensure_candidate(remote, current_timestamp());
        assert!(list.record_table_entries_for_publish(&own, 201).is_empty());
    }

    #[test]
    fn direct_verification_promotes_candidate() {
        let own = key(KEY_ONE);
        let remote = key(KEY_TWO);
        let mut list = InternalNodeList::new();
        list.ensure_candidate(remote.clone(), current_timestamp());
        list.promote_dht_verified(remote.clone(), Some(100), current_timestamp());
        let published = list.record_table_entries_for_publish(&own, 201);
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].their_address, remote);
    }

    #[test]
    fn failed_direct_invariant_quarantines_verified_node() {
        let own = key(KEY_ONE);
        let remote = key(KEY_TWO);
        let mut list = InternalNodeList::new();
        let now = current_timestamp();
        list.promote_dht_verified(remote.clone(), Some(now.saturating_sub(100)), now);
        assert_eq!(list.record_table_entries_for_publish(&own, 201).len(), 1);

        list.quarantine_failed_direct_verification(&remote, now.saturating_add(1));
        assert!(list.get_by_address(&remote).is_none());
        assert!(list.get_candidate_index(&remote).is_some());
        assert!(list.record_table_entries_for_publish(&own, 201).is_empty());
    }

    #[test]
    fn future_creation_cohort_flags_only_after_threshold() {
        let mut list = InternalNodeList::new();
        let one = key(KEY_ONE);
        let two = key(KEY_TWO);
        let now = current_timestamp();
        assert!(list
            .record_future_creation_event(one.clone(), now + 10_000, now, 600, 2)
            .is_empty());
        let flagged = list.record_future_creation_event(two.clone(), now + 10_000, now, 600, 2);
        assert_eq!(flagged.len(), 2);
        assert!(flagged.contains(&one));
        assert!(flagged.contains(&two));
    }

    #[test]
    fn remote_observation_timestamps_do_not_become_local_facts() {
        let own = key(KEY_ONE);
        let advertiser = key(KEY_TWO);
        let remote = key(KEY_THREE);
        let mut list = InternalNodeList::new();
        let now = current_timestamp();
        list.add_advertised_candidates(
            &advertiser,
            vec![RecordTableEntry {
                their_address: remote.clone(),
                account_created_at: now.saturating_sub(100),
                last_update: u64::MAX,
                app_bloom: crate::types::AppBloomFilter::default(),
                mailbox_range: (0, 0),
                mailbox_inlist: [0; 4],
                routingtable_minhash: [0; 4],
                first_seen: u64::MAX,
                last_seen: u64::MAX,
                seen_in: Vec::new(),
            }],
            &own,
            now,
        );
        assert!(list.get_by_address(&remote).is_none());
        let candidate = &list.candidates[list.get_candidate_index(&remote).unwrap()];
        assert_eq!(candidate.first_advertised_at, now);
        assert_eq!(candidate.last_advertised_at, now);
    }
}

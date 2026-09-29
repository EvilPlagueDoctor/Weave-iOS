//! Bounded, disposable application-peer discovery cache.
//!
//! This cache is deliberately separate from the curated routing/node list.
//! The routing list optimizes network health; this cache optimizes novelty for
//! applications that need to cycle through many public identities. Entries are
//! direct AppInfo observations only, never unverified referrals.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use veilid_core::RecordKey;

use crate::{
    types::APP_DISCOVERY_ACTIVITY_TTL_SECS,
    user_auth::{UserAuth, UserSession},
};

pub const APP_DISCOVERY_STORE_KEY: &str = "app_discovery_cache";
pub const APP_DISCOVERY_CACHE_VERSION: u16 = 1;
pub const APP_DISCOVERY_RECENT_CAPACITY: usize = 3_072;
pub const APP_DISCOVERY_ARCHIVE_CAPACITY: usize = 1_024;
pub const APP_DISCOVERY_PER_APP_CAPACITY: usize =
    APP_DISCOVERY_RECENT_CAPACITY + APP_DISCOVERY_ARCHIVE_CAPACITY;
pub const APP_DISCOVERY_GLOBAL_ASSOCIATION_CAPACITY: usize = 24_576;
pub const APP_DISCOVERY_GLOBAL_PEER_CAPACITY: usize = 24_576;
pub const APP_DISCOVERY_MAX_API_RESULTS: usize = 1_000;
pub const APP_DISCOVERY_MAX_SEARCH_SEEDS: usize = 256;

const APP_FINGERPRINT_DOMAIN: &[u8] = b"veilknit/app-name-fingerprint/v1";
const ARCHIVE_SAMPLE_DOMAIN: &[u8] = b"veilknit/app-discovery-archive/v1";

/// Hash the exact canonical application name. A protocol/version number can be
/// part of the string itself, for example `veilknit.veilyshort.v1`.
pub fn app_fingerprint(app_id: &str) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(APP_FINGERPRINT_DOMAIN);
    hasher.update(&(app_id.len() as u32).to_le_bytes());
    hasher.update(app_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppPeerTier {
    Recent,
    Archive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPeerRecord {
    pub peer_id: u64,
    pub first_discovered_at: u64,
    pub last_directly_verified_at: u64,
    pub last_app_info_updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPeerMembership {
    pub peer_id: u64,
    pub first_seen_for_app: u64,
    pub last_verified_for_app: u64,
    pub last_returned_at: u64,
    pub return_count: u32,
    /// Lazily resolved app-defined root DHT. `None` plus a non-zero
    /// `app_root_checked_at` means the peer was checked and did not publish a
    /// root for this exact app id.
    #[serde(default)]
    pub app_root_dht: Option<String>,
    #[serde(default)]
    pub app_root_checked_at: u64,
    #[serde(default)]
    pub app_directory_generation: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppPeerSet {
    pub total_verified_observations: u64,
    pub recent: Vec<AppPeerMembership>,
    pub archive: Vec<AppPeerMembership>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDiscoveryState {
    pub version: u16,
    pub generation: u64,
    pub next_peer_id: u64,
    pub interested_apps: HashMap<String, u64>,
    pub peers: HashMap<String, AppPeerRecord>,
    pub apps: HashMap<String, AppPeerSet>,
}

impl Default for AppDiscoveryState {
    fn default() -> Self {
        Self {
            version: APP_DISCOVERY_CACHE_VERSION,
            generation: 0,
            next_peer_id: 1,
            interested_apps: HashMap::new(),
            peers: HashMap::new(),
            apps: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppPeerResult {
    pub main_dht: RecordKey,
    pub first_discovered_at: u64,
    pub last_directly_verified_at: u64,
    pub last_returned_at: u64,
    pub return_count: u32,
    pub tier: AppPeerTier,
    pub app_root_dht: Option<RecordKey>,
    pub app_root_checked_at: u64,
    pub app_directory_generation: u64,
}

#[derive(Debug, Clone)]
pub enum AppRootCacheState {
    Unknown,
    Found {
        root_dht: RecordKey,
        checked_at: u64,
        directory_generation: u64,
    },
    NotPublished {
        checked_at: u64,
        directory_generation: u64,
    },
}

#[derive(Debug, Clone)]
pub struct AppPeerPage {
    pub generation: u64,
    pub total_cached: usize,
    pub peers: Vec<AppPeerResult>,
}

/// Compact dashboard view of one locally interesting application's disposable
/// discovery cache. This intentionally contains counts only, never peer keys.
#[derive(Debug, Clone)]
pub struct AppDiscoveryAppSummary {
    pub app_id: String,
    pub recent_peers: usize,
    pub archive_peers: usize,
    pub total_cached: usize,
    pub total_verified_observations: u64,
}

#[derive(Clone)]
pub struct AppDiscoveryCache {
    inner: Arc<RwLock<AppDiscoveryState>>,
    auth: Option<Arc<UserAuth>>,
    session: Option<Arc<UserSession>>,
}

impl AppDiscoveryCache {
    pub fn load(auth: Option<Arc<UserAuth>>, session: Option<Arc<UserSession>>) -> Self {
        let state = match (&auth, &session) {
            (Some(auth), Some(session)) => auth
                .read_user_encrypted::<AppDiscoveryState>(session, APP_DISCOVERY_STORE_KEY)
                .ok()
                .flatten()
                .filter(|state| state.version == APP_DISCOVERY_CACHE_VERSION)
                .unwrap_or_default(),
            _ => AppDiscoveryState::default(),
        };
        Self {
            inner: Arc::new(RwLock::new(state)),
            auth,
            session,
        }
    }

    pub async fn persist(&self) -> Result<(), String> {
        let (Some(auth), Some(session)) = (&self.auth, &self.session) else {
            return Ok(());
        };
        let state = self.inner.read().await.clone();
        auth.write_user_encrypted(session, APP_DISCOVERY_STORE_KEY, &state)
            .map_err(|error| error.to_string())
    }

    /// Register a locally authenticated application's interest. Normal walks
    /// retain observations only for requested local apps, preventing arbitrary
    /// remote app-name advertisements from consuming the global cache.
    pub async fn register_interest(&self, app_id: &str, now: u64) -> bool {
        let mut state = self.inner.write().await;
        let cutoff = now.saturating_sub(APP_DISCOVERY_ACTIVITY_TTL_SECS);
        let previous = state.interested_apps.insert(app_id.to_string(), now);
        let newly_active = previous.map_or(true, |last_requested_at| last_requested_at < cutoff);
        if previous != Some(now) {
            state.generation = state.generation.saturating_add(1).max(1);
        }
        newly_active
    }

    /// Apply a directly read AppInfo set for one peer. Missing app names are
    /// removed for that peer because the direct record is authoritative.
    pub async fn observe_direct_app_set(
        &self,
        peer: &RecordKey,
        application_ids: &[String],
        app_info_updated_at: u64,
        directly_verified_at: u64,
        now: u64,
    ) -> bool {
        let peer_text = peer.to_string();
        let verified_at = directly_verified_at.min(now);
        let mut state = self.inner.write().await;
        let mut changed = prune_expired_locked(&mut state, now);
        let advertised: HashSet<String> = application_ids
            .iter()
            .filter(|app_id| state.interested_apps.contains_key(app_id.as_str()))
            .cloned()
            .collect();
        if state
            .peers
            .get(&peer_text)
            .is_some_and(|record| app_info_updated_at < record.last_app_info_updated_at)
        {
            if changed {
                state.generation = state.generation.saturating_add(1).max(1);
            }
            return changed;
        }
        let existing_peer_id = state.peers.get(&peer_text).map(|record| record.peer_id);

        // A direct AppInfo read is authoritative for this peer. Remove any
        // cached app membership that is no longer present in the record.
        for (app_id, set) in state.apps.iter_mut() {
            if advertised.contains(app_id) {
                continue;
            }
            let before_recent = set.recent.len();
            let before_archive = set.archive.len();
            set.recent
                .retain(|membership| Some(membership.peer_id) != existing_peer_id);
            set.archive
                .retain(|membership| Some(membership.peer_id) != existing_peer_id);
            changed |= before_recent != set.recent.len() || before_archive != set.archive.len();
        }

        // Keep a bounded tombstone for a peer that used to be cached. This
        // prevents an older AppInfo generation from reintroducing a membership
        // immediately after a newer direct read removed it.
        if advertised.is_empty() {
            if let Some(record) = state.peers.get_mut(&peer_text) {
                let newest_verification = record.last_directly_verified_at.max(verified_at);
                if record.last_directly_verified_at != newest_verification
                    || record.last_app_info_updated_at != app_info_updated_at
                {
                    record.last_directly_verified_at = newest_verification;
                    record.last_app_info_updated_at = app_info_updated_at;
                    changed = true;
                }
            }
            changed |= enforce_peer_capacity_locked(&mut state);
            if changed {
                state.generation = state.generation.saturating_add(1).max(1);
            }
            return changed;
        }

        let was_known = state.peers.contains_key(&peer_text);
        let peer_id = match existing_peer_id {
            Some(peer_id) => peer_id,
            None => {
                let peer_id = state.next_peer_id.max(1);
                state.next_peer_id = peer_id.checked_add(1).unwrap_or(1);
                peer_id
            }
        };
        let record = state
            .peers
            .entry(peer_text.clone())
            .or_insert_with(|| AppPeerRecord {
                peer_id,
                first_discovered_at: verified_at,
                last_directly_verified_at: verified_at,
                last_app_info_updated_at: app_info_updated_at,
            });
        let newest_verification = record.last_directly_verified_at.max(verified_at);
        if !was_known
            || record.last_directly_verified_at != newest_verification
            || record.last_app_info_updated_at != app_info_updated_at
        {
            record.last_directly_verified_at = newest_verification;
            record.last_app_info_updated_at = app_info_updated_at;
            changed = true;
        }

        for app_id in advertised {
            if observe_membership_locked(&mut state, &app_id, peer_id, verified_at) {
                changed = true;
            }
        }

        changed |= enforce_global_capacity_locked(&mut state);
        changed |= enforce_peer_capacity_locked(&mut state);
        if changed {
            state.generation = state.generation.saturating_add(1).max(1);
        }
        changed
    }

    /// Return counts for each app currently represented in the bounded
    /// disposable cache. The cache contains only directly verified app
    /// observations for locally interested apps.
    pub async fn app_summaries(&self, now: u64) -> Vec<AppDiscoveryAppSummary> {
        let mut state = self.inner.write().await;
        let changed = prune_expired_locked(&mut state, now);
        if changed {
            state.generation = state.generation.saturating_add(1).max(1);
        }
        let mut summaries: Vec<_> = state
            .apps
            .iter()
            .map(|(app_id, set)| AppDiscoveryAppSummary {
                app_id: app_id.clone(),
                recent_peers: set.recent.len(),
                archive_peers: set.archive.len(),
                total_cached: set.recent.len() + set.archive.len(),
                total_verified_observations: set.total_verified_observations,
            })
            .collect();
        summaries.sort_by(|left, right| {
            right
                .total_cached
                .cmp(&left.total_cached)
                .then_with(|| left.app_id.cmp(&right.app_id))
        });
        summaries
    }

    pub async fn list_peers(&self, app_id: &str, requested_limit: usize, now: u64) -> AppPeerPage {
        let limit = requested_limit.clamp(1, APP_DISCOVERY_MAX_API_RESULTS);
        let mut state = self.inner.write().await;
        let mut changed = prune_expired_locked(&mut state, now);
        let peer_records: HashMap<u64, (String, AppPeerRecord)> = state
            .peers
            .iter()
            .map(|(address, record)| (record.peer_id, (address.clone(), record.clone())))
            .collect();
        let Some(set) = state.apps.get_mut(app_id) else {
            if changed {
                state.generation = state.generation.saturating_add(1).max(1);
            }
            return AppPeerPage {
                generation: state.generation,
                total_cached: 0,
                peers: Vec::new(),
            };
        };

        set.recent.sort_by_key(return_priority);
        set.archive.sort_by_key(return_priority);

        let desired_recent = (limit * 4 + 4) / 5;
        let mut selected: Vec<(AppPeerTier, usize)> = Vec::with_capacity(limit);
        selected.extend(
            (0..set.recent.len().min(desired_recent)).map(|index| (AppPeerTier::Recent, index)),
        );
        let archive_needed = limit.saturating_sub(selected.len());
        selected.extend(
            (0..set.archive.len().min(archive_needed)).map(|index| (AppPeerTier::Archive, index)),
        );
        if selected.len() < limit {
            let start = selected
                .iter()
                .filter(|(tier, _)| *tier == AppPeerTier::Recent)
                .count();
            selected.extend(
                (start..set.recent.len().min(start + limit - selected.len()))
                    .map(|index| (AppPeerTier::Recent, index)),
            );
        }
        if selected.len() < limit {
            let start = selected
                .iter()
                .filter(|(tier, _)| *tier == AppPeerTier::Archive)
                .count();
            selected.extend(
                (start..set.archive.len().min(start + limit - selected.len()))
                    .map(|index| (AppPeerTier::Archive, index)),
            );
        }

        let mut peers = Vec::with_capacity(selected.len());
        for (tier, index) in selected {
            let membership = match tier {
                AppPeerTier::Recent => &mut set.recent[index],
                AppPeerTier::Archive => &mut set.archive[index],
            };
            let previous_returned = membership.last_returned_at;
            let previous_count = membership.return_count;
            membership.last_returned_at = now;
            membership.return_count = membership.return_count.saturating_add(1);
            changed |= previous_returned != now || previous_count != membership.return_count;

            let Some((address, record)) = peer_records.get(&membership.peer_id) else {
                continue;
            };
            let Ok(main_dht) = address.parse::<RecordKey>() else {
                continue;
            };
            peers.push(AppPeerResult {
                main_dht,
                first_discovered_at: record.first_discovered_at,
                last_directly_verified_at: membership.last_verified_for_app,
                last_returned_at: previous_returned,
                return_count: previous_count,
                tier,
                app_root_dht: membership
                    .app_root_dht
                    .as_deref()
                    .and_then(|value| value.parse::<RecordKey>().ok()),
                app_root_checked_at: membership.app_root_checked_at,
                app_directory_generation: membership.app_directory_generation,
            });
        }

        let total_cached = set.recent.len() + set.archive.len();
        if changed {
            state.generation = state.generation.saturating_add(1).max(1);
        }
        let generation = state.generation;
        AppPeerPage {
            generation,
            total_cached,
            peers,
        }
    }

    /// Return the cached app-root state for a peer already verified for this
    /// exact application. `None` means the peer is not in this app's cache and
    /// cannot be used as an arbitrary directory-scanning target.
    pub async fn app_root_cache_state(
        &self,
        app_id: &str,
        peer: &RecordKey,
    ) -> Option<AppRootCacheState> {
        let state = self.inner.read().await;
        let peer_id = state.peers.get(&peer.to_string())?.peer_id;
        let set = state.apps.get(app_id)?;
        let membership = set
            .recent
            .iter()
            .chain(set.archive.iter())
            .find(|membership| membership.peer_id == peer_id)?;
        if membership.app_root_checked_at == 0 {
            return Some(AppRootCacheState::Unknown);
        }
        match membership
            .app_root_dht
            .as_deref()
            .and_then(|value| value.parse::<RecordKey>().ok())
        {
            Some(root_dht) => Some(AppRootCacheState::Found {
                root_dht,
                checked_at: membership.app_root_checked_at,
                directory_generation: membership.app_directory_generation,
            }),
            None => Some(AppRootCacheState::NotPublished {
                checked_at: membership.app_root_checked_at,
                directory_generation: membership.app_directory_generation,
            }),
        }
    }

    /// Store an authoritative lazy lookup result. The membership must already
    /// exist from a direct AppInfo observation; root resolution never creates
    /// an app peer by itself.
    pub async fn cache_app_root(
        &self,
        app_id: &str,
        peer: &RecordKey,
        root_dht: Option<&RecordKey>,
        directory_generation: u64,
        checked_at: u64,
    ) -> bool {
        let mut state = self.inner.write().await;
        let Some(peer_id) = state.peers.get(&peer.to_string()).map(|record| record.peer_id) else {
            return false;
        };
        let Some(set) = state.apps.get_mut(app_id) else {
            return false;
        };
        let Some(membership) = set
            .recent
            .iter_mut()
            .chain(set.archive.iter_mut())
            .find(|membership| membership.peer_id == peer_id)
        else {
            return false;
        };
        let root_text = root_dht.map(ToString::to_string);
        let changed = membership.app_root_dht != root_text
            || membership.app_root_checked_at != checked_at
            || membership.app_directory_generation != directory_generation;
        if changed {
            membership.app_root_dht = root_text;
            membership.app_root_checked_at = checked_at;
            membership.app_directory_generation = directory_generation;
            state.generation = state.generation.saturating_add(1).max(1);
        }
        changed
    }

    pub async fn search_seeds(&self, app_id: &str, max: usize, now: u64) -> Vec<RecordKey> {
        let mut state = self.inner.write().await;
        let changed = prune_expired_locked(&mut state, now);
        if changed {
            state.generation = state.generation.saturating_add(1).max(1);
        }
        let addresses_by_id: HashMap<u64, String> = state
            .peers
            .iter()
            .map(|(address, record)| (record.peer_id, address.clone()))
            .collect();
        let Some(set) = state.apps.get(app_id) else {
            return Vec::new();
        };
        let mut memberships: Vec<&AppPeerMembership> =
            set.recent.iter().chain(set.archive.iter()).collect();
        memberships.sort_by_key(|membership| {
            (
                membership.last_returned_at,
                std::cmp::Reverse(membership.last_verified_for_app),
                membership.peer_id,
            )
        });
        memberships
            .into_iter()
            .filter_map(|membership| {
                addresses_by_id
                    .get(&membership.peer_id)
                    .and_then(|address| address.parse::<RecordKey>().ok())
            })
            .take(max.min(APP_DISCOVERY_MAX_SEARCH_SEEDS))
            .collect()
    }

    pub async fn remove_peers(&self, peers: &[RecordKey]) -> bool {
        if peers.is_empty() {
            return false;
        }
        let blocked: HashSet<String> = peers.iter().map(ToString::to_string).collect();
        let mut state = self.inner.write().await;
        let blocked_ids: HashSet<u64> = blocked
            .iter()
            .filter_map(|address| state.peers.get(address).map(|record| record.peer_id))
            .collect();
        let before_peers = state.peers.len();
        state.peers.retain(|key, _| !blocked.contains(key));
        let mut changed = before_peers != state.peers.len();
        for set in state.apps.values_mut() {
            let before = set.recent.len() + set.archive.len();
            set.recent.retain(|item| !blocked_ids.contains(&item.peer_id));
            set.archive.retain(|item| !blocked_ids.contains(&item.peer_id));
            changed |= before != set.recent.len() + set.archive.len();
        }
        state.apps.retain(|_, set| !set.recent.is_empty() || !set.archive.is_empty());
        if changed {
            state.generation = state.generation.saturating_add(1).max(1);
        }
        changed
    }
}

fn observe_membership_locked(
    state: &mut AppDiscoveryState,
    app_id: &str,
    peer_id: u64,
    now: u64,
) -> bool {
    let set = state.apps.entry(app_id.to_string()).or_default();
    if let Some(existing) = set
        .recent
        .iter_mut()
        .chain(set.archive.iter_mut())
        .find(|membership| membership.peer_id == peer_id)
    {
        if now > existing.last_verified_for_app {
            existing.last_verified_for_app = now;
            return true;
        }
        return false;
    }

    set.total_verified_observations = set.total_verified_observations.saturating_add(1);
    let new_membership = AppPeerMembership {
        peer_id,
        first_seen_for_app: now,
        last_verified_for_app: now,
        last_returned_at: 0,
        return_count: 0,
        app_root_dht: None,
        app_root_checked_at: 0,
        app_directory_generation: 0,
    };

    if set.recent.len() < APP_DISCOVERY_RECENT_CAPACITY {
        set.recent.push(new_membership);
        return true;
    }

    let displaced_index = set
        .recent
        .iter()
        .enumerate()
        .max_by_key(|(_, membership)| {
            (
                membership.last_returned_at,
                membership.return_count,
                std::cmp::Reverse(membership.first_seen_for_app),
            )
        })
        .map(|(index, _)| index)
        .unwrap_or(0);
    let displaced = std::mem::replace(&mut set.recent[displaced_index], new_membership);
    consider_archive_locked(app_id, set, displaced);
    true
}

fn consider_archive_locked(app_id: &str, set: &mut AppPeerSet, membership: AppPeerMembership) {
    if set.archive.len() < APP_DISCOVERY_ARCHIVE_CAPACITY {
        set.archive.push(membership);
        return;
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARCHIVE_SAMPLE_DOMAIN);
    hasher.update(&(app_id.len() as u32).to_le_bytes());
    hasher.update(app_id.as_bytes());
    hasher.update(&membership.peer_id.to_le_bytes());
    hasher.update(&set.total_verified_observations.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    let draw = u64::from_le_bytes(bytes) % set.total_verified_observations.max(1);
    if draw < APP_DISCOVERY_ARCHIVE_CAPACITY as u64 {
        set.archive[draw as usize] = membership;
    }
}

fn return_priority(membership: &AppPeerMembership) -> (u64, u32, u64, u64) {
    (
        membership.last_returned_at,
        membership.return_count,
        membership.first_seen_for_app,
        membership.peer_id,
    )
}

fn prune_expired_locked(state: &mut AppDiscoveryState, now: u64) -> bool {
    let cutoff = now.saturating_sub(APP_DISCOVERY_ACTIVITY_TTL_SECS);
    let before_interests = state.interested_apps.len();
    state
        .interested_apps
        .retain(|_, last_requested_at| *last_requested_at >= cutoff);
    let mut changed = before_interests != state.interested_apps.len();
    let active_interests: HashSet<String> = state.interested_apps.keys().cloned().collect();
    let before_apps = state.apps.len();
    state
        .apps
        .retain(|app_id, _| active_interests.contains(app_id));
    changed |= before_apps != state.apps.len();
    for set in state.apps.values_mut() {
        let before = set.recent.len() + set.archive.len();
        set.recent
            .retain(|membership| membership.last_verified_for_app >= cutoff);
        set.archive
            .retain(|membership| membership.last_verified_for_app >= cutoff);
        changed |= before != set.recent.len() + set.archive.len();
    }
    state
        .apps
        .retain(|_, set| !set.recent.is_empty() || !set.archive.is_empty());

    let referenced: HashSet<u64> = state
        .apps
        .values()
        .flat_map(|set| set.recent.iter().chain(set.archive.iter()))
        .map(|membership| membership.peer_id)
        .collect();
    let before_peers = state.peers.len();
    state.peers.retain(|_, record| {
        record.last_directly_verified_at >= cutoff || referenced.contains(&record.peer_id)
    });
    changed |= before_peers != state.peers.len();
    changed |= enforce_peer_capacity_locked(state);
    changed
}

fn enforce_global_capacity_locked(state: &mut AppDiscoveryState) -> bool {
    let total: usize = state
        .apps
        .values()
        .map(|set| set.recent.len() + set.archive.len())
        .sum();
    if total <= APP_DISCOVERY_GLOBAL_ASSOCIATION_CAPACITY {
        return false;
    }

    let mut candidates = Vec::with_capacity(total);
    for (app_id, set) in &state.apps {
        for membership in &set.recent {
            candidates.push((
                membership.last_verified_for_app,
                app_id.clone(),
                AppPeerTier::Recent,
                membership.peer_id,
            ));
        }
        for membership in &set.archive {
            candidates.push((
                membership.last_verified_for_app,
                app_id.clone(),
                AppPeerTier::Archive,
                membership.peer_id,
            ));
        }
    }
    candidates.sort_by_key(|candidate| candidate.0);
    let remove_count = total - APP_DISCOVERY_GLOBAL_ASSOCIATION_CAPACITY;
    let remove: HashSet<(String, AppPeerTier, u64)> = candidates
        .into_iter()
        .take(remove_count)
        .map(|(_, app_id, tier, peer_id)| (app_id, tier, peer_id))
        .collect();
    for (app_id, set) in state.apps.iter_mut() {
        set.recent.retain(|membership| {
            !remove.contains(&(app_id.clone(), AppPeerTier::Recent, membership.peer_id))
        });
        set.archive.retain(|membership| {
            !remove.contains(&(app_id.clone(), AppPeerTier::Archive, membership.peer_id))
        });
    }
    state
        .apps
        .retain(|_, set| !set.recent.is_empty() || !set.archive.is_empty());
    true
}

fn enforce_peer_capacity_locked(state: &mut AppDiscoveryState) -> bool {
    if state.peers.len() <= APP_DISCOVERY_GLOBAL_PEER_CAPACITY {
        return false;
    }

    let referenced: HashSet<u64> = state
        .apps
        .values()
        .flat_map(|set| set.recent.iter().chain(set.archive.iter()))
        .map(|membership| membership.peer_id)
        .collect();
    let mut candidates: Vec<(bool, u64, String, u64)> = state
        .peers
        .iter()
        .map(|(address, record)| {
            (
                referenced.contains(&record.peer_id),
                record.last_directly_verified_at,
                address.clone(),
                record.peer_id,
            )
        })
        .collect();
    // Unreferenced tombstones are evicted before active memberships, then the
    // least recently verified records are removed first.
    candidates.sort_by_key(|(is_referenced, verified_at, _, _)| (*is_referenced, *verified_at));
    let remove_count = state.peers.len() - APP_DISCOVERY_GLOBAL_PEER_CAPACITY;
    let removed: Vec<(String, u64)> = candidates
        .into_iter()
        .take(remove_count)
        .map(|(_, _, address, peer_id)| (address, peer_id))
        .collect();
    let removed_ids: HashSet<u64> = removed.iter().map(|(_, peer_id)| *peer_id).collect();
    for (address, _) in removed {
        state.peers.remove(&address);
    }
    if !removed_ids.is_empty() {
        for set in state.apps.values_mut() {
            set.recent
                .retain(|membership| !removed_ids.contains(&membership.peer_id));
            set.archive
                .retain(|membership| !removed_ids.contains(&membership.peer_id));
        }
        state
            .apps
            .retain(|_, set| !set.recent.is_empty() || !set.archive.is_empty());
    }
    true
}

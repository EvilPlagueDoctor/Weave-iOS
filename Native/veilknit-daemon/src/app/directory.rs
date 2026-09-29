//! Daemon-owned application directory and lazy peer root resolution.
//!
//! The user's main DHT publishes only a tiny pointer at subkey 11. That pointer
//! leads to one daemon-owned directory DHT whose subkey 0 maps exact canonical
//! application names (for example `veilknit.veilyshort.v1`) to app-defined root
//! DHTs. The daemon never interprets data beyond those roots.

use std::{collections::{HashMap, HashSet}, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};
use veilid_core::RecordKey;

use crate::{
    app::discovery::AppDiscoveryCache,
    dht_module::DHTModule,
    network_decode::MAX_NETWORK_DHT_VALUE_BYTES,
    types::{
        current_timestamp, decode_app_directory_info, decode_app_directory_manifest,
        is_canonical_application_id, AppDirectoryEntry, AppDirectoryManifest,
        APP_DIRECTORY_LOCATION, APP_DIRECTORY_RECORD_VERSION,
        PUBLIC_METADATA_MAX_FUTURE_SKEW_SECS,
    },
    user_auth::{UserAuth, UserSession},
    user_dht::MainDhtRuntime,
};

pub const APP_DIRECTORY_STORE_KEY: &str = "app_directory_state";
pub const APP_DIRECTORY_DHT_NAME: &str = "app_directory";
pub const APP_DIRECTORY_SUBKEY: u32 = 0;
pub const APP_DIRECTORY_TOTAL_SUBKEYS: u32 = 1;
pub const APP_DIRECTORY_MAX_ENTRIES: usize = 128;
pub const APP_ROOT_CACHE_TTL_SECS: u64 = 24 * 60 * 60;
pub const APP_ROOT_NEGATIVE_CACHE_TTL_SECS: u64 = 60 * 60;
const APP_DIRECTORY_LOOKUP_CONCURRENCY: usize = 4;
pub const APP_DIRECTORY_MAX_PENDING_LOOKUPS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAppDirectoryState {
    version: u16,
    package_index: usize,
    /// Durable local roots. Only the subset whose apps are inside the normal
    /// six-month public activity window is copied into the public directory.
    #[serde(default)]
    roots: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppRootLookupQueueState {
    Queued,
    AlreadyPending,
    QueueFull,
}

#[derive(Debug, Clone)]
pub struct OwnAppRootUpdate {
    pub app_id: String,
    pub root_dht: Option<RecordKey>,
    pub directory_dht: RecordKey,
    pub generation: u64,
    pub updated_at: u64,
}

#[derive(Clone)]
pub struct AppDirectoryManager {
    dht_module: DHTModule,
    auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    main_runtime: MainDhtRuntime,
    package_index: usize,
    directory_dht: RecordKey,
    manifest: Arc<Mutex<AppDirectoryManifest>>,
    stored: Arc<Mutex<StoredAppDirectoryState>>,
    lookup_permits: Arc<Semaphore>,
    inflight: Arc<Mutex<HashSet<(String, String)>>>,
}

impl AppDirectoryManager {
    pub async fn load_or_create(
        auth: Arc<UserAuth>,
        session: Arc<UserSession>,
        dht_module: DHTModule,
        main_runtime: MainDhtRuntime,
    ) -> Result<Self, String> {
        let saved = auth
            .read_user_encrypted::<StoredAppDirectoryState>(&session, APP_DIRECTORY_STORE_KEY)
            .map_err(|error| error.to_string())?;

        let mut saved_state = saved
            .filter(|state| state.version == APP_DIRECTORY_RECORD_VERSION);
        let mut package_index = match saved_state.as_ref() {
            Some(state) => validate_directory_package(&dht_module, state.package_index)
                .await
                .then_some(state.package_index),
            None => None,
        };

        if package_index.is_none() {
            package_index = find_existing_directory_package(&dht_module).await;
        }

        let (package_index, manifest, created) = match package_index {
            Some(index) => {
                let bytes = dht_module
                    .read_from_dht(index, APP_DIRECTORY_SUBKEY, false)
                    .await
                    .map_err(|error| format!("could not read owned app directory: {error:?}"))?;
                let manifest = match decode_app_directory_manifest(&bytes) {
                    Ok(manifest) => manifest,
                    Err(error) => {
                        // This is daemon-owned state, and version 1 has no deployed
                        // compatibility requirement. Rebuild an invalid manifest;
                        // durable local roots are restored below and republished by
                        // the normal AppInfo reconciliation path.
                        crate::teprintln!(
                            "[app-directory] owned manifest was invalid; rebuilding: {error}"
                        );
                        let manifest = AppDirectoryManifest::empty(current_timestamp());
                        write_manifest(&dht_module, index, &manifest).await?;
                        manifest
                    }
                };
                (index, manifest, false)
            }
            None => {
                let index = dht_module
                    .create_dht(APP_DIRECTORY_DHT_NAME.to_string(), vec![1])
                    .await
                    .map_err(|error| format!("could not create app directory DHT: {error:?}"))?;
                let manifest = AppDirectoryManifest::empty(current_timestamp());
                write_manifest(&dht_module, index, &manifest).await?;
                (index, manifest, true)
            }
        };

        let directory_dht = dht_module
            .package_id_to_key(package_index)
            .await
            .map_err(|error| format!("could not obtain app directory key: {error:?}"))?;

        let mut durable_state = saved_state.take().unwrap_or_else(|| StoredAppDirectoryState {
            version: APP_DIRECTORY_RECORD_VERSION,
            package_index,
            roots: HashMap::new(),
        });
        durable_state.version = APP_DIRECTORY_RECORD_VERSION;
        durable_state.package_index = package_index;
        // Seed local durable roots from a pre-existing public manifest if the
        // local state was missing. This is recovery-friendly and does not make
        // the public directory any broader than it already was.
        for entry in &manifest.entries {
            durable_state
                .roots
                .entry(entry.app_id.clone())
                .or_insert_with(|| entry.root_dht.clone());
        }
        auth.write_user_encrypted(&session, APP_DIRECTORY_STORE_KEY, &durable_state)
            .map_err(|error| error.to_string())?;

        // A newly created writer package must be in the durable owned-DHT
        // snapshot before we advertise it publicly.
        if created {
            let snapshot = dht_module.export_snapshot().await;
            crate::user_dht::persist_dht_snapshot(&auth, &session, &snapshot)
                .map_err(|error| error.to_string())?;
        }

        main_runtime
            .publish_app_directory_info(directory_dht.to_string(), manifest.generation)
            .await
            .map_err(|error| error.to_string())?;

        Ok(Self {
            dht_module,
            auth,
            session,
            main_runtime,
            package_index,
            directory_dht,
            manifest: Arc::new(Mutex::new(manifest)),
            stored: Arc::new(Mutex::new(durable_state)),
            lookup_permits: Arc::new(Semaphore::new(APP_DIRECTORY_LOOKUP_CONCURRENCY)),
            inflight: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn directory_dht(&self) -> &RecordKey {
        &self.directory_dht
    }

    /// Number of remote app-root lookups currently active or queued.
    /// This is local diagnostic state and is never published.
    pub async fn pending_lookup_count(&self) -> usize {
        self.inflight.lock().await.len()
    }

    /// Reconcile the public directory with the exact same active-app set used
    /// by AppInfo. Durable local roots survive expiry, but their app ids and
    /// pointers disappear publicly when the six-month activity window closes.
    pub async fn sync_public_apps(&self, active_apps: &[String]) -> Result<bool, String> {
        let active: HashSet<&str> = active_apps.iter().map(String::as_str).collect();
        let stored = self.stored.lock().await.clone();
        let now = current_timestamp();
        let mut manifest = self.manifest.lock().await;
        let mut desired = Vec::new();
        for (app_id, root_dht) in &stored.roots {
            if !active.contains(app_id.as_str()) {
                continue;
            }
            let updated_at = manifest
                .entries
                .iter()
                .find(|entry| entry.app_id == *app_id && entry.root_dht == *root_dht)
                .map_or(now, |entry| entry.updated_at);
            desired.push(AppDirectoryEntry {
                app_id: app_id.clone(),
                root_dht: root_dht.clone(),
                updated_at,
            });
        }
        desired.sort_by(|left, right| left.app_id.cmp(&right.app_id));
        if desired == manifest.entries {
            return Ok(false);
        }

        // Build the next generation separately. The in-memory committed state
        // is not advanced until both DHT writes succeed, so a transient failure
        // remains visible to the next hourly/event reconciliation and retries.
        let mut next = manifest.clone();
        next.entries = desired;
        next.generation = next.generation.saturating_add(1).max(1);
        next.updated_at = now;
        write_manifest(&self.dht_module, self.package_index, &next).await?;
        self.main_runtime
            .publish_app_directory_info(self.directory_dht.to_string(), next.generation)
            .await
            .map_err(|error| error.to_string())?;
        *manifest = next;
        Ok(true)
    }

    pub async fn set_own_app_root(
        &self,
        app_id: &str,
        root_dht: RecordKey,
    ) -> Result<OwnAppRootUpdate, String> {
        if !is_canonical_application_id(app_id) {
            return Err("application id is not canonical".to_string());
        }
        let now = current_timestamp();
        let root_string = root_dht.to_string();
        {
            let mut stored = self.stored.lock().await;
            if stored.roots.len() >= APP_DIRECTORY_MAX_ENTRIES
                && !stored.roots.contains_key(app_id)
            {
                return Err(format!(
                    "app directory contains {} durable roots; maximum is {}",
                    stored.roots.len(),
                    APP_DIRECTORY_MAX_ENTRIES
                ));
            }
            stored.roots.insert(app_id.to_string(), root_string.clone());
            self.auth
                .write_user_encrypted(&self.session, APP_DIRECTORY_STORE_KEY, &*stored)
                .map_err(|error| error.to_string())?;
        }

        let mut manifest = self.manifest.lock().await;
        if let Some(index) = manifest.entries.iter().position(|entry| entry.app_id == app_id) {
            if manifest.entries[index].root_dht == root_string {
                let generation = manifest.generation;
                let updated_at = manifest.entries[index].updated_at;
                return Ok(OwnAppRootUpdate {
                    app_id: app_id.to_string(),
                    root_dht: Some(root_dht),
                    directory_dht: self.directory_dht.clone(),
                    generation,
                    updated_at,
                });
            }
        } else if manifest.entries.len() >= APP_DIRECTORY_MAX_ENTRIES {
            return Err(format!(
                "app directory contains {} entries; maximum is {}",
                manifest.entries.len(),
                APP_DIRECTORY_MAX_ENTRIES
            ));
        }

        let mut next = manifest.clone();
        if let Some(index) = next.entries.iter().position(|entry| entry.app_id == app_id) {
            next.entries[index].root_dht = root_string.clone();
            next.entries[index].updated_at = now;
        } else {
            next.entries.push(AppDirectoryEntry {
                app_id: app_id.to_string(),
                root_dht: root_string,
                updated_at: now,
            });
            next.entries.sort_by(|left, right| left.app_id.cmp(&right.app_id));
        }
        next.generation = next.generation.saturating_add(1).max(1);
        next.updated_at = now;
        write_manifest(&self.dht_module, self.package_index, &next).await?;
        self.main_runtime
            .publish_app_directory_info(self.directory_dht.to_string(), next.generation)
            .await
            .map_err(|error| error.to_string())?;
        *manifest = next;
        Ok(OwnAppRootUpdate {
            app_id: app_id.to_string(),
            root_dht: Some(root_dht),
            directory_dht: self.directory_dht.clone(),
            generation: manifest.generation,
            updated_at: now,
        })
    }

    pub async fn clear_own_app_root(&self, app_id: &str) -> Result<OwnAppRootUpdate, String> {
        if !is_canonical_application_id(app_id) {
            return Err("application id is not canonical".to_string());
        }
        let now = current_timestamp();
        {
            let mut stored = self.stored.lock().await;
            if stored.roots.remove(app_id).is_some() {
                self.auth
                    .write_user_encrypted(&self.session, APP_DIRECTORY_STORE_KEY, &*stored)
                    .map_err(|error| error.to_string())?;
            }
        }

        let mut manifest = self.manifest.lock().await;
        if !manifest.entries.iter().any(|entry| entry.app_id == app_id) {
            return Ok(OwnAppRootUpdate {
                app_id: app_id.to_string(),
                root_dht: None,
                directory_dht: self.directory_dht.clone(),
                generation: manifest.generation,
                updated_at: manifest.updated_at,
            });
        }
        let mut next = manifest.clone();
        next.entries.retain(|entry| entry.app_id != app_id);
        next.generation = next.generation.saturating_add(1).max(1);
        next.updated_at = now;
        write_manifest(&self.dht_module, self.package_index, &next).await?;
        self.main_runtime
            .publish_app_directory_info(self.directory_dht.to_string(), next.generation)
            .await
            .map_err(|error| error.to_string())?;
        *manifest = next;
        Ok(OwnAppRootUpdate {
            app_id: app_id.to_string(),
            root_dht: None,
            directory_dht: self.directory_dht.clone(),
            generation: manifest.generation,
            updated_at: now,
        })
    }

    /// Queue one remote root resolution. The caller receives immediately; the
    /// bounded task performs at most two foreign DHT reads and updates the
    /// disposable app cache when it has an authoritative result.
    pub async fn queue_peer_root_lookup(
        &self,
        app_id: String,
        peer_main_dht: RecordKey,
        cache: AppDiscoveryCache,
    ) -> AppRootLookupQueueState {
        let key = (app_id.clone(), peer_main_dht.to_string());
        {
            let mut inflight = self.inflight.lock().await;
            if inflight.contains(&key) {
                return AppRootLookupQueueState::AlreadyPending;
            }
            if inflight.len() >= APP_DIRECTORY_MAX_PENDING_LOOKUPS {
                return AppRootLookupQueueState::QueueFull;
            }
            inflight.insert(key.clone());
        }

        let manager = self.clone();
        tokio::spawn(async move {
            let permit = manager.lookup_permits.clone().acquire_owned().await;
            if permit.is_err() {
                manager.inflight.lock().await.remove(&key);
                return;
            }
            let _permit = permit.expect("lookup semaphore closed after successful acquire");
            match manager.resolve_peer_root(&app_id, &peer_main_dht).await {
                Ok((root, generation)) => {
                    let now = current_timestamp();
                    if cache
                        .cache_app_root(&app_id, &peer_main_dht, root.as_ref(), generation, now)
                        .await
                    {
                        if let Err(error) = cache.persist().await {
                            crate::teprintln!("[app-directory] could not persist resolved app root: {error}");
                        }
                    }
                }
                Err(error) => crate::teprintln!(
                    "[app-directory] root lookup failed for app={} peer={}: {}",
                    app_id,
                    peer_main_dht,
                    error
                ),
            }
            manager.inflight.lock().await.remove(&key);
        });
        AppRootLookupQueueState::Queued
    }

    async fn resolve_peer_root(
        &self,
        app_id: &str,
        peer_main_dht: &RecordKey,
    ) -> Result<(Option<RecordKey>, u64), String> {
        let now = current_timestamp();
        let info_bytes = self
            .dht_module
            .read_foreign_subkey(peer_main_dht.clone(), APP_DIRECTORY_LOCATION, true)
            .await
            .map_err(|error| format!("could not read peer app-directory pointer: {error:?}"))?;
        let info = decode_app_directory_info(&info_bytes)?;
        if !info.timestamp_is_plausible_at(now) {
            return Err("peer app-directory pointer has an implausible future timestamp".to_string());
        }
        let directory_key = info
            .directory_dht
            .parse::<RecordKey>()
            .map_err(|error| format!("peer app-directory key is invalid: {error:?}"))?;
        let manifest_bytes = self
            .dht_module
            .read_foreign_subkey(directory_key, APP_DIRECTORY_SUBKEY, true)
            .await
            .map_err(|error| format!("could not read peer app directory: {error:?}"))?;
        let manifest = decode_app_directory_manifest(&manifest_bytes)?;
        if manifest.generation != info.generation {
            return Err(format!(
                "directory generation mismatch (pointer={}, manifest={})",
                info.generation, manifest.generation
            ));
        }
        if manifest.updated_at > now.saturating_add(PUBLIC_METADATA_MAX_FUTURE_SKEW_SECS) {
            return Err("peer app-directory manifest has an implausible future timestamp".to_string());
        }
        let root = manifest
            .entries
            .iter()
            .find(|entry| entry.app_id == app_id)
            .map(|entry| entry.root_dht.parse::<RecordKey>())
            .transpose()
            .map_err(|error| format!("peer app root key is invalid: {error:?}"))?;
        Ok((root, manifest.generation))
    }
}

async fn validate_directory_package(dht_module: &DHTModule, index: usize) -> bool {
    dht_module.get_dht_info(index).await.is_some_and(|package| {
        package.name == APP_DIRECTORY_DHT_NAME
            && package.total_subkeys() >= APP_DIRECTORY_TOTAL_SUBKEYS
    })
}

async fn find_existing_directory_package(dht_module: &DHTModule) -> Option<usize> {
    for index in 0..4096usize {
        let Some(package) = dht_module.get_dht_info(index).await else {
            break;
        };
        if package.name == APP_DIRECTORY_DHT_NAME
            && package.total_subkeys() >= APP_DIRECTORY_TOTAL_SUBKEYS
        {
            return Some(index);
        }
    }
    None
}

async fn write_manifest(
    dht_module: &DHTModule,
    package_index: usize,
    manifest: &AppDirectoryManifest,
) -> Result<(), String> {
    let mut normalized = manifest.clone();
    normalized.record_version = APP_DIRECTORY_RECORD_VERSION;
    if normalized.entries.len() > APP_DIRECTORY_MAX_ENTRIES {
        return Err(format!(
            "app directory contains {} entries; maximum is {}",
            normalized.entries.len(),
            APP_DIRECTORY_MAX_ENTRIES
        ));
    }
    let bytes = bincode::serialize(&normalized)
        .map_err(|error| format!("could not serialize app directory: {error}"))?;
    if bytes.len() > MAX_NETWORK_DHT_VALUE_BYTES {
        return Err(format!(
            "app directory is {} bytes; maximum network DHT value is {} bytes",
            bytes.len(),
            MAX_NETWORK_DHT_VALUE_BYTES
        ));
    }
    dht_module
        .write_to_dht(package_index, APP_DIRECTORY_SUBKEY, bytes)
        .await
        .map_err(|error| format!("could not write app directory: {error:?}"))?;
    Ok(())
}

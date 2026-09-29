//! Daemon-owned encrypted local storage for authenticated applications.
//!
//! The important security boundary is deliberately simple:
//!
//!     active VeilKnit account/profile + authenticated APP_ID -> one private vault
//!
//! Applications never supply an account id and never supply another app id.  The local API
//! authenticates a session first, then this module derives the vault from that trusted session.
//! Nothing stored here is published to Veilid/DHT storage.
//!
//! Small values are encrypted as individual authenticated files.  Large blobs are split into
//! independently authenticated chunks so reads can decrypt only the requested range instead of
//! loading an entire video/image into memory.  Filenames and app directories are opaque hashes;
//! semantic names live only inside encrypted manifests.
//!
//! A random storage master key is generated per VeilKnit network profile and wrapped by the
//! existing account encryption.  Per-app keys are derived from that master key, so a future
//! password-change implementation only has to re-wrap the master key rather than re-encrypting
//! every app blob.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use aes_gcm::{
    aead::{Aead, Payload, OsRng, rand_core::RngCore},
    Aes256Gcm, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};
use tokio::{sync::{watch, Mutex}, task::JoinHandle};
use uuid::Uuid;

use crate::{
    identity_manager::AuthenticatedAppSession,
    types::current_timestamp,
    user_auth::{atomic_write, UserAuth, UserSession},
};

const MASTER_KEY_STORE_KEY: &str = "private_app_storage_master_v1";
const CATALOG_STORE_KEY: &str = "private_app_storage_catalog_v1";
const CATALOG_VERSION: u32 = 1;
const MANIFEST_VERSION: u32 = 1;
const MASTER_VERSION: u32 = 1;
const PRIVATE_ROOT_DIR: &str = "private_apps_v1";
const MANIFEST_FILE: &str = "manifest.bin";
const VALUES_DIR: &str = "values";
const BLOBS_DIR: &str = "blobs";
const CHUNKS_DIR: &str = "chunks";

pub const MAX_PRIVATE_VALUE_BYTES: usize = 512 * 1024;
pub const MAX_PRIVATE_BLOB_APPEND_BYTES: usize = 256 * 1024;
pub const MAX_PRIVATE_BLOB_READ_BYTES: u64 = 512 * 1024;
pub const MAX_PRIVATE_BLOB_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MIN_EPHEMERAL_TTL_SECS: u64 = 60 * 60;
pub const MAX_EPHEMERAL_TTL_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_DELETE_ON_SHUTDOWN_FALLBACK_SECS: u64 = 24 * 60 * 60;
pub const DEFAULT_PRIVATE_CACHE_LIMIT_BYTES: u64 = 1024 * 1024 * 1024;
const INCOMPLETE_BLOB_MAX_AGE_SECS: u64 = 24 * 60 * 60;
const MAINTENANCE_INTERVAL_SECS: u64 = 10 * 60;
// Blob chunks are at most 256 KiB. Never recursively delete an arbitrarily large blob from a
// maintenance/shutdown-adjacent path; make it unreachable in the encrypted manifest first, then
// remove at most this many chunk files per sweep. Leftovers remain encrypted orphans for a later
// startup/maintenance pass.
const ORPHAN_BLOB_CHUNK_DELETE_BUDGET: usize = 128;

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

#[derive(Debug)]
pub enum PrivateStorageError {
    InvalidKey,
    ValueTooLarge(usize),
    InvalidContentType,
    InvalidBlobId,
    ValueNotFound,
    BlobNotFound,
    BlobIncomplete,
    BlobAlreadyComplete,
    BlobTooLarge(u64),
    AppendTooLarge(usize),
    RangeTooLarge(u64),
    InvalidRange,
    InvalidTtl,
    Corrupt(String),
    Io(String),
    Crypto(String),
    Persistence(String),
}

impl std::fmt::Display for PrivateStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "private value key is empty, too long, or contains control characters"),
            Self::ValueTooLarge(size) => write!(f, "private value is {size} bytes; maximum is {MAX_PRIVATE_VALUE_BYTES}"),
            Self::InvalidContentType => write!(f, "private blob content type is empty or too long"),
            Self::InvalidBlobId => write!(f, "private blob id is malformed"),
            Self::ValueNotFound => write!(f, "private value was not found"),
            Self::BlobNotFound => write!(f, "private blob was not found"),
            Self::BlobIncomplete => write!(f, "private blob upload is not complete"),
            Self::BlobAlreadyComplete => write!(f, "private blob upload is already complete"),
            Self::BlobTooLarge(size) => write!(f, "private blob would be {size} bytes; maximum is {MAX_PRIVATE_BLOB_BYTES}"),
            Self::AppendTooLarge(size) => write!(f, "private blob append is {size} bytes; maximum is {MAX_PRIVATE_BLOB_APPEND_BYTES}"),
            Self::RangeTooLarge(size) => write!(f, "private blob range is {size} bytes; maximum is {MAX_PRIVATE_BLOB_READ_BYTES}"),
            Self::InvalidRange => write!(f, "private blob range is outside the blob"),
            Self::InvalidTtl => write!(f, "temporary/shutdown TTL must be between 1 and 24 hours"),
            Self::Corrupt(message) => write!(f, "private storage is corrupt: {message}"),
            Self::Io(message) => write!(f, "private storage I/O failed: {message}"),
            Self::Crypto(message) => write!(f, "private storage authentication/decryption failed: {message}"),
            Self::Persistence(message) => write!(f, "private storage persistence failed: {message}"),
        }
    }
}
impl std::error::Error for PrivateStorageError {}
impl From<std::io::Error> for PrivateStorageError {
    fn from(value: std::io::Error) -> Self { Self::Io(value.to_string()) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StorageMaster {
    version: u32,
    key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateStorageCatalog {
    version: u32,
    app_ids: BTreeSet<String>,
}
impl Default for PrivateStorageCatalog {
    fn default() -> Self { Self { version: CATALOG_VERSION, app_ids: BTreeSet::new() } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateValueEntry {
    key: String,
    opaque_id: String,
    bytes: u64,
    retention: PrivateRetention,
    expires_at: Option<u64>,
    created_at: u64,
    updated_at: u64,
    last_accessed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateChunkEntry {
    index: u32,
    plain_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateBlobEntry {
    blob_id: String,
    content_type: String,
    total_bytes: u64,
    chunks: Vec<PrivateChunkEntry>,
    complete: bool,
    retention: PrivateRetention,
    expires_at: Option<u64>,
    created_at: u64,
    updated_at: u64,
    last_accessed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateAppManifest {
    version: u32,
    values: HashMap<String, PrivateValueEntry>,
    blobs: HashMap<String, PrivateBlobEntry>,
    updated_at: u64,
}
impl Default for PrivateAppManifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            values: HashMap::new(),
            blobs: HashMap::new(),
            updated_at: current_timestamp(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivateValueDescriptor {
    pub key: String,
    pub bytes: u64,
    pub retention: PrivateRetention,
    pub expires_at: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
    pub last_accessed_at: u64,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct PrivateStorageUsage {
    pub value_count: usize,
    pub value_bytes: u64,
    pub blob_count: usize,
    pub blob_bytes: u64,
    pub cache_bytes: u64,
    pub cache_limit_bytes: u64,
}

impl From<&PrivateValueEntry> for PrivateValueDescriptor {
    fn from(value: &PrivateValueEntry) -> Self {
        Self {
            key: value.key.clone(), bytes: value.bytes, retention: value.retention,
            expires_at: value.expires_at, created_at: value.created_at,
            updated_at: value.updated_at, last_accessed_at: value.last_accessed_at,
        }
    }
}
impl From<&PrivateBlobEntry> for PrivateBlobDescriptor {
    fn from(value: &PrivateBlobEntry) -> Self {
        Self {
            blob_id: value.blob_id.clone(), content_type: value.content_type.clone(),
            total_bytes: value.total_bytes, chunk_count: value.chunks.len(), complete: value.complete,
            retention: value.retention, expires_at: value.expires_at, created_at: value.created_at,
            updated_at: value.updated_at, last_accessed_at: value.last_accessed_at,
        }
    }
}

#[derive(Clone)]
pub struct PrivateAppStorageManager {
    auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    master: [u8; 32],
    catalog: Arc<Mutex<PrivateStorageCatalog>>,
    write_gate: Arc<Mutex<()>>,
    cache_limit_bytes: u64,
}

impl PrivateAppStorageManager {
    pub fn load(auth: Arc<UserAuth>, session: Arc<UserSession>) -> Result<Self, PrivateStorageError> {
        let master = match auth
            .read_user_encrypted::<StorageMaster>(&session, MASTER_KEY_STORE_KEY)
            .map_err(|e| PrivateStorageError::Persistence(e.to_string()))?
        {
            Some(master) => {
                if master.version != MASTER_VERSION {
                    return Err(PrivateStorageError::Corrupt(format!("unsupported storage master version {}", master.version)));
                }
                master.key
            }
            None => {
                let mut key = [0u8; 32];
                OsRng.fill_bytes(&mut key);
                auth.write_user_encrypted(&session, MASTER_KEY_STORE_KEY, &StorageMaster { version: MASTER_VERSION, key })
                    .map_err(|e| PrivateStorageError::Persistence(e.to_string()))?;
                key
            }
        };
        let catalog = auth
            .read_user_encrypted::<PrivateStorageCatalog>(&session, CATALOG_STORE_KEY)
            .map_err(|e| PrivateStorageError::Persistence(e.to_string()))?
            .unwrap_or_default();
        if catalog.version != CATALOG_VERSION {
            return Err(PrivateStorageError::Corrupt(format!("unsupported private storage catalog version {}", catalog.version)));
        }
        fs::create_dir_all(session.store_dir().join(PRIVATE_ROOT_DIR))?;
        Ok(Self {
            auth, session, master,
            catalog: Arc::new(Mutex::new(catalog)),
            write_gate: Arc::new(Mutex::new(())),
            cache_limit_bytes: DEFAULT_PRIVATE_CACHE_LIMIT_BYTES,
        })
    }

    pub fn spawn_maintenance(&self, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            // Startup cleanup handles objects left inaccessible after a clean shutdown and stale
            // incomplete writes after a crash.  A failure is diagnostic only; the vault remains
            // available and a later sweep can try again.
            if let Err(error) = manager.cleanup_all().await {
                crate::teprintln!("[private-storage] startup cleanup: {error}");
            }
            let mut interval = tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
            interval.tick().await;
            loop {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() { break; }
                    }
                    _ = interval.tick() => {
                        if let Err(error) = manager.cleanup_all().await {
                            crate::teprintln!("[private-storage] maintenance: {error}");
                        }
                    }
                }
            }
        })
    }

    pub async fn put_value(
        &self,
        app: &AuthenticatedAppSession,
        key: &str,
        value: &[u8],
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateValueDescriptor, PrivateStorageError> {
        validate_value_key(key)?;
        if value.len() > MAX_PRIVATE_VALUE_BYTES { return Err(PrivateStorageError::ValueTooLarge(value.len())); }
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        self.ensure_app_registered_locked(&app_id).await?;
        let app_key = self.app_key(&app_id);
        let now = current_timestamp();
        let expires_at = expiry_for(retention, ttl_seconds, now)?;
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let opaque_id = self.value_opaque_id(&app_key, key);
        let created_at = manifest.values.get(key).map(|v| v.created_at).unwrap_or(now);
        let path = self.values_dir(&app_id).join(format!("{opaque_id}.bin"));
        fs::create_dir_all(path.parent().expect("value parent"))?;
        let encrypted = encrypt_bytes(&app_key, &value_aad(&app_id, key), value)?;
        atomic_write(&path, &encrypted).map_err(|e| PrivateStorageError::Persistence(e.to_string()))?;
        let entry = PrivateValueEntry {
            key: key.to_string(), opaque_id, bytes: value.len() as u64,
            retention, expires_at, created_at, updated_at: now, last_accessed_at: now,
        };
        manifest.values.insert(key.to_string(), entry.clone());
        manifest.updated_at = now;
        self.save_manifest(&app_id, &app_key, &manifest)?;
        self.prune_cache_locked(&app_id, &app_key, &mut manifest)?;
        Ok((&entry).into())
    }

    pub async fn get_value(
        &self,
        app: &AuthenticatedAppSession,
        key: &str,
    ) -> Result<Option<(PrivateValueDescriptor, Vec<u8>)>, PrivateStorageError> {
        validate_value_key(key)?;
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let Some(entry) = manifest.values.get(key).cloned() else { return Ok(None); };
        if is_expired(entry.expires_at, now) { return Ok(None); }
        let path = self.values_dir(&app_id).join(format!("{}.bin", entry.opaque_id));
        if !path.exists() { return Err(PrivateStorageError::Corrupt(format!("value '{}' is missing its encrypted file", key))); }
        let encrypted = fs::read(path)?;
        let bytes = decrypt_bytes(&app_key, &value_aad(&app_id, key), &encrypted)?;
        if bytes.len() as u64 != entry.bytes {
            return Err(PrivateStorageError::Corrupt(format!("value '{}' length did not match its manifest", key)));
        }
        if now.saturating_sub(entry.last_accessed_at) >= 60 {
            if let Some(stored) = manifest.values.get_mut(key) { stored.last_accessed_at = now; }
            manifest.updated_at = now;
            self.save_manifest(&app_id, &app_key, &manifest)?;
        }
        let descriptor = manifest.values.get(key).map(PrivateValueDescriptor::from).unwrap_or_else(|| (&entry).into());
        Ok(Some((descriptor, bytes)))
    }

    pub async fn list_values(&self, app: &AuthenticatedAppSession) -> Result<Vec<PrivateValueDescriptor>, PrivateStorageError> {
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let mut values: Vec<_> = manifest.values.values()
            .filter(|entry| !is_expired(entry.expires_at, now))
            .map(PrivateValueDescriptor::from).collect();
        values.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(values)
    }

    pub async fn delete_value(&self, app: &AuthenticatedAppSession, key: &str) -> Result<bool, PrivateStorageError> {
        validate_value_key(key)?;
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let Some(entry) = manifest.values.remove(key) else { return Ok(false); };
        manifest.updated_at = current_timestamp();
        self.save_manifest(&app_id, &app_key, &manifest)?; // inaccessible before physical deletion
        remove_file_best_effort(self.values_dir(&app_id).join(format!("{}.bin", entry.opaque_id)));
        Ok(true)
    }

    pub async fn renew_value(
        &self,
        app: &AuthenticatedAppSession,
        key: &str,
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateValueDescriptor, PrivateStorageError> {
        validate_value_key(key)?;
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let expires_at = expiry_for(retention, ttl_seconds, now)?;
        let entry = manifest.values.get_mut(key).ok_or(PrivateStorageError::ValueNotFound)?;
        if is_expired(entry.expires_at, now) { return Err(PrivateStorageError::ValueNotFound); }
        entry.retention = retention; entry.expires_at = expires_at; entry.updated_at = now; entry.last_accessed_at = now;
        let result = PrivateValueDescriptor::from(&*entry);
        manifest.updated_at = now;
        self.save_manifest(&app_id, &app_key, &manifest)?;
        Ok(result)
    }

    pub async fn begin_blob(
        &self,
        app: &AuthenticatedAppSession,
        content_type: &str,
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateBlobDescriptor, PrivateStorageError> {
        let content_type = content_type.trim();
        if content_type.is_empty() || content_type.len() > 256 || content_type.chars().any(char::is_control) {
            return Err(PrivateStorageError::InvalidContentType);
        }
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        self.ensure_app_registered_locked(&app_id).await?;
        let app_key = self.app_key(&app_id);
        let now = current_timestamp();
        let expires_at = expiry_for(retention, ttl_seconds, now)?;
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let blob_id = Uuid::new_v4().simple().to_string();
        let entry = PrivateBlobEntry {
            blob_id: blob_id.clone(), content_type: content_type.to_string(), total_bytes: 0,
            chunks: Vec::new(), complete: false, retention, expires_at,
            created_at: now, updated_at: now, last_accessed_at: now,
        };
        fs::create_dir_all(self.blob_chunks_dir(&app_id, &blob_id))?;
        manifest.blobs.insert(blob_id, entry.clone());
        manifest.updated_at = now;
        self.save_manifest(&app_id, &app_key, &manifest)?;
        Ok((&entry).into())
    }

    pub async fn append_blob(
        &self,
        app: &AuthenticatedAppSession,
        blob_id: &str,
        data: &[u8],
    ) -> Result<PrivateBlobDescriptor, PrivateStorageError> {
        validate_blob_id(blob_id)?;
        if data.is_empty() || data.len() > MAX_PRIVATE_BLOB_APPEND_BYTES {
            return Err(PrivateStorageError::AppendTooLarge(data.len()));
        }
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let entry = manifest.blobs.get_mut(blob_id).ok_or(PrivateStorageError::BlobNotFound)?;
        if entry.complete { return Err(PrivateStorageError::BlobAlreadyComplete); }
        if is_expired(entry.expires_at, now) { return Err(PrivateStorageError::BlobNotFound); }
        let new_total = entry.total_bytes.saturating_add(data.len() as u64);
        if new_total > MAX_PRIVATE_BLOB_BYTES { return Err(PrivateStorageError::BlobTooLarge(new_total)); }
        let index: u32 = entry.chunks.len().try_into().map_err(|_| PrivateStorageError::BlobTooLarge(new_total))?;
        let chunk_path = self.blob_chunks_dir(&app_id, blob_id).join(format!("{index:08x}.bin"));
        fs::create_dir_all(chunk_path.parent().expect("chunk parent"))?;
        let encrypted = encrypt_bytes(&app_key, &blob_chunk_aad(&app_id, blob_id, index), data)?;
        atomic_write(&chunk_path, &encrypted).map_err(|e| PrivateStorageError::Persistence(e.to_string()))?;
        entry.chunks.push(PrivateChunkEntry { index, plain_bytes: data.len() as u32 });
        entry.total_bytes = new_total; entry.updated_at = now; entry.last_accessed_at = now;
        let result = PrivateBlobDescriptor::from(&*entry);
        manifest.updated_at = now;
        self.save_manifest(&app_id, &app_key, &manifest)?;
        Ok(result)
    }

    pub async fn finish_blob(&self, app: &AuthenticatedAppSession, blob_id: &str) -> Result<PrivateBlobDescriptor, PrivateStorageError> {
        validate_blob_id(blob_id)?;
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let entry = manifest.blobs.get_mut(blob_id).ok_or(PrivateStorageError::BlobNotFound)?;
        if is_expired(entry.expires_at, now) { return Err(PrivateStorageError::BlobNotFound); }
        entry.complete = true; entry.updated_at = now; entry.last_accessed_at = now;
        let result = PrivateBlobDescriptor::from(&*entry);
        manifest.updated_at = now;
        self.save_manifest(&app_id, &app_key, &manifest)?;
        self.prune_cache_locked(&app_id, &app_key, &mut manifest)?;
        Ok(result)
    }

    pub async fn abort_blob(&self, app: &AuthenticatedAppSession, blob_id: &str) -> Result<bool, PrivateStorageError> {
        validate_blob_id(blob_id)?;
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        if manifest.blobs.remove(blob_id).is_none() { return Ok(false); }
        manifest.updated_at = current_timestamp();
        self.save_manifest(&app_id, &app_key, &manifest)?;
        let mut budget = ORPHAN_BLOB_CHUNK_DELETE_BUDGET;
        remove_blob_dir_bounded(&self.blob_dir(&app_id, blob_id), &mut budget);
        Ok(true)
    }

    pub async fn delete_blob(&self, app: &AuthenticatedAppSession, blob_id: &str) -> Result<bool, PrivateStorageError> {
        self.abort_blob(app, blob_id).await
    }

    pub async fn list_blobs(&self, app: &AuthenticatedAppSession) -> Result<Vec<PrivateBlobDescriptor>, PrivateStorageError> {
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let mut blobs: Vec<_> = manifest.blobs.values()
            .filter(|entry| !is_expired(entry.expires_at, now))
            .map(PrivateBlobDescriptor::from).collect();
        blobs.sort_by_key(|blob| blob.created_at);
        Ok(blobs)
    }

    pub async fn read_blob_range(
        &self,
        app: &AuthenticatedAppSession,
        blob_id: &str,
        offset: u64,
        length: u64,
    ) -> Result<(PrivateBlobDescriptor, Vec<u8>), PrivateStorageError> {
        validate_blob_id(blob_id)?;
        if length > MAX_PRIVATE_BLOB_READ_BYTES { return Err(PrivateStorageError::RangeTooLarge(length)); }
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let entry = manifest.blobs.get(blob_id).cloned().ok_or(PrivateStorageError::BlobNotFound)?;
        if !entry.complete { return Err(PrivateStorageError::BlobIncomplete); }
        if is_expired(entry.expires_at, now) { return Err(PrivateStorageError::BlobNotFound); }
        if offset > entry.total_bytes { return Err(PrivateStorageError::InvalidRange); }
        let end = if length == 0 { offset } else { offset.checked_add(length).ok_or(PrivateStorageError::InvalidRange)? };
        if end > entry.total_bytes { return Err(PrivateStorageError::InvalidRange); }
        let mut out = Vec::with_capacity(length as usize);
        if length > 0 {
            let mut chunk_start = 0u64;
            for chunk in &entry.chunks {
                let chunk_end = chunk_start + u64::from(chunk.plain_bytes);
                if chunk_end <= offset { chunk_start = chunk_end; continue; }
                if chunk_start >= end { break; }
                let path = self.blob_chunks_dir(&app_id, blob_id).join(format!("{:08x}.bin", chunk.index));
                let encrypted = fs::read(&path).map_err(|e| PrivateStorageError::Corrupt(format!("blob {blob_id} chunk {} missing: {e}", chunk.index)))?;
                let plain = decrypt_bytes(&app_key, &blob_chunk_aad(&app_id, blob_id, chunk.index), &encrypted)?;
                if plain.len() != chunk.plain_bytes as usize {
                    return Err(PrivateStorageError::Corrupt(format!("blob {blob_id} chunk {} length mismatch", chunk.index)));
                }
                let from = offset.saturating_sub(chunk_start) as usize;
                let to = (end.min(chunk_end) - chunk_start) as usize;
                out.extend_from_slice(&plain[from..to]);
                chunk_start = chunk_end;
            }
        }
        if out.len() as u64 != length { return Err(PrivateStorageError::Corrupt(format!("blob {blob_id} range was incomplete"))); }
        if now.saturating_sub(entry.last_accessed_at) >= 60 {
            if let Some(stored) = manifest.blobs.get_mut(blob_id) { stored.last_accessed_at = now; }
            manifest.updated_at = now;
            self.save_manifest(&app_id, &app_key, &manifest)?;
        }
        let descriptor = manifest.blobs.get(blob_id).map(PrivateBlobDescriptor::from).unwrap_or_else(|| (&entry).into());
        Ok((descriptor, out))
    }

    pub async fn renew_blob(
        &self,
        app: &AuthenticatedAppSession,
        blob_id: &str,
        retention: PrivateRetention,
        ttl_seconds: Option<u64>,
    ) -> Result<PrivateBlobDescriptor, PrivateStorageError> {
        validate_blob_id(blob_id)?;
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let mut manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let expires_at = expiry_for(retention, ttl_seconds, now)?;
        let entry = manifest.blobs.get_mut(blob_id).ok_or(PrivateStorageError::BlobNotFound)?;
        if is_expired(entry.expires_at, now) { return Err(PrivateStorageError::BlobNotFound); }
        entry.retention = retention; entry.expires_at = expires_at; entry.updated_at = now; entry.last_accessed_at = now;
        let result = PrivateBlobDescriptor::from(&*entry);
        manifest.updated_at = now;
        self.save_manifest(&app_id, &app_key, &manifest)?;
        Ok(result)
    }

    pub async fn usage(&self, app: &AuthenticatedAppSession) -> Result<PrivateStorageUsage, PrivateStorageError> {
        let app_id = app.app_id().to_string();
        let app_key = self.app_key(&app_id);
        let manifest = self.load_manifest(&app_id, &app_key)?;
        let now = current_timestamp();
        let values: Vec<_> = manifest.values.values().filter(|v| !is_expired(v.expires_at, now)).collect();
        let blobs: Vec<_> = manifest.blobs.values().filter(|b| !is_expired(b.expires_at, now)).collect();
        Ok(PrivateStorageUsage {
            value_count: values.len(), value_bytes: values.iter().map(|v| v.bytes).sum(),
            blob_count: blobs.len(), blob_bytes: blobs.iter().filter(|b| b.complete).map(|b| b.total_bytes).sum(),
            cache_bytes: values.iter().filter(|v| v.retention == PrivateRetention::Cache).map(|v| v.bytes).sum::<u64>()
                + blobs.iter().filter(|b| b.complete && b.retention == PrivateRetention::Cache).map(|b| b.total_bytes).sum::<u64>(),
            cache_limit_bytes: self.cache_limit_bytes,
        })
    }

    /// Clean-shutdown boundary for DeleteOnShutdown objects.  Entries are removed from the
    /// encrypted manifest first, which makes them inaccessible immediately.  We intentionally
    /// do not recursively delete their chunk directories here: deleting gigabytes is not allowed
    /// to hold the lifecycle watchdog hostage.  Startup/maintenance removes the resulting orphans.
    pub async fn prepare_shutdown(&self) -> Result<usize, PrivateStorageError> {
        let _gate = self.write_gate.lock().await;
        let app_ids: Vec<String> = self.catalog.lock().await.app_ids.iter().cloned().collect();
        let mut removed = 0usize;
        for app_id in app_ids {
            let app_key = self.app_key(&app_id);
            let mut manifest = self.load_manifest(&app_id, &app_key)?;
            let before_values = manifest.values.len();
            let before_blobs = manifest.blobs.len();
            manifest.values.retain(|_, v| v.retention != PrivateRetention::DeleteOnShutdown);
            manifest.blobs.retain(|_, b| b.retention != PrivateRetention::DeleteOnShutdown);
            let changed = before_values != manifest.values.len() || before_blobs != manifest.blobs.len();
            removed += before_values - manifest.values.len() + before_blobs - manifest.blobs.len();
            if changed {
                manifest.updated_at = current_timestamp();
                self.save_manifest(&app_id, &app_key, &manifest)?;
            }
        }
        Ok(removed)
    }

    pub async fn cleanup_all(&self) -> Result<(), PrivateStorageError> {
        let _gate = self.write_gate.lock().await;
        let app_ids: Vec<String> = self.catalog.lock().await.app_ids.iter().cloned().collect();
        for app_id in app_ids {
            let app_key = self.app_key(&app_id);
            let mut manifest = self.load_manifest(&app_id, &app_key)?;
            let now = current_timestamp();
            let mut dead_values = Vec::new();
            manifest.values.retain(|_, entry| {
                let keep = !is_expired(entry.expires_at, now);
                if !keep { dead_values.push(entry.opaque_id.clone()); }
                keep
            });
            manifest.blobs.retain(|_, entry| {
                let stale_incomplete = !entry.complete && now.saturating_sub(entry.updated_at) >= INCOMPLETE_BLOB_MAX_AGE_SECS;
                !is_expired(entry.expires_at, now) && !stale_incomplete
            });
            manifest.updated_at = now;
            self.prune_cache_locked(&app_id, &app_key, &mut manifest)?;
            self.save_manifest(&app_id, &app_key, &manifest)?;
            for opaque in dead_values { remove_file_best_effort(self.values_dir(&app_id).join(format!("{opaque}.bin"))); }
            self.remove_orphans(&app_id, &manifest)?;
        }
        Ok(())
    }

    async fn ensure_app_registered_locked(&self, app_id: &str) -> Result<(), PrivateStorageError> {
        let mut catalog = self.catalog.lock().await;
        if catalog.app_ids.insert(app_id.to_string()) {
            self.auth.write_user_encrypted(&self.session, CATALOG_STORE_KEY, &*catalog)
                .map_err(|e| PrivateStorageError::Persistence(e.to_string()))?;
        }
        Ok(())
    }

    fn root(&self) -> PathBuf { self.session.store_dir().join(PRIVATE_ROOT_DIR) }
    fn app_dir(&self, app_id: &str) -> PathBuf { self.root().join(self.app_scope_id(app_id)) }
    fn values_dir(&self, app_id: &str) -> PathBuf { self.app_dir(app_id).join(VALUES_DIR) }
    fn blobs_dir(&self, app_id: &str) -> PathBuf { self.app_dir(app_id).join(BLOBS_DIR) }
    fn blob_dir(&self, app_id: &str, blob_id: &str) -> PathBuf { self.blobs_dir(app_id).join(blob_id) }
    fn blob_chunks_dir(&self, app_id: &str, blob_id: &str) -> PathBuf { self.blob_dir(app_id, blob_id).join(CHUNKS_DIR) }
    fn manifest_path(&self, app_id: &str) -> PathBuf { self.app_dir(app_id).join(MANIFEST_FILE) }

    fn app_scope_id(&self, app_id: &str) -> String { keyed_hex(&self.master, b"veilknit/private-app/scope/v1\0", app_id.as_bytes()) }
    fn app_key(&self, app_id: &str) -> [u8; 32] { keyed_bytes(&self.master, b"veilknit/private-app/key/v1\0", app_id.as_bytes()) }
    fn value_opaque_id(&self, app_key: &[u8; 32], key: &str) -> String { keyed_hex(app_key, b"veilknit/private-app/value-id/v1\0", key.as_bytes()) }

    fn load_manifest(&self, app_id: &str, app_key: &[u8; 32]) -> Result<PrivateAppManifest, PrivateStorageError> {
        let path = self.manifest_path(app_id);
        if !path.exists() { return Ok(PrivateAppManifest::default()); }
        let encrypted = fs::read(path)?;
        let plain = decrypt_bytes(app_key, &manifest_aad(app_id), &encrypted)?;
        let manifest: PrivateAppManifest = serde_json::from_slice(&plain).map_err(|e| PrivateStorageError::Corrupt(e.to_string()))?;
        if manifest.version != MANIFEST_VERSION {
            return Err(PrivateStorageError::Corrupt(format!("unsupported app manifest version {}", manifest.version)));
        }
        Ok(manifest)
    }

    fn save_manifest(&self, app_id: &str, app_key: &[u8; 32], manifest: &PrivateAppManifest) -> Result<(), PrivateStorageError> {
        let path = self.manifest_path(app_id);
        fs::create_dir_all(path.parent().expect("manifest parent"))?;
        let plain = serde_json::to_vec(manifest).map_err(|e| PrivateStorageError::Persistence(e.to_string()))?;
        let encrypted = encrypt_bytes(app_key, &manifest_aad(app_id), &plain)?;
        atomic_write(&path, &encrypted).map_err(|e| PrivateStorageError::Persistence(e.to_string()))
    }

    fn prune_cache_locked(&self, app_id: &str, app_key: &[u8; 32], manifest: &mut PrivateAppManifest) -> Result<(), PrivateStorageError> {
        let mut cache_bytes = manifest.values.values().filter(|v| v.retention == PrivateRetention::Cache).map(|v| v.bytes).sum::<u64>()
            + manifest.blobs.values().filter(|b| b.complete && b.retention == PrivateRetention::Cache).map(|b| b.total_bytes).sum::<u64>();
        if cache_bytes <= self.cache_limit_bytes { return Ok(()); }
        #[derive(Clone)] enum Candidate { Value(String, String, u64, u64), Blob(String, u64, u64) }
        let mut candidates = Vec::new();
        for (key, value) in &manifest.values {
            if value.retention == PrivateRetention::Cache { candidates.push(Candidate::Value(key.clone(), value.opaque_id.clone(), value.last_accessed_at, value.bytes)); }
        }
        for (id, blob) in &manifest.blobs {
            if blob.complete && blob.retention == PrivateRetention::Cache { candidates.push(Candidate::Blob(id.clone(), blob.last_accessed_at, blob.total_bytes)); }
        }
        candidates.sort_by_key(|candidate| match candidate { Candidate::Value(_, _, at, _) | Candidate::Blob(_, at, _) => *at });
        let mut dead_values = Vec::new();
        let mut dead_blobs = Vec::new();
        for candidate in candidates {
            if cache_bytes <= self.cache_limit_bytes { break; }
            match candidate {
                Candidate::Value(key, opaque, _, bytes) => {
                    if manifest.values.remove(&key).is_some() { cache_bytes = cache_bytes.saturating_sub(bytes); dead_values.push(opaque); }
                }
                Candidate::Blob(id, _, bytes) => {
                    if manifest.blobs.remove(&id).is_some() { cache_bytes = cache_bytes.saturating_sub(bytes); dead_blobs.push(id); }
                }
            }
        }
        manifest.updated_at = current_timestamp();
        self.save_manifest(app_id, app_key, manifest)?; // commit invisibility first
        for opaque in dead_values { remove_file_best_effort(self.values_dir(app_id).join(format!("{opaque}.bin"))); }
        let mut budget = ORPHAN_BLOB_CHUNK_DELETE_BUDGET;
        for id in dead_blobs {
            if budget == 0 { break; }
            remove_blob_dir_bounded(&self.blob_dir(app_id, &id), &mut budget);
        }
        Ok(())
    }

    fn remove_orphans(&self, app_id: &str, manifest: &PrivateAppManifest) -> Result<(), PrivateStorageError> {
        let live_values: HashSet<String> = manifest.values.values().map(|v| format!("{}.bin", v.opaque_id)).collect();
        let values_dir = self.values_dir(app_id);
        if let Ok(entries) = fs::read_dir(&values_dir) {
            for entry in entries.flatten() {
                if entry.file_type().map(|t| t.is_file()).unwrap_or(false) && !live_values.contains(&entry.file_name().to_string_lossy().to_string()) {
                    remove_file_best_effort(entry.path());
                }
            }
        }
        let live_blobs: HashSet<String> = manifest.blobs.keys().cloned().collect();
        let blobs_dir = self.blobs_dir(app_id);
        let mut budget = ORPHAN_BLOB_CHUNK_DELETE_BUDGET;
        if let Ok(entries) = fs::read_dir(&blobs_dir) {
            for entry in entries.flatten() {
                if budget == 0 { break; }
                if entry.file_type().map(|t| t.is_dir()).unwrap_or(false)
                    && !live_blobs.contains(&entry.file_name().to_string_lossy().to_string())
                {
                    remove_blob_dir_bounded(&entry.path(), &mut budget);
                }
            }
        }
        Ok(())
    }
}

fn validate_value_key(key: &str) -> Result<(), PrivateStorageError> {
    let key = key.trim();
    if key.is_empty() || key.len() > 512 || key.chars().any(char::is_control) { Err(PrivateStorageError::InvalidKey) } else { Ok(()) }
}
fn validate_blob_id(blob_id: &str) -> Result<(), PrivateStorageError> {
    if blob_id.len() != 32 || !blob_id.bytes().all(|b| b.is_ascii_hexdigit()) { Err(PrivateStorageError::InvalidBlobId) } else { Ok(()) }
}
fn expiry_for(retention: PrivateRetention, ttl_seconds: Option<u64>, now: u64) -> Result<Option<u64>, PrivateStorageError> {
    match retention {
        PrivateRetention::Persistent | PrivateRetention::Cache => Ok(None),
        PrivateRetention::Temporary => {
            let ttl = ttl_seconds.ok_or(PrivateStorageError::InvalidTtl)?;
            if !(MIN_EPHEMERAL_TTL_SECS..=MAX_EPHEMERAL_TTL_SECS).contains(&ttl) { return Err(PrivateStorageError::InvalidTtl); }
            Ok(Some(now.saturating_add(ttl)))
        }
        PrivateRetention::DeleteOnShutdown => {
            let ttl = ttl_seconds.unwrap_or(DEFAULT_DELETE_ON_SHUTDOWN_FALLBACK_SECS);
            if !(MIN_EPHEMERAL_TTL_SECS..=MAX_EPHEMERAL_TTL_SECS).contains(&ttl) { return Err(PrivateStorageError::InvalidTtl); }
            Ok(Some(now.saturating_add(ttl)))
        }
    }
}
fn is_expired(expires_at: Option<u64>, now: u64) -> bool { expires_at.map(|at| at <= now).unwrap_or(false) }

fn keyed_bytes(key: &[u8; 32], domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(domain); hasher.update(value);
    *hasher.finalize().as_bytes()
}
fn keyed_hex(key: &[u8; 32], domain: &[u8], value: &[u8]) -> String { hex::encode(keyed_bytes(key, domain, value)) }
fn manifest_aad(app_id: &str) -> Vec<u8> { aad_parts(&[b"veilknit/private-app/manifest/v1\0", app_id.as_bytes()]) }
fn value_aad(app_id: &str, key: &str) -> Vec<u8> { aad_parts(&[b"veilknit/private-app/value/v1\0", app_id.as_bytes(), b"\0", key.as_bytes()]) }
fn blob_chunk_aad(app_id: &str, blob_id: &str, index: u32) -> Vec<u8> {
    let index_bytes = index.to_le_bytes();
    aad_parts(&[b"veilknit/private-app/blob-chunk/v1\0", app_id.as_bytes(), b"\0", blob_id.as_bytes(), b"\0", &index_bytes])
}
fn aad_parts(parts: &[&[u8]]) -> Vec<u8> { let mut out = Vec::new(); for part in parts { out.extend_from_slice(part); } out }

fn encrypt_bytes(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, PrivateStorageError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| PrivateStorageError::Crypto(e.to_string()))?;
    let mut nonce_bytes = [0u8; 12]; OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: plaintext, aad })
        .map_err(|_| PrivateStorageError::Crypto("encryption failed".into()))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len()); out.extend_from_slice(&nonce_bytes); out.extend_from_slice(&ciphertext); Ok(out)
}
fn decrypt_bytes(key: &[u8; 32], aad: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, PrivateStorageError> {
    if encrypted.len() < 12 + 16 { return Err(PrivateStorageError::Crypto("ciphertext is too short".into())); }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| PrivateStorageError::Crypto(e.to_string()))?;
    cipher.decrypt(Nonce::from_slice(&encrypted[..12]), Payload { msg: &encrypted[12..], aad })
        .map_err(|_| PrivateStorageError::Crypto("authentication failed".into()))
}
fn remove_file_best_effort(path: impl AsRef<Path>) { match fs::remove_file(path) { Ok(()) => {}, Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}, Err(_) => {} } }

/// Delete only a bounded number of chunk files from one orphaned blob. This is deliberately not
/// `remove_dir_all`: very large cache/video trees must never turn a cleanup pass into an unbounded
/// shutdown delay. Empty directories are removed opportunistically after their chunks are gone.
fn remove_blob_dir_bounded(blob_dir: &Path, budget: &mut usize) {
    if *budget == 0 { return; }
    let chunks_dir = blob_dir.join(CHUNKS_DIR);
    if let Ok(entries) = fs::read_dir(&chunks_dir) {
        for entry in entries.flatten() {
            if *budget == 0 { break; }
            if entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) {
                remove_file_best_effort(entry.path());
                *budget = budget.saturating_sub(1);
            }
        }
    }
    let _ = fs::remove_dir(&chunks_dir); // succeeds only when empty
    let _ = fs::remove_dir(blob_dir);    // succeeds only when empty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_prevents_value_swap() {
        let key = [7u8; 32];
        let encrypted = encrypt_bytes(&key, &value_aad("app.a", "one"), b"secret").unwrap();
        assert_eq!(decrypt_bytes(&key, &value_aad("app.a", "one"), &encrypted).unwrap(), b"secret");
        assert!(decrypt_bytes(&key, &value_aad("app.a", "two"), &encrypted).is_err());
        assert!(decrypt_bytes(&key, &value_aad("app.b", "one"), &encrypted).is_err());
    }

    #[test]
    fn retention_boundaries_are_enforced() {
        let now = 1000;
        assert!(expiry_for(PrivateRetention::Persistent, None, now).unwrap().is_none());
        assert!(expiry_for(PrivateRetention::Cache, Some(1), now).unwrap().is_none());
        assert!(expiry_for(PrivateRetention::Temporary, None, now).is_err());
        assert!(expiry_for(PrivateRetention::Temporary, Some(MIN_EPHEMERAL_TTL_SECS - 1), now).is_err());
        assert_eq!(expiry_for(PrivateRetention::Temporary, Some(MIN_EPHEMERAL_TTL_SECS), now).unwrap(), Some(now + MIN_EPHEMERAL_TTL_SECS));
        assert_eq!(expiry_for(PrivateRetention::DeleteOnShutdown, None, now).unwrap(), Some(now + DEFAULT_DELETE_ON_SHUTDOWN_FALLBACK_SECS));
        assert!(expiry_for(PrivateRetention::DeleteOnShutdown, Some(MAX_EPHEMERAL_TTL_SECS + 1), now).is_err());
    }
}

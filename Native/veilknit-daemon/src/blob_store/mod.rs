//! Generic large-object storage built from chained, size-safe DHT records.
//!
//! The blob store deliberately treats content as opaque bytes. Applications
//! decide whether those bytes represent a video, image, archive, document, or
//! any other format. The daemon only handles chunking, persistence, integrity,
//! resumable uploads, chained DHT records, bounded reads, and ownership.
//!
//! Each segment uses a 64-subkey DHT: subkey 0 stores a compact segment header
//! and subkeys 1..=63 store up to 12 KiB each. A full segment therefore carries
//! about 756 KiB while remaining below Veilid's schema limits. Segment headers
//! form a forward chain; the first segment is the public blob address.

use std::{collections::HashMap, fmt, sync::Arc};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;
use veilid_core::RecordKey;

use crate::{
    app_services::{AppServiceError, AppStorageManager, AppStoreDescriptor, AppStoreReadValue},
    identity_manager::AuthenticatedAppSession,
    types::current_timestamp,
    user_auth::{UserAuth, UserSession},
};

const BLOB_CATALOG_KEY: &str = "application_blob_store_v1";
const BLOB_CATALOG_VERSION: u32 = 1;
const SEGMENT_MAGIC: [u8; 4] = *b"VKBS";
const SEGMENT_VERSION: u16 = 1;

pub const BLOB_SEGMENT_SUBKEYS: u16 = 64;
pub const BLOB_DATA_SUBKEYS_PER_SEGMENT: u32 = 63;
pub const BLOB_CHUNK_BYTES: usize = 12 * 1024;
pub const BLOB_MAX_APPEND_BYTES: usize = 512 * 1024;
pub const BLOB_MAX_SEGMENTS: u32 = 256;
pub const BLOB_MAX_BYTES: u64 = BLOB_CHUNK_BYTES as u64
    * BLOB_DATA_SUBKEYS_PER_SEGMENT as u64
    * BLOB_MAX_SEGMENTS as u64;
pub const BLOB_MAX_CONTENT_TYPE_BYTES: usize = 128;

#[derive(Debug)]
pub enum BlobStoreError {
    InvalidUploadId,
    UploadNotFound,
    BlobNotFound,
    UploadAlreadyFinished,
    InvalidContentType,
    EmptyAppend,
    AppendTooLarge(usize),
    BlobTooLarge(u64),
    TooManySegments,
    InvalidManifest(String),
    IntegrityMismatch,
    RangeOutsideBlob,
    Persistence(String),
    Storage(AppServiceError),
}

impl fmt::Display for BlobStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUploadId => write!(f, "blob upload id is malformed"),
            Self::UploadNotFound => write!(f, "blob upload was not found"),
            Self::BlobNotFound => write!(f, "blob was not found"),
            Self::UploadAlreadyFinished => write!(f, "blob upload is already finished"),
            Self::InvalidContentType => write!(f, "content type is empty or too long"),
            Self::EmptyAppend => write!(f, "blob append contains no bytes"),
            Self::AppendTooLarge(size) => write!(f, "blob append is {size} bytes; maximum is {BLOB_MAX_APPEND_BYTES}"),
            Self::BlobTooLarge(size) => write!(f, "blob would be {size} bytes; maximum is {BLOB_MAX_BYTES}"),
            Self::TooManySegments => write!(f, "blob segment limit reached"),
            Self::InvalidManifest(reason) => write!(f, "invalid blob manifest: {reason}"),
            Self::IntegrityMismatch => write!(f, "blob content failed SHA-256 verification"),
            Self::RangeOutsideBlob => write!(f, "requested blob range is outside the object"),
            Self::Persistence(reason) => write!(f, "blob catalog persistence failed: {reason}"),
            Self::Storage(error) => write!(f, "blob DHT operation failed: {error}"),
        }
    }
}

impl std::error::Error for BlobStoreError {}

impl From<AppServiceError> for BlobStoreError {
    fn from(value: AppServiceError) -> Self { Self::Storage(value) }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentHeader {
    magic: [u8; 4],
    version: u16,
    blob_id: String,
    segment_index: u32,
    chunk_count: u32,
    payload_bytes: u64,
    next_record_key: Option<String>,
    content_type: Option<String>,
    total_bytes: Option<u64>,
    segment_count: Option<u32>,
    sha256: Option<[u8; 32]>,
    created_at: u64,
    finalized_at: Option<u64>,
}

impl SegmentHeader {
    fn validate(&self, expected_blob_id: Option<&str>, expected_index: u32) -> Result<(), BlobStoreError> {
        if self.magic != SEGMENT_MAGIC || self.version != SEGMENT_VERSION {
            return Err(BlobStoreError::InvalidManifest("unknown magic or version".into()));
        }
        if self.segment_index != expected_index {
            return Err(BlobStoreError::InvalidManifest("segment index mismatch".into()));
        }
        if let Some(expected) = expected_blob_id {
            if self.blob_id != expected {
                return Err(BlobStoreError::InvalidManifest("blob id changed between segments".into()));
            }
        }
        if self.chunk_count > BLOB_DATA_SUBKEYS_PER_SEGMENT {
            return Err(BlobStoreError::InvalidManifest("chunk count exceeds segment capacity".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadSegment {
    store_id: String,
    record_key: String,
    chunk_count: u32,
    payload_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadState {
    upload_id: String,
    blob_id: String,
    application_id: String,
    content_type: String,
    segments: Vec<UploadSegment>,
    committed_bytes: u64,
    created_at: u64,
    finalized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredBlob {
    application_id: String,
    descriptor: BlobDescriptor,
    segment_store_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlobCatalog {
    version: u32,
    uploads: HashMap<String, UploadState>,
    blobs: HashMap<String, StoredBlob>,
}

impl Default for BlobCatalog {
    fn default() -> Self {
        Self { version: BLOB_CATALOG_VERSION, uploads: HashMap::new(), blobs: HashMap::new() }
    }
}

#[derive(Clone)]
pub struct BlobStoreManager {
    auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    storage: AppStorageManager,
    catalog: Arc<Mutex<BlobCatalog>>,
    mutation_gate: Arc<Mutex<()>>,
}

impl BlobStoreManager {
    pub fn load(
        auth: Arc<UserAuth>,
        session: Arc<UserSession>,
        storage: AppStorageManager,
    ) -> Result<Self, BlobStoreError> {
        let catalog = auth
            .read_user_encrypted::<BlobCatalog>(&session, BLOB_CATALOG_KEY)
            .map_err(|e| BlobStoreError::Persistence(e.to_string()))?
            .unwrap_or_default();
        if catalog.version != BLOB_CATALOG_VERSION {
            return Err(BlobStoreError::Persistence(format!(
                "unsupported blob catalog version {}", catalog.version
            )));
        }
        Ok(Self {
            auth,
            session,
            storage,
            catalog: Arc::new(Mutex::new(catalog)),
            mutation_gate: Arc::new(Mutex::new(())),
        })
    }

    pub async fn begin_upload(
        &self,
        app: &AuthenticatedAppSession,
        content_type: String,
    ) -> Result<BlobUploadStatus, BlobStoreError> {
        let content_type = content_type.trim().to_string();
        if content_type.is_empty() || content_type.len() > BLOB_MAX_CONTENT_TYPE_BYTES {
            return Err(BlobStoreError::InvalidContentType);
        }
        let _gate = self.mutation_gate.lock().await;
        let upload_id = Uuid::new_v4().simple().to_string();
        let blob_id = Uuid::new_v4().simple().to_string();
        let store = self.create_segment(app, &blob_id, 0, &content_type, current_timestamp()).await?;
        let state = UploadState {
            upload_id: upload_id.clone(),
            blob_id: blob_id.clone(),
            application_id: app.app_id().to_string(),
            content_type: content_type.clone(),
            segments: vec![UploadSegment {
                store_id: store.store_id,
                record_key: store.record_key.clone(),
                chunk_count: 0,
                payload_bytes: 0,
            }],
            committed_bytes: 0,
            created_at: current_timestamp(),
            finalized: false,
        };
        let status = status_from_upload(&state);
        let mut catalog = self.catalog.lock().await;
        catalog.uploads.insert(upload_id, state);
        self.persist_locked(&catalog)?;
        Ok(status)
    }

    pub async fn append(
        &self,
        app: &AuthenticatedAppSession,
        upload_id: &str,
        data: &[u8],
    ) -> Result<BlobUploadStatus, BlobStoreError> {
        validate_uuid(upload_id)?;
        if data.is_empty() { return Err(BlobStoreError::EmptyAppend); }
        if data.len() > BLOB_MAX_APPEND_BYTES { return Err(BlobStoreError::AppendTooLarge(data.len())); }
        let _gate = self.mutation_gate.lock().await;
        let mut state = {
            let catalog = self.catalog.lock().await;
            catalog.uploads.get(upload_id).cloned().ok_or(BlobStoreError::UploadNotFound)?
        };
        ensure_owner(app, &state.application_id)?;
        if state.finalized { return Err(BlobStoreError::UploadAlreadyFinished); }
        let new_total = state.committed_bytes.saturating_add(data.len() as u64);
        if new_total > BLOB_MAX_BYTES { return Err(BlobStoreError::BlobTooLarge(new_total)); }

        let mut offset = 0usize;
        while offset < data.len() {
            if state.segments.last().map(|s| s.chunk_count).unwrap_or(BLOB_DATA_SUBKEYS_PER_SEGMENT)
                >= BLOB_DATA_SUBKEYS_PER_SEGMENT
            {
                if state.segments.len() as u32 >= BLOB_MAX_SEGMENTS { return Err(BlobStoreError::TooManySegments); }
                let index = state.segments.len() as u32;
                let next = self.create_segment(app, &state.blob_id, index, &state.content_type, state.created_at).await?;
                let previous = state.segments.last().cloned().ok_or(BlobStoreError::InvalidManifest("missing previous segment".into()))?;
                let previous_header = self.make_header(&state, (index - 1) as usize, Some(next.record_key.clone()), false, None);
                self.write_header(app, &previous.store_id, previous_header).await?;
                state.segments.push(UploadSegment {
                    store_id: next.store_id,
                    record_key: next.record_key,
                    chunk_count: 0,
                    payload_bytes: 0,
                });
            }
            let take = (data.len() - offset).min(BLOB_CHUNK_BYTES);
            let index = state.segments.len() - 1;
            let (store_id, location) = {
                let segment = &state.segments[index];
                (segment.store_id.clone(), segment.chunk_count + 1)
            };
            self.storage
                .write_own(app, &store_id, None, vec![(location, data[offset..offset + take].to_vec())])
                .await?;
            state.segments[index].chunk_count += 1;
            state.segments[index].payload_bytes += take as u64;
            state.committed_bytes += take as u64;
            offset += take;
            let header = self.make_header(&state, index, None, false, None);
            self.write_header(app, &store_id, header).await?;
        }

        let status = status_from_upload(&state);
        let mut catalog = self.catalog.lock().await;
        catalog.uploads.insert(upload_id.to_string(), state);
        self.persist_locked(&catalog)?;
        Ok(status)
    }

    pub async fn finish(
        &self,
        app: &AuthenticatedAppSession,
        upload_id: &str,
        expected_sha256: Option<[u8; 32]>,
    ) -> Result<BlobDescriptor, BlobStoreError> {
        validate_uuid(upload_id)?;
        let _gate = self.mutation_gate.lock().await;
        let mut state = {
            let catalog = self.catalog.lock().await;
            catalog.uploads.get(upload_id).cloned().ok_or(BlobStoreError::UploadNotFound)?
        };
        ensure_owner(app, &state.application_id)?;
        if state.finalized { return Err(BlobStoreError::UploadAlreadyFinished); }

        let digest = self.hash_owned_upload(app, &state).await?;
        if expected_sha256.is_some_and(|expected| expected != digest) {
            return Err(BlobStoreError::IntegrityMismatch);
        }
        let finalized_at = current_timestamp();
        state.finalized = true;
        for index in (0..state.segments.len()).rev() {
            let next = state.segments.get(index + 1).map(|s| s.record_key.clone());
            let header = self.make_header(&state, index, next, true, Some((digest, finalized_at)));
            self.write_header(app, &state.segments[index].store_id, header).await?;
        }
        let descriptor = BlobDescriptor {
            blob_id: state.blob_id.clone(),
            root_record_key: state.segments[0].record_key.clone(),
            content_type: state.content_type.clone(),
            total_bytes: state.committed_bytes,
            segment_count: state.segments.len() as u32,
            sha256_hex: hex::encode(digest),
            created_at: state.created_at,
            finalized_at,
        };
        let stored = StoredBlob {
            application_id: state.application_id.clone(),
            descriptor: descriptor.clone(),
            segment_store_ids: state.segments.iter().map(|s| s.store_id.clone()).collect(),
        };
        let mut catalog = self.catalog.lock().await;
        catalog.uploads.remove(upload_id);
        catalog.blobs.insert(state.blob_id.clone(), stored);
        self.persist_locked(&catalog)?;
        Ok(descriptor)
    }

    pub async fn list(&self, app: &AuthenticatedAppSession) -> Vec<BlobDescriptor> {
        let app_id = app.app_id().to_string();
        let catalog = self.catalog.lock().await;
        catalog.blobs.values()
            .filter(|blob| blob.application_id == app_id)
            .map(|blob| blob.descriptor.clone())
            .collect()
    }

    /// Read a public blob range. The root record key is sufficient; no app
    /// writer capability is exposed. The returned bytes are verified against
    /// the final SHA-256 when the complete blob is requested.
    pub async fn read_public_range(
        &self,
        root_record_key: RecordKey,
        offset: u64,
        length: u64,
        force_refresh: bool,
    ) -> Result<(BlobDescriptor, Vec<u8>), BlobStoreError> {
        let canonical_root_key = root_record_key.to_string();
        let root_header = self.read_public_header(root_record_key.clone(), force_refresh).await?;
        root_header.validate(None, 0)?;
        let total = root_header.total_bytes.ok_or_else(|| BlobStoreError::InvalidManifest("root segment is not finalized".into()))?;
        let expected_hash = root_header.sha256.ok_or_else(|| BlobStoreError::InvalidManifest("root hash missing".into()))?;
        let end = offset.checked_add(length).ok_or(BlobStoreError::RangeOutsideBlob)?;
        if offset > total || end > total { return Err(BlobStoreError::RangeOutsideBlob); }

        let mut current_key = root_record_key;
        let mut expected_index = 0u32;
        let mut global_cursor = 0u64;
        let mut output = Vec::with_capacity(length.min(usize::MAX as u64) as usize);
        let mut whole_hasher = (offset == 0 && length == total).then(Sha256::new);
        let mut first_header = Some(root_header.clone());

        loop {
            let header = if let Some(header) = first_header.take() { header } else { self.read_public_header(current_key.clone(), force_refresh).await? };
            header.validate(Some(&root_header.blob_id), expected_index)?;
            let locations: Vec<u32> = (1..=header.chunk_count).collect();
            let mut values = if locations.is_empty() { Vec::new() } else { self.storage.read_public(current_key.clone(), locations, force_refresh).await? };
            values.sort_by_key(|value| value.location);
            for value in values {
                let bytes = decode_store_value(value)?;
                let chunk_start = global_cursor;
                let chunk_end = global_cursor + bytes.len() as u64;
                if let Some(hasher) = whole_hasher.as_mut() { hasher.update(&bytes); }
                if chunk_end > offset && chunk_start < end {
                    let from = offset.saturating_sub(chunk_start) as usize;
                    let to = (end.min(chunk_end) - chunk_start) as usize;
                    output.extend_from_slice(&bytes[from..to]);
                }
                global_cursor = chunk_end;
            }
            if output.len() as u64 >= length { break; }
            let Some(next) = header.next_record_key else { break; };
            current_key = next.parse().map_err(|_| BlobStoreError::InvalidManifest("invalid next record key".into()))?;
            expected_index += 1;
            if expected_index >= BLOB_MAX_SEGMENTS { return Err(BlobStoreError::TooManySegments); }
        }
        if output.len() as u64 != length { return Err(BlobStoreError::InvalidManifest("blob chain ended before requested range".into())); }
        if let Some(hasher) = whole_hasher {
            if hasher.finalize().as_slice() != expected_hash { return Err(BlobStoreError::IntegrityMismatch); }
        }
        let descriptor = BlobDescriptor {
            blob_id: root_header.blob_id,
            root_record_key: canonical_root_key,
            content_type: root_header.content_type.unwrap_or_else(|| "application/octet-stream".into()),
            total_bytes: total,
            segment_count: root_header.segment_count.unwrap_or(expected_index + 1),
            sha256_hex: hex::encode(expected_hash),
            created_at: root_header.created_at,
            finalized_at: root_header.finalized_at.unwrap_or(0),
        };
        Ok((descriptor, output))
    }

    pub async fn delete(&self, app: &AuthenticatedAppSession, blob_id: &str) -> Result<(), BlobStoreError> {
        validate_uuid(blob_id)?;
        let _gate = self.mutation_gate.lock().await;
        let stored = {
            let catalog = self.catalog.lock().await;
            catalog.blobs.get(blob_id).cloned().ok_or(BlobStoreError::BlobNotFound)?
        };
        ensure_owner(app, &stored.application_id)?;
        // Best-effort tombstoning. Distributed replicas may retain historical
        // generations, so callers must not treat this as cryptographic erasure.
        for store_id in &stored.segment_store_ids {
            let _ = self.storage.write_own(
                app,
                store_id,
                None,
                (0..u32::from(BLOB_SEGMENT_SUBKEYS))
                    .map(|location| (location, crate::dht_module::NULL_DHT_VALUE.to_vec()))
                    .collect(),
            ).await;
        }
        let mut catalog = self.catalog.lock().await;
        catalog.blobs.remove(blob_id);
        self.persist_locked(&catalog)?;
        Ok(())
    }

    pub async fn abort(&self, app: &AuthenticatedAppSession, upload_id: &str) -> Result<(), BlobStoreError> {
        validate_uuid(upload_id)?;
        let _gate = self.mutation_gate.lock().await;
        let state = {
            let catalog = self.catalog.lock().await;
            catalog.uploads.get(upload_id).cloned().ok_or(BlobStoreError::UploadNotFound)?
        };
        ensure_owner(app, &state.application_id)?;
        // Veilid does not guarantee immediate erasure of already replicated
        // values. Nulling the known subkeys makes the current generation inert;
        // catalog removal prevents further writes under this app upload.
        for segment in &state.segments {
            let mut writes = Vec::with_capacity(segment.chunk_count as usize + 1);
            for location in 0..=segment.chunk_count { writes.push((location, crate::dht_module::NULL_DHT_VALUE.to_vec())); }
            let _ = self.storage.write_own(app, &segment.store_id, None, writes).await;
        }
        let mut catalog = self.catalog.lock().await;
        catalog.uploads.remove(upload_id);
        self.persist_locked(&catalog)?;
        Ok(())
    }

    async fn create_segment(
        &self,
        app: &AuthenticatedAppSession,
        blob_id: &str,
        index: u32,
        content_type: &str,
        created_at: u64,
    ) -> Result<AppStoreDescriptor, BlobStoreError> {
        let store = self.storage.create_internal_store(
            app,
            format!("blob:{blob_id}:{index}"),
            BLOB_SEGMENT_SUBKEYS,
        ).await?;
        let header = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            blob_id: blob_id.to_string(),
            segment_index: index,
            chunk_count: 0,
            payload_bytes: 0,
            next_record_key: None,
            content_type: (index == 0).then(|| content_type.to_string()),
            total_bytes: None,
            segment_count: None,
            sha256: None,
            created_at,
            finalized_at: None,
        };
        self.write_header(app, &store.store_id, header).await?;
        Ok(store)
    }

    fn make_header(
        &self,
        state: &UploadState,
        index: usize,
        next: Option<String>,
        finalized: bool,
        final_data: Option<([u8; 32], u64)>,
    ) -> SegmentHeader {
        let segment = &state.segments[index];
        SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            blob_id: state.blob_id.clone(),
            segment_index: index as u32,
            chunk_count: segment.chunk_count,
            payload_bytes: segment.payload_bytes,
            next_record_key: next,
            content_type: (index == 0).then(|| state.content_type.clone()),
            total_bytes: (index == 0 && finalized).then_some(state.committed_bytes),
            segment_count: (index == 0 && finalized).then_some(state.segments.len() as u32),
            sha256: (index == 0).then(|| final_data.map(|v| v.0)).flatten(),
            created_at: state.created_at,
            finalized_at: finalized.then(|| final_data.map(|v| v.1)).flatten(),
        }
    }

    async fn write_header(&self, app: &AuthenticatedAppSession, store_id: &str, header: SegmentHeader) -> Result<(), BlobStoreError> {
        let bytes = bincode::serialize(&header).map_err(|e| BlobStoreError::InvalidManifest(e.to_string()))?;
        if bytes.len() > BLOB_CHUNK_BYTES { return Err(BlobStoreError::InvalidManifest("segment header too large".into())); }
        self.storage.write_own(app, store_id, None, vec![(0, bytes)]).await?;
        Ok(())
    }

    async fn hash_owned_upload(&self, app: &AuthenticatedAppSession, state: &UploadState) -> Result<[u8; 32], BlobStoreError> {
        let mut hasher = Sha256::new();
        for segment in &state.segments {
            if segment.chunk_count == 0 { continue; }
            let locations: Vec<u32> = (1..=segment.chunk_count).collect();
            let (_, values) = self.storage.read_own(app, &segment.store_id, locations, false).await?;
            for value in values { hasher.update(decode_store_value(value)?); }
        }
        Ok(hasher.finalize().into())
    }

    async fn read_public_header(&self, record_key: RecordKey, force_refresh: bool) -> Result<SegmentHeader, BlobStoreError> {
        let mut values = self.storage.read_public(record_key, vec![0], force_refresh).await?;
        let value = values.pop().ok_or_else(|| BlobStoreError::InvalidManifest("header subkey missing".into()))?;
        let bytes = decode_store_value(value)?;
        bincode::deserialize(&bytes).map_err(|e| BlobStoreError::InvalidManifest(e.to_string()))
    }

    fn persist_locked(&self, catalog: &BlobCatalog) -> Result<(), BlobStoreError> {
        self.auth.write_user_encrypted(&self.session, BLOB_CATALOG_KEY, catalog)
            .map_err(|e| BlobStoreError::Persistence(e.to_string()))
    }
}

fn validate_uuid(value: &str) -> Result<(), BlobStoreError> {
    Uuid::parse_str(value).map(|_| ()).map_err(|_| BlobStoreError::InvalidUploadId)
}

fn ensure_owner(app: &AuthenticatedAppSession, owner: &str) -> Result<(), BlobStoreError> {
    if app.app_id().to_string() == owner { Ok(()) } else { Err(BlobStoreError::BlobNotFound) }
}

fn status_from_upload(state: &UploadState) -> BlobUploadStatus {
    BlobUploadStatus {
        upload_id: state.upload_id.clone(),
        blob_id: state.blob_id.clone(),
        root_record_key: state.segments.first().map(|s| s.record_key.clone()).unwrap_or_default(),
        content_type: state.content_type.clone(),
        committed_bytes: state.committed_bytes,
        segment_count: state.segments.len() as u32,
        finalized: state.finalized,
        created_at: state.created_at,
    }
}

fn decode_store_value(value: AppStoreReadValue) -> Result<Vec<u8>, BlobStoreError> {
    if let Some(error) = value.error { return Err(BlobStoreError::InvalidManifest(error)); }
    if value.is_null { return Err(BlobStoreError::InvalidManifest(format!("subkey {} is null", value.location))); }
    let encoded = value.value_base64.ok_or_else(|| BlobStoreError::InvalidManifest(format!("subkey {} has no value", value.location)))?;
    BASE64.decode(encoded).map_err(|e| BlobStoreError::InvalidManifest(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_stays_within_configured_limit() {
        assert_eq!(BLOB_SEGMENT_SUBKEYS, 64);
        assert_eq!(BLOB_DATA_SUBKEYS_PER_SEGMENT, 63);
        assert!(BLOB_CHUNK_BYTES <= 12 * 1024);
        assert!(BLOB_MAX_BYTES > 100 * 1024 * 1024);
    }

    #[test]
    fn segment_header_round_trips() {
        let header = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            blob_id: "a".repeat(32),
            segment_index: 0,
            chunk_count: 1,
            payload_bytes: 42,
            next_record_key: None,
            content_type: Some("application/octet-stream".into()),
            total_bytes: Some(42),
            segment_count: Some(1),
            sha256: Some([7; 32]),
            created_at: 1,
            finalized_at: Some(2),
        };
        let bytes = bincode::serialize(&header).unwrap();
        assert!(bytes.len() < BLOB_CHUNK_BYTES);
        let decoded: SegmentHeader = bincode::deserialize(&bytes).unwrap();
        decoded.validate(None, 0).unwrap();
    }
}

//! Capability-scoped services exposed to authenticated local applications.
//!
//! This module deliberately keeps application signing keys and owned-store
//! writer descriptors inside the daemon. Applications receive stable public
//! descriptors and signatures, but never receive DHT writer keys or private
//! signing keys.
//!
//! ## Privacy and public identity boundaries
//!
//! Registering or authenticating an app performs **no public DHT write**. App
//! ids, executable paths, authorization request ids, local daemon usernames,
//! local app secrets, and installation metadata stay in the encrypted local
//! account. `create_store` is the deliberate exception: it creates an app-owned
//! DHT only when an authenticated app explicitly asks for network storage.
//!
//! A daemon-generated app signing key identifies one locally-authorized app
//! installation. It does not, by itself, prove that a binary is an official
//! publisher build. Cross-daemon product identity requires a separately pinned
//! publisher/release key; local authorization keys must never be reused for
//! that purpose because doing so would make installations linkable.

use std::{collections::HashMap, fmt, sync::Arc};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use futures::{stream, StreamExt};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;
use veilid_core::RecordKey;

use crate::{
    dht_module::{CreateDhtError, DHTModule, NULL_DHT_VALUE},
    identity_manager::AuthenticatedAppSession,
    types::current_timestamp,
    user_auth::{UserAuth, UserSession},
    };

const APP_STORE_CATALOG_KEY: &str = "application_network_stores_v1";
const APP_SIGNING_KEYS_KEY: &str = "application_signing_keys_v1";
const APP_STORE_CATALOG_VERSION: u32 = 1;
const APP_SIGNING_STORE_VERSION: u32 = 1;
const APP_SIGNATURE_PREFIX: &[u8] = b"veilknit/app-signature/v1\0";

pub const MAX_APP_STORES_PER_APP: usize = 64;
const MAX_INTERNAL_APP_STORES_PER_APP: usize = 2048;
pub const MAX_APP_STORE_SUBKEYS: u16 = 1000;
pub const MAX_APP_STORE_WRITES_PER_REQUEST: usize = 128;
pub const MAX_APP_STORE_READS_PER_REQUEST: usize = 256;
pub const MAX_APP_STORE_VALUE_BYTES: usize = 32 * 1024;
pub const MAX_APP_STORE_WRITE_BYTES_PER_REQUEST: usize = 512 * 1024;
pub const MAX_APP_SIGNATURE_PAYLOAD_BYTES: usize = 128 * 1024;
pub const MAX_APP_SIGNATURE_DOMAIN_BYTES: usize = 128;
const STORE_INITIALIZE_CONCURRENCY: usize = 32;
const STORE_IO_CONCURRENCY: usize = 32;

#[derive(Debug)]
pub enum AppServiceError {
    InvalidName,
    InvalidStoreId,
    StoreNotFound,
    TooManyStores,
    InvalidSubkeyCount,
    InvalidSubkey(u32),
    TooManyReads,
    TooManyWrites,
    ValueTooLarge(usize),
    WriteRequestTooLarge(usize),
    GenerationConflict { expected: u64, actual: u64 },
    InvalidDomain,
    SignaturePayloadTooLarge(usize),
    InvalidPublicKey,
    InvalidSignature,
    Persistence(String),
    Dht(String),
}

impl fmt::Display for AppServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => write!(formatter, "store name is empty or too long"),
            Self::InvalidStoreId => write!(formatter, "store id is malformed"),
            Self::StoreNotFound => write!(formatter, "application store was not found"),
            Self::TooManyStores => write!(formatter, "application store limit reached"),
            Self::InvalidSubkeyCount => write!(formatter, "subkey count must be between 1 and {MAX_APP_STORE_SUBKEYS}"),
            Self::InvalidSubkey(location) => write!(formatter, "subkey {location} is outside the store"),
            Self::TooManyReads => write!(formatter, "too many subkeys requested in one read"),
            Self::TooManyWrites => write!(formatter, "too many subkeys requested in one write"),
            Self::ValueTooLarge(size) => write!(formatter, "store value is {size} bytes; maximum is {MAX_APP_STORE_VALUE_BYTES}"),
            Self::WriteRequestTooLarge(size) => write!(formatter, "store write request contains {size} payload bytes; maximum is {MAX_APP_STORE_WRITE_BYTES_PER_REQUEST}"),
            Self::GenerationConflict { expected, actual } => write!(formatter, "store generation conflict: expected {expected}, current generation is {actual}"),
            Self::InvalidDomain => write!(formatter, "signature domain is empty or too long"),
            Self::SignaturePayloadTooLarge(size) => write!(formatter, "signature payload is {size} bytes; maximum is {MAX_APP_SIGNATURE_PAYLOAD_BYTES}"),
            Self::InvalidPublicKey => write!(formatter, "invalid Ed25519 public key"),
            Self::InvalidSignature => write!(formatter, "invalid Ed25519 signature"),
            Self::Persistence(message) => write!(formatter, "application service persistence failed: {message}"),
            Self::Dht(message) => write!(formatter, "application DHT operation failed: {message}"),
        }
    }
}

impl std::error::Error for AppServiceError {}

impl From<CreateDhtError> for AppServiceError {
    fn from(value: CreateDhtError) -> Self {
        Self::Dht(format!("{value:?}"))
    }
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
struct StoredAppStore {
    descriptor: AppStoreDescriptor,
    package_index: usize,
    /// Daemon-owned backing records (for example blob segments) are hidden
    /// from the generic app-store listing and have a separate bounded quota.
    #[serde(default)]
    internal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppStoreCatalog {
    version: u32,
    stores: HashMap<String, Vec<StoredAppStore>>,
}

impl Default for AppStoreCatalog {
    fn default() -> Self {
        Self {
            version: APP_STORE_CATALOG_VERSION,
            stores: HashMap::new(),
        }
    }
}

#[derive(Clone)]
pub struct AppStorageManager {
    auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    dht: DHTModule,
    catalog: Arc<Mutex<AppStoreCatalog>>,
    write_gate: Arc<Mutex<()>>,
}

impl AppStorageManager {
    pub fn load(
        auth: Arc<UserAuth>,
        session: Arc<UserSession>,
        dht: DHTModule,
    ) -> Result<Self, AppServiceError> {
        let catalog = auth
            .read_user_encrypted::<AppStoreCatalog>(&session, APP_STORE_CATALOG_KEY)
            .map_err(|error| AppServiceError::Persistence(error.to_string()))?
            .unwrap_or_default();
        if catalog.version != APP_STORE_CATALOG_VERSION {
            return Err(AppServiceError::Persistence(format!(
                "unsupported app store catalog version {}",
                catalog.version
            )));
        }
        Ok(Self {
            auth,
            session,
            dht,
            catalog: Arc::new(Mutex::new(catalog)),
            write_gate: Arc::new(Mutex::new(())),
        })
    }

    pub async fn list_stores(&self, app: &AuthenticatedAppSession) -> Vec<AppStoreDescriptor> {
        let catalog = self.catalog.lock().await;
        catalog
            .stores
            .get(&app.app_id().to_string())
            .map(|stores| stores.iter().filter(|store| !store.internal).map(|store| store.descriptor.clone()).collect())
            .unwrap_or_default()
    }

    pub async fn create_store(
        &self,
        app: &AuthenticatedAppSession,
        name: String,
        subkey_count: u16,
        initialize: bool,
    ) -> Result<AppStoreDescriptor, AppServiceError> {
        self.create_store_impl(app, name, subkey_count, initialize, false).await
    }

    /// Create a daemon-managed record on behalf of an app. Internal records
    /// remain capability-scoped to the same app but do not clutter the generic
    /// app-store list or consume its small user-facing quota.
    pub(crate) async fn create_internal_store(
        &self,
        app: &AuthenticatedAppSession,
        name: String,
        subkey_count: u16,
    ) -> Result<AppStoreDescriptor, AppServiceError> {
        self.create_store_impl(app, name, subkey_count, false, true).await
    }

    async fn create_store_impl(
        &self,
        app: &AuthenticatedAppSession,
        name: String,
        subkey_count: u16,
        initialize: bool,
        internal: bool,
    ) -> Result<AppStoreDescriptor, AppServiceError> {
        let name = name.trim().to_string();
        if name.is_empty() || name.len() > 128 {
            return Err(AppServiceError::InvalidName);
        }
        if !(1..=MAX_APP_STORE_SUBKEYS).contains(&subkey_count) {
            return Err(AppServiceError::InvalidSubkeyCount);
        }
        let _gate = self.write_gate.lock().await;
        let app_id = app.app_id().to_string();
        {
            let catalog = self.catalog.lock().await;
            let stores = catalog.stores.get(&app_id);
            let count = stores.map_or(0, |stores| {
                stores.iter().filter(|store| store.internal == internal).count()
            });
            let limit = if internal { MAX_INTERNAL_APP_STORES_PER_APP } else { MAX_APP_STORES_PER_APP };
            if count >= limit {
                return Err(AppServiceError::TooManyStores);
            }
        }

        let store_id = Uuid::new_v4().simple().to_string();
        let dht_name = format!("app:{app_id}:{store_id}:{name}");
        let package_index = self
            .dht
            .create_dht(dht_name, vec![subkey_count])
            .await?;
        let record_key = self.dht.package_id_to_key(package_index).await?;

        if initialize {
            let dht = self.dht.clone();
            let failures: Vec<_> = stream::iter(0..u32::from(subkey_count))
                .map(move |location| {
                    let dht = dht.clone();
                    async move {
                        dht.write_to_dht(package_index, location, NULL_DHT_VALUE.to_vec())
                            .await
                            .map(|_| ())
                            .map_err(|error| (location, error))
                    }
                })
                .buffer_unordered(STORE_INITIALIZE_CONCURRENCY)
                .filter_map(|result| async move { result.err() })
                .collect()
                .await;
            if let Some((location, error)) = failures.into_iter().next() {
                return Err(AppServiceError::Dht(format!(
                    "failed to initialize subkey {location}: {error:?}"
                )));
            }
        }

        let descriptor = AppStoreDescriptor {
            store_id,
            application_id: app_id.clone(),
            name,
            record_key: record_key.to_string(),
            subkey_count,
            generation: 0,
            created_at: current_timestamp(),
        };
        {
            let mut catalog = self.catalog.lock().await;
            catalog
                .stores
                .entry(app_id)
                .or_default()
                .push(StoredAppStore {
                    descriptor: descriptor.clone(),
                    package_index,
                    internal,
                });
            self.persist_catalog_locked(&catalog)?;
        }
        self.persist_dht_snapshot().await?;
        Ok(descriptor)
    }

    pub async fn read_own(
        &self,
        app: &AuthenticatedAppSession,
        store_id: &str,
        locations: Vec<u32>,
        force_refresh: bool,
    ) -> Result<(AppStoreDescriptor, Vec<AppStoreReadValue>), AppServiceError> {
        validate_store_id(store_id)?;
        if locations.len() > MAX_APP_STORE_READS_PER_REQUEST {
            return Err(AppServiceError::TooManyReads);
        }
        let stored = self.find_owned_store(app, store_id).await?;
        validate_locations(&stored.descriptor, &locations)?;
        let package_index = stored.package_index;
        let dht = self.dht.clone();
        let values = stream::iter(deduplicate_locations(locations))
            .map(move |location| {
                let dht = dht.clone();
                async move {
                    let value = dht.read_from_dht(package_index, location, force_refresh).await;
                    app_store_read_value(location, value.map_err(AppServiceError::from))
                }
            })
            .buffer_unordered(STORE_IO_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        let mut values = values;
        values.sort_by_key(|value| value.location);
        Ok((stored.descriptor, values))
    }

    pub async fn write_own(
        &self,
        app: &AuthenticatedAppSession,
        store_id: &str,
        expected_generation: Option<u64>,
        writes: Vec<(u32, Vec<u8>)>,
    ) -> Result<AppStoreDescriptor, AppServiceError> {
        validate_store_id(store_id)?;
        if writes.is_empty() || writes.len() > MAX_APP_STORE_WRITES_PER_REQUEST {
            return Err(AppServiceError::TooManyWrites);
        }
        let total_payload_bytes = writes
            .iter()
            .try_fold(0usize, |total, (_, value)| total.checked_add(value.len()))
            .unwrap_or(usize::MAX);
        if total_payload_bytes > MAX_APP_STORE_WRITE_BYTES_PER_REQUEST {
            return Err(AppServiceError::WriteRequestTooLarge(total_payload_bytes));
        }
        for (_, value) in &writes {
            if value.len() > MAX_APP_STORE_VALUE_BYTES {
                return Err(AppServiceError::ValueTooLarge(value.len()));
            }
        }

        let _gate = self.write_gate.lock().await;
        let stored = self.find_owned_store(app, store_id).await?;
        if let Some(expected) = expected_generation {
            if expected != stored.descriptor.generation {
                return Err(AppServiceError::GenerationConflict {
                    expected,
                    actual: stored.descriptor.generation,
                });
            }
        }
        validate_locations(
            &stored.descriptor,
            &writes.iter().map(|(location, _)| *location).collect::<Vec<_>>(),
        )?;

        let package_index = stored.package_index;
        let dht = self.dht.clone();
        let failures: Vec<_> = stream::iter(writes)
            .map(move |(location, value)| {
                let dht = dht.clone();
                async move {
                    dht.write_to_dht(package_index, location, value)
                        .await
                        .map(|_| ())
                        .map_err(|error| (location, error))
                }
            })
            .buffer_unordered(STORE_IO_CONCURRENCY)
            .filter_map(|result| async move { result.err() })
            .collect()
            .await;
        if let Some((location, error)) = failures.into_iter().next() {
            return Err(AppServiceError::Dht(format!(
                "failed to write subkey {location}: {error:?}"
            )));
        }

        let mut catalog = self.catalog.lock().await;
        let stores = catalog
            .stores
            .get_mut(&app.app_id().to_string())
            .ok_or(AppServiceError::StoreNotFound)?;
        let store = stores
            .iter_mut()
            .find(|store| store.descriptor.store_id == store_id)
            .ok_or(AppServiceError::StoreNotFound)?;
        store.descriptor.generation = store.descriptor.generation.saturating_add(1);
        let descriptor = store.descriptor.clone();
        self.persist_catalog_locked(&catalog)?;
        Ok(descriptor)
    }

    pub async fn read_public(
        &self,
        record_key: RecordKey,
        locations: Vec<u32>,
        force_refresh: bool,
    ) -> Result<Vec<AppStoreReadValue>, AppServiceError> {
        if locations.is_empty() || locations.len() > MAX_APP_STORE_READS_PER_REQUEST {
            return Err(AppServiceError::TooManyReads);
        }
        let results = self
            .dht
            .read_foreign_subkeys(record_key, deduplicate_locations(locations), force_refresh)
            .await?;
        Ok(results
            .into_iter()
            .map(|(location, result)| app_store_read_value(location, result.map_err(AppServiceError::from)))
            .collect())
    }

    async fn find_owned_store(
        &self,
        app: &AuthenticatedAppSession,
        store_id: &str,
    ) -> Result<StoredAppStore, AppServiceError> {
        let catalog = self.catalog.lock().await;
        catalog
            .stores
            .get(&app.app_id().to_string())
            .and_then(|stores| {
                stores
                    .iter()
                    .find(|store| store.descriptor.store_id == store_id)
            })
            .cloned()
            .ok_or(AppServiceError::StoreNotFound)
    }

    fn persist_catalog_locked(&self, catalog: &AppStoreCatalog) -> Result<(), AppServiceError> {
        self.auth
            .write_user_encrypted(&self.session, APP_STORE_CATALOG_KEY, catalog)
            .map_err(|error| AppServiceError::Persistence(error.to_string()))
    }

    async fn persist_dht_snapshot(&self) -> Result<(), AppServiceError> {
        let snapshot = self.dht.export_snapshot().await;
        crate::user_dht::persist_dht_snapshot(&self.auth, &self.session, &snapshot)
            .map_err(|error| AppServiceError::Persistence(error.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStoreReadValue {
    pub location: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_base64: Option<String>,
    pub is_null: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn app_store_read_value(
    location: u32,
    value: Result<Vec<u8>, AppServiceError>,
) -> AppStoreReadValue {
    match value {
        Ok(value) if value == NULL_DHT_VALUE => AppStoreReadValue {
            location,
            value_base64: None,
            is_null: true,
            error: None,
        },
        Ok(value) => AppStoreReadValue {
            location,
            value_base64: Some(BASE64.encode(value)),
            is_null: false,
            error: None,
        },
        Err(error) => AppStoreReadValue {
            location,
            value_base64: None,
            is_null: false,
            error: Some(error.to_string()),
        },
    }
}

fn validate_store_id(store_id: &str) -> Result<(), AppServiceError> {
    Uuid::parse_str(store_id)
        .map(|_| ())
        .map_err(|_| AppServiceError::InvalidStoreId)
}

fn validate_locations(
    descriptor: &AppStoreDescriptor,
    locations: &[u32],
) -> Result<(), AppServiceError> {
    if let Some(location) = locations
        .iter()
        .copied()
        .find(|location| *location >= u32::from(descriptor.subkey_count))
    {
        return Err(AppServiceError::InvalidSubkey(location));
    }
    Ok(())
}

fn deduplicate_locations(mut locations: Vec<u32>) -> Vec<u32> {
    locations.sort_unstable();
    locations.dedup();
    locations
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSigningKey {
    generation: u64,
    created_at: u64,
    secret_key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppSigningStore {
    version: u32,
    keys: HashMap<String, StoredSigningKey>,
}

impl Default for AppSigningStore {
    fn default() -> Self {
        Self {
            version: APP_SIGNING_STORE_VERSION,
            keys: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSigningIdentity {
    pub application_id: String,
    pub main_dht: String,
    pub key_generation: u64,
    pub public_key_hex: String,
    pub created_at: u64,
    /// This is a daemon-authenticated installation key bound to the local
    /// account at issuance time. It contains no account name, OS username,
    /// executable path, device identifier, or local authentication secret.
    /// Applications may publish/pin the public half in their own protocol data,
    /// but must not present it as proof of an official publisher build.
    pub binding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSignatureResult {
    pub application_id: String,
    pub key_generation: u64,
    pub public_key_hex: String,
    pub domain: String,
    pub signature_hex: String,
}

#[derive(Clone)]
pub struct AppSigningManager {
    auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    store: Arc<Mutex<AppSigningStore>>,
}

impl AppSigningManager {
    pub fn load(
        auth: Arc<UserAuth>,
        session: Arc<UserSession>,
    ) -> Result<Self, AppServiceError> {
        let store = auth
            .read_user_encrypted::<AppSigningStore>(&session, APP_SIGNING_KEYS_KEY)
            .map_err(|error| AppServiceError::Persistence(error.to_string()))?
            .unwrap_or_default();
        if store.version != APP_SIGNING_STORE_VERSION {
            return Err(AppServiceError::Persistence(format!(
                "unsupported app signing store version {}",
                store.version
            )));
        }
        Ok(Self {
            auth,
            session,
            store: Arc::new(Mutex::new(store)),
        })
    }

    pub async fn identity(
        &self,
        app: &AuthenticatedAppSession,
        main_dht: &str,
    ) -> Result<AppSigningIdentity, AppServiceError> {
        let record = self.ensure_key(app).await?;
        let signing_key = SigningKey::from_bytes(&record.secret_key);
        Ok(AppSigningIdentity {
            application_id: app.app_id().to_string(),
            main_dht: main_dht.to_string(),
            key_generation: record.generation,
            public_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            created_at: record.created_at,
            binding: "daemon_authenticated_local_account".to_string(),
        })
    }

    pub async fn sign(
        &self,
        app: &AuthenticatedAppSession,
        domain: String,
        payload: &[u8],
    ) -> Result<AppSignatureResult, AppServiceError> {
        validate_signature_input(&domain, payload)?;
        let record = self.ensure_key(app).await?;
        let signing_key = SigningKey::from_bytes(&record.secret_key);
        let signature = signing_key.sign(&signature_message(&domain, payload));
        Ok(AppSignatureResult {
            application_id: app.app_id().to_string(),
            key_generation: record.generation,
            public_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            domain,
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }

    pub async fn rotate(
        &self,
        app: &AuthenticatedAppSession,
        main_dht: &str,
    ) -> Result<AppSigningIdentity, AppServiceError> {
        let app_id = app.app_id().to_string();
        let mut store = self.store.lock().await;
        let next_generation = store
            .keys
            .get(&app_id)
            .map_or(1, |record| record.generation.saturating_add(1));
        let signing_key = SigningKey::generate(&mut OsRng);
        let record = StoredSigningKey {
            generation: next_generation,
            created_at: current_timestamp(),
            secret_key: signing_key.to_bytes(),
        };
        store.keys.insert(app_id.clone(), record.clone());
        self.persist_locked(&store)?;
        Ok(AppSigningIdentity {
            application_id: app_id,
            main_dht: main_dht.to_string(),
            key_generation: record.generation,
            public_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            created_at: record.created_at,
            binding: "daemon_authenticated_local_account".to_string(),
        })
    }

    pub fn verify(
        public_key: &[u8; 32],
        domain: &str,
        payload: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, AppServiceError> {
        validate_signature_input(domain, payload)?;
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| AppServiceError::InvalidPublicKey)?;
        let signature = Signature::from_bytes(signature);
        Ok(verifying_key
            .verify(&signature_message(domain, payload), &signature)
            .is_ok())
    }

    async fn ensure_key(
        &self,
        app: &AuthenticatedAppSession,
    ) -> Result<StoredSigningKey, AppServiceError> {
        let app_id = app.app_id().to_string();
        let mut store = self.store.lock().await;
        if let Some(record) = store.keys.get(&app_id) {
            return Ok(record.clone());
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let record = StoredSigningKey {
            generation: 1,
            created_at: current_timestamp(),
            secret_key: signing_key.to_bytes(),
        };
        store.keys.insert(app_id, record.clone());
        self.persist_locked(&store)?;
        Ok(record)
    }

    fn persist_locked(&self, store: &AppSigningStore) -> Result<(), AppServiceError> {
        self.auth
            .write_user_encrypted(&self.session, APP_SIGNING_KEYS_KEY, store)
            .map_err(|error| AppServiceError::Persistence(error.to_string()))
    }
}

fn validate_signature_input(domain: &str, payload: &[u8]) -> Result<(), AppServiceError> {
    if domain.is_empty() || domain.len() > MAX_APP_SIGNATURE_DOMAIN_BYTES {
        return Err(AppServiceError::InvalidDomain);
    }
    if payload.len() > MAX_APP_SIGNATURE_PAYLOAD_BYTES {
        return Err(AppServiceError::SignaturePayloadTooLarge(payload.len()));
    }
    Ok(())
}

fn signature_message(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(APP_SIGNATURE_PREFIX.len() + domain.len() + payload.len() + 16);
    message.extend_from_slice(APP_SIGNATURE_PREFIX);
    message.extend_from_slice(&(domain.len() as u32).to_le_bytes());
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    message.extend_from_slice(payload);
    message
}

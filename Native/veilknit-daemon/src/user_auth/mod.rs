pub mod backup;

use aes_gcm::{
    aead::{Aead, OsRng, rand_core::RngCore},
    Aes256Gcm, KeyInit, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};
use zeroize::Zeroizing;

/// Encrypted user-store key for account-level setup state.
pub const USER_SETUP_STATE_KEY: &str = "user_setup_state";

const NETWORK_PROFILE_CATALOG_FILE: &str = "network_profiles.bin";
const NETWORK_PROFILE_CATALOG_VERSION: u32 = 1;
pub const DEFAULT_NETWORK_PROFILE_ID: &str = "default";
const MAX_NETWORK_PROFILE_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkProfile {
    /// Stable local identifier used only to namespace encrypted daemon state.
    /// It is not published as network identity or personally identifying data.
    pub profile_id: String,
    pub display_name: String,
    pub created_at: u64,
    pub retired_at: Option<u64>,
}

impl NetworkProfile {
    pub fn is_retired(&self) -> bool {
        self.retired_at.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkProfileCatalog {
    version: u32,
    active_profile_id: String,
    profiles: Vec<NetworkProfile>,
}

impl NetworkProfileCatalog {
    fn legacy_default() -> Self {
        Self {
            version: NETWORK_PROFILE_CATALOG_VERSION,
            active_profile_id: DEFAULT_NETWORK_PROFILE_ID.to_string(),
            profiles: vec![NetworkProfile {
                profile_id: DEFAULT_NETWORK_PROFILE_ID.to_string(),
                display_name: "Default".to_string(),
                created_at: current_timestamp(),
                retired_at: None,
            }],
        }
    }

    fn active_profile(&self) -> Option<NetworkProfile> {
        self.profiles
            .iter()
            .find(|profile| {
                profile.profile_id == self.active_profile_id && !profile.is_retired()
            })
            .cloned()
            .or_else(|| {
                self.profiles
                    .iter()
                    .find(|profile| !profile.is_retired())
                    .cloned()
            })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserSetupState {
    /// True only after the main DHT has been created, initialized, saved,
    /// and handed to the route manager.
    pub main_dht_setup: bool,

    /// DHTModule package index assigned to the main DHT.
    pub main_dht_package_index: Option<usize>,
}

#[derive(Debug)]
pub enum AuthError {
    UserAlreadyExists,
    UserNotFound,
    WrongPassword,
    InvalidUsername,
    InvalidDisplayName,
    InvalidProfileName,
    ProfileNotFound,
    ProfileRetired,
    CannotRetireActiveProfile,
    CannotRetireLastProfile,
    Io(String),
    Crypto(String),
    Serde(String),
    Backup(String),
}

impl From<std::io::Error> for AuthError {
    fn from(e: std::io::Error) -> Self {
        AuthError::Io(e.to_string())
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::UserAlreadyExists => write!(f, "user already exists"),
            AuthError::UserNotFound => write!(f, "user not found"),
            AuthError::WrongPassword => write!(f, "wrong password"),
            AuthError::InvalidUsername => write!(f, "invalid username"),
            AuthError::InvalidDisplayName => write!(f, "invalid display name"),
            AuthError::InvalidProfileName => write!(f, "invalid network profile name"),
            AuthError::ProfileNotFound => write!(f, "network profile not found"),
            AuthError::ProfileRetired => write!(f, "network profile is retired"),
            AuthError::CannotRetireActiveProfile => write!(f, "select another profile before retiring the active profile"),
            AuthError::CannotRetireLastProfile => write!(f, "the last usable network profile cannot be retired"),
            AuthError::Io(msg) => write!(f, "io error: {msg}"),
            AuthError::Crypto(msg) => write!(f, "crypto error: {msg}"),
            AuthError::Serde(msg) => write!(f, "serialization error: {msg}"),
            AuthError::Backup(msg) => write!(f, "backup error: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProfile {
    pub username: String,
    pub display_name: String,
    pub created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccountFile {
    password_hash: String,
    crypto_salt: Vec<u8>,
}

pub struct UserSession {
    user: AccountProfile,
    user_dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
    network_profile: NetworkProfile,
}

impl UserSession {
    pub fn user(&self) -> &AccountProfile {
        &self.user
    }

    pub fn username(&self) -> &str {
        &self.user.username
    }

    pub fn network_profile(&self) -> &NetworkProfile {
        &self.network_profile
    }

    pub fn network_profile_id(&self) -> &str {
        &self.network_profile.profile_id
    }

    fn user_dir(&self) -> &Path {
        &self.user_dir
    }

    /// The original default profile intentionally keeps the historical
    /// `store/` location so existing accounts migrate without copying data.
    /// Additional profiles receive isolated encrypted stores.
    pub(crate) fn store_dir(&self) -> PathBuf {
        if self.network_profile.profile_id == DEFAULT_NETWORK_PROFILE_ID {
            self.user_dir.join("store")
        } else {
            self.user_dir
                .join("profiles")
                .join(clean_key(&self.network_profile.profile_id))
                .join("store")
        }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, AuthError> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| AuthError::Crypto(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| AuthError::Crypto(e.to_string()))?;

        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.append(&mut ciphertext);

        Ok(out)
    }

    fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, AuthError> {
        if encrypted.len() < 12 {
            return Err(AuthError::Crypto("encrypted data too short".into()));
        }

        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref())
            .map_err(|e| AuthError::Crypto(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| AuthError::WrongPassword)
    }
}

pub struct UserAuth {
    root_dir: PathBuf,
}

impl UserAuth {
    pub fn new(root_dir: impl Into<PathBuf>) -> Result<Self, AuthError> {
        let root_dir = root_dir.into();

        fs::create_dir_all(root_dir.join("users"))?;
        fs::create_dir_all(root_dir.join("global"))?;

        Ok(Self { root_dir })
    }

    pub fn signup(&self, username: &str, password: &str) -> Result<UserSession, AuthError> {
        validate_username(username)?;

        let user_dir = self.user_dir(username);
        let account_path = user_dir.join("account.json");
        let profile_path = user_dir.join("user_profile.bin");

        if account_path.exists() {
            return Err(AuthError::UserAlreadyExists);
        }

        fs::create_dir_all(&user_dir)?;

        let password_salt = SaltString::generate(&mut OsRng);

        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &password_salt)
            .map_err(|e| AuthError::Crypto(e.to_string()))?
            .to_string();

        let mut crypto_salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut crypto_salt);

        let account = AccountFile {
            password_hash,
            crypto_salt: crypto_salt.clone(),
        };

        let account_bytes = serde_json::to_vec_pretty(&account)
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        atomic_write(&account_path, &account_bytes)?;

        let key = derive_key(password, &crypto_salt)?;

        let session = UserSession {
            user: AccountProfile {
                username: username.to_string(),
                display_name: username.to_string(),
                created_at: current_timestamp(),
            },
            user_dir,
            key,
            network_profile: NetworkProfileCatalog::legacy_default()
                .active_profile()
                .expect("default profile exists"),
        };

        let profile_bytes = serde_json::to_vec_pretty(session.user())
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        let encrypted_profile = session.encrypt(&profile_bytes)?;
        atomic_write(&profile_path, &encrypted_profile)?;

        self.write_network_profile_catalog(
            &session,
            &NetworkProfileCatalog::legacy_default(),
        )?;

        // A new account starts without a configured main DHT. The user_dht
        // module changes this only after the complete setup workflow succeeds.
        self.write_user_setup_state(&session, &UserSetupState::default())?;

        Ok(session)
    }

    pub fn login(&self, username: &str, password: &str) -> Result<UserSession, AuthError> {
        let login_started = Instant::now();
        validate_username(username)?;

        let user_dir = self.user_dir(username);
        let account_path = user_dir.join("account.json");
        let profile_path = user_dir.join("user_profile.bin");

        if !account_path.exists() {
            return Err(AuthError::UserNotFound);
        }

        let account_bytes = fs::read(&account_path)?;
        let account: AccountFile = serde_json::from_slice(&account_bytes)
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        let parsed_hash = PasswordHash::new(&account.password_hash)
            .map_err(|e| AuthError::Crypto(e.to_string()))?;

        let verify_started = Instant::now();
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::WrongPassword)?;
        let verify_ms = verify_started.elapsed().as_millis();

        let derive_started = Instant::now();
        let key = derive_key(password, &account.crypto_salt)?;
        let derive_ms = derive_started.elapsed().as_millis();

        let temp_session = UserSession {
            user: AccountProfile {
                username: username.to_string(),
                display_name: username.to_string(),
                created_at: 0,
            },
            user_dir,
            key,
            network_profile: NetworkProfileCatalog::legacy_default()
                .active_profile()
                .expect("default profile exists"),
        };

        let encrypted_profile = fs::read(&profile_path)?;
        let profile_bytes = temp_session.decrypt(&encrypted_profile)?;

        let user: AccountProfile = serde_json::from_slice(&profile_bytes)
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        let mut session = UserSession {
            user,
            user_dir: temp_session.user_dir,
            key: temp_session.key,
            network_profile: NetworkProfileCatalog::legacy_default()
                .active_profile()
                .expect("default profile exists"),
        };

        let loaded_catalog = self.read_network_profile_catalog(&session)?;
        let mut catalog_changed = loaded_catalog.is_none();
        let mut catalog = loaded_catalog.unwrap_or_else(NetworkProfileCatalog::legacy_default);
        if catalog.version != NETWORK_PROFILE_CATALOG_VERSION {
            // The profile catalogue is account-local metadata. Unknown future
            // formats are not interpreted in place; fall back to the legacy
            // profile and immediately persist the supported version.
            catalog = NetworkProfileCatalog::legacy_default();
            catalog_changed = true;
        }
        let active = catalog.active_profile().unwrap_or_else(|| {
            catalog_changed = true;
            NetworkProfileCatalog::legacy_default()
                .active_profile()
                .expect("default profile exists")
        });
        if catalog.active_profile_id != active.profile_id {
            catalog.active_profile_id = active.profile_id.clone();
            catalog_changed = true;
        }
        if !catalog
            .profiles
            .iter()
            .any(|profile| profile.profile_id == active.profile_id)
        {
            catalog.profiles.push(active.clone());
            catalog_changed = true;
        }
        if catalog_changed {
            self.write_network_profile_catalog(&session, &catalog)?;
        }
        session.network_profile = active;
        crate::tprintln!(
            "[startup] Account login cryptography: password_verify={}ms key_derivation={}ms total_login={}ms",
            verify_ms,
            derive_ms,
            login_started.elapsed().as_millis()
        );
        Ok(session)
    }

    pub fn write_user_encrypted<T: Serialize>(
        &self,
        session: &UserSession,
        key: &str,
        value: &T,
    ) -> Result<(), AuthError> {
        let dir = session.store_dir();
        fs::create_dir_all(&dir)?;

        let path = dir.join(format!("{}.bin", clean_key(key)));

        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        let encrypted = session.encrypt(&bytes)?;

        atomic_write(&path, &encrypted)
    }

    /// Remove one encrypted value from the active network profile. Missing
    /// values are treated as already removed.
    pub fn remove_user_encrypted(
        &self,
        session: &UserSession,
        key: &str,
    ) -> Result<(), AuthError> {
        let path = session
            .store_dir()
            .join(format!("{}.bin", clean_key(key)));
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn read_user_encrypted<T: DeserializeOwned>(
        &self,
        session: &UserSession,
        key: &str,
    ) -> Result<Option<T>, AuthError> {
        let path = session
            .store_dir()
            .join(format!("{}.bin", clean_key(key)));

        if !path.exists() {
            return Ok(None);
        }

        let encrypted = fs::read(path)?;
        let bytes = session.decrypt(&encrypted)?;

        let value = serde_json::from_slice(&bytes)
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        Ok(Some(value))
    }

    pub fn read_user_setup_state(
        &self,
        session: &UserSession,
    ) -> Result<UserSetupState, AuthError> {
        Ok(self
            .read_user_encrypted::<UserSetupState>(session, USER_SETUP_STATE_KEY)?
            .unwrap_or_default())
    }

    pub fn write_user_setup_state(
        &self,
        session: &UserSession,
        state: &UserSetupState,
    ) -> Result<(), AuthError> {
        self.write_user_encrypted(session, USER_SETUP_STATE_KEY, state)
    }

    /// Lists every local network profile, including retired profiles for
    /// audit/recovery purposes. Profile ids and names remain encrypted locally.
    pub fn list_network_profiles(
        &self,
        session: &UserSession,
    ) -> Result<Vec<NetworkProfile>, AuthError> {
        Ok(self
            .read_network_profile_catalog(session)?
            .unwrap_or_else(NetworkProfileCatalog::legacy_default)
            .profiles)
    }

    /// Creates an isolated network profile under the same encrypted login.
    /// Network services begin using it only after `select_network_profile` and
    /// a controlled daemon restart.
    pub fn create_network_profile(
        &self,
        session: &UserSession,
        display_name: &str,
    ) -> Result<NetworkProfile, AuthError> {
        let display_name = validate_profile_name(display_name)?;
        let mut catalog = self
            .read_network_profile_catalog(session)?
            .unwrap_or_else(NetworkProfileCatalog::legacy_default);
        let profile = NetworkProfile {
            profile_id: uuid::Uuid::new_v4().simple().to_string(),
            display_name,
            created_at: current_timestamp(),
            retired_at: None,
        };
        catalog.profiles.push(profile.clone());
        self.write_network_profile_catalog(session, &catalog)?;
        Ok(profile)
    }

    /// Selects which profile will be active on the next service start and
    /// returns a session scoped to it. Callers that already started network
    /// actors must shut them down before using the returned session.
    pub fn select_network_profile(
        &self,
        session: &UserSession,
        profile_id: &str,
    ) -> Result<UserSession, AuthError> {
        let mut catalog = self
            .read_network_profile_catalog(session)?
            .unwrap_or_else(NetworkProfileCatalog::legacy_default);
        let profile = catalog
            .profiles
            .iter()
            .find(|profile| profile.profile_id == profile_id)
            .cloned()
            .ok_or(AuthError::ProfileNotFound)?;
        if profile.is_retired() {
            return Err(AuthError::ProfileRetired);
        }
        catalog.active_profile_id = profile.profile_id.clone();
        self.write_network_profile_catalog(session, &catalog)?;
        Ok(UserSession {
            user: session.user.clone(),
            user_dir: session.user_dir.clone(),
            key: session.key.clone(),
            network_profile: profile,
        })
    }

    pub fn retire_network_profile(
        &self,
        session: &UserSession,
        profile_id: &str,
    ) -> Result<NetworkProfile, AuthError> {
        let mut catalog = self
            .read_network_profile_catalog(session)?
            .unwrap_or_else(NetworkProfileCatalog::legacy_default);
        if catalog.active_profile_id == profile_id {
            return Err(AuthError::CannotRetireActiveProfile);
        }
        if catalog.profiles.iter().filter(|profile| !profile.is_retired()).count() <= 1 {
            return Err(AuthError::CannotRetireLastProfile);
        }
        let profile = catalog
            .profiles
            .iter_mut()
            .find(|profile| profile.profile_id == profile_id)
            .ok_or(AuthError::ProfileNotFound)?;
        profile.retired_at = Some(current_timestamp());
        let retired = profile.clone();
        self.write_network_profile_catalog(session, &catalog)?;
        Ok(retired)
    }

    fn profile_catalog_path(&self, session: &UserSession) -> PathBuf {
        session.user_dir().join(NETWORK_PROFILE_CATALOG_FILE)
    }

    fn read_network_profile_catalog(
        &self,
        session: &UserSession,
    ) -> Result<Option<NetworkProfileCatalog>, AuthError> {
        let path = self.profile_catalog_path(session);
        if !path.exists() {
            return Ok(None);
        }
        let encrypted = fs::read(path)?;
        let bytes = session.decrypt(&encrypted)?;
        let catalog = serde_json::from_slice(&bytes)
            .map_err(|error| AuthError::Serde(error.to_string()))?;
        Ok(Some(catalog))
    }

    fn write_network_profile_catalog(
        &self,
        session: &UserSession,
        catalog: &NetworkProfileCatalog,
    ) -> Result<(), AuthError> {
        let bytes = serde_json::to_vec_pretty(catalog)
            .map_err(|error| AuthError::Serde(error.to_string()))?;
        let encrypted = session.encrypt(&bytes)?;
        atomic_write(&self.profile_catalog_path(session), &encrypted)
    }

    pub fn write_global<T: Serialize>(&self, key: &str, value: &T) -> Result<(), AuthError> {
        let path = self
            .root_dir
            .join("global")
            .join(format!("{}.json", clean_key(key)));

        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        atomic_write(&path, &bytes)
    }

    pub fn read_global<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, AuthError> {
        let path = self
            .root_dir
            .join("global")
            .join(format!("{}.json", clean_key(key)));

        if !path.exists() {
            return Ok(None);
        }

        let bytes = fs::read(path)?;

        let value = serde_json::from_slice(&bytes)
            .map_err(|e| AuthError::Serde(e.to_string()))?;

        Ok(Some(value))
    }

    fn user_dir(&self, username: &str) -> PathBuf {
        let username_hash = blake3::hash(username.as_bytes()).to_hex().to_string();
        self.root_dir.join("users").join(username_hash)
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, AuthError> {
    let mut key = Zeroizing::new([0u8; 32]);

    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| AuthError::Crypto(e.to_string()))?;

    Ok(key)
}

fn validate_username(username: &str) -> Result<(), AuthError> {
    let valid = !username.is_empty()
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');

    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidUsername)
    }
}

fn validate_profile_name(value: &str) -> Result<String, AuthError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_NETWORK_PROFILE_NAME_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err(AuthError::InvalidProfileName);
    }
    Ok(trimmed.to_string())
}

fn clean_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), AuthError> {
    let tmp = path.with_extension("tmp");

    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, path)?;

    // Best effort: syncing a directory is supported on some platforms but not
    // all (notably it may fail on Windows). The file itself has already been
    // synced, so a directory-sync failure should not make account writes fail.
    if let Some(parent) = path.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }

    Ok(())
}

fn current_timestamp() -> u64 {
    crate::support::timing::unix_seconds()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "veilknit-user-auth-test-{}",
            uuid::Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn network_profiles_isolate_encrypted_state_under_one_login() {
        let root = test_root();
        let auth = UserAuth::new(&root).expect("create auth root");
        let default_session = auth.signup("alice", "correct horse battery staple")
            .expect("create account");
        auth.write_user_encrypted(&default_session, "probe", &"default-value")
            .expect("write default profile");

        let second_profile = auth
            .create_network_profile(&default_session, "Testing")
            .expect("create second profile");
        let second_session = auth
            .select_network_profile(&default_session, &second_profile.profile_id)
            .expect("select second profile");
        assert_eq!(
            auth.read_user_encrypted::<String>(&second_session, "probe")
                .expect("read second profile"),
            None
        );
        auth.write_user_encrypted(&second_session, "probe", &"second-value")
            .expect("write second profile");

        let default_again = auth
            .select_network_profile(&second_session, DEFAULT_NETWORK_PROFILE_ID)
            .expect("return to default profile");
        assert_eq!(
            auth.read_user_encrypted::<String>(&default_again, "probe")
                .expect("read default profile")
                .as_deref(),
            Some("default-value")
        );
        assert_eq!(
            auth.read_user_encrypted::<String>(&second_session, "probe")
                .expect("read second profile again")
                .as_deref(),
            Some("second-value")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn profile_names_are_local_display_values_not_paths() {
        assert_eq!(validate_profile_name("  Test profile  ").unwrap(), "Test profile");
        assert!(validate_profile_name("bad\nname").is_err());
        assert!(validate_profile_name("").is_err());
    }
}

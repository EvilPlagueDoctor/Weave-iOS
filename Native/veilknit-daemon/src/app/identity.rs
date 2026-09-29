//! Local identity and attachment authentication for core modules and apps.
//!
//! Local app credentials contain no public profile name, OS username, path,
//! device id, or other personally identifying metadata.
//!
//! Core modules are trusted because the host process registers them directly.
//! Apps are not trusted by name alone. Each registered app receives a random
//! 256-bit credential and must answer a short-lived, one-use challenge before
//! the host returns an authenticated app session.
//!
//! This module is transport agnostic. A local socket, plugin loader, RPC layer,
//! or other attachment mechanism can carry `AppAuthChallenge` and the proof.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::network_events::{
    EventSeverity, NetworkEvent, NetworkEventBus, NetworkEventSource,
};
use crate::reputation::{
    AppId, CoreModuleId, ReputationAppHandle, ReputationManager, ReputationModuleHandle,
};
use crate::types::{current_timestamp, APP_DISCOVERY_ACTIVITY_TTL_SECS};
use crate::user_auth::{AuthError, UserAuth, UserSession};

pub const IDENTITY_STORE_KEY: &str = "identity_manager_apps";
const IDENTITY_STORE_VERSION: u32 = 1;
const APP_SECRET_BYTES: usize = 32;
const CHALLENGE_BYTES: usize = 32;
const SESSION_TOKEN_BYTES: usize = 32;
const SESSION_ID_BYTES: usize = 16;
const DEFAULT_CHALLENGE_TTL_SECS: u64 = 30;
const DEFAULT_SESSION_TTL_SECS: u64 = 12 * 60 * 60;
const MAX_PENDING_CHALLENGES: usize = 4096;
const MAX_ACTIVE_SESSIONS: usize = 4096;
const PROOF_DOMAIN: &[u8] = b"veilknit/app-auth/v2";

// ============================================================================
// Public identities and credentials
// ============================================================================


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AppCapability {
    SendMessages,
    ReceiveMessages,
    ManageOwnStorage,
    ReadOwnStorage,
    ReadPublicProfiles,
    SubscribeNetworkStatus,
    SubmitReputation,
    RequestAppScopedRestriction,
    InspectOwnReputationSubmissions,
    SignAppData,

    // Administrative capabilities are never granted by an app-supplied
    // request. The local user/host must add them to the registration.
    InspectNodes,
    InspectReputation,
    ModifyBans,
    RetractAppReputation,
    InspectDht,
    ControlWalker,
    ManageApplications,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AppCapabilitySet {
    values: BTreeSet<AppCapability>,
}

impl AppCapabilitySet {
    pub fn new(values: impl IntoIterator<Item = AppCapability>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    pub fn standard_app() -> Self {
        Self::new([
            AppCapability::SendMessages,
            AppCapability::ReceiveMessages,
            AppCapability::ManageOwnStorage,
            AppCapability::ReadOwnStorage,
            AppCapability::ReadPublicProfiles,
            AppCapability::SubscribeNetworkStatus,
            AppCapability::SubmitReputation,
            AppCapability::RequestAppScopedRestriction,
            AppCapability::InspectOwnReputationSubmissions,
            AppCapability::SignAppData,
        ])
    }

    pub fn contains(&self, capability: AppCapability) -> bool {
        self.values.contains(&capability)
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.values.is_subset(&other.values)
    }

    pub fn iter(&self) -> impl Iterator<Item = AppCapability> + '_ {
        self.values.iter().copied()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRegistration {
    pub app_id: AppId,
    pub display_name: String,
    pub created_at: u64,
    /// Last successful local authentication. This is the only activity signal
    /// used when deciding whether the app id remains in the public main-DHT
    /// advertisement. It contains no executable path, device id, or account
    /// username.
    #[serde(default)]
    pub last_used_at: u64,
    pub enabled: bool,
    pub credential_generation: u64,
    // Existing Patch-B/C registrations had unrestricted access to the app
    // APIs. Migrate them to the standard non-administrative set instead of an
    // empty set that would silently lock them out.
    #[serde(default = "AppCapabilitySet::standard_app")]
    pub granted_capabilities: AppCapabilitySet,
}

/// Returned only when an app is registered or its credential is rotated.
/// The app should store this secret in its own protected local storage.
#[derive(Clone)]
pub struct AppCredential {
    pub app_id: AppId,
    secret: [u8; APP_SECRET_BYTES],
    pub credential_generation: u64,
}

impl AppCredential {
    pub fn secret_bytes(&self) -> &[u8; APP_SECRET_BYTES] {
        &self.secret
    }

    pub fn into_secret_bytes(self) -> [u8; APP_SECRET_BYTES] {
        self.secret
    }

    /// Compute the response an app sends for a challenge.
    pub fn answer(&self, challenge: &AppAuthChallenge) -> Result<AppAuthResponse, IdentityError> {
        if self.app_id != challenge.app_id {
            return Err(IdentityError::CredentialDoesNotMatchChallenge);
        }
        if self.credential_generation != challenge.credential_generation {
            return Err(IdentityError::CredentialGenerationMismatch);
        }

        Ok(AppAuthResponse {
            app_id: self.app_id.clone(),
            challenge_id: challenge.challenge_id,
            proof: compute_app_proof(&self.secret, challenge),
        })
    }
}

impl fmt::Debug for AppCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppCredential")
            .field("app_id", &self.app_id)
            .field("secret", &"[REDACTED]")
            .field("credential_generation", &self.credential_generation)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuthChallenge {
    pub app_id: AppId,
    pub challenge_id: u64,
    pub nonce: [u8; CHALLENGE_BYTES],
    pub issued_at: u64,
    pub expires_at: u64,
    pub credential_generation: u64,
    #[serde(default)]
    pub requested_capabilities: AppCapabilitySet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuthResponse {
    pub app_id: AppId,
    pub challenge_id: u64,
    pub proof: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppSessionId([u8; SESSION_ID_BYTES]);

impl AppSessionId {
    pub fn as_bytes(&self) -> &[u8; SESSION_ID_BYTES] {
        &self.0
    }
}

impl fmt::Display for AppSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppSessionToken([u8; SESSION_TOKEN_BYTES]);

impl AppSessionToken {
    pub fn from_bytes(bytes: [u8; SESSION_TOKEN_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SESSION_TOKEN_BYTES] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; SESSION_TOKEN_BYTES] {
        self.0
    }
}

impl fmt::Debug for AppSessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppSessionToken([REDACTED])")
    }
}

impl fmt::Display for AppSessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED APP SESSION TOKEN]")
    }
}

/// Host-minted proof that one registered app completed the challenge-response
/// flow. All fields are private, so an attached app cannot manufacture a
/// session for another `AppId` or add capabilities to itself.
#[derive(Debug, Clone)]
pub struct AuthenticatedAppSession {
    app_id: AppId,
    session_id: AppSessionId,
    session_token: AppSessionToken,
    authenticated_at: u64,
    expires_at: u64,
    credential_generation: u64,
    capabilities: AppCapabilitySet,
}

impl AuthenticatedAppSession {
    pub fn app_id(&self) -> &AppId {
        &self.app_id
    }

    pub fn session_id(&self) -> &AppSessionId {
        &self.session_id
    }

    pub fn session_token(&self) -> &AppSessionToken {
        &self.session_token
    }

    pub fn authenticated_at(&self) -> u64 {
        self.authenticated_at
    }

    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    pub fn capabilities(&self) -> &AppCapabilitySet {
        &self.capabilities
    }

    pub fn has_capability(&self, capability: AppCapability) -> bool {
        self.capabilities.contains(capability)
    }

    pub fn require_capability(&self, capability: AppCapability) -> Result<(), IdentityError> {
        if self.has_capability(capability) {
            Ok(())
        } else {
            Err(IdentityError::CapabilityDenied(capability))
        }
    }

    pub fn reputation_handle(
        &self,
        reputation: &ReputationManager,
    ) -> Result<ReputationAppHandle, IdentityError> {
        self.require_capability(AppCapability::SubmitReputation)?;
        Ok(reputation.authenticated_app_handle_with_session(
            self.app_id.clone(),
            self.session_id.to_string(),
            self.credential_generation,
            self.authenticated_at,
        ))
    }
}

/// Compatibility name for modules written against Patch B/C. New code should
/// use `AuthenticatedAppSession` so the lifetime/capability semantics are clear.
pub type AuthenticatedAppIdentity = AuthenticatedAppSession;

/// Core-module identities are minted only by direct host registration.
#[derive(Debug, Clone)]
pub struct AuthenticatedModuleIdentity {
    module_id: CoreModuleId,
}

impl AuthenticatedModuleIdentity {
    pub fn module_id(&self) -> &CoreModuleId {
        &self.module_id
    }

    pub fn reputation_handle(&self, reputation: &ReputationManager) -> ReputationModuleHandle {
        reputation.core_module_handle(self.module_id.clone())
    }
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
pub enum IdentityError {
    AppAlreadyRegistered,
    AppNotRegistered,
    AppDisabled,
    ModuleAlreadyRegistered,
    InvalidDisplayName,
    TooManyPendingChallenges,
    TooManyActiveSessions,
    ChallengeNotFound,
    ChallengeExpired,
    ChallengeAppMismatch,
    CredentialDoesNotMatchChallenge,
    CredentialGenerationMismatch,
    InvalidProof,
    SessionNotFound,
    SessionExpired,
    CapabilityDenied(AppCapability),
    StoreVersionUnsupported(u32),
    Persistence(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppAlreadyRegistered => write!(f, "app id is already registered"),
            Self::AppNotRegistered => write!(f, "app id is not registered"),
            Self::AppDisabled => write!(f, "app identity is disabled"),
            Self::ModuleAlreadyRegistered => write!(f, "core module is already registered"),
            Self::InvalidDisplayName => write!(f, "invalid app display name"),
            Self::TooManyPendingChallenges => write!(f, "too many pending app challenges"),
            Self::TooManyActiveSessions => write!(f, "too many active app sessions"),
            Self::ChallengeNotFound => write!(f, "authentication challenge was not found or was already used"),
            Self::ChallengeExpired => write!(f, "authentication challenge expired"),
            Self::ChallengeAppMismatch => write!(f, "challenge belongs to another app"),
            Self::CredentialDoesNotMatchChallenge => write!(f, "credential belongs to another app"),
            Self::CredentialGenerationMismatch => write!(f, "app credential has been rotated"),
            Self::InvalidProof => write!(f, "invalid app authentication proof"),
            Self::SessionNotFound => write!(f, "app session was not found"),
            Self::SessionExpired => write!(f, "app session expired"),
            Self::CapabilityDenied(capability) => {
                write!(f, "app session lacks capability {capability:?}")
            }
            Self::StoreVersionUnsupported(version) => {
                write!(f, "unsupported identity-store version {version}")
            }
            Self::Persistence(message) => write!(f, "identity persistence error: {message}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<AuthError> for IdentityError {
    fn from(value: AuthError) -> Self {
        Self::Persistence(value.to_string())
    }
}

// ============================================================================
// Persistent and runtime state
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAppIdentity {
    registration: AppRegistration,
    secret: [u8; APP_SECRET_BYTES],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityStore {
    version: u32,
    next_challenge_id: u64,
    apps: HashMap<String, StoredAppIdentity>,
}

impl Default for IdentityStore {
    fn default() -> Self {
        Self {
            version: IDENTITY_STORE_VERSION,
            next_challenge_id: 1,
            apps: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct PendingChallenge {
    challenge: AppAuthChallenge,
}

#[derive(Debug, Clone)]
struct ActiveAppSession {
    app_id: AppId,
    session_id: AppSessionId,
    authenticated_at: u64,
    expires_at: u64,
    credential_generation: u64,
    capabilities: AppCapabilitySet,
}

struct Inner {
    store: IdentityStore,
    core_modules: HashMap<String, AuthenticatedModuleIdentity>,
    pending_challenges: HashMap<u64, PendingChallenge>,
    active_sessions: HashMap<AppSessionToken, ActiveAppSession>,
}

// ============================================================================
// Manager
// ============================================================================

#[derive(Clone)]
pub struct IdentityManager {
    user_auth: Arc<UserAuth>,
    user_session: Arc<UserSession>,
    inner: Arc<Mutex<Inner>>,
    events: Option<NetworkEventBus>,
    challenge_ttl_secs: u64,
    session_ttl_secs: u64,
}

impl IdentityManager {
    pub fn load(
        user_auth: Arc<UserAuth>,
        user_session: Arc<UserSession>,
    ) -> Result<Self, IdentityError> {
        Self::load_internal(user_auth, user_session, None)
    }

    pub fn load_with_event_bus(
        user_auth: Arc<UserAuth>,
        user_session: Arc<UserSession>,
        events: NetworkEventBus,
    ) -> Result<Self, IdentityError> {
        Self::load_internal(user_auth, user_session, Some(events))
    }

    fn load_internal(
        user_auth: Arc<UserAuth>,
        user_session: Arc<UserSession>,
        events: Option<NetworkEventBus>,
    ) -> Result<Self, IdentityError> {
        let store = user_auth
            .read_user_encrypted::<IdentityStore>(&user_session, IDENTITY_STORE_KEY)?
            .unwrap_or_default();

        if store.version != IDENTITY_STORE_VERSION {
            return Err(IdentityError::StoreVersionUnsupported(store.version));
        }

        Ok(Self {
            user_auth,
            user_session,
            inner: Arc::new(Mutex::new(Inner {
                store,
                core_modules: HashMap::new(),
                pending_challenges: HashMap::new(),
                active_sessions: HashMap::new(),
            })),
            events,
            challenge_ttl_secs: DEFAULT_CHALLENGE_TTL_SECS,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
        })
    }

    /// Register a trusted in-process core module. Core-module registrations are
    /// deliberately not loaded from disk: the host executable must declare
    /// them again on every startup.
    pub async fn register_core_module(
        &self,
        module_id: CoreModuleId,
    ) -> Result<AuthenticatedModuleIdentity, IdentityError> {
        let mut inner = self.inner.lock().await;
        let key = module_id.to_string();
        if inner.core_modules.contains_key(&key) {
            return Err(IdentityError::ModuleAlreadyRegistered);
        }

        let identity = AuthenticatedModuleIdentity { module_id };
        inner.core_modules.insert(key, identity.clone());
        Ok(identity)
    }

    /// Create a persistent app identity with the standard non-administrative
    /// capability set and return its credential exactly once.
    pub async fn register_app(
        &self,
        app_id: AppId,
        display_name: impl Into<String>,
    ) -> Result<AppCredential, IdentityError> {
        self.register_app_with_capabilities(
            app_id,
            display_name,
            AppCapabilitySet::standard_app(),
        )
        .await
    }

    pub async fn register_app_with_capabilities(
        &self,
        app_id: AppId,
        display_name: impl Into<String>,
        granted_capabilities: AppCapabilitySet,
    ) -> Result<AppCredential, IdentityError> {
        let display_name = display_name.into();
        validate_display_name(&display_name)?;

        let mut inner = self.inner.lock().await;
        let key = app_id.to_string();
        if inner.store.apps.contains_key(&key) {
            return Err(IdentityError::AppAlreadyRegistered);
        }

        let mut secret = [0u8; APP_SECRET_BYTES];
        OsRng.fill_bytes(&mut secret);
        let generation = 1;
        let created_at = current_timestamp();
        let registration = AppRegistration {
            app_id: app_id.clone(),
            display_name,
            created_at,
            // Approval alone is not public app activity. The first successful
            // challenge-response authentication records actual use.
            last_used_at: 0,
            enabled: true,
            credential_generation: generation,
            granted_capabilities,
        };

        inner.store.apps.insert(
            key,
            StoredAppIdentity {
                registration,
                secret,
            },
        );
        self.persist_locked(&inner)?;

        Ok(AppCredential {
            app_id,
            secret,
            credential_generation: generation,
        })
    }

    /// Replace an app's secret. All old credentials, pending challenges, and
    /// active sessions for that app become invalid.
    pub async fn rotate_app_credential(
        &self,
        app_id: &AppId,
    ) -> Result<AppCredential, IdentityError> {
        let mut inner = self.inner.lock().await;
        let key = app_id.to_string();
        let stored = inner
            .store
            .apps
            .get_mut(&key)
            .ok_or(IdentityError::AppNotRegistered)?;

        let mut secret = [0u8; APP_SECRET_BYTES];
        OsRng.fill_bytes(&mut secret);
        stored.secret = secret;
        stored.registration.credential_generation = stored
            .registration
            .credential_generation
            .saturating_add(1)
            .max(1);
        let generation = stored.registration.credential_generation;

        inner
            .pending_challenges
            .retain(|_, pending| &pending.challenge.app_id != app_id);
        inner
            .active_sessions
            .retain(|_, session| &session.app_id != app_id);
        self.persist_locked(&inner)?;

        Ok(AppCredential {
            app_id: app_id.clone(),
            secret,
            credential_generation: generation,
        })
    }

    pub async fn set_app_enabled(
        &self,
        app_id: &AppId,
        enabled: bool,
    ) -> Result<(), IdentityError> {
        let mut inner = self.inner.lock().await;
        let stored = inner
            .store
            .apps
            .get_mut(&app_id.to_string())
            .ok_or(IdentityError::AppNotRegistered)?;
        stored.registration.enabled = enabled;

        if !enabled {
            inner
                .pending_challenges
                .retain(|_, pending| &pending.challenge.app_id != app_id);
            inner
                .active_sessions
                .retain(|_, session| &session.app_id != app_id);
        }

        self.persist_locked(&inner)?;
        drop(inner);
        if let Some(events) = &self.events {
            events.emit(
                NetworkEventSource::Identity,
                EventSeverity::Notice,
                NetworkEvent::AppRegistrationChanged {
                    app_id: app_id.to_string(),
                    enabled,
                },
            );
        }
        Ok(())
    }

    pub async fn set_app_capabilities(
        &self,
        app_id: &AppId,
        granted_capabilities: AppCapabilitySet,
    ) -> Result<(), IdentityError> {
        let mut inner = self.inner.lock().await;
        let stored = inner
            .store
            .apps
            .get_mut(&app_id.to_string())
            .ok_or(IdentityError::AppNotRegistered)?;
        stored.registration.granted_capabilities = granted_capabilities;
        inner
            .pending_challenges
            .retain(|_, pending| &pending.challenge.app_id != app_id);
        inner
            .active_sessions
            .retain(|_, session| &session.app_id != app_id);
        self.persist_locked(&inner)
    }

    pub async fn begin_app_auth(
        &self,
        app_id: &AppId,
    ) -> Result<AppAuthChallenge, IdentityError> {
        let granted = {
            let inner = self.inner.lock().await;
            let stored = inner
                .store
                .apps
                .get(&app_id.to_string())
                .ok_or(IdentityError::AppNotRegistered)?;
            stored.registration.granted_capabilities.clone()
        };
        self.begin_app_auth_with_capabilities(app_id, granted).await
    }

    pub async fn begin_app_auth_with_capabilities(
        &self,
        app_id: &AppId,
        requested_capabilities: AppCapabilitySet,
    ) -> Result<AppAuthChallenge, IdentityError> {
        let now = current_timestamp();
        let mut inner = self.inner.lock().await;
        cleanup_expired(&mut inner, now);

        if inner.pending_challenges.len() >= MAX_PENDING_CHALLENGES {
            return Err(IdentityError::TooManyPendingChallenges);
        }

        let credential_generation = {
            let stored = inner
                .store
                .apps
                .get(&app_id.to_string())
                .ok_or(IdentityError::AppNotRegistered)?;
            if !stored.registration.enabled {
                return Err(IdentityError::AppDisabled);
            }
            if !requested_capabilities.is_subset_of(
                &stored.registration.granted_capabilities,
            ) {
                let denied = requested_capabilities
                    .iter()
                    .find(|capability| {
                        !stored
                            .registration
                            .granted_capabilities
                            .contains(*capability)
                    })
                    .unwrap_or(AppCapability::SubscribeNetworkStatus);
                return Err(IdentityError::CapabilityDenied(denied));
            }
            stored.registration.credential_generation
        };

        let challenge_id = inner.store.next_challenge_id;
        inner.store.next_challenge_id = inner.store.next_challenge_id.saturating_add(1).max(1);

        let mut nonce = [0u8; CHALLENGE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let challenge = AppAuthChallenge {
            app_id: app_id.clone(),
            challenge_id,
            nonce,
            issued_at: now,
            expires_at: now.saturating_add(self.challenge_ttl_secs),
            credential_generation,
            requested_capabilities,
        };

        inner.pending_challenges.insert(
            challenge_id,
            PendingChallenge {
                challenge: challenge.clone(),
            },
        );
        // Persist the monotonically increasing id, but never pending challenges.
        self.persist_locked(&inner)?;
        Ok(challenge)
    }

    pub async fn finish_app_auth(
        &self,
        response: AppAuthResponse,
    ) -> Result<AuthenticatedAppSession, IdentityError> {
        let now = current_timestamp();
        let mut inner = self.inner.lock().await;
        cleanup_expired(&mut inner, now);

        // Remove before verification: every challenge is one-use, including a
        // challenge answered incorrectly.
        let pending = inner
            .pending_challenges
            .remove(&response.challenge_id)
            .ok_or(IdentityError::ChallengeNotFound)?;
        let challenge = pending.challenge;

        if challenge.expires_at <= now {
            return Err(IdentityError::ChallengeExpired);
        }
        if challenge.app_id != response.app_id {
            return Err(IdentityError::ChallengeAppMismatch);
        }

        let stored = inner
            .store
            .apps
            .get(&response.app_id.to_string())
            .ok_or(IdentityError::AppNotRegistered)?;
        if !stored.registration.enabled {
            return Err(IdentityError::AppDisabled);
        }
        if stored.registration.credential_generation != challenge.credential_generation {
            return Err(IdentityError::CredentialGenerationMismatch);
        }

        let expected = compute_app_proof(&stored.secret, &challenge);
        if !constant_time_eq(&expected, &response.proof) {
            return Err(IdentityError::InvalidProof);
        }

        // Record app use only after a valid proof. This timestamp is later
        // filtered to the six-month public discovery window before any app id is published.
        if let Some(stored) = inner.store.apps.get_mut(&response.app_id.to_string()) {
            stored.registration.last_used_at = now;
        }
        self.persist_locked(&inner)?;

        if inner.active_sessions.len() >= MAX_ACTIVE_SESSIONS {
            return Err(IdentityError::TooManyActiveSessions);
        }

        let mut token_bytes = [0u8; SESSION_TOKEN_BYTES];
        loop {
            OsRng.fill_bytes(&mut token_bytes);
            let candidate = AppSessionToken(token_bytes);
            if !inner.active_sessions.contains_key(&candidate) {
                break;
            }
        }
        let token = AppSessionToken(token_bytes);
        let mut session_id_bytes = [0u8; SESSION_ID_BYTES];
        OsRng.fill_bytes(&mut session_id_bytes);
        let session_id = AppSessionId(session_id_bytes);
        let expires_at = now.saturating_add(self.session_ttl_secs);
        let capabilities = challenge.requested_capabilities.clone();
        inner.active_sessions.insert(
            token.clone(),
            ActiveAppSession {
                app_id: response.app_id.clone(),
                session_id: session_id.clone(),
                authenticated_at: now,
                expires_at,
                credential_generation: challenge.credential_generation,
                capabilities: capabilities.clone(),
            },
        );

        let authenticated = AuthenticatedAppSession {
            app_id: response.app_id,
            session_id,
            session_token: token,
            authenticated_at: now,
            expires_at,
            credential_generation: challenge.credential_generation,
            capabilities,
        };
        if let Some(events) = &self.events {
            events.emit(
                NetworkEventSource::Identity,
                EventSeverity::Notice,
                NetworkEvent::AppAuthenticated {
                    app_id: authenticated.app_id().to_string(),
                    session_id: authenticated.session_id().to_string(),
                    expires_at: authenticated.expires_at(),
                },
            );
        }
        Ok(authenticated)
    }

    /// Revalidate a token supplied on a later request from the same attached app.
    pub async fn authenticate_session(
        &self,
        token: &AppSessionToken,
    ) -> Result<AuthenticatedAppSession, IdentityError> {
        let now = current_timestamp();
        let mut inner = self.inner.lock().await;
        cleanup_expired(&mut inner, now);

        let session = inner
            .active_sessions
            .get(token)
            .ok_or(IdentityError::SessionNotFound)?;
        if session.expires_at <= now {
            return Err(IdentityError::SessionExpired);
        }

        Ok(AuthenticatedAppSession {
            app_id: session.app_id.clone(),
            session_id: session.session_id.clone(),
            session_token: token.clone(),
            authenticated_at: session.authenticated_at,
            expires_at: session.expires_at,
            credential_generation: session.credential_generation,
            capabilities: session.capabilities.clone(),
        })
    }

    pub async fn revoke_session(&self, token: &AppSessionToken) -> bool {
        let removed = self.inner.lock().await.active_sessions.remove(token);
        if let (Some(events), Some(session)) = (&self.events, removed.as_ref()) {
            events.emit(
                NetworkEventSource::Identity,
                EventSeverity::Info,
                NetworkEvent::AppSessionRevoked {
                    app_id: session.app_id.to_string(),
                    session_id: session.session_id.to_string(),
                },
            );
        }
        removed.is_some()
    }

    pub async fn revoke_all_app_sessions(&self, app_id: &AppId) -> usize {
        let mut inner = self.inner.lock().await;
        let revoked: Vec<_> = inner
            .active_sessions
            .values()
            .filter(|session| &session.app_id == app_id)
            .map(|session| session.session_id.clone())
            .collect();
        inner
            .active_sessions
            .retain(|_, session| &session.app_id != app_id);
        drop(inner);
        if let Some(events) = &self.events {
            for session_id in &revoked {
                events.emit(
                    NetworkEventSource::Identity,
                    EventSeverity::Info,
                    NetworkEvent::AppSessionRevoked {
                        app_id: app_id.to_string(),
                        session_id: session_id.to_string(),
                    },
                );
            }
        }
        revoked.len()
    }

    pub async fn list_apps(&self) -> Vec<AppRegistration> {
        let inner = self.inner.lock().await;
        let mut apps: Vec<_> = inner
            .store
            .apps
            .values()
            .map(|stored| {
                let mut registration = stored.registration.clone();
                // Older stores predate last_used_at. Treat their creation time
                // as their initial activity rather than publishing them forever.
                if registration.last_used_at == 0 {
                    registration.last_used_at = registration.created_at;
                }
                registration
            })
            .collect();
        apps.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        apps
    }

    /// Canonical app ids that are enabled and have been used recently enough
    /// to remain in the six-month public app advertisement. Approval alone is
    /// not public: `last_used_at` must have been set by successful authentication.
    pub async fn recently_used_app_ids(&self, now: u64) -> Vec<String> {
        let cutoff = now.saturating_sub(APP_DISCOVERY_ACTIVITY_TTL_SECS);
        let inner = self.inner.lock().await;
        let mut ids: Vec<_> = inner
            .store
            .apps
            .values()
            .filter(|stored| stored.registration.enabled)
            .filter(|stored| {
                stored.registration.last_used_at != 0
                    && stored.registration.last_used_at >= cutoff
            })
            .map(|stored| stored.registration.app_id.to_string())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    fn persist_locked(&self, inner: &Inner) -> Result<(), IdentityError> {
        self.user_auth
            .write_user_encrypted(&self.user_session, IDENTITY_STORE_KEY, &inner.store)
            .map_err(IdentityError::from)
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn compute_app_proof(
    secret: &[u8; APP_SECRET_BYTES],
    challenge: &AppAuthChallenge,
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        PROOF_DOMAIN.len() + challenge.app_id.0.len() + CHALLENGE_BYTES + 32,
    );
    input.extend_from_slice(PROOF_DOMAIN);
    input.extend_from_slice(&(challenge.app_id.0.len() as u32).to_le_bytes());
    input.extend_from_slice(challenge.app_id.0.as_bytes());
    input.extend_from_slice(&challenge.challenge_id.to_le_bytes());
    input.extend_from_slice(&challenge.nonce);
    input.extend_from_slice(&challenge.issued_at.to_le_bytes());
    input.extend_from_slice(&challenge.expires_at.to_le_bytes());
    input.extend_from_slice(&challenge.credential_generation.to_le_bytes());
    let capabilities: Vec<_> = challenge.requested_capabilities.iter().collect();
    input.extend_from_slice(&(capabilities.len() as u32).to_le_bytes());
    for capability in capabilities {
        input.extend_from_slice(format!("{capability:?}").as_bytes());
        input.push(0);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts 32-byte keys");
    mac.update(&input);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

fn cleanup_expired(inner: &mut Inner, now: u64) {
    inner
        .pending_challenges
        .retain(|_, pending| pending.challenge.expires_at > now);
    inner
        .active_sessions
        .retain(|_, session| session.expires_at > now);
}

fn validate_display_name(value: &str) -> Result<(), IdentityError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > 256 {
        Err(IdentityError::InvalidDisplayName)
    } else {
        Ok(())
    }
}

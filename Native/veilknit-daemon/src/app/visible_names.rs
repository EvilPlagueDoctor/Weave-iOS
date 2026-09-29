//! User-controlled names exposed to local applications.
//!
//! The account login name is an authentication detail and should not
//! automatically become application-visible identity. This store provides one
//! default display name plus optional per-app aliases. It is encrypted inside
//! the active user account and is never published to the DHT by this module.

use std::{collections::BTreeMap, sync::Arc};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    reputation::AppId,
    user_auth::{AuthError, UserAuth, UserSession},
};

const APP_VISIBLE_NAMES_KEY: &str = "application_visible_names_v1";
const APP_VISIBLE_NAMES_VERSION: u32 = 1;
const MAX_VISIBLE_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredVisibleNames {
    version: u32,
    default_name: String,
    per_app: BTreeMap<String, String>,
}

impl StoredVisibleNames {
    fn new(default_name: String) -> Self {
        Self {
            version: APP_VISIBLE_NAMES_VERSION,
            default_name,
            per_app: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VisibleNameSnapshot {
    pub default_name: String,
    pub per_app: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct AppVisibleNameManager {
    auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    state: Arc<RwLock<StoredVisibleNames>>,
}

impl AppVisibleNameManager {
    /// Constructs an in-memory fallback when the encrypted alias store is
    /// damaged. Changes made through this fallback still attempt persistence.
    pub fn temporary(auth: Arc<UserAuth>, session: Arc<UserSession>) -> Self {
        let fallback = sanitize_name(&session.user().display_name)
            .unwrap_or_else(|| "VeilKnit user".to_string());
        Self {
            auth,
            session,
            state: Arc::new(RwLock::new(StoredVisibleNames::new(fallback))),
        }
    }

    pub fn load(auth: Arc<UserAuth>, session: Arc<UserSession>) -> Result<Self, AuthError> {
        let fallback = sanitize_name(&session.user().display_name)
            .unwrap_or_else(|| "VeilKnit user".to_string());
        let mut state = auth
            .read_user_encrypted::<StoredVisibleNames>(&session, APP_VISIBLE_NAMES_KEY)?
            .unwrap_or_else(|| StoredVisibleNames::new(fallback.clone()));

        if state.version != APP_VISIBLE_NAMES_VERSION {
            state = StoredVisibleNames::new(fallback);
        }
        if sanitize_name(&state.default_name).is_none() {
            state.default_name = "VeilKnit user".to_string();
        }
        state.per_app.retain(|app_id, name| {
            !app_id.trim().is_empty() && sanitize_name(name).is_some()
        });

        Ok(Self {
            auth,
            session,
            state: Arc::new(RwLock::new(state)),
        })
    }

    /// Returns the alias visible to this app. The login username is never
    /// consulted here after the encrypted default has been initialized.
    pub async fn name_for(&self, app_id: &AppId) -> String {
        let state = self.state.read().await;
        state
            .per_app
            .get(&app_id.to_string())
            .cloned()
            .unwrap_or_else(|| state.default_name.clone())
    }

    pub async fn snapshot(&self) -> VisibleNameSnapshot {
        let state = self.state.read().await;
        VisibleNameSnapshot {
            default_name: state.default_name.clone(),
            per_app: state.per_app.clone(),
        }
    }

    pub async fn set_default(&self, value: impl Into<String>) -> Result<(), AuthError> {
        let value = validate_name(value.into())?;
        let mut state = self.state.write().await;
        state.default_name = value;
        self.persist_locked(&state)
    }

    pub async fn set_for_app(
        &self,
        app_id: &AppId,
        value: impl Into<String>,
    ) -> Result<(), AuthError> {
        let value = validate_name(value.into())?;
        let mut state = self.state.write().await;
        state.per_app.insert(app_id.to_string(), value);
        self.persist_locked(&state)
    }

    pub async fn clear_for_app(&self, app_id: &AppId) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        state.per_app.remove(&app_id.to_string());
        self.persist_locked(&state)
    }

    fn persist_locked(&self, state: &StoredVisibleNames) -> Result<(), AuthError> {
        self.auth
            .write_user_encrypted(&self.session, APP_VISIBLE_NAMES_KEY, state)
    }
}

fn sanitize_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_VISIBLE_NAME_BYTES {
        return None;
    }
    if trimmed.chars().any(char::is_control) {
        return None;
    }
    Some(trimmed.to_string())
}

fn validate_name(value: String) -> Result<String, AuthError> {
    sanitize_name(&value).ok_or(AuthError::InvalidDisplayName)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_control_names() {
        assert!(sanitize_name("   ").is_none());
        assert!(sanitize_name("hello\nworld").is_none());
        assert_eq!(sanitize_name("  Alice  ").as_deref(), Some("Alice"));
    }
}

//! Optional network-assisted recovery storage.
//!
//! The DHT never contains a plaintext account archive. A local
//! `.veilknit-backup` file is encrypted once by its user-selected backup
//! passphrase and then encrypted again with a randomly generated 256-bit
//! recovery secret before being split across a dedicated 64-subkey record.
//! The recovery code contains the random record address and that secret.

use std::{fs, path::Path, str::FromStr};

use aes_gcm::{
    aead::{Aead, Payload, OsRng, rand_core::RngCore},
    Aes256Gcm, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use veilid_core::RecordKey;
use zeroize::Zeroizing;

use crate::{
    dht_module::{CreateDhtError, DHTModule, NULL_DHT_VALUE},
    types::current_timestamp,
    user_auth::{AuthError, UserAuth, UserSession},
};

pub const NETWORK_RECOVERY_STATE_KEY: &str = "network_recovery_state";
const RECOVERY_VERSION: u16 = 1;
const RECOVERY_SUBKEYS: u16 = 64;
const RECOVERY_CHUNK_BYTES: usize = 12 * 1024;
const RECOVERY_AAD: &[u8] = b"veilknit/network-recovery/v1";
const MAX_RECOVERY_BYTES: usize = RECOVERY_CHUNK_BYTES * 63;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkRecoveryState {
    pub record_key: String,
    pub chunk_count: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecoveryManifest {
    version: u16,
    nonce_hex: String,
    chunk_count: u32,
    ciphertext_len: usize,
    ciphertext_sha256_hex: String,
    created_at: u64,
}

#[derive(Debug, Clone)]
pub struct RecoveryUploadResult {
    pub recovery_code: String,
    pub record_key: String,
    pub chunk_count: u32,
}

pub async fn upload_backup(
    auth: &UserAuth,
    session: &UserSession,
    dht: &DHTModule,
    backup_path: impl AsRef<Path>,
) -> Result<RecoveryUploadResult, String> {
    let previous_state = auth
        .read_user_encrypted::<NetworkRecoveryState>(session, NETWORK_RECOVERY_STATE_KEY)
        .map_err(|error| error.to_string())?;
    let backup = fs::read(backup_path.as_ref()).map_err(|error| error.to_string())?;
    if backup.len() > MAX_RECOVERY_BYTES.saturating_sub(64) {
        return Err(format!(
            "backup is {} bytes; network recovery currently supports at most {} bytes",
            backup.len(),
            MAX_RECOVERY_BYTES.saturating_sub(64)
        ));
    }

    let package = dht
        .create_dht("Network recovery backup".to_string(), vec![RECOVERY_SUBKEYS])
        .await
        .map_err(format_dht_error)?;
    let record_key = dht
        .package_id_to_key(package)
        .await
        .map_err(format_dht_error)?;

    let mut secret = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(secret.as_mut());
    OsRng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(secret.as_ref())
        .map_err(|error| error.to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &backup,
                aad: RECOVERY_AAD,
            },
        )
        .map_err(|_| "could not encrypt network recovery backup".to_string())?;
    let chunks: Vec<&[u8]> = ciphertext.chunks(RECOVERY_CHUNK_BYTES).collect();
    if chunks.len() > 63 {
        return Err("encrypted recovery backup requires too many DHT chunks".into());
    }

    // Commit data pages first. Subkey zero acts as the final manifest/commit
    // marker, so readers never treat a partially written upload as complete.
    for (index, chunk) in chunks.iter().enumerate() {
        dht.write_owned_subkey(package, index as u32 + 1, chunk.to_vec())
            .await
            .map_err(format_dht_error)?;
    }
    let manifest = RecoveryManifest {
        version: RECOVERY_VERSION,
        nonce_hex: hex::encode(nonce),
        chunk_count: chunks.len() as u32,
        ciphertext_len: ciphertext.len(),
        ciphertext_sha256_hex: hex::encode(Sha256::digest(&ciphertext)),
        created_at: current_timestamp(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| error.to_string())?;
    dht.write_owned_subkey(package, 0, manifest_bytes)
        .await
        .map_err(format_dht_error)?;

    let now = current_timestamp();
    let new_state = NetworkRecoveryState {
        record_key: record_key.to_string(),
        chunk_count: chunks.len() as u32,
        created_at: now,
        updated_at: now,
    };
    auth.write_user_encrypted(session, NETWORK_RECOVERY_STATE_KEY, &new_state)
        .map_err(|error| error.to_string())?;

    // A successful replacement should not leave the previous latest recovery
    // generation readable forever. Failure to clean up the old record does
    // not invalidate the newly committed backup, but it is surfaced in logs.
    if let Some(previous) = previous_state.filter(|state| state.record_key != new_state.record_key) {
        if let Err(error) = wipe_state_record(dht, &previous).await {
            crate::teprintln!(
                "[recovery] New backup committed, but the previous recovery record could not be wiped: {error}"
            );
        }
    }

    Ok(RecoveryUploadResult {
        recovery_code: format!("VKR1|{}|{}", record_key, hex::encode(secret.as_ref())),
        record_key: record_key.to_string(),
        chunk_count: chunks.len() as u32,
    })
}

pub async fn download_backup(
    dht: &DHTModule,
    recovery_code: &str,
    destination: impl AsRef<Path>,
) -> Result<(), String> {
    let (record_key, secret) = parse_recovery_code(recovery_code)?;
    let manifest_bytes = dht
        .read_foreign_subkey(record_key.clone(), 0, true)
        .await
        .map_err(format_dht_error)?;
    let manifest: RecoveryManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("recovery manifest is invalid: {error}"))?;
    if manifest.version != RECOVERY_VERSION || manifest.chunk_count == 0 || manifest.chunk_count > 63 {
        return Err("recovery manifest uses an unsupported layout".into());
    }

    let locations = (1..=manifest.chunk_count).collect::<Vec<_>>();
    let values = dht
        .read_foreign_subkeys(record_key, locations, true)
        .await
        .map_err(format_dht_error)?;
    let mut chunks = values;
    chunks.sort_by_key(|(location, _)| *location);
    let mut ciphertext = Vec::with_capacity(manifest.ciphertext_len);
    for (location, value) in chunks {
        let value = value.map_err(|error| {
            format!("could not read recovery chunk {location}: {}", format_dht_error(error))
        })?;
        ciphertext.extend_from_slice(&value);
    }
    ciphertext.truncate(manifest.ciphertext_len);
    if ciphertext.len() != manifest.ciphertext_len
        || hex::encode(Sha256::digest(&ciphertext)) != manifest.ciphertext_sha256_hex
    {
        return Err("network recovery data is incomplete or damaged".into());
    }

    let nonce = hex::decode(&manifest.nonce_hex)
        .map_err(|_| "recovery manifest nonce is invalid".to_string())?;
    if nonce.len() != 12 {
        return Err("recovery manifest nonce has the wrong length".into());
    }
    let cipher = Aes256Gcm::new_from_slice(secret.as_ref())
        .map_err(|error| error.to_string())?;
    let backup = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: RECOVERY_AAD,
            },
        )
        .map_err(|_| "recovery code is incorrect or the backup is damaged".to_string())?;
    atomic_write_public(destination.as_ref(), &backup).map_err(|error| error.to_string())
}

/// Replace every currently used recovery subkey with the null marker. Veilid
/// DHT history cannot be guaranteed to disappear instantly from every cache,
/// but the latest readable generation no longer contains the backup.
pub async fn wipe_network_backup(
    auth: &UserAuth,
    session: &UserSession,
    dht: &DHTModule,
) -> Result<(), String> {
    let state = auth
        .read_user_encrypted::<NetworkRecoveryState>(session, NETWORK_RECOVERY_STATE_KEY)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "no local network recovery record is configured".to_string())?;
    wipe_state_record(dht, &state).await?;
    auth.remove_user_encrypted(session, NETWORK_RECOVERY_STATE_KEY)
        .map_err(|error| error.to_string())?;
    Ok(())
}


async fn wipe_state_record(
    dht: &DHTModule,
    state: &NetworkRecoveryState,
) -> Result<(), String> {
    let record_key = RecordKey::from_str(&state.record_key)
        .map_err(|error| format!("saved recovery key is invalid: {error:?}"))?;
    let packages = dht.export_snapshot().await;
    let package = packages
        .iter()
        .position(|stored| stored.record_key == record_key)
        .ok_or_else(|| {
            "the recovery writer package is not available locally; import the identity backup before wiping it"
                .to_string()
        })?;
    for location in 0..=state.chunk_count {
        dht.write_owned_subkey(package, location, NULL_DHT_VALUE.to_vec())
            .await
            .map_err(format_dht_error)?;
    }
    Ok(())
}

pub fn local_recovery_state(
    auth: &UserAuth,
    session: &UserSession,
) -> Result<Option<NetworkRecoveryState>, AuthError> {
    auth.read_user_encrypted(session, NETWORK_RECOVERY_STATE_KEY)
}

fn parse_recovery_code(value: &str) -> Result<(RecordKey, Zeroizing<[u8; 32]>), String> {
    let mut parts = value.trim().split('|');
    if parts.next() != Some("VKR1") {
        return Err("recovery code must begin with VKR1".into());
    }
    let record_key = parts
        .next()
        .ok_or_else(|| "recovery code is missing its DHT key".to_string())?
        .parse::<RecordKey>()
        .map_err(|error| format!("recovery DHT key is invalid: {error:?}"))?;
    let secret_bytes = hex::decode(
        parts
            .next()
            .ok_or_else(|| "recovery code is missing its secret".to_string())?,
    )
    .map_err(|_| "recovery secret is not valid hexadecimal".to_string())?;
    if parts.next().is_some() || secret_bytes.len() != 32 {
        return Err("recovery code has an invalid secret".into());
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&secret_bytes);
    Ok((record_key, secret))
}

fn format_dht_error(error: CreateDhtError) -> String {
    format!("DHT recovery error: {error:?}")
}

fn atomic_write_public(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp, bytes)?;
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(first_error) => {
            // Windows does not replace an existing file with rename. Keep the
            // new archive in the same directory and retry after removal.
            if path.exists() {
                fs::remove_file(path)?;
                fs::rename(&temp, path)
            } else {
                let _ = fs::remove_file(&temp);
                Err(first_error)
            }
        }
    }
}

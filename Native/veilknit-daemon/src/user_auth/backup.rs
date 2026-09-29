//! Portable encrypted account backups.
//!
//! A `.veilknit-backup` file contains only the files required to restore an
//! account. The archive is encrypted independently of the normal login store,
//! so losing the local installation does not make the backup unusable. The
//! outer header exposes only a magic value, format version, salt, nonce, and
//! ciphertext length; the username and profile identifiers remain encrypted.

use super::{atomic_write, current_timestamp, validate_username, AuthError, UserAuth, UserSession};
use aes_gcm::{
    aead::{Aead, Payload, OsRng, rand_core::RngCore},
    Aes256Gcm, KeyInit, Nonce,
};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

const BACKUP_MAGIC: &[u8; 4] = b"VKBK";
const BACKUP_VERSION: u16 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const FIXED_HEADER_BYTES: usize = 4 + 2 + SALT_BYTES + NONCE_BYTES + 8;
const BACKUP_AAD: &[u8] = b"veilknit/account-backup/v1";
const MAX_BACKUP_FILE_COUNT: usize = 65_536;
const MAX_BACKUP_TOTAL_BYTES: usize = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub format_version: u16,
    pub username: String,
    pub created_at: u64,
    pub file_count: usize,
    pub total_plaintext_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupEntry {
    relative_path: String,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupArchive {
    version: u16,
    username: String,
    created_at: u64,
    entries: Vec<BackupEntry>,
}

impl UserAuth {
    /// Export the complete encrypted account state to a portable authenticated
    /// container. Runtime logs, temporary files, and prior backup files are
    /// intentionally excluded.
    pub fn export_local_backup(
        &self,
        session: &UserSession,
        destination: impl AsRef<Path>,
        backup_passphrase: &str,
    ) -> Result<BackupMetadata, AuthError> {
        if backup_passphrase.len() < 8 {
            return Err(AuthError::Backup(
                "backup passphrase must contain at least 8 characters".into(),
            ));
        }

        let mut entries = Vec::new();
        collect_backup_entries(session.user_dir(), session.user_dir(), &mut entries)?;
        if entries.is_empty()
            || !entries.iter().any(|entry| entry.relative_path == "account.json")
            || !entries.iter().any(|entry| entry.relative_path == "user_profile.bin")
        {
            return Err(AuthError::Backup(
                "account files are incomplete; refusing to create an unusable backup".into(),
            ));
        }
        if entries.len() > MAX_BACKUP_FILE_COUNT {
            return Err(AuthError::Backup("backup contains too many files".into()));
        }
        let total_plaintext_bytes = entries.iter().map(|entry| entry.bytes.len()).sum::<usize>();
        if total_plaintext_bytes > MAX_BACKUP_TOTAL_BYTES {
            return Err(AuthError::Backup("backup exceeds the supported size limit".into()));
        }

        let archive = BackupArchive {
            version: BACKUP_VERSION,
            username: session.username().to_string(),
            created_at: current_timestamp(),
            entries,
        };
        let plaintext = bincode::serialize(&archive)
            .map_err(|error| AuthError::Backup(format!("could not serialize backup: {error}")))?;

        let mut salt = [0u8; SALT_BYTES];
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_backup_key(backup_passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(key.as_ref())
            .map_err(|error| AuthError::Crypto(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: BACKUP_AAD,
                },
            )
            .map_err(|_| AuthError::Backup("backup encryption failed".into()))?;

        let mut output = Vec::with_capacity(FIXED_HEADER_BYTES + ciphertext.len());
        output.extend_from_slice(BACKUP_MAGIC);
        output.extend_from_slice(&BACKUP_VERSION.to_le_bytes());
        output.extend_from_slice(&salt);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        output.extend_from_slice(&ciphertext);
        atomic_write(destination.as_ref(), &output)?;

        Ok(BackupMetadata {
            format_version: BACKUP_VERSION,
            username: archive.username,
            created_at: archive.created_at,
            file_count: archive.entries.len(),
            total_plaintext_bytes,
        })
    }

    /// Decrypt and inspect a backup without writing it to disk.
    pub fn inspect_local_backup(
        &self,
        source: impl AsRef<Path>,
        backup_passphrase: &str,
    ) -> Result<BackupMetadata, AuthError> {
        let archive = read_backup_archive(source.as_ref(), backup_passphrase)?;
        let total_plaintext_bytes = archive.entries.iter().map(|entry| entry.bytes.len()).sum();
        Ok(BackupMetadata {
            format_version: archive.version,
            username: archive.username,
            created_at: archive.created_at,
            file_count: archive.entries.len(),
            total_plaintext_bytes,
        })
    }

    /// Restore an account transactionally. Existing accounts are never
    /// overwritten; the user must remove or rename an old installation first.
    pub fn restore_local_backup(
        &self,
        source: impl AsRef<Path>,
        backup_passphrase: &str,
    ) -> Result<BackupMetadata, AuthError> {
        let archive = read_backup_archive(source.as_ref(), backup_passphrase)?;
        validate_username(&archive.username)?;
        validate_archive_entries(&archive.entries)?;

        let destination = self.user_dir(&archive.username);
        if destination.exists() {
            return Err(AuthError::Backup(format!(
                "an account named '{}' already exists on this installation",
                archive.username
            )));
        }

        let users_dir = self.root_dir.join("users");
        fs::create_dir_all(&users_dir)?;
        let temp_dir = users_dir.join(format!(
            ".restore-{}-{}",
            std::process::id(),
            current_timestamp()
        ));
        if temp_dir.exists() {
            fs::remove_dir_all(&temp_dir)?;
        }
        fs::create_dir_all(&temp_dir)?;

        let restore_result = (|| -> Result<(), AuthError> {
            for entry in &archive.entries {
                let relative = validated_relative_path(&entry.relative_path)?;
                let path = temp_dir.join(relative);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                atomic_write(&path, &entry.bytes)?;
            }
            if !temp_dir.join("account.json").is_file()
                || !temp_dir.join("user_profile.bin").is_file()
            {
                return Err(AuthError::Backup(
                    "backup does not contain the required account files".into(),
                ));
            }
            fs::rename(&temp_dir, &destination)?;
            Ok(())
        })();
        if restore_result.is_err() {
            let _ = fs::remove_dir_all(&temp_dir);
        }
        restore_result?;

        let total_plaintext_bytes = archive.entries.iter().map(|entry| entry.bytes.len()).sum();
        Ok(BackupMetadata {
            format_version: archive.version,
            username: archive.username,
            created_at: archive.created_at,
            file_count: archive.entries.len(),
            total_plaintext_bytes,
        })
    }
}

fn collect_backup_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<BackupEntry>,
) -> Result<(), AuthError> {
    for item in fs::read_dir(directory)? {
        let item = item?;
        let path = item.path();
        let file_type = item.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_backup_entries(root, &path, entries)?;
            continue;
        }
        if !file_type.is_file() || should_exclude(&path) {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| AuthError::Backup("backup path escaped the account directory".into()))?;
        let relative_path = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        entries.push(BackupEntry {
            relative_path,
            bytes: fs::read(&path)?,
        });
        if entries.len() > MAX_BACKUP_FILE_COUNT {
            return Err(AuthError::Backup("backup contains too many files".into()));
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(())
}

fn should_exclude(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".tmp")
        || name.ends_with(".log")
        || name.ends_with(".veilknit-backup")
        || name == "session.log"
        // Routing and app-discovery caches are regenerable device-local state,
        // not account identity. Excluding them keeps portable/DHT backups small
        // and avoids restoring stale network observations on another device.
        || name == "internal_node_list.bin"
        || name == "app_discovery_cache.bin"
}

fn read_backup_archive(path: &Path, passphrase: &str) -> Result<BackupArchive, AuthError> {
    let bytes = fs::read(path)?;
    if bytes.len() < FIXED_HEADER_BYTES || &bytes[..4] != BACKUP_MAGIC {
        return Err(AuthError::Backup("not a VeilKnit backup file".into()));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != BACKUP_VERSION {
        return Err(AuthError::Backup(format!(
            "unsupported backup format version {version}"
        )));
    }
    let salt_start = 6;
    let nonce_start = salt_start + SALT_BYTES;
    let length_start = nonce_start + NONCE_BYTES;
    let ciphertext_start = length_start + 8;
    let salt = &bytes[salt_start..nonce_start];
    let nonce = &bytes[nonce_start..length_start];
    let declared = u64::from_le_bytes(
        bytes[length_start..ciphertext_start]
            .try_into()
            .map_err(|_| AuthError::Backup("invalid backup header".into()))?,
    ) as usize;
    if declared != bytes.len().saturating_sub(ciphertext_start) {
        return Err(AuthError::Backup("backup length check failed".into()));
    }

    let key = derive_backup_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref())
        .map_err(|error| AuthError::Crypto(error.to_string()))?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: &bytes[ciphertext_start..],
                aad: BACKUP_AAD,
            },
        )
        .map_err(|_| AuthError::Backup("incorrect passphrase or damaged backup".into()))?;
    let archive: BackupArchive = bincode::deserialize(&plaintext)
        .map_err(|error| AuthError::Backup(format!("could not decode backup: {error}")))?;
    if archive.version != BACKUP_VERSION {
        return Err(AuthError::Backup("backup payload version does not match its header".into()));
    }
    validate_username(&archive.username)?;
    validate_archive_entries(&archive.entries)?;
    Ok(archive)
}

fn validate_archive_entries(entries: &[BackupEntry]) -> Result<(), AuthError> {
    if entries.len() > MAX_BACKUP_FILE_COUNT {
        return Err(AuthError::Backup("backup contains too many files".into()));
    }
    let mut total = 0usize;
    for entry in entries {
        validated_relative_path(&entry.relative_path)?;
        total = total
            .checked_add(entry.bytes.len())
            .ok_or_else(|| AuthError::Backup("backup size overflow".into()))?;
        if total > MAX_BACKUP_TOTAL_BYTES {
            return Err(AuthError::Backup("backup exceeds the supported size limit".into()));
        }
    }
    Ok(())
}

fn validated_relative_path(value: &str) -> Result<PathBuf, AuthError> {
    let path = Path::new(value);
    if path.is_absolute() || value.is_empty() {
        return Err(AuthError::Backup("backup contains an invalid file path".into()));
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(AuthError::Backup("backup contains an unsafe file path".into()));
        }
    }
    Ok(path.to_path_buf())
}

fn derive_backup_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, AuthError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|error| AuthError::Crypto(error.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "veilknit-backup-test-{label}-{}-{}",
            std::process::id(),
            current_timestamp()
        ))
    }

    #[test]
    fn disposable_discovery_caches_are_not_backed_up() {
        assert!(should_exclude(Path::new("internal_node_list.bin")));
        assert!(should_exclude(Path::new("app_discovery_cache.bin")));
        assert!(!should_exclude(Path::new("app_identities.bin")));
    }

    #[test]
    fn backup_round_trip_and_wrong_passphrase() {
        let source_root = temp_root("source");
        let restored_root = temp_root("restore");
        let backup_path = source_root.join("alice.veilknit-backup");
        let source = UserAuth::new(&source_root).unwrap();
        let session = source.signup("alice", "account password").unwrap();
        source
            .write_user_encrypted(&session, "example", &vec!["hello", "world"])
            .unwrap();
        source
            .export_local_backup(&session, &backup_path, "backup password")
            .unwrap();
        assert!(source
            .inspect_local_backup(&backup_path, "wrong password")
            .is_err());

        let restored = UserAuth::new(&restored_root).unwrap();
        let metadata = restored
            .restore_local_backup(&backup_path, "backup password")
            .unwrap();
        assert_eq!(metadata.username, "alice");
        let restored_session = restored.login("alice", "account password").unwrap();
        let value: Option<Vec<String>> = restored
            .read_user_encrypted(&restored_session, "example")
            .unwrap();
        assert_eq!(value.unwrap(), vec!["hello", "world"]);

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(restored_root);
    }
}

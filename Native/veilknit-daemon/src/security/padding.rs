//! Authenticated size-class padding for encrypted network payloads.
//!
//! Padding is applied **before** encryption so observers can learn only the
//! selected size class rather than the exact serialized plaintext length. The
//! random padding bytes are then covered by AEAD authentication together with
//! the real payload. This is intentionally a small set of classes instead of
//! padding every write to the largest possible DHT value.

use rand_core::{OsRng, RngCore};
use std::fmt;

const MAGIC: &[u8; 8] = b"VKPAD001";
const HEADER_LEN: usize = MAGIC.len() + std::mem::size_of::<u32>();

/// Size classes are chosen to reduce exact-length leakage without turning a
/// short control message into a 12 KiB write.
pub const DHT_SIZE_CLASSES: &[usize] = &[
    256,
    512,
    1024,
    2048,
    4096,
    8192,
    12 * 1024,
];

/// Direct encrypted routes are not constrained by a DHT page, so preserve the
/// existing direct-message limit while still hiding the exact payload length.
pub const DIRECT_SIZE_CLASSES: &[usize] = &[
    256,
    512,
    1024,
    2048,
    4096,
    8192,
    12 * 1024,
    16 * 1024,
    24 * 1024,
    32 * 1024,
    48 * 1024,
    64 * 1024,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingError {
    PayloadTooLarge { required: usize, maximum: usize },
    InvalidLength { declared: usize, available: usize },
}

impl fmt::Display for PaddingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge { required, maximum } => write!(
                formatter,
                "payload needs {required} padded bytes; maximum class is {maximum}"
            ),
            Self::InvalidLength { declared, available } => write!(
                formatter,
                "padded payload declares {declared} bytes but only {available} are available"
            ),
        }
    }
}

impl std::error::Error for PaddingError {}

/// Wrap `plaintext` in a versioned header and fill the selected class with
/// cryptographically random bytes. The returned bytes are ready for AEAD
/// encryption; callers must not send them in plaintext.
pub fn pad_for_encryption(plaintext: &[u8]) -> Result<Vec<u8>, PaddingError> {
    pad_with_classes(plaintext, DHT_SIZE_CLASSES)
}

pub fn pad_for_direct_encryption(plaintext: &[u8]) -> Result<Vec<u8>, PaddingError> {
    pad_with_classes(plaintext, DIRECT_SIZE_CLASSES)
}

fn pad_with_classes(
    plaintext: &[u8],
    classes: &[usize],
) -> Result<Vec<u8>, PaddingError> {
    let required = HEADER_LEN.saturating_add(plaintext.len());
    let target = classes
        .iter()
        .copied()
        .find(|candidate| *candidate >= required)
        .ok_or(PaddingError::PayloadTooLarge {
            required,
            maximum: *classes.last().unwrap_or(&0),
        })?;

    let mut padded = vec![0u8; target];
    padded[..MAGIC.len()].copy_from_slice(MAGIC);
    padded[MAGIC.len()..HEADER_LEN]
        .copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    padded[HEADER_LEN..HEADER_LEN + plaintext.len()].copy_from_slice(plaintext);
    OsRng.fill_bytes(&mut padded[HEADER_LEN + plaintext.len()..]);
    Ok(padded)
}

/// Remove size-class padding. `Ok(None)` means the payload predates this
/// format and should be decoded using the legacy unpadded path.
pub fn unpad_after_decryption(bytes: &[u8]) -> Result<Option<&[u8]>, PaddingError> {
    if bytes.len() < HEADER_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return Ok(None);
    }

    let mut length_bytes = [0u8; 4];
    length_bytes.copy_from_slice(&bytes[MAGIC.len()..HEADER_LEN]);
    let declared = u32::from_le_bytes(length_bytes) as usize;
    let available = bytes.len().saturating_sub(HEADER_LEN);
    if declared > available {
        return Err(PaddingError::InvalidLength {
            declared,
            available,
        });
    }
    Ok(Some(&bytes[HEADER_LEN..HEADER_LEN + declared]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_to_smallest_matching_class_and_round_trips() {
        let original = vec![7u8; 700];
        let padded = pad_for_encryption(&original).expect("padding succeeds");
        assert_eq!(padded.len(), 1024);
        assert_eq!(
            unpad_after_decryption(&padded)
                .expect("valid padding")
                .expect("new format"),
            original.as_slice()
        );
    }

    #[test]
    fn legacy_payload_is_left_untouched() {
        assert!(unpad_after_decryption(b"legacy bincode")
            .expect("legacy is valid")
            .is_none());
    }
}

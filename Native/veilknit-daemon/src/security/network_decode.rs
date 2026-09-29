//! Bounded decoding helpers for data received from DHT records or app messages.
//!
//! PATCH A: keep all hostile-input size limits in one place so individual
//! modules do not accidentally fall back to unrestricted deserialization.

use bincode::Options;
use serde::de::DeserializeOwned;

/// Conservative upper bound for a single structured DHT value.
/// Veilid records used by this project are expected to be far smaller.
pub const MAX_NETWORK_DHT_VALUE_BYTES: usize = 64 * 1024;

/// Route blobs can be larger than ordinary metadata but should still have a
/// firm protocol limit before allocation-heavy decoding is attempted.
pub const MAX_ROUTE_BLOB_RECORD_BYTES: usize = 128 * 1024;

#[derive(Debug)]
pub enum NetworkDecodeError {
    EmptyEnvelope,
    EnvelopeTooLarge { actual: usize, maximum: usize },
    FieldTooLarge { field: &'static str, actual: usize, maximum: usize },
    CollectionTooLarge { field: &'static str, actual: usize, maximum: usize },
    TimestampOutsideWindow,
    AllZeroValue { field: &'static str },
    Decode(String),
}

impl std::fmt::Display for NetworkDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyEnvelope => formatter.write_str("network envelope is empty"),
            Self::EnvelopeTooLarge { actual, maximum } => write!(
                formatter,
                "network envelope is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::FieldTooLarge { field, actual, maximum } => write!(
                formatter,
                "field {field} is {actual} bytes; maximum is {maximum} bytes"
            ),
            Self::CollectionTooLarge { field, actual, maximum } => write!(
                formatter,
                "collection {field} has {actual} items; maximum is {maximum}"
            ),
            Self::TimestampOutsideWindow => formatter.write_str("timestamp is outside the allowed window"),
            Self::AllZeroValue { field } => write!(formatter, "field {field} must not be all zero"),
            Self::Decode(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for NetworkDecodeError {}

pub fn validate_envelope_size(bytes: &[u8], maximum: usize) -> Result<(), NetworkDecodeError> {
    if bytes.is_empty() {
        return Err(NetworkDecodeError::EmptyEnvelope);
    }
    if bytes.len() > maximum {
        return Err(NetworkDecodeError::EnvelopeTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(())
}

pub fn validate_utf8_field(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), NetworkDecodeError> {
    if value.len() > maximum_bytes {
        return Err(NetworkDecodeError::FieldTooLarge {
            field,
            actual: value.len(),
            maximum: maximum_bytes,
        });
    }
    Ok(())
}

pub fn validate_collection_len(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), NetworkDecodeError> {
    if actual > maximum {
        return Err(NetworkDecodeError::CollectionTooLarge { field, actual, maximum });
    }
    Ok(())
}

pub fn validate_timestamp_window(
    timestamp: u64,
    now: u64,
    past_window_secs: u64,
    future_window_secs: u64,
) -> Result<(), NetworkDecodeError> {
    if timestamp > now.saturating_add(future_window_secs)
        || timestamp.saturating_add(past_window_secs) < now
    {
        return Err(NetworkDecodeError::TimestampOutsideWindow);
    }
    Ok(())
}

pub fn reject_all_zero(field: &'static str, bytes: &[u8]) -> Result<(), NetworkDecodeError> {
    if !bytes.is_empty() && bytes.iter().all(|byte| *byte == 0) {
        return Err(NetworkDecodeError::AllZeroValue { field });
    }
    Ok(())
}

pub fn decode_bincode_limited<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, NetworkDecodeError> {
    validate_envelope_size(bytes, maximum)?;

    bincode::DefaultOptions::new()
        // Match bincode::{serialize, deserialize} compatibility in bincode 1.x.
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(maximum as u64)
        .deserialize(bytes)
        .map_err(|error| NetworkDecodeError::Decode(error.to_string()))
}

pub fn decode_json_limited<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, NetworkDecodeError> {
    validate_envelope_size(bytes, maximum)?;

    // Use a streaming deserializer and explicitly require its end. This makes
    // the no-trailing-data rule visible and consistent with bounded bincode.
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|error| NetworkDecodeError::Decode(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| NetworkDecodeError::Decode(error.to_string()))?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Example {
        value: u32,
        label: String,
    }

    #[test]
    fn bounded_bincode_round_trip_uses_legacy_encoding() {
        let expected = Example {
            value: 42,
            label: "bounded".to_string(),
        };
        let bytes = bincode::serialize(&expected).expect("serialize test value");
        let decoded: Example =
            decode_bincode_limited(&bytes, 1024).expect("decode test value");
        assert_eq!(decoded, expected);
    }

    #[test]
    fn oversized_envelope_is_rejected_before_decode() {
        let bytes = vec![0u8; 17];
        let error = decode_bincode_limited::<Vec<u8>>(&bytes, 16)
            .expect_err("oversized value must be rejected");
        assert!(matches!(
            error,
            NetworkDecodeError::EnvelopeTooLarge {
                actual: 17,
                maximum: 16
            }
        ));
    }

    #[test]
    fn trailing_bincode_bytes_are_rejected() {
        let mut bytes = bincode::serialize(&7u32).expect("serialize integer");
        bytes.push(0);
        assert!(decode_bincode_limited::<u32>(&bytes, 64).is_err());
    }

    #[test]
    fn empty_envelopes_are_rejected() {
        assert!(matches!(
            decode_json_limited::<Example>(b"", 64),
            Err(NetworkDecodeError::EmptyEnvelope)
        ));
    }

    #[test]
    fn trailing_json_values_are_rejected() {
        assert!(decode_json_limited::<u32>(b"7 8", 64).is_err());
    }

    #[test]
    fn semantic_helpers_apply_limits() {
        assert!(validate_utf8_field("name", "abcd", 3).is_err());
        assert!(validate_collection_len("items", 4, 3).is_err());
        assert!(validate_timestamp_window(50, 100, 10, 10).is_err());
        assert!(reject_all_zero("key", &[0u8; 32]).is_err());
    }
}

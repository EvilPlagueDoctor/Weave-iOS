// ============================================================================
// Protocol constants and default policy
// ============================================================================

pub const MAILBOX_PROTOCOL_VERSION: u16 = 1;
pub const MAILBOX_STORE_VERSION: u32 = 1;
pub const MAILBOX_STORE_KEY: &str = "mailbox_state_v1";
pub const MAILBOX_TRANSACTION_STORE_KEY: &str = "mailbox_transactions_v1";
pub const MAILBOX_QUOTA_STORE_KEY: &str = "mailbox_quota_state_v1";

pub const INDEX_SLOT_A: u32 = 0;
pub const INDEX_SLOT_B: u32 = 1;
pub const FIRST_DATA_SUBKEY: u32 = 2;

pub const MAILBOX_DHT_NAME: &str = "mailbox_custodian";
pub const MAILSEND_DHT_NAME: &str = "mail_send";
pub const MAILRESPONSE_DHT_NAME: &str = "mail_response";
pub const OVERFLOW_DHT_NAME_PREFIX: &str = "mailbox_overflow";

/// Mailbox page records deliberately use 64 subkeys.
///
/// Veilid divides a record's roughly 1 MiB value budget across its schema
/// subkeys. A 1000-subkey record therefore permits only about 1 KiB per value,
/// which is too small for an encrypted message page. Sixty-four subkeys leave
/// roughly 16 KiB per value while still providing 62 copy-on-write data slots
/// after the two A/B index slots.
pub const PAGED_DHT_GROUPS: [u16; 1] = [64];
pub const PAGED_DHT_TOTAL_SUBKEYS: u32 = 64;

const RECEIVE_KDF_DOMAIN: &[u8] = b"network-walk/mailbox/receive-key/v1";
const MESSAGE_KEY_DOMAIN: &[u8] = b"network-walk/mailbox/message-key/v1";
const MESSAGE_ID_DOMAIN: &[u8] = b"network-walk/mailbox/message-id/v1";
const MESSAGE_SIGNATURE_DOMAIN: &[u8] = b"network-walk/mailbox/message-signature/v1";
const BUMP_SIGNATURE_DOMAIN: &[u8] = b"network-walk/mailbox/bump-signature/v1";
const RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"network-walk/mailbox/response-signature/v1";
const SERVICE_REQUEST_ID_DOMAIN: &[u8] = b"network-walk/mailbox/service-request-id/v1";
const SERVICE_REQUEST_SIGNATURE_DOMAIN: &[u8] = b"network-walk/mailbox/service-request-signature/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxConfig {
    pub participate_as_custodian: bool,
    pub page_target_size: usize,
    pub page_split_threshold: usize,
    pub complete_message_max_size: usize,
    pub max_plaintext_size: usize,
    /// Public service requests are deliberately much smaller/shorter-lived than private mail.
    pub max_service_request_size: usize,
    pub max_service_payload_size: usize,
    pub max_service_reply_route_size: usize,
    pub default_service_request_ttl_secs: u64,
    pub max_service_request_ttl_secs: u64,
    pub active_service_requests_per_sender: usize,
    pub active_service_requests_per_host: usize,
    pub recent_service_request_cache: usize,
    pub service_request_pointer_checks_per_walk: usize,
    pub normal_batch_interval_secs: u64,
    pub maintenance_interval_secs: u64,
    pub early_flush_queue_size: usize,
    pub dht_io_concurrency: usize,
    pub max_navigation_suggestions: usize,
    pub advertised_previous_key_epochs: usize,
    pub max_timestamp_skew_secs: u64,
    pub max_message_age_secs: u64,
    pub max_requested_expiry_secs: u64,
    pub minimum_bump_interval_secs: u64,
    pub active_messages_per_sender: usize,
    pub active_messages_per_sender_recipient: usize,
    pub active_messages_per_recipient: usize,
    pub active_messages_per_overflow_record: usize,
    pub candidate_messages_per_walk: usize,
    pub mailsend_pages_per_walk: usize,
    pub mailbox_pages_per_walk: usize,
    pub pending_validation_limit: usize,
    pub recipient_inline_pointer_limit: usize,
    pub recipient_inline_byte_limit: usize,
    pub overflow_demote_pointer_limit: usize,
    pub overflow_demote_byte_limit: usize,
    pub overflow_demote_hysteresis_secs: u64,
    pub max_overflow_dhts: usize,
    pub response_check_base_secs: u64,
    pub response_check_max_secs: u64,
    pub response_retention_secs: u64,
    pub close_grace_secs: u64,
    pub receive_region_prefix_bits: u16,
    pub retention_weights: RetentionWeights,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self {
            participate_as_custodian: true,
            // A 64-subkey DHT has approximately 16 KiB available per value.
            // Keep pages comfortably below that ceiling for schema/encoding
            // overhead and future format growth.
            page_target_size: 12 * 1024,
            page_split_threshold: 14 * 1024,
            complete_message_max_size: 10 * 1024,
            max_plaintext_size: 8 * 1024,
            max_service_request_size: 8 * 1024,
            max_service_payload_size: 1024,
            max_service_reply_route_size: 4 * 1024,
            default_service_request_ttl_secs: 15 * 60,
            max_service_request_ttl_secs: 60 * 60,
            active_service_requests_per_sender: 32,
            active_service_requests_per_host: 8,
            recent_service_request_cache: 1024,
            service_request_pointer_checks_per_walk: 24,
            normal_batch_interval_secs: 120,
            maintenance_interval_secs: 30 * 60,
            early_flush_queue_size: 128,
            dht_io_concurrency: 128,
            max_navigation_suggestions: 12,
            advertised_previous_key_epochs: 64,
            max_timestamp_skew_secs: 15 * 60,
            max_message_age_secs: 365 * 24 * 60 * 60,
            max_requested_expiry_secs: 180 * 24 * 60 * 60,
            minimum_bump_interval_secs: 24 * 60 * 60,
            active_messages_per_sender: 256,
            active_messages_per_sender_recipient: 32,
            active_messages_per_recipient: 4_096,
            active_messages_per_overflow_record: 1_000,
            candidate_messages_per_walk: 128,
            mailsend_pages_per_walk: 16,
            mailbox_pages_per_walk: 24,
            pending_validation_limit: 2_048,
            recipient_inline_pointer_limit: 48,
            recipient_inline_byte_limit: 9 * 1024,
            overflow_demote_pointer_limit: 24,
            overflow_demote_byte_limit: 6 * 1024,
            overflow_demote_hysteresis_secs: 14 * 24 * 60 * 60,
            max_overflow_dhts: 256,
            response_check_base_secs: 15 * 60,
            response_check_max_secs: 7 * 24 * 60 * 60,
            response_retention_secs: 180 * 24 * 60 * 60,
            close_grace_secs: 7 * 24 * 60 * 60,
            receive_region_prefix_bits: 12,
            retention_weights: RetentionWeights::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionWeights {
    pub recent_message: f32,
    pub recent_bump: f32,
    pub distance: f32,
    pub sender_reputation: f32,
    pub repeated_verification: f32,
    pub under_replication: f32,
    pub age_penalty: f32,
    pub storage_cost_penalty: f32,
    pub sender_quota_penalty: f32,
    pub replication_penalty: f32,
}

impl Default for RetentionWeights {
    fn default() -> Self {
        Self {
            recent_message: 30.0,
            recent_bump: 10.0,
            distance: 20.0,
            sender_reputation: 20.0,
            repeated_verification: 8.0,
            under_replication: 12.0,
            age_penalty: 35.0,
            storage_cost_penalty: 12.0,
            sender_quota_penalty: 25.0,
            replication_penalty: 10.0,
        }
    }
}

// ============================================================================

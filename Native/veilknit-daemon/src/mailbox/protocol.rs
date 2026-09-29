// Public protocol structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxRegionHint {
    pub center: RecordKey,
    /// A higher value means a narrower preferred XOR neighborhood.
    pub preferred_prefix_bits: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxNavigationSuggestion {
    pub custodian_main_dht: RecordKey,
    pub custodian_mailbox_dht: RecordKey,
    pub advertised_generation: u64,
    pub last_verified_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingMessage {
    pub version: u16,
    pub message_id: [u8; 32],
    pub sender_main_dht: RecordKey,
    pub recipient_main_dht: RecordKey,
    pub receive_key_epoch: u64,
    pub sender_ephemeral_public_key: Vec<u8>,
    pub message_nonce: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub posted_at: u64,
    pub bumped_at: u64,
    pub expires_at: u64,
    pub conversation_id: Option<[u8; 32]>,
    pub proposed_conversation_dht: Option<RecordKey>,
    pub signature: Vec<Signature>,
    /// Authenticates the mutable `bumped_at` field without changing the stable
    /// message identity or the immutable signature.
    pub bump_signature: Vec<Signature>,
}


/// Short-lived, deliberately public mailbox rendezvous request. Unlike
/// `OutgoingMessage`, every field here is readable by custodians/compatible
/// third parties. Applications MUST independently confirm the host's advertised
/// service/widget policy before acting on a delegated request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRequest {
    pub version: u16,
    pub request_id: [u8; 32],
    pub requester_main_dht: RecordKey,
    pub intended_host_main_dht: RecordKey,
    /// Opaque application-defined service/protocol identifier.
    pub service_id: [u8; 32],
    /// Hash of the exact service/widget manifest/source being requested.
    pub service_manifest_hash: [u8; 32],
    /// Identifies the concrete hosted widget/service instance.
    pub instance_id: [u8; 32],
    /// Disposable Veilid private route owned by the requester's daemon.
    pub reply_route_blob: Vec<u8>,
    /// Small, intentionally public application payload (match type, options, etc.).
    pub public_payload: Vec<u8>,
    pub delegation_allowed: bool,
    pub spectators_allowed: bool,
    pub posted_at: u64,
    pub expires_at: u64,
    pub request_nonce: [u8; 32],
    pub signature: Vec<Signature>,
}

#[derive(Debug, Clone)]
pub struct ServiceRequestPublishRequest {
    pub intended_host_main_dht: RecordKey,
    pub service_id: [u8; 32],
    pub service_manifest_hash: [u8; 32],
    pub instance_id: [u8; 32],
    pub public_payload: Vec<u8>,
    pub delegation_allowed: bool,
    pub spectators_allowed: bool,
    pub ttl_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PublishedServiceRequest {
    pub request_id: [u8; 32],
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingWithdrawal {
    pub version: u16,
    pub message_id: [u8; 32],
    pub sender_main_dht: RecordKey,
    pub withdrawn_at: u64,
    pub signature: Vec<Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutgoingRecord {
    // Keep existing variant order stable for bincode compatibility: Message=0,
    // Withdrawal=1. New record kinds must be appended.
    Message(OutgoingMessage),
    Withdrawal(OutgoingWithdrawal),
    ServiceRequest(ServiceRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailSourcePointer {
    pub message_id: [u8; 32],
    pub sender_main_dht: RecordKey,
    pub mail_send_dht: RecordKey,
    pub posted_at: u64,
    pub bumped_at: u64,
    pub requested_expires_at: u64,
    pub first_observed_at: u64,
    pub last_observed_at: u64,
    pub last_verified_at: u64,
    pub failed_verification_count: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecipientSourceStorage {
    Inline { sources: Vec<MailSourcePointer> },
    Overflow {
        record_key: RecordKey,
        overflow_epoch: [u8; 16],
        entry_count: u32,
        serialized_size: u32,
        digest: [u8; 32],
        below_inline_threshold_since: Option<u64>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxRecipientEntry {
    pub recipient_main_dht: RecordKey,
    pub storage: RecipientSourceStorage,
    pub newest_posted_at: u64,
    pub newest_first_seen_at: u64,
    pub last_recipient_check: u64,
    pub last_sender_check: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowPageDescriptor {
    pub subkey: u32,
    /// Canonical full-key bytes. For message/response stores this is the stable
    /// 32-byte id; for mailbox pages it is the full recipient-key bytes.
    pub first_key: Vec<u8>,
    pub last_key: Vec<u8>,
    pub generation: u64,
    pub entry_count: u32,
    pub serialized_size: u32,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowIndex {
    pub version: u16,
    pub generation: u64,
    pub previous_generation: Option<u64>,
    pub created_at: u64,
    pub pages: Vec<CowPageDescriptor>,
    pub digest: [u8; 32],
}

pub type MailboxIndex = CowIndex;
pub type MailSendIndex = CowIndex;
pub type MailResponseIndex = CowIndex;
pub type OverflowIndex = CowIndex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CowDataPage<T> {
    pub version: u16,
    pub generation: u64,
    pub entries: Vec<T>,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailResponseKind {
    Received,
    Seen,
    ApplicationCode { application_id: String, code: u32 },
    EncryptedResponse,
    ConversationDhtAccepted,
    ConversationDhtRejected,
    Rejected { reason_code: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailResponse {
    pub version: u16,
    pub response_id: [u8; 32],
    pub responding_to_message_id: [u8; 32],
    pub conversation_id: Option<[u8; 32]>,
    pub responder_main_dht: RecordKey,
    pub original_sender_main_dht: RecordKey,
    pub response_kind: MailResponseKind,
    pub posted_at: u64,
    pub ciphertext: Option<Vec<u8>>,
    pub published_conversation_dht: Option<RecordKey>,
    pub signature: Vec<Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodianMessageObservation {
    pub custodian_main_dht: RecordKey,
    pub custodian_mailbox_dht: RecordKey,
    pub mailbox_generation: u64,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub trust_weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingMessageObservationReport {
    pub message_id: [u8; 32],
    pub posted_at: u64,
    pub observations: Vec<CustodianMessageObservation>,
    pub raw_recent_custodian_count: u32,
    pub trust_weighted_recent_count: f32,
    pub last_observation_at: Option<u64>,
    pub last_walk_coverage_estimate: f32,
    pub replication_health_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwaitingResponse {
    pub message_id: [u8; 32],
    pub conversation_id: Option<[u8; 32]>,
    pub recipient_main_dht: RecordKey,
    pub recipient_response_dht: RecordKey,
    pub first_check_at: u64,
    pub last_checked_at: Option<u64>,
    pub next_check_at: u64,
    pub stop_checking_after: u64,
    pub check_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxPeerState {
    pub node_main_dht: RecordKey,
    pub mailbox_dht: Option<RecordKey>,
    pub advertised_region: Option<MailboxRegionHint>,
    pub last_advertisement_seen: u64,
    pub last_mailbox_update_seen: Option<u64>,
    pub last_successful_read: Option<u64>,
    pub mailbox_generation: Option<u64>,
    pub stores_our_region: bool,
    pub overlaps_our_preferred_region: bool,
    pub stale_since: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedRecipient {
    pub recipient_main_dht: RecordKey,
    pub first_seen: u64,
    pub last_seen: u64,
    pub last_verified_receiving: Option<u64>,
    pub source_count: u32,
    pub stored_locally: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MailboxAgeProfile {
    pub under_one_week_bytes: u64,
    pub one_week_to_one_month_bytes: u64,
    pub one_to_three_month_bytes: u64,
    pub three_months_to_one_year_bytes: u64,
    pub over_one_year_bytes: u64,
    pub vacant_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct OutgoingMessageRequest {
    pub application_id: String,
    pub recipient_main_dht: RecordKey,
    pub plaintext: Vec<u8>,
    pub expires_at: Option<u64>,
    pub conversation_id: Option<[u8; 32]>,
    pub proposed_conversation_dht: Option<RecordKey>,
    pub await_response: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedApplicationEnvelope {
    version: u16,
    application_id: String,
    sent_at: u64,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ReceivedMailboxMessage {
    pub message: OutgoingMessage,
    pub application_id: String,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct MailboxInboxSummary {
    pub message_id: [u8; 32],
    pub sender_main_dht: RecordKey,
    pub application_id: String,
    pub posted_at: u64,
    pub received_at: u64,
    pub plaintext_len: usize,
    pub read: bool,
}

#[derive(Debug, Clone)]
pub struct MailboxInboxMessage {
    pub message_id: [u8; 32],
    pub sender_main_dht: RecordKey,
    pub recipient_main_dht: RecordKey,
    pub application_id: String,
    pub posted_at: u64,
    pub received_at: u64,
    pub expires_at: u64,
    pub conversation_id: Option<[u8; 32]>,
    pub plaintext: Vec<u8>,
    pub read: bool,
}

#[derive(Debug, Clone)]
pub enum MailboxEvent {
    MailDiscovered(MailSourcePointer),
    ServiceRequestDiscovered(ServiceRequest),
    OutgoingSeeded(MailSourcePointer),
    MailDecrypted(ReceivedMailboxMessage),
    ResponseDiscovered(MailResponse),
    ObservationReportUpdated(OutgoingMessageObservationReport),
    MailboxAdvertisementChanged(MailboxAdvertisement),
    RequestWalk(MailboxWalkRequest),
    Warning(String),
}

#[derive(Debug, Clone)]
pub enum MailboxWalkRequest {
    RetrieveOurMail,
    MaintenanceTargets(Vec<RecordKey>),
}

// ============================================================================

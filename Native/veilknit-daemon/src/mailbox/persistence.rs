// Local persistent structures
// ============================================================================

/// JSON object keys must be strings. Mailbox message identifiers are binary
/// 32-byte values, so serialize maps keyed by message id using lowercase hex
/// keys and convert them back while loading. Empty legacy JSON maps remain
/// compatible with this representation.
mod message_id_map {
    use super::*;
    use serde::{ser::SerializeMap, Deserializer, Serializer};

    pub fn serialize<S, V>(
        values: &BTreeMap<[u8; 32], V>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        let mut map = serializer.serialize_map(Some(values.len()))?;
        for (message_id, value) in values {
            map.serialize_entry(&hex::encode(message_id), value)?;
        }
        map.end()
    }

    pub fn deserialize<'de, D, V>(deserializer: D) -> Result<BTreeMap<[u8; 32], V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let encoded = BTreeMap::<String, V>::deserialize(deserializer)?;
        let mut values = BTreeMap::new();
        for (encoded_id, value) in encoded {
            let mut message_id = [0u8; 32];
            hex::decode_to_slice(encoded_id.as_bytes(), &mut message_id).map_err(|error| {
                <D::Error as serde::de::Error>::custom(format!(
                    "invalid mailbox message-id key {encoded_id:?}: {error}"
                ))
            })?;
            values.insert(message_id, value);
        }
        Ok(values)
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
struct OverflowLocalState {
    recipient_main_dht: RecordKey,
    record_key: RecordKey,
    package_index: usize,
    overflow_epoch: [u8; 16],
    below_inline_threshold_since: Option<u64>,
    retired: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingCowTransaction {
    store_name: String,
    package_index: usize,
    generation: u64,
    target_index_slot: u32,
    new_page_subkeys: Vec<u32>,
    started_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingCowTransactionLog {
    version: u32,
    transactions: Vec<PendingCowTransaction>,
}

impl Default for PendingCowTransactionLog {
    fn default() -> Self {
        Self {
            version: MAILBOX_STORE_VERSION,
            transactions: Vec::new(),
        }
    }
}

fn persist_transaction_log(
    auth: &UserAuth,
    session: &UserSession,
    transactions: &[PendingCowTransaction],
) -> Result<(), MailboxError> {
    auth.write_user_encrypted(
        session,
        MAILBOX_TRANSACTION_STORE_KEY,
        &PendingCowTransactionLog {
            version: MAILBOX_STORE_VERSION,
            transactions: transactions.to_vec(),
        },
    )?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMailboxMessage {
    message_id: [u8; 32],
    sender_main_dht: RecordKey,
    recipient_main_dht: RecordKey,
    application_id: String,
    posted_at: u64,
    received_at: u64,
    expires_at: u64,
    conversation_id: Option<[u8; 32]>,
    plaintext: Vec<u8>,
    read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxPersistentState {
    version: u32,
    mailbox_package: Option<usize>,
    mail_send_package: Option<usize>,
    mail_response_package: usize,
    mailbox_master_secret: [u8; 32],
    mail_signing_keypair: KeyPair,
    receive_status: crate::types::ReceiveStatus,
    receive_key_epoch: u64,
    receive_key_versions: Vec<ReceiveKeyVersion>,
    revoked_receive_epochs: HashSet<u64>,
    overflow_records: HashMap<String, OverflowLocalState>,
    #[serde(with = "message_id_map")]
    outgoing_messages: BTreeMap<[u8; 32], OutgoingMessage>,
    #[serde(with = "message_id_map")]
    awaiting_responses: BTreeMap<[u8; 32], AwaitingResponse>,
    #[serde(with = "message_id_map")]
    observation_reports: BTreeMap<[u8; 32], OutgoingMessageObservationReport>,
    mailbox_peers: HashMap<String, MailboxPeerState>,
    observed_recipients: HashMap<String, ObservedRecipient>,
    pending_transactions: Vec<PendingCowTransaction>,
    generation_counter: u64,
    // Kept at the end for backward-compatible bincode deserialization of v1 state.
    #[serde(default, with = "message_id_map")]
    inbox_messages: BTreeMap<[u8; 32], StoredMailboxMessage>,
}

// ============================================================================
// Errors
// ============================================================================

#[derive(Debug)]
pub enum MailboxError {
    ChannelClosed,
    Dht(String),
    Auth(String),
    Serialize(String),
    Crypto(String),
    InvalidAdvertisement(String),
    InvalidMessage(String),
    MessageTooLarge { actual: usize, maximum: usize },
    PlaintextTooLarge { actual: usize, maximum: usize },
    RecipientNotAccepting,
    ReceiveKeyUnavailable(u64),
    MessageNotFound,
    ResponseNotExpected,
    QuotaExceeded(&'static str),
    NoFreePageSubkey,
    StoreCorrupt(String),
    UnsupportedStoreVersion(u32),
    Shutdown,
}

impl fmt::Display for MailboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelClosed => write!(f, "mailbox controller channel closed"),
            Self::Dht(message) => write!(f, "DHT error: {message}"),
            Self::Auth(message) => write!(f, "mailbox persistence error: {message}"),
            Self::Serialize(message) => write!(f, "serialization error: {message}"),
            Self::Crypto(message) => write!(f, "mailbox cryptography error: {message}"),
            Self::InvalidAdvertisement(message) => write!(f, "invalid mailbox advertisement: {message}"),
            Self::InvalidMessage(message) => write!(f, "invalid mailbox message: {message}"),
            Self::MessageTooLarge { actual, maximum } => write!(f, "serialized message is {actual} bytes; maximum is {maximum}"),
            Self::PlaintextTooLarge { actual, maximum } => write!(f, "plaintext is {actual} bytes; maximum is {maximum}"),
            Self::RecipientNotAccepting => write!(f, "recipient is not accepting this message"),
            Self::ReceiveKeyUnavailable(epoch) => write!(f, "receive key epoch {epoch} is unavailable or revoked"),
            Self::MessageNotFound => write!(f, "mailbox message was not found"),
            Self::ResponseNotExpected => write!(f, "no response is pending for this message"),
            Self::QuotaExceeded(name) => write!(f, "mailbox quota exceeded: {name}"),
            Self::NoFreePageSubkey => write!(f, "no free DHT data-page subkey remains"),
            Self::StoreCorrupt(message) => write!(f, "copy-on-write store is corrupt: {message}"),
            Self::UnsupportedStoreVersion(version) => write!(f, "unsupported mailbox store version {version}"),
            Self::Shutdown => write!(f, "mailbox controller is shutting down"),
        }
    }
}

impl std::error::Error for MailboxError {}

impl From<CreateDhtError> for MailboxError {
    fn from(value: CreateDhtError) -> Self {
        Self::Dht(format!("{value:?}"))
    }
}

impl From<AuthError> for MailboxError {
    fn from(value: AuthError) -> Self {
        Self::Auth(value.to_string())
    }
}

// ============================================================================

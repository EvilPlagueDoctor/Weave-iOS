// Transactional custodian quota accounting
// ============================================================================
//
// The DHT page/index generations remain authoritative. These counters are a
// persistent enforcement cache: they are updated with each in-memory mutation,
// persisted after successful page commits, and rebuilt from validated stores on
// startup/repair. A crash before or after either side of a commit therefore
// cannot permanently desynchronise quota enforcement.

const MAILBOX_QUOTA_STATE_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MailboxQuotaState {
    version: u16,
    generation: u64,
    rebuilt_at: u64,
    sender_counts: HashMap<String, u32>,
    sender_recipient_counts: HashMap<String, HashMap<String, u32>>,
    recipient_counts: HashMap<String, u32>,
    overflow_record_counts: HashMap<String, u32>,
}

impl Default for MailboxQuotaState {
    fn default() -> Self {
        Self {
            version: MAILBOX_QUOTA_STATE_VERSION,
            generation: 0,
            rebuilt_at: 0,
            sender_counts: HashMap::new(),
            sender_recipient_counts: HashMap::new(),
            recipient_counts: HashMap::new(),
            overflow_record_counts: HashMap::new(),
        }
    }
}

impl MailboxQuotaState {
    fn same_counts(&self, other: &Self) -> bool {
        self.sender_counts == other.sender_counts
            && self.sender_recipient_counts == other.sender_recipient_counts
            && self.recipient_counts == other.recipient_counts
            && self.overflow_record_counts == other.overflow_record_counts
    }

    fn rebuild(
        mailbox_store: Option<&CowPagedStore<MailboxRecipientEntry>>,
        overflow_stores: &HashMap<String, CowPagedStore<MailSourcePointer>>,
    ) -> Self {
        let mut state = Self::default();
        state.generation = 1;
        state.rebuilt_at = current_timestamp();
        let Some(mailbox_store) = mailbox_store else {
            return state;
        };

        let mut seen = HashSet::<(String, [u8; 32])>::new();
        for entry in mailbox_store.all_entries() {
            let recipient = entry.recipient_main_dht.to_string();
            match entry.storage {
                RecipientSourceStorage::Inline { sources } => {
                    for pointer in sources {
                        if seen.insert((recipient.clone(), pointer.message_id)) {
                            state.add_pointer_counts(&recipient, &pointer);
                        }
                    }
                }
                RecipientSourceStorage::Overflow { record_key, .. } => {
                    let sources = overflow_stores
                        .get(&recipient)
                        .map(|store| store.all_entries())
                        .unwrap_or_default();
                    let mut overflow_count = 0u32;
                    for pointer in sources {
                        if seen.insert((recipient.clone(), pointer.message_id)) {
                            state.add_pointer_counts(&recipient, &pointer);
                            overflow_count = overflow_count.saturating_add(1);
                        }
                    }
                    if overflow_count != 0 {
                        state
                            .overflow_record_counts
                            .insert(record_key.to_string(), overflow_count);
                    }
                }
            }
        }
        state
    }

    fn ensure_can_add(
        &self,
        recipient: &RecordKey,
        pointer: &MailSourcePointer,
        overflow_record: Option<&RecordKey>,
        config: &MailboxConfig,
    ) -> Result<(), MailboxError> {
        let sender = pointer.sender_main_dht.to_string();
        let recipient = recipient.to_string();
        if self.sender_counts.get(&sender).copied().unwrap_or(0) as usize
            >= config.active_messages_per_sender
        {
            return Err(MailboxError::QuotaExceeded("custodian messages per sender"));
        }
        if self
            .sender_recipient_counts
            .get(&sender)
            .and_then(|recipients| recipients.get(&recipient))
            .copied()
            .unwrap_or(0) as usize
            >= config.active_messages_per_sender_recipient
        {
            return Err(MailboxError::QuotaExceeded(
                "custodian messages per sender-recipient",
            ));
        }
        if self.recipient_counts.get(&recipient).copied().unwrap_or(0) as usize
            >= config.active_messages_per_recipient
        {
            return Err(MailboxError::QuotaExceeded(
                "custodian messages per recipient",
            ));
        }
        if let Some(record_key) = overflow_record {
            if self
                .overflow_record_counts
                .get(&record_key.to_string())
                .copied()
                .unwrap_or(0) as usize
                >= config.active_messages_per_overflow_record
            {
                return Err(MailboxError::QuotaExceeded(
                    "messages in one overflow record",
                ));
            }
        }
        Ok(())
    }

    fn note_added(
        &mut self,
        recipient: &RecordKey,
        pointer: &MailSourcePointer,
        overflow_record: Option<&RecordKey>,
    ) {
        self.add_pointer_counts(&recipient.to_string(), pointer);
        if let Some(record_key) = overflow_record {
            increment_map(&mut self.overflow_record_counts, record_key.to_string());
        }
        self.generation = self.generation.saturating_add(1).max(1);
    }

    fn note_removed(
        &mut self,
        recipient: &RecordKey,
        pointer: &MailSourcePointer,
        overflow_record: Option<&RecordKey>,
    ) {
        let sender = pointer.sender_main_dht.to_string();
        let recipient = recipient.to_string();
        decrement_map(&mut self.sender_counts, &sender);
        decrement_nested_map(&mut self.sender_recipient_counts, &sender, &recipient);
        decrement_map(&mut self.recipient_counts, &recipient);
        if let Some(record_key) = overflow_record {
            decrement_map(&mut self.overflow_record_counts, &record_key.to_string());
        }
        self.generation = self.generation.saturating_add(1).max(1);
    }

    fn set_overflow_count(&mut self, record_key: &RecordKey, count: usize) {
        if count == 0 {
            self.overflow_record_counts.remove(&record_key.to_string());
        } else {
            self.overflow_record_counts
                .insert(record_key.to_string(), count.min(u32::MAX as usize) as u32);
        }
        self.generation = self.generation.saturating_add(1).max(1);
    }

    fn remove_overflow_record(&mut self, record_key: &RecordKey) {
        if self
            .overflow_record_counts
            .remove(&record_key.to_string())
            .is_some()
        {
            self.generation = self.generation.saturating_add(1).max(1);
        }
    }

    fn add_pointer_counts(&mut self, recipient: &str, pointer: &MailSourcePointer) {
        let sender = pointer.sender_main_dht.to_string();
        increment_map(&mut self.sender_counts, sender.clone());
        increment_nested_map(
            &mut self.sender_recipient_counts,
            sender,
            recipient.to_string(),
        );
        increment_map(&mut self.recipient_counts, recipient.to_string());
    }
}

fn increment_map<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u32>, key: K) {
    let value = map.entry(key).or_insert(0);
    *value = value.saturating_add(1);
}

fn increment_nested_map(
    map: &mut HashMap<String, HashMap<String, u32>>,
    outer: String,
    inner: String,
) {
    increment_map(map.entry(outer).or_default(), inner);
}

fn decrement_nested_map(map: &mut HashMap<String, HashMap<String, u32>>, outer: &str, inner: &str) {
    let remove_outer = match map.get_mut(outer) {
        Some(inner_map) => {
            decrement_map(inner_map, &inner.to_string());
            inner_map.is_empty()
        }
        None => false,
    };
    if remove_outer {
        map.remove(outer);
    }
}

fn decrement_map<K: std::hash::Hash + Eq>(map: &mut HashMap<K, u32>, key: &K) {
    let remove = match map.get_mut(key) {
        Some(value) if *value > 1 => {
            *value -= 1;
            false
        }
        Some(_) => true,
        None => false,
    };
    if remove {
        map.remove(key);
    }
}

#[cfg(test)]
mod quota_tests {
    use super::*;

    const TEST_DHT: &str = "VLD0:Ql5L4_BYpaHtBECl5khtcSIW-lAnnC5vV5PIZCl7vAs:9C9jBokYTHBBBaq7aev39a9ujPVCCzGLE0-Tx_N7FyQ";

    fn pointer(key: &RecordKey) -> MailSourcePointer {
        MailSourcePointer {
            message_id: [7; 32],
            sender_main_dht: key.clone(),
            mail_send_dht: key.clone(),
            posted_at: 1,
            bumped_at: 1,
            requested_expires_at: 100,
            first_observed_at: 1,
            last_observed_at: 1,
            last_verified_at: 1,
            failed_verification_count: 0,
        }
    }

    #[test]
    fn quota_add_remove_round_trip_enforces_all_dimensions() {
        let key: RecordKey = TEST_DHT.parse().unwrap();
        let source = pointer(&key);
        let mut config = MailboxConfig::default();
        config.active_messages_per_sender = 1;
        config.active_messages_per_sender_recipient = 1;
        config.active_messages_per_recipient = 1;
        config.active_messages_per_overflow_record = 1;

        let mut state = MailboxQuotaState::default();
        assert!(state
            .ensure_can_add(&key, &source, Some(&key), &config)
            .is_ok());
        state.note_added(&key, &source, Some(&key));
        assert!(serde_json::to_vec_pretty(&state).is_ok());
        assert!(matches!(
            state.ensure_can_add(&key, &source, Some(&key), &config),
            Err(MailboxError::QuotaExceeded(_))
        ));
        state.note_removed(&key, &source, Some(&key));
        assert!(state
            .ensure_can_add(&key, &source, Some(&key), &config)
            .is_ok());
        assert!(state.sender_counts.is_empty());
        assert!(state.sender_recipient_counts.is_empty());
        assert!(state.recipient_counts.is_empty());
        assert!(state.overflow_record_counts.is_empty());
    }
}

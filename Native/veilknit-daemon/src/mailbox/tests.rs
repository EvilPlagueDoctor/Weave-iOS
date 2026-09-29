#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct MessageIdMapFixture {
        #[serde(with = "message_id_map")]
        values: BTreeMap<[u8; 32], u32>,
    }

    #[test]
    fn message_id_maps_round_trip_through_json_string_keys() {
        let mut values = BTreeMap::new();
        values.insert([0xabu8; 32], 7);
        let fixture = MessageIdMapFixture { values };

        let encoded = serde_json::to_string_pretty(&fixture).unwrap();
        assert!(encoded.contains(&hex::encode([0xabu8; 32])));

        let decoded: MessageIdMapFixture = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, fixture);
    }

    const TEST_DHT: &str = "VLD0:Ql5L4_BYpaHtBECl5khtcSIW-lAnnC5vV5PIZCl7vAs:9C9jBokYTHBBBaq7aev39a9ujPVCCzGLE0-Tx_N7FyQ";

    #[test]
    fn receive_epoch_derivation_is_deterministic_and_separated() {
        let master = [7u8; 32];
        assert_eq!(receive_public_key(&master, 1), receive_public_key(&master, 1));
        assert_ne!(receive_public_key(&master, 1), receive_public_key(&master, 2));
    }

    #[test]
    fn bump_does_not_change_message_id() {
        let sender: RecordKey = TEST_DHT.parse().unwrap();
        let recipient = sender.clone();
        let nonce = [9u8; 32];
        let ciphertext = b"ciphertext";
        let first = calculate_message_id(&sender, &recipient, 100, &nonce, ciphertext);
        let second = calculate_message_id(&sender, &recipient, 100, &nonce, ciphertext);
        assert_eq!(first, second);
        assert_ne!(bump_bytes(first, 101).unwrap(), bump_bytes(first, 102).unwrap());
    }

    #[test]
    fn page_digest_detects_content_mutation() {
        let mut page = CowDataPage {
            version: MAILBOX_PROTOCOL_VERSION,
            generation: 1,
            entries: vec![1u32, 2, 3],
            digest: [0; 32],
        };
        page.digest = page_digest(&page).unwrap();
        let original = page.digest;
        page.entries.push(4);
        assert_ne!(original, page_digest(&page).unwrap());
    }

    #[test]
    fn dirty_page_splits_without_rewriting_clean_pages() {
        let sender: RecordKey = TEST_DHT.parse().unwrap();
        let mut entries = Vec::new();
        for value in 0u8..16 {
            let mut id = [0u8; 32];
            id[31] = value;
            entries.push(OutgoingRecord::Withdrawal(OutgoingWithdrawal {
                version: MAILBOX_PROTOCOL_VERSION,
                message_id: id,
                sender_main_dht: sender.clone(),
                withdrawn_at: value as u64,
                signature: Vec::new(),
            }));
        }
        let mut store = CowPagedStore {
            name: "test".to_string(),
            package_index: 0,
            total_subkeys: 1000,
            active_index_slot: INDEX_SLOT_A,
            current_index: None,
            previous_index: None,
            pages: vec![LocalPage {
                descriptor: None,
                entries,
                dirty: true,
            }],
        };
        let mut config = MailboxConfig::default();
        config.page_target_size = 256;
        config.page_split_threshold = 300;
        store.rebalance_dirty_pages(&config).unwrap();
        assert!(store.pages.len() > 1);
        assert!(store.pages.iter().all(|page| page.dirty));
    }

    #[test]
    fn mailbox_paged_schema_leaves_room_for_encrypted_message_pages() {
        assert_eq!(
            PAGED_DHT_GROUPS.iter().map(|count| *count as u32).sum::<u32>(),
            PAGED_DHT_TOTAL_SUBKEYS,
        );
        assert_eq!(PAGED_DHT_TOTAL_SUBKEYS, 64);

        let config = MailboxConfig::default();
        let safe_value_limit = estimated_dht_value_limit(PAGED_DHT_TOTAL_SUBKEYS);
        assert!(config.page_target_size < config.page_split_threshold);
        assert!(config.page_split_threshold <= safe_value_limit);
        assert!(config.complete_message_max_size < config.page_split_threshold);
    }

    #[test]
    fn legacy_thousand_subkey_schema_is_too_small_for_mail_pages() {
        let legacy_limit = estimated_dht_value_limit(1000);
        let current_limit = estimated_dht_value_limit(PAGED_DHT_TOTAL_SUBKEYS);
        assert!(legacy_limit < 1024);
        assert!(current_limit > 14 * 1024);
    }

    #[test]
    fn observation_count_deduplicates_by_custodian_in_runtime_logic() {
        let dht: RecordKey = TEST_DHT.parse().unwrap();
        let mut report = OutgoingMessageObservationReport {
            message_id: [1; 32],
            posted_at: 1,
            observations: vec![CustodianMessageObservation {
                custodian_main_dht: dht.clone(),
                custodian_mailbox_dht: dht,
                mailbox_generation: 1,
                first_seen_at: 10,
                last_seen_at: 20,
                trust_weight: 1.0,
            }],
            raw_recent_custodian_count: 0,
            trust_weighted_recent_count: 0.0,
            last_observation_at: None,
            last_walk_coverage_estimate: 0.0,
            replication_health_score: 0.0,
        };
        refresh_observation_report(&mut report, 21, 1.0);
        assert_eq!(report.raw_recent_custodian_count, 1);
    }
}

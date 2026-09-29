// Runtime initialization and actor
// ============================================================================

const RECENTLY_DECRYPTED_MAX_ENTRIES: usize = 65_536;
const RECENTLY_DECRYPTED_TTL_SECS: u64 = 30 * 24 * 60 * 60;
const LOCAL_INBOX_MAX_MESSAGES: usize = 4_096;

/// PATCH A: bounded replay/deduplication cache. The previous HashSet retained
/// every decrypted message id for the lifetime of the process.
struct RecentlyDecryptedCache {
    entries: HashMap<[u8; 32], u64>,
    order: VecDeque<([u8; 32], u64)>,
}

impl RecentlyDecryptedCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn contains(&mut self, message_id: &[u8; 32], now: u64) -> bool {
        self.prune(now);
        self.entries.contains_key(message_id)
    }

    fn insert(&mut self, message_id: [u8; 32], now: u64) {
        self.prune(now);
        if self.entries.contains_key(&message_id) {
            return;
        }
        self.entries.insert(message_id, now);
        self.order.push_back((message_id, now));
        self.prune(now);
    }

    fn prune(&mut self, now: u64) {
        while let Some((message_id, inserted_at)) = self.order.front().copied() {
            let expired = inserted_at.saturating_add(RECENTLY_DECRYPTED_TTL_SECS) <= now;
            let over_capacity = self.entries.len() > RECENTLY_DECRYPTED_MAX_ENTRIES;
            if !expired && !over_capacity {
                break;
            }

            self.order.pop_front();
            if self.entries.get(&message_id).copied() == Some(inserted_at) {
                self.entries.remove(&message_id);
            }
        }
    }
}

struct MailboxRuntime {
    veilid: VeilidAPI,
    dht: DHTModule,
    main_dht_package: usize,
    own_main_dht: RecordKey,
    auth: Arc<UserAuth>,
    session: Arc<UserSession>,
    reputation: ReputationModuleHandle,
    config: MailboxConfig,
    persistent: MailboxPersistentState,
    mailbox_store: Option<CowPagedStore<MailboxRecipientEntry>>,
    outbox_store: Option<CowPagedStore<OutgoingRecord>>,
    response_store: CowPagedStore<MailResponse>,
    overflow_stores: HashMap<String, CowPagedStore<MailSourcePointer>>,
    quota_state: MailboxQuotaState,
    recently_decrypted: RecentlyDecryptedCache,
    /// Short-lived requests created by this process. They are deliberately not
    /// persisted because their disposable Veilid reply routes cannot survive a
    /// daemon restart.
    outgoing_service_requests: BTreeMap<[u8; 32], ServiceRequest>,
    service_reply_routes: HashMap<[u8; 32], RouteId>,
    /// Recently verified public requests used to give new subscribers an
    /// immediate snapshot instead of waiting for the next network walk.
    recent_service_requests: BTreeMap<[u8; 32], ServiceRequest>,
    last_walk_report: Option<WalkRunReport>,
}

async fn package_uses_current_paged_layout(
    dht: &DHTModule,
    package_index: usize,
) -> bool {
    dht.get_dht_info(package_index)
        .await
        .is_some_and(|package| package.total_subkeys() == PAGED_DHT_TOTAL_SUBKEYS)
}

async fn recover_legacy_store_entries<T: PageEntry>(
    store_name: impl Into<String>,
    dht: &DHTModule,
    package_index: usize,
    config: &MailboxConfig,
) -> Vec<T> {
    let store_name = store_name.into();
    match CowPagedStore::<T>::load_owned(
        store_name.clone(),
        dht,
        package_index,
        config,
    )
    .await
    {
        Ok(store) => {
            let entries = store.all_entries();
            crate::teprintln!(
                "[mailbox] migrating {} entries from legacy {}-subkey store {:?}",
                entries.len(),
                dht.get_dht_info(package_index)
                    .await
                    .map(|package| package.total_subkeys())
                    .unwrap_or(0),
                store_name,
            );
            entries
        }
        Err(error) => {
            crate::teprintln!(
                "[mailbox] could not read legacy store {:?} before rotation: {}",
                store_name,
                error,
            );
            Vec::new()
        }
    }
}

fn migrate_legacy_own_pointer(
    pointer: &mut MailSourcePointer,
    own_main_dht: &RecordKey,
    legacy_mail_send_dht: Option<&RecordKey>,
    replacement_mail_send_dht: Option<&RecordKey>,
    outgoing_messages: &BTreeMap<[u8; 32], OutgoingMessage>,
) -> bool {
    if &pointer.sender_main_dht != own_main_dht {
        return true;
    }
    let Some(legacy_mail_send_dht) = legacy_mail_send_dht else {
        return true;
    };
    if &pointer.mail_send_dht != legacy_mail_send_dht {
        return true;
    }

    if !outgoing_messages.contains_key(&pointer.message_id) {
        // A prior send may have committed its self-seeded pointer before the
        // oversized MailSend page failed. Do not carry that dangling pointer
        // into the replacement mailbox.
        return false;
    }

    let Some(replacement) = replacement_mail_send_dht else {
        return false;
    };
    pointer.mail_send_dht = replacement.clone();
    true
}

impl MailboxRuntime {
    async fn initialize(init: MailboxInit) -> Result<Self, MailboxError> {
        let own_main_dht = init
            .dht_module
            .package_id_to_key(init.main_dht_package)
            .await?;
        let mut persistent = match init
            .user_auth
            .read_user_encrypted::<MailboxPersistentState>(&init.user_session, MAILBOX_STORE_KEY)?
        {
            Some(state) => {
                if state.version != MAILBOX_STORE_VERSION {
                    return Err(MailboxError::UnsupportedStoreVersion(state.version));
                }
                state
            }
            None => {
                let mut master = [0u8; 32];
                OsRng.fill_bytes(&mut master);
                let signing = Crypto::generate_keypair(CRYPTO_KIND_VLD0)
                    .map_err(|error| MailboxError::Crypto(error.to_string()))?;
                let now = current_timestamp();
                let public_key = receive_public_key(&master, 1);

                let response_package = init
                    .dht_module
                    .create_dht(MAILRESPONSE_DHT_NAME.to_string(), PAGED_DHT_GROUPS.to_vec())
                    .await?;
                let mailbox_package = if init.config.participate_as_custodian {
                    Some(
                        init.dht_module
                            .create_dht(MAILBOX_DHT_NAME.to_string(), PAGED_DHT_GROUPS.to_vec())
                            .await?,
                    )
                } else {
                    None
                };

                MailboxPersistentState {
                    version: MAILBOX_STORE_VERSION,
                    mailbox_package,
                    mail_send_package: None,
                    mail_response_package: response_package,
                    mailbox_master_secret: master,
                    mail_signing_keypair: signing,
                    receive_status: crate::types::ReceiveStatus::Accepting,
                    receive_key_epoch: 1,
                    receive_key_versions: vec![ReceiveKeyVersion {
                        epoch: 1,
                        public_key,
                        valid_from: now,
                        valid_until: None,
                        status: ReceiveKeyStatus::Current,
                    }],
                    revoked_receive_epochs: HashSet::new(),
                    overflow_records: HashMap::new(),
                    outgoing_messages: BTreeMap::new(),
                    awaiting_responses: BTreeMap::new(),
                    observation_reports: BTreeMap::new(),
                    mailbox_peers: HashMap::new(),
                    observed_recipients: HashMap::new(),
                    pending_transactions: Vec::new(),
                    generation_counter: 0,
                    inbox_messages: BTreeMap::new(),
                }
            }
        };

        // Consult the separately persisted transaction log before recovery.
        // A/B index validation remains authoritative; the log identifies the
        // exact generation/subkeys that may have been orphaned by a crash.
        let transaction_log = init
            .user_auth
            .read_user_encrypted::<PendingCowTransactionLog>(
                &init.user_session,
                MAILBOX_TRANSACTION_STORE_KEY,
            )?
            .unwrap_or_default();
        if transaction_log.version != MAILBOX_STORE_VERSION {
            return Err(MailboxError::UnsupportedStoreVersion(
                transaction_log.version,
            ));
        }
        persistent.pending_transactions = transaction_log.transactions;
        for transaction in &persistent.pending_transactions {
            crate::teprintln!(
                "[mailbox] recovering interrupted {} generation {} (index slot {}, pages {:?})",
                transaction.store_name,
                transaction.generation,
                transaction.target_index_slot,
                transaction.new_page_subkeys,
            );
        }
        // Store loading below chooses the highest completely valid generation.
        // Any logged pages not referenced by that generation remain recyclable.
        persistent.pending_transactions.clear();

        // Package indices are valid only when the corresponding owned DHT was
        // restored into DHTModule. In addition, mailbox paging records created
        // by the earlier 1000-subkey layout must be rotated: Veilid divides the
        // record's value budget across subkeys, leaving only about 1 KiB per
        // value in that schema. The current 64-subkey layout leaves enough room
        // for a complete encrypted message page.
        let mut migrated_mailbox_entries: Vec<MailboxRecipientEntry> = Vec::new();
        let mut migrated_outbox_entries: Vec<OutgoingRecord> = Vec::new();
        let mut migrated_response_entries: Vec<MailResponse> = Vec::new();
        let mut migrated_overflow_entries: HashMap<String, Vec<MailSourcePointer>> =
            HashMap::new();
        let mut legacy_mail_send_dht: Option<RecordKey> = None;

        if !package_uses_current_paged_layout(
            &init.dht_module,
            persistent.mail_response_package,
        )
        .await
        {
            if init
                .dht_module
                .get_dht_info(persistent.mail_response_package)
                .await
                .is_some()
            {
                migrated_response_entries = recover_legacy_store_entries(
                    "mail_response_legacy",
                    &init.dht_module,
                    persistent.mail_response_package,
                    &init.config,
                )
                .await;
            }
            persistent.mail_response_package = init
                .dht_module
                .create_dht(
                    MAILRESPONSE_DHT_NAME.to_string(),
                    PAGED_DHT_GROUPS.to_vec(),
                )
                .await?;
        }

        if let Some(package) = persistent.mailbox_package {
            if !package_uses_current_paged_layout(&init.dht_module, package).await {
                if init.dht_module.get_dht_info(package).await.is_some() {
                    migrated_mailbox_entries = recover_legacy_store_entries(
                        "mailbox_legacy",
                        &init.dht_module,
                        package,
                        &init.config,
                    )
                    .await;
                }
                persistent.mailbox_package = None;
            }
        }
        if persistent.mailbox_package.is_none() && init.config.participate_as_custodian {
            persistent.mailbox_package = Some(
                init.dht_module
                    .create_dht(
                        MAILBOX_DHT_NAME.to_string(),
                        PAGED_DHT_GROUPS.to_vec(),
                    )
                    .await?,
            );
        }

        if let Some(package) = persistent.mail_send_package {
            if !package_uses_current_paged_layout(&init.dht_module, package).await {
                if init.dht_module.get_dht_info(package).await.is_some() {
                    legacy_mail_send_dht =
                        init.dht_module.package_id_to_key(package).await.ok();
                    migrated_outbox_entries = recover_legacy_store_entries(
                        "mail_send_legacy",
                        &init.dht_module,
                        package,
                        &init.config,
                    )
                    .await;
                }
                persistent.mail_send_package = None;
            }
        }
        if persistent.mail_send_package.is_none() && !persistent.outgoing_messages.is_empty() {
            persistent.mail_send_package = Some(
                init.dht_module
                    .create_dht(
                        MAILSEND_DHT_NAME.to_string(),
                        PAGED_DHT_GROUPS.to_vec(),
                    )
                    .await?,
            );
        }

        persistent
            .overflow_records
            .retain(|_, overflow| !overflow.retired);
        for (recipient, mut overflow) in persistent.overflow_records.clone() {
            if package_uses_current_paged_layout(
                &init.dht_module,
                overflow.package_index,
            )
            .await
            {
                continue;
            }

            if init
                .dht_module
                .get_dht_info(overflow.package_index)
                .await
                .is_some()
            {
                let entries = recover_legacy_store_entries(
                    format!("overflow_legacy:{recipient}"),
                    &init.dht_module,
                    overflow.package_index,
                    &init.config,
                )
                .await;
                migrated_overflow_entries.insert(recipient.clone(), entries);
            }

            let package = init
                .dht_module
                .create_dht(
                    format!(
                        "{OVERFLOW_DHT_NAME_PREFIX}_{}",
                        &hash_bytes(recipient.as_bytes())[..4]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    ),
                    PAGED_DHT_GROUPS.to_vec(),
                )
                .await?;
            overflow.package_index = package;
            overflow.record_key = init.dht_module.package_id_to_key(package).await?;
            persistent.overflow_records.insert(recipient, overflow);
        }

        let replacement_mail_send_dht = match persistent.mail_send_package {
            Some(package) => Some(init.dht_module.package_id_to_key(package).await?),
            None => None,
        };

        // Repoint valid self-seeded pointers to the replacement MailSend DHT.
        // Drop the dangling pointer left by a send whose mailbox pointer
        // committed before its oversized message page failed.
        migrated_mailbox_entries.retain_mut(|entry| match &mut entry.storage {
            RecipientSourceStorage::Inline { sources } => {
                sources.retain_mut(|pointer| {
                    migrate_legacy_own_pointer(
                        pointer,
                        &own_main_dht,
                        legacy_mail_send_dht.as_ref(),
                        replacement_mail_send_dht.as_ref(),
                        &persistent.outgoing_messages,
                    )
                });
                !sources.is_empty()
            }
            RecipientSourceStorage::Overflow { .. } => true,
        });
        for sources in migrated_overflow_entries.values_mut() {
            sources.retain_mut(|pointer| {
                migrate_legacy_own_pointer(
                    pointer,
                    &own_main_dht,
                    legacy_mail_send_dht.as_ref(),
                    replacement_mail_send_dht.as_ref(),
                    &persistent.outgoing_messages,
                )
            });
        }

        // Mailbox recipient entries may contain direct pointers to an overflow
        // record that was just rotated. Repoint those entries before committing
        // the migrated mailbox generation.
        for entry in &mut migrated_mailbox_entries {
            let recipient = entry.recipient_main_dht.to_string();
            if let RecipientSourceStorage::Overflow { record_key, .. } = &mut entry.storage {
                if let Some(overflow) = persistent.overflow_records.get(&recipient) {
                    *record_key = overflow.record_key.clone();
                }
            }
        }

        let mut mailbox_store = match persistent.mailbox_package {
            Some(package) => Some(
                CowPagedStore::load_owned("mailbox", &init.dht_module, package, &init.config)
                    .await?,
            ),
            None => None,
        };
        if let Some(store) = &mut mailbox_store {
            for entry in migrated_mailbox_entries {
                store.upsert(entry);
            }
        }
        let mut outbox_store = match persistent.mail_send_package {
            Some(package) => Some(
                CowPagedStore::load_owned("mail_send", &init.dht_module, package, &init.config)
                    .await?,
            ),
            None => None,
        };
        if let Some(store) = &mut outbox_store {
            for record in migrated_outbox_entries {
                store.upsert(record);
            }

            // Recover authoritative outgoing records that reached the DHT but
            // were not written to the encrypted JSON state (for example, an
            // interrupted persistence write). This also repairs the first-send
            // failure caused by binary message ids being invalid JSON keys.
            for record in store.all_entries() {
                match record {
                    OutgoingRecord::Message(message) => {
                        let message_id = message.message_id;
                        persistent
                            .outgoing_messages
                            .entry(message_id)
                            .or_insert_with(|| message.clone());
                        persistent
                            .observation_reports
                            .entry(message_id)
                            .or_insert_with(|| OutgoingMessageObservationReport {
                                message_id,
                                posted_at: message.posted_at,
                                observations: Vec::new(),
                                raw_recent_custodian_count: 0,
                                trust_weighted_recent_count: 0.0,
                                last_observation_at: None,
                                last_walk_coverage_estimate: 0.0,
                                replication_health_score: 0.0,
                            });
                    }
                    OutgoingRecord::ServiceRequest(request) => {
                        // Disposable service-reply routes are process-local. A
                        // recovered request from a prior daemon process cannot
                        // safely receive replies, so remove it from the owned
                        // outbox; remote pointers expire on the short request TTL.
                        store.remove(&request.request_id);
                    }
                    OutgoingRecord::Withdrawal(withdrawal) => {
                        persistent.outgoing_messages.remove(&withdrawal.message_id);
                        persistent.awaiting_responses.remove(&withdrawal.message_id);
                        persistent.observation_reports.remove(&withdrawal.message_id);
                    }
                }
            }

            for message in persistent.outgoing_messages.values().cloned() {
                let key = message.message_id;
                if store.get(&key).is_none() {
                    store.upsert(OutgoingRecord::Message(message));
                }
            }
        }

        let mut response_store = CowPagedStore::load_owned(
            "mail_response",
            &init.dht_module,
            persistent.mail_response_package,
            &init.config,
        )
        .await?;
        for response in migrated_response_entries {
            response_store.upsert(response);
        }

        let mut overflow_stores = HashMap::new();
        for (recipient, overflow) in persistent.overflow_records.clone() {
            if overflow.retired {
                continue;
            }
            match CowPagedStore::load_owned(
                format!("overflow:{recipient}"),
                &init.dht_module,
                overflow.package_index,
                &init.config,
            )
            .await
            {
                Ok(mut store) => {
                    if let Some(entries) = migrated_overflow_entries.remove(&recipient) {
                        for entry in entries {
                            store.upsert(entry);
                        }
                    }
                    overflow_stores.insert(recipient, store);
                }
                Err(error) => crate::teprintln!("[mailbox] overflow recovery failed: {error}"),
            }
        }

        let stored_quota = init
            .user_auth
            .read_user_encrypted::<MailboxQuotaState>(&init.user_session, MAILBOX_QUOTA_STORE_KEY)?
            .unwrap_or_default();
        let mut runtime = Self {
            veilid: init.veilid,
            dht: init.dht_module,
            main_dht_package: init.main_dht_package,
            own_main_dht,
            auth: init.user_auth,
            session: init.user_session,
            reputation: init.reputation,
            config: init.config,
            persistent,
            mailbox_store,
            outbox_store,
            response_store,
            overflow_stores,
            quota_state: MailboxQuotaState::default(),
            recently_decrypted: RecentlyDecryptedCache::new(),
            outgoing_service_requests: BTreeMap::new(),
            service_reply_routes: HashMap::new(),
            recent_service_requests: BTreeMap::new(),
            last_walk_report: None,
        };

        let migrated_layout = runtime
            .mailbox_store
            .as_ref()
            .is_some_and(|store| store.pending_changes() > 0)
            || runtime
                .outbox_store
                .as_ref()
                .is_some_and(|store| store.pending_changes() > 0)
            || runtime.response_store.pending_changes() > 0
            || runtime
                .overflow_stores
                .values()
                .any(|store| store.pending_changes() > 0);
        if migrated_layout {
            let (migration_events, _) = broadcast::channel(1);
            runtime.flush_pending_writes(&migration_events).await?;
            crate::tprintln!(
                "[mailbox] completed migration to the 64-subkey size-safe mailbox layout"
            );
        }

        // If a process stopped after an overflow generation committed but
        // before its parent mailbox index committed, the DHT generations are
        // both valid but the parent's count/digest is stale. Repair the parent
        // from the owned, validated overflow generation before rebuilding
        // enforcement counters.
        if runtime.reconcile_overflow_parent_metadata().await? {
            crate::teprintln!(
                "[mailbox] repaired mailbox overflow metadata after an interrupted cross-record commit"
            );
        }
        let rebuilt_quota =
            MailboxQuotaState::rebuild(runtime.mailbox_store.as_ref(), &runtime.overflow_stores);
        if stored_quota.version == MAILBOX_QUOTA_STATE_VERSION
            && stored_quota.generation != 0
            && !stored_quota.same_counts(&rebuilt_quota)
        {
            crate::teprintln!(
                "[mailbox] repaired persisted quota counters from validated DHT page generations"
            );
        }
        runtime.quota_state = rebuilt_quota;
        runtime.persist().await?;
        runtime.publish_advertisement(None).await?;
        Ok(runtime)
    }

    async fn reconcile_overflow_parent_metadata(&mut self) -> Result<bool, MailboxError> {
        let entries = match self.mailbox_store.as_ref() {
            Some(store) => store.all_entries(),
            None => return Ok(false),
        };
        let mut changed = false;
        for mut entry in entries {
            let recipient = entry.recipient_main_dht.to_string();
            let RecipientSourceStorage::Overflow {
                record_key,
                overflow_epoch,
                entry_count,
                serialized_size,
                digest,
                ..
            } = &mut entry.storage
            else {
                continue;
            };
            let Some(local) = self.persistent.overflow_records.get(&recipient) else {
                continue;
            };
            if local.record_key != *record_key || local.overflow_epoch != *overflow_epoch {
                continue;
            }
            let Some(store) = self.overflow_stores.get(&recipient) else {
                continue;
            };
            let entries = store.all_entries();
            let encoded = serialize(&entries)?;
            let expected_count = entries.len().min(u32::MAX as usize) as u32;
            let expected_size = encoded.len().min(u32::MAX as usize) as u32;
            let expected_digest = hash_bytes(&encoded);
            if *entry_count == expected_count
                && *serialized_size == expected_size
                && *digest == expected_digest
            {
                continue;
            }
            *entry_count = expected_count;
            *serialized_size = expected_size;
            *digest = expected_digest;
            if let Some(mailbox_store) = self.mailbox_store.as_mut() {
                mailbox_store.upsert(entry);
            }
            changed = true;
        }

        if changed {
            if let Some(mailbox_store) = self.mailbox_store.as_mut() {
                mailbox_store
                    .commit(
                        &self.dht,
                        &self.config,
                        &mut self.persistent.pending_transactions,
                        &self.auth,
                        &self.session,
                    )
                    .await?;
            }
        }
        Ok(changed)
    }

    fn persist_local_only(&self) -> Result<(), MailboxError> {
        self.auth
            .write_user_encrypted(&self.session, MAILBOX_STORE_KEY, &self.persistent)?;
        self.auth.write_user_encrypted(
            &self.session,
            MAILBOX_QUOTA_STORE_KEY,
            &self.quota_state,
        )?;
        persist_transaction_log(
            &self.auth,
            &self.session,
            &self.persistent.pending_transactions,
        )?;
        Ok(())
    }

    async fn persist(&self) -> Result<(), MailboxError> {
        self.persist_local_only()?;
        let snapshot = self.dht.export_snapshot().await;
        crate::user_dht::persist_dht_snapshot(&self.auth, &self.session, &snapshot)?;
        Ok(())
    }

    async fn public_snapshot(&self) -> Result<MailboxPublicSnapshot, MailboxError> {
        Ok(MailboxPublicSnapshot {
            status: self.status().await?,
            inbox: self.inbox_summaries(),
            service_requests: self.recent_service_requests.values().cloned().collect(),
            observation_reports: self.persistent.observation_reports.values().cloned().collect(),
        })
    }

    fn pending_page_sets(&self) -> usize {
        self.mailbox_store
            .as_ref()
            .map_or(0, CowPagedStore::pending_changes)
            + self.outbox_store.as_ref().map_or(0, CowPagedStore::pending_changes)
            + self.response_store.pending_changes()
            + self
                .overflow_stores
                .values()
                .map(CowPagedStore::pending_changes)
                .sum::<usize>()
    }

    async fn refresh_public_snapshot(
        &self,
        snapshot: &Arc<RwLock<MailboxPublicSnapshot>>,
    ) -> Result<(), MailboxError> {
        *snapshot.write().await = self.public_snapshot().await?;
        Ok(())
    }

    async fn status(&self) -> Result<MailboxStatus, MailboxError> {
        let mailbox_dht = match self.persistent.mailbox_package {
            Some(package) => Some(self.dht.package_id_to_key(package).await?),
            None => None,
        };
        let mail_send_dht = match self.persistent.mail_send_package {
            Some(package) => Some(self.dht.package_id_to_key(package).await?),
            None => None,
        };
        let mail_response_dht = self
            .dht
            .package_id_to_key(self.persistent.mail_response_package)
            .await?;
        Ok(MailboxStatus {
            mailbox_dht,
            mail_send_dht,
            mail_response_dht,
            receive_key_epoch: self.persistent.receive_key_epoch,
            pending_page_sets: self
                .mailbox_store
                .as_ref()
                .map_or(0, CowPagedStore::pending_changes)
                + self
                    .outbox_store
                    .as_ref()
                    .map_or(0, CowPagedStore::pending_changes)
                + self.response_store.pending_changes()
                + self
                    .overflow_stores
                    .values()
                    .map(CowPagedStore::pending_changes)
                    .sum::<usize>(),
            outgoing_message_count: self.persistent.outgoing_messages.len(),
            outgoing_service_request_count: self.outgoing_service_requests.len(),
            recent_service_request_count: self.recent_service_requests.len(),
            awaiting_response_count: self.persistent.awaiting_responses.len(),
            stored_inbox_count: self.persistent.inbox_messages.len(),
            unread_inbox_count: self
                .persistent
                .inbox_messages
                .values()
                .filter(|message| !message.read)
                .count(),
            known_custodian_count: self.persistent.mailbox_peers.len(),
        })
    }

    fn inbox_summaries(&self) -> Vec<MailboxInboxSummary> {
        let mut messages: Vec<_> = self
            .persistent
            .inbox_messages
            .values()
            .map(|message| MailboxInboxSummary {
                message_id: message.message_id,
                sender_main_dht: message.sender_main_dht.clone(),
                application_id: message.application_id.clone(),
                posted_at: message.posted_at,
                received_at: message.received_at,
                plaintext_len: message.plaintext.len(),
                read: message.read,
            })
            .collect();
        messages.sort_by(|left, right| right.received_at.cmp(&left.received_at));
        messages
    }

    async fn read_inbox_message(
        &mut self,
        message_id: [u8; 32],
    ) -> Result<MailboxInboxMessage, MailboxError> {
        let result = {
            let stored = self
                .persistent
                .inbox_messages
                .get_mut(&message_id)
                .ok_or(MailboxError::MessageNotFound)?;
            stored.read = true;
            MailboxInboxMessage {
                message_id: stored.message_id,
                sender_main_dht: stored.sender_main_dht.clone(),
                recipient_main_dht: stored.recipient_main_dht.clone(),
                application_id: stored.application_id.clone(),
                posted_at: stored.posted_at,
                received_at: stored.received_at,
                expires_at: stored.expires_at,
                conversation_id: stored.conversation_id,
                plaintext: stored.plaintext.clone(),
                read: true,
            }
        };
        self.persist().await?;
        Ok(result)
    }

    async fn delete_inbox_message(&mut self, message_id: [u8; 32]) -> Result<(), MailboxError> {
        self.persistent
            .inbox_messages
            .remove(&message_id)
            .ok_or(MailboxError::MessageNotFound)?;
        self.persist().await
    }

    async fn advertisement(&self) -> Result<MailboxAdvertisement, MailboxError> {
        let mailbox_dht = match self.persistent.mailbox_package {
            Some(package) => Some(self.dht.package_id_to_key(package).await?),
            None => None,
        };
        let mail_send_dht = match self.persistent.mail_send_package {
            Some(package) => Some(self.dht.package_id_to_key(package).await?),
            None => None,
        };
        let mail_response_dht = self
            .dht
            .package_id_to_key(self.persistent.mail_response_package)
            .await?;
        let (signing_public, _signing_secret) =
            self.persistent.mail_signing_keypair.clone().into_split();
        let mut previous_receive_keys: Vec<_> = self
            .persistent
            .receive_key_versions
            .iter()
            .filter(|version| version.epoch != self.persistent.receive_key_epoch)
            .cloned()
            .collect();
        previous_receive_keys.sort_by(|a, b| b.epoch.cmp(&a.epoch));
        previous_receive_keys.truncate(self.config.advertised_previous_key_epochs);

        let mut suggestions: Vec<_> = self
            .persistent
            .mailbox_peers
            .values()
            .filter_map(|peer| {
                Some(MailboxNavigationSuggestion {
                    custodian_main_dht: peer.node_main_dht.clone(),
                    custodian_mailbox_dht: peer.mailbox_dht.clone()?,
                    advertised_generation: peer.mailbox_generation.unwrap_or(0),
                    last_verified_at: peer.last_successful_read.unwrap_or(0),
                })
            })
            .collect();
        suggestions.sort_by(|a, b| {
            b.last_verified_at.cmp(&a.last_verified_at).then_with(|| {
                xor_distance_fraction(&self.own_main_dht, &a.custodian_main_dht)
                    .partial_cmp(&xor_distance_fraction(
                        &self.own_main_dht,
                        &b.custodian_main_dht,
                    ))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        suggestions.truncate(self.config.max_navigation_suggestions);

        let current = self
            .persistent
            .receive_key_versions
            .iter()
            .find(|version| version.epoch == self.persistent.receive_key_epoch)
            .ok_or(MailboxError::ReceiveKeyUnavailable(
                self.persistent.receive_key_epoch,
            ))?;
        Ok(MailboxAdvertisement {
            version: MAILBOX_PROTOCOL_VERSION,
            custodian_mailbox_dht: mailbox_dht,
            mail_send_dht,
            mail_response_dht,
            receive_status: self.persistent.receive_status.clone(),
            current_receive_public_key: current.public_key.clone(),
            receive_key_epoch: current.epoch,
            current_receive_key_valid_from: current.valid_from,
            previous_receive_keys,
            mailbox_signing_public_key: signing_public,
            retention_region: Some(crate::types::MailboxRegionHint {
                center: self.own_main_dht.clone(),
                preferred_prefix_bits: self.config.receive_region_prefix_bits,
            }),
            mailbox_generation: self
                .mailbox_store
                .as_ref()
                .map_or(0, CowPagedStore::generation),
            advertisement_updated_at: current_timestamp(),
            navigation_suggestions: suggestions
                .into_iter()
                .map(|suggestion| crate::types::MailboxNavigationSuggestion {
                    custodian_main_dht: suggestion.custodian_main_dht,
                    custodian_mailbox_dht: suggestion.custodian_mailbox_dht,
                    advertised_generation: suggestion.advertised_generation,
                    last_verified_at: suggestion.last_verified_at,
                })
                .collect(),
            migration: None,
        })
    }

    async fn publish_advertisement(
        &self,
        events: Option<&broadcast::Sender<MailboxEvent>>,
    ) -> Result<(), MailboxError> {
        let advertisement = self.advertisement().await?;
        self.dht
            .write_to_dht(
                self.main_dht_package,
                MAILBOX_ADVERTISEMENT_LOCATION,
                serialize(&advertisement)?,
            )
            .await?;
        if let Some(events) = events {
            let _ = events.send(MailboxEvent::MailboxAdvertisementChanged(advertisement));
        }
        Ok(())
    }
}

fn mailbox_command_name(command: &MailboxCommand) -> &'static str {
    match command {
        MailboxCommand::WalkNodeObserved(_) => "WalkNodeObserved",
        MailboxCommand::WalkCompleted(_) => "WalkCompleted",
        MailboxCommand::SubmitOutgoingMessage { .. } => "SubmitOutgoingMessage",
        MailboxCommand::PublishServiceRequest { .. } => "PublishServiceRequest",
        MailboxCommand::WithdrawServiceRequest { .. } => "WithdrawServiceRequest",
        MailboxCommand::WithdrawOutgoingMessage { .. } => "WithdrawOutgoingMessage",
        MailboxCommand::BumpOutgoingMessage { .. } => "BumpOutgoingMessage",
        MailboxCommand::PublishResponse { .. } => "PublishResponse",
        MailboxCommand::RotateReceiveKey { .. } => "RotateReceiveKey",
        MailboxCommand::SetReceiveStatus { .. } => "SetReceiveStatus",
        MailboxCommand::RetrieveOurMail => "RetrieveOurMail",
        MailboxCommand::CheckPendingResponses => "CheckPendingResponses",
        MailboxCommand::RunMaintenance => "RunMaintenance",
        MailboxCommand::FlushPendingWrites { .. } => "FlushPendingWrites",
        MailboxCommand::RepairMailbox { .. } => "RepairMailbox",
        MailboxCommand::GetStatus { .. } => "GetStatus",
        MailboxCommand::ListInbox { .. } => "ListInbox",
        MailboxCommand::ReadInbox { .. } => "ReadInbox",
        MailboxCommand::DeleteInbox { .. } => "DeleteInbox",
        MailboxCommand::Shutdown { .. } => "Shutdown",
    }
}

async fn wait_for_mailbox_shutdown_signal(shutdown_rx: &mut watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

async fn mailbox_actor(
    mut rx: mpsc::Receiver<MailboxCommand>,
    shutdown_rx: watch::Receiver<bool>,
    mut runtime: MailboxRuntime,
    events: broadcast::Sender<MailboxEvent>,
    snapshot: Arc<RwLock<MailboxPublicSnapshot>>,
) {
    let mut batch_interval = time::interval(Duration::from_secs(
        runtime.config.normal_batch_interval_secs.max(1),
    ));
    batch_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut maintenance_interval = time::interval(Duration::from_secs(
        runtime.config.maintenance_interval_secs.max(60),
    ));
    maintenance_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = batch_interval.tick() => {
                let batch_started = std::time::Instant::now();
                crate::shutdown_debug!("mailbox actor: BATCH TICK START pending={} queued_commands={}", runtime.pending_page_sets(), rx.len());
                let mut stop = shutdown_rx.clone();
                let interrupted = tokio::select! {
                    biased;
                    _ = wait_for_mailbox_shutdown_signal(&mut stop) => true,
                    _ = async {
                        if let Err(error) = runtime.flush_pending_writes(&events).await {
                            let _ = events.send(MailboxEvent::Warning(format!("mailbox batch flush failed: {error}")));
                        }
                        if let Err(error) = runtime.refresh_public_snapshot(&snapshot).await {
                            let _ = events.send(MailboxEvent::Warning(format!("mailbox snapshot refresh failed: {error}")));
                        }
                    } => false,
                };
                if interrupted {
                    crate::shutdown_debug!("mailbox actor: BATCH TICK INTERRUPTED by shutdown after {}ms", batch_started.elapsed().as_millis());
                } else {
                    crate::shutdown_debug!("mailbox actor: BATCH TICK END elapsed={}ms pending={} queued_commands={}", batch_started.elapsed().as_millis(), runtime.pending_page_sets(), rx.len());
                }
            }
            _ = maintenance_interval.tick() => {
                let maintenance_started = std::time::Instant::now();
                crate::shutdown_debug!("mailbox actor: MAINTENANCE START pending={} queued_commands={}", runtime.pending_page_sets(), rx.len());
                let mut stop = shutdown_rx.clone();
                let interrupted = tokio::select! {
                    biased;
                    _ = wait_for_mailbox_shutdown_signal(&mut stop) => true,
                    _ = async {
                        if let Err(error) = runtime.run_maintenance(&events).await {
                            let _ = events.send(MailboxEvent::Warning(format!("mailbox maintenance failed: {error}")));
                        }
                        if let Err(error) = runtime.refresh_public_snapshot(&snapshot).await {
                            let _ = events.send(MailboxEvent::Warning(format!("mailbox snapshot refresh failed: {error}")));
                        }
                    } => false,
                };
                if interrupted {
                    crate::shutdown_debug!("mailbox actor: MAINTENANCE INTERRUPTED by shutdown after {}ms", maintenance_started.elapsed().as_millis());
                } else {
                    crate::shutdown_debug!("mailbox actor: MAINTENANCE END elapsed={}ms pending={} queued_commands={}", maintenance_started.elapsed().as_millis(), runtime.pending_page_sets(), rx.len());
                }
            }
            command = rx.recv() => {
                let Some(command) = command else {
                    crate::shutdown_debug!("mailbox actor: command channel closed; final flush starting pending={}", runtime.pending_page_sets());
                    let _ = runtime.flush_for_shutdown(&events, "channel-close").await;
                    runtime.release_all_service_reply_routes();
                    crate::shutdown_debug!("mailbox actor: command channel closed; actor exiting");
                    return;
                };
                let command_name = mailbox_command_name(&command);
                let command_started = std::time::Instant::now();
                crate::shutdown_debug!("mailbox actor: COMMAND START name={} queued_behind={} pending={}", command_name, rx.len(), runtime.pending_page_sets());

                // Once shutdown has been requested, do not start stale queued
                // work ahead of the Shutdown command.  Dropping a queued
                // request also drops its reply sender, so any waiting caller
                // receives ChannelClosed rather than hanging indefinitely.
                if *shutdown_rx.borrow() && !matches!(&command, MailboxCommand::Shutdown { .. }) {
                    crate::shutdown_debug!(
                        "mailbox actor: COMMAND SKIPPED name={} because shutdown is pending",
                        command_name
                    );
                    continue;
                }

                match command {
                    MailboxCommand::WalkNodeObserved(event) => {
                        let mut stop = shutdown_rx.clone();
                        let result = tokio::select! {
                            biased;
                            _ = wait_for_mailbox_shutdown_signal(&mut stop) => {
                                crate::shutdown_debug!(
                                    "mailbox actor: WalkNodeObserved INTERRUPTED by shutdown after {}ms; dropping in-flight mailbox DHT work",
                                    command_started.elapsed().as_millis()
                                );
                                None
                            }
                            result = runtime.process_walk_observation(event, &events) => Some(result),
                        };
                        if let Some(Err(error)) = result {
                            let _ = events.send(MailboxEvent::Warning(format!("walk mailbox observation failed: {error}")));
                        }
                    }
                    MailboxCommand::WalkCompleted(report) => {
                        runtime.last_walk_report = Some(report);
                    }
                    MailboxCommand::SubmitOutgoingMessage { request, reply } => {
                        let result = runtime.submit_outgoing_message(request, &events).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::PublishServiceRequest { request, reply } => {
                        let result = runtime.publish_service_request(request, &events).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::WithdrawServiceRequest { request_id, reply } => {
                        let result = runtime.withdraw_service_request(request_id).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::WithdrawOutgoingMessage { message_id, reply } => {
                        let result = runtime.withdraw_message(message_id).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::BumpOutgoingMessage { message_id, reply } => {
                        let result = runtime.bump_message(message_id).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::PublishResponse { response, reply } => {
                        let result = runtime.publish_response(response).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::RotateReceiveKey { revoke_previous, reply } => {
                        let result = runtime.rotate_receive_key(revoke_previous, &events).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::SetReceiveStatus { status, reply } => {
                        runtime.persistent.receive_status = status;
                        let result = async {
                            runtime.persist().await?;
                            runtime.publish_advertisement(Some(&events)).await
                        }.await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::RetrieveOurMail => {
                        let _ = events.send(MailboxEvent::RequestWalk(
                            MailboxWalkRequest::RetrieveOurMail,
                        ));
                    }
                    MailboxCommand::CheckPendingResponses => {
                        if let Err(error) = runtime.check_due_responses(&events).await {
                            let _ = events.send(MailboxEvent::Warning(format!("response check failed: {error}")));
                        }
                    }
                    MailboxCommand::RunMaintenance => {
                        if let Err(error) = runtime.run_maintenance(&events).await {
                            let _ = events.send(MailboxEvent::Warning(format!("maintenance failed: {error}")));
                        }
                    }
                    MailboxCommand::FlushPendingWrites { reply } => {
                        let result = runtime.flush_pending_writes(&events).await;
                        if let Some(reply) = reply { let _ = reply.send(result); }
                    }
                    MailboxCommand::RepairMailbox { reply } => {
                        let result = runtime.repair_stores(&events).await;
                        let _ = reply.send(result);
                    }
                    MailboxCommand::GetStatus { reply } => {
                        let _ = reply.send(runtime.status().await);
                    }
                    MailboxCommand::ListInbox { reply } => {
                        let _ = reply.send(Ok(runtime.inbox_summaries()));
                    }
                    MailboxCommand::ReadInbox { message_id, reply } => {
                        let _ = reply.send(runtime.read_inbox_message(message_id).await);
                    }
                    MailboxCommand::DeleteInbox { message_id, reply } => {
                        let _ = reply.send(runtime.delete_inbox_message(message_id).await);
                    }
                    MailboxCommand::Shutdown { reply } => {
                        crate::shutdown_debug!(
                            "mailbox actor: SHUTDOWN received after queue drain; queued_remaining={} pending={} command_elapsed={}ms",
                            rx.len(),
                            runtime.pending_page_sets(),
                            command_started.elapsed().as_millis()
                        );
                        let flush_started = std::time::Instant::now();
                        let result = runtime.flush_for_shutdown(&events, "shutdown").await;
                        crate::shutdown_debug!(
                            "mailbox actor: shutdown flush returned after {}ms result={}",
                            flush_started.elapsed().as_millis(),
                            if result.is_ok() { "Ok" } else { "Err" }
                        );
                        runtime.release_all_service_reply_routes();
                        crate::shutdown_debug!("mailbox actor: service reply routes released; sending shutdown acknowledgement");
                        let _ = reply.send(result);
                        crate::shutdown_debug!("mailbox actor: shutdown acknowledgement sent; actor exiting");
                        return;
                    }
                }

                crate::shutdown_debug!(
                    "mailbox actor: COMMAND END name={} elapsed={}ms pending={} queued_commands={}",
                    command_name,
                    command_started.elapsed().as_millis(),
                    runtime.pending_page_sets(),
                    rx.len()
                );

                // Do not start the actor's normal post-command flush/snapshot
                // work after shutdown has been signalled.  The queued Shutdown
                // command owns the final traced flush and should run next.
                if *shutdown_rx.borrow() {
                    crate::shutdown_debug!(
                        "mailbox actor: post-command maintenance skipped because shutdown is pending"
                    );
                    continue;
                }

                let pending = runtime.mailbox_store.as_ref().map_or(0, CowPagedStore::pending_changes)
                    + runtime.outbox_store.as_ref().map_or(0, CowPagedStore::pending_changes)
                    + runtime.response_store.pending_changes();
                if pending >= runtime.config.early_flush_queue_size {
                    if let Err(error) = runtime.flush_pending_writes(&events).await {
                        let _ = events.send(MailboxEvent::Warning(format!("early mailbox flush failed: {error}")));
                    }
                }
                if let Err(error) = runtime.refresh_public_snapshot(&snapshot).await {
                    let _ = events.send(MailboxEvent::Warning(format!("mailbox snapshot refresh failed: {error}")));
                }
            }
        }
    }
}

#[cfg(test)]
mod recently_decrypted_tests {
    use super::*;

    #[test]
    fn replay_cache_expires_old_ids() {
        let mut cache = RecentlyDecryptedCache::new();
        let id = [7u8; 32];
        cache.insert(id, 100);
        assert!(cache.contains(&id, 100));
        assert!(!cache.contains(&id, 100 + RECENTLY_DECRYPTED_TTL_SECS + 1));
    }

    #[test]
    fn replay_cache_enforces_capacity() {
        let mut cache = RecentlyDecryptedCache::new();
        for index in 0..=RECENTLY_DECRYPTED_MAX_ENTRIES {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(index as u64).to_le_bytes());
            cache.insert(id, 100);
        }
        assert_eq!(cache.entries.len(), RECENTLY_DECRYPTED_MAX_ENTRIES);
    }
}

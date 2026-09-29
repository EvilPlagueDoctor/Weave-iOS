// Page keys and canonical digests
// ============================================================================

trait PageEntry: Clone + Serialize + DeserializeOwned + Send + Sync + 'static {
    fn page_key(&self) -> Vec<u8>;
}

impl PageEntry for MailboxRecipientEntry {
    fn page_key(&self) -> Vec<u8> {
        full_record_key_bytes(&self.recipient_main_dht)
    }
}

impl PageEntry for OutgoingRecord {
    fn page_key(&self) -> Vec<u8> {
        match self {
            Self::Message(message) => message.message_id.to_vec(),
            Self::ServiceRequest(request) => request.request_id.to_vec(),
            Self::Withdrawal(withdrawal) => withdrawal.message_id.to_vec(),
        }
    }
}

impl PageEntry for MailResponse {
    fn page_key(&self) -> Vec<u8> {
        self.response_id.to_vec()
    }
}

impl PageEntry for MailSourcePointer {
    fn page_key(&self) -> Vec<u8> {
        self.message_id.to_vec()
    }
}

fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, MailboxError> {
    bincode::serialize(value).map_err(|error| MailboxError::Serialize(error.to_string()))
}

fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, MailboxError> {
    crate::network_decode::decode_bincode_limited(
        bytes,
        crate::network_decode::MAX_NETWORK_DHT_VALUE_BYTES,
    )
    .map_err(|error| MailboxError::Serialize(error.to_string()))
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn estimated_dht_value_limit(total_subkeys: u32) -> usize {
    // Veilid's record-value budget is approximately 1 MiB divided across the
    // schema's subkeys. Keep a fixed safety margin for schema and encoding
    // overhead rather than writing at the theoretical edge.
    const RECORD_VALUE_BUDGET: usize = 1_048_576;
    const SAFETY_MARGIN: usize = 512;

    let subkeys = total_subkeys.max(1) as usize;
    (RECORD_VALUE_BUDGET / subkeys)
        .saturating_sub(SAFETY_MARGIN)
        .max(256)
}

fn page_digest<T: Serialize + Clone>(page: &CowDataPage<T>) -> Result<[u8; 32], MailboxError> {
    let mut unsigned = page.clone();
    unsigned.digest = [0; 32];
    Ok(hash_bytes(&serialize(&unsigned)?))
}

fn index_digest(index: &CowIndex) -> Result<[u8; 32], MailboxError> {
    let mut unsigned = index.clone();
    unsigned.digest = [0; 32];
    Ok(hash_bytes(&serialize(&unsigned)?))
}

fn full_record_key_bytes(key: &RecordKey) -> Vec<u8> {
    let text = key.to_string();
    let mut parts = text.splitn(3, ':');
    let _ = parts.next();
    if let Some(encoded) = parts.next() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        if let Ok(bytes) = URL_SAFE_NO_PAD.decode(encoded) {
            return bytes;
        }
    }
    text.into_bytes()
}

fn xor_distance_fraction(a: &RecordKey, b: &RecordKey) -> f32 {
    let a = full_record_key_bytes(a);
    let b = full_record_key_bytes(b);
    let mut top = [0u8; 8];
    for (index, slot) in top.iter_mut().enumerate() {
        let av = a.get(index).copied().unwrap_or(0);
        let bv = b.get(index).copied().unwrap_or(0);
        *slot = av ^ bv;
    }
    u64::from_be_bytes(top) as f32 / u64::MAX as f32
}

// ============================================================================
// Copy-on-write paged store
// ============================================================================

#[derive(Clone)]
struct LocalPage<T> {
    descriptor: Option<CowPageDescriptor>,
    entries: Vec<T>,
    dirty: bool,
}

struct CowPagedStore<T> {
    name: String,
    package_index: usize,
    total_subkeys: u32,
    active_index_slot: u32,
    current_index: Option<CowIndex>,
    previous_index: Option<CowIndex>,
    pages: Vec<LocalPage<T>>,
}

impl<T: PageEntry> CowPagedStore<T> {
    async fn load_owned(
        name: impl Into<String>,
        dht: &DHTModule,
        package_index: usize,
        config: &MailboxConfig,
    ) -> Result<Self, MailboxError> {
        let name = name.into();
        let package = dht
            .get_dht_info(package_index)
            .await
            .ok_or_else(|| MailboxError::Dht(format!("package {package_index} not found")))?;
        let total_subkeys = package.total_subkeys();

        // The A/B index slots are independent.  Read them together so a sick
        // DHT costs at most one operation timeout here instead of two serial
        // 45-second stalls before the mailbox can decide how to recover.
        let (slot_a, slot_b) = tokio::join!(
            dht.read_from_dht(package_index, INDEX_SLOT_A, true),
            dht.read_from_dht(package_index, INDEX_SLOT_B, true),
        );

        let mut candidates = Vec::new();
        for (slot, result) in [(INDEX_SLOT_A, slot_a), (INDEX_SLOT_B, slot_b)] {
            match result {
                Ok(bytes) => {
                    if let Ok(index) = deserialize::<CowIndex>(&bytes) {
                        if validate_index_shape(&index).is_ok()
                            && index_digest(&index).ok() == Some(index.digest)
                        {
                            candidates.push((slot, index));
                        }
                    }
                }
                Err(CreateDhtError::NotFound) => {}
                Err(error) => crate::teprintln!("[mailbox] could not read {name:?} index slot {slot}: {error:?}"),
            }
        }

        candidates.sort_by(|a, b| b.1.generation.cmp(&a.1.generation));
        let mut chosen: Option<(u32, CowIndex, Vec<LocalPage<T>>)> = None;
        let mut older_valid = None;

        for (slot, index) in candidates {
            match load_and_validate_owned_pages::<T>(dht, package_index, &index, config).await {
                Ok(pages) if chosen.is_none() => chosen = Some((slot, index, pages)),
                Ok(_) if older_valid.is_none() => older_valid = Some(index),
                Ok(_) => {}
                Err(error) => crate::teprintln!("[mailbox] ignoring invalid {name:?} index generation {}: {error}", index.generation),
            }
        }

        let (active_index_slot, current_index, pages) = match chosen {
            Some((slot, index, pages)) => (slot, Some(index), pages),
            None => (
                INDEX_SLOT_A,
                None,
                vec![LocalPage {
                    descriptor: None,
                    entries: Vec::new(),
                    dirty: false,
                }],
            ),
        };

        Ok(Self {
            name,
            package_index,
            total_subkeys,
            active_index_slot,
            current_index,
            previous_index: older_valid,
            pages,
        })
    }

    fn generation(&self) -> u64 {
        self.current_index.as_ref().map_or(0, |index| index.generation)
    }

    fn all_entries(&self) -> Vec<T> {
        self.pages
            .iter()
            .flat_map(|page| page.entries.iter().cloned())
            .collect()
    }

    fn pending_changes(&self) -> usize {
        self.pages.iter().filter(|page| page.dirty).count()
    }

    fn upsert(&mut self, entry: T) {
        let key = entry.page_key();
        let page_index = self.find_page_index(&key);
        let page = &mut self.pages[page_index];
        match page
            .entries
            .binary_search_by(|existing| existing.page_key().cmp(&key))
        {
            Ok(index) => page.entries[index] = entry,
            Err(index) => page.entries.insert(index, entry),
        }
        page.dirty = true;
    }

    fn remove(&mut self, key: &[u8]) -> Option<T> {
        let page_index = self.find_page_index(key);
        let page = &mut self.pages[page_index];
        let index = page
            .entries
            .binary_search_by(|existing| existing.page_key().as_slice().cmp(key))
            .ok()?;
        page.dirty = true;
        Some(page.entries.remove(index))
    }

    fn get(&self, key: &[u8]) -> Option<&T> {
        let page_index = self.find_page_index(key);
        let page = &self.pages[page_index];
        let index = page
            .entries
            .binary_search_by(|existing| existing.page_key().as_slice().cmp(key))
            .ok()?;
        page.entries.get(index)
    }

    fn find_page_index(&self, key: &[u8]) -> usize {
        if self.pages.len() <= 1 {
            return 0;
        }
        for (index, page) in self.pages.iter().enumerate() {
            let Some(descriptor) = &page.descriptor else {
                return index;
            };
            if key <= descriptor.last_key.as_slice() {
                return index;
            }
        }
        self.pages.len() - 1
    }

    async fn commit(
        &mut self,
        dht: &DHTModule,
        config: &MailboxConfig,
        transactions: &mut Vec<PendingCowTransaction>,
        auth: &UserAuth,
        session: &UserSession,
    ) -> Result<bool, MailboxError> {
        self.commit_inner(dht, config, transactions, auth, session, None)
            .await
    }

    async fn commit_shutdown_traced(
        &mut self,
        dht: &DHTModule,
        config: &MailboxConfig,
        transactions: &mut Vec<PendingCowTransaction>,
        auth: &UserAuth,
        session: &UserSession,
        context: &'static str,
    ) -> Result<bool, MailboxError> {
        self.commit_inner(dht, config, transactions, auth, session, Some(context))
            .await
    }

    async fn commit_inner(
        &mut self,
        dht: &DHTModule,
        config: &MailboxConfig,
        transactions: &mut Vec<PendingCowTransaction>,
        auth: &UserAuth,
        session: &UserSession,
        trace_context: Option<&'static str>,
    ) -> Result<bool, MailboxError> {
        let pending_before = self.pending_changes();
        if pending_before == 0 {
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox commit[{context}]: store={} SKIP no pending pages", self.name);
            }
            return Ok(false);
        }

        let commit_started = std::time::Instant::now();
        if let Some(context) = trace_context {
            crate::shutdown_debug!(
                "mailbox commit[{context}]: store={} START package={} pending_pages={} current_generation={}",
                self.name,
                self.package_index,
                pending_before,
                self.generation()
            );
        }

        self.rebalance_dirty_pages(config)?;
        let dht_value_limit = estimated_dht_value_limit(self.total_subkeys);
        let page_value_limit = config.page_split_threshold.min(dht_value_limit);
        let next_generation = self.generation().saturating_add(1).max(1);
        let referenced_current: HashSet<u32> = self
            .current_index
            .iter()
            .flat_map(|index| index.pages.iter().map(|page| page.subkey))
            .collect();
        let referenced_previous: HashSet<u32> = self
            .previous_index
            .iter()
            .flat_map(|index| index.pages.iter().map(|page| page.subkey))
            .collect();

        let mut unavailable = referenced_current;
        unavailable.extend(referenced_previous);
        let mut free_subkeys = (FIRST_DATA_SUBKEY..self.total_subkeys)
            .filter(|subkey| !unavailable.contains(subkey));

        let mut new_pages = Vec::with_capacity(self.pages.len());
        let mut page_writes = Vec::new();
        for page in &self.pages {
            if !page.dirty {
                let descriptor = page.descriptor.clone().ok_or_else(|| {
                    MailboxError::StoreCorrupt("clean page has no descriptor".to_string())
                })?;
                new_pages.push(descriptor);
                continue;
            }

            let subkey = free_subkeys.next().ok_or(MailboxError::NoFreePageSubkey)?;
            let mut wire_page = CowDataPage {
                version: MAILBOX_PROTOCOL_VERSION,
                generation: next_generation,
                entries: page.entries.clone(),
                digest: [0; 32],
            };
            wire_page.digest = page_digest(&wire_page)?;
            let bytes = serialize(&wire_page)?;
            if bytes.len() > page_value_limit {
                return Err(MailboxError::StoreCorrupt(format!(
                    "page remains {} bytes after splitting; this {}-subkey DHT safely permits about {} bytes per value",
                    bytes.len(),
                    self.total_subkeys,
                    page_value_limit,
                )));
            }
            let first_key = wire_page
                .entries
                .first()
                .map(PageEntry::page_key)
                .unwrap_or_default();
            let last_key = wire_page
                .entries
                .last()
                .map(PageEntry::page_key)
                .unwrap_or_default();
            let descriptor = CowPageDescriptor {
                subkey,
                first_key,
                last_key,
                generation: next_generation,
                entry_count: wire_page.entries.len() as u32,
                serialized_size: bytes.len() as u32,
                digest: wire_page.digest,
            };
            new_pages.push(descriptor.clone());
            page_writes.push((descriptor, bytes));
        }

        new_pages.sort_by(|a, b| a.first_key.cmp(&b.first_key));
        let target_slot = if self.active_index_slot == INDEX_SLOT_A {
            INDEX_SLOT_B
        } else {
            INDEX_SLOT_A
        };
        transactions.push(PendingCowTransaction {
            store_name: self.name.clone(),
            package_index: self.package_index,
            generation: next_generation,
            target_index_slot: target_slot,
            new_page_subkeys: page_writes.iter().map(|(descriptor, _)| descriptor.subkey).collect(),
            started_at: current_timestamp(),
        });
        // Persist advisory transaction metadata before any page becomes visible.
        // Startup still trusts only fully validated A/B generations, but this
        // log makes orphan inspection and interrupted-write diagnostics exact.
        persist_transaction_log(auth, session, transactions)?;
        if let Some(context) = trace_context {
            crate::shutdown_debug!(
                "mailbox commit[{context}]: store={} transaction recorded; page_writes={} target_index_slot={} generation={}",
                self.name,
                page_writes.len(),
                target_slot,
                next_generation
            );
        }

        let page_write_started = std::time::Instant::now();
        if let Some(context) = trace_context {
            crate::shutdown_debug!(
                "mailbox commit[{context}]: store={} PAGE WRITES START count={} concurrency={}",
                self.name,
                page_writes.len(),
                config.dht_io_concurrency.max(1)
            );
        }
        let writes = stream::iter(page_writes.clone().into_iter().map(|(descriptor, bytes)| {
            let dht = dht.clone();
            let package = self.package_index;
            async move {
                dht.write_to_dht(package, descriptor.subkey, bytes)
                    .await
                    .map_err(MailboxError::from)?;
                Ok::<_, MailboxError>(descriptor)
            }
        }))
        .buffer_unordered(config.dht_io_concurrency.max(1))
        .collect::<Vec<_>>()
        .await;
        for result in writes {
            result?;
        }
        if let Some(context) = trace_context {
            crate::shutdown_debug!(
                "mailbox commit[{context}]: store={} PAGE WRITES END elapsed={}ms",
                self.name,
                page_write_started.elapsed().as_millis()
            );
        }

        // Read back every newly written page before making it reachable.
        let page_readback_started = std::time::Instant::now();
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox commit[{context}]: store={} PAGE READBACK START count={}", self.name, page_writes.len());
        }
        for (descriptor, _) in &page_writes {
            let bytes = dht
                .read_from_dht(self.package_index, descriptor.subkey, true)
                .await?;
            let page: CowDataPage<T> = deserialize(&bytes)?;
            validate_page(&page, descriptor)?;
        }
        if let Some(context) = trace_context {
            crate::shutdown_debug!(
                "mailbox commit[{context}]: store={} PAGE READBACK END elapsed={}ms",
                self.name,
                page_readback_started.elapsed().as_millis()
            );
        }

        let mut index = CowIndex {
            version: MAILBOX_PROTOCOL_VERSION,
            generation: next_generation,
            previous_generation: self.current_index.as_ref().map(|index| index.generation),
            created_at: current_timestamp(),
            pages: new_pages,
            digest: [0; 32],
        };
        index.digest = index_digest(&index)?;
        let index_bytes = serialize(&index)?;
        if index_bytes.len() > dht_value_limit {
            return Err(MailboxError::StoreCorrupt(format!(
                "index is {} bytes; this {}-subkey DHT safely permits about {} bytes per value and needs another segment",
                index_bytes.len(),
                self.total_subkeys,
                dht_value_limit,
            )));
        }
        let index_write_started = std::time::Instant::now();
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox commit[{context}]: store={} INDEX WRITE START slot={} bytes={}", self.name, target_slot, index_bytes.len());
        }
        dht.write_to_dht(self.package_index, target_slot, index_bytes)
            .await?;
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox commit[{context}]: store={} INDEX WRITE END elapsed={}ms", self.name, index_write_started.elapsed().as_millis());
        }

        let index_read_started = std::time::Instant::now();
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox commit[{context}]: store={} INDEX READBACK START slot={}", self.name, target_slot);
        }
        let readback = dht
            .read_from_dht(self.package_index, target_slot, true)
            .await?;
        let readback_index: CowIndex = deserialize(&readback)?;
        if readback_index.digest != index.digest || index_digest(&readback_index)? != index.digest {
            return Err(MailboxError::StoreCorrupt(
                "index readback digest mismatch".to_string(),
            ));
        }
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox commit[{context}]: store={} INDEX READBACK END elapsed={}ms", self.name, index_read_started.elapsed().as_millis());
        }

        let validate_started = std::time::Instant::now();
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox commit[{context}]: store={} GENERATION VALIDATION START pages={}", self.name, readback_index.pages.len());
        }
        let verified_pages = load_and_validate_owned_pages::<T>(
            dht,
            self.package_index,
            &readback_index,
            config,
        )
        .await?;
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox commit[{context}]: store={} GENERATION VALIDATION END elapsed={}ms", self.name, validate_started.elapsed().as_millis());
        }

        self.previous_index = self.current_index.take();
        self.current_index = Some(readback_index);
        self.active_index_slot = target_slot;
        self.pages = verified_pages;
        transactions.retain(|transaction| {
            !(transaction.store_name == self.name && transaction.generation == next_generation)
        });
        persist_transaction_log(auth, session, transactions)?;
        if let Some(context) = trace_context {
            crate::shutdown_debug!(
                "mailbox commit[{context}]: store={} END total_elapsed={}ms new_generation={}",
                self.name,
                commit_started.elapsed().as_millis(),
                next_generation
            );
        }
        Ok(true)
    }

    fn rebalance_dirty_pages(&mut self, config: &MailboxConfig) -> Result<(), MailboxError> {
        let mut rebuilt = Vec::new();
        for mut page in self.pages.drain(..) {
            page.entries.sort_by_key(PageEntry::page_key);
            if !page.dirty || serialized_page_size(&page.entries)? <= config.page_split_threshold {
                rebuilt.push(page);
                continue;
            }

            let mut pending = vec![page.entries];
            while let Some(entries) = pending.pop() {
                if entries.len() <= 1 || serialized_page_size(&entries)? <= config.page_target_size {
                    rebuilt.push(LocalPage {
                        descriptor: None,
                        entries,
                        dirty: true,
                    });
                    continue;
                }
                let midpoint = entries.len() / 2;
                let right = entries[midpoint..].to_vec();
                let left = entries[..midpoint].to_vec();
                pending.push(right);
                pending.push(left);
            }
        }
        rebuilt.sort_by(|a, b| {
            let a = a.entries.first().map(PageEntry::page_key).unwrap_or_default();
            let b = b.entries.first().map(PageEntry::page_key).unwrap_or_default();
            a.cmp(&b)
        });
        self.pages = rebuilt;
        Ok(())
    }
}

fn serialized_page_size<T: Serialize + Clone>(entries: &[T]) -> Result<usize, MailboxError> {
    let mut page = CowDataPage {
        version: MAILBOX_PROTOCOL_VERSION,
        generation: 0,
        entries: entries.to_vec(),
        digest: [0; 32],
    };
    page.digest = page_digest(&page)?;
    Ok(serialize(&page)?.len())
}

fn validate_index_shape(index: &CowIndex) -> Result<(), MailboxError> {
    if index.version != MAILBOX_PROTOCOL_VERSION {
        return Err(MailboxError::StoreCorrupt(format!(
            "unsupported index version {}",
            index.version
        )));
    }
    let mut previous_last: Option<&[u8]> = None;
    for descriptor in &index.pages {
        if descriptor.subkey < FIRST_DATA_SUBKEY || descriptor.first_key > descriptor.last_key {
            return Err(MailboxError::StoreCorrupt("invalid page range".to_string()));
        }
        if let Some(last) = previous_last {
            if last >= descriptor.first_key.as_slice() {
                return Err(MailboxError::StoreCorrupt(
                    "overlapping or unsorted page ranges".to_string(),
                ));
            }
        }
        previous_last = Some(&descriptor.last_key);
    }
    Ok(())
}

fn validate_page<T: PageEntry>(
    page: &CowDataPage<T>,
    descriptor: &CowPageDescriptor,
) -> Result<(), MailboxError> {
    if page.version != MAILBOX_PROTOCOL_VERSION
        || page.generation != descriptor.generation
        || page.entries.len() as u32 != descriptor.entry_count
        || page.digest != descriptor.digest
        || page_digest(page)? != descriptor.digest
    {
        return Err(MailboxError::StoreCorrupt(format!(
            "page {} metadata or digest mismatch",
            descriptor.subkey
        )));
    }
    let mut previous: Option<Vec<u8>> = None;
    for entry in &page.entries {
        let key = entry.page_key();
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(MailboxError::StoreCorrupt(format!(
                "page {} is not strictly sorted",
                descriptor.subkey
            )));
        }
        previous = Some(key);
    }
    let first = page.entries.first().map(PageEntry::page_key).unwrap_or_default();
    let last = page.entries.last().map(PageEntry::page_key).unwrap_or_default();
    if first != descriptor.first_key || last != descriptor.last_key {
        return Err(MailboxError::StoreCorrupt(format!(
            "page {} key range mismatch",
            descriptor.subkey
        )));
    }
    Ok(())
}

async fn load_and_validate_owned_pages<T: PageEntry>(
    dht: &DHTModule,
    package_index: usize,
    index: &CowIndex,
    config: &MailboxConfig,
) -> Result<Vec<LocalPage<T>>, MailboxError> {
    validate_index_shape(index)?;
    let results = stream::iter(index.pages.clone().into_iter().map(|descriptor| {
        let dht = dht.clone();
        async move {
            let bytes = dht
                .read_from_dht(package_index, descriptor.subkey, true)
                .await?;
            if bytes.len() != descriptor.serialized_size as usize {
                return Err(MailboxError::StoreCorrupt(format!(
                    "page {} serialized-size mismatch",
                    descriptor.subkey
                )));
            }
            let page: CowDataPage<T> = deserialize(&bytes)?;
            validate_page(&page, &descriptor)?;
            Ok::<_, MailboxError>(LocalPage {
                descriptor: Some(descriptor),
                entries: page.entries,
                dirty: false,
            })
        }
    }))
    .buffer_unordered(config.dht_io_concurrency.max(1))
    .collect::<Vec<_>>()
    .await;

    let mut pages = Vec::with_capacity(results.len().max(1));
    for result in results {
        pages.push(result?);
    }
    pages.sort_by(|a, b| {
        let a = a.descriptor.as_ref().map(|d| &d.first_key);
        let b = b.descriptor.as_ref().map(|d| &d.first_key);
        a.cmp(&b)
    });
    if pages.is_empty() {
        pages.push(LocalPage {
            descriptor: None,
            entries: Vec::new(),
            dirty: false,
        });
    }
    Ok(pages)
}

async fn read_foreign_store<T: PageEntry>(
    dht: &DHTModule,
    record_key: &RecordKey,
    maximum_pages: usize,
    _config: &MailboxConfig,
) -> Result<(CowIndex, Vec<T>), MailboxError> {
    let total_started = std::time::Instant::now();
    let entry_type = std::any::type_name::<T>();
    crate::mailbox_walk_debug!(
        "FOREIGN_STORE START type={} dht={} max_pages={}",
        entry_type,
        record_key,
        maximum_pages
    );

    let index_started = std::time::Instant::now();
    let index_reads = dht
        .read_foreign_subkeys(
            record_key.clone(),
            vec![INDEX_SLOT_A, INDEX_SLOT_B],
            true,
        )
        .await?;
    crate::mailbox_walk_debug!(
        "FOREIGN_STORE INDEX_READ END type={} dht={} elapsed={}ms returned_subkeys={}",
        entry_type,
        record_key,
        index_started.elapsed().as_millis(),
        index_reads.len()
    );

    let mut indexes = Vec::new();
    for (_, result) in index_reads {
        let Ok(bytes) = result else { continue };
        let Ok(index) = deserialize::<CowIndex>(&bytes) else { continue };
        if validate_index_shape(&index).is_ok() && index_digest(&index).ok() == Some(index.digest) {
            indexes.push(index);
        }
    }
    indexes.sort_by(|a, b| b.generation.cmp(&a.generation));
    crate::mailbox_walk_debug!(
        "FOREIGN_STORE INDEX_VALIDATE type={} dht={} valid_generations={} candidates={:?}",
        entry_type,
        record_key,
        indexes.len(),
        indexes.iter().map(|index| (index.generation, index.pages.len())).collect::<Vec<_>>()
    );

    for index in indexes {
        if index.pages.len() > maximum_pages {
            crate::mailbox_walk_debug!(
                "FOREIGN_STORE GENERATION SKIP type={} dht={} generation={} pages={} reason=over-max-pages",
                entry_type,
                record_key,
                index.generation,
                index.pages.len()
            );
            continue;
        }
        let locations: Vec<u32> = index.pages.iter().map(|page| page.subkey).collect();
        let page_started = std::time::Instant::now();
        crate::mailbox_walk_debug!(
            "FOREIGN_STORE PAGE_READ START type={} dht={} generation={} pages={} subkeys={:?}",
            entry_type,
            record_key,
            index.generation,
            locations.len(),
            locations
        );
        let reads = dht
            .read_foreign_subkeys(record_key.clone(), locations, true)
            .await?;
        crate::mailbox_walk_debug!(
            "FOREIGN_STORE PAGE_READ END type={} dht={} generation={} elapsed={}ms returned_subkeys={}",
            entry_type,
            record_key,
            index.generation,
            page_started.elapsed().as_millis(),
            reads.len()
        );
        let by_subkey: HashMap<u32, Result<Vec<u8>, CreateDhtError>> = reads.into_iter().collect();
        let validate_started = std::time::Instant::now();
        let mut entries = Vec::new();
        let mut valid = true;
        for descriptor in &index.pages {
            let Some(Ok(bytes)) = by_subkey.get(&descriptor.subkey) else {
                valid = false;
                break;
            };
            if bytes.len() != descriptor.serialized_size as usize {
                valid = false;
                break;
            }
            let Ok(page) = deserialize::<CowDataPage<T>>(bytes) else {
                valid = false;
                break;
            };
            if validate_page(&page, descriptor).is_err() {
                valid = false;
                break;
            }
            entries.extend(page.entries);
        }
        crate::mailbox_walk_debug!(
            "FOREIGN_STORE PAGE_VALIDATE type={} dht={} generation={} elapsed={}ms valid={} entries={}",
            entry_type,
            record_key,
            index.generation,
            validate_started.elapsed().as_millis(),
            valid,
            entries.len()
        );
        if valid {
            crate::mailbox_walk_debug!(
                "FOREIGN_STORE END type={} dht={} generation={} entries={} total_elapsed={}ms",
                entry_type,
                record_key,
                index.generation,
                entries.len(),
                total_started.elapsed().as_millis()
            );
            return Ok((index, entries));
        }
    }

    crate::mailbox_walk_debug!(
        "FOREIGN_STORE FAIL type={} dht={} total_elapsed={}ms reason=no-valid-generation",
        entry_type,
        record_key,
        total_started.elapsed().as_millis()
    );
    Err(MailboxError::StoreCorrupt(format!(
        "no completely valid index generation for {record_key}"
    )))
}

// ============================================================================

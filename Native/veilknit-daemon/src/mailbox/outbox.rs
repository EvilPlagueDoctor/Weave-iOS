impl MailboxRuntime {
    async fn ensure_outbox(&mut self) -> Result<(), MailboxError> {
        if self.outbox_store.is_some() {
            return Ok(());
        }
        let package = self
            .dht
            .create_dht(MAILSEND_DHT_NAME.to_string(), PAGED_DHT_GROUPS.to_vec())
            .await?;
        self.persistent.mail_send_package = Some(package);
        self.outbox_store =
            Some(CowPagedStore::load_owned("mail_send", &self.dht, package, &self.config).await?);
        self.persist().await?;
        self.publish_advertisement(None).await?;
        Ok(())
    }

    async fn submit_outgoing_message(
        &mut self,
        request: OutgoingMessageRequest,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<[u8; 32], MailboxError> {
        if request.plaintext.len() > self.config.max_plaintext_size {
            return Err(MailboxError::PlaintextTooLarge {
                actual: request.plaintext.len(),
                maximum: self.config.max_plaintext_size,
            });
        }
        if request.application_id.trim().is_empty() || request.application_id.len() > 256 {
            return Err(MailboxError::InvalidMessage(
                "application id is empty or too long".to_string(),
            ));
        }

        self.enforce_outgoing_quotas(&request.recipient_main_dht)?;
        let advertisement = self
            .read_mailbox_advertisement(&request.recipient_main_dht)
            .await?;
        let now = current_timestamp();
        if !advertisement.receive_status.permits_new_message(now) {
            return Err(MailboxError::RecipientNotAccepting);
        }

        let requested_expiry = request
            .expires_at
            .unwrap_or_else(|| now.saturating_add(30 * 24 * 60 * 60));
        let expires_at = requested_expiry
            .min(now.saturating_add(self.config.max_requested_expiry_secs))
            .max(now.saturating_add(60));
        let envelope = EncryptedApplicationEnvelope {
            version: MAILBOX_PROTOCOL_VERSION,
            application_id: request.application_id,
            sent_at: now,
            payload: request.plaintext,
        };
        let (ephemeral_public, ciphertext) = encrypt_envelope(
            &envelope,
            &advertisement.current_receive_public_key,
            &self.own_main_dht,
            &request.recipient_main_dht,
            advertisement.receive_key_epoch,
        )?;
        let mut message_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut message_nonce);
        let message_id = calculate_message_id(
            &self.own_main_dht,
            &request.recipient_main_dht,
            now,
            &message_nonce,
            &ciphertext,
        );
        let mut message = OutgoingMessage {
            version: MAILBOX_PROTOCOL_VERSION,
            message_id,
            sender_main_dht: self.own_main_dht.clone(),
            recipient_main_dht: request.recipient_main_dht.clone(),
            receive_key_epoch: advertisement.receive_key_epoch,
            sender_ephemeral_public_key: ephemeral_public,
            message_nonce,
            ciphertext,
            posted_at: now,
            bumped_at: now,
            expires_at,
            conversation_id: request.conversation_id,
            proposed_conversation_dht: request.proposed_conversation_dht,
            signature: Vec::new(),
            bump_signature: Vec::new(),
        };
        message.signature = sign_bytes(
            &self.veilid,
            &self.persistent.mail_signing_keypair,
            &immutable_message_bytes(&message)?,
        )?;
        message.bump_signature = sign_bytes(
            &self.veilid,
            &self.persistent.mail_signing_keypair,
            &bump_bytes(message.message_id, message.bumped_at)?,
        )?;

        let wire_size = serialize(&message)?.len();
        if wire_size > self.config.complete_message_max_size {
            return Err(MailboxError::MessageTooLarge {
                actual: wire_size,
                maximum: self.config.complete_message_max_size,
            });
        }

        // Validate the complete copy-on-write page envelope before mutating
        // local state. This converts future sizing regressions into a clear
        // local error instead of Veilid's generic schema-validation failure.
        let page_wire_size =
            serialized_page_size(&[OutgoingRecord::Message(message.clone())])?;
        let page_limit = self
            .config
            .page_split_threshold
            .min(estimated_dht_value_limit(PAGED_DHT_TOTAL_SUBKEYS));
        if page_wire_size > page_limit {
            return Err(MailboxError::MessageTooLarge {
                actual: page_wire_size,
                maximum: page_limit,
            });
        }

        self.ensure_outbox().await?;
        self.outbox_store
            .as_mut()
            .expect("outbox was just initialized")
            .upsert(OutgoingRecord::Message(message.clone()));
        self.persistent
            .outgoing_messages
            .insert(message_id, message.clone());
        self.persistent.observation_reports.insert(
            message_id,
            OutgoingMessageObservationReport {
                message_id,
                posted_at: now,
                observations: Vec::new(),
                raw_recent_custodian_count: 0,
                trust_weighted_recent_count: 0.0,
                last_observation_at: None,
                last_walk_coverage_estimate: 0.0,
                replication_health_score: 0.0,
            },
        );
        if request.await_response {
            self.persistent.awaiting_responses.insert(
                message_id,
                AwaitingResponse {
                    message_id,
                    conversation_id: message.conversation_id,
                    recipient_main_dht: message.recipient_main_dht.clone(),
                    recipient_response_dht: advertisement.mail_response_dht,
                    first_check_at: now.saturating_add(self.config.response_check_base_secs),
                    last_checked_at: None,
                    next_check_at: now.saturating_add(self.config.response_check_base_secs),
                    stop_checking_after: expires_at,
                    check_attempts: 0,
                },
            );
        }

        // Seed the sender's own custodian mailbox immediately. This gives every
        // outgoing message one discoverable pointer as soon as it is created,
        // instead of waiting for another node's walk to encounter MailSend.
        let mut self_seeded_pointer = None;
        if self.mailbox_store.is_some() {
            let mail_send_package = self
                .persistent
                .mail_send_package
                .ok_or(MailboxError::MessageNotFound)?;
            let mail_send_dht = self.dht.package_id_to_key(mail_send_package).await?;
            let pointer = MailSourcePointer {
                message_id,
                sender_main_dht: self.own_main_dht.clone(),
                mail_send_dht,
                posted_at: message.posted_at,
                bumped_at: message.bumped_at,
                requested_expires_at: message.expires_at,
                first_observed_at: now,
                last_observed_at: now,
                last_verified_at: now,
                failed_verification_count: 0,
            };
            self.add_pointer_to_custodian_mailbox(
                message.recipient_main_dht.clone(),
                pointer.clone(),
            )
            .await?;
            self_seeded_pointer = Some(pointer);
        }

        // Commit both MailSend and the self-seeded mailbox pointer before
        // returning, so the first copy is genuinely online immediately.
        self.flush_pending_writes(events).await?;
        if let Some(pointer) = self_seeded_pointer {
            let _ = events.send(MailboxEvent::OutgoingSeeded(pointer));
        }
        Ok(message_id)
    }

    async fn publish_service_request(
        &mut self,
        request: ServiceRequestPublishRequest,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<PublishedServiceRequest, MailboxError> {
        if request.public_payload.len() > self.config.max_service_payload_size {
            return Err(MailboxError::MessageTooLarge {
                actual: request.public_payload.len(),
                maximum: self.config.max_service_payload_size,
            });
        }
        self.enforce_service_request_quotas(&request.intended_host_main_dht)?;
        self.ensure_outbox().await?;

        let now = current_timestamp();
        let ttl_secs = request
            .ttl_secs
            .unwrap_or(self.config.default_service_request_ttl_secs)
            .clamp(60, self.config.max_service_request_ttl_secs.max(60));
        let expires_at = now.saturating_add(ttl_secs);

        let route = self
            .veilid
            .new_private_route()
            .await
            .map_err(|error| MailboxError::Dht(format!("temporary service reply route failed: {error}")))?;
        let route_id = route.route_id;
        let route_blob = route.blob;
        if route_blob.len() > self.config.max_service_reply_route_size {
            let _ = self.veilid.release_private_route(route_id);
            return Err(MailboxError::MessageTooLarge {
                actual: route_blob.len(),
                maximum: self.config.max_service_reply_route_size,
            });
        }

        let mut request_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut request_nonce);
        let request_id = calculate_service_request_id(
            &self.own_main_dht,
            &request.intended_host_main_dht,
            &request.service_id,
            &request.service_manifest_hash,
            &request.instance_id,
            &route_blob,
            &request.public_payload,
            request.delegation_allowed,
            request.spectators_allowed,
            now,
            expires_at,
            &request_nonce,
        );
        let mut service_request = ServiceRequest {
            version: MAILBOX_PROTOCOL_VERSION,
            request_id,
            requester_main_dht: self.own_main_dht.clone(),
            intended_host_main_dht: request.intended_host_main_dht,
            service_id: request.service_id,
            service_manifest_hash: request.service_manifest_hash,
            instance_id: request.instance_id,
            reply_route_blob: route_blob,
            public_payload: request.public_payload,
            delegation_allowed: request.delegation_allowed,
            spectators_allowed: request.spectators_allowed,
            posted_at: now,
            expires_at,
            request_nonce,
            signature: Vec::new(),
        };
        let signing_bytes = match immutable_service_request_bytes(&service_request) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = self.veilid.release_private_route(route_id);
                return Err(error);
            }
        };
        service_request.signature = match sign_bytes(
            &self.veilid,
            &self.persistent.mail_signing_keypair,
            &signing_bytes,
        ) {
            Ok(signature) => signature,
            Err(error) => {
                let _ = self.veilid.release_private_route(route_id);
                return Err(error);
            }
        };

        let wire_size = match serialize(&service_request) {
            Ok(bytes) => bytes.len(),
            Err(error) => {
                let _ = self.veilid.release_private_route(route_id);
                return Err(error);
            }
        };
        let page_wire_size = match serialized_page_size(&[OutgoingRecord::ServiceRequest(service_request.clone())]) {
            Ok(size) => size,
            Err(error) => {
                let _ = self.veilid.release_private_route(route_id);
                return Err(error);
            }
        };
        let page_limit = self
            .config
            .page_split_threshold
            .min(estimated_dht_value_limit(PAGED_DHT_TOTAL_SUBKEYS));
        if wire_size > self.config.max_service_request_size || page_wire_size > page_limit {
            let _ = self.veilid.release_private_route(route_id);
            return Err(MailboxError::MessageTooLarge {
                actual: wire_size.max(page_wire_size),
                maximum: self.config.max_service_request_size.min(page_limit),
            });
        }

        self.outbox_store
            .as_mut()
            .expect("outbox was just initialized")
            .upsert(OutgoingRecord::ServiceRequest(service_request.clone()));
        self.outgoing_service_requests
            .insert(request_id, service_request.clone());
        self.service_reply_routes.insert(request_id, route_id);
        self.record_verified_service_request(service_request.clone(), events);

        let mut self_seeded_pointer = None;
        if self.mailbox_store.is_some() {
            let mail_send_package = self
                .persistent
                .mail_send_package
                .ok_or(MailboxError::MessageNotFound)?;
            let mail_send_dht = self.dht.package_id_to_key(mail_send_package).await?;
            let pointer = MailSourcePointer {
                message_id: request_id,
                sender_main_dht: self.own_main_dht.clone(),
                mail_send_dht,
                posted_at: now,
                bumped_at: now,
                requested_expires_at: expires_at,
                first_observed_at: now,
                last_observed_at: now,
                last_verified_at: now,
                failed_verification_count: 0,
            };
            self.add_pointer_to_custodian_mailbox(
                service_request.intended_host_main_dht.clone(),
                pointer.clone(),
            )
            .await?;
            self_seeded_pointer = Some(pointer);
        }

        self.flush_pending_writes(events).await?;
        if let Some(pointer) = self_seeded_pointer {
            let _ = events.send(MailboxEvent::OutgoingSeeded(pointer));
        }
        Ok(PublishedServiceRequest {
            request_id,
            expires_at,
        })
    }

    fn release_all_service_reply_routes(&mut self) {
        for (_, route_id) in self.service_reply_routes.drain() {
            let _ = self.veilid.release_private_route(route_id);
        }
    }

    fn enforce_service_request_quotas(&self, host: &RecordKey) -> Result<(), MailboxError> {
        if self.outgoing_service_requests.len() >= self.config.active_service_requests_per_sender {
            return Err(MailboxError::QuotaExceeded("active service requests per sender"));
        }
        let host_count = self
            .outgoing_service_requests
            .values()
            .filter(|request| &request.intended_host_main_dht == host)
            .count();
        if host_count >= self.config.active_service_requests_per_host {
            return Err(MailboxError::QuotaExceeded("active service requests per host"));
        }
        Ok(())
    }

    fn enforce_outgoing_quotas(&self, recipient: &RecordKey) -> Result<(), MailboxError> {
        if self.persistent.outgoing_messages.len() >= self.config.active_messages_per_sender {
            return Err(MailboxError::QuotaExceeded("active messages per sender"));
        }
        let pair_count = self
            .persistent
            .outgoing_messages
            .values()
            .filter(|message| &message.recipient_main_dht == recipient)
            .count();
        if pair_count >= self.config.active_messages_per_sender_recipient {
            return Err(MailboxError::QuotaExceeded(
                "active messages per sender-recipient pair",
            ));
        }
        Ok(())
    }

    async fn bump_message(&mut self, message_id: [u8; 32]) -> Result<(), MailboxError> {
        let mut updated = self
            .persistent
            .outgoing_messages
            .get(&message_id)
            .cloned()
            .ok_or(MailboxError::MessageNotFound)?;
        let now = current_timestamp();
        if now
            < updated
                .bumped_at
                .saturating_add(self.config.minimum_bump_interval_secs)
        {
            return Err(MailboxError::QuotaExceeded("minimum bump interval"));
        }
        updated.bumped_at = now;
        updated.bump_signature = sign_bytes(
            &self.veilid,
            &self.persistent.mail_signing_keypair,
            &bump_bytes(message_id, now)?,
        )?;
        self.persistent
            .outgoing_messages
            .insert(message_id, updated.clone());
        self.outbox_store
            .as_mut()
            .ok_or(MailboxError::MessageNotFound)?
            .upsert(OutgoingRecord::Message(updated));
        self.persist().await
    }

    async fn withdraw_message(&mut self, message_id: [u8; 32]) -> Result<(), MailboxError> {
        let removed_message = self.persistent.outgoing_messages.remove(&message_id).is_some();
        let removed_service = self.outgoing_service_requests.remove(&message_id).is_some();
        if !removed_message && !removed_service {
            return Err(MailboxError::MessageNotFound);
        }
        if let Some(route_id) = self.service_reply_routes.remove(&message_id) {
            let _ = self.veilid.release_private_route(route_id);
        }
        self.recent_service_requests.remove(&message_id);
        let withdrawn_at = current_timestamp();
        let signature_bytes = serialize(&(
            MESSAGE_SIGNATURE_DOMAIN,
            b"withdrawal",
            message_id,
            self.own_main_dht.to_string(),
            withdrawn_at,
        ))?;
        let withdrawal = OutgoingWithdrawal {
            version: MAILBOX_PROTOCOL_VERSION,
            message_id,
            sender_main_dht: self.own_main_dht.clone(),
            withdrawn_at,
            signature: sign_bytes(
                &self.veilid,
                &self.persistent.mail_signing_keypair,
                &signature_bytes,
            )?,
        };
        self.outbox_store
            .as_mut()
            .ok_or(MailboxError::MessageNotFound)?
            .upsert(OutgoingRecord::Withdrawal(withdrawal));
        self.persistent.awaiting_responses.remove(&message_id);
        self.persistent.observation_reports.remove(&message_id);
        self.persist().await
    }

    async fn withdraw_service_request(&mut self, request_id: [u8; 32]) -> Result<(), MailboxError> {
        if !self.outgoing_service_requests.contains_key(&request_id) {
            return Err(MailboxError::MessageNotFound);
        }
        self.withdraw_message(request_id).await
    }

    async fn publish_response(
        &mut self,
        request: MailResponseRequest,
    ) -> Result<[u8; 32], MailboxError> {
        if request
            .ciphertext
            .as_ref()
            .is_some_and(|body| body.len() > 8 * 1024)
        {
            return Err(MailboxError::MessageTooLarge {
                actual: request.ciphertext.as_ref().map_or(0, Vec::len),
                maximum: 8 * 1024,
            });
        }
        let now = current_timestamp();
        let mut random = [0u8; 32];
        OsRng.fill_bytes(&mut random);
        let response_id = hash_bytes(&serialize(&(
            RESPONSE_SIGNATURE_DOMAIN,
            request.responding_to_message_id,
            self.own_main_dht.to_string(),
            request.original_sender_main_dht.to_string(),
            now,
            random,
        ))?);
        let mut response = MailResponse {
            version: MAILBOX_PROTOCOL_VERSION,
            response_id,
            responding_to_message_id: request.responding_to_message_id,
            conversation_id: request.conversation_id,
            responder_main_dht: self.own_main_dht.clone(),
            original_sender_main_dht: request.original_sender_main_dht,
            response_kind: request.response_kind,
            posted_at: now,
            ciphertext: request.ciphertext,
            published_conversation_dht: request.published_conversation_dht,
            signature: Vec::new(),
        };
        response.signature = sign_bytes(
            &self.veilid,
            &self.persistent.mail_signing_keypair,
            &response_signing_bytes(&response)?,
        )?;
        self.response_store.upsert(response);
        Ok(response_id)
    }

    async fn rotate_receive_key(
        &mut self,
        revoke_previous: bool,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<u64, MailboxError> {
        let now = current_timestamp();
        let previous_epoch = self.persistent.receive_key_epoch;
        let previous_status = if revoke_previous {
            self.persistent
                .revoked_receive_epochs
                .insert(previous_epoch);
            ReceiveKeyStatus::Revoked
        } else {
            ReceiveKeyStatus::Superseded
        };
        if let Some(previous) = self
            .persistent
            .receive_key_versions
            .iter_mut()
            .find(|version| version.epoch == previous_epoch)
        {
            previous.valid_until = Some(now);
            previous.status = previous_status;
        }
        let epoch = previous_epoch.saturating_add(1).max(1);
        self.persistent.receive_key_epoch = epoch;
        self.persistent
            .receive_key_versions
            .push(ReceiveKeyVersion {
                epoch,
                public_key: receive_public_key(&self.persistent.mailbox_master_secret, epoch),
                valid_from: now,
                valid_until: None,
                status: ReceiveKeyStatus::Current,
            });
        self.persist().await?;
        self.publish_advertisement(Some(events)).await?;
        Ok(epoch)
    }

    async fn flush_pending_writes(
        &mut self,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<(), MailboxError> {
        self.flush_pending_writes_inner(events, None).await
    }

    async fn flush_pending_writes_shutdown_traced(
        &mut self,
        events: &broadcast::Sender<MailboxEvent>,
        context: &'static str,
    ) -> Result<(), MailboxError> {
        self.flush_pending_writes_inner(events, Some(context)).await
    }

    /// Shutdown must remain bounded even when Veilid/DHT traffic is unhealthy.
    /// Try to publish pending COW pages for a short window, then fall back to
    /// the encrypted local mailbox state/transaction log.  Startup recovery is
    /// already designed to reconcile an interrupted COW generation.
    async fn flush_for_shutdown(
        &mut self,
        events: &broadcast::Sender<MailboxEvent>,
        context: &'static str,
    ) -> Result<(), MailboxError> {
        const NETWORK_FLUSH_BUDGET: Duration = Duration::from_secs(8);
        const SNAPSHOT_BUDGET: Duration = Duration::from_secs(2);

        match time::timeout(
            NETWORK_FLUSH_BUDGET,
            self.flush_pending_writes_shutdown_traced(events, context),
        )
        .await
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => {
                crate::teprintln!(
                    "[mailbox] shutdown network flush failed ({error}); saving local recovery state instead"
                );
                let _ = events.send(MailboxEvent::Warning(format!(
                    "shutdown network flush failed; local recovery state saved instead: {error}"
                )));
            }
            Err(_) => {
                crate::teprintln!(
                    "[mailbox] shutdown network flush exceeded {}s; saving local recovery state instead",
                    NETWORK_FLUSH_BUDGET.as_secs()
                );
                let _ = events.send(MailboxEvent::Warning(
                    "shutdown network flush timed out; local recovery state saved instead"
                        .to_string(),
                ));
            }
        }

        // These encrypted writes are local and are the important durability
        // boundary when the network itself is the thing that is failing.
        self.persist_local_only()?;

        // The DHT snapshot is actor-local metadata rather than a network
        // publish, but do not let a jammed DHT actor turn the fallback into a
        // second shutdown hang.  Missing this snapshot is recoverable from the
        // last good snapshot plus the encrypted mailbox transaction log.
        match time::timeout(SNAPSHOT_BUDGET, self.dht.export_snapshot()).await {
            Ok(snapshot) => {
                if let Err(error) = crate::user_dht::persist_dht_snapshot(
                    &self.auth,
                    &self.session,
                    &snapshot,
                ) {
                    crate::teprintln!(
                        "[mailbox] shutdown fallback could not refresh DHT snapshot: {error}"
                    );
                }
            }
            Err(_) => crate::teprintln!(
                "[mailbox] shutdown fallback skipped DHT snapshot after {}s; last good snapshot retained",
                SNAPSHOT_BUDGET.as_secs()
            ),
        }

        Ok(())
    }

    async fn flush_pending_writes_inner(
        &mut self,
        events: &broadcast::Sender<MailboxEvent>,
        trace_context: Option<&'static str>,
    ) -> Result<(), MailboxError> {
        let mut advertisement_changed = false;
        let flush_started = std::time::Instant::now();
        if let Some(context) = trace_context {
            crate::shutdown_debug!(
                "mailbox flush[{context}]: START pending_total={} overflow_stores={} mailbox_pending={} outbox_pending={} response_pending={}",
                self.pending_page_sets(),
                self.overflow_stores.len(),
                self.mailbox_store.as_ref().map_or(0, CowPagedStore::pending_changes),
                self.outbox_store.as_ref().map_or(0, CowPagedStore::pending_changes),
                self.response_store.pending_changes(),
            );
        }

        // Overflow records are the data side of the mailbox pointer. Commit
        // them first; the owning mailbox index/digest is published afterward.
        for store in self.overflow_stores.values_mut() {
            let pending = store.pending_changes();
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: overflow store={} START pending_pages={}", store.name, pending);
            }
            let started = std::time::Instant::now();
            if let Some(context) = trace_context {
                store
                    .commit_shutdown_traced(
                        &self.dht,
                        &self.config,
                        &mut self.persistent.pending_transactions,
                        &self.auth,
                        &self.session,
                        context,
                    )
                    .await?;
            } else {
                store
                    .commit(
                        &self.dht,
                        &self.config,
                        &mut self.persistent.pending_transactions,
                        &self.auth,
                        &self.session,
                    )
                    .await?;
            }
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: overflow store={} END elapsed={}ms", store.name, started.elapsed().as_millis());
            }
        }
        if let Some(store) = &mut self.mailbox_store {
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: mailbox store START pending_pages={}", store.pending_changes());
            }
            let started = std::time::Instant::now();
            let changed = if let Some(context) = trace_context {
                store
                    .commit_shutdown_traced(
                        &self.dht,
                        &self.config,
                        &mut self.persistent.pending_transactions,
                        &self.auth,
                        &self.session,
                        context,
                    )
                    .await?
            } else {
                store
                    .commit(
                        &self.dht,
                        &self.config,
                        &mut self.persistent.pending_transactions,
                        &self.auth,
                        &self.session,
                    )
                    .await?
            };
            advertisement_changed |= changed;
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: mailbox store END elapsed={}ms changed={}", started.elapsed().as_millis(), advertisement_changed);
            }
        }
        if let Some(store) = &mut self.outbox_store {
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: outbox store START pending_pages={}", store.pending_changes());
            }
            let started = std::time::Instant::now();
            let changed = if let Some(context) = trace_context {
                store
                    .commit_shutdown_traced(
                        &self.dht,
                        &self.config,
                        &mut self.persistent.pending_transactions,
                        &self.auth,
                        &self.session,
                        context,
                    )
                    .await?
            } else {
                store
                    .commit(
                        &self.dht,
                        &self.config,
                        &mut self.persistent.pending_transactions,
                        &self.auth,
                        &self.session,
                    )
                    .await?
            };
            advertisement_changed |= changed;
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: outbox store END elapsed={}ms changed={}", started.elapsed().as_millis(), changed);
            }
        }
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox flush[{context}]: response store START pending_pages={}", self.response_store.pending_changes());
        }
        let response_started = std::time::Instant::now();
        let response_changed = if let Some(context) = trace_context {
            self.response_store
                .commit_shutdown_traced(
                    &self.dht,
                    &self.config,
                    &mut self.persistent.pending_transactions,
                    &self.auth,
                    &self.session,
                    context,
                )
                .await?
        } else {
            self.response_store
                .commit(
                    &self.dht,
                    &self.config,
                    &mut self.persistent.pending_transactions,
                    &self.auth,
                    &self.session,
                )
                .await?
        };
        advertisement_changed |= response_changed;
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox flush[{context}]: response store END elapsed={}ms changed={}", response_started.elapsed().as_millis(), response_changed);
        }

        // Counters and DHT package metadata are persisted only after every
        // authoritative page/index generation above has committed.
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox flush[{context}]: encrypted local persistence START");
        }
        let persist_started = std::time::Instant::now();
        self.persist().await?;
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox flush[{context}]: encrypted local persistence END elapsed={}ms", persist_started.elapsed().as_millis());
        }
        if advertisement_changed {
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: advertisement publish START");
            }
            let advertisement_started = std::time::Instant::now();
            self.publish_advertisement(Some(events)).await?;
            if let Some(context) = trace_context {
                crate::shutdown_debug!("mailbox flush[{context}]: advertisement publish END elapsed={}ms", advertisement_started.elapsed().as_millis());
            }
        } else if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox flush[{context}]: advertisement unchanged; publish skipped");
        }
        if let Some(context) = trace_context {
            crate::shutdown_debug!("mailbox flush[{context}]: END total_elapsed={}ms", flush_started.elapsed().as_millis());
        }
        Ok(())
    }

    async fn repair_stores(
        &mut self,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<(), MailboxError> {
        self.mailbox_store = match self.persistent.mailbox_package {
            Some(package) => {
                Some(CowPagedStore::load_owned("mailbox", &self.dht, package, &self.config).await?)
            }
            None => None,
        };
        self.outbox_store = match self.persistent.mail_send_package {
            Some(package) => Some(
                CowPagedStore::load_owned("mail_send", &self.dht, package, &self.config).await?,
            ),
            None => None,
        };
        self.response_store = CowPagedStore::load_owned(
            "mail_response",
            &self.dht,
            self.persistent.mail_response_package,
            &self.config,
        )
        .await?;
        self.persistent.pending_transactions.clear();
        self.quota_state =
            MailboxQuotaState::rebuild(self.mailbox_store.as_ref(), &self.overflow_stores);
        self.persist().await?;
        self.publish_advertisement(Some(events)).await
    }

    async fn read_mailbox_advertisement(
        &self,
        main_dht: &RecordKey,
    ) -> Result<MailboxAdvertisement, MailboxError> {
        let started = std::time::Instant::now();
        crate::mailbox_walk_debug!(
            "ADVERTISEMENT_READ START main_dht={} subkey={}",
            main_dht,
            MAILBOX_ADVERTISEMENT_LOCATION
        );
        let bytes = self
            .dht
            .read_foreign_subkey(main_dht.clone(), MAILBOX_ADVERTISEMENT_LOCATION, true)
            .await?;
        crate::mailbox_walk_debug!(
            "ADVERTISEMENT_READ DHT_END main_dht={} elapsed={}ms bytes={}",
            main_dht,
            started.elapsed().as_millis(),
            bytes.len()
        );
        let advertisement: MailboxAdvertisement = deserialize(&bytes)?;
        validate_advertisement(&advertisement, &self.config)?;
        crate::mailbox_walk_debug!(
            "ADVERTISEMENT_READ END main_dht={} total_elapsed={}ms mail_send={} custodian_mailbox={}",
            main_dht,
            started.elapsed().as_millis(),
            advertisement.mail_send_dht.is_some(),
            advertisement.custodian_mailbox_dht.is_some()
        );
        Ok(advertisement)
    }

    fn retrieval_targets(&self) -> Vec<RecordKey> {
        let mut targets: Vec<_> = self
            .persistent
            .mailbox_peers
            .values()
            .filter(|peer| peer.stores_our_region || peer.overlaps_our_preferred_region)
            .map(|peer| peer.node_main_dht.clone())
            .collect();
        targets.sort_by(|a, b| {
            xor_distance_fraction(&self.own_main_dht, a)
                .partial_cmp(&xor_distance_fraction(&self.own_main_dht, b))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        targets.dedup();
        targets.truncate(64);
        targets
    }
}

fn response_signing_bytes(response: &MailResponse) -> Result<Vec<u8>, MailboxError> {
    serialize(&(
        RESPONSE_SIGNATURE_DOMAIN,
        response.version,
        response.response_id,
        response.responding_to_message_id,
        response.conversation_id,
        response.responder_main_dht.to_string(),
        response.original_sender_main_dht.to_string(),
        &response.response_kind,
        response.posted_at,
        response.ciphertext.as_ref().map(|body| hash_bytes(body)),
        response
            .published_conversation_dht
            .as_ref()
            .map(ToString::to_string),
    ))
}

fn validate_advertisement(
    advertisement: &MailboxAdvertisement,
    config: &MailboxConfig,
) -> Result<(), MailboxError> {
    if advertisement.version != MAILBOX_PROTOCOL_VERSION {
        return Err(MailboxError::InvalidAdvertisement(format!(
            "unsupported protocol version {}",
            advertisement.version
        )));
    }
    if advertisement.current_receive_public_key.len() != 32 {
        return Err(MailboxError::InvalidAdvertisement(
            "current receive key must be 32 bytes".to_string(),
        ));
    }
    if advertisement.navigation_suggestions.len() > config.max_navigation_suggestions * 4 {
        return Err(MailboxError::InvalidAdvertisement(
            "excessive navigation suggestions".to_string(),
        ));
    }
    Ok(())
}

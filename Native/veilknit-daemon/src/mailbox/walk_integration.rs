/// Convert a mailbox validation failure into reputation evidence.
///
/// `InvalidMessage` is a broad protocol/validation error and must not be
/// treated as proof of a bad cryptographic signature.  In particular, the old
/// code classified an otherwise valid but expired message as
/// `InvalidSignature`, allowing normal mailbox expiry to create permanent
/// automatic network bans.
fn mailbox_reputation_kind_for_rejection(error: &MailboxError) -> ObservationKind {
    match error {
        MailboxError::InvalidMessage(message)
            if message == "immutable message signature is invalid"
                || message == "bump signature is invalid" =>
        {
            ObservationKind::InvalidSignature
        }
        _ => ObservationKind::MessageRejected,
    }
}

impl MailboxRuntime {
    async fn process_walk_observation(
        &mut self,
        event: HopEvent,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<(), MailboxError> {
        let total_started = std::time::Instant::now();
        let target = event.snapshot.target.to_string();
        crate::mailbox_walk_debug!(
            "OBS START target={} hop={}/{} discovered_this_hop={} reachable={} own={} snapshot_values={}",
            target,
            event.hop_index + 1,
            event.requested_hops,
            event.discovered_this_hop,
            event.snapshot.is_reachable(),
            event.snapshot.target == self.own_main_dht,
            event.snapshot.values.len()
        );

        if !event.snapshot.is_reachable() || event.snapshot.target == self.own_main_dht {
            crate::mailbox_walk_debug!(
                "OBS END target={} elapsed={}ms reason=unreachable-or-self",
                target,
                total_started.elapsed().as_millis()
            );
            return Ok(());
        }
        let Some(bytes) = event.snapshot.get(MAILBOX_ADVERTISEMENT_LOCATION) else {
            crate::mailbox_walk_debug!(
                "OBS END target={} elapsed={}ms reason=no-mailbox-advertisement",
                target,
                total_started.elapsed().as_millis()
            );
            return Ok(());
        };

        let parse_started = std::time::Instant::now();
        let advertisement: MailboxAdvertisement = match deserialize(bytes) {
            Ok(value) => value,
            Err(error) => {
                crate::mailbox_walk_debug!(
                    "OBS PARSE FAIL target={} elapsed={}ms error={}",
                    target,
                    parse_started.elapsed().as_millis(),
                    error
                );
                self.submit_reputation(
                    event.snapshot.target.clone(),
                    ObservationKind::MalformedProtocolMessage,
                    format!("invalid mailbox advertisement: {error}"),
                );
                return Ok(());
            }
        };
        if let Err(error) = validate_advertisement(&advertisement, &self.config) {
            crate::mailbox_walk_debug!(
                "OBS VALIDATE FAIL target={} elapsed={}ms error={}",
                target,
                parse_started.elapsed().as_millis(),
                error
            );
            self.submit_reputation(
                event.snapshot.target.clone(),
                ObservationKind::MalformedProtocolMessage,
                error.to_string(),
            );
            return Ok(());
        }

        let awaiting_response = self
            .persistent
            .awaiting_responses
            .values()
            .any(|pending| pending.recipient_main_dht == event.snapshot.target);
        crate::mailbox_walk_debug!(
            "OBS ADVERTISEMENT target={} parse_validate={}ms mail_send={} custodian_mailbox={} awaiting_response={} nav_hints={} generation={}",
            target,
            parse_started.elapsed().as_millis(),
            advertisement.mail_send_dht.is_some(),
            advertisement.custodian_mailbox_dht.is_some(),
            awaiting_response,
            advertisement.navigation_suggestions.len(),
            advertisement.mailbox_generation
        );

        let local_started = std::time::Instant::now();
        self.record_peer_advertisement(&event.snapshot.target, &advertisement);
        self.accept_navigation_hints(&advertisement);
        crate::mailbox_walk_debug!(
            "OBS LOCAL target={} record-advertisement-and-hints={}ms",
            target,
            local_started.elapsed().as_millis()
        );

        if let Some(mail_send_dht) = &advertisement.mail_send_dht {
            let stage_started = std::time::Instant::now();
            crate::mailbox_walk_debug!(
                "OBS STAGE START target={} stage=sender-outbox dht={}",
                target,
                mail_send_dht
            );
            let result = self.observe_sender_outbox(
                &event.snapshot.target,
                &advertisement,
                mail_send_dht,
                events,
            ).await;
            crate::mailbox_walk_debug!(
                "OBS STAGE END target={} stage=sender-outbox elapsed={}ms result={}",
                target,
                stage_started.elapsed().as_millis(),
                if result.is_ok() { "Ok" } else { "Err" }
            );
            result?;
        }
        if let Some(mailbox_dht) = &advertisement.custodian_mailbox_dht {
            let stage_started = std::time::Instant::now();
            crate::mailbox_walk_debug!(
                "OBS STAGE START target={} stage=custodian-mailbox dht={} advertised_generation={}",
                target,
                mailbox_dht,
                advertisement.mailbox_generation
            );
            let result = self.observe_custodian_mailbox(
                &event.snapshot.target,
                mailbox_dht,
                advertisement.mailbox_generation,
                events,
            ).await;
            crate::mailbox_walk_debug!(
                "OBS STAGE END target={} stage=custodian-mailbox elapsed={}ms result={}",
                target,
                stage_started.elapsed().as_millis(),
                if result.is_ok() { "Ok" } else { "Err" }
            );
            result?;
        }
        if awaiting_response {
            let stage_started = std::time::Instant::now();
            crate::mailbox_walk_debug!(
                "OBS STAGE START target={} stage=response-dht dht={}",
                target,
                advertisement.mail_response_dht
            );
            let result = self.observe_response_dht(&event.snapshot.target, &advertisement, events)
                .await;
            crate::mailbox_walk_debug!(
                "OBS STAGE END target={} stage=response-dht elapsed={}ms result={}",
                target,
                stage_started.elapsed().as_millis(),
                if result.is_ok() { "Ok" } else { "Err" }
            );
            result?;
        }

        crate::mailbox_walk_debug!(
            "OBS END target={} total_elapsed={}ms",
            target,
            total_started.elapsed().as_millis()
        );
        Ok(())
    }

    fn record_peer_advertisement(
        &mut self,
        node: &RecordKey,
        advertisement: &MailboxAdvertisement,
    ) {
        let now = current_timestamp();
        let stores_our_region = advertisement
            .retention_region
            .as_ref()
            .is_some_and(|region| {
                xor_distance_fraction(&region.center, &self.own_main_dht)
                    <= prefix_bits_to_distance(region.preferred_prefix_bits)
            });
        let entry = self
            .persistent
            .mailbox_peers
            .entry(node.to_string())
            .or_insert_with(|| MailboxPeerState {
                node_main_dht: node.clone(),
                mailbox_dht: None,
                advertised_region: None,
                last_advertisement_seen: now,
                last_mailbox_update_seen: None,
                last_successful_read: None,
                mailbox_generation: None,
                stores_our_region,
                overlaps_our_preferred_region: stores_our_region,
                stale_since: None,
            });
        if entry.mailbox_generation != Some(advertisement.mailbox_generation) {
            entry.last_mailbox_update_seen = Some(now);
        }
        entry.mailbox_dht = advertisement.custodian_mailbox_dht.clone();
        entry.advertised_region =
            advertisement
                .retention_region
                .as_ref()
                .map(|region| MailboxRegionHint {
                    center: region.center.clone(),
                    preferred_prefix_bits: region.preferred_prefix_bits,
                });
        entry.last_advertisement_seen = now;
        entry.mailbox_generation = Some(advertisement.mailbox_generation);
        entry.stores_our_region = stores_our_region;
        entry.overlaps_our_preferred_region = stores_our_region;
    }

    fn accept_navigation_hints(&mut self, advertisement: &MailboxAdvertisement) {
        let now = current_timestamp();
        for suggestion in advertisement
            .navigation_suggestions
            .iter()
            .take(self.config.max_navigation_suggestions)
        {
            self.persistent
                .mailbox_peers
                .entry(suggestion.custodian_main_dht.to_string())
                .or_insert_with(|| MailboxPeerState {
                    node_main_dht: suggestion.custodian_main_dht.clone(),
                    mailbox_dht: Some(suggestion.custodian_mailbox_dht.clone()),
                    advertised_region: None,
                    last_advertisement_seen: now,
                    last_mailbox_update_seen: None,
                    last_successful_read: None,
                    mailbox_generation: Some(suggestion.advertised_generation),
                    stores_our_region: false,
                    overlaps_our_preferred_region: false,
                    stale_since: None,
                });
        }
    }

    async fn observe_sender_outbox(
        &mut self,
        sender_main_dht: &RecordKey,
        sender_advertisement: &MailboxAdvertisement,
        mail_send_dht: &RecordKey,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<(), MailboxError> {
        let total_started = std::time::Instant::now();
        crate::mailbox_walk_debug!(
            "SENDER START sender={} mail_send_dht={}",
            sender_main_dht,
            mail_send_dht
        );

        let reputation_started = std::time::Instant::now();
        let access = match self.reputation.get_view(sender_main_dht.clone()).await {
            Ok(view) => view.network_access,
            Err(_) => AccessLevel::Allowed,
        };
        crate::mailbox_walk_debug!(
            "SENDER reputation sender={} elapsed={}ms access={:?}",
            sender_main_dht,
            reputation_started.elapsed().as_millis(),
            access
        );
        if access == AccessLevel::Blocked {
            crate::mailbox_walk_debug!(
                "SENDER END sender={} total_elapsed={}ms reason=blocked",
                sender_main_dht,
                total_started.elapsed().as_millis()
            );
            return Ok(());
        }

        let read_started = std::time::Instant::now();
        crate::mailbox_walk_debug!(
            "SENDER foreign-store START sender={} dht={} max_pages={}",
            sender_main_dht,
            mail_send_dht,
            self.config.mailsend_pages_per_walk
        );
        let (_, records) = match read_foreign_store::<OutgoingRecord>(
            &self.dht,
            mail_send_dht,
            self.config.mailsend_pages_per_walk,
            &self.config,
        )
        .await
        {
            Ok(value) => value,
            Err(error) => {
                crate::mailbox_walk_debug!(
                    "SENDER foreign-store FAIL sender={} elapsed={}ms error={}",
                    sender_main_dht,
                    read_started.elapsed().as_millis(),
                    error
                );
                self.submit_reputation(
                    sender_main_dht.clone(),
                    ObservationKind::InvalidDhtResponse,
                    format!("advertised MailSend DHT could not be validated: {error}"),
                );
                return Ok(());
            }
        };
        let message_count = records.iter().filter(|record| matches!(record, OutgoingRecord::Message(_))).count();
        let withdrawal_count = records.iter().filter(|record| matches!(record, OutgoingRecord::Withdrawal(_))).count();
        let service_count = records.iter().filter(|record| matches!(record, OutgoingRecord::ServiceRequest(_))).count();
        crate::mailbox_walk_debug!(
            "SENDER foreign-store END sender={} elapsed={}ms records={} messages={} withdrawals={} services={}",
            sender_main_dht,
            read_started.elapsed().as_millis(),
            records.len(),
            message_count,
            withdrawal_count,
            service_count
        );

        let withdrawal_started = std::time::Instant::now();
        let withdrawals: HashSet<[u8; 32]> = records
            .iter()
            .filter_map(|record| match record {
                OutgoingRecord::Withdrawal(withdrawal) => Some(withdrawal.message_id),
                _ => None,
            })
            .collect();
        let mut verified_withdrawals = 0usize;
        for withdrawal in records.iter().filter_map(|record| match record {
            OutgoingRecord::Withdrawal(withdrawal) => Some(withdrawal),
            _ => None,
        }) {
            if self
                .verify_withdrawal(withdrawal, sender_advertisement)
                .unwrap_or(false)
            {
                verified_withdrawals += 1;
                self.recent_service_requests.remove(&withdrawal.message_id);
                self.remove_pointer_everywhere(withdrawal.message_id)
                    .await?;
            }
        }
        crate::mailbox_walk_debug!(
            "SENDER withdrawals sender={} elapsed={}ms seen={} verified={}",
            sender_main_dht,
            withdrawal_started.elapsed().as_millis(),
            withdrawal_count,
            verified_withdrawals
        );

        let messages_started = std::time::Instant::now();
        let mut processed = 0usize;
        let mut accepted_messages = 0usize;
        let mut rejected_messages = 0usize;
        for message in records.iter().filter_map(|record| match record {
            OutgoingRecord::Message(message) => Some(message.clone()),
            _ => None,
        }) {
            if processed >= self.config.candidate_messages_per_walk {
                break;
            }
            processed += 1;
            if withdrawals.contains(&message.message_id) {
                crate::mailbox_walk_debug!(
                    "SENDER message SKIP sender={} candidate={} reason=withdrawn",
                    sender_main_dht,
                    processed
                );
                continue;
            }
            let candidate_started = std::time::Instant::now();
            crate::mailbox_walk_debug!(
                "SENDER message START sender={} candidate={} recipient={}",
                sender_main_dht,
                processed,
                message.recipient_main_dht
            );
            match self
                .validate_candidate_message(
                    sender_main_dht,
                    sender_advertisement,
                    mail_send_dht,
                    &message,
                )
                .await
            {
                Ok(recipient_advertisement) => {
                    let validate_elapsed = candidate_started.elapsed().as_millis();
                    crate::mailbox_walk_debug!(
                        "SENDER message VALID sender={} candidate={} elapsed={}ms; accepting pointer",
                        sender_main_dht,
                        processed,
                        validate_elapsed
                    );
                    self.accept_valid_message_pointer(
                        mail_send_dht,
                        &message,
                        &recipient_advertisement,
                        events,
                    )
                    .await?;
                    accepted_messages += 1;
                    crate::mailbox_walk_debug!(
                        "SENDER message END sender={} candidate={} total_elapsed={}ms result=accepted",
                        sender_main_dht,
                        processed,
                        candidate_started.elapsed().as_millis()
                    );
                }
                Err(error) => {
                    rejected_messages += 1;
                    crate::mailbox_walk_debug!(
                        "SENDER message END sender={} candidate={} total_elapsed={}ms result=rejected error={}",
                        sender_main_dht,
                        processed,
                        candidate_started.elapsed().as_millis(),
                        error
                    );
                    self.submit_reputation(
                        sender_main_dht.clone(),
                        mailbox_reputation_kind_for_rejection(&error),
                        error.to_string(),
                    );
                }
            }
        }
        crate::mailbox_walk_debug!(
            "SENDER messages END sender={} elapsed={}ms processed={} accepted={} rejected={} configured_limit={}",
            sender_main_dht,
            messages_started.elapsed().as_millis(),
            processed,
            accepted_messages,
            rejected_messages,
            self.config.candidate_messages_per_walk
        );

        let services_started = std::time::Instant::now();
        let mut processed_services = 0usize;
        let mut accepted_services = 0usize;
        let mut rejected_services = 0usize;
        for request in records.iter().filter_map(|record| match record {
            OutgoingRecord::ServiceRequest(request) => Some(request.clone()),
            _ => None,
        }) {
            if processed_services >= self.config.candidate_messages_per_walk {
                break;
            }
            processed_services += 1;
            if withdrawals.contains(&request.request_id) {
                continue;
            }
            let candidate_started = std::time::Instant::now();
            match self.validate_candidate_service_request(
                sender_main_dht,
                sender_advertisement,
                mail_send_dht,
                &request,
            ) {
                Ok(()) => {
                    self.accept_valid_service_request_pointer(mail_send_dht, &request, events)
                        .await?;
                    accepted_services += 1;
                    crate::mailbox_walk_debug!(
                        "SENDER service END sender={} candidate={} elapsed={}ms result=accepted",
                        sender_main_dht,
                        processed_services,
                        candidate_started.elapsed().as_millis()
                    );
                }
                Err(error) => {
                    rejected_services += 1;
                    crate::mailbox_walk_debug!(
                        "SENDER service END sender={} candidate={} elapsed={}ms result=rejected error={}",
                        sender_main_dht,
                        processed_services,
                        candidate_started.elapsed().as_millis(),
                        error
                    );
                    self.submit_reputation(
                        sender_main_dht.clone(),
                        ObservationKind::MessageRejected,
                        error.to_string(),
                    );
                }
            }
        }
        crate::mailbox_walk_debug!(
            "SENDER services END sender={} elapsed={}ms processed={} accepted={} rejected={}",
            sender_main_dht,
            services_started.elapsed().as_millis(),
            processed_services,
            accepted_services,
            rejected_services
        );

        crate::mailbox_walk_debug!(
            "SENDER END sender={} total_elapsed={}ms",
            sender_main_dht,
            total_started.elapsed().as_millis()
        );
        Ok(())
    }

    fn validate_candidate_service_request(
        &self,
        observed_sender: &RecordKey,
        sender_advertisement: &MailboxAdvertisement,
        mail_send_dht: &RecordKey,
        request: &ServiceRequest,
    ) -> Result<(), MailboxError> {
        if sender_advertisement.mail_send_dht.as_ref() != Some(mail_send_dht) {
            return Err(MailboxError::InvalidMessage(
                "sender no longer advertises this MailSend DHT".to_string(),
            ));
        }
        if &request.requester_main_dht != observed_sender {
            return Err(MailboxError::InvalidMessage(
                "service requester does not match observed sender".to_string(),
            ));
        }
        if request.version != MAILBOX_PROTOCOL_VERSION {
            return Err(MailboxError::InvalidMessage(
                "unsupported service request protocol version".to_string(),
            ));
        }
        if request.public_payload.len() > self.config.max_service_payload_size
            || request.reply_route_blob.is_empty()
            || request.reply_route_blob.len() > self.config.max_service_reply_route_size
        {
            return Err(MailboxError::InvalidMessage(
                "service request payload/route exceeds policy".to_string(),
            ));
        }
        let calculated_id = calculate_service_request_id(
            &request.requester_main_dht,
            &request.intended_host_main_dht,
            &request.service_id,
            &request.service_manifest_hash,
            &request.instance_id,
            &request.reply_route_blob,
            &request.public_payload,
            request.delegation_allowed,
            request.spectators_allowed,
            request.posted_at,
            request.expires_at,
            &request.request_nonce,
        );
        if calculated_id != request.request_id {
            return Err(MailboxError::InvalidMessage(
                "service request identity changed".to_string(),
            ));
        }
        if !verify_bytes(
            &self.veilid,
            &sender_advertisement.mailbox_signing_public_key,
            &immutable_service_request_bytes(request)?,
            &request.signature,
        )? {
            return Err(MailboxError::InvalidMessage(
                "service request signature is invalid".to_string(),
            ));
        }
        let serialized_size = serialize(request)?.len();
        if serialized_size > self.config.max_service_request_size {
            return Err(MailboxError::MessageTooLarge {
                actual: serialized_size,
                maximum: self.config.max_service_request_size,
            });
        }
        let now = current_timestamp();
        if request.posted_at > now.saturating_add(self.config.max_timestamp_skew_secs)
            || request.expires_at <= request.posted_at
            || request.expires_at
                > request
                    .posted_at
                    .saturating_add(self.config.max_service_request_ttl_secs)
            || now >= request.expires_at
        {
            return Err(MailboxError::InvalidMessage(
                "service request timestamps are outside short-lived policy".to_string(),
            ));
        }
        Ok(())
    }

    async fn accept_valid_service_request_pointer(
        &mut self,
        mail_send_dht: &RecordKey,
        request: &ServiceRequest,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<(), MailboxError> {
        let now = current_timestamp();
        self.record_verified_service_request(request.clone(), events);
        if self.mailbox_store.is_some() {
            self.add_pointer_to_custodian_mailbox(
                request.intended_host_main_dht.clone(),
                MailSourcePointer {
                    message_id: request.request_id,
                    sender_main_dht: request.requester_main_dht.clone(),
                    mail_send_dht: mail_send_dht.clone(),
                    posted_at: request.posted_at,
                    bumped_at: request.posted_at,
                    requested_expires_at: request.expires_at,
                    first_observed_at: now,
                    last_observed_at: now,
                    last_verified_at: now,
                    failed_verification_count: 0,
                },
            )
            .await?;
        }
        self.submit_reputation(
            request.requester_main_dht.clone(),
            ObservationKind::UsefulService,
            "valid public service rendezvous request observed".to_string(),
        );
        Ok(())
    }

    fn record_verified_service_request(
        &mut self,
        request: ServiceRequest,
        events: &broadcast::Sender<MailboxEvent>,
    ) {
        let now = current_timestamp();
        self.recent_service_requests
            .retain(|_, existing| existing.expires_at > now);
        let is_new = !self.recent_service_requests.contains_key(&request.request_id);
        self.recent_service_requests.insert(request.request_id, request.clone());
        while self.recent_service_requests.len() > self.config.recent_service_request_cache {
            let oldest = self
                .recent_service_requests
                .values()
                .min_by_key(|entry| (entry.expires_at, entry.posted_at))
                .map(|entry| entry.request_id);
            let Some(oldest) = oldest else { break; };
            self.recent_service_requests.remove(&oldest);
        }
        if is_new {
            let _ = events.send(MailboxEvent::ServiceRequestDiscovered(request));
        }
    }

    async fn validate_candidate_message(
        &self,
        observed_sender: &RecordKey,
        sender_advertisement: &MailboxAdvertisement,
        mail_send_dht: &RecordKey,
        message: &OutgoingMessage,
    ) -> Result<MailboxAdvertisement, MailboxError> {
        if sender_advertisement.mail_send_dht.as_ref() != Some(mail_send_dht) {
            return Err(MailboxError::InvalidMessage(
                "sender no longer advertises this MailSend DHT".to_string(),
            ));
        }
        if &message.sender_main_dht != observed_sender {
            return Err(MailboxError::InvalidMessage(
                "message sender does not match the observed main DHT".to_string(),
            ));
        }
        if message.version != MAILBOX_PROTOCOL_VERSION {
            return Err(MailboxError::InvalidMessage(
                "unsupported message protocol version".to_string(),
            ));
        }
        let calculated_id = calculate_message_id(
            &message.sender_main_dht,
            &message.recipient_main_dht,
            message.posted_at,
            &message.message_nonce,
            &message.ciphertext,
        );
        if calculated_id != message.message_id {
            return Err(MailboxError::InvalidMessage(
                "immutable message identity changed".to_string(),
            ));
        }
        if !verify_bytes(
            &self.veilid,
            &sender_advertisement.mailbox_signing_public_key,
            &immutable_message_bytes(message)?,
            &message.signature,
        )? {
            return Err(MailboxError::InvalidMessage(
                "immutable message signature is invalid".to_string(),
            ));
        }
        if !verify_bytes(
            &self.veilid,
            &sender_advertisement.mailbox_signing_public_key,
            &bump_bytes(message.message_id, message.bumped_at)?,
            &message.bump_signature,
        )? {
            return Err(MailboxError::InvalidMessage(
                "bump signature is invalid".to_string(),
            ));
        }
        let serialized_size = serialize(message)?.len();
        if serialized_size > self.config.complete_message_max_size {
            return Err(MailboxError::MessageTooLarge {
                actual: serialized_size,
                maximum: self.config.complete_message_max_size,
            });
        }
        let now = current_timestamp();
        if message.posted_at > now.saturating_add(self.config.max_timestamp_skew_secs)
            || message.bumped_at > now.saturating_add(self.config.max_timestamp_skew_secs)
            || message.posted_at > message.bumped_at
            || message.expires_at <= message.posted_at
            || message.expires_at
                > message
                    .posted_at
                    .saturating_add(self.config.max_requested_expiry_secs)
            || now
                > message
                    .posted_at
                    .saturating_add(self.config.max_message_age_secs)
        {
            return Err(MailboxError::InvalidMessage(
                "message timestamps are outside policy".to_string(),
            ));
        }
        if now >= message.expires_at {
            return Err(MailboxError::InvalidMessage("message expired".to_string()));
        }

        let recipient_advertisement = self
            .read_mailbox_advertisement(&message.recipient_main_dht)
            .await?;
        if !recipient_advertisement
            .receive_status
            .permits_message_posted_at(message.posted_at)
        {
            return Err(MailboxError::RecipientNotAccepting);
        }
        let key_version = recipient_advertisement
            .find_receive_key(message.receive_key_epoch)
            .ok_or(MailboxError::ReceiveKeyUnavailable(
                message.receive_key_epoch,
            ))?;
        if key_version.status == ReceiveKeyStatus::Revoked
            || message.posted_at < key_version.valid_from
            || key_version
                .valid_until
                .is_some_and(|until| message.posted_at > until)
        {
            return Err(MailboxError::ReceiveKeyUnavailable(
                message.receive_key_epoch,
            ));
        }
        Ok(recipient_advertisement)
    }

    fn verify_withdrawal(
        &self,
        withdrawal: &OutgoingWithdrawal,
        advertisement: &MailboxAdvertisement,
    ) -> Result<bool, MailboxError> {
        let bytes = serialize(&(
            MESSAGE_SIGNATURE_DOMAIN,
            b"withdrawal",
            withdrawal.message_id,
            withdrawal.sender_main_dht.to_string(),
            withdrawal.withdrawn_at,
        ))?;
        verify_bytes(
            &self.veilid,
            &advertisement.mailbox_signing_public_key,
            &bytes,
            &withdrawal.signature,
        )
    }

    async fn accept_valid_message_pointer(
        &mut self,
        mail_send_dht: &RecordKey,
        message: &OutgoingMessage,
        _recipient_advertisement: &MailboxAdvertisement,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<(), MailboxError> {
        let now = current_timestamp();
        let pointer = MailSourcePointer {
            message_id: message.message_id,
            sender_main_dht: message.sender_main_dht.clone(),
            mail_send_dht: mail_send_dht.clone(),
            posted_at: message.posted_at,
            bumped_at: message.bumped_at,
            requested_expires_at: message.expires_at,
            first_observed_at: now,
            last_observed_at: now,
            last_verified_at: now,
            failed_verification_count: 0,
        };
        let _ = events.send(MailboxEvent::MailDiscovered(pointer.clone()));

        if message.recipient_main_dht == self.own_main_dht {
            self.decrypt_and_emit(message, events).await?;
        }
        if self.mailbox_store.is_some() {
            self.add_pointer_to_custodian_mailbox(message.recipient_main_dht.clone(), pointer)
                .await?;
        }
        self.submit_reputation(
            message.sender_main_dht.clone(),
            ObservationKind::MessageDelivered,
            "valid mailbox message publication observed".to_string(),
        );
        Ok(())
    }

    async fn decrypt_and_emit(
        &mut self,
        message: &OutgoingMessage,
        events: &broadcast::Sender<MailboxEvent>,
    ) -> Result<(), MailboxError> {
        let now = current_timestamp();
        if self
            .recently_decrypted
            .contains(&message.message_id, now)
        {
            return Ok(());
        }
        if self
            .persistent
            .revoked_receive_epochs
            .contains(&message.receive_key_epoch)
        {
            return Err(MailboxError::ReceiveKeyUnavailable(
                message.receive_key_epoch,
            ));
        }
        let envelope = decrypt_envelope(message, &self.persistent.mailbox_master_secret)?;
        self.recently_decrypted.insert(message.message_id, now);

        let received = ReceivedMailboxMessage {
            message: message.clone(),
            application_id: envelope.application_id,
            plaintext: envelope.payload,
        };
        self.persistent.inbox_messages.insert(
            message.message_id,
            StoredMailboxMessage {
                message_id: message.message_id,
                sender_main_dht: message.sender_main_dht.clone(),
                recipient_main_dht: message.recipient_main_dht.clone(),
                application_id: received.application_id.clone(),
                posted_at: message.posted_at,
                received_at: now,
                expires_at: message.expires_at,
                conversation_id: message.conversation_id,
                plaintext: received.plaintext.clone(),
                read: false,
            },
        );
        self.prune_local_inbox();
        self.persist().await?;
        let _ = events.send(MailboxEvent::MailDecrypted(received));
        Ok(())
    }

    fn prune_local_inbox(&mut self) {
        while self.persistent.inbox_messages.len() > LOCAL_INBOX_MAX_MESSAGES {
            let candidate = self
                .persistent
                .inbox_messages
                .values()
                .min_by_key(|message| (if message.read { 0u8 } else { 1u8 }, message.received_at))
                .map(|message| message.message_id);
            let Some(message_id) = candidate else {
                break;
            };
            self.persistent.inbox_messages.remove(&message_id);
        }
    }

    async fn add_pointer_to_custodian_mailbox(
        &mut self,
        recipient: RecordKey,
        pointer: MailSourcePointer,
    ) -> Result<(), MailboxError> {
        let pointer_posted_at = pointer.posted_at;
        let pointer_first_observed_at = pointer.first_observed_at;
        let recipient_key = full_record_key_bytes(&recipient);
        let current = self
            .mailbox_store
            .as_ref()
            .and_then(|store| store.get(&recipient_key))
            .cloned();

        let existing_pointer = current.as_ref().and_then(|entry| match &entry.storage {
            RecipientSourceStorage::Inline { sources } => sources
                .iter()
                .find(|existing| existing.message_id == pointer.message_id)
                .cloned(),
            RecipientSourceStorage::Overflow { .. } => self
                .overflow_stores
                .get(&recipient.to_string())
                .and_then(|store| store.get(&pointer.message_id))
                .cloned(),
        });
        if let Some(existing) = &existing_pointer {
            if existing.sender_main_dht != pointer.sender_main_dht
                || existing.mail_send_dht != pointer.mail_send_dht
            {
                return Err(MailboxError::InvalidMessage(
                    "message id was reused with a different sender or MailSend DHT".to_string(),
                ));
            }
        }

        let existing_overflow_record = current.as_ref().and_then(|entry| match &entry.storage {
            RecipientSourceStorage::Overflow { record_key, .. } => Some(record_key.clone()),
            RecipientSourceStorage::Inline { .. } => None,
        });
        let is_new_pointer = existing_pointer.is_none();
        if is_new_pointer {
            self.quota_state.ensure_can_add(
                &recipient,
                &pointer,
                existing_overflow_record.as_ref(),
                &self.config,
            )?;
        }

        let mut entry = current.unwrap_or_else(|| MailboxRecipientEntry {
            recipient_main_dht: recipient.clone(),
            storage: RecipientSourceStorage::Inline {
                sources: Vec::new(),
            },
            newest_posted_at: pointer_posted_at,
            newest_first_seen_at: pointer_first_observed_at,
            last_recipient_check: current_timestamp(),
            last_sender_check: current_timestamp(),
        });

        let mut promote_sources = None;
        match &mut entry.storage {
            RecipientSourceStorage::Inline { sources } => {
                upsert_pointer(sources, pointer.clone());
                sources.sort_by_key(|source| source.message_id);
                let inline_size = serialize(sources)?.len();
                if (sources.len() > self.config.recipient_inline_pointer_limit
                    || inline_size > self.config.recipient_inline_byte_limit)
                    && self.persistent.overflow_records.len() < self.config.max_overflow_dhts
                {
                    promote_sources = Some(std::mem::take(sources));
                }
            }
            RecipientSourceStorage::Overflow {
                record_key,
                overflow_epoch,
                entry_count,
                serialized_size,
                digest,
                below_inline_threshold_since,
            } => {
                let store = self
                    .overflow_stores
                    .get_mut(&recipient.to_string())
                    .ok_or_else(|| {
                        MailboxError::StoreCorrupt("overflow store missing".to_string())
                    })?;
                store.upsert(pointer.clone());
                let all = store.all_entries();
                if all.len() > self.config.active_messages_per_overflow_record {
                    return Err(MailboxError::QuotaExceeded(
                        "messages in one overflow record",
                    ));
                }
                let encoded = serialize(&all)?;
                *entry_count = all.len() as u32;
                *serialized_size = encoded.len() as u32;
                *digest = hash_bytes(&encoded);
                *below_inline_threshold_since = None;
                let local = self
                    .persistent
                    .overflow_records
                    .get(&recipient.to_string())
                    .ok_or_else(|| {
                        MailboxError::StoreCorrupt("overflow metadata missing".to_string())
                    })?;
                if &local.record_key != record_key || &local.overflow_epoch != overflow_epoch {
                    return Err(MailboxError::StoreCorrupt(
                        "overflow epoch/key mismatch".to_string(),
                    ));
                }
            }
        }

        let mut promoted_overflow = None;
        if let Some(sources) = promote_sources {
            if sources.len() > self.config.active_messages_per_overflow_record {
                return Err(MailboxError::QuotaExceeded(
                    "messages in one overflow record",
                ));
            }
            entry.storage = self
                .promote_recipient_to_overflow(&recipient, sources)
                .await?;
            if let RecipientSourceStorage::Overflow { record_key, .. } = &entry.storage {
                promoted_overflow = Some(record_key.clone());
            }
        }
        entry.newest_posted_at = entry.newest_posted_at.max(pointer_posted_at);
        entry.newest_first_seen_at = entry.newest_first_seen_at.max(pointer_first_observed_at);
        self.mailbox_store
            .as_mut()
            .ok_or_else(|| {
                MailboxError::StoreCorrupt("custodian mailbox store missing".to_string())
            })?
            .upsert(entry);

        if is_new_pointer {
            // Promotion already set the complete overflow-record count. Global,
            // pair, and recipient counters still need the one new pointer.
            let overflow_for_increment = if promoted_overflow.is_some() {
                None
            } else {
                existing_overflow_record.as_ref()
            };
            self.quota_state
                .note_added(&recipient, &pointer, overflow_for_increment);
        }

        if promoted_overflow.is_some() {
            // Overflow promotion is a cross-record transaction: the overflow
            // page generation was committed first, so now commit the owning
            // mailbox pointer/index and only then persist metadata/counters.
            if let Some(store) = &mut self.mailbox_store {
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
            self.persist().await?;
        }

        let observed = self
            .persistent
            .observed_recipients
            .entry(recipient.to_string())
            .or_insert_with(|| ObservedRecipient {
                recipient_main_dht: recipient,
                first_seen: current_timestamp(),
                last_seen: current_timestamp(),
                last_verified_receiving: Some(current_timestamp()),
                source_count: 0,
                stored_locally: true,
            });
        observed.last_seen = current_timestamp();
        if is_new_pointer {
            observed.source_count = observed.source_count.saturating_add(1);
        }
        observed.stored_locally = true;
        Ok(())
    }

    async fn promote_recipient_to_overflow(
        &mut self,
        recipient: &RecordKey,
        sources: Vec<MailSourcePointer>,
    ) -> Result<RecipientSourceStorage, MailboxError> {
        let mut epoch = [0u8; 16];
        OsRng.fill_bytes(&mut epoch);
        let package = self
            .dht
            .create_dht(
                format!(
                    "{OVERFLOW_DHT_NAME_PREFIX}_{}",
                    &hash_bytes(recipient.to_string().as_bytes())[..4]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
                PAGED_DHT_GROUPS.to_vec(),
            )
            .await?;
        let record_key = self.dht.package_id_to_key(package).await?;
        let mut store = CowPagedStore::load_owned(
            format!("overflow:{}", recipient),
            &self.dht,
            package,
            &self.config,
        )
        .await?;
        for source in sources {
            store.upsert(source);
        }
        store
            .commit(
                &self.dht,
                &self.config,
                &mut self.persistent.pending_transactions,
                &self.auth,
                &self.session,
            )
            .await?;
        let all = store.all_entries();
        if all.len() > self.config.active_messages_per_overflow_record {
            return Err(MailboxError::QuotaExceeded(
                "messages in one overflow record",
            ));
        }
        let serialized = serialize(&all)?;
        self.quota_state.set_overflow_count(&record_key, all.len());
        let storage = RecipientSourceStorage::Overflow {
            record_key: record_key.clone(),
            overflow_epoch: epoch,
            entry_count: all.len() as u32,
            serialized_size: serialized.len() as u32,
            digest: hash_bytes(&serialized),
            below_inline_threshold_since: None,
        };
        self.persistent.overflow_records.insert(
            recipient.to_string(),
            OverflowLocalState {
                recipient_main_dht: recipient.clone(),
                record_key,
                package_index: package,
                overflow_epoch: epoch,
                below_inline_threshold_since: None,
                retired: false,
            },
        );
        self.overflow_stores.insert(recipient.to_string(), store);

        // Persist ownership keys and the advisory overflow transaction state
        // before the parent mailbox publishes a pointer to this record. A
        // crash may leave an orphan that can be retired later, but it cannot
        // leave a publicly referenced overflow DHT whose owner key was lost.
        self.persist().await?;
        Ok(storage)
    }

    async fn remove_pointer_everywhere(
        &mut self,
        message_id: [u8; 32],
    ) -> Result<(), MailboxError> {
        let entries = match self.mailbox_store.as_ref() {
            Some(store) => store.all_entries(),
            None => return Ok(()),
        };
        for mut entry in entries {
            let recipient = entry.recipient_main_dht.clone();
            let mut removed: Option<(MailSourcePointer, Option<RecordKey>)> = None;
            match &mut entry.storage {
                RecipientSourceStorage::Inline { sources } => {
                    if let Some(index) = sources
                        .iter()
                        .position(|source| source.message_id == message_id)
                    {
                        removed = Some((sources.remove(index), None));
                    }
                }
                RecipientSourceStorage::Overflow {
                    record_key,
                    entry_count,
                    serialized_size,
                    digest,
                    ..
                } => {
                    if let Some(overflow) = self
                        .overflow_stores
                        .get_mut(&entry.recipient_main_dht.to_string())
                    {
                        if let Some(pointer) = overflow.remove(&message_id) {
                            let all = overflow.all_entries();
                            let bytes = serialize(&all)?;
                            *entry_count = all.len() as u32;
                            *serialized_size = bytes.len() as u32;
                            *digest = hash_bytes(&bytes);
                            removed = Some((pointer, Some((*record_key).clone())));
                        }
                    }
                }
            }
            if let Some((pointer, overflow_record)) = removed {
                self.quota_state
                    .note_removed(&recipient, &pointer, overflow_record.as_ref());
                if let Some(store) = &mut self.mailbox_store {
                    store.upsert(entry);
                }
            }
        }
        Ok(())
    }
}

fn upsert_pointer(sources: &mut Vec<MailSourcePointer>, pointer: MailSourcePointer) {
    if let Some(existing) = sources
        .iter_mut()
        .find(|existing| existing.message_id == pointer.message_id)
    {
        existing.bumped_at = existing.bumped_at.max(pointer.bumped_at);
        existing.last_observed_at = pointer.last_observed_at;
        existing.last_verified_at = pointer.last_verified_at;
        existing.requested_expires_at = pointer.requested_expires_at;
        return;
    }
    sources.push(pointer);
}

fn prefix_bits_to_distance(prefix_bits: u16) -> f32 {
    if prefix_bits == 0 {
        1.0
    } else if prefix_bits >= 32 {
        0.0
    } else {
        2f32.powi(-(prefix_bits as i32))
    }
}

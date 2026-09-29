// user_dht.rs
//
// Application policy for the user's main public DHT.
//
// DHTModule remains generic: it creates, opens, reads, and writes DHTs.
// This module decides the main DHT layout, initializes its subkeys through
// normal WriteToDHT calls, persists ownership data, connects RouteManager,
// and finally marks account setup complete.

use std::{sync::Arc, time::Instant};

use futures::{stream, StreamExt};
use tokio::{
    sync::{watch, Mutex},
    task::JoinHandle,
    time::{self, Duration, MissedTickBehavior},
};

use crate::{
    dht_module::{CreateDhtError, DHTModule, StoredDhtRecord},
    route_manager::RouteManager,
    types::{
        current_timestamp, decode_user_info, AppDirectoryInfo, AppInfo, UserInfo,
        APPINFO_LOCATION, APP_DIRECTORY_LOCATION, LEXICAL_LIBRARY_ADVERTISEMENT_LOCATION, APP_DIRECTORY_RECORD_VERSION,
        APP_INFO_RECORD_VERSION, STATUS_LOCATION,
    },
    user_auth::{AuthError, UserAuth, UserSession, UserSetupState},
};

/// Local name used for the user's primary public DHT package.
pub const MAIN_DHT_NAME: &str = "main_dht";

/// Two ownership groups provide subkeys 0 through 250.
pub const MAIN_DHT_GROUPS: [u16; 2] = [250, 1];
pub const MAIN_DHT_TOTAL_SUBKEYS: u32 = 251;

/// The main-record initialization uses the measured efficient per-record bulk
/// concurrency. This is not a hard Veilid safety ceiling.
pub const MAIN_DHT_INIT_WRITE_CONCURRENCY: usize = 64;

/// Refresh the public presence/check-in timestamp approximately every ten
/// minutes. Explicit offline remains authoritative; an online claim becomes
/// ineffective after the fifteen-minute stale threshold in `types`.
pub const PRESENCE_HEARTBEAT_INTERVAL_SECS: u64 = 10 * 60;

/// Maximum time allowed for the heartbeat task to finish after its stop signal.
/// A stuck DHT heartbeat is aborted so it cannot prevent the final offline write.
pub const PRESENCE_HEARTBEAT_STOP_TIMEOUT_SECS: u64 = 3;

/// Maximum time allowed for the final main-DHT offline publication.
/// Veilid shutdown is not signaled until this write succeeds, fails, or reaches
/// this explicit deadline. Kept below lifecycle's six-second announce ceiling
/// so the module can report its own timeout before the tier has to cancel it.
pub const PRESENCE_OFFLINE_WRITE_TIMEOUT_SECS: u64 = 5;

/// Encrypted user-store key containing the current committed owned-DHT snapshot.
/// Kept at the historical key so existing accounts migrate in place.
pub const DHT_SNAPSHOT_KEY: &str = "dht_snapshot";
/// Previous committed DHT snapshot.  This is intentionally retained across saves so
/// a structurally valid but unusable newest snapshot cannot strand an account.
pub const DHT_SNAPSHOT_PREVIOUS_KEY: &str = "dht_snapshot_previous";
/// Temporary fully-encrypted candidate written before the current snapshot is replaced.
pub const DHT_SNAPSHOT_CANDIDATE_KEY: &str = "dht_snapshot_candidate";
/// Full snapshot preserved when startup has to fall back to main-DHT-only recovery.
/// Ordinary successful saves never rotate this away.
pub const DHT_SNAPSHOT_RECOVERY_ARCHIVE_KEY: &str = "dht_snapshot_recovery_archive";
/// Redundant copy of the account's critical main-DHT descriptor/keypairs.
pub const MAIN_DHT_RECOVERY_KEY: &str = "main_dht_recovery";

/// Persist a complete DHT snapshot using a small A/B journal.  The candidate is
/// serialized/encrypted first and read back before the previous committed snapshot is
/// rotated.  `atomic_write` still protects each individual encrypted file; the extra
/// generation protects us from a logically bad newest snapshot.
pub fn persist_dht_snapshot(
    auth: &UserAuth,
    session: &UserSession,
    snapshot: &[StoredDhtRecord],
) -> Result<(), AuthError> {
    let main_index = auth.read_user_setup_state(session)?.main_dht_package_index;
    persist_dht_snapshot_with_main_index(auth, session, snapshot, main_index)
}

pub fn persist_dht_snapshot_with_main_index(
    auth: &UserAuth,
    session: &UserSession,
    snapshot: &[StoredDhtRecord],
    main_index: Option<usize>,
) -> Result<(), AuthError> {
    auth.write_user_encrypted(session, DHT_SNAPSHOT_CANDIDATE_KEY, &snapshot)?;

    let verified = auth
        .read_user_encrypted::<Vec<StoredDhtRecord>>(session, DHT_SNAPSHOT_CANDIDATE_KEY)?
        .ok_or_else(|| AuthError::Serde("DHT snapshot candidate disappeared after write".into()))?;
    if verified.len() != snapshot.len()
        || verified.iter().zip(snapshot.iter()).any(|(left, right)| {
            left.record_key.to_string() != right.record_key.to_string()
                || left.name != right.name
                || left.subkey_ranges != right.subkey_ranges
                || left.keypairs.len() != right.keypairs.len()
                || left.member_ids != right.member_ids
        })
    {
        return Err(AuthError::Serde(
            "DHT snapshot candidate failed read-back verification".into(),
        ));
    }

    if let Some(current) = auth
        .read_user_encrypted::<Vec<StoredDhtRecord>>(session, DHT_SNAPSHOT_KEY)?
    {
        auth.write_user_encrypted(session, DHT_SNAPSHOT_PREVIOUS_KEY, &current)?;
    }

    auth.write_user_encrypted(session, DHT_SNAPSHOT_KEY, &verified)?;

    if let Some(index) = main_index {
        if let Some(main_record) = verified.get(index) {
            auth.write_user_encrypted(session, MAIN_DHT_RECOVERY_KEY, main_record)?;
        }
    }

    let _ = auth.remove_user_encrypted(session, DHT_SNAPSHOT_CANDIDATE_KEY);
    Ok(())
}


#[derive(Debug, Clone, Default)]
pub struct DhtRestoreSummary {
    pub source: Option<String>,
    pub restored_records: usize,
    pub auxiliary_background: usize,
    pub main_only: bool,
    pub warnings: Vec<String>,
}

/// Restore the newest usable DHT generation.  A failed full snapshot is rolled
/// back by DHTModule, so another generation can be attempted safely.  If every
/// full generation contains a stale auxiliary record, recover only the main DHT
/// rather than stranding the account.
pub async fn restore_saved_dhts(
    auth: &UserAuth,
    session: &UserSession,
    dht_module: &DHTModule,
) -> Result<DhtRestoreSummary, AuthError> {
    let state = auth.read_user_setup_state(session)?;
    let main_index = state.main_dht_package_index;
    let mut summary = DhtRestoreSummary::default();
    let mut main_candidates: Vec<(String, StoredDhtRecord)> = Vec::new();
    let mut archive_candidate: Option<Vec<StoredDhtRecord>> = None;

    for (label, key) in [
        ("current", DHT_SNAPSHOT_KEY),
        ("candidate", DHT_SNAPSHOT_CANDIDATE_KEY),
        ("previous", DHT_SNAPSHOT_PREVIOUS_KEY),
        ("recovery archive", DHT_SNAPSHOT_RECOVERY_ARCHIVE_KEY),
    ] {
        let snapshot = match auth.read_user_encrypted::<Vec<StoredDhtRecord>>(session, key) {
            Ok(Some(snapshot)) if !snapshot.is_empty() => snapshot,
            Ok(_) => continue,
            Err(error) => {
                summary.warnings.push(format!("{label} snapshot could not be read: {error}"));
                continue;
            }
        };

        if archive_candidate.is_none() && label != "recovery archive" {
            archive_candidate = Some(snapshot.clone());
        }

        if let Some(index) = main_index {
            if let Some(record) = snapshot.get(index).cloned() {
                main_candidates.push((format!("{label} snapshot package {index}"), record));
            } else {
                summary.warnings.push(format!(
                    "{label} snapshot has {} record(s) and does not contain main package {index}",
                    snapshot.len()
                ));
                continue;
            }
        }

        let count = snapshot.len();
        crate::tprintln!("[startup] Trying {label} DHT snapshot ({count} record(s))...");
        let restore_result = match main_index {
            Some(index) => dht_module.import_snapshot_prioritized(snapshot, index).await,
            None => dht_module.import_snapshot(snapshot).await,
        };
        match restore_result {
            Ok(()) => {
                summary.source = Some(label.to_string());
                summary.restored_records = count;
                summary.auxiliary_background = if main_index.is_some() { count.saturating_sub(1) } else { 0 };
                if label != "current" {
                    crate::tprintln!("[recovery] Restored DHTs from {label} snapshot.");
                }
                return Ok(summary);
            }
            Err(error) => {
                summary.warnings.push(format!("{label} snapshot restore failed: {error:?}"));
            }
        }
    }

    // Prefer the dedicated emergency record when this version has previously
    // written one, but also retain extracted legacy main records so old accounts
    // can recover on their very first run after upgrading.
    match auth.read_user_encrypted::<StoredDhtRecord>(session, MAIN_DHT_RECOVERY_KEY) {
        Ok(Some(record)) => main_candidates.insert(0, ("dedicated main-DHT recovery".into(), record)),
        Ok(None) => {}
        Err(error) => summary.warnings.push(format!("main-DHT recovery record could not be read: {error}")),
    }

    let mut tried_keys = std::collections::HashSet::new();
    for (label, record) in main_candidates {
        let key_text = record.record_key.to_string();
        if !tried_keys.insert(key_text.clone()) {
            continue;
        }
        crate::tprintln!("[recovery] Trying {label} as main-DHT-only recovery ({key_text})...");
        match dht_module.import_snapshot(vec![record.clone()]).await {
            Ok(()) => {
                // A one-record restore is necessarily package 0 in a fresh actor.
                // Main-DHT package indices are local bookkeeping, not network identity.
                auth.write_user_setup_state(
                    session,
                    &UserSetupState {
                        main_dht_setup: true,
                        main_dht_package_index: Some(0),
                    },
                )?;
                auth.write_user_encrypted(session, MAIN_DHT_RECOVERY_KEY, &record)?;
                if let Some(full_snapshot) = archive_candidate.as_ref() {
                    auth.write_user_encrypted(
                        session,
                        DHT_SNAPSHOT_RECOVERY_ARCHIVE_KEY,
                        full_snapshot,
                    )?;
                }
                summary.source = Some(label);
                summary.restored_records = 1;
                summary.main_only = true;
                summary.warnings.push(
                    "auxiliary DHTs were not restored; the main account DHT was recovered independently"
                        .to_string(),
                );
                return Ok(summary);
            }
            Err(error) => summary.warnings.push(format!(
                "main-DHT-only recovery from {label} failed: {error:?}"
            )),
        }
    }

    Ok(summary)
}

#[derive(Debug)]
pub enum UserDhtError {
    Auth(AuthError),
    Dht(CreateDhtError),
    SavedPackageMissing(usize),
    SavedPackageTooSmall {
        package_index: usize,
        actual_subkeys: u32,
        required_subkeys: u32,
    },
    Serialize(String),
    BackgroundTask(String),
}

impl std::fmt::Display for UserDhtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(error) => write!(f, "user storage error: {error}"),
            Self::Dht(error) => write!(f, "DHT error: {error:?}"),
            Self::SavedPackageMissing(index) => {
                write!(f, "saved main DHT package {index} was not restored")
            }
            Self::SavedPackageTooSmall {
                package_index,
                actual_subkeys,
                required_subkeys,
            } => write!(
                f,
                "saved main DHT package {package_index} has {actual_subkeys} subkeys; \
                 {required_subkeys} are required"
            ),
            Self::Serialize(message) => write!(f, "main-DHT serialization error: {message}"),
            Self::BackgroundTask(message) => write!(f, "main-DHT background task failed: {message}"),
        }
    }
}

impl std::error::Error for UserDhtError {}

impl From<AuthError> for UserDhtError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<CreateDhtError> for UserDhtError {
    fn from(error: CreateDhtError) -> Self {
        Self::Dht(error)
    }
}

fn startup_stop_requested() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        crate::mobile_bridge::startup_stop_requested()
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        false
    }
}

/// Use the restored main DHT when available; otherwise create and initialize it.
///
/// Call this after importing the user's saved DHT snapshot into DHTModule.
pub async fn load_or_create_main_dht(
    auth: &UserAuth,
    session: &UserSession,
    dht_module: &DHTModule,
    route_manager: &RouteManager,
) -> Result<usize, UserDhtError> {
    if startup_stop_requested() {
        return Err(UserDhtError::Dht(CreateDhtError::ChannelClosed));
    }

    let state = auth.read_user_setup_state(session)?;

    if let Some(package_index) = state.main_dht_package_index {
        let saved_package = dht_module.get_dht_info(package_index).await;

        // During Android startup, Stop Safely deliberately cancels outstanding
        // DHT actor replies. Do not reinterpret that cancellation as a
        // missing/incomplete saved package and create a replacement DHT while
        // the process is trying to exit.
        if startup_stop_requested() {
            return Err(UserDhtError::Dht(CreateDhtError::ChannelClosed));
        }

        match saved_package {
            Some(package) => {
                let actual_subkeys = package.total_subkeys();
                if actual_subkeys < MAIN_DHT_TOTAL_SUBKEYS {
                    return Err(UserDhtError::SavedPackageTooSmall {
                        package_index,
                        actual_subkeys,
                        required_subkeys: MAIN_DHT_TOTAL_SUBKEYS,
                    });
                }

                // A previously interrupted setup may already have saved the
                // package but not yet flipped the final flag. Reconnect it and
                // finish the persistent state rather than creating a duplicate.
                route_manager
                    .set_dht(dht_module.clone(), package_index)
                    .await;

                if !state.main_dht_setup {
                    auth.write_user_setup_state(
                        session,
                        &UserSetupState {
                            main_dht_setup: true,
                            main_dht_package_index: Some(package_index),
                        },
                    )?;
                }

                return Ok(package_index);
            }
            None if state.main_dht_setup => {
                return Err(UserDhtError::SavedPackageMissing(package_index));
            }
            None => {
                // Setup was incomplete and its package was never persisted.
                // Start over with a fresh DHT below.
            }
        }
    }

    if startup_stop_requested() {
        return Err(UserDhtError::Dht(CreateDhtError::ChannelClosed));
    }

    create_main_dht(auth, session, dht_module, route_manager).await
}

async fn create_main_dht(
    auth: &UserAuth,
    session: &UserSession,
    dht_module: &DHTModule,
    route_manager: &RouteManager,
) -> Result<usize, UserDhtError> {
    // Mark setup incomplete before any network work begins.
    auth.write_user_setup_state(session, &UserSetupState::default())?;

    let package_index = dht_module
        .create_dht(MAIN_DHT_NAME.to_string(), MAIN_DHT_GROUPS.to_vec())
        .await?;

    initialize_main_dht(dht_module, package_index).await?;

    // Persist the DHT descriptor and writer keypairs before recording its index.
    let snapshot: Vec<StoredDhtRecord> = dht_module.export_snapshot().await;
    persist_dht_snapshot_with_main_index(auth, session, &snapshot, Some(package_index))?;

    // Record the package while the final flag remains false. This lets a restart
    // recover cleanly if shutdown occurs between persistence and finalization.
    auth.write_user_setup_state(
        session,
        &UserSetupState {
            main_dht_setup: false,
            main_dht_package_index: Some(package_index),
        },
    )?;

    // RouteManager now owns maintaining the route-blob subkey.
    route_manager
        .set_dht(dht_module.clone(), package_index)
        .await;

    // This is deliberately the final persistent setup operation.
    auth.write_user_setup_state(
        session,
        &UserSetupState {
            main_dht_setup: true,
            main_dht_package_index: Some(package_index),
        },
    )?;

    Ok(package_index)
}

/// Initialize every main-DHT subkey through DHTModule's ordinary write API.
///
/// Empty data is intentionally passed here. DHTModule normalizes empty writes
/// (and the text "null") to NULL_DHT_VALUE, currently b"0".
/// Writes are bounded by `MAIN_DHT_INIT_WRITE_CONCURRENCY`; this returns only
/// after every subkey has completed successfully.
async fn initialize_main_dht(
    dht_module: &DHTModule,
    package_index: usize,
) -> Result<(), UserDhtError> {
    let writes = stream::iter(0..MAIN_DHT_TOTAL_SUBKEYS)
        .map(|location| {
            let dht_module = dht_module.clone();
            async move {
                dht_module
                    .write_to_dht(package_index, location, Vec::new())
                    .await?;
                Ok::<(), CreateDhtError>(())
            }
        })
        .buffer_unordered(MAIN_DHT_INIT_WRITE_CONCURRENCY);

    tokio::pin!(writes);
    while let Some(result) = writes.next().await {
        result?;
    }

    Ok(())
}

// ============================================================================
// Main-DHT live metadata publisher
// ============================================================================

/// Verify that refreshed DHT traffic can actually leave the local process.
/// Attachment alone is insufficient on platforms where a firewall can allow
/// Veilid initialization while blocking external DHT operations.
pub async fn verify_main_dht_network_access(
    dht_module: &DHTModule,
    package_index: usize,
    maximum_wait: Duration,
) -> Result<(veilid_core::RecordKey, Duration), UserDhtError> {
    let package = dht_module
        .get_dht_info(package_index)
        .await
        .ok_or(UserDhtError::SavedPackageMissing(package_index))?;
    let record_key = package.dht_record.key().clone();
    let started = Instant::now();
    let deadline = started + maximum_wait;
    loop {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if crate::mobile_bridge::stop_requested() {
            return Err(UserDhtError::BackgroundTask(
                "Mobile host stop requested during DHT network verification".to_string(),
            ));
        }

        // This record is already open on DHTModule's persistent owned
        // routing context. Reading it through the foreign-record helper would
        // open and then close the same record key; Veilid treats that close as
        // closing the live record, including the owned handle. Use the owned
        // force-refresh path so the probe performs real network traffic
        // without closing the main DHT afterward.
        let last_error = match time::timeout(
            Duration::from_secs(5),
            dht_module.read_from_dht(package_index, STATUS_LOCATION, true),
        )
        .await
        {
            Ok(Ok(bytes)) if decode_user_info(&bytes).is_ok() => {
                return Ok((record_key, started.elapsed()));
            }
            Ok(Ok(_)) => "refreshed status value was empty or malformed".to_string(),
            Ok(Err(error)) => format!("{error:?}"),
            Err(_) => "individual refreshed DHT read timed out after 5 seconds".to_string(),
        };

        if Instant::now() >= deadline {
            return Err(UserDhtError::BackgroundTask(format!(
                "DHT network verification timed out after {:?}: {}",
                maximum_wait,
                last_error
            )));
        }
        time::sleep(Duration::from_secs(1)).await;
    }
}

/// Maintains the fixed, cross-module metadata in the user's main DHT.
///
/// RouteManager owns subkey 1, MailboxManager owns subkey 2, and WalkTask owns
/// subkeys 50-250. This runtime owns presence at subkey 0 and application/node
/// capabilities at subkey 10 and the App Directory pointer at subkey 11.
#[derive(Clone)]
pub struct MainDhtRuntime {
    dht_module: DHTModule,
    package_index: usize,
    presence: Arc<Mutex<UserInfo>>,
    stop_tx: watch::Sender<bool>,
    heartbeat_task: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl MainDhtRuntime {
    /// Publish a fresh login record and start the periodic online heartbeat.
    pub async fn start(
        dht_module: DHTModule,
        package_index: usize,
        account_created_at: u64,
    ) -> Result<Self, UserDhtError> {
        let previous = match dht_module
            .read_from_dht(package_index, STATUS_LOCATION, true)
            .await
        {
            Ok(bytes) => match decode_user_info(&bytes) {
                Ok(value) => Some(value),
                Err(error) => {
                    crate::teprintln!(
                        "[user_dht] Existing presence record was unreadable; replacing it: {error}"
                    );
                    None
                }
            },
            Err(CreateDhtError::NotFound) => None,
            Err(error) => {
                crate::teprintln!(
                    "[user_dht] Could not read the previous presence record; replacing it: {error:?}"
                );
                None
            }
        };

        let presence = UserInfo::begin_session(
            previous.as_ref(),
            current_timestamp(),
            account_created_at,
        );
        write_presence(&dht_module, package_index, &presence).await?;

        let (stop_tx, stop_rx) = watch::channel(false);
        let runtime = Self {
            dht_module: dht_module.clone(),
            package_index,
            presence: Arc::new(Mutex::new(presence)),
            stop_tx,
            heartbeat_task: Arc::new(Mutex::new(None)),
        };

        let task = tokio::spawn(run_presence_heartbeat(
            dht_module,
            package_index,
            runtime.presence.clone(),
            stop_rx,
        ));
        *runtime.heartbeat_task.lock().await = Some(task);

        Ok(runtime)
    }

    /// Update public reachability when Veilid attaches or detaches.
    pub async fn set_network_online(&self, online: bool) -> Result<(), UserDhtError> {
        let snapshot = {
            let mut presence = self.presence.lock().await;
            presence.set_network_online(online, current_timestamp());
            presence.clone()
        };
        write_presence(&self.dht_module, self.package_index, &snapshot).await
    }

    /// Rebuild subkey 10 after modules or attached apps change.
    pub async fn publish_app_info(&self, mut app_info: AppInfo) -> Result<(), UserDhtError> {
        app_info.record_version = APP_INFO_RECORD_VERSION;
        app_info.updated_at = current_timestamp();
        let bytes = bincode::serialize(&app_info)
            .map_err(|error| UserDhtError::Serialize(error.to_string()))?;
        self.dht_module
            .write_to_dht(self.package_index, APPINFO_LOCATION, bytes)
            .await?;
        Ok(())
    }

    /// Publish the small main-DHT pointer to the daemon-owned App Directory.
    /// The directory manifest is committed first; this pointer is the public
    /// commit marker for its generation.
    pub async fn publish_app_directory_info(
        &self,
        directory_dht: String,
        generation: u64,
    ) -> Result<(), UserDhtError> {
        let mut info = AppDirectoryInfo::new(directory_dht, generation, current_timestamp());
        info.record_version = APP_DIRECTORY_RECORD_VERSION;
        info.updated_at = current_timestamp();
        let bytes = bincode::serialize(&info)
            .map_err(|error| UserDhtError::Serialize(error.to_string()))?;
        self.dht_module
            .write_to_dht(self.package_index, APP_DIRECTORY_LOCATION, bytes)
            .await?;
        Ok(())
    }

    /// Publish the compact lexical-library advertisement set at main-DHT subkey 12.
    pub async fn publish_lexical_library_advertisements(&self, bytes: Vec<u8>) -> Result<(), UserDhtError> {
        self.dht_module
            .write_to_dht(self.package_index, LEXICAL_LIBRARY_ADVERTISEMENT_LOCATION, bytes)
            .await?;
        Ok(())
    }

    pub async fn presence_snapshot(&self) -> UserInfo {
        self.presence.lock().await.clone()
    }

    /// Stop the periodic presence heartbeat without doing network I/O.
    ///
    /// Lifecycle uses this as intake cleanup so no new heartbeat can race the final offline
    /// announcement. It is safe to call even when the network is unreachable.
    pub async fn stop_heartbeat(&self) -> Result<(), UserDhtError> {
        let _ = self.stop_tx.send(true);

        if let Some(mut task) = self.heartbeat_task.lock().await.take() {
            match time::timeout(
                Duration::from_secs(PRESENCE_HEARTBEAT_STOP_TIMEOUT_SECS),
                &mut task,
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(error)) => crate::teprintln!(
                    "[user_dht] Presence heartbeat task ended abnormally during shutdown: {error}"
                ),
                Err(_) => {
                    crate::teprintln!(
                        "[user_dht] Presence heartbeat did not stop within {} seconds; aborting it before the offline write.",
                        PRESENCE_HEARTBEAT_STOP_TIMEOUT_SECS,
                    );
                    task.abort();
                    let _ = task.await;
                }
            }
        }
        Ok(())
    }

    /// Publish one bounded clean offline/logout record while Veilid is still reachable.
    ///
    /// Lifecycle places this in the announce tier, so it can be skipped wholesale for an
    /// unreachable host or a quick in-process restart without skipping local cleanup.
    pub async fn publish_offline(&self) -> Result<(), UserDhtError> {
        // Mark the in-memory record offline before beginning the network write. Even if the
        // write fails or times out, the write was genuinely attempted while Veilid was alive.
        let snapshot = {
            let mut presence = self.presence.lock().await;
            presence.finish_session(current_timestamp());
            presence.clone()
        };

        match time::timeout(
            Duration::from_secs(PRESENCE_OFFLINE_WRITE_TIMEOUT_SECS),
            write_presence(&self.dht_module, self.package_index, &snapshot),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(UserDhtError::BackgroundTask(format!(
                "offline main-DHT write timed out after {} seconds",
                PRESENCE_OFFLINE_WRITE_TIMEOUT_SECS,
            ))),
        }
    }

}

async fn run_presence_heartbeat(
    dht_module: DHTModule,
    package_index: usize,
    presence: Arc<Mutex<UserInfo>>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut interval = time::interval(Duration::from_secs(
        PRESENCE_HEARTBEAT_INTERVAL_SECS.max(1),
    ));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Consume Tokio's immediate first tick; the login record was just written.
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let snapshot = {
                    let mut presence = presence.lock().await;
                    presence.heartbeat(current_timestamp());
                    presence.clone()
                };
                if let Err(error) = write_presence(&dht_module, package_index, &snapshot).await {
                    crate::teprintln!("[user_dht] Presence heartbeat write failed: {error}");
                }
            }
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn write_presence(
    dht_module: &DHTModule,
    package_index: usize,
    presence: &UserInfo,
) -> Result<(), UserDhtError> {
    let bytes = bincode::serialize(presence)
        .map_err(|error| UserDhtError::Serialize(error.to_string()))?;
    dht_module
        .write_to_dht(package_index, STATUS_LOCATION, bytes)
        .await?;
    Ok(())
}

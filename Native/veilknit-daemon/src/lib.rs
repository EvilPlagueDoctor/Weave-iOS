//! VeilKnit daemon executable.
//!
//! This file is the wiring diagram: it creates the major modules, connects them together, starts
//! the background services, and handles the console/GUI commands. The modules themselves own
//! their real logic. Shutdown is intentionally handed to the shared `Lifecycle` coordinator so
//! this file does not need to remember a fragile manual cleanup order.

mod app;
mod api;
mod events;
mod presentation;
mod security;
mod support;

pub(crate) use app::identity as identity_manager;
pub(crate) use app::services as app_services;
pub(crate) use api::local as named_pipe_api;
pub(crate) use events::network_events;
pub(crate) use presentation::console_log;
pub(crate) use presentation::console_ui;
pub(crate) use security::network_decode;

mod blob_store;
mod private_app_storage;
mod stream_transport;
mod gossip;
mod lexical_library;
mod dht_module;
mod handshake;
mod lifecycle;
mod shutdown_debug;
mod mailbox_walk_debug;
mod network_supervisor;
mod node;
mod node_list;
mod reputation;
mod recovery;
mod route_manager;
mod types;
mod user_auth;
mod user_dht;
mod walk_settings;
mod walk_task;

use std::io::{self, Write};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

mod mailbox;
#[cfg(target_os = "android")]
mod android_bridge;
#[cfg(target_os = "ios")]
mod ios_bridge;
#[cfg(target_os = "android")]
pub(crate) use android_bridge as mobile_bridge;
#[cfg(target_os = "ios")]
pub(crate) use ios_bridge as mobile_bridge;

use blob_store::BlobStoreManager;
use private_app_storage::PrivateAppStorageManager;
use dht_module::DHTModule;
use console_ui::ConsoleDashboard;
use user_dht::MainDhtRuntime;
use handshake::HandshakeManager;
use lexical_library::{
    LexicalLibraryManager, LexicalObserveRequest, LEXICAL_ACTIVE_WINDOW_DAYS,
    LEXICAL_TEST_APPLICATION_ID, LEXICAL_TEST_LAYER, LEXICAL_TEST_LIBRARY_NAME,
};
use gossip::{
    derive_index_tokens, GossipManager, GossipPublishRequest, GossipSearchQuery,
    GossipTokenMatchMode, GossipTokenPolarity, GossipTokenProbe,
    GOSSIP_DEFAULT_TTL_SECS, GOSSIP_TEST_APPLICATION_ID, GOSSIP_TEST_INDEX_NAME,
    GOSSIP_TEST_NAMESPACE,
};
use app_services::{AppSigningManager, AppStorageManager};
use app::directory::AppDirectoryManager;
use app::visible_names::AppVisibleNameManager;
use identity_manager::{AppCredential, IdentityManager};
use mailbox::{
    MailboxConfig, MailboxEvent, MailboxInit, MailboxManager, MailboxWalkRequest,
    OutgoingMessageRequest,
};
use lifecycle::{HookResult, HookSpec, ResourceNeed, StopReason};
use node::*;
use network_events::{NetworkEvent, StartupStage};
use network_supervisor::{
    spawn_auto_walk_scheduler, NetworkSupervisor, WalkReason,
};
use named_pipe_api::{default_endpoint, spawn_local_api};
use route_manager::RouteManager;
use reputation::{
    AppId, CoreModuleId, ReputationManager, SubscriptionFilter,
};
use types::{
    current_timestamp, current_timestamp_millis, decode_user_info, AppInfo, MailboxAdvertisement,
    CAPABILITY_APP_AUTH, CAPABILITY_HANDSHAKE, CAPABILITY_MAILBOX,
    CAPABILITY_MAILBOX_CUSTODIAN, CAPABILITY_NETWORK_WALK,
    CAPABILITY_PRIVATE_ROUTES, CAPABILITY_REPUTATION,
    MAILBOX_ADVERTISEMENT_LOCATION, STATUS_LOCATION,
};
use user_auth::{AuthError, UserAuth, UserSession};
use walk_settings::{WalkModeSettings, WalkSettings, WALK_SETTINGS_STORE_KEY};
use walk_task::{
    WalkConfig, WalkStartResult, WalkStatus, WalkSubscriber, WalkTask, WalkTaskInit,
};
use veilid_core::RecordKey;

static GUI_BRIDGE_MODE: AtomicBool = AtomicBool::new(false);

/// Starts the daemon using the Android/embedded host bridge.
///
/// Android owns the Tokio runtime in `android_bridge.rs`; this function deliberately remains
/// an ordinary async function so the same daemon core can also be launched by the tiny CLI
/// binary in `src/main.rs`.
pub async fn run_daemon(
    gui_bridge_mode: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    GUI_BRIDGE_MODE.store(gui_bridge_mode, Ordering::Relaxed);

    let auth = Arc::new(UserAuth::new("./user_data")?);

    let Some(session) = login_or_signup(&auth) else {
        crate::tprintln!("Mobile host stop requested before authentication completed.");
        return Ok(());
    };
    let session = Arc::new(session);
    let startup_started = Instant::now();

    crate::tprintln!("Welcome, {}!", session.username());
    let supervisor = NetworkSupervisor::default();
    let lifecycle = supervisor.lifecycle();
    lifecycle.set_data_dir("./user_data");
    if let Some(previous) = lifecycle.take_previous_record() {
        if previous.looks_dirty() {
            crate::teprintln!(
                "[lifecycle] previous shutdown needs review ({}): {}",
                previous.path.display(),
                previous.json
            );
        }
    }
    let event_bus = supervisor.event_bus();
    let configuration_stage = supervisor
        .stage_running(StartupStage::Configuration, None)
        .await;
    configuration_stage.complete(None).await;

    // Local, per-user reputation service. It loads its encrypted state now and
    // remains available to core modules and authenticated apps through
    // capability-limited handles.
    let reputation_stage = supervisor
        .stage_running(StartupStage::Reputation, None)
        .await;
    let reputation_manager = ReputationManager::spawn(auth.clone(), session.clone())?;
    let reputation_user = reputation_manager.user_handle();
    let reputation_event_task = match reputation_user
        .subscribe(SubscriptionFilter::default(), None)
        .await
    {
        Ok(mut subscription) => {
            let events = event_bus.clone();
            Some(tokio::spawn(async move {
                while let Some(notice) = subscription.recv().await {
                    events.emit(
                        network_events::NetworkEventSource::Reputation,
                        network_events::EventSeverity::Info,
                        network_events::NetworkEvent::ReputationChanged {
                            subject: notice.subject.to_string(),
                            reason: format!("{:?}", notice.kind),
                        },
                    );
                }
            }))
        }
        Err(error) => {
            crate::tprintln!("Warning: could not subscribe to reputation events: {error}");
            None
        }
    };
    reputation_stage.complete(None).await;

    // Core modules receive stable, host-minted identities. This prevents an
    // attached app from claiming the walker's or handshake module's authority
    // when submitting reputation observations.
    let identity_stage = supervisor.stage_running(StartupStage::Identity, None).await;
    let identity_manager = IdentityManager::load_with_event_bus(
        auth.clone(),
        session.clone(),
        event_bus.clone(),
    )?;
    let handshake_identity = identity_manager
        .register_core_module(CoreModuleId::new("handshake")?)
        .await?;
    let walker_identity = identity_manager
        .register_core_module(CoreModuleId::new("network_walker")?)
        .await?;
    let mailbox_identity = identity_manager
        .register_core_module(CoreModuleId::new("mailbox")?)
        .await?;
    let handshake_reputation = handshake_identity.reputation_handle(&reputation_manager);
    let walker_reputation = walker_identity.reputation_handle(&reputation_manager);
    let mailbox_reputation = mailbox_identity.reputation_handle(&reputation_manager);
    identity_stage.complete(None).await;

    // Namespace the Veilid node per-account, using the username instead of
    // an arbitrary string, so each user's protected/table store is isolated.
    let veilid_stage = supervisor.stage_running(StartupStage::Veilid, None).await;
    let node = create_node(session.username().to_string()).await?;
    veilid_stage.complete(None).await;
    let attachment_stage = supervisor
        .stage_running(StartupStage::NetworkAttachment, None)
        .await;
    supervisor
        .set_network_attachment(true, "Veilid reported network readiness")
        .await;
    attachment_stage.complete(None).await;

    let veilid = Arc::new(node.veilid.clone());
    let background = DHTModule::new(veilid.clone());

    // Route manager: publishes a private route blob into a DHT so other
    // peers have somewhere stable to look us up. It needs both the node
    // (to actually create/publish routes) and a DHT package index (to know
    // where to write the blob) before it'll do anything.
    let routes_stage = supervisor.stage_running(StartupStage::Routes, None).await;
    let route_manager = RouteManager::spawn();
    node.set_route_change_handler(route_manager.make_route_change_handler());
    route_manager.set_node(node.clone()).await;
    routes_stage.complete(None).await;

    // Restore the newest usable DHT generation. Full snapshots are opened with
    // bounded concurrency; if a stale auxiliary record poisons every generation,
    // the account's critical main DHT is recovered independently.
    let restore_stage = supervisor.stage_running(StartupStage::DhtRestore, None).await;
    let restore_started = Instant::now();
    match user_dht::restore_saved_dhts(&auth, &session, &background).await {
        Ok(summary) => {
            match &summary.source {
                Some(source) if summary.main_only => crate::tprintln!(
                    "[recovery] Main DHT recovered from {source}; auxiliary DHT recovery will be deferred."
                ),
                Some(source) if summary.auxiliary_background > 0 => crate::tprintln!(
                    "Main DHT restored from {source} snapshot; {} auxiliary DHT slot(s) were checked and any slow/missing records will continue in the background.",
                    summary.auxiliary_background
                ),
                Some(source) => crate::tprintln!(
                    "DHTs restored from {source} snapshot ({} record(s)).",
                    summary.restored_records
                ),
                None if summary.warnings.is_empty() => {
                    crate::tprintln!("No saved DHTs found for this account.")
                }
                None => crate::tprintln!("No usable full DHT snapshot could be restored."),
            }
            for warning in summary.warnings {
                crate::teprintln!("[recovery] {warning}");
            }
        }
        Err(error) => crate::teprintln!("[recovery] Could not inspect saved DHT state: {error}"),
    }
    crate::tprintln!(
        "[startup] DHT restore stage completed in {} ms",
        restore_started.elapsed().as_millis()
    );
    restore_stage.complete(None).await;

    // user_dht owns the main-DHT layout and setup policy. It either reconnects
    // the restored package or creates it, initializes every subkey through the
    // normal DHTModule write API, persists it, and hands it to RouteManager.
    let main_dht_stage = supervisor.stage_running(StartupStage::MainDht, None).await;
    let main_dht_index: Option<usize> = match user_dht::load_or_create_main_dht(
        &auth,
        &session,
        &background,
        &route_manager,
    )
    .await
    {
        Ok(index) => {
            crate::tprintln!("Main DHT is ready at package index {index}.");
            Some(index)
        }
        Err(error) => {
            crate::tprintln!("Main DHT setup failed: {error}");
            None
        }
    };
    if main_dht_index.is_some() {
        main_dht_stage.complete(None).await;
    } else {
        main_dht_stage.fail("Main DHT unavailable").await;
    }

    // Subkey 0 was previously defined but never written. Start the presence
    // runtime now so login time, online state, and a crash-tolerant heartbeat
    // are all visible before the other public services come online.
    let presence_stage = supervisor.stage_running(StartupStage::Presence, None).await;
    let main_dht_runtime: Option<MainDhtRuntime> = match main_dht_index {
        Some(index) => match MainDhtRuntime::start(
            background.clone(),
            index,
            session.user().created_at,
        )
        .await
        {
            Ok(runtime) => {
                crate::tprintln!("Main-DHT presence publisher started.");
                Some(runtime)
            }
            Err(error) => {
                crate::tprintln!("Main-DHT presence publisher could not start: {error}");
                None
            }
        },
        None => None,
    };
    if main_dht_runtime.is_some() {
        presence_stage.complete(None).await;
    } else {
        presence_stage
            .skip(Some("No main DHT runtime".to_string()))
            .await;
    }

    // A successful attachment is not enough on platforms where a firewall can
    // allow Veilid startup but block refreshed DHT traffic. Verify one real
    // force-refreshed read through the persistent owned record context.
    // Opening the same key as a foreign record and closing it afterward would
    // also close the live owned record in Veilid.
    let verification_stage = supervisor
        .stage_running(StartupStage::DhtNetworkVerification, None)
        .await;
    if let Some(index) = main_dht_index {
        match user_dht::verify_main_dht_network_access(
            &background,
            index,
            Duration::from_secs(90),
        )
        .await
        {
            Ok((record_key, elapsed)) => {
                supervisor
                    .set_dht_network_verified(
                        record_key.to_string(),
                        types::STATUS_LOCATION,
                        elapsed,
                    )
                    .await;
                verification_stage.complete(None).await;
            }
            Err(error) => {
                crate::tprintln!("Warning: DHT network verification failed: {error}");
                verification_stage.fail(error.to_string()).await;
            }
        }
    } else {
        verification_stage
            .skip(Some("No main DHT to verify".to_string()))
            .await;
    }

    // Keep both the structured status and public online bit synchronized with
    // actual Veilid attachment changes instead of relying only on startup and
    // the clean-shutdown path.
    {
        let runtime = main_dht_runtime.clone();
        let supervisor = supervisor.clone();
        node.set_attachment_handler(move |attachment| {
            let runtime = runtime.clone();
            let supervisor = supervisor.clone();
            async move {
                let attached = attachment.state.is_attached();
                supervisor
                    .set_network_attachment(attached, format!("{:?}", attachment.state))
                    .await;
                if let Some(runtime) = runtime {
                    if let Err(error) = runtime.set_network_online(attached).await {
                        crate::teprintln!("[user_dht] Could not publish attachment state: {error}");
                    }
                }
            }
        });
    }

    // Handshake manager: needs to know our own DHT record key (as a string)
    // so peers can find their way back to us, plus the DHT module (to look
    // up peers' route blobs) and the node (to install the app-message
    // handler and drive retries/check-ins on a timer).
    let our_dht_key = match main_dht_index {
        Some(idx) => match background.get_dht_info(idx).await {
            Some(package) => package.dht_record.key().to_string(),
            None => {
                crate::tprintln!("Warning: route DHT index {idx} vanished; handshakes will report an empty sender address.");
                String::new()
            }
        },
        None => {
            crate::tprintln!("Warning: no route DHT available; handshakes will report an empty sender address.");
            String::new()
        }
    };

    if gui_bridge_mode {
        crate::tprintln!("[gui] MAIN_DHT_KEY={our_dht_key}");
    }

    // The App Directory is application-critical, not merely an optional network extra.
    // Embedded Weave cannot publish its profile root without it. Previously it shared the
    // 30-second optional startup budget with mailbox + walker; if those services consumed the
    // budget first, the daemon still announced READY with app_directory=None and every
    // register_app_root request failed immediately with service_unavailable. Give the directory
    // its own bounded recovery window before optional services begin.
    crate::tprintln!("[app-directory] Preparing application services...");
    const APP_DIRECTORY_STARTUP_ATTEMPTS: usize = 2;
    const APP_DIRECTORY_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);
    let app_directory_manager = match main_dht_runtime.clone() {
        Some(runtime) => {
            let mut ready = None;
            for attempt in 1..=APP_DIRECTORY_STARTUP_ATTEMPTS {
                crate::tprintln!(
                    "[app-directory] Opening App Directory (attempt {attempt}/{APP_DIRECTORY_STARTUP_ATTEMPTS})..."
                );
                match tokio::time::timeout(
                    APP_DIRECTORY_ATTEMPT_TIMEOUT,
                    AppDirectoryManager::load_or_create(
                        auth.clone(),
                        session.clone(),
                        background.clone(),
                        runtime.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(manager)) => {
                        crate::tprintln!(
                            "[app-directory] App Directory ready at {}.",
                            manager.directory_dht()
                        );
                        ready = Some(manager);
                        break;
                    }
                    Ok(Err(error)) => {
                        crate::teprintln!(
                            "[app-directory] attempt {attempt}/{APP_DIRECTORY_STARTUP_ATTEMPTS} failed: {error}"
                        );
                    }
                    Err(_) => {
                        crate::teprintln!(
                            "[app-directory] attempt {attempt}/{APP_DIRECTORY_STARTUP_ATTEMPTS} timed out after {}s",
                            APP_DIRECTORY_ATTEMPT_TIMEOUT.as_secs()
                        );
                    }
                }

                if attempt < APP_DIRECTORY_STARTUP_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(750)).await;
                }
            }
            ready
        }
        None => None,
    };
    if app_directory_manager.is_none() {
        crate::teprintln!(
            "[app-directory] application services remain unavailable; local apps may not publish roots this session"
        );
    }

    // Everything below is layered on top of the restored main DHT. These services used to
    // share one 30-second stopwatch. That meant a healthy-but-slow mailbox startup (several
    // routability waits of ~10 seconds each) could consume the entire allowance and force the
    // walker, app advertisement, and lexical library to be skipped for the whole session.
    // Give each subsystem its own bounded startup window instead. This preserves Stop Safely
    // protection against a genuinely wedged DHT without allowing one service to starve the rest.
    const MAILBOX_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
    const WALKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
    const APP_INFO_STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
    const LEXICAL_STARTUP_TIMEOUT: Duration = Duration::from_secs(45);

    let mailbox_config = MailboxConfig::default();
    let mailbox_participates_as_custodian = mailbox_config.participate_as_custodian;

    let mailbox_stage = supervisor.stage_running(StartupStage::Mailbox, None).await;
    let mailbox_manager: Option<Arc<MailboxManager>> = match main_dht_index {
        Some(main_dht_package) => {
            // Mailbox recovery touches several DHT pages.  If DHT traffic has
            // become unhealthy after the main record came online, serial
            // operation timeouts used to keep Android on the loading screen
            // for minutes and also prevented Stop Safely from reaching the
            // command loop.  Mailbox is optional for daemon readiness, so
            // bound this startup stage and continue in degraded mode.
            let init = MailboxInit {
                veilid: node.veilid.clone(),
                dht_module: background.clone(),
                main_dht_package,
                user_auth: auth.clone(),
                user_session: session.clone(),
                reputation: mailbox_reputation,
                config: mailbox_config,
            };
            crate::tprintln!("[mailbox] Starting mailbox services (timeout={}s)...", MAILBOX_STARTUP_TIMEOUT.as_secs());
            match tokio::time::timeout(MAILBOX_STARTUP_TIMEOUT, MailboxManager::spawn(init)).await {
                Ok(Ok(manager)) => {
                    crate::tprintln!("Mailbox controller started.");
                    Some(manager)
                }
                Ok(Err(error)) => {
                    crate::tprintln!("Mailbox controller could not start: {error}");
                    None
                }
                Err(_) => {
                    crate::teprintln!(
                        "[mailbox] startup exceeded {}s; continuing without mailbox services for this session",
                        MAILBOX_STARTUP_TIMEOUT.as_secs()
                    );
                    None
                }
            }
        }
        None => None,
    };
    if mailbox_manager.is_some() {
        mailbox_stage.complete(None).await;
    } else {
        mailbox_stage.skip(Some("Mailbox unavailable".to_string())).await;
    }

    let handshake_stage = supervisor.stage_running(StartupStage::Handshake, None).await;
    let handshake_manager = HandshakeManager::new(
        node.veilid.clone(),
        background.clone(),
        our_dht_key.clone(),
        handshake_reputation,
    )
    .with_event_bus(event_bus.clone())
    .into_shared();
    HandshakeManager::start_background_task(handshake_manager.clone(), node.clone());
    handshake_stage.complete(None).await;

    let walker_stage = supervisor.stage_running(StartupStage::Walker, None).await;
    let walk_task = match main_dht_index {
        Some(public_dht_package) => {
            let init = WalkTaskInit::new(public_dht_package, background.clone())
                .with_handshake(handshake_manager.clone())
                .with_reputation(walker_reputation.clone())
                .with_user_storage(auth.clone(), session.clone())
                .with_event_bus(event_bus.clone());

            crate::tprintln!("[walker] Starting network walker (timeout={}s)...", WALKER_STARTUP_TIMEOUT.as_secs());
            match tokio::time::timeout(WALKER_STARTUP_TIMEOUT, WalkTask::spawn(init)).await {
                Ok(Ok(task)) => {
                    let handler = task.established_peer_handler();
                    handshake_manager
                        .lock()
                        .await
                        .set_established_peer_handler(handler);
                    Some(task)
                }
                Ok(Err(err)) => {
                    crate::tprintln!("Network walker could not start: {err}");
                    None
                }
                Err(_) => {
                    crate::teprintln!(
                        "[walker] startup exceeded {}s; continuing without the walker for this session",
                        WALKER_STARTUP_TIMEOUT.as_secs()
                    );
                    None
                }
            }
        }
        None => None,
    };
    if walk_task.is_some() {
        walker_stage.complete(None).await;
    } else {
        walker_stage.skip(Some("Walker unavailable".to_string())).await;
    }

    // Main-DHT subkey 10 advertises built-in capabilities and exact app names
    // used during the previous six months. Publication is event-driven when a
    // successful authentication changes the set, reconciled hourly, and forced
    // once per day so unchanged records still receive a fresh commit time.
    let application_info_stage = supervisor
        .stage_running(StartupStage::ApplicationInfo, None)
        .await;
    let mut public_capability_flags = CAPABILITY_PRIVATE_ROUTES
        | CAPABILITY_HANDSHAKE
        | CAPABILITY_REPUTATION
        | CAPABILITY_APP_AUTH;
    if walk_task.is_some() {
        public_capability_flags |= CAPABILITY_NETWORK_WALK;
    }
    if mailbox_manager.is_some() {
        public_capability_flags |= CAPABILITY_MAILBOX;
        if mailbox_participates_as_custodian {
            public_capability_flags |= CAPABILITY_MAILBOX_CUSTODIAN;
        }
    }

    let app_info_task = if let Some(runtime) = &main_dht_runtime {
        let mut last_published_apps = Vec::new();
        let mut last_app_info_publish_at = 0u64;
        crate::tprintln!("[user_dht] Publishing initial application advertisement (timeout={}s)...", APP_INFO_STARTUP_TIMEOUT.as_secs());
        match tokio::time::timeout(
            APP_INFO_STARTUP_TIMEOUT,
            reconcile_current_app_info(
                runtime,
                &identity_manager,
                app_directory_manager.as_ref(),
                public_capability_flags,
                &mut last_published_apps,
                &mut last_app_info_publish_at,
                true,
            ),
        )
        .await
        {
            Ok(Ok(_)) => application_info_stage.complete(None).await,
            Ok(Err(error)) => {
                crate::tprintln!("Warning: could not publish main-DHT app information: {error}");
                application_info_stage.fail(error.to_string()).await;
            }
            Err(_) => {
                crate::teprintln!(
                    "[user_dht] initial app advertisement exceeded {}s; background reconciliation will retry later",
                    APP_INFO_STARTUP_TIMEOUT.as_secs()
                );
                application_info_stage
                    .skip(Some("Initial app advertisement timed out; background retry scheduled".to_string()))
                    .await;
            }
        }

        let runtime = runtime.clone();
        let identities = identity_manager.clone();
        let app_directory = app_directory_manager.clone();
        let mut app_events = event_bus.subscribe();
        Some(tokio::spawn(async move {
            const RECONCILE_SECS: u64 = 60 * 60;
            const FORCE_REFRESH_SECS: u64 = 24 * 60 * 60;
            const EVENT_DEBOUNCE_SECS: u64 = 30;

            let mut ticker = tokio::time::interval(Duration::from_secs(RECONCILE_SECS));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Startup reconciliation above is the first tick.
            ticker.tick().await;

            loop {
                let event_triggered = tokio::select! {
                    _ = ticker.tick() => false,
                    received = app_events.recv() => {
                        match received {
                            Ok(envelope) if matches!(
                                envelope.event,
                                NetworkEvent::AppAuthenticated { .. }
                                    | NetworkEvent::AppRegistrationChanged { .. }
                            ) => true,
                            Ok(_) => continue,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => true,
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                };

                if event_triggered {
                    tokio::time::sleep(Duration::from_secs(EVENT_DEBOUNCE_SECS)).await;
                    // Collapse a burst of app startups/authentications into one
                    // comparison and at most one DHT write.
                    while app_events.try_recv().is_ok() {}
                }

                let now = current_timestamp();
                let force = now.saturating_sub(last_app_info_publish_at) >= FORCE_REFRESH_SECS;
                if let Err(error) = reconcile_current_app_info(
                    &runtime,
                    &identities,
                    app_directory.as_ref(),
                    public_capability_flags,
                    &mut last_published_apps,
                    &mut last_app_info_publish_at,
                    force,
                )
                .await
                {
                    crate::teprintln!("[user_dht] Could not refresh app advertisement: {error}");
                }
            }
        }))
    } else {
        application_info_stage
            .skip(Some("No main-DHT runtime".to_string()))
            .await;
        None
    };

    let background_services_stage = supervisor
        .stage_running(StartupStage::BackgroundServices, None)
        .await;

    let initial_walk_settings = match auth
        .read_user_encrypted::<WalkSettings>(&session, WALK_SETTINGS_STORE_KEY)
    {
        Ok(Some(settings)) => settings.sanitized(),
        Ok(None) => WalkSettings::default(),
        Err(error) => {
            crate::tprintln!(
                "Could not load saved walk settings; using defaults: {error}"
            );
            WalkSettings::default()
        }
    };

    let automatic_walk = walk_task.as_ref().map(|walker| {
        let subscribers: Vec<Arc<dyn WalkSubscriber>> = mailbox_manager
            .as_ref()
            .map(|mailbox| {
                let subscriber: Arc<dyn WalkSubscriber> = mailbox.clone();
                vec![subscriber]
            })
            .unwrap_or_default();
        spawn_auto_walk_scheduler(
            walker.clone(),
            subscribers,
            supervisor.walk_policy(),
            initial_walk_settings,
            event_bus.clone(),
        )
    });

    // Bridge the mailbox actor's domain events into the common event stream.
    // Its explicit RequestWalk event is the one non-periodic automatic-walk
    // trigger: unhealthy mailbox coverage requests a walk through the central
    // scheduler, which deduplicates work and enforces the five-minute cooldown.
    let mailbox_event_task = mailbox_manager.as_ref().map(|mailbox| {
        let mut mailbox_events = mailbox.subscribe();
        let events = event_bus.clone();
        let auto_walk = automatic_walk.clone();
        tokio::spawn(async move {
            loop {
                match mailbox_events.recv().await {
                    Ok(MailboxEvent::RequestWalk(request)) => {
                        let detail = match request {
                            MailboxWalkRequest::RetrieveOurMail => {
                                "retrieve our mail".to_string()
                            }
                            MailboxWalkRequest::MaintenanceTargets(targets) => {
                                format!("refresh {} mailbox maintenance target(s)", targets.len())
                            }
                        };
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Notice,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "walk requested".to_string(),
                                detail,
                            },
                        );
                        if let Some(auto_walk) = &auto_walk {
                            let _ = auto_walk
                                .request(WalkReason::MailboxCoverageUnhealthy)
                                .await;
                        }
                    }
                    Ok(MailboxEvent::MailDiscovered(pointer)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Info,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "mail discovered".to_string(),
                                detail: format!(
                                    "message={} sender={}",
                                    hex::encode(pointer.message_id),
                                    pointer.sender_main_dht
                                ),
                            },
                        );
                    }
                    Ok(MailboxEvent::ServiceRequestDiscovered(request)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Info,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "service request discovered".to_string(),
                                detail: format!(
                                    "request={} requester={} host={} expires={}",
                                    hex::encode(request.request_id),
                                    request.requester_main_dht,
                                    request.intended_host_main_dht,
                                    request.expires_at,
                                ),
                            },
                        );
                    }
                    Ok(MailboxEvent::OutgoingSeeded(pointer)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Notice,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "outgoing mail self-posted".to_string(),
                                detail: format!(
                                    "message={} recipient seed stored in our mailbox",
                                    hex::encode(pointer.message_id),
                                ),
                            },
                        );
                    }
                    Ok(MailboxEvent::MailDecrypted(message)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Notice,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "mail decrypted".to_string(),
                                detail: format!(
                                    "message={} application={}",
                                    hex::encode(message.message.message_id),
                                    message.application_id
                                ),
                            },
                        );
                    }
                    Ok(MailboxEvent::ResponseDiscovered(response)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Info,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "response discovered".to_string(),
                                detail: format!("{:?}", response),
                            },
                        );
                    }
                    Ok(MailboxEvent::ObservationReportUpdated(report)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Info,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "replication observation updated".to_string(),
                                detail: format!(
                                    "message={} health={:.3}",
                                    hex::encode(report.message_id),
                                    report.replication_health_score
                                ),
                            },
                        );
                    }
                    Ok(MailboxEvent::MailboxAdvertisementChanged(advertisement)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Info,
                            network_events::NetworkEvent::MailboxActivity {
                                activity: "advertisement changed".to_string(),
                                detail: format!("{:?}", advertisement),
                            },
                        );
                    }
                    Ok(MailboxEvent::Warning(reason)) => {
                        events.emit(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Warning,
                            network_events::NetworkEvent::MailOperationFailed {
                                operation: "mailbox background task".to_string(),
                                reason,
                                duration_ms: 0,
                            },
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        events.diagnostic(
                            network_events::NetworkEventSource::Mailbox,
                            network_events::EventSeverity::Warning,
                            format!("Mailbox event bridge skipped {skipped} event(s)"),
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    });
    background_services_stage.complete(None).await;

    // App-owned DHT stores and daemon-held signing identities are loaded once
    // per account and shared by every authenticated local API connection.
    let app_storage_manager = match AppStorageManager::load(
        auth.clone(),
        session.clone(),
        background.clone(),
    ) {
        Ok(manager) => Some(manager),
        Err(error) => {
            crate::teprintln!("[api] App storage service unavailable: {error}");
            None
        }
    };
    let blob_store_manager = app_storage_manager.clone().and_then(|storage| {
        match BlobStoreManager::load(auth.clone(), session.clone(), storage) {
            Ok(manager) => Some(manager),
            Err(error) => {
                crate::teprintln!("[api] Blob store service unavailable: {error}");
                None
            }
        }
    });
    let app_signing_manager = match AppSigningManager::load(auth.clone(), session.clone()) {
        Ok(manager) => Some(manager),
        Err(error) => {
            crate::teprintln!("[api] App signing service unavailable: {error}");
            None
        }
    };

    // Local-only encrypted app vault. It is scoped to this signed-in account/profile,
    // while each API request is further scoped to the authenticated APP_ID.
    let private_app_storage_manager = match PrivateAppStorageManager::load(auth.clone(), session.clone()) {
        Ok(manager) => {
            crate::tprintln!("[private-storage] Encrypted private application storage ready.");
            Some(manager)
        }
        Err(error) => {
            crate::teprintln!("[private-storage] Private application storage unavailable: {error}");
            None
        }
    };

    let app_visible_names = match AppVisibleNameManager::load(auth.clone(), session.clone()) {
        Ok(manager) => manager,
        Err(error) => {
            crate::teprintln!(
                "[api] App-visible name store could not be loaded: {error}; using a temporary default"
            );
            AppVisibleNameManager::temporary(auth.clone(), session.clone())
        }
    };

    // One daemon-owned gossip manager is shared by local IPC and the built-in
    // two-node diagnostic. Application partitions (including the diagnostic
    // partition) are still activated lazily when they are actually used.
    let gossip_manager = GossipManager::new(
        handshake_manager.clone(),
        walk_task.clone(),
        our_dht_key.clone(),
    );

    // Daemon-owned distributed lexical library. It reuses managed gossip for
    // live hints and owns per-app DHT snapshots for offline librarian access.
    let lexical_library_manager = match main_dht_runtime.clone() {
        Some(runtime) => {
            crate::tprintln!("[lexical] Starting distributed lexical library (timeout={}s)...", LEXICAL_STARTUP_TIMEOUT.as_secs());
            match tokio::time::timeout(
                LEXICAL_STARTUP_TIMEOUT,
                LexicalLibraryManager::load(
                    auth.clone(),
                    session.clone(),
                    background.clone(),
                    runtime,
                    gossip_manager.clone(),
                    walk_task.clone(),
                    our_dht_key.clone(),
                ),
            )
            .await
            {
                Ok(Ok(manager)) => {
                    manager.start_background().await;
                    Some(manager)
                }
                Ok(Err(error)) => {
                    crate::teprintln!("[lexical] Distributed lexical library unavailable: {error}");
                    None
                }
                Err(_) => {
                    crate::teprintln!(
                        "[lexical] startup exceeded {}s; continuing without the distributed lexical library for this session",
                        LEXICAL_STARTUP_TIMEOUT.as_secs()
                    );
                    None
                }
            }
        }
        None => None,
    };

    // Start the local application API. On Windows this is a named pipe; Unix
    // builds use an equivalent Unix-domain socket with the same JSON-lines
    // protocol. Apps must still complete IdentityManager authentication before
    // accessing status/events or future networking operations.
    let local_api_endpoint = default_endpoint(session.username());
    let endpoint = local_api_endpoint.clone();
    let local_api = match spawn_local_api(
        endpoint.clone(),
        supervisor.clone(),
        identity_manager.clone(),
        mailbox_manager.clone(),
        walk_task.clone(),
        handshake_manager.clone(),
        session.username().to_string(),
        session.network_profile_id().to_string(),
        our_dht_key.clone(),
        reputation_manager.clone(),
        app_directory_manager.clone(),
        app_storage_manager.clone(),
        private_app_storage_manager.clone(),
        blob_store_manager.clone(),
        app_signing_manager.clone(),
        gossip_manager.clone(),
        lexical_library_manager.clone(),
        app_visible_names.clone(),
    ) {
        Ok(handle) => {
            crate::tprintln!("[api] Local application API listening at {}", handle.endpoint());
            crate::tprintln!(
                "[startup] Local application API ready after {} ms total",
                startup_started.elapsed().as_millis()
            );
            Some(handle)
        }
        Err(error) => {
            crate::teprintln!("[api] Could not start local application API at {endpoint}: {error}");
            None
        }
    };

    // Register shutdown work by declared resource requirement. Registration order no longer
    // controls shutdown order; Lifecycle is the single executor and derives sequencing from
    // HookSpec.
    {
        let node = node.clone();
        supervisor
            .register_shutdown_hook(
                HookSpec::teardown("node/veilid").detail("detach and stop Veilid"),
                move |progress| {
                    let node = node.clone();
                    async move {
                        progress.step("detaching and stopping Veilid");
                        node.shutdown().await;
                        progress.step("Veilid stopped");
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(lexical) = lexical_library_manager.clone() {
        supervisor
            .register_shutdown_hook(
                HookSpec::new("lexical/library", ResourceNeed::Network)
                    .detail("flush lexical epochs/pages and stop lexical gossip")
                    .budget(Duration::from_secs(10)),
                move |progress| {
                    let lexical = lexical.clone();
                    async move {
                        progress.step("stopping lexical background work");
                        progress.fragile("committing dirty lexical DHT pages");
                        lexical.shutdown().await.map_err(|error| error.to_string())?;
                        progress.settled("lexical library committed");
                        Ok(())
                    }
                },
            )
            .await;
    }
    {
        let background = background.clone();
        let auth = auth.clone();
        let session = session.clone();
        supervisor
            .register_shutdown_hook(
                HookSpec::new("dht/snapshot", ResourceNeed::Storage)
                    .detail("save owned DHT snapshot"),
                move |progress| {
                    let background = background.clone();
                    let auth = auth.clone();
                    let session = session.clone();
                    async move {
                        progress.step("exporting DHT snapshot");
                        let snapshot = background.export_snapshot().await;
                        let count = snapshot.len();
                        progress.fragile("writing encrypted DHT snapshot");
                        user_dht::persist_dht_snapshot(&auth, &session, &snapshot)
                            .map_err(|error| error.to_string())?;
                        progress.settled(format!("DHT snapshot committed ({count} record(s))"));
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(runtime) = main_dht_runtime.clone() {
        let heartbeat_runtime = runtime.clone();
        supervisor
            .register_shutdown_hook(
                HookSpec::new("presence/heartbeat", ResourceNeed::None)
                    .detail("stop presence heartbeat")
                    .budget(lifecycle::budget::INTAKE),
                move |progress| {
                    let runtime = heartbeat_runtime.clone();
                    async move {
                        progress.step("stopping presence heartbeat");
                        runtime
                            .stop_heartbeat()
                            .await
                            .map_err(|error| error.to_string())?;
                        progress.step("presence heartbeat stopped");
                        Ok(())
                    }
                },
            )
            .await;

        supervisor
            .register_shutdown_hook(
                HookSpec::new("presence/offline", ResourceNeed::Network)
                    .detail("publish final offline presence")
                    .budget(lifecycle::budget::ANNOUNCE),
                move |progress| {
                    let runtime = runtime.clone();
                    async move {
                        progress.step("publishing final offline presence");
                        runtime
                            .publish_offline()
                            .await
                            .map_err(|error| error.to_string())?;
                        progress.step("offline presence published");
                        Ok(())
                    }
                },
            )
            .await;
    }
    {
        let node = node.clone();
        supervisor
            .register_shutdown_hook(
                HookSpec::new("presence/attachment-observer", ResourceNeed::VeilidNode)
                    .detail("disable attachment callbacks"),
                move |progress| {
                    let node = node.clone();
                    async move {
                        progress.step("clearing attachment callback");
                        node.clear_attachment_handler();
                        progress.step("attachment callback cleared");
                        Ok(())
                    }
                },
            )
            .await;
    }
    {
        let reputation_manager = reputation_manager.clone();
        supervisor
            .register_shutdown_hook(
                HookSpec::new("reputation", ResourceNeed::Storage)
                    .detail("persist reputation state"),
                move |progress| {
                    let reputation_manager = reputation_manager.clone();
                    async move {
                        progress.fragile("persisting reputation state");
                        reputation_manager
                            .shutdown()
                            .await
                            .map_err(|error| error.to_string())?;
                        progress.settled("reputation state persisted");
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(task) = reputation_event_task {
        let task = Arc::new(tokio::sync::Mutex::new(Some(task)));
        supervisor
            .register_shutdown_hook(
                HookSpec::new("events/reputation-bridge", ResourceNeed::None),
                move |progress| {
                    let task = task.clone();
                    async move {
                        progress.step("stopping reputation event bridge");
                        if let Some(task) = task.lock().await.take() {
                            task.abort();
                            let _ = task.await;
                        }
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(mailbox) = mailbox_manager.clone() {
        supervisor
            .register_shutdown_hook(
                HookSpec::new("mailbox", ResourceNeed::VeilidNode)
                    .detail("flush and stop mailbox")
                    .budget(Duration::from_secs(15)),
                move |progress| {
                    let mailbox = mailbox.clone();
                    async move {
                        progress.fragile("flushing pending mailbox writes");
                        mailbox.shutdown().await.map_err(|error| error.to_string())?;
                        progress.settled("mailbox stopped");
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(walker) = walk_task.clone() {
        supervisor
            .register_shutdown_hook(
                HookSpec::new("walker", ResourceNeed::VeilidNode)
                    .detail("stop network walker")
                    .budget(Duration::from_secs(6)),
                move |progress| {
                    let walker = walker.clone();
                    async move {
                        progress.step("stopping network walker");
                        walker.shutdown().await.map_err(|error| error.to_string())?;
                        progress.step("network walker stopped");
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(auto_walk) = automatic_walk.clone() {
        supervisor
            .register_shutdown_hook(
                HookSpec::new("walk/automatic-scheduler", ResourceNeed::None)
                    .continue_after_timeout(),
                move |progress| {
                    let auto_walk = auto_walk.clone();
                    async move {
                        progress.step("stopping automatic walk scheduler");
                        auto_walk.shutdown().await;
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(task) = mailbox_event_task {
        let task = Arc::new(tokio::sync::Mutex::new(Some(task)));
        supervisor
            .register_shutdown_hook(
                HookSpec::new("events/mailbox-bridge", ResourceNeed::None),
                move |progress| {
                    let task = task.clone();
                    async move {
                        progress.step("stopping mailbox event bridge");
                        if let Some(task) = task.lock().await.take() {
                            task.abort();
                            let _ = task.await;
                        }
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(task) = app_info_task {
        let task = Arc::new(tokio::sync::Mutex::new(Some(task)));
        supervisor
            .register_shutdown_hook(
                HookSpec::new("app/advertisement-publisher", ResourceNeed::None),
                move |progress| {
                    let task = task.clone();
                    async move {
                        progress.step("stopping application advertisement publisher");
                        if let Some(task) = task.lock().await.take() {
                            task.abort();
                            let _ = task.await;
                        }
                        Ok(())
                    }
                },
            )
            .await;
    }
    if let Some(local_api) = local_api.clone() {
        supervisor
            .register_shutdown_hook(
                HookSpec::new("api/local", ResourceNeed::None).detail("stop local application API"),
                move |progress| {
                    let local_api = local_api.clone();
                    async move {
                        progress.step("stopping local application API intake");
                        local_api.shutdown().await;
                        progress.step("local application API stopped");
                        Ok(())
                    }
                },
            )
            .await;
    }

    if let Err(error) = supervisor.mark_ready().await {
        crate::tprintln!("Network core startup is incomplete: {error}");
        crate::tprintln!("The administration console will remain available for diagnostics and shutdown.");
    }
    let dashboard = if gui_bridge_mode {
        None
    } else {
        match ConsoleDashboard::start(supervisor.status().await) {
            Ok(dashboard) => Some(dashboard),
            Err(error) => {
                crate::tprintln!("Could not start three-region console; using the basic console: {error}");
                None
            }
        }
    };
    let dashboard_event_task = dashboard.as_ref().map(|dashboard| {
        let sender = dashboard.sender();
        let mut events = supervisor.subscribe();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => sender.send_event(event),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        })
    });

    // Console infrastructure intentionally outlives Veilid so it can display the complete
    // network shutdown. It is still lifecycle-owned rather than being a second ad-hoc cleanup
    // path after supervisor.shutdown().
    let dashboard = Arc::new(tokio::sync::Mutex::new(dashboard));
    let dashboard_event_task = Arc::new(tokio::sync::Mutex::new(dashboard_event_task));
    {
        let dashboard = dashboard.clone();
        let dashboard_event_task = dashboard_event_task.clone();
        supervisor
            .register_shutdown_hook(
                HookSpec::after_teardown("ui/dashboard").detail("stop console event bridge and dashboard"),
                move |progress| {
                    let dashboard = dashboard.clone();
                    let dashboard_event_task = dashboard_event_task.clone();
                    async move {
                        progress.step("stopping dashboard event bridge");
                        if let Some(task) = dashboard_event_task.lock().await.take() {
                            task.abort();
                            let _ = task.await;
                        }
                        progress.step("stopping console dashboard");
                        if let Some(dashboard) = dashboard.lock().await.take() {
                            dashboard.shutdown();
                        }
                        progress.step("console dashboard stopped");
                        Ok(())
                    }
                },
            )
            .await;
    }

    crate::tprintln!("Main is still running.");
    crate::tprintln!("Administration console ready.");
    if gui_bridge_mode {
        print_gui_walk_settings(initial_walk_settings);
        crate::tprintln!("[gui] READY");
        #[cfg(any(target_os = "android", target_os = "ios"))]
        mobile_bridge::mark_command_loop_ready();
    }

    let stop_reason = StopReason::Shutdown;
    loop {
        if !gui_bridge_mode && !console_ui::is_active() {
            print_basic_command_menu();
        }
        let choice = read_line("Command: ");
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if mobile_bridge::is_stop_sentinel(&choice) {
            crate::tprintln!("Mobile host stop requested.");
            break;
        }
        let command = choice.trim();



        if command.eq_ignore_ascii_case("profile-list") {
            match auth.list_network_profiles(&session) {
                Ok(profiles) => {
                    crate::tprintln!(
                        "Active network profile: {} ({})",
                        session.network_profile().display_name,
                        session.network_profile_id()
                    );
                    for profile in profiles {
                        crate::tprintln!(
                            "  {}  {}{}",
                            profile.profile_id,
                            profile.display_name,
                            if profile.is_retired() { " [retired]" } else { "" }
                        );
                    }
                }
                Err(error) => crate::tprintln!("Could not list profiles: {error}"),
            }
            continue;
        }

        if let Some(name) = command.strip_prefix("profile-create ") {
            match auth.create_network_profile(&session, name) {
                Ok(profile) => crate::tprintln!(
                    "Created profile '{}' ({}). Use 'profile-use {}' and restart the daemon to activate it.",
                    profile.display_name,
                    profile.profile_id,
                    profile.profile_id
                ),
                Err(error) => crate::tprintln!("Could not create profile: {error}"),
            }
            continue;
        }

        if let Some(profile_id) = command.strip_prefix("profile-use ") {
            match auth.select_network_profile(&session, profile_id.trim()) {
                Ok(profile_session) => crate::tprintln!(
                    "Profile '{}' ({}) will be active after a controlled daemon restart. Existing services were not hot-swapped.",
                    profile_session.network_profile().display_name,
                    profile_session.network_profile_id()
                ),
                Err(error) => crate::tprintln!("Could not select profile: {error}"),
            }
            continue;
        }

        if let Some(profile_id) = command.strip_prefix("profile-retire ") {
            match auth.retire_network_profile(&session, profile_id.trim()) {
                Ok(profile) => crate::tprintln!(
                    "Retired profile '{}' ({}). Its encrypted local data was retained for recovery/export.",
                    profile.display_name,
                    profile.profile_id
                ),
                Err(error) => crate::tprintln!("Could not retire profile: {error}"),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("app-name") {
            let snapshot = app_visible_names.snapshot().await;
            // Machine-readable marker used by the consumer GUIs. Hex keeps Unicode names
            // and spaces unambiguous without exposing the login username.
            crate::tprintln!(
                "GUI_APP_VISIBLE_NAME_HEX={}",
                hex::encode(snapshot.default_name.as_bytes())
            );
            crate::tprintln!("Default application-visible name: {}", snapshot.default_name);
            if snapshot.per_app.is_empty() {
                crate::tprintln!("Per-app aliases: none");
            } else {
                crate::tprintln!("Per-app aliases:");
                for (app_id, name) in snapshot.per_app {
                    crate::tprintln!("  {app_id} -> {name}");
                }
            }
            crate::tprintln!(
                "Use: app-name default <name> | app-name set <app-id> <name> | app-name clear <app-id>"
            );
            continue;
        }

        if let Some(arguments) = command.strip_prefix("app-name ") {
            let mut parts = arguments.trim().splitn(3, char::is_whitespace);
            let operation = parts.next().unwrap_or_default();
            let target = parts.next().unwrap_or_default();
            let remainder = parts.next().unwrap_or_default().trim();

            let result = match operation {
                "default" => {
                    let mut full_name = target.to_string();
                    if !remainder.is_empty() {
                        if !full_name.is_empty() {
                            full_name.push(' ');
                        }
                        full_name.push_str(remainder);
                    }
                    app_visible_names.set_default(full_name).await
                }
                "set" => match AppId::new(target.to_string()) {
                    Ok(app_id) => app_visible_names.set_for_app(&app_id, remainder).await,
                    Err(error) => {
                        crate::tprintln!("Invalid application id: {error}");
                        continue;
                    }
                },
                "clear" => match AppId::new(target.to_string()) {
                    Ok(app_id) => app_visible_names.clear_for_app(&app_id).await,
                    Err(error) => {
                        crate::tprintln!("Invalid application id: {error}");
                        continue;
                    }
                },
                _ => {
                    crate::tprintln!(
                        "Use: app-name default <name> | app-name set <app-id> <name> | app-name clear <app-id>"
                    );
                    continue;
                }
            };
            match result {
                Ok(()) => crate::tprintln!("Application-visible name settings saved."),
                Err(error) => crate::tprintln!("Could not save application-visible name: {error}"),
            }
            continue;
        }

        if let Some(path) = command.strip_prefix("backup-local ") {
            let passphrase = read_line("Backup passphrase (at least 8 characters): ");
            let confirmation = read_line("Repeat backup passphrase: ");
            if passphrase != confirmation {
                crate::tprintln!("Backup passphrases did not match.");
            } else {
                match auth.export_local_backup(&session, path.trim(), &passphrase) {
                    Ok(metadata) => crate::tprintln!(
                        "Encrypted local backup written for '{}' ({} files, {} bytes).",
                        metadata.username,
                        metadata.file_count,
                        metadata.total_plaintext_bytes
                    ),
                    Err(error) => crate::tprintln!("Could not create local backup: {error}"),
                }
            }
            continue;
        }

        if let Some(path) = command.strip_prefix("backup-inspect ") {
            let passphrase = read_line("Backup passphrase: ");
            match auth.inspect_local_backup(path.trim(), &passphrase) {
                Ok(metadata) => crate::tprintln!(
                    "Backup version {} for '{}' created at {}; {} files, {} bytes.",
                    metadata.format_version,
                    metadata.username,
                    metadata.created_at,
                    metadata.file_count,
                    metadata.total_plaintext_bytes
                ),
                Err(error) => crate::tprintln!("Could not inspect backup: {error}"),
            }
            continue;
        }

        if let Some(path) = command.strip_prefix("recovery-upload ") {
            match recovery::upload_backup(&auth, &session, &background, path.trim()).await {
                Ok(upload) => {
                    crate::tprintln!(
                        "Network recovery backup committed to {} in {} chunk(s).",
                        upload.record_key,
                        upload.chunk_count
                    );
                    crate::tprintln!("RECOVERY CODE (store this privately): {}", upload.recovery_code);
                }
                Err(error) => crate::tprintln!("Could not upload network recovery backup: {error}"),
            }
            continue;
        }

        if let Some(arguments) = command.strip_prefix("recovery-download ") {
            let mut parts = arguments.splitn(2, char::is_whitespace);
            let code = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default().trim();
            if code.is_empty() || path.is_empty() {
                crate::tprintln!("Usage: recovery-download <VKR1|...|...> <output.veilknit-backup>");
            } else {
                match recovery::download_backup(&background, code, path).await {
                    Ok(()) => crate::tprintln!(
                        "Network recovery archive downloaded to {path}. Restart and choose Restore on the login screen."
                    ),
                    Err(error) => crate::tprintln!("Could not download network recovery backup: {error}"),
                }
            }
            continue;
        }

        if command.eq_ignore_ascii_case("recovery-status") {
            match recovery::local_recovery_state(&auth, &session) {
                Ok(Some(state)) => crate::tprintln!(
                    "Network recovery record: {} ({} chunks, updated {})",
                    state.record_key,
                    state.chunk_count,
                    state.updated_at
                ),
                Ok(None) => crate::tprintln!("No network recovery record is configured."),
                Err(error) => crate::tprintln!("Could not read recovery status: {error}"),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("recovery-wipe") {
            let confirmation = read_line("Type WIPE to replace the network recovery data with tombstones: ");
            if confirmation == "WIPE" {
                match recovery::wipe_network_backup(&auth, &session, &background).await {
                    Ok(()) => crate::tprintln!("The latest network recovery record was wiped."),
                    Err(error) => crate::tprintln!("Could not wipe network recovery data: {error}"),
                }
            } else {
                crate::tprintln!("Network recovery wipe cancelled.");
            }
            continue;
        }

        if command.eq_ignore_ascii_case("lex-test-set") {
            crate::tprintln!("Usage: lex-test-set <words/text...>");
            continue;
        }
        if let Some(arguments) = command.strip_prefix("lex-test-set ") {
            let Some(lexical) = lexical_library_manager.as_ref() else { crate::tprintln!("[lex-test] lexical library service is unavailable"); continue; };
            let object_hash = blake3::hash(our_dht_key.as_bytes());
            let object_id = format!("lex-test-node-{}", hex::encode(&object_hash.as_bytes()[..8]));
            match lexical.observe(LEXICAL_TEST_APPLICATION_ID, LexicalObserveRequest {
                library_name: LEXICAL_TEST_LIBRARY_NAME.to_string(), layer: LEXICAL_TEST_LAYER.to_string(),
                object_id, generation: current_timestamp_millis(), field_id: "diagnostic_text".to_string(),
                text: Some(arguments.to_string()), pretokenized_terms: Vec::new(), authoritative_pointer: Some(our_dht_key.clone()), publish_posting_hint: true,
            }).await {
                Ok(result) => crate::tprintln!("[lex-test] observed {} word(s), {} unique, {} association edge(s), {} subword token(s); library={} epoch={}", result.words_observed, result.unique_words, result.associations_observed, result.subword_tokens, result.library_id.hex(), result.current_epoch),
                Err(error) => crate::tprintln!("[lex-test] observation failed: {error}"),
            }
            continue;
        }
        if command.eq_ignore_ascii_case("lex-test-search") { crate::tprintln!("Usage: lex-test-search <word> [word ...]"); continue; }
        if let Some(arguments) = command.strip_prefix("lex-test-search ") {
            let Some(lexical) = lexical_library_manager.as_ref() else { crate::tprintln!("[lex-test] lexical library service is unavailable"); continue; };
            let terms = parse_gossip_test_terms(arguments);
            if terms.is_empty() { crate::tprintln!("Usage: lex-test-search <word> [word ...]"); continue; }
            match lexical.search(LEXICAL_TEST_APPLICATION_ID, LEXICAL_TEST_LIBRARY_NAME, LEXICAL_TEST_LAYER, &terms, LEXICAL_ACTIVE_WINDOW_DAYS, true).await {
                Ok(result) => {
                    crate::tprintln!("[lex-test] {} term(s); gossip peers contacted={} durable libraries consulted={} candidate object(s)={}", result.terms.len(), result.gossip_peers_contacted, result.dht_libraries_consulted, result.candidates.len());
                    for (term, view) in terms.iter().zip(&result.words) {
                        crate::tprintln!("  word='{}' id={} prevalence={:.4} ({:.1}/{:.1}) rarity={:.3} specificity={:.3} confidence={:.3} utility={:.3} sources={}", term, view.word_id.short_hex(), view.stats.prevalence, view.stats.estimated_objects_containing_word, view.stats.estimated_universe_objects, view.stats.rarity_normalized, view.stats.specificity, view.stats.evidence_confidence, view.stats.search_utility, view.sources_consulted);
                        for neighbor in view.neighbors.iter().take(6) { crate::tprintln!("      {} {} distance={} conditional={:.3} support≈{:.1} confidence={:.3}", neighbor.direction, neighbor.word_id.short_hex(), neighbor.distance, neighbor.conditional_probability, neighbor.estimated_distinct_objects, neighbor.confidence); }
                    }
                    for (index, candidate) in result.candidates.iter().take(12).enumerate() { crate::tprintln!("  candidate[{}] origin={} object={} generation={} matched={} pointer={}", index+1, candidate.origin_main_dht, candidate.object_id, candidate.generation, candidate.matched_words, candidate.authoritative_pointer.as_deref().unwrap_or("<none>")); }
                }
                Err(error) => crate::tprintln!("[lex-test] search failed: {error}"),
            }
            continue;
        }
        if let Some(arguments) = command.strip_prefix("lex-test-compare ") {
            let Some(lexical) = lexical_library_manager.as_ref() else { crate::tprintln!("[lex-test] lexical library service is unavailable"); continue; };
            let mut terms=arguments.split_whitespace();let left=terms.next().unwrap_or_default();let right=terms.next().unwrap_or_default();
            if left.is_empty()||right.is_empty(){crate::tprintln!("Usage: lex-test-compare <word-a> <word-b>");}else{let score=lexical.compare_terms(left,right);crate::tprintln!("[lex-test] compare '{}' vs '{}': exact={:.3} normalized={:.3} edit={:.3} accent={:.3} translit={:.3} visual={:.3} combined={:.3}",left,right,score.exact,score.normalized,score.edit,score.accent_fold,score.transliteration,score.visual,score.combined);}
            continue;
        }
        if command.eq_ignore_ascii_case("lex-test-stats") {
            let Some(lexical)=lexical_library_manager.as_ref() else{crate::tprintln!("[lex-test] lexical library service is unavailable");continue;};
            match lexical.stats(LEXICAL_TEST_APPLICATION_ID,LEXICAL_TEST_LIBRARY_NAME).await{Ok(stats)=>crate::tprintln!("[lex-test] stats: {stats:?}"),Err(error)=>crate::tprintln!("[lex-test] stats failed: {error}")}
            continue;
        }

        if command.eq_ignore_ascii_case("gossip-test-set") {
            crate::tprintln!("Usage: gossip-test-set <word> [word ...]");
            continue;
        }

        if let Some(arguments) = command.strip_prefix("gossip-test-set ") {
            let terms = parse_gossip_test_terms(arguments);
            if terms.is_empty() {
                crate::tprintln!("Usage: gossip-test-set <word> [word ...]");
            } else {
                match derive_index_tokens(
                    GOSSIP_TEST_APPLICATION_ID,
                    GOSSIP_TEST_NAMESPACE,
                    GOSSIP_TEST_INDEX_NAME,
                    terms.iter().map(String::as_str),
                ) {
                    Ok(index_tokens) => {
                        let object_hash = blake3::hash(our_dht_key.as_bytes());
                        let object_id = format!(
                            "node-{}",
                            hex::encode(&object_hash.as_bytes()[..8])
                        );
                        let request = GossipPublishRequest {
                            namespace: GOSSIP_TEST_NAMESPACE.to_string(),
                            object_id,
                            generation: current_timestamp_millis(),
                            authoritative_pointer: None,
                            fingerprints: Vec::new(),
                            index_tokens: index_tokens.clone(),
                            custom_payload: Vec::new(),
                            flags: 0,
                            ttl_seconds: GOSSIP_DEFAULT_TTL_SECS,
                        };
                        match gossip_manager
                            .publish(GOSSIP_TEST_APPLICATION_ID, request)
                            .await
                        {
                            Ok(hit) => {
                                crate::tprintln!(
                                    "[gossip-test] published {} word(s) as {} opaque token(s); object={} generation={}",
                                    terms.len(),
                                    index_tokens.len(),
                                    hit.record.object_id,
                                    hit.record.generation,
                                );
                                crate::tprintln!(
                                    "[gossip-test] words stay local; first token={} (search peers derive the same scoped digest)",
                                    index_tokens
                                        .first()
                                        .map(|token| hex::encode(token.digest))
                                        .unwrap_or_else(|| "<none>".to_string())
                                );
                            }
                            Err(error) => crate::tprintln!("[gossip-test] publish failed: {error}"),
                        }
                    }
                    Err(error) => crate::tprintln!("[gossip-test] invalid words/index: {error}"),
                }
            }
            continue;
        }

        if command.eq_ignore_ascii_case("gossip-test-search") {
            crate::tprintln!("Usage: gossip-test-search <word> [word ...]");
            continue;
        }

        if let Some(arguments) = command.strip_prefix("gossip-test-search ") {
            let terms = parse_gossip_test_terms(arguments);
            if terms.is_empty() {
                crate::tprintln!("Usage: gossip-test-search <word> [word ...]");
            } else {
                match derive_index_tokens(
                    GOSSIP_TEST_APPLICATION_ID,
                    GOSSIP_TEST_NAMESPACE,
                    GOSSIP_TEST_INDEX_NAME,
                    terms.iter().map(String::as_str),
                ) {
                    Ok(tokens) => {
                        let query = GossipSearchQuery {
                            namespace: GOSSIP_TEST_NAMESPACE.to_string(),
                            probes: Vec::new(),
                            token_probes: vec![GossipTokenProbe {
                                tokens,
                                polarity: GossipTokenPolarity::Required,
                                match_mode: GossipTokenMatchMode::All,
                                weight: 100,
                            }],
                            limit: 16,
                            min_score_milli: None,
                            include_withdrawn: false,
                        };
                        match gossip_manager
                            .search(GOSSIP_TEST_APPLICATION_ID, query, true, 750)
                            .await
                        {
                            Ok((query_id, contacted, hits)) => {
                                crate::tprintln!(
                                    "[gossip-test] query={} contacted {} peer(s); {} matching hint(s)",
                                    query_id, contacted, hits.len()
                                );
                                for (index, hit) in hits.iter().enumerate() {
                                    crate::tprintln!(
                                        "  [{}] origin={} object={} generation={} tokens_matched={} verification={:?}",
                                        index + 1,
                                        hit.record.origin_main_dht,
                                        hit.record.object_id,
                                        hit.record.generation,
                                        hit.matched_index_tokens,
                                        hit.verification,
                                    );
                                }
                                if contacted == 0 {
                                    crate::tprintln!(
                                        "[gossip-test] no peers were available; run a normal walk on both nodes first so each has verified peers."
                                    );
                                }
                            }
                            Err(error) => crate::tprintln!("[gossip-test] search failed: {error}"),
                        }
                    }
                    Err(error) => crate::tprintln!("[gossip-test] invalid words/index: {error}"),
                }
            }
            continue;
        }

        if command.eq_ignore_ascii_case("gossip-test-list") {
            match gossip_manager
                .list_recent(GOSSIP_TEST_APPLICATION_ID, Some(GOSSIP_TEST_NAMESPACE), 32)
                .await
            {
                Ok(hits) => {
                    crate::tprintln!("[gossip-test] {} cached diagnostic object(s)", hits.len());
                    for (index, hit) in hits.iter().enumerate() {
                        crate::tprintln!(
                            "  [{}] origin={} object={} generation={} token_count={} verification={:?}",
                            index + 1,
                            hit.record.origin_main_dht,
                            hit.record.object_id,
                            hit.record.generation,
                            hit.record.index_tokens.len(),
                            hit.verification,
                        );
                    }
                }
                Err(error) => crate::tprintln!("[gossip-test] list failed: {error}"),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("gossip-test-stats") {
            match gossip_manager.stats(GOSSIP_TEST_APPLICATION_ID).await {
                Ok(stats) => crate::tprintln!("[gossip-test] stats: {stats:?}"),
                Err(error) => crate::tprintln!("[gossip-test] stats failed: {error}"),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("help") {
            print_command_help();
            continue;
        }

        if command.eq_ignore_ascii_case("headers") {
            match main_dht_index {
                Some(index) => print_own_headers(&background, index).await,
                None => crate::tprintln!("The main DHT is not available."),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("summary") {
            if gui_bridge_mode {
                print_gui_network_summary(walk_task.as_ref(), app_directory_manager.as_ref()).await;
                print_gui_app_summary(walk_task.as_ref()).await;
            } else {
                crate::tprintln!("The structured summary command is intended for the local GUI.");
            }
            continue;
        }

        if command.eq_ignore_ascii_case("walk-settings") {
            let settings = automatic_walk
                .as_ref()
                .map(|scheduler| scheduler.settings())
                .unwrap_or(initial_walk_settings);
            print_walk_settings(settings);
            if gui_bridge_mode {
                print_gui_walk_settings(settings);
            }
            continue;
        }

        if command.eq_ignore_ascii_case("walk-normal") {
            match &automatic_walk {
                Some(scheduler) => match scheduler.request(WalkReason::UserRequested).await {
                    Ok(()) => crate::tprintln!("Adaptive normal walk requested."),
                    Err(error) => crate::tprintln!("Could not request normal walk: {error}"),
                },
                None => crate::tprintln!("The automatic walk scheduler is not available."),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("walk-mail") {
            match &automatic_walk {
                Some(scheduler) => match scheduler.request(WalkReason::MailRequested).await {
                    Ok(()) => crate::tprintln!("Adaptive mail-mode walk requested."),
                    Err(error) => crate::tprintln!("Could not request mail-mode walk: {error}"),
                },
                None => crate::tprintln!("The automatic walk scheduler is not available."),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("walk-set")
            || command
                .get(..9)
                .map(|prefix| prefix.eq_ignore_ascii_case("walk-set "))
                .unwrap_or(false)
        {
            match parse_walk_settings_command(command) {
                Ok(settings) => match &automatic_walk {
                    Some(scheduler) => match scheduler.update_settings(settings) {
                        Ok(()) => {
                            let active = scheduler.settings();
                            match auth.write_user_encrypted(
                                &session,
                                WALK_SETTINGS_STORE_KEY,
                                &active,
                            ) {
                                Ok(()) => crate::tprintln!("Adaptive walk settings updated and saved."),
                                Err(error) => crate::tprintln!(
                                    "Walk settings are active but could not be saved: {error}"
                                ),
                            }
                            print_walk_settings(active);
                            if gui_bridge_mode {
                                print_gui_walk_settings(active);
                            }
                        }
                        Err(error) => crate::tprintln!("Could not update walk settings: {error}"),
                    },
                    None => crate::tprintln!("The automatic walk scheduler is not available."),
                },
                Err(error) => crate::tprintln!("Could not parse walk settings: {error}"),
            }
            continue;
        }
        if command.eq_ignore_ascii_case("mail")
            || command
                .get(..5)
                .map(|prefix| prefix.eq_ignore_ascii_case("mail "))
                .unwrap_or(false)
        {
            match &mailbox_manager {
                Some(mailbox) => handle_mail_command(mailbox, command).await,
                None => crate::tprintln!("The mailbox controller is not available."),
            }
            continue;
        }

        if command.eq_ignore_ascii_case("app-pending") {
            match &local_api {
                Some(api) => {
                    let pending = api.pending_registration_requests().await;
                    if gui_bridge_mode {
                        print_gui_pending_app_requests(&pending);
                    } else if pending.is_empty() {
                        crate::tprintln!("No application authorization requests are pending.");
                    } else {
                        crate::tprintln!("Pending application authorization requests:");
                        for request in &pending {
                            crate::tprintln!(
                                "  #{} | {} | {} | capabilities={:?}",
                                request.request_id,
                                request.app_id,
                                request.display_name,
                                request.requested_capabilities
                            );
                        }
                        crate::tprintln!("Approve with: app-approve <request-id>");
                        crate::tprintln!("Reject with:  app-reject <request-id> [reason]");
                    }
                }
                None => crate::tprintln!("The local application API is not running."),
            }
            continue;
        }

        if let Some(value) = command
            .strip_prefix("app-approve ")
            .or_else(|| command.strip_prefix("APP-APPROVE "))
        {
            let request_id = match value.trim().parse::<u64>() {
                Ok(request_id) => request_id,
                Err(_) => {
                    crate::tprintln!("Usage: app-approve <request-id>");
                    continue;
                }
            };
            match &local_api {
                Some(api) => match api.approve_registration(request_id).await {
                    Ok(request) => crate::tprintln!(
                        "Approved application #{}: {} ({}). The requesting app can now finish connecting.",
                        request.request_id,
                        request.app_id,
                        request.display_name
                    ),
                    Err(error) => crate::tprintln!("Could not approve application: {error}"),
                },
                None => crate::tprintln!("The local application API is not running."),
            }
            continue;
        }

        if let Some(value) = command
            .strip_prefix("app-reject ")
            .or_else(|| command.strip_prefix("APP-REJECT "))
        {
            let mut parts = value.trim().splitn(2, char::is_whitespace);
            let request_id = match parts.next().and_then(|part| part.parse::<u64>().ok()) {
                Some(request_id) => request_id,
                None => {
                    crate::tprintln!("Usage: app-reject <request-id> [reason]");
                    continue;
                }
            };
            let reason = parts.next().unwrap_or("rejected by the local user");
            match &local_api {
                Some(api) => match api.reject_registration(request_id, reason).await {
                    Ok(()) => crate::tprintln!("Rejected application request #{request_id}."),
                    Err(error) => crate::tprintln!("Could not reject application: {error}"),
                },
                None => crate::tprintln!("The local application API is not running."),
            }
            continue;
        }

        // Read-only reputation explanation for one public DHT identity. This
        // deliberately mirrors the automatic block diagnostic so a suspected
        // false positive can be inspected even when the peer is not currently
        // sending a handshake packet.
        {
            let mut parts = command.split_whitespace();
            if parts
                .next()
                .is_some_and(|part| part.eq_ignore_ascii_case("reputation"))
            {
                match parts.next() {
                    Some(subcommand) if subcommand.eq_ignore_ascii_case("explain") => {
                        let Some(peer_text) = parts.next() else {
                            crate::tprintln!("Usage: reputation explain <peer-dht-key>");
                            continue;
                        };
                        if parts.next().is_some() {
                            crate::tprintln!("Usage: reputation explain <peer-dht-key>");
                            continue;
                        }
                        let peer_key: RecordKey = match peer_text.parse() {
                            Ok(key) => key,
                            Err(error) => {
                                crate::tprintln!("Invalid peer DHT key: {error:?}");
                                continue;
                            }
                        };
                        crate::tprintln!(
                            "[reputation][diagnostic] context=manual_explain peer={} BEGIN",
                            peer_key
                        );
                        match reputation_user.get_diagnostic_report(peer_key).await {
                            Ok(report) => {
                                for line in report.lines() {
                                    crate::tprintln!("[reputation][diagnostic] {line}");
                                }
                            }
                            Err(error) => crate::teprintln!(
                                "[reputation][diagnostic] context=manual_explain report failed: {error}"
                            ),
                        }
                        crate::tprintln!(
                            "[reputation][diagnostic] context=manual_explain peer={} END",
                            peer_text
                        );
                    }
                    _ => crate::tprintln!("Usage: reputation explain <peer-dht-key>"),
                }
                continue;
            }
        }

        match command {
            "n" | "N" => {
                let name = read_line("Name for this DHT: ");
                let subkey_groups = read_subkey_groups();

                let total: u32 = subkey_groups.iter().map(|&n| n as u32).sum();

                crate::tprintln!(
                    "Trying to create DHT '{}' with {} owner group(s), {} subkeys total...",
                    name,
                    subkey_groups.len(),
                    total
                );

                match background.create_dht(name, subkey_groups).await {
                    Ok(index) => crate::tprintln!("Created DHT at index {}", index),
                    Err(err) => crate::tprintln!("Failed to create DHT: {:?}", err),
                }
            }

            "g" | "G" => {
                let index = read_index("Index of DHT to inspect: ");
                match background.get_dht_info(index).await {
                    Some(package) => {
                        let subkey_count: u32 = package
                            .subkey_ranges
                            .iter()
                            .map(|(start, end)| end - start)
                            .sum();

                        crate::tprintln!("DHT name: {}", package.name);
                        crate::tprintln!("Subkey count: {}", subkey_count);
                        crate::tprintln!("Owner (keypair) count: {}", package.keypairs.len());
                        crate::tprintln!("Record key: {}", package.dht_record.key());
                    }
                    None => crate::tprintln!("No DHT package exists at index {}", index),
                }
            }

            "w" | "W" => {
                let index = read_index("Index of DHT to write to: ");
                let location: u32 = loop {
                    let raw = read_line("Subkey location to write to: ");
                    match raw.parse::<u32>() {
                        Ok(n) => break n,
                        _ => crate::tprintln!("Please enter a valid non-negative number."),
                    }
                };

                let data = read_line("Data to write: ");

                match background.write_to_dht(index, location, data.into_bytes()).await {
                    Ok(_) => crate::tprintln!("Write successful"),
                    Err(err) => crate::tprintln!("Write failed: {:?}", err),
                }
            }

            "a" | "A" => {
                let index = read_index("Index of DHT to bombard: ");

                let size: u32 = match background.get_dht_info(index).await {
                    Some(package) => package
                        .subkey_ranges
                        .iter()
                        .map(|(start, end)| end - start)
                        .sum(),
                    None => {
                        crate::tprintln!("No DHT package exists at index {}", index);
                        continue;
                    }
                };

                crate::tprintln!("Firing off {} simultaneous writes to DHT index {}...", size, index);

                for loc in 0..size {
                    let background = background.clone();
                    let payload = format!("bulk-write-{}", loc).into_bytes();

                    tokio::spawn(async move {
                        match background.write_to_dht(index, loc, payload).await {
                            Ok(_) => crate::tprintln!("[bombard] subkey {} write OK", loc),
                            Err(err) => crate::tprintln!("[bombard] subkey {} write FAILED: {:?}", loc, err),
                        }
                    });
                }

                crate::tprintln!("All {} writes dispatched. Watch above for results as they land.", size);
            }

            "r" | "R" => {
                let index = read_index("Index of DHT to read from: ");
                let location: u32 = loop {
                    let raw = read_line("Subkey location to read: ");
                    match raw.parse::<u32>() {
                        Ok(n) => break n,
                        _ => crate::tprintln!("Please enter a valid non-negative number."),
                    }
                };

                match background.read_from_dht(index, location, false).await {
                    Ok(data) => match String::from_utf8(data.clone()) {
                        Ok(text) => crate::tprintln!("Subkey {} -> \"{}\"", location, text),
                        Err(_) => crate::tprintln!("Subkey {} -> {} raw bytes", location, data.len()),
                    },
                    Err(err) => crate::tprintln!("Read failed: {:?}", err),
                }
            }

            "l" | "L" => {
                let index = read_index("Index of DHT to read (all subkeys): ");

                match background.read_all_dht(index, false).await {
                    Ok(results) => {
                        crate::tprintln!("Read {} subkey(s) from DHT index {}:", results.len(), index);
                        for (loc, result) in results {
                            match result {
                                Ok(data) => match String::from_utf8(data.clone()) {
                                    Ok(text) => crate::tprintln!("  [{}] -> \"{}\"", loc, text),
                                    Err(_) => crate::tprintln!("  [{}] -> {} raw bytes", loc, data.len()),
                                },
                                Err(err) => crate::tprintln!("  [{}] -> FAILED: {:?}", loc, err),
                            }
                        }
                    }
                    Err(err) => crate::tprintln!("Batch read failed: {:?}", err),
                }
            }

            "e" | "E" => {
                let record_key_text = read_line("External DHT record key: ");
                let record_key: RecordKey = match record_key_text.trim().parse() {
                    Ok(key) => key,
                    Err(err) => {
                        crate::tprintln!("Invalid DHT record key: {err:?}");
                        continue;
                    }
                };

                let location: u32 = loop {
                    let raw = read_line("Subkey location to read: ");
                    match raw.parse::<u32>() {
                        Ok(n) => break n,
                        _ => crate::tprintln!("Please enter a valid non-negative number."),
                    }
                };

                match background
                    .read_foreign_subkey(record_key, location, true)
                    .await
                {
                    Ok(data) => print_dht_value(location, &data),
                    Err(err) => crate::tprintln!("External read failed: {:?}", err),
                }
            }

            "x" | "X" => {
                let record_key_text = read_line("External DHT record key: ");
                let record_key: RecordKey = match record_key_text.trim().parse() {
                    Ok(key) => key,
                    Err(err) => {
                        crate::tprintln!("Invalid DHT record key: {err:?}");
                        continue;
                    }
                };

                match background.read_all_foreign_dht(record_key, true).await {
                    Ok(results) => {
                        crate::tprintln!("Read {} subkey(s) from external DHT:", results.len());
                        for (location, result) in results {
                            match result {
                                Ok(data) => print_dht_value(location, &data),
                                Err(dht_module::CreateDhtError::NotFound) => {
                                    crate::tprintln!("  [{}] -> <unset>", location)
                                }
                                Err(err) => crate::tprintln!("  [{}] -> FAILED: {:?}", location, err),
                            }
                        }
                    }
                    Err(err) => crate::tprintln!("External batch read failed: {:?}", err),
                }
            }

            "y" | "Y" => {
                let record_key_text = read_line("External DHT record key: ");
                let record_key: RecordKey = match record_key_text.trim().parse() {
                    Ok(key) => key,
                    Err(err) => {
                        crate::tprintln!("Invalid DHT record key: {err:?}");
                        continue;
                    }
                };

                let locations = read_subkey_selection(
                    "Subkeys (examples: 0,1,10,50-75): ",
                );

                match background
                    .read_foreign_subkeys(record_key, locations, true)
                    .await
                {
                    Ok(results) => {
                        crate::tprintln!("Partial parallel read returned {} result(s):", results.len());
                        for (location, result) in results {
                            match result {
                                Ok(data) => print_dht_value(location, &data),
                                Err(dht_module::CreateDhtError::NotFound) => {
                                    crate::tprintln!("  [{}] -> <unset>", location)
                                }
                                Err(err) => crate::tprintln!("  [{}] -> FAILED: {:?}", location, err),
                            }
                        }
                    }
                    Err(err) => crate::tprintln!("External partial read failed: {:?}", err),
                }
            }

            "s" | "S" => {
                let snapshot = background.export_snapshot().await;
                match user_dht::persist_dht_snapshot(&auth, &session, &snapshot) {
                    Ok(()) => crate::tprintln!("Saved {} DHT(s) to your account.", snapshot.len()),
                    Err(err) => crate::tprintln!("Failed to save DHTs: {:?}", err),
                }
            }

            "c" | "C" => {
                let status = route_manager.get_status().await;
                crate::tprintln!("Route manager readiness: {:?}", status.readiness);
                crate::tprintln!("Route manager publish state: {:?}", status.publish_state);
                match status.active_route_id {
                    Some(id) => crate::tprintln!("Active route id: {:?}", id),
                    None => crate::tprintln!("No active route published yet."),
                }
            }

            "d" | "D" => {
                crate::tprintln!("Logged in as: {}", session.username());

                let snapshot = background.export_snapshot().await;
                crate::tprintln!("{} DHT(s) currently tracked in memory:", snapshot.len());
                for (i, record) in snapshot.iter().enumerate() {
                    let subkeys: u32 = record
                        .subkey_ranges
                        .iter()
                        .map(|(start, end)| end - start)
                        .sum();
                    crate::tprintln!(
                        "  [{}] \"{}\" - {} owner group(s), {} subkey(s)",
                        i,
                        record.name,
                        record.keypairs.len(),
                        subkeys
                    );
                }

                match auth.read_user_setup_state(&session) {
                    Ok(state) => {
                        crate::tprintln!("Main DHT setup complete: {}", state.main_dht_setup);
                        match state.main_dht_package_index {
                            Some(index) => crate::tprintln!("Main DHT package index on file: {index}"),
                            None => crate::tprintln!("No main DHT package index saved yet."),
                        }
                    }
                    Err(error) => crate::tprintln!("Error reading user setup state: {error:?}"),
                }

                if let Some(runtime) = &main_dht_runtime {
                    let presence = runtime.presence_snapshot().await;
                    crate::tprintln!("Public online status: {}", presence.user_status);
                    crate::tprintln!("Last login: {}", presence.last_login);
                    crate::tprintln!("Online since: {:?}", presence.online_since);
                    crate::tprintln!("Last heartbeat/online: {}", presence.last_online);
                    crate::tprintln!("Last clean logout: {:?}", presence.last_logout);
                }

                if let Some(scheduler) = &automatic_walk {
                    print_walk_settings(scheduler.settings());
                }
            }

            "h" | "H" => {
                let peer_dht = read_line("Peer's DHT record key (the address they gave you): ");

                if peer_dht.trim().is_empty() {
                    crate::tprintln!("Empty DHT address, nothing to do.");
                    continue;
                }

                if our_dht_key.is_empty() {
                    crate::tprintln!(
                        "Warning: we don't have a route DHT of our own yet, so the peer won't \
                         be able to reply. Continuing anyway..."
                    );
                }

                let mut mgr = handshake_manager.lock().await;
                match mgr.initiate_handshake(peer_dht.trim().to_string()).await {
                    Ok(()) => crate::tprintln!(
                        "Handshake initiated. Use 'k' to check its status, or watch the \
                         [handshake] log lines above as messages come in."
                    ),
                    Err(err) => crate::tprintln!("Failed to initiate handshake: {err}"),
                }
            }

            "k" | "K" => {
                let peer_dht = read_line("Peer's DHT record key to check: ");
                let mgr = handshake_manager.lock().await;

                match mgr.session(peer_dht.trim()) {
                    Some(state) => {
                        crate::tprintln!("Status: {:?}", state.status);
                        crate::tprintln!("Is initiator: {}", state.is_initiator);
                        crate::tprintln!("Encryption mode: {:?}", state.encryption_mode);
                        crate::tprintln!("Retries so far: {}", state.retries);
                    }
                    None => crate::tprintln!("No handshake session on file for that DHT address."),
                }
            }

            "t" | "T" => {
                let Some(walker) = &walk_task else {
                    crate::tprintln!("The network walker is not available.");
                    continue;
                };

                let hops = read_index("How many hops should this walk attempt? ");
                let mut config = WalkConfig::random(hops);
                if let Some(mailbox) = &mailbox_manager {
                    let subscriber: Arc<dyn WalkSubscriber> = mailbox.clone();
                    config = config.with_subscribers(vec![subscriber]);
                }
                match walker.start_walk(config).await {
                    Ok(WalkStartResult::Started(_handle)) => {
                        crate::tprintln!("Walk started with {hops} requested hop(s).");
                    }
                    Ok(WalkStartResult::AlreadyRunning(handle)) => {
                        crate::tprintln!(
                            "A walk is already running; about {} hop(s) remain.",
                            handle.estimated_hops_remaining()
                        );
                    }
                    Err(err) => crate::tprintln!("Could not start walk: {err}"),
                }
            }

            "p" | "P" => {
                let Some(walker) = &walk_task else {
                    crate::tprintln!("The network walker is not available.");
                    continue;
                };
                match walker.current_walk_status().await {
                    Some(WalkStatus::Running {
                        requested_hops,
                        completed_hops,
                        current_target,
                    }) => {
                        crate::tprintln!("Walk progress: {completed_hops}/{requested_hops}");
                        if let Some(target) = current_target {
                            crate::tprintln!("Currently reading: {target}");
                        }
                    }
                    Some(WalkStatus::Finished(report)) => crate::tprintln!("Last walk: {report:?}"),
                    Some(WalkStatus::Failed(message)) => crate::tprintln!("Walk failed: {message}"),
                    None => crate::tprintln!("No walk has been started during this run."),
                }
            },

            "i" | "I" => {
                let Some(walker) = &walk_task else {
                    crate::tprintln!("The network walker is not available.");
                    continue;
                };

                let list = walker.get_internal_list_copy().await;
                crate::tprintln!(
                    "Topology contains {} verified/authenticated peer(s) and {} unverified candidate(s).",
                    list.len(),
                    list.candidate_len()
                );
                for (index, entry) in list.entries.iter().enumerate().take(50) {
                    crate::tprintln!(
                        "  [{index}] {} | {:?} | presence {} | presence checked {} | last direct read {} | last authenticated {} | account created {:?} | capabilities 0x{:x} | advertised by {} peer(s)",
                        entry.their_address,
                        entry.verification_state,
                        entry.presence_state_at(current_timestamp()).label(),
                        entry.presence_checked_at,
                        entry.last_direct_dht_read_at,
                        entry.last_authenticated_at,
                        entry.account_created_at,
                        entry.capability_flags,
                        entry.advertisers.len()
                    );
                }
                if list.len() > 50 {
                    crate::tprintln!("  ...and {} more", list.len() - 50);
                }
            }

            "o" | "O" => {
                let Some(walker) = &walk_task else {
                    crate::tprintln!("The network walker is not available.");
                    continue;
                };
                if walker.cancel_current_walk().await {
                    crate::tprintln!("Walk cancellation requested.");
                } else {
                    crate::tprintln!("No active walk to stop.");
                }
            },

            "m" | "M" => {
                let Some(mailbox) = &mailbox_manager else {
                    crate::tprintln!("The mailbox controller is not available.");
                    continue;
                };
                let recipient_text = read_line("Recipient main DHT record key: ");
                let recipient_main_dht: RecordKey = match recipient_text.parse() {
                    Ok(key) => key,
                    Err(error) => {
                        crate::tprintln!("Invalid recipient DHT key: {error:?}");
                        continue;
                    }
                };
                let application_id = read_line("Application id/name: ");
                let plaintext = read_line("Small mailbox payload: ").into_bytes();
                match mailbox
                    .submit_outgoing_message(OutgoingMessageRequest {
                        application_id,
                        recipient_main_dht,
                        plaintext,
                        expires_at: None,
                        conversation_id: None,
                        proposed_conversation_dht: None,
                        await_response: true,
                    })
                    .await
                {
                    Ok(message_id) => crate::tprintln!("Mailbox message queued: {}", hex_id(&message_id)),
                    Err(error) => crate::tprintln!("Mailbox send failed: {error}"),
                }
            }

            "j" | "J" => {
                let Some(mailbox) = &mailbox_manager else {
                    crate::tprintln!("The mailbox controller is not available.");
                    continue;
                };
                match mailbox.status().await {
                    Ok(status) => crate::tprintln!("Mailbox status: {status:?}"),
                    Err(error) => crate::tprintln!("Could not read mailbox status: {error}"),
                }
            }

            "f" | "F" => {
                let Some(mailbox) = &mailbox_manager else {
                    crate::tprintln!("The mailbox controller is not available.");
                    continue;
                };
                match mailbox.flush().await {
                    Ok(()) => crate::tprintln!("Mailbox writes flushed."),
                    Err(error) => crate::tprintln!("Mailbox flush failed: {error}"),
                }
            }

            "v" | "V" => {
                let app_text = read_line("Application id/name: ");
                let app_id = match AppId::new(app_text) {
                    Ok(app_id) => app_id,
                    Err(error) => {
                        crate::tprintln!("Invalid app id: {error}");
                        continue;
                    }
                };
                match reputation_user.get_app_source_report(app_id).await {
                    Ok(report) => crate::tprintln!("App reputation source: {report:#?}"),
                    Err(error) => crate::tprintln!("Could not read app reputation source: {error}"),
                }
            }

            "z" | "Z" => {
                let app_text = read_line("Application id/name to retract: ");
                let app_id = match AppId::new(app_text) {
                    Ok(app_id) => app_id,
                    Err(error) => {
                        crate::tprintln!("Invalid app id: {error}");
                        continue;
                    }
                };
                let reason = read_line("Reason for retracting this app's reputation influence: ");
                let event_reason = reason.clone();
                match reputation_user.retract_app_source(app_id, reason).await {
                    Ok(report) => {
                        event_bus.emit(
                            network_events::NetworkEventSource::Reputation,
                            network_events::EventSeverity::Notice,
                            network_events::NetworkEvent::AppObservationsRetracted {
                                app_id: report.app_id.to_string(),
                                active_observations: report.active_observations_retracted,
                                historical_observations: report.historical_observations_retracted,
                                decisions_revoked: report.decisions_revoked,
                                affected_subjects: report.affected_subjects,
                                reason: event_reason,
                            },
                        );
                        crate::tprintln!("App reputation influence retracted: {report:#?}");
                    }
                    Err(error) => crate::tprintln!("Could not retract app reputation source: {error}"),
                }
            }

            "app-add" | "APP-ADD" => {
                let app_text = read_line("Application id (for example daemon.group-chat): ");
                let app_id = match AppId::new(app_text) {
                    Ok(app_id) => app_id,
                    Err(error) => {
                        crate::tprintln!("Invalid app id: {error}");
                        continue;
                    }
                };
                let display_name = read_line("Application display name: ");
                match identity_manager
                    .register_app(app_id.clone(), display_name.clone())
                    .await
                {
                    Ok(credential) => {
                        match save_app_credential_file(
                            &credential,
                            &display_name,
                            &local_api_endpoint,
                        ) {
                            Ok(path) => crate::tprintln!(
                                "Application registered. Credential saved to {}",
                                path.display()
                            ),
                            Err(error) => {
                                crate::teprintln!("Application registered, but credential save failed: {error}");
                                crate::tprintln!(
                                    "Copy this secret now; it cannot be recovered later: {}",
                                    hex::encode(credential.secret_bytes())
                                );
                            }
                        }
                        crate::tprintln!("Application id: {}", credential.app_id);
                        crate::tprintln!(
                            "Credential generation: {}",
                            credential.credential_generation
                        );
                        crate::tprintln!("API endpoint: {local_api_endpoint}");
                    }
                    Err(error) => crate::tprintln!("Could not register application: {error}"),
                }
            }

            "app-list" | "APP-LIST" => {
                let apps = identity_manager.list_apps().await;
                if apps.is_empty() {
                    crate::tprintln!("No applications are registered.");
                } else {
                    for app in &apps {
                        crate::tprintln!(
                            "{} | {} | enabled={} | generation={} | capabilities={:?}",
                            app.app_id,
                            app.display_name,
                            app.enabled,
                            app.credential_generation,
                            app.granted_capabilities.iter().collect::<Vec<_>>()
                        );
                    }
                }

                // Machine-readable copy for the GUI. The human-readable block above is kept
                // for console users; this exists so the Applications tab can offer a list to
                // pick from instead of asking someone to type an app id by hand.
                crate::tprintln!("[gui] GUI_LOCAL_APPS_BEGIN");
                for app in &apps {
                    crate::tprintln!(
                        "[gui] GUI_LOCAL_APP=app_hex={};name_hex={};enabled={};generation={};capabilities={}",
                        hex::encode(app.app_id.to_string().as_bytes()),
                        hex::encode(app.display_name.as_bytes()),
                        if app.enabled { 1 } else { 0 },
                        app.credential_generation,
                        app.granted_capabilities.iter().count(),
                    );
                }
                crate::tprintln!("[gui] GUI_LOCAL_APPS_END");
            }

            "app-rotate" | "APP-ROTATE" => {
                let app_text = read_line("Application id to rotate: ");
                let app_id = match AppId::new(app_text) {
                    Ok(app_id) => app_id,
                    Err(error) => {
                        crate::tprintln!("Invalid app id: {error}");
                        continue;
                    }
                };
                match identity_manager.rotate_app_credential(&app_id).await {
                    Ok(credential) => {
                        // Credential rotation is the recovery path for a
                        // misbehaving or compromised app. Remove that app's
                        // active reputation influence while preserving an audit
                        // trail of the retraction.
                        match reputation_user
                            .retract_app_source(
                                app_id.clone(),
                                "Application credential rotated by the local user".to_string(),
                            )
                            .await
                        {
                            Ok(report) if report.active_observations_retracted != 0
                                || report.decisions_revoked != 0 =>
                            {
                                crate::tprintln!(
                                    "Retracted old app influence: {} observations, {} decisions",
                                    report.active_observations_retracted,
                                    report.decisions_revoked
                                );
                            }
                            Ok(_) => {}
                            Err(error) => crate::teprintln!(
                                "Credential rotated, but old reputation influence could not be retracted: {error}"
                            ),
                        }
                        let display_name = identity_manager
                            .list_apps()
                            .await
                            .into_iter()
                            .find(|app| app.app_id == app_id)
                            .map(|app| app.display_name)
                            .unwrap_or_else(|| app_id.to_string());
                        match save_app_credential_file(
                            &credential,
                            &display_name,
                            &local_api_endpoint,
                        ) {
                            Ok(path) => crate::tprintln!(
                                "Credential rotated and saved to {}. All previous app sessions are invalid.",
                                path.display()
                            ),
                            Err(error) => {
                                crate::teprintln!("Credential rotated, but save failed: {error}");
                                crate::tprintln!(
                                    "Copy this secret now; it cannot be recovered later: {}",
                                    hex::encode(credential.secret_bytes())
                                );
                            }
                        }
                    }
                    Err(error) => crate::tprintln!("Could not rotate credential: {error}"),
                }
            }

            "u" | "U" | "log" | "LOG" => {
                let requested = read_line(
                    "Session log path (blank = session_logs/session_<timestamp>.log): ",
                );
                match console_log::save_session_log(Some(&requested)) {
                    Ok(saved) => crate::tprintln!(
                        "Session log saved to {} ({} lines)",
                        saved.path.display(),
                        saved.lines
                    ),
                    Err(error) => crate::teprintln!("Could not save session log: {error}"),
                }
            }

            "q" | "Q" => {
                crate::tprintln!("Shutting down...");
                break;
            }

            _ => crate::tprintln!("Unknown command. Type 'help' to see the available commands."),
        }
    }

    let outcomes = supervisor.shutdown(stop_reason).await;
    for outcome in &outcomes {
        match &outcome.result {
            HookResult::Failed(error) => {
                crate::tprintln!("{} shutdown warning: {error}", outcome.module);
            }
            HookResult::Overran => {
                crate::tprintln!(
                    "{} shutdown warning: timed out while {}",
                    outcome.module,
                    outcome.detail
                );
            }
            HookResult::Ok | HookResult::Skipped(_) => {}
        }
    }
    let had_shutdown_error = outcomes.iter().any(|outcome| {
        matches!(&outcome.result, HookResult::Failed(_) | HookResult::Overran)
    });
    if lifecycle.watchdog_left_armed() {
        crate::teprintln!(
            "Shutdown could not prove safe quiescence; the lifecycle watchdog remains armed."
        );
    } else if had_shutdown_error {
        crate::teprintln!("Shutdown completed with lifecycle warnings; review the hook results above.");
    } else {
        crate::tprintln!("Network services stopped safely.");
        crate::tprintln!("Safely Shut Down");
    }

    Ok(())
}


async fn reconcile_current_app_info(
    runtime: &MainDhtRuntime,
    identities: &IdentityManager,
    app_directory: Option<&AppDirectoryManager>,
    capability_flags: u64,
    last_published_apps: &mut Vec<String>,
    last_published_at: &mut u64,
    force: bool,
) -> Result<bool, String> {
    let now = current_timestamp();
    let application_ids = identities.recently_used_app_ids(now).await;
    let directory_changed = match app_directory {
        Some(directory) => directory.sync_public_apps(&application_ids).await?,
        None => false,
    };
    if !force && application_ids == *last_published_apps {
        return Ok(directory_changed);
    }

    runtime
        .publish_app_info(AppInfo::new(capability_flags, application_ids.clone(), now))
        .await
        .map_err(|error| error.to_string())?;
    *last_published_apps = application_ids;
    *last_published_at = now;
    Ok(true)
}

/// Parses the compact console command used to change automatic-walk settings.
fn parse_walk_settings_command(command: &str) -> Result<WalkSettings, String> {
    let values: Vec<&str> = command.split_whitespace().skip(1).collect();
    if values.len() != 11 {
        return Err(
            "usage: walk-set <normal-min-hops> <normal-max-hops> <normal-min-secs> <normal-target-secs> <normal-max-secs> <mail-min-hops> <mail-max-hops> <mail-min-secs> <mail-target-secs> <mail-max-secs> <mail-mode-0-or-1>"
                .to_string(),
        );
    }

    fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
        value
            .parse::<usize>()
            .map_err(|_| format!("{name} must be a non-negative whole number"))
    }

    fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
        value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be a non-negative whole number"))
    }

    let mail_mode_enabled = match values[10].to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => return Err("mail mode must be 0/1, true/false, yes/no, or on/off".to_string()),
    };

    Ok(WalkSettings {
        normal: WalkModeSettings {
            minimum_hops: parse_usize(values[0], "normal minimum hops")?,
            maximum_hops: parse_usize(values[1], "normal maximum hops")?,
            minimum_interval_secs: parse_u64(values[2], "normal minimum interval")?,
            target_interval_secs: parse_u64(values[3], "normal target interval")?,
            maximum_interval_secs: parse_u64(values[4], "normal maximum interval")?,
        },
        mail: WalkModeSettings {
            minimum_hops: parse_usize(values[5], "mail minimum hops")?,
            maximum_hops: parse_usize(values[6], "mail maximum hops")?,
            minimum_interval_secs: parse_u64(values[7], "mail minimum interval")?,
            target_interval_secs: parse_u64(values[8], "mail target interval")?,
            maximum_interval_secs: parse_u64(values[9], "mail maximum interval")?,
        },
        mail_mode_enabled,
    }
    .sanitized())
}

fn print_walk_settings(settings: WalkSettings) {
    let settings = settings.sanitized();
    crate::tprintln!("Adaptive walk settings:");
    crate::tprintln!(
        "  Normal mode: {}-{} hops; interval {} / {} / {} seconds (minimum / target / maximum)",
        settings.normal.minimum_hops,
        settings.normal.maximum_hops,
        settings.normal.minimum_interval_secs,
        settings.normal.target_interval_secs,
        settings.normal.maximum_interval_secs,
    );
    crate::tprintln!(
        "  Mail mode:   {}-{} hops; interval {} / {} / {} seconds (minimum / target / maximum)",
        settings.mail.minimum_hops,
        settings.mail.maximum_hops,
        settings.mail.minimum_interval_secs,
        settings.mail.target_interval_secs,
        settings.mail.maximum_interval_secs,
    );
    crate::tprintln!(
        "  Automatic mail mode: {}",
        if settings.mail_mode_enabled { "enabled" } else { "disabled" }
    );
}


fn print_gui_pending_app_requests(requests: &[named_pipe_api::PendingAppRegistration]) {
    crate::tprintln!("[gui] GUI_APP_REQUESTS_BEGIN");
    for request in requests {
        crate::tprintln!(
            "[gui] GUI_APP_REQUEST=request_id={};app_hex={};name_hex={};requested_at={};expires_at={}",
            request.request_id,
            hex::encode(request.app_id.as_bytes()),
            hex::encode(request.display_name.as_bytes()),
            request.requested_at,
            request.expires_at,
        );
    }
    crate::tprintln!("[gui] GUI_APP_REQUESTS_END");
}

async fn print_gui_app_summary(walker: Option<&WalkTask>) {
    let now = current_timestamp();
    let mut combined: BTreeMap<String, (usize, usize, usize, usize, u64)> = BTreeMap::new();
    if let Some(walker) = walker {
        let list = walker.get_internal_list_copy().await;
        for (app_id, observed) in list.observed_application_counts_at(now) {
            combined.entry(app_id).or_default().0 = observed;
        }
        for summary in walker.app_discovery_cache().app_summaries(now).await {
            let entry = combined.entry(summary.app_id).or_default();
            entry.1 = summary.total_cached;
            entry.2 = summary.recent_peers;
            entry.3 = summary.archive_peers;
            entry.4 = summary.total_verified_observations;
        }
    }
    let mut rows: Vec<_> = combined.into_iter().collect();
    rows.sort_by(|left, right| {
        let left_count = left.1.1.max(left.1.0);
        let right_count = right.1.1.max(right.1.0);
        right_count.cmp(&left_count).then_with(|| left.0.cmp(&right.0))
    });
    crate::tprintln!("[gui] GUI_APPS_BEGIN");
    for (app_id, (observed, cached, recent, archive, observations)) in rows.into_iter().take(128) {
        crate::tprintln!(
            "[gui] GUI_APP=app_hex={};observed={};cached={};recent={};archive={};observations={}",
            hex::encode(app_id.as_bytes()), observed, cached, recent, archive, observations,
        );
    }
    crate::tprintln!("[gui] GUI_APPS_END");
}

async fn print_gui_network_summary(
    walker: Option<&WalkTask>,
    app_directory: Option<&AppDirectoryManager>,
) {
    let now = current_timestamp();
    let mut verified = 0usize;
    let mut candidates = 0usize;
    let mut authenticated = 0usize;
    let mut online = 0usize;
    let mut offline = 0usize;
    let mut stale = 0usize;
    let mut refresh = 0usize;
    let mut unknown = 0usize;
    let mut presence_ok = 0usize;
    let mut presence_failed = 0usize;
    let mut presence_unread = 0usize;
    let mut app_headers = 0usize;
    let mut mailbox_capable = 0usize;
    let mut app_searches = 0usize;
    let mut walk_state = "idle";
    let mut walk_done = 0usize;
    let mut walk_total = 0usize;
    let mut walk_new = 0usize;
    let mut walk_updated = 0usize;
    let mut walk_reachable = 0usize;
    let mut walk_unreachable = 0usize;

    if let Some(walker) = walker {
        let list = walker.get_internal_list_copy().await;
        let summary = list.network_summary_at(now);
        verified = summary.verified_nodes;
        candidates = summary.candidate_nodes;
        authenticated = summary.authenticated_nodes;
        online = summary.online;
        offline = summary.explicitly_offline;
        stale = summary.stale_online_claim;
        refresh = summary.needs_refresh;
        unknown = summary.unknown;
        presence_ok = summary.presence_reads_ok;
        presence_failed = summary.presence_reads_failed;
        presence_unread = summary.presence_never_checked;
        app_headers = summary.active_app_headers;
        mailbox_capable = summary.mailbox_capable;
        app_searches = walker.queued_app_search_count().await;

        match walker.current_walk_status().await {
            Some(WalkStatus::Running { requested_hops, completed_hops, .. }) => {
                walk_state = "running";
                walk_done = completed_hops;
                walk_total = requested_hops;
            }
            Some(WalkStatus::Finished(report)) => {
                walk_state = if report.cancelled { "cancelled" } else { "finished" };
                walk_done = report.completed_hops;
                walk_total = report.requested_hops;
                walk_new = report.new_nodes;
                walk_updated = report.updated_nodes;
                walk_reachable = report.reachable;
                walk_unreachable = report.unreachable;
            }
            Some(WalkStatus::Failed(_)) => walk_state = "failed",
            None => {}
        }
    }

    let root_lookups = match app_directory {
        Some(directory) => directory.pending_lookup_count().await,
        None => 0,
    };

    crate::tprintln!(
        "[gui] GUI_SUMMARY=sampled_at={};verified={};candidates={};authenticated={};online={};offline={};stale={};refresh={};unknown={};presence_ok={};presence_failed={};presence_unread={};app_headers={};mailbox_capable={};app_searches={};root_lookups={};walk_state={};walk_done={};walk_total={};walk_new={};walk_updated={};walk_reachable={};walk_unreachable={}",
        now, verified, candidates, authenticated, online, offline, stale, refresh, unknown,
        presence_ok, presence_failed, presence_unread, app_headers, mailbox_capable,
        app_searches, root_lookups, walk_state, walk_done, walk_total, walk_new,
        walk_updated, walk_reachable, walk_unreachable,
    );
}

fn print_gui_walk_settings(settings: WalkSettings) {
    let settings = settings.sanitized();
    crate::tprintln!(
        "[gui] WALK_SETTINGS={},{},{},{},{},{},{},{},{},{},{}",
        settings.normal.minimum_hops,
        settings.normal.maximum_hops,
        settings.normal.minimum_interval_secs,
        settings.normal.target_interval_secs,
        settings.normal.maximum_interval_secs,
        settings.mail.minimum_hops,
        settings.mail.maximum_hops,
        settings.mail.minimum_interval_secs,
        settings.mail.target_interval_secs,
        settings.mail.maximum_interval_secs,
        if settings.mail_mode_enabled { 1 } else { 0 },
    );
}

async fn print_own_headers(dht: &DHTModule, package_index: usize) {
    let main_header = match dht
        .read_from_dht(package_index, STATUS_LOCATION, false)
        .await
    {
        Ok(bytes) if bytes.is_empty() || bytes == dht_module::NULL_DHT_VALUE => {
            "Header is blank/null.".to_string()
        }
        Ok(bytes) => match decode_user_info(&bytes) {
            Ok(header) => format!(
                "user_status: {}\nversion: {}\nlast_online: {}\naccount_created_at: {}\nrecord_version: {}\nlast_login: {}\nonline_since: {:?}\nlast_logout: {:?}\nstatus_updated_at: {}\nraw_bytes: {}\nhex_preview: {}",
                header.user_status,
                header.version,
                header.last_online,
                header.account_created_at,
                header.record_version,
                header.last_login,
                header.online_since,
                header.last_logout,
                header.status_updated_at,
                bytes.len(),
                hex_preview(&bytes, 192),
            ),
            Err(error) => format!(
                "Could not decode UserInfo: {error}\nraw_bytes: {}\nhex_preview: {}",
                bytes.len(),
                hex_preview(&bytes, 192),
            ),
        },
        Err(error) => format!("Could not read main header: {error:?}"),
    };

    let mailbox_header = match dht
        .read_from_dht(package_index, MAILBOX_ADVERTISEMENT_LOCATION, false)
        .await
    {
        Ok(bytes) if bytes.is_empty() || bytes == dht_module::NULL_DHT_VALUE => {
            "Mailbox header is blank/null.".to_string()
        }
        Ok(bytes) => match bincode::deserialize::<MailboxAdvertisement>(&bytes) {
            Ok(header) => format!(
                "version: {}\ncustodian_mailbox_dht: {:?}\nmail_send_dht: {:?}\nmail_response_dht: {}\nreceive_status: {:?}\nreceive_key_epoch: {}\ncurrent_receive_key_valid_from: {}\nprevious_receive_keys: {}\nmailbox_signing_public_key: {:?}\nretention_region: {:?}\nmailbox_generation: {}\nadvertisement_updated_at: {}\nnavigation_suggestions: {}\nmigration: {:?}\nraw_bytes: {}\nhex_preview: {}",
                header.version,
                header.custodian_mailbox_dht,
                header.mail_send_dht,
                header.mail_response_dht,
                header.receive_status,
                header.receive_key_epoch,
                header.current_receive_key_valid_from,
                header.previous_receive_keys.len(),
                header.mailbox_signing_public_key,
                header.retention_region,
                header.mailbox_generation,
                header.advertisement_updated_at,
                header.navigation_suggestions.len(),
                header.migration,
                bytes.len(),
                hex_preview(&bytes, 192),
            ),
            Err(error) => format!(
                "Could not decode MailboxAdvertisement: {error}\nraw_bytes: {}\nhex_preview: {}",
                bytes.len(),
                hex_preview(&bytes, 192),
            ),
        },
        Err(error) => format!("Could not read mailbox header: {error:?}"),
    };

    crate::tprintln!("Own main/presence header:\n{main_header}");
    crate::tprintln!("Own mailbox advertisement header:\n{mailbox_header}");

    if GUI_BRIDGE_MODE.load(Ordering::Relaxed) {
        crate::tprintln!("[gui] MAIN_HEADER={}", escape_gui_value(&main_header));
        crate::tprintln!("[gui] MAILBOX_HEADER={}", escape_gui_value(&mailbox_header));
    }
}

/// Escapes text before placing it into the simple line-oriented GUI bridge protocol.
fn escape_gui_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn hex_preview(bytes: &[u8], maximum_bytes: usize) -> String {
    let shown = bytes.len().min(maximum_bytes);
    let mut result = hex::encode(&bytes[..shown]);
    if shown < bytes.len() {
        result.push_str("...");
    }
    result
}

/// Loops until the user successfully logs in or signs up.
/// Small interactive desktop helper that logs into an account or creates a new one.
fn login_or_signup(auth: &UserAuth) -> Option<UserSession> {
    loop {
        let choice = read_line("Login, Signup, or Restore local backup? (l/s/r): ");
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if mobile_bridge::is_stop_sentinel(&choice) {
            return None;
        }
        if matches!(choice.trim(), "r" | "R") {
            let path = read_line("Path to .veilknit-backup file: ");
            #[cfg(any(target_os = "android", target_os = "ios"))]
            if mobile_bridge::is_stop_sentinel(&path) {
                return None;
            }
            let passphrase = read_line("Backup passphrase: ");
            #[cfg(any(target_os = "android", target_os = "ios"))]
            if mobile_bridge::is_stop_sentinel(&passphrase) {
                return None;
            }
            match auth.restore_local_backup(path.trim(), &passphrase) {
                Ok(metadata) => crate::tprintln!(
                    "Restored account '{}'. Log in with its original account password.",
                    metadata.username
                ),
                Err(error) => crate::tprintln!("Could not restore backup: {error}"),
            }
            continue;
        }

        let username = read_line("Username: ");
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if mobile_bridge::is_stop_sentinel(&username) {
            return None;
        }
        let password = read_line("Password: "); // Android UI masks this field
        #[cfg(any(target_os = "android", target_os = "ios"))]
        if mobile_bridge::is_stop_sentinel(&password) {
            return None;
        }

        let result = match choice.trim() {
            "l" | "L" => auth.login(&username, &password),
            "s" | "S" => auth.signup(&username, &password),
            _ => {
                crate::tprintln!("Please enter l, s, or r.");
                continue;
            }
        };

        match result {
            Ok(session) => return Some(session),
            Err(AuthError::UserNotFound) => crate::tprintln!("No account with that username."),
            Err(AuthError::UserAlreadyExists) => crate::tprintln!("That username is already taken."),
            Err(AuthError::WrongPassword) => crate::tprintln!("Wrong password."),
            Err(AuthError::InvalidUsername) => {
                crate::tprintln!("Usernames may only contain letters, numbers, '_' and '-'.")
            }
            Err(err) => crate::tprintln!("Auth error: {:?}", err),
        }
    }
}

fn read_index(prompt: &str) -> usize {
    loop {
        let raw = read_line(prompt);
        match raw.parse::<usize>() {
            Ok(n) => return n,
            _ => crate::tprintln!("Please enter a valid non-negative number."),
        }
    }
}

/// Prompts the user to build up the list of owner groups for a new DHT.
fn read_subkey_groups() -> Vec<u16> {
    let mut groups: Vec<u16> = Vec::new();

    loop {
        let size: u16 = loop {
            let raw = read_line(&format!(
                "Subkeys for owner group #{} (1-250): ",
                groups.len() + 1
            ));
            match raw.parse::<u16>() {
                Ok(n) if n >= 1 && n <= 250 => break n,
                _ => crate::tprintln!("Please enter a number between 1 and 250."),
            }
        };

        groups.push(size);

        if groups.len() >= 250 {
            crate::tprintln!("Reached the maximum of 250 owner groups.");
            break;
        }

        loop {
            let more = read_line("Add another owner group? (y/n): ");
            match more.trim() {
                "y" | "Y" => break,
                "n" | "N" => return groups,
                _ => crate::tprintln!("Please enter y or n."),
            }
        }
    }

    groups
}

fn read_subkey_selection(prompt: &str) -> Vec<u32> {
    loop {
        let raw = read_line(prompt);
        let mut locations = Vec::new();
        let mut valid = true;

        for part in raw.split(',').map(str::trim).filter(|part| !part.is_empty()) {
            if let Some((start, end)) = part.split_once('-') {
                match (start.trim().parse::<u32>(), end.trim().parse::<u32>()) {
                    (Ok(start), Ok(end)) if start <= end => locations.extend(start..=end),
                    _ => {
                        valid = false;
                        break;
                    }
                }
            } else {
                match part.parse::<u32>() {
                    Ok(location) => locations.push(location),
                    Err(_) => {
                        valid = false;
                        break;
                    }
                }
            }
        }

        if valid && !locations.is_empty() {
            locations.sort_unstable();
            locations.dedup();
            return locations;
        }

        crate::tprintln!("Enter comma-separated subkeys and/or inclusive ranges, such as 0,1,10,50-75.");
    }
}

/// Handles the developer-console mailbox commands without mixing them into mailbox internals.
async fn handle_mail_command(mailbox: &Arc<MailboxManager>, command_line: &str) {
    let mut parts = command_line.split_whitespace();
    let _mail = parts.next();
    let subcommand = parts.next().unwrap_or("status").to_ascii_lowercase();
    let selector = parts.next().map(str::to_string);

    match subcommand.as_str() {
        "send" => {
            let recipient_text = read_line("Recipient main DHT record key: ");
            let recipient_main_dht: RecordKey = match recipient_text.parse() {
                Ok(key) => key,
                Err(error) => {
                    crate::tprintln!("Invalid recipient DHT key: {error:?}");
                    return;
                }
            };
            let application_id = read_line("Application id/name: ");
            let plaintext = read_line("Small mailbox payload: ").into_bytes();
            match mailbox
                .submit_outgoing_message(OutgoingMessageRequest {
                    application_id,
                    recipient_main_dht,
                    plaintext,
                    expires_at: None,
                    conversation_id: None,
                    proposed_conversation_dht: None,
                    await_response: true,
                })
                .await
            {
                Ok(message_id) => crate::tprintln!(
                    "Mailbox message committed and self-seeded: {}",
                    hex_id(&message_id)
                ),
                Err(error) => crate::tprintln!("Mailbox send failed: {error}"),
            }
        }
        "status" => match mailbox.status().await {
            Ok(status) => {
                crate::tprintln!("==================== MAILBOX ====================");
                match status.mailbox_dht {
                    Some(key) => crate::tprintln!("Custodian mailbox DHT: {key}"),
                    None => crate::tprintln!("Custodian mailbox DHT: disabled"),
                }
                match status.mail_send_dht {
                    Some(key) => crate::tprintln!("Outgoing MailSend DHT: {key}"),
                    None => crate::tprintln!("Outgoing MailSend DHT: not created yet"),
                }
                crate::tprintln!("Response DHT: {}", status.mail_response_dht);
                crate::tprintln!("Receive-key epoch: {}", status.receive_key_epoch);
                crate::tprintln!(
                    "Inbox: {} stored, {} unread",
                    status.stored_inbox_count,
                    status.unread_inbox_count
                );
                crate::tprintln!(
                    "Outgoing: {} active, {} awaiting response",
                    status.outgoing_message_count,
                    status.awaiting_response_count
                );
                crate::tprintln!("Known custodians: {}", status.known_custodian_count);
                crate::tprintln!("Pending DHT page sets: {}", status.pending_page_sets);
                crate::tprintln!(
                    "Commands: mail send | mail list | mail read <number/id> | mail delete <number/id> | mail retrieve | mail stats | mail flush | mail repair"
                );
            }
            Err(error) => crate::tprintln!("Could not read mailbox status: {error}"),
        },
        "list" => match mailbox.list_inbox().await {
            Ok(messages) if messages.is_empty() => {
                crate::tprintln!("Your local mailbox inbox is empty.");
            }
            Ok(messages) => {
                crate::tprintln!(
                    "#    State   Age       Bytes  Application              Sender / message"
                );
                crate::tprintln!(
                    "--------------------------------------------------------------------------"
                );
                for (index, message) in messages.iter().take(200).enumerate() {
                    crate::tprintln!(
                        "{:<4} {:<7} {:<9} {:<6} {:<24} {} / {}",
                        index + 1,
                        if message.read { "read" } else { "UNREAD" },
                        mailbox_age(message.received_at),
                        message.plaintext_len,
                        shorten_console(&message.application_id, 24),
                        shorten_console(&message.sender_main_dht.to_string(), 22),
                        &hex_id(&message.message_id)[..12],
                    );
                }
                if messages.len() > 200 {
                    crate::tprintln!("...and {} more message(s)", messages.len() - 200);
                }
                crate::tprintln!("Use 'mail read <number>' to inspect a message.");
            }
            Err(error) => crate::tprintln!("Could not list mailbox messages: {error}"),
        },
        "read" => {
            let selector = selector.unwrap_or_else(|| read_line("Message number or id: "));
            let message_id = match resolve_mail_selector(mailbox, &selector).await {
                Ok(id) => id,
                Err(error) => {
                    crate::tprintln!("{error}");
                    return;
                }
            };
            match mailbox.read_inbox(message_id).await {
                Ok(message) => {
                    crate::tprintln!("==================== MAIL ====================");
                    crate::tprintln!("Message id: {}", hex_id(&message.message_id));
                    crate::tprintln!("From: {}", message.sender_main_dht);
                    crate::tprintln!("To: {}", message.recipient_main_dht);
                    crate::tprintln!("Application: {}", message.application_id);
                    crate::tprintln!("Posted timestamp: {}", message.posted_at);
                    crate::tprintln!("Received timestamp: {}", message.received_at);
                    crate::tprintln!("Expires timestamp: {}", message.expires_at);
                    if let Some(conversation_id) = message.conversation_id {
                        crate::tprintln!("Conversation id: {}", hex_id(&conversation_id));
                    }
                    crate::tprintln!("Payload size: {} byte(s)", message.plaintext.len());
                    match String::from_utf8(message.plaintext.clone()) {
                        Ok(text) => {
                            crate::tprintln!("-------------------- BODY --------------------");
                            for line in text.lines() {
                                crate::tprintln!("{line}");
                            }
                        }
                        Err(_) => {
                            let preview_len = message.plaintext.len().min(256);
                            crate::tprintln!(
                                "Binary payload preview ({} of {} bytes): {}",
                                preview_len,
                                message.plaintext.len(),
                                hex::encode(&message.plaintext[..preview_len])
                            );
                        }
                    }
                }
                Err(error) => crate::tprintln!("Could not read mailbox message: {error}"),
            }
        }
        "delete" => {
            let selector = selector.unwrap_or_else(|| read_line("Message number or id: "));
            let message_id = match resolve_mail_selector(mailbox, &selector).await {
                Ok(id) => id,
                Err(error) => {
                    crate::tprintln!("{error}");
                    return;
                }
            };
            match mailbox.delete_inbox(message_id).await {
                Ok(()) => crate::tprintln!(
                    "Deleted local inbox copy {}. This does not erase remote custodian copies.",
                    hex_id(&message_id)
                ),
                Err(error) => crate::tprintln!("Could not delete mailbox message: {error}"),
            }
        }
        "retrieve" => match mailbox.retrieve_our_mail().await {
            Ok(()) => crate::tprintln!(
                "Mailbox retrieval requested. The network supervisor will schedule the required walk."
            ),
            Err(error) => crate::tprintln!("Could not request mailbox retrieval: {error}"),
        },
        "stats" => match mailbox.status().await {
            Ok(status) => {
                crate::tprintln!("Mailbox statistics:");
                crate::tprintln!("  Stored inbox messages: {}", status.stored_inbox_count);
                crate::tprintln!("  Unread inbox messages: {}", status.unread_inbox_count);
                crate::tprintln!("  Active outgoing messages: {}", status.outgoing_message_count);
                crate::tprintln!("  Awaiting responses: {}", status.awaiting_response_count);
                crate::tprintln!("  Known custodians: {}", status.known_custodian_count);
                crate::tprintln!("  Pending DHT page sets: {}", status.pending_page_sets);
                crate::tprintln!(
                    "  Self-seeding: enabled whenever this node participates as a custodian"
                );
            }
            Err(error) => crate::tprintln!("Could not read mailbox statistics: {error}"),
        },
        "flush" => match mailbox.flush().await {
            Ok(()) => crate::tprintln!("Mailbox DHT writes flushed."),
            Err(error) => crate::tprintln!("Mailbox flush failed: {error}"),
        },
        "repair" => match mailbox.repair().await {
            Ok(()) => crate::tprintln!("Mailbox stores reloaded and repaired."),
            Err(error) => crate::tprintln!("Mailbox repair failed: {error}"),
        },
        "help" => {
            crate::tprintln!("mail send            Send and immediately self-seed mailbox mail");
            crate::tprintln!("mail/status          Show mailbox addresses and counts");
            crate::tprintln!("mail list            List persisted received messages");
            crate::tprintln!("mail read <n|id>     Read and mark a message as read");
            crate::tprintln!("mail delete <n|id>   Delete the local inbox copy");
            crate::tprintln!("mail retrieve        Request an immediate retrieval walk");
            crate::tprintln!("mail stats           Show mailbox counters");
            crate::tprintln!("mail flush           Commit pending mailbox DHT writes");
            crate::tprintln!("mail repair          Reload and validate mailbox stores");
        }
        _ => crate::tprintln!("Unknown mail command. Use 'mail help'."),
    }
}

async fn resolve_mail_selector(
    mailbox: &Arc<MailboxManager>,
    selector: &str,
) -> Result<[u8; 32], String> {
    let messages = mailbox
        .list_inbox()
        .await
        .map_err(|error| format!("Could not list mailbox messages: {error}"))?;
    let selector = selector.trim();
    if let Ok(index) = selector.parse::<usize>() {
        if index == 0 || index > messages.len() {
            return Err(format!(
                "Message number must be between 1 and {}.",
                messages.len()
            ));
        }
        return Ok(messages[index - 1].message_id);
    }

    let normalized = selector.to_ascii_lowercase();
    if normalized.len() < 8 || !normalized.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("Use a list number or at least eight hexadecimal id characters.".to_string());
    }
    let matching: Vec<_> = messages
        .iter()
        .filter(|message| hex_id(&message.message_id).starts_with(&normalized))
        .collect();
    match matching.as_slice() {
        [message] => Ok(message.message_id),
        [] => Err("No inbox message matches that id.".to_string()),
        _ => Err("That id prefix matches more than one message; enter more characters.".to_string()),
    }
}

fn mailbox_age(timestamp: u64) -> String {
    let elapsed = current_timestamp().saturating_sub(timestamp);
    match elapsed {
        0..=59 => format!("{}s", elapsed),
        60..=3_599 => format!("{}m", elapsed / 60),
        3_600..=86_399 => format!("{}h", elapsed / 3_600),
        _ => format!("{}d", elapsed / 86_400),
    }
}

fn shorten_console(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_string();
    }
    let keep = maximum.saturating_sub(3);
    format!("{}...", value.chars().take(keep).collect::<String>())
}

fn print_command_help() {
    crate::tprintln!("Core commands:");
    crate::tprintln!("  mail ...              Mailbox status, inbox, retrieval, and maintenance");
    crate::tprintln!("  app-pending/approve/reject  Review first-run app authorization");
    crate::tprintln!("  app-add/list/rotate          Manage authenticated local applications");
    crate::tprintln!("  app-name ...                 Set the default or per-app visible name");
    crate::tprintln!("  reputation explain <peer>    Explain one peer's current reputation state");
    crate::tprintln!("  profile-list/create/use/retire Manage isolated network profiles");
    crate::tprintln!("  backup-local <path>   Create an encrypted .veilknit-backup archive");
    crate::tprintln!("  backup-inspect <path> Verify and describe a local backup");
    crate::tprintln!("  recovery-upload <path> Upload an encrypted backup to a random recovery DHT");
    crate::tprintln!("  recovery-download <code> <path> Download a recovery archive");
    crate::tprintln!("  recovery-status/wipe  Inspect or wipe the configured recovery record");
    crate::tprintln!("  log or U              Save the current session log");
    crate::tprintln!("  T/P/O                 Start, inspect, or stop a network walk");
    crate::tprintln!("  H/K                   Start or inspect a handshake");
    crate::tprintln!("  I                     Show internal nodes");
    crate::tprintln!("  lex-test-set <text...>       Feed diagnostic text into the distributed lexical library");
    crate::tprintln!("  lex-test-search <words...>    Search lexical gossip + durable librarian DHTs");
    crate::tprintln!("  lex-test-compare <a> <b>      Compare spelling/accent/transliteration/leet similarity");
    crate::tprintln!("  lex-test-stats                Inspect diagnostic lexical-library state");
    crate::tprintln!("  gossip-test-set <words...>    Publish exact-search diagnostic words");
    crate::tprintln!("  gossip-test-search <words...> Search another node for all words");
    crate::tprintln!("  gossip-test-list/stats        Inspect the diagnostic gossip cache");
    crate::tprintln!("  D                     Show daemon and DHT status");
    crate::tprintln!("  Q                     Save and shut down");
    crate::tprintln!("Legacy DHT test commands remain available: N/G/W/A/R/L/E/X/Y/S/C.");
    crate::tprintln!("Use 'mail help' for mailbox subcommands.");
}

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_line(prompt: &str) -> String {
    if let Some(value) = console_ui::prompt(prompt) {
        return value;
    }
    #[cfg(any(target_os = "android", target_os = "ios"))]
    if GUI_BRIDGE_MODE.load(Ordering::Relaxed) {
        return mobile_bridge::read_command();
    }
    if !GUI_BRIDGE_MODE.load(Ordering::Relaxed) {
        print!("{prompt}");
        io::stdout().flush().ok();
    }
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .expect("Failed to read line");
    buf.trim().to_owned()
}

fn parse_gossip_test_terms(input: &str) -> Vec<String> {
    input
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn print_basic_command_menu() {
    println!("*************************************");
    println!("* N New DHT       G Inspect DHT     *");
    println!("* W Write          A Write all       *");
    println!("* R/L Owned reads  E/X/Y External    *");
    println!("* S Save           C Route status    *");
    println!("* D Debug          H/K Handshake     *");
    println!("* T/P/O Walk       I Internal nodes  *");
    println!("* mail ... Mailbox V/Z Reputation    *");
    println!("* app-pending/approve/reject | help   *");
    println!("* app-add/list/rotate                 *");
    println!("* app-name ... App-visible aliases    *");
    println!("* profile-... Network profiles        *");
    println!("* backup-/recovery-... Identity backup *");
    println!("* lex-test-set/search/compare/stats    *");
    println!("* gossip-test-set/search/list/stats    *");
    println!("* U/log Save log   Q Quit             *");
    println!("*************************************");
}

#[derive(serde::Serialize)]
struct SavedAppCredentialFile {
    protocol_version: u16,
    endpoint: String,
    app_id: String,
    display_name: String,
    secret_hex: String,
    credential_generation: u64,
}

fn save_app_credential_file(
    credential: &AppCredential,
    display_name: &str,
    endpoint: &str,
) -> io::Result<std::path::PathBuf> {
    let safe_name: String = credential
        .app_id
        .to_string()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let directory = std::path::PathBuf::from("app_credentials");
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{safe_name}.json"));
    let document = SavedAppCredentialFile {
        protocol_version: named_pipe_api::LOCAL_API_PROTOCOL_VERSION,
        endpoint: endpoint.to_string(),
        app_id: credential.app_id.to_string(),
        display_name: display_name.to_string(),
        secret_hex: hex::encode(credential.secret_bytes()),
        credential_generation: credential.credential_generation,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    bytes.push(b'\n');
    std::fs::write(&path, bytes)?;
    Ok(path)
}

fn print_dht_value(location: u32, data: &[u8]) {
    match std::str::from_utf8(data) {
        Ok(text) => crate::tprintln!("  [{}] -> \"{}\"", location, text),
        Err(_) => crate::tprintln!("  [{}] -> {} raw bytes: {:?}", location, data.len(), data),
    }
}

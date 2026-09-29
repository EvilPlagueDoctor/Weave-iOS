//! JNI bridge for the Android foreground service.
//!
//! The existing daemon is deliberately kept command-compatible with the
//! desktop GUI. Android sends the same newline-oriented commands through a
//! channel, while log lines are buffered for Kotlin to poll.

use std::{
    collections::VecDeque,
    fs,
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Mutex, OnceLock,
    },
    thread,
};

use jni::{
    errors::LogErrorAndDefault,
    objects::{JClass, JObject, JString},
    sys::{jboolean, jlong, jstring, JNI_FALSE, JNI_TRUE},
    EnvUnowned,
};

const MAX_PENDING_LOG_LINES: usize = 20_000;

static COMMAND_SENDER: OnceLock<Mutex<Option<Sender<String>>>> = OnceLock::new();
static COMMAND_RECEIVER: OnceLock<Mutex<Option<Receiver<String>>>> = OnceLock::new();
static LOG_QUEUE: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static COMMAND_LOOP_READY: AtomicBool = AtomicBool::new(false);
const STOP_SENTINEL: &str = "__VEILKNIT_ANDROID_STOP__";

fn command_sender() -> &'static Mutex<Option<Sender<String>>> {
    COMMAND_SENDER.get_or_init(|| Mutex::new(None))
}

fn command_receiver() -> &'static Mutex<Option<Receiver<String>>> {
    COMMAND_RECEIVER.get_or_init(|| Mutex::new(None))
}

fn log_queue() -> &'static Mutex<VecDeque<String>> {
    LOG_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

pub(crate) fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

/// True only while Android has requested a stop but the daemon has not yet
/// reached its normal command loop.
///
/// Startup contains several DHT-backed recovery/initialization steps.  A
/// regular queued `Q` command cannot interrupt those awaits because the
/// command loop is not alive yet.  DHTModule uses this narrower signal to
/// abandon startup-only waits promptly without also cancelling the deliberate
/// network writes performed by Lifecycle during an ordinary graceful stop.
pub(crate) fn startup_stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
        && !COMMAND_LOOP_READY.load(Ordering::SeqCst)
}

/// Android currently does not forward ConnectivityManager change callbacks
/// into the Rust bridge. Keep a stable generation until that callback is
/// explicitly wired, so the network wait loop can still compile and operate.
pub(crate) fn network_change_generation() -> u64 {
    0
}

pub(crate) fn network_description() -> &'static str {
    "Android network (bridge callback unavailable)"
}

pub(crate) fn publish_log(line: &str) {
    let mut queue = log_queue()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    queue.push_back(line.to_owned());
    while queue.len() > MAX_PENDING_LOG_LINES {
        queue.pop_front();
    }
}

pub(crate) fn read_command() -> String {
    loop {
        if STOP_REQUESTED.load(Ordering::Relaxed) {
            return STOP_SENTINEL.to_string();
        }

        let received = {
            let guard = command_receiver()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            guard.as_ref().and_then(|receiver| receiver.recv().ok())
        };

        match received {
            Some(command) => return command,
            None => return "Q".to_string(),
        }
    }
}


pub(crate) fn mark_command_loop_ready() {
    COMMAND_LOOP_READY.store(true, Ordering::SeqCst);
}

pub(crate) fn is_stop_sentinel(value: &str) -> bool {
    value == STOP_SENTINEL
}

fn send_command(command: String) -> bool {
    let guard = command_sender()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    guard
        .as_ref()
        .map(|sender| sender.send(command).is_ok())
        .unwrap_or(false)
}

fn clear_bridge_state() {
    *command_sender()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    *command_receiver()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    STOP_REQUESTED.store(false, Ordering::Relaxed);
    COMMAND_LOOP_READY.store(false, Ordering::Relaxed);
}


#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeStart(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
    data_directory: JString<'_>,
    signup: jboolean,
    username: JString<'_>,
    password: JString<'_>,
) -> jboolean {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return JNI_FALSE;
    }

    let arguments = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<(String, String, String)>> {
            Ok(Some((
                data_directory.try_to_string(env)?,
                username.try_to_string(env)?,
                password.try_to_string(env)?,
            )))
        })
        .resolve::<LogErrorAndDefault>();

    let (data_directory, username, password) = match arguments {
        Some(values) => values,
        None => {
            publish_log("[android] Could not read arguments passed from Kotlin.");
            RUNNING.store(false, Ordering::SeqCst);
            return JNI_FALSE;
        }
    };

    veilid_core::veilid_core_setup_android(unowned_env, context);

    let signup = signup == JNI_TRUE;

    STOP_REQUESTED.store(false, Ordering::SeqCst);
    COMMAND_LOOP_READY.store(false, Ordering::SeqCst);
    log_queue()
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();

    let (sender, receiver) = mpsc::channel::<String>();
    *command_sender()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(sender.clone());
    *command_receiver()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(receiver);

    // Seed the existing login/signup prompt sequence before the runtime starts.
    if sender
        .send(if signup { "s" } else { "l" }.to_string())
        .and_then(|_| sender.send(username))
        .and_then(|_| sender.send(password))
        .is_err()
    {
        clear_bridge_state();
        RUNNING.store(false, Ordering::SeqCst);
        return JNI_FALSE;
    }

    thread::Builder::new()
        .name("veilknit-daemon".to_string())
        .spawn(move || {
            let data_root = PathBuf::from(data_directory);
            if let Err(error) = fs::create_dir_all(&data_root) {
                publish_log(&format!(
                    "[android] Could not create daemon data directory: {error}"
                ));
                clear_bridge_state();
                RUNNING.store(false, Ordering::SeqCst);
                return;
            }
            if let Err(error) = std::env::set_current_dir(&data_root) {
                publish_log(&format!(
                    "[android] Could not select daemon data directory: {error}"
                ));
                clear_bridge_state();
                RUNNING.store(false, Ordering::SeqCst);
                return;
            }
            std::env::set_var("VEILKNIT_DATA_DIR", &data_root);

            let run_result = panic::catch_unwind(AssertUnwindSafe(|| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .thread_name("veilknit-tokio")
                    .build()
                    .map_err(|error| error.to_string())?;
                runtime
                    .block_on(crate::run_daemon(true))
                    .map_err(|error| error.to_string())
            }));

            match run_result {
                Ok(Ok(())) => publish_log("[android] Daemon stopped."),
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let lower = message.to_ascii_lowercase();
                    let intentional_stop = STOP_REQUESTED.load(Ordering::SeqCst)
                        && (lower.contains("stop requested") || lower.contains("interrupted"));
                    if intentional_stop {
                        // A user can stop the foreground service while Veilid is still attaching
                        // or while the main-DHT network probe is running.  Those helpers return an
                        // Interrupted/stop-requested error to unwind startup quickly; it is not a
                        // daemon failure and should not turn the Android notification red.
                        publish_log("[android] Daemon stopped.");
                    } else {
                        publish_log(&format!("[android] Daemon error: {message}"));
                    }
                }
                Err(_) => publish_log("[android] Daemon panicked."),
            }

            clear_bridge_state();
            RUNNING.store(false, Ordering::SeqCst);
        })
        .map(|_| JNI_TRUE)
        .unwrap_or_else(|error| {
            publish_log(&format!("[android] Could not start daemon thread: {error}"));
            clear_bridge_state();
            RUNNING.store(false, Ordering::SeqCst);
            JNI_FALSE
        })
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeSendCommand(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    command: JString<'_>,
) -> jboolean {
    let command = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<String>> {
            Ok(Some(command.try_to_string(env)?))
        })
        .resolve::<LogErrorAndDefault>();

    let Some(command) = command else {
        return JNI_FALSE;
    };

    if send_command(command) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeRequestStop(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jboolean {
    // Android stop is an out-of-band cancellation request, not merely another console
    // command.  Set the flag even after the command loop is ready so startup/network wait
    // helpers and the command reader all agree that shutdown has been requested.
    STOP_REQUESTED.store(true, Ordering::SeqCst);

    if !RUNNING.load(Ordering::SeqCst) {
        return JNI_TRUE;
    }

    // Once the normal command loop is alive, Q preserves the same user-visible path as the
    // desktop/UI shutdown button.  Before that point, the sentinel can also unblock login or
    // the first command read.  read_command() checks STOP_REQUESTED first, so either token is
    // only a wake-up mechanism; the actual cleanup still goes through Lifecycle.
    let wake_command = if COMMAND_LOOP_READY.load(Ordering::SeqCst) {
        "Q"
    } else {
        STOP_SENTINEL
    };

    if send_command(wake_command.to_string()) || !RUNNING.load(Ordering::SeqCst) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeIsRunning(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jboolean {
    if RUNNING.load(Ordering::SeqCst) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}


#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeRestoreBackup(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    data_directory: JString<'_>,
    backup_path: JString<'_>,
    passphrase: JString<'_>,
) -> jstring {
    let arguments = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<(String, String, String)>> {
            Ok(Some((
                data_directory.try_to_string(env)?,
                backup_path.try_to_string(env)?,
                passphrase.try_to_string(env)?,
            )))
        })
        .resolve::<LogErrorAndDefault>();

    let message = match arguments {
        None => "Backup restore failed: Android could not read the selected file details.".to_string(),
        Some(_) if RUNNING.load(Ordering::SeqCst) =>
            "Backup restore failed: stop the daemon before restoring an identity.".to_string(),
        Some((data_directory, backup_path, passphrase)) => {
            let users_root = PathBuf::from(data_directory).join("user_data");
            match crate::user_auth::UserAuth::new(users_root)
                .and_then(|auth| auth.restore_local_backup(&backup_path, &passphrase))
            {
                Ok(metadata) => format!(
                    "Restored account '{}'. Log in with its original account password.",
                    metadata.username
                ),
                Err(error) => format!("Backup restore failed: {error}"),
            }
        }
    };

    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            let value = JString::from_str(env, message)?;
            Ok(value.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeDrainLogs(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jstring {
    let lines: Vec<String> = {
        let mut queue = log_queue()
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        queue.drain(..).collect()
    };

    let payload = serde_json::to_string(&lines).unwrap_or_else(|_| "[]".to_string());

    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            let value = JString::from_str(env, payload)?;
            Ok(value.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}


#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeEmbeddedTransact(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    request_json: JString<'_>,
) -> jstring {
    let request = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<String>> {
            Ok(Some(request_json.try_to_string(env)?))
        })
        .resolve::<LogErrorAndDefault>();

    let response = match request {
        Some(request) => crate::named_pipe_api::embedded_transact(request),
        None => r#"{"protocol_version":3,"request_id":0,"ok":false,"error":{"code":"embedded_bridge_error","message":"Android could not read the request"}}"#.to_string(),
    };

    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            let value = JString::from_str(env, response)?;
            Ok(value.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeEmbeddedRecoverAppCredential(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    app_id: JString<'_>,
) -> jstring {
    let app_id = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<String>> {
            Ok(Some(app_id.try_to_string(env)?))
        })
        .resolve::<LogErrorAndDefault>();

    let response = match app_id {
        Some(app_id) => crate::named_pipe_api::embedded_recover_app_credential(app_id),
        None => serde_json::json!({
            "ok": false,
            "error": "Android could not read the application id",
        })
        .to_string(),
    };

    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            let value = JString::from_str(env, response)?;
            Ok(value.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeEmbeddedSubscribe(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    request_json: JString<'_>,
) -> jlong {
    let request = unowned_env
        .with_env(|env| -> jni::errors::Result<Option<String>> {
            Ok(Some(request_json.try_to_string(env)?))
        })
        .resolve::<LogErrorAndDefault>();

    request
        .map(crate::named_pipe_api::embedded_subscribe)
        .unwrap_or(0) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeEmbeddedDrainSubscription(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
    subscription_id: jlong,
) -> jstring {
    let lines = if subscription_id > 0 {
        crate::named_pipe_api::embedded_drain_subscription(subscription_id as u64)
    } else {
        Vec::new()
    };
    let payload = serde_json::to_string(&lines).unwrap_or_else(|_| "[]".to_string());
    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            let value = JString::from_str(env, payload)?;
            Ok(value.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeEmbeddedSubscriptionActive(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    subscription_id: jlong,
) -> jboolean {
    if subscription_id > 0
        && crate::named_pipe_api::embedded_subscription_active(subscription_id as u64)
    {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeEmbeddedProfileId(
    mut unowned_env: EnvUnowned<'_>,
    _class: JClass<'_>,
) -> jstring {
    let profile_id = crate::named_pipe_api::embedded_profile_id();
    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            let value = JString::from_str(env, profile_id)?;
            Ok(value.into_raw())
        })
        .resolve::<LogErrorAndDefault>()
}

#[no_mangle]
pub extern "system" fn Java_com_example_veilknit_1deamon_NativeDaemonBridge_nativeEmbeddedUnsubscribe(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    subscription_id: jlong,
) -> jboolean {
    if subscription_id <= 0 {
        return JNI_FALSE;
    }
    crate::named_pipe_api::embedded_unsubscribe(subscription_id as u64);
    JNI_TRUE
}

//! C ABI bridge used by the native Swift/SwiftUI iOS host.
//!
//! iOS cannot use the Android JNI/foreground-service layer. This module keeps the
//! same in-process protocol-v3 dispatcher and daemon command channel while exposing
//! a small C ABI that Swift can call through a bridging header.

use std::{
    collections::VecDeque,
    ffi::{CStr, CString},
    fs,
    os::raw::c_char,
    panic::{self, AssertUnwindSafe},
    path::PathBuf,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Mutex, OnceLock,
    },
    thread,
};

const MAX_PENDING_LOG_LINES: usize = 20_000;
const STOP_SENTINEL: &str = "__VEILKNIT_IOS_STOP__";

static COMMAND_SENDER: OnceLock<Mutex<Option<Sender<String>>>> = OnceLock::new();
static COMMAND_RECEIVER: OnceLock<Mutex<Option<Receiver<String>>>> = OnceLock::new();
static LOG_QUEUE: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
static RUNNING: AtomicBool = AtomicBool::new(false);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static COMMAND_LOOP_READY: AtomicBool = AtomicBool::new(false);

fn command_sender() -> &'static Mutex<Option<Sender<String>>> {
    COMMAND_SENDER.get_or_init(|| Mutex::new(None))
}

fn command_receiver() -> &'static Mutex<Option<Receiver<String>>> {
    COMMAND_RECEIVER.get_or_init(|| Mutex::new(None))
}

fn log_queue() -> &'static Mutex<VecDeque<String>> {
    LOG_QUEUE.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn c_string(value: *const c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(value) }.to_str().ok().map(ToOwned::to_owned)
}

fn owned_c_string(value: impl Into<String>) -> *mut c_char {
    let value = value.into().replace('\0', "�");
    CString::new(value)
        .unwrap_or_else(|_| CString::new("{\"ok\":false,\"error\":\"invalid string\"}").unwrap())
        .into_raw()
}

pub(crate) fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

pub(crate) fn startup_stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst) && !COMMAND_LOOP_READY.load(Ordering::SeqCst)
}

/// The Swift host can later increment this when NWPathMonitor reports a path change.
/// Keep the first iOS conversion stable and equivalent to the Android bridge for now.
pub(crate) fn network_change_generation() -> u64 {
    0
}

pub(crate) fn network_description() -> &'static str {
    "iOS network (bridge callback unavailable)"
}

pub(crate) fn publish_log(line: &str) {
    let mut queue = log_queue().lock().unwrap_or_else(|error| error.into_inner());
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
            let guard = command_receiver().lock().unwrap_or_else(|error| error.into_inner());
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
    let guard = command_sender().lock().unwrap_or_else(|error| error.into_inner());
    guard
        .as_ref()
        .map(|sender| sender.send(command).is_ok())
        .unwrap_or(false)
}

fn clear_bridge_state() {
    *command_sender().lock().unwrap_or_else(|error| error.into_inner()) = None;
    *command_receiver().lock().unwrap_or_else(|error| error.into_inner()) = None;
    STOP_REQUESTED.store(false, Ordering::Relaxed);
    COMMAND_LOOP_READY.store(false, Ordering::Relaxed);
}

#[no_mangle]
pub extern "C" fn weave_veilknit_start(
    data_directory: *const c_char,
    signup: bool,
    username: *const c_char,
    password: *const c_char,
) -> bool {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return false;
    }

    let Some(data_directory) = c_string(data_directory) else {
        RUNNING.store(false, Ordering::SeqCst);
        return false;
    };
    let Some(username) = c_string(username) else {
        RUNNING.store(false, Ordering::SeqCst);
        return false;
    };
    let Some(password) = c_string(password) else {
        RUNNING.store(false, Ordering::SeqCst);
        return false;
    };

    STOP_REQUESTED.store(false, Ordering::SeqCst);
    COMMAND_LOOP_READY.store(false, Ordering::SeqCst);
    log_queue().lock().unwrap_or_else(|error| error.into_inner()).clear();

    let (sender, receiver) = mpsc::channel::<String>();
    *command_sender().lock().unwrap_or_else(|error| error.into_inner()) = Some(sender.clone());
    *command_receiver().lock().unwrap_or_else(|error| error.into_inner()) = Some(receiver);

    if sender
        .send(if signup { "s" } else { "l" }.to_string())
        .and_then(|_| sender.send(username))
        .and_then(|_| sender.send(password))
        .is_err()
    {
        clear_bridge_state();
        RUNNING.store(false, Ordering::SeqCst);
        return false;
    }

    match thread::Builder::new()
        .name("veilknit-daemon".to_string())
        .spawn(move || {
            let data_root = PathBuf::from(data_directory);
            if let Err(error) = fs::create_dir_all(&data_root) {
                publish_log(&format!("[ios] Could not create daemon data directory: {error}"));
                clear_bridge_state();
                RUNNING.store(false, Ordering::SeqCst);
                return;
            }
            if let Err(error) = std::env::set_current_dir(&data_root) {
                publish_log(&format!("[ios] Could not select daemon data directory: {error}"));
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
                Ok(Ok(())) => publish_log("[ios] Daemon stopped."),
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let lower = message.to_ascii_lowercase();
                    let intentional_stop = STOP_REQUESTED.load(Ordering::SeqCst)
                        && (lower.contains("stop requested") || lower.contains("interrupted"));
                    if intentional_stop {
                        publish_log("[ios] Daemon stopped.");
                    } else {
                        publish_log(&format!("[ios] Daemon error: {message}"));
                    }
                }
                Err(_) => publish_log("[ios] Daemon panicked."),
            }

            clear_bridge_state();
            RUNNING.store(false, Ordering::SeqCst);
        })
    {
        Ok(_) => true,
        Err(error) => {
            publish_log(&format!("[ios] Could not start daemon thread: {error}"));
            clear_bridge_state();
            RUNNING.store(false, Ordering::SeqCst);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn weave_veilknit_send_command(command: *const c_char) -> bool {
    c_string(command).map(send_command).unwrap_or(false)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_request_stop() -> bool {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    if !RUNNING.load(Ordering::SeqCst) {
        return true;
    }
    let wake = if COMMAND_LOOP_READY.load(Ordering::SeqCst) {
        "Q"
    } else {
        STOP_SENTINEL
    };
    send_command(wake.to_string()) || !RUNNING.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_restore_backup(
    data_directory: *const c_char,
    backup_path: *const c_char,
    passphrase: *const c_char,
) -> *mut c_char {
    if RUNNING.load(Ordering::SeqCst) {
        return owned_c_string("Backup restore failed: stop the daemon before restoring an identity.");
    }
    let Some(data_directory) = c_string(data_directory) else {
        return owned_c_string("Backup restore failed: missing data directory.");
    };
    let Some(backup_path) = c_string(backup_path) else {
        return owned_c_string("Backup restore failed: missing backup path.");
    };
    let Some(passphrase) = c_string(passphrase) else {
        return owned_c_string("Backup restore failed: missing passphrase.");
    };
    let users_root = PathBuf::from(data_directory).join("user_data");
    let message = match crate::user_auth::UserAuth::new(users_root)
        .and_then(|auth| auth.restore_local_backup(&backup_path, &passphrase))
    {
        Ok(metadata) => format!(
            "Restored account '{}'. Log in with its original account password.",
            metadata.username
        ),
        Err(error) => format!("Backup restore failed: {error}"),
    };
    owned_c_string(message)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_drain_logs() -> *mut c_char {
    let lines: Vec<String> = {
        let mut queue = log_queue().lock().unwrap_or_else(|error| error.into_inner());
        queue.drain(..).collect()
    };
    owned_c_string(serde_json::to_string(&lines).unwrap_or_else(|_| "[]".to_string()))
}

#[no_mangle]
pub extern "C" fn weave_veilknit_transact(request_json: *const c_char) -> *mut c_char {
    let response = c_string(request_json)
        .map(crate::named_pipe_api::embedded_transact)
        .unwrap_or_else(|| r#"{"protocol_version":3,"request_id":0,"ok":false,"error":{"code":"embedded_bridge_error","message":"iOS could not read the request"}}"#.to_string());
    owned_c_string(response)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_recover_app_credential(app_id: *const c_char) -> *mut c_char {
    let response = c_string(app_id)
        .map(crate::named_pipe_api::embedded_recover_app_credential)
        .unwrap_or_else(|| serde_json::json!({"ok": false, "error": "iOS could not read the application id"}).to_string());
    owned_c_string(response)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_subscribe(request_json: *const c_char) -> u64 {
    c_string(request_json)
        .map(crate::named_pipe_api::embedded_subscribe)
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_drain_subscription(subscription_id: u64) -> *mut c_char {
    let lines = if subscription_id > 0 {
        crate::named_pipe_api::embedded_drain_subscription(subscription_id)
    } else {
        Vec::new()
    };
    owned_c_string(serde_json::to_string(&lines).unwrap_or_else(|_| "[]".to_string()))
}

#[no_mangle]
pub extern "C" fn weave_veilknit_subscription_active(subscription_id: u64) -> bool {
    subscription_id > 0 && crate::named_pipe_api::embedded_subscription_active(subscription_id)
}

#[no_mangle]
pub extern "C" fn weave_veilknit_profile_id() -> *mut c_char {
    owned_c_string(crate::named_pipe_api::embedded_profile_id())
}

#[no_mangle]
pub extern "C" fn weave_veilknit_unsubscribe(subscription_id: u64) -> bool {
    if subscription_id == 0 {
        return false;
    }
    crate::named_pipe_api::embedded_unsubscribe(subscription_id);
    true
}

#[no_mangle]
pub extern "C" fn weave_veilknit_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(value));
    }
}

#[no_mangle]
pub extern "C" fn weave_veilknit_null_string() -> *mut c_char {
    ptr::null_mut()
}

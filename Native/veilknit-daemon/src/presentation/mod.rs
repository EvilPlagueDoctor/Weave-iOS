//! Optional human-facing console presentation.
//!
//! The network core emits structured events and can compile without the
//! terminal dashboard. Android uses a lightweight bridge implementation.

pub(crate) mod console_log;

#[cfg(any(target_os = "android", target_os = "ios"))]
#[path = "console_ui_android.rs"]
pub(crate) mod console_ui;

#[cfg(all(not(any(target_os = "android", target_os = "ios")), feature = "console-ui"))]
#[path = "console_ui.rs"]
pub(crate) mod console_ui;

#[cfg(all(not(any(target_os = "android", target_os = "ios")), not(feature = "console-ui")))]
#[path = "console_ui_stub.rs"]
pub(crate) mod console_ui;

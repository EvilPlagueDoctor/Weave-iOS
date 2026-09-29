//! Optional command-line launcher for the Android daemon library.
//!
//! Android normally starts the daemon through JNI/Binder. Keeping this binary
//! tiny avoids compiling a second, independent copy of the daemon module tree.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let gui_bridge_mode = std::env::args()
        .any(|argument| argument.eq_ignore_ascii_case("--gui"));
    veilknit_daemon::run_daemon(gui_bridge_mode).await
}

use arc_swap::ArcSwapOption;
use futures::future::BoxFuture;
use std::{
    io,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use veilid_core::*;

/// Generic async handler type
pub type AsyncHandler<T> =
    Arc<dyn Fn(T) -> BoxFuture<'static, ()> + Send + Sync>;

/// Handler aliases
pub type AppMessageHandler = AsyncHandler<Vec<u8>>;
pub type RouteChangeHandler = AsyncHandler<Vec<RouteId>>;
pub type ShutdownHandler = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;
pub type AttachmentHandler = AsyncHandler<VeilidStateAttachment>;
pub type NetworkHandler = Arc<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync>;

/// Internal handler storage
pub struct NodeHandlers {
    pub app_message_handler: ArcSwapOption<AppMessageHandler>,
    pub route_change_handler: ArcSwapOption<RouteChangeHandler>,
    pub shutdown_handler: ArcSwapOption<ShutdownHandler>,
    pub attachment_handler: ArcSwapOption<AttachmentHandler>,
    pub network_handler: ArcSwapOption<NetworkHandler>,
}

impl NodeHandlers {
    pub fn new() -> Self {
        Self {
            app_message_handler: ArcSwapOption::empty(),
            route_change_handler: ArcSwapOption::empty(),
            shutdown_handler: ArcSwapOption::empty(),
            attachment_handler: ArcSwapOption::empty(),
            network_handler: ArcSwapOption::empty(),
        }
    }

    async fn handle_update(&self, update: VeilidUpdate) {
        match update {
            VeilidUpdate::AppMessage(msg) => {
                if let Some(handler) = self.app_message_handler.load().as_ref() {
                    let handler = Arc::clone(handler);

                    let data = msg.message().to_vec();

                    handler(data).await;
                }
            }

            VeilidUpdate::RouteChange(change) => {
                if let Some(handler) = self.route_change_handler.load().as_ref() {
                    let handler = Arc::clone(handler);

                    handler(change.dead_routes).await;
                }
            }

            VeilidUpdate::Shutdown => {
                if let Some(handler) = self.shutdown_handler.load().as_ref() {
                    let handler = Arc::clone(handler);

                    handler().await;
                }
            }

            VeilidUpdate::Attachment(state) => {
                if let Some(handler) = self.attachment_handler.load().as_ref() {
                    let handler = Arc::clone(handler);

                    handler(*state).await;
                }
            }

            VeilidUpdate::Network(_) => {
                if let Some(handler) = self.network_handler.load().as_ref() {
                    let handler = Arc::clone(handler);

                    handler().await;
                }
            }

            _ => {}
        }
    }
}

/// Main node structure
pub struct Node {
    pub veilid: VeilidAPI,

    handlers: Arc<NodeHandlers>,

    /// Limits concurrent update tasks
    update_semaphore: Arc<Semaphore>,
}

impl Node {
    /// Set app message handler
    pub fn set_app_message_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let wrapped: AppMessageHandler = Arc::new(move |data| {
            Box::pin(handler(data))
        });

        self.handlers
            .app_message_handler
            .store(Some(Arc::new(wrapped)));
    }

    /// Set route change handler
    pub fn set_route_change_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Vec<RouteId>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let wrapped: RouteChangeHandler = Arc::new(move |routes| {
            Box::pin(handler(routes))
        });

        self.handlers
            .route_change_handler
            .store(Some(Arc::new(wrapped)));
    }

    /// Set shutdown handler
    pub fn set_shutdown_handler<F, Fut>(&self, handler: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let wrapped: ShutdownHandler = Arc::new(move || {
            Box::pin(handler())
        });

        self.handlers
            .shutdown_handler
            .store(Some(Arc::new(wrapped)));
    }

    /// Set attachment handler
    pub fn set_attachment_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(VeilidStateAttachment) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let wrapped: AttachmentHandler = Arc::new(move |state| {
            Box::pin(handler(state))
        });

        self.handlers
            .attachment_handler
            .store(Some(Arc::new(wrapped)));
    }

    /// Disable attachment callbacks during orderly shutdown. This prevents a
    /// final Veilid detach event from attempting DHT writes after the API has
    /// already begun shutting down.
    pub fn clear_attachment_handler(&self) {
        self.handlers.attachment_handler.store(None);
    }

    /// Set network handler
    pub fn set_network_handler<F, Fut>(&self, handler: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let wrapped: NetworkHandler = Arc::new(move || {
            Box::pin(handler())
        });

        self.handlers
            .network_handler
            .store(Some(Arc::new(wrapped)));
    }

    /// Shutdown node
    pub async fn shutdown(&self) {
	self.veilid.clone().shutdown().await;
    }

    /// Get state
    pub async fn get_state(&self) -> VeilidAPIResult<VeilidState> {
        self.veilid.get_state().await
    }

    /// Is attached
    pub async fn is_attached(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let state = self.veilid.get_state().await?;
        Ok(state.attachment.state.is_attached())
    }

	// yes, is_attached and is_network ready are the same thing, I'll probably combine them later, but for now I'm just experimenting.

    /// Is network ready
    pub async fn is_network_ready(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let state = self.veilid.get_state().await?;

	Ok(matches!(
    	    state.attachment.state,
    	    AttachmentState::AttachedWeak
        	| AttachmentState::AttachedFair
        	| AttachmentState::AttachedGood
        	| AttachmentState::AttachedStrong
        	| AttachmentState::AttachedFull
        ))
    }
}

/// Create node
pub async fn create_node(
    namespace: String,
) -> Result<Arc<Node>, Box<dyn std::error::Error + Send + Sync>> {

    let exe_dir = std::env::var_os("VEILKNIT_DATA_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|x| x.parent().map(|p| p.to_owned()))
        })
        .unwrap_or_else(|| ".".into());

	let protected_store_directory = exe_dir
	    .join(".veilid")
	    .join(&namespace)
	    .join("protected_store");
	
	let table_store_directory = exe_dir
	    .join(".veilid")
	    .join(&namespace)
	    .join("table_store");
	
	let block_store_directory = exe_dir
	    .join(".veilid")
	    .join(&namespace)
	    .join("block_store");
	
	std::fs::create_dir_all(&protected_store_directory)?;
	std::fs::create_dir_all(&table_store_directory)?;
	std::fs::create_dir_all(&block_store_directory)?;

    let config = VeilidConfig {
        program_name: "VeilKnitNode".into(),
        namespace: namespace.clone(),

        protected_store: VeilidConfigProtectedStore {
            always_use_insecure_storage: cfg!(any(target_os = "android", target_os = "ios")),
            directory: protected_store_directory
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        },

        table_store: VeilidConfigTableStore {
            directory: table_store_directory
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        },

        block_store: VeilidConfigBlockStore {
            directory: block_store_directory
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        },

        ..Default::default()
    };

    let handlers = Arc::new(NodeHandlers::new());

    let semaphore = Arc::new(Semaphore::new(50));

    let handlers_weak = Arc::downgrade(&handlers);

    let semaphore_clone = semaphore.clone();

    let callback = Arc::new(move |update: VeilidUpdate| {

        let Some(handlers) = handlers_weak.upgrade() else {
            return;
        };

        let semaphore = semaphore_clone.clone();

        tokio::spawn(async move {

            let permit = semaphore.acquire_owned().await;

            if permit.is_err() {
                return;
            }

            let _permit = permit.unwrap();

            handlers.handle_update(update).await;
        });
    });

    let veilid = veilid_core::api_startup(callback, config).await?;

    crate::tprintln!("[node] Attaching to network...");

    veilid.attach().await?;

    crate::tprintln!("[node] Waiting for network readiness...");

    if let Err(error) = wait_for_network(&veilid).await {
        crate::tprintln!("[node] Network readiness wait ended: {error}");
        veilid.clone().shutdown().await;
        return Err(error);
    }

    crate::tprintln!("[node] Network ready");

    let node = Arc::new(Node {
        veilid,
        handlers,
        update_semaphore: semaphore,
    });

    Ok(node)
}

/// How frequently the startup screen receives a concise Veilid status line.
const NETWORK_DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(5);
/// After this long, remain in the connecting state but make the stalled state explicit.
const NETWORK_WAIT_WARNING_AFTER: Duration = Duration::from_secs(30);
/// Give Android's active-network callback time to settle before one refresh attach.
#[cfg(any(target_os = "android", target_os = "ios"))]
const ANDROID_INITIAL_REATTACH_AFTER: Duration = Duration::from_secs(15);
/// Avoid repeatedly cycling Veilid when Android sends several callbacks for one change.
#[cfg(any(target_os = "android", target_os = "ios"))]
const ANDROID_REATTACH_COOLDOWN: Duration = Duration::from_secs(10);

fn startup_stop_requested() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        return crate::mobile_bridge::stop_requested();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        false
    }
}

fn startup_cancelled_error() -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::new(
        io::ErrorKind::Interrupted,
        "daemon stop requested while waiting for Veilid network readiness",
    ))
}

/// Wait for PublicInternet readiness while remaining observable and cancellable.
///
/// Veilid's `attach()` only starts the background attachment state machine. A
/// cellular interface can remain in an attaching state without returning an
/// error, so this loop deliberately keeps reporting state instead of silently
/// blocking. Android can also request one detach/attach refresh after its
/// validated default network changes.
async fn wait_for_network(
    veilid: &VeilidAPI,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    let mut last_diagnostic = Instant::now()
        .checked_sub(NETWORK_DIAGNOSTIC_INTERVAL)
        .unwrap_or_else(Instant::now);
    let mut last_signature = String::new();
    let mut warned = false;

    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut last_network_generation = crate::mobile_bridge::network_change_generation();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut pending_android_refresh = true;
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let mut last_android_refresh: Option<Instant> = None;

    loop {
        if startup_stop_requested() {
            crate::tprintln!("[node] Stop requested while waiting for network readiness.");
            return Err(startup_cancelled_error());
        }

        let state = veilid.get_state().await?;
        let attachment = &state.attachment;
        let elapsed_secs = started.elapsed().as_secs();
        let signature = format!(
            "{:?}|{}|{}|{}|{}",
            attachment.state,
            attachment.public_internet_ready,
            attachment.local_network_ready,
            state.network.started,
            state.network.peers.len(),
        );

        if signature != last_signature || last_diagnostic.elapsed() >= NETWORK_DIAGNOSTIC_INTERVAL {
            crate::tprintln!(
                "[node] Attachment status: state={:?}, public_ready={}, local_ready={}, network_started={}, peers={}, down={:?}, up={:?}, elapsed={}s",
                attachment.state,
                attachment.public_internet_ready,
                attachment.local_network_ready,
                state.network.started,
                state.network.peers.len(),
                state.network.bps_down,
                state.network.bps_up,
                elapsed_secs,
            );
            crate::tprintln!(
                "[gui] NETWORK_STATUS attachment={:?} public_ready={} local_ready={} network_started={} peers={} elapsed_secs={}",
                attachment.state,
                attachment.public_internet_ready,
                attachment.local_network_ready,
                state.network.started,
                state.network.peers.len(),
                elapsed_secs,
            );
            last_signature = signature;
            last_diagnostic = Instant::now();
        }

        if attachment.public_internet_ready {
            return Ok(());
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            let generation = crate::mobile_bridge::network_change_generation();
            if generation != last_network_generation {
                last_network_generation = generation;
                pending_android_refresh = true;
                crate::tprintln!(
                    "[node] Mobile active network changed: {}",
                    crate::mobile_bridge::network_description(),
                );
            }

            let refresh_cooled_down = last_android_refresh
                .map(|instant| instant.elapsed() >= ANDROID_REATTACH_COOLDOWN)
                .unwrap_or(true);
            if pending_android_refresh
                && started.elapsed() >= ANDROID_INITIAL_REATTACH_AFTER
                && refresh_cooled_down
            {
                pending_android_refresh = false;
                last_android_refresh = Some(Instant::now());
                crate::tprintln!(
                    "[node] Refreshing Veilid attachment after mobile network update: {}",
                    crate::mobile_bridge::network_description(),
                );

                match tokio::time::timeout(Duration::from_secs(5), veilid.detach()).await {
                    Ok(Ok(())) => crate::tprintln!("[node] Veilid detach requested for network refresh."),
                    Ok(Err(error)) => crate::tprintln!(
                        "[node] Veilid detach during network refresh returned: {error}"
                    ),
                    Err(_) => crate::tprintln!(
                        "[node] Veilid detach timed out during network refresh; attempting attach anyway."
                    ),
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
                if startup_stop_requested() {
                    return Err(startup_cancelled_error());
                }

                match tokio::time::timeout(Duration::from_secs(5), veilid.attach()).await {
                    Ok(Ok(())) => crate::tprintln!("[node] Veilid attachment restarted."),
                    Ok(Err(error)) => crate::tprintln!(
                        "[node] Veilid attach during network refresh returned: {error}"
                    ),
                    Err(_) => crate::tprintln!(
                        "[node] Veilid attach request timed out during network refresh."
                    ),
                }
            }
        }

        if !warned && started.elapsed() >= NETWORK_WAIT_WARNING_AFTER {
            warned = true;
            crate::tprintln!(
                "[node] Veilid has not reached PublicInternet readiness after {} seconds. The daemon remains cancellable and will continue retrying.",
                elapsed_secs,
            );
            #[cfg(any(target_os = "android", target_os = "ios"))]
            crate::tprintln!(
                "[node] Android network at timeout: {}",
                crate::mobile_bridge::network_description(),
            );
            crate::tprintln!("[gui] NETWORK_WAIT_WARNING elapsed_secs={elapsed_secs}");
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

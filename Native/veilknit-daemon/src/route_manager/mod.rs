use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::{sleep, timeout, Duration, Instant};
use veilid_core::{RouteId, Target, VeilidAPI, VeilidAPIResult};

use crate::dht_module::DHTModule;
use crate::node::Node;
use crate::types::{current_timestamp, RouteBlobRecord, BLOB_LOCATION};

// ============================================================================
// Readiness state
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    WaitingForNode,
    WaitingForDht,
    Ready,
}

// ============================================================================
// Publish lifecycle
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishState {
    Idle,
    Publishing,
}

// ============================================================================
// Status snapshot, handed back to callers who want to check on things
// (e.g. from a UI) without poking at the private Inner state directly.
// ============================================================================

#[derive(Debug, Clone)]
pub struct RouteManagerStatus {
    pub readiness: Readiness,
    pub publish_state: PublishState,
    pub active_route_id: Option<RouteId>,
}

impl RouteManagerStatus {
    fn unknown() -> Self {
        Self {
            readiness: Readiness::WaitingForNode,
            publish_state: PublishState::Idle,
            active_route_id: None,
        }
    }
}

// ============================================================================
// Messages
// ============================================================================

enum RouteManagerMsg {
    SetNode(Arc<Node>),

    /// The new DHTModule stores DHT records internally and refers to them by
    /// package index, not by RecordKey + external DhtStore.
    SetDht {
        dht_module: DHTModule,
        dht_package: usize,
    },

    RouteChange(Vec<RouteId>),

    GetStatus(oneshot::Sender<RouteManagerStatus>),

    // PATCH A: publication completes out-of-band so the actor remains
    // responsive to status queries and route-loss notifications.
    PublishFinished {
        generation: u64,
        result: Result<RouteId, String>,
    },
    RetryPublish,
}

// ============================================================================
// Public handle
// ============================================================================

#[derive(Clone)]
pub struct RouteManager {
    tx: mpsc::Sender<RouteManagerMsg>,
}

impl RouteManager {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(route_manager_task(rx, tx.clone()));
        Self { tx }
    }

    pub async fn set_node(&self, node: Arc<Node>) {
        if let Err(e) = self.tx.send(RouteManagerMsg::SetNode(node)).await {
            crate::tprintln!("[route_manager] Failed to send SetNode: {e}");
        }
    }

    /// Give the manager the DHT package it should publish our current
    /// private-route blob to.
    ///
    /// `dht_package` is the usize index returned by `DHTModule::create_dht(...)`
    /// or the index assigned after importing/restoring a DHT snapshot.
    pub async fn set_dht(&self, dht_module: DHTModule, dht_package: usize) {
        if let Err(e) = self
            .tx
            .send(RouteManagerMsg::SetDht {
                dht_module,
                dht_package,
            })
            .await
        {
            crate::tprintln!("[route_manager] Failed to send SetDht: {e}");
        }
    }

    pub fn make_route_change_handler(
        &self,
    ) -> impl Fn(Vec<RouteId>) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static
    {
        let tx = self.tx.clone();

        move |dead_routes: Vec<RouteId>| {
            let tx = tx.clone();

            Box::pin(async move {
                let _ = tx.send(RouteManagerMsg::RouteChange(dead_routes)).await;
            })
        }
    }

    /// Ask the background task for a snapshot of where things currently
    /// stand: readiness (waiting on node/DHT, or ready), whether a publish
    /// is in flight, and the currently active route id, if any.
    pub async fn get_status(&self) -> RouteManagerStatus {
        let (reply_tx, reply_rx) = oneshot::channel();

        if self
            .tx
            .send(RouteManagerMsg::GetStatus(reply_tx))
            .await
            .is_err()
        {
            return RouteManagerStatus::unknown();
        }

        reply_rx.await.unwrap_or_else(|_| RouteManagerStatus::unknown())
    }

    /// Send one app message to a published remote private-route blob.
    ///
    /// `route_blob` is the bytes stored in `RouteBlobRecord.blob`.
    pub async fn send_private_route_message(
        veilid: &VeilidAPI,
        route_blob: &[u8],
        data: Vec<u8>,
    ) -> VeilidAPIResult<()> {
        let route_id = veilid.import_remote_private_route(route_blob.to_vec())?;
        let routing_context = veilid.routing_context()?;

        let result = routing_context
            .app_message(Target::RouteId(route_id.clone()), data)
            .await;

        let _ = veilid.release_private_route(route_id);

        result
    }
}

// ============================================================================
// Internal state
// ============================================================================

struct Inner {
    readiness: Readiness,
    publish_state: PublishState,

    node: Option<Arc<Node>>,
    dht_module: Option<DHTModule>,
    dht_package: Option<usize>,

    active_route_id: Option<RouteId>,

    /// If true, one of our routes died while a publish operation was already
    /// running. After publish completes, immediately publish again.
    pending_route_loss: bool,
    publish_generation: u64,
    retry_attempt: u32,
}

impl Inner {
    fn new() -> Self {
        Self {
            readiness: Readiness::WaitingForNode,
            publish_state: PublishState::Idle,
            node: None,
            dht_module: None,
            dht_package: None,
            active_route_id: None,
            pending_route_loss: false,
            publish_generation: 0,
            retry_attempt: 0,
        }
    }

    fn refresh_readiness(&mut self) {
        self.readiness = match (&self.node, &self.dht_module, &self.dht_package) {
            (None, _, _) => Readiness::WaitingForNode,
            (Some(_), None, _) | (Some(_), _, None) => Readiness::WaitingForDht,
            (Some(_), Some(_), Some(_)) => Readiness::Ready,
        };
    }

    fn can_publish(&self) -> bool {
        self.readiness == Readiness::Ready
            && self.publish_state == PublishState::Idle
            && self.active_route_id.is_none()
    }

    fn status(&self) -> RouteManagerStatus {
        RouteManagerStatus {
            readiness: self.readiness,
            publish_state: self.publish_state,
            active_route_id: self.active_route_id.clone(),
        }
    }
}

// ============================================================================
// Background task
// ============================================================================

async fn route_manager_task(
    mut rx: mpsc::Receiver<RouteManagerMsg>,
    tx: mpsc::Sender<RouteManagerMsg>,
) {
    let mut inner = Inner::new();

    while let Some(msg) = rx.recv().await {
        match msg {
            RouteManagerMsg::SetNode(node) => {
                crate::tprintln!("[route_manager] Node received");
                inner.node = Some(node);
                inner.refresh_readiness();
                start_publish(&mut inner, &tx);
            }

            RouteManagerMsg::SetDht {
                dht_module,
                dht_package,
            } => {
                crate::tprintln!("[route_manager] DHT package received: {dht_package}");
                inner.dht_module = Some(dht_module);
                inner.dht_package = Some(dht_package);
                inner.refresh_readiness();
                start_publish(&mut inner, &tx);
            }

            RouteManagerMsg::RouteChange(dead_routes) => {
                if dead_routes.is_empty() {
                    continue;
                }

                let is_dead = inner
                    .active_route_id
                    .as_ref()
                    .is_some_and(|id| dead_routes.contains(id));
                if !is_dead {
                    continue;
                }

                if let Some(active_route) = inner.active_route_id.take() {
                    crate::tprintln!("[route_manager] Active route died: {active_route:?}");
                }

                if inner.publish_state == PublishState::Publishing {
                    inner.pending_route_loss = true;
                } else {
                    start_publish(&mut inner, &tx);
                }
            }

            RouteManagerMsg::GetStatus(reply) => {
                let _ = reply.send(inner.status());
            }

            RouteManagerMsg::PublishFinished { generation, result } => {
                if generation != inner.publish_generation {
                    if let Ok(route_id) = result {
                        if let Some(node) = &inner.node {
                            let _ = node.veilid.release_private_route(route_id);
                        }
                    }
                    continue;
                }

                inner.publish_state = PublishState::Idle;
                match result {
                    Ok(route_id) => {
                        crate::tprintln!("[route_manager] Route published: {route_id:?}");
                        inner.active_route_id = Some(route_id);
                        inner.retry_attempt = 0;

                        if inner.pending_route_loss {
                            inner.pending_route_loss = false;
                            if let Some(route_id) = inner.active_route_id.take() {
                                if let Some(node) = &inner.node {
                                    let _ = node.veilid.release_private_route(route_id);
                                }
                            }
                            start_publish(&mut inner, &tx);
                        }
                    }
                    Err(error) => {
                        crate::teprintln!("[route_manager] Failed to publish route: {error}");
                        inner.active_route_id = None;
                        inner.retry_attempt = inner.retry_attempt.saturating_add(1);
                        schedule_publish_retry(&inner, &tx);
                    }
                }
            }

            RouteManagerMsg::RetryPublish => {
                if inner.active_route_id.is_none() {
                    start_publish(&mut inner, &tx);
                }
            }
        }
    }

    crate::tprintln!("[route_manager] Channel closed, task exiting");
}

// ============================================================================
// Publish worker
// ============================================================================

const ROUTE_PUBLISH_TIMEOUT: Duration = Duration::from_secs(15);
const ROUTE_RETRY_MAX_SECS: u64 = 60;

fn start_publish(inner: &mut Inner, tx: &mpsc::Sender<RouteManagerMsg>) {
    if !inner.can_publish() {
        return;
    }

    let (Some(node), Some(dht_module), Some(dht_package)) = (
        inner.node.clone(),
        inner.dht_module.clone(),
        inner.dht_package,
    ) else {
        return;
    };

    inner.publish_state = PublishState::Publishing;
    inner.publish_generation = inner.publish_generation.wrapping_add(1);
    let generation = inner.publish_generation;
    let tx = tx.clone();

    tokio::spawn(async move {
        let result = create_and_publish_route(&node.veilid, &dht_module, dht_package).await;
        let _ = tx
            .send(RouteManagerMsg::PublishFinished { generation, result })
            .await;
    });
}

fn schedule_publish_retry(inner: &Inner, tx: &mpsc::Sender<RouteManagerMsg>) {
    if inner.readiness != Readiness::Ready {
        return;
    }

    let exponent = inner.retry_attempt.min(5);
    let base = (1u64 << exponent).min(ROUTE_RETRY_MAX_SECS);
    let jitter_window = (base / 5).max(1);
    let jitter = rand::random::<u64>() % (jitter_window + 1);
    let delay = Duration::from_secs((base + jitter).min(ROUTE_RETRY_MAX_SECS));
    let tx = tx.clone();

    tokio::spawn(async move {
        sleep(delay).await;
        let _ = tx.send(RouteManagerMsg::RetryPublish).await;
    });
}

async fn create_and_publish_route(
    veilid: &VeilidAPI,
    dht_module: &DHTModule,
    dht_package: usize,
) -> Result<RouteId, String> {
    let deadline = Instant::now() + ROUTE_PUBLISH_TIMEOUT;
    let route_blob = timeout(
        ROUTE_PUBLISH_TIMEOUT,
        veilid.new_private_route(),
    )
    .await
    .map_err(|_| "new_private_route timed out".to_string())?
    .map_err(|error| format!("new_private_route failed: {error}"))?;

    let route_id = route_blob.route_id.clone();
    let mut release_on_error = true;
    let result = async {
        let record = RouteBlobRecord {
            blob: route_blob.blob,
            timestamp: current_timestamp(),
        };
        let bytes = bincode::serialize(&record)
            .map_err(|error| format!("failed to serialize RouteBlobRecord: {error}"))?;

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("route publication exceeded 15-second deadline".to_string());
        }

        // DHTModule owns the write worker once the request has been queued.  If
        // our 15-second publication deadline expires, simply dropping the
        // caller future would not cancel that worker. Keep the private route
        // alive until the queued write finishes so a late write never
        // publishes a route that we have already released.
        let dht_module = dht_module.clone();
        let mut write_task = tokio::spawn(async move {
            dht_module
                .write_to_dht(dht_package, BLOB_LOCATION, bytes)
                .await
        });

        match timeout(remaining, &mut write_task).await {
            Ok(Ok(Ok(_))) => {}
            Ok(Ok(Err(error))) => {
                return Err(format!("DHT write failed: {error:?}"));
            }
            Ok(Err(join_error)) => {
                return Err(format!("DHT route publication worker failed: {join_error}"));
            }
            Err(_) => {
                let cleanup_veilid = (*veilid).clone();
                let cleanup_route_id = route_id.clone();
                tokio::spawn(async move {
                    let _ = write_task.await;
                    let _ = cleanup_veilid.release_private_route(cleanup_route_id);
                });
                release_on_error = false;
                return Err(
                    "DHT route publication timed out; cleanup will run when the queued write finishes"
                        .to_string(),
                );
            }
        }

        Ok::<(), String>(())
    }
    .await;

    if let Err(error) = result {
        if release_on_error {
            let _ = veilid.release_private_route(route_id.clone());
        }
        return Err(error);
    }

    Ok(route_id)
}

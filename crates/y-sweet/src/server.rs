use crate::update_webhook::{self, UpdateWebhookConfig};
use anyhow::{anyhow, Result};
use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket},
        DefaultBodyLimit, Path, Query, Request, State, WebSocketUpgrade,
    },
    http::{
        header::{HeaderMap, HeaderName},
        StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_extra::typed_header::TypedHeader;
use dashmap::{
    mapref::{entry::Entry, one::MappedRef},
    DashMap,
};
use futures::{
    future::{BoxFuture, Shared},
    FutureExt, SinkExt, StreamExt,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    future::{Future, IntoFuture},
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::mpsc::{channel, Receiver},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{span, Instrument, Level};
use url::Url;
use y_sweet_core::{
    api_types::{
        validate_doc_name, AuthDocRequest, Authorization, ClientToken, DocCreationRequest,
        NewDocResponse,
    },
    auth::{
        Actor, Authenticator, DocAccess, ExpirationTimeEpochMillis, DEFAULT_EXPIRATION_SECONDS,
    },
    doc_connection::{DocConnection, DOC_NAME},
    doc_sync::{apply_update_to, is_live, DocWithSyncKv},
    store::Store,
    sync::awareness::Awareness,
    sync_kv::SyncKv,
    update_events::UpdateCallback,
};

const PLANE_VERIFIED_USER_DATA_HEADER: &str = "x-verified-user-data";

// Every 20 seconds, we send a ping to the client.
const PING_EVERY: Duration = Duration::from_secs(20);
// If we haven't received a pong in the last 40 seconds, we close the connection.
// All modern browsers will respond to websocket pings with a pong message.
const PONG_TIMEOUT: Duration = Duration::from_secs(40);

/// The default of [ShutdownBudgets::total] (`Y_SWEET_SHUTDOWN_TIMEOUT_SECONDS`).
///
/// Sized against the stop timeout of the deployment it ships to: the Dalus ECS task gives the
/// container 120 s between the stop signal and `SIGKILL`, so 110 s leaves a margin for the
/// process to exit. A platform with a shorter grace period (Docker's default is 10 s, the
/// on-prem compose file sets 30 s) kills the process when its own period ends whatever this
/// says; until then the doc saves keep running, as they did upstream, which waited without limit.
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(110);

/// Time limits of the shutdown (see [Server::serve]).
///
/// Saving docs is the stage that must not be cut short, so it gets everything: saves run until
/// `total` has passed since shutdown began. The other two stages are bounded so they cannot eat
/// that time: connections get `connections` at the start, and the webhook flush, which is
/// expendable, gets `webhook` at the end, starting when the saves are done or when only
/// `webhook` is left of `total`, whichever comes first (it then runs beside the saves).
#[derive(Clone, Copy, Debug)]
pub struct ShutdownBudgets {
    /// Finishing in-flight HTTP requests, closing websockets and closing the write gate.
    pub connections: Duration,
    /// The whole shutdown, and so the deadline of the final saves.
    pub total: Duration,
    /// The update webhook's final flush. Its own budget (5 s) applies inside; this bounds the
    /// stage as a whole.
    pub webhook: Duration,
}

impl Default for ShutdownBudgets {
    fn default() -> Self {
        Self::with_total(DEFAULT_SHUTDOWN_TIMEOUT)
    }
}

impl ShutdownBudgets {
    /// The budgets for a shutdown that may take `total` in all.
    pub fn with_total(total: Duration) -> Self {
        Self {
            connections: Duration::from_secs(5).min(total / 4),
            total,
            webhook: Duration::from_secs(7).min(total / 4),
        }
    }
}

/// How long a writer waits to get its doc (see [Server::live_doc]) before it gives up with
/// `503`: loading it, waiting behind another load of it, or waiting for a doc GC retired to be
/// dropped and loading it again. Giving up does not stop the load.
pub const DEFAULT_DOC_WAIT: Duration = Duration::from_secs(15);

/// A load of a doc that is under way. It runs in a task of its own; everyone who wants the doc
/// meanwhile waits on a clone of this, and gets the load's result (the error as text, so that
/// it can be shared).
type SharedLoad = Shared<BoxFuture<'static, Result<(), String>>>;

/// Removes a doc's entry from the map of loads under way when its load ends, however it ends.
struct LoadDone {
    loading: Arc<DashMap<String, SharedLoad>>,
    doc_id: String,
}

impl Drop for LoadDone {
    fn drop(&mut self) {
        self.loading.remove(&self.doc_id);
    }
}

/// What loading a doc needs of the server, owned, so that a load can run in a task that
/// outlives the request that started it.
struct DocLoader {
    docs: Arc<DashMap<String, DocWithSyncKv>>,
    store: Option<Arc<Box<dyn Store>>>,
    checkpoint_freq: Duration,
    doc_gc: bool,
    skip_gc: bool,
    on_update: Option<UpdateCallback>,
    doc_workers_token: CancellationToken,
    doc_worker_tracker: TaskTracker,
    suspect_window: Duration,
    suspect_resave: Duration,
}

/// Admission for writes to docs, closed once at shutdown before the final saves.
///
/// Closing has two parts. [WriteGate::close] stops admitting at once: every write that has not
/// yet been admitted is refused from then on, however long draining takes. [WriteGate::drained]
/// then waits for writes already admitted to finish applying. A write holds its admission only
/// while it applies, never across doc loading or store I/O, so draining is quick.
///
/// Draining is bounded, so a write can still be applying when the final saves start
/// ([WriteGate::seal]). Such a write may be missing from them; [Admission::in_time] tells it
/// so, and it is not acknowledged. (A websocket client's acknowledgement is the echo of a later
/// message, which the closed gate refuses.)
pub(crate) struct WriteGate {
    accepting: std::sync::atomic::AtomicBool,
    /// Set when the final saves start.
    sealed: std::sync::atomic::AtomicBool,
    /// Admitted writes hold this for reading; draining takes it for writing.
    in_progress: tokio::sync::RwLock<()>,
}

/// One admitted write. Hold it while applying.
pub(crate) struct Admission<'a> {
    _applying: tokio::sync::RwLockReadGuard<'a, ()>,
    sealed: &'a std::sync::atomic::AtomicBool,
}

impl Admission<'_> {
    /// Whether what this write has applied so far is in the final saves. Ask after applying,
    /// before acknowledging: false once the final saves have started without waiting for it.
    fn in_time(&self) -> bool {
        !self.sealed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl WriteGate {
    fn new() -> Self {
        Self {
            accepting: std::sync::atomic::AtomicBool::new(true),
            sealed: std::sync::atomic::AtomicBool::new(false),
            in_progress: tokio::sync::RwLock::new(()),
        }
    }

    /// Admits one write: `None` once the gate is closed. Hold the admission while applying.
    async fn enter(&self) -> Option<Admission<'_>> {
        let guard = self.in_progress.read().await;
        // Checked after taking the read lock: a write admitted here is one `drained` waits for.
        self.accepting
            .load(std::sync::atomic::Ordering::SeqCst)
            .then_some(Admission {
                _applying: guard,
                sealed: &self.sealed,
            })
    }

    /// Marks the start of the final saves: a write that finishes applying after this is not
    /// in time ([Admission::in_time]).
    fn seal(&self) {
        self.sealed.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn close(&self) {
        self.accepting
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    async fn drained(&self) {
        let _ = self.in_progress.write().await;
    }
}

/// The dirty callback of a doc: wakes its persistence worker. It runs inside the doc's update
/// observer, under the doc write lock, so it must never block or panic. Once the worker has
/// exited (shutdown, or the doc was collected) the channel is closed; there is no one left to
/// wake, so the notification is dropped. A full channel means a wake-up is already pending.
fn dirty_callback(send: tokio::sync::mpsc::Sender<()>) -> impl Fn() + Send + Sync + 'static {
    move || {
        let _ = send.try_send(());
    }
}

fn current_time_epoch_millis() -> u64 {
    let now = std::time::SystemTime::now();
    let duration_since_epoch = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    duration_since_epoch.as_millis() as u64
}

#[derive(Debug)]
pub struct AppError(StatusCode, anyhow::Error);
impl std::error::Error for AppError {}
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, format!("Something went wrong: {}", self.1)).into_response()
    }
}
impl<E> From<(StatusCode, E)> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from((status_code, err): (StatusCode, E)) -> Self {
        Self(status_code, err.into())
    }
}
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status code: {} {}", self.0, self.1)?;
        Ok(())
    }
}

pub struct Server {
    docs: Arc<DashMap<String, DocWithSyncKv>>,
    doc_worker_tracker: TaskTracker,
    store: Option<Arc<Box<dyn Store>>>,
    checkpoint_freq: Duration,
    authenticator: Option<Authenticator>,
    url_prefix: Option<Url>,
    cancellation_token: CancellationToken,
    /// Whether to garbage collect docs that are no longer in use.
    /// Disabled for single-doc mode, since we only have one doc.
    doc_gc: bool,
    max_body_size: Option<usize>,
    /// Whether to skip garbage collection in Yrs documents.
    skip_gc: bool,
    /// Whether the mint endpoint binds the requested actor into the tokens it issues.
    /// Off by default: binaries that predate attributed tokens reject them.
    attributed_tokens: bool,
    /// Receives every update applied to a doc when the update webhook is configured.
    on_update: Option<UpdateCallback>,
    /// Websocket connections, which outlive the HTTP request that upgraded them, so the HTTP
    /// server's graceful shutdown does not wait for them.
    connection_tracker: TaskTracker,
    /// Every write to a doc is admitted through this while it applies; shutdown closes it
    /// before the final saves, so nothing is applied after them.
    write_gate: Arc<WriteGate>,
    /// Stops the persistence and GC workers. Cancelled by `serve` only once no write can be
    /// applied any more, not by `cancellation_token`.
    doc_workers_token: CancellationToken,
    /// The update webhook dispatcher, stopped last so it carries every update applied.
    webhook_tracker: TaskTracker,
    webhook_token: CancellationToken,
    shutdown_budgets: ShutdownBudgets,
    /// See [DEFAULT_DOC_WAIT].
    doc_wait: Duration,
    /// The loads under way, one per doc, so that concurrent requests load a doc once and a
    /// load survives the requests waiting for it (see [Server::load_doc]).
    loading: Arc<DashMap<String, SharedLoad>>,
    /// How long a doc stays suspect after a save of it may still land, at least, and how
    /// often it is saved again meanwhile without having changed (see [SyncKv::is_suspect]).
    suspect_window: Duration,
    suspect_resave: Duration,
}

impl Server {
    // The signature is upstream's; kept so the fork stays easy to merge.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        store: Option<Box<dyn Store>>,
        checkpoint_freq: Duration,
        authenticator: Option<Authenticator>,
        url_prefix: Option<Url>,
        cancellation_token: CancellationToken,
        doc_gc: bool,
        max_body_size: Option<usize>,
        skip_gc: bool,
    ) -> Result<Self> {
        Ok(Self {
            docs: Arc::new(DashMap::new()),
            doc_worker_tracker: TaskTracker::new(),
            store: store.map(Arc::new),
            checkpoint_freq,
            authenticator,
            url_prefix,
            cancellation_token,
            doc_gc,
            max_body_size,
            skip_gc,
            attributed_tokens: false,
            on_update: None,
            connection_tracker: TaskTracker::new(),
            write_gate: Arc::new(WriteGate::new()),
            doc_workers_token: CancellationToken::new(),
            webhook_tracker: TaskTracker::new(),
            webhook_token: CancellationToken::new(),
            shutdown_budgets: ShutdownBudgets::default(),
            doc_wait: DEFAULT_DOC_WAIT,
            loading: Arc::new(DashMap::new()),
            suspect_window: y_sweet_core::sync_kv::DEFAULT_SUSPECT_WINDOW,
            suspect_resave: y_sweet_core::sync_kv::DEFAULT_SUSPECT_RESAVE_INTERVAL,
        })
    }

    pub fn with_shutdown_budgets(mut self, shutdown_budgets: ShutdownBudgets) -> Self {
        self.shutdown_budgets = shutdown_budgets;
        self
    }

    /// Sets whether `POST /doc/:doc_id/auth` mints attributed tokens when the request names a
    /// `userId` or a `writer`. Verification of attributed tokens is always on.
    pub fn with_attributed_tokens(mut self, attributed_tokens: bool) -> Self {
        self.attributed_tokens = attributed_tokens;
        self
    }

    /// Delivers every update applied to a doc loaded from now on to the configured webhook.
    ///
    /// Spawns the dispatcher, so it must be called from within a Tokio runtime. `serve` stops
    /// it as the last shutdown stage and waits for its final flush.
    pub fn with_update_webhook(mut self, config: UpdateWebhookConfig) -> Result<Self> {
        self.enable_update_webhook(config)?;
        Ok(self)
    }

    /// [Server::with_update_webhook] for a caller that wants to keep the server when the
    /// webhook cannot be set up (the webhook is optional; serving docs is not).
    pub fn enable_update_webhook(&mut self, config: UpdateWebhookConfig) -> Result<()> {
        let (on_update, dispatcher) = update_webhook::start(config, self.webhook_token.clone())?;
        self.webhook_tracker
            .spawn(dispatcher.instrument(span!(Level::INFO, "update_webhook")));
        self.on_update = Some(on_update);
        Ok(())
    }

    pub async fn doc_exists(&self, doc_id: &str) -> bool {
        if self.docs.contains_key(doc_id) {
            return true;
        }
        if let Some(store) = &self.store {
            store
                .exists(&format!("{}/data.ysweet", doc_id))
                .await
                .unwrap_or_default()
        } else {
            false
        }
    }

    pub async fn create_doc(&self) -> Result<String> {
        let doc_id = nanoid::nanoid!();
        self.load_doc(&doc_id).await?;
        tracing::info!(doc_id=?doc_id, "Created doc");
        Ok(doc_id)
    }

    /// Loads a doc into the map, unless it is there already.
    ///
    /// A doc is loaded once at a time: a request that finds a load under way waits for it and
    /// then uses the doc it loaded. A second load replacing the first would drop the first
    /// doc's persistence subscription while writers still hold it, losing their writes.
    ///
    /// The load runs in a task of its own, not in the caller: a caller that stops waiting (a
    /// writer gives up after [DEFAULT_DOC_WAIT], a client disconnects) does not cancel it. The
    /// load goes on, and whoever asks for the doc next finds it loaded, or joins the same
    /// load. Were it cancelled with its caller, a doc that takes longer to load than a writer
    /// waits could never be opened: every attempt would start over and be cut off again.
    pub async fn load_doc(&self, doc_id: &str) -> Result<()> {
        if self.docs.contains_key(doc_id) {
            return Ok(());
        }
        let load = match self.loading.entry(doc_id.to_string()) {
            Entry::Occupied(load) => load.get().clone(),
            Entry::Vacant(vacant) => {
                let loader = DocLoader {
                    docs: self.docs.clone(),
                    store: self.store.clone(),
                    checkpoint_freq: self.checkpoint_freq,
                    doc_gc: self.doc_gc,
                    skip_gc: self.skip_gc,
                    on_update: self.on_update.clone(),
                    doc_workers_token: self.doc_workers_token.clone(),
                    doc_worker_tracker: self.doc_worker_tracker.clone(),
                    suspect_window: self.suspect_window,
                    suspect_resave: self.suspect_resave,
                };
                // The entry goes when the task ends, also if it panics. That cannot happen
                // before the entry is in the map: removing it needs the shard lock held here.
                let done = LoadDone {
                    loading: self.loading.clone(),
                    doc_id: doc_id.to_string(),
                };
                let doc_id = doc_id.to_string();
                let task = tokio::spawn(
                    async move {
                        let _done = done;
                        // With its context, as text: the result is shared by all waiters.
                        loader.load(&doc_id).await.map_err(|e| format!("{e:#}"))
                    }
                    .in_current_span(),
                );
                let load = async move {
                    task.await
                        .unwrap_or_else(|e| Err(format!("The doc load did not finish: {e}")))
                }
                .boxed()
                .shared();
                vacant.insert(load.clone());
                load
            }
        };
        load.await.map_err(|e| anyhow!(e))
    }
}

impl DocLoader {
    /// Loads the doc and starts its workers, unless it is in the map already. Only ever run
    /// by one task per doc at a time (see [Server::load_doc]).
    async fn load(self, doc_id: &str) -> Result<()> {
        // A load that finished between the caller's look at the map and this task.
        if self.docs.contains_key(doc_id) {
            return Ok(());
        }
        let (send, recv) = channel(1024);

        let dwskv = DocWithSyncKv::new(
            doc_id,
            self.store.clone(),
            dirty_callback(send),
            self.skip_gc,
            self.on_update.clone(),
        )
        .await?;
        dwskv
            .sync_kv()
            .set_suspect_window(self.suspect_window, self.suspect_resave);

        dwskv
            .sync_kv()
            .persist()
            .await
            .map_err(|e| anyhow!("Error persisting: {:?}", e))?;

        {
            let sync_kv = dwskv.sync_kv();
            let checkpoint_freq = self.checkpoint_freq;
            let doc_id = doc_id.to_string();
            // Not the server's cancellation token: these stop only once nothing can write (see
            // `shut_down`). A child token per doc, so GC can also stop them once it dropped the
            // doc.
            let cancellation_token = self.doc_workers_token.child_token();
            // Saves of this doc run one at a time, so GC's save cannot report "nothing to
            // save" while the worker's save of the same changes is still being written.
            let persist_lock = Arc::new(tokio::sync::Mutex::new(()));
            // Set by GC when it has saved and dropped the doc: its worker must not save again.
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));

            // Spawn a task to save the document to the store when it changes.
            self.doc_worker_tracker.spawn(
                Server::doc_persistence_worker(
                    recv,
                    sync_kv,
                    checkpoint_freq,
                    doc_id.clone(),
                    cancellation_token.clone(),
                    persist_lock.clone(),
                    dropped.clone(),
                )
                .instrument(span!(Level::INFO, "save_loop", doc_id=?doc_id)),
            );

            if self.doc_gc {
                self.doc_worker_tracker.spawn(
                    Server::doc_gc_worker(
                        self.docs.clone(),
                        doc_id.clone(),
                        checkpoint_freq,
                        cancellation_token,
                        persist_lock,
                        dropped,
                    )
                    .instrument(span!(Level::INFO, "gc_loop", doc_id=?doc_id)),
                );
            }
        }

        // One load per doc at a time, so the entry is empty here; `or_insert` keeps it that way
        // should any other path have filled it, rather than replacing a doc writers may hold.
        self.docs.entry(doc_id.to_string()).or_insert(dwskv);
        Ok(())
    }
}

impl Server {
    async fn doc_gc_worker(
        docs: Arc<DashMap<String, DocWithSyncKv>>,
        doc_id: String,
        checkpoint_freq: Duration,
        // This doc's workers' token: cancelled at shutdown, and by this worker once it has
        // dropped the doc.
        cancellation_token: CancellationToken,
        persist_lock: Arc<tokio::sync::Mutex<()>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut checkpoints_without_refs = 0;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(checkpoint_freq) => {
                    let (retired, sync_kv) = {
                        let Some(doc) = docs.get(&doc_id) else {
                            break;
                        };
                        let awareness = Arc::downgrade(&doc.awareness());
                        if awareness.strong_count() > 1 {
                            checkpoints_without_refs = 0;
                            tracing::debug!("doc is still alive - it has {} references", awareness.strong_count());
                        } else {
                            checkpoints_without_refs += 1;
                            tracing::info!("doc has only one reference, candidate for GC. checkpoints_without_refs: {}", checkpoints_without_refs);
                        }
                        // Retired only if, under the doc lock, nothing holds it: a writer that
                        // took the doc since the count above keeps it alive.
                        // Nor while an earlier save of it may still land: memory then holds
                        // the only copy known to be current (see `SyncKv::is_suspect`).
                        let retire = checkpoints_without_refs >= 2 && !doc.sync_kv().is_suspect();
                        (retire && doc.retire_if_unused(), doc.sync_kv())
                    };
                    if checkpoints_without_refs >= 2 && !retired {
                        // A writer got in first, or the doc is suspect.
                        checkpoints_without_refs = 0;
                    }
                    if !retired {
                        continue;
                    }

                    // The last save this copy gets (see `SyncKv::resave_now`).
                    sync_kv.resave_now();
                    // Save before dropping: a writer that finds the doc retired waits for it to
                    // go (see `live_doc`), and its reload must read everything. Never abandoned
                    // part-way: a write already sent cannot be recalled, and one that lands
                    // after a newer save would overwrite it. A store that hangs therefore holds
                    // up this doc's GC; writers stop waiting for the doc after `doc_wait` (503),
                    // and shutdown after its stage budget.
                    let saved = Self::compact_and_persist(&sync_kv, &persist_lock).await;
                    match saved {
                        // A save by the persistence worker failed just before this one, in
                        // a way that may still land.
                        Ok(()) if sync_kv.is_unsettled() => {
                            tracing::warn!("an earlier save of the doc being collected may still land; keeping it loaded");
                        }
                        Ok(()) => {
                            tracing::info!("GCing doc");
                            docs.remove_if(&doc_id, |_, doc| doc.sync_kv().is_shutdown());
                            // The doc is gone, saved in full: its persistence worker has
                            // nothing left to do, and must not write this copy again (a fresh
                            // load may already hold newer state).
                            dropped.store(true, std::sync::atomic::Ordering::SeqCst);
                            cancellation_token.cancel();
                            break;
                        }
                        Err(error) => {
                            tracing::warn!(%error, "could not save the doc being collected; keeping it loaded");
                        }
                    }
                    // Not saved: the only copy of its latest state is this one. Keep it, writable,
                    // with its persistence worker, which retries the save; try again later.
                    sync_kv.resume();
                    checkpoints_without_refs = 0;
                }
                _ = cancellation_token.cancelled() => {
                    break;
                }
            };
        }
        tracing::info!("Exiting gc_loop");
    }

    /// One save of a doc, as every save path makes it (the periodic checkpoint, the final save
    /// at shutdown and each retry of it, GC's save of a doc it retires): merge the doc's
    /// pending update log into its state, then write the doc to the store.
    ///
    /// Both steps run under the doc's save lock, so two saves of a doc, or a save and a
    /// compaction, never interleave. Nothing here looks at a cancellation token: a save that
    /// was asked for is made in full.
    ///
    /// The merge is an optimisation, not what makes the save complete: `SyncKv::persist`
    /// writes the whole map, pending log included. So a merge that fails is logged and the save
    /// goes ahead. It runs on a blocking thread because it takes time in proportion to the doc.
    async fn compact_and_persist(
        sync_kv: &Arc<SyncKv>,
        persist_lock: &tokio::sync::Mutex<()>,
    ) -> Result<(), String> {
        let _saving = persist_lock.lock().await;
        let kv = sync_kv.clone();
        match tokio::task::spawn_blocking(move || kv.compact(DOC_NAME)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(?e, "Error compacting."),
            Err(e) => tracing::error!(?e, "Compaction task failed."),
        }
        // As text: the error cannot be held across an await by the callers.
        sync_kv.persist().await.map_err(|e| format!("{e:?}"))
    }

    async fn doc_persistence_worker(
        mut recv: Receiver<()>,
        sync_kv: Arc<SyncKv>,
        checkpoint_freq: Duration,
        doc_id: String,
        // Cancelled at shutdown, or by GC once it dropped the doc. Retirement alone does not
        // stop this worker: GC un-retires a doc it could not save, and this worker then keeps
        // retrying the save.
        cancellation_token: CancellationToken,
        persist_lock: Arc<tokio::sync::Mutex<()>>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    ) {
        let mut last_save = std::time::Instant::now();

        loop {
            let is_done = tokio::select! {
                v = recv.recv() => v.is_none(),
                _ = cancellation_token.cancelled() => true,
                _ = tokio::time::sleep(checkpoint_freq) => false,
            };

            tracing::info!("Received signal. done: {}", is_done);
            let now = std::time::Instant::now();
            if !is_done && now - last_save < checkpoint_freq {
                let sleep = tokio::time::sleep(checkpoint_freq - (now - last_save));
                tokio::pin!(sleep);
                tracing::info!("Throttling.");

                loop {
                    tokio::select! {
                        _ = &mut sleep => {
                            break;
                        }
                        v = recv.recv() => {
                            tracing::info!("Received dirty while throttling.");
                            if v.is_none() {
                                break;
                            }
                        }
                        _ = cancellation_token.cancelled() => {
                            tracing::info!("Received cancellation while throttling.");
                            break;
                        }

                    }
                    tracing::info!("Done throttling.");
                }
            }
            if dropped.load(std::sync::atomic::Ordering::SeqCst) {
                // GC saved this doc and dropped it; this copy is no longer the doc.
                break;
            }
            tracing::info!("Persisting.");
            if is_done {
                // The last save: a suspect doc gets it whether or not its interval is up.
                sync_kv.resave_now();
            }
            let mut retry_in = Duration::from_millis(250);
            loop {
                let result = Self::compact_and_persist(&sync_kv, &persist_lock).await;
                match result {
                    Ok(()) => {
                        tracing::info!("Done persisting.");
                        break;
                    }
                    Err(e) => tracing::error!(e, "Error persisting."),
                }
                if !is_done {
                    // The next checkpoint tries again.
                    break;
                }
                // The last save of this doc: there is no later one, so retry until it works.
                // Shutdown bounds this with its deadline, after which the process exits.
                tracing::warn!(
                    retry_in_ms = retry_in.as_millis() as u64,
                    "final save failed; retrying"
                );
                tokio::time::sleep(retry_in).await;
                retry_in = (retry_in * 2).min(Duration::from_secs(5));
            }
            last_save = std::time::Instant::now();

            if is_done {
                break;
            }
        }
        tracing::info!("Terminating loop for {}", doc_id);
    }

    /// The awareness and store of a doc that GC has not retired, loading the doc if needed.
    ///
    /// Holding the returned awareness keeps GC from retiring the doc, so writes made through it
    /// are saved. A doc that GC has retired but not yet dropped (it is still being saved) is
    /// waited out, so that a reload reads what was saved. The wait for all of it, loads
    /// included, is bounded by [DEFAULT_DOC_WAIT] and by shutdown; either ends it with `503`.
    /// A load being waited for is not cancelled by that: it carries on (see
    /// [Server::load_doc]), so a later attempt finds the doc.
    pub async fn live_doc(
        &self,
        doc_id: &str,
    ) -> Result<(Arc<RwLock<Awareness>>, Arc<SyncKv>), AppError> {
        let get = async {
            loop {
                let (awareness, sync_kv) = {
                    let doc = self
                        .get_or_create_doc(doc_id)
                        .await
                        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e))?;
                    (doc.awareness(), doc.sync_kv())
                };
                if is_live(&awareness, &sync_kv) {
                    return Ok((awareness, sync_kv));
                }
                drop(awareness);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::select! {
            // A doc that is there at once is taken even during shutdown: requests in flight
            // are let finish (see `shut_down`). Only waiting for one is cut short.
            biased;
            got = tokio::time::timeout(self.doc_wait, get) => got.unwrap_or_else(|_| {
                Err(AppError(
                    StatusCode::SERVICE_UNAVAILABLE,
                    anyhow!("The doc is not available yet; try again."),
                ))
            }),
            _ = self.cancellation_token.cancelled() => Err(AppError(
                StatusCode::SERVICE_UNAVAILABLE,
                anyhow!("The server is shutting down."),
            )),
        }
    }

    pub async fn get_or_create_doc(
        &self,
        doc_id: &str,
    ) -> Result<MappedRef<String, DocWithSyncKv, DocWithSyncKv>> {
        if !self.docs.contains_key(doc_id) {
            tracing::info!(doc_id=?doc_id, "Loading doc");
            self.load_doc(doc_id).await?;
        }

        Ok(self
            .docs
            .get(doc_id)
            .ok_or_else(|| anyhow!("Failed to get-or-create doc"))?
            .map(|d| d))
    }

    pub fn check_auth(
        &self,
        auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    ) -> Result<(), AppError> {
        if let Some(auth) = &self.authenticator {
            if let Some(TypedHeader(headers::Authorization(bearer))) = auth_header {
                if let Ok(()) =
                    auth.verify_server_token(bearer.token(), current_time_epoch_millis())
                {
                    return Ok(());
                }
            }
            Err((StatusCode::UNAUTHORIZED, anyhow!("Unauthorized.")))?
        } else {
            Ok(())
        }
    }

    pub async fn redact_error_middleware(req: Request, next: Next) -> impl IntoResponse {
        let resp = next.run(req).await;
        if resp.status().is_server_error() || resp.status().is_client_error() {
            // If we should redact errors, copy over only the status code and
            // not the response body.
            return resp.status().into_response();
        }
        resp
    }

    pub fn routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/ready", get(ready))
            .route("/check_store", post(check_store))
            .route("/check_store", get(check_store_deprecated))
            .route("/doc/ws/:doc_id", get(handle_socket_upgrade_deprecated))
            .route("/doc/new", post(new_doc))
            .route("/doc/:doc_id/auth", post(auth_doc))
            .route("/doc/:doc_id/as-update", get(get_doc_as_update_deprecated))
            .route("/doc/:doc_id/update", post(update_doc_deprecated))
            .route("/d/:doc_id/as-update", get(get_doc_as_update))
            .route("/d/:doc_id/update", post(update_doc))
            .route(
                "/d/:doc_id/ws/:doc_id2",
                get(handle_socket_upgrade_full_path),
            )
            .with_state(self.clone())
    }

    pub fn single_doc_routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/ws/:doc_id", get(handle_socket_upgrade_single))
            .route("/as-update", get(get_doc_as_update_single))
            .route("/update", post(update_doc_single))
            .with_state(self.clone())
    }

    async fn serve_internal(
        self: Arc<Self>,
        listener: TcpListener,
        redact_errors: bool,
        routes: Router,
    ) -> Result<()> {
        let token = self.cancellation_token.clone();

        let mut app = if let Some(max_body_size) = self.max_body_size {
            routes.layer(DefaultBodyLimit::max(max_body_size))
        } else {
            routes
        };

        app = if redact_errors {
            app
        } else {
            app.layer(middleware::from_fn(Self::redact_error_middleware))
        };

        let serve = axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(token.clone().cancelled_owned())
            .into_future();
        tokio::pin!(serve);
        // Runs until the token is cancelled (or the server fails).
        let served = tokio::select! {
            result = &mut serve => Some(result),
            _ = token.cancelled() => None,
        };
        self.finish_serving(served, serve).await
    }

    /// Shuts down after the HTTP server either finished (`served` is its result) or was told
    /// to stop and is still draining (`served` is `None`, and `serve` is what to wait for).
    async fn finish_serving(
        &self,
        served: Option<std::io::Result<()>>,
        serve: Pin<&mut (dyn Future<Output = std::io::Result<()>> + Send)>,
    ) -> Result<()> {
        match served {
            // Still draining connections: shutdown waits for it, within its budget.
            None => self.shut_down(Some(serve)).await,
            // Already finished, which a graceful shutdown with nothing in flight can do before
            // this task sees the cancellation. It must not be polled again.
            Some(Ok(())) => self.shut_down(None).await,
            Some(Err(err)) => {
                self.shut_down(None).await;
                return Err(err.into());
            }
        }
        Ok(())
    }

    /// Stops the server in an order that loses no acknowledged write, each stage bounded by
    /// [ShutdownBudgets]:
    ///
    /// 1. (Already done by the cancelled token.) Stop accepting connections and tell every
    ///    websocket to close.
    /// 2. Let in-flight HTTP requests finish and websockets close, then close the write gate:
    ///    from here on a write is refused (`503`, or the websocket is dropped), never applied.
    /// 3. Stop the persistence workers; each makes a final save of its doc, retrying a save
    ///    that fails. The saves have until the end of the total budget; docs still unsaved
    ///    then are logged one by one.
    /// 4. Stop the update webhook, which flushes what the stages above produced. It starts
    ///    when the saves are done, or beside them when only its own budget is left.
    ///
    /// Stages 2 and 4 are logged and left behind if they overrun; they never take time from
    /// the saves.
    async fn shut_down(
        &self,
        http: Option<Pin<&mut (dyn Future<Output = std::io::Result<()>> + Send)>>,
    ) {
        let started = std::time::Instant::now();
        let shutdown_began = tokio::time::Instant::now();
        let budgets = self.shutdown_budgets;
        tracing::info!(
            budget_ms = budgets.total.as_millis() as u64,
            "shutdown started"
        );
        let stage_timed_out = |stage: &'static str, budget: Duration| {
            tracing::warn!(
                stage,
                budget_ms = budget.as_millis() as u64,
                "shutdown stage did not finish in time"
            );
        };

        // Stage 2. One budget for the whole stage.
        let deadline = shutdown_began + budgets.connections;
        if let Some(http) = http {
            match tokio::time::timeout_at(deadline, http).await {
                Ok(Err(err)) => tracing::error!(?err, "HTTP server failed while shutting down"),
                Ok(Ok(())) => {}
                Err(_) => stage_timed_out("http", budgets.connections),
            }
        }
        self.connection_tracker.close();
        if tokio::time::timeout_at(deadline, self.connection_tracker.wait())
            .await
            .is_err()
        {
            stage_timed_out("websockets", budgets.connections);
        }
        // Closed unconditionally, whatever the stages above did: no write is admitted from
        // here on, even one that was still loading its doc or receiving its body.
        self.write_gate.close();
        // Writes already admitted are mid-apply; wait for them. They hold the gate only while
        // applying, so this is short, but bounded all the same: the floor keeps it from being
        // skipped when the stages above used up the deadline.
        let drain_deadline = deadline.max(tokio::time::Instant::now() + Duration::from_millis(500));
        if tokio::time::timeout_at(drain_deadline, self.write_gate.drained())
            .await
            .is_err()
        {
            // A write admitted before the close may land after the final save below; the seal
            // keeps it from being acknowledged.
            stage_timed_out("write_gate", budgets.connections);
        }

        // Stage 3: the final saves. They have until the total deadline, and a save that fails
        // is retried until then (see `doc_persistence_worker`).
        let total_deadline = shutdown_began + budgets.total;
        // Before any final save reads its doc: a write that sees the gate unsealed after
        // applying is in the saves.
        self.write_gate.seal();
        self.doc_workers_token.cancel();
        self.doc_worker_tracker.close();
        let saves = self.doc_worker_tracker.wait();
        tokio::pin!(saves);
        // The flush starts when the saves are done, or when only its own budget is left; in
        // that case it runs beside the saves rather than instead of them.
        let flush_at = total_deadline
            .checked_sub(budgets.webhook)
            .unwrap_or(shutdown_began)
            .max(tokio::time::Instant::now());
        let saves_done = tokio::time::timeout_at(flush_at, &mut saves).await.is_ok();

        // Stage 4: the webhook flush. Nothing is applied any more, so what it flushes is
        // complete even while saves are still running.
        self.webhook_token.cancel();
        self.webhook_tracker.close();
        // Its own budget, but never past the end of the whole shutdown, however late it starts.
        let flush_deadline = (tokio::time::Instant::now() + budgets.webhook).min(total_deadline);
        let flush = async {
            if tokio::time::timeout_at(flush_deadline, self.webhook_tracker.wait())
                .await
                .is_err()
            {
                stage_timed_out("webhook", budgets.webhook);
            }
        };
        if saves_done {
            flush.await;
        } else {
            let (_, saved) =
                tokio::join!(flush, tokio::time::timeout_at(total_deadline, &mut saves));
            if saved.is_err() {
                // Out of time. Say exactly which docs the store may not have in full.
                let mut unsaved = 0usize;
                for doc in self.docs.iter() {
                    if doc.sync_kv().has_unsaved_changes() {
                        unsaved += 1;
                        tracing::error!(
                            doc_id = %doc.key(),
                            "doc not saved before the shutdown deadline; its changes since the last save are lost"
                        );
                    }
                }
                tracing::error!(
                    stage = "persist",
                    budget_ms = budgets.total.as_millis() as u64,
                    unsaved_docs = unsaved,
                    workers_left = self.doc_worker_tracker.len(),
                    "shutdown stage did not finish in time"
                );
            }
        }

        // Docs with a recent save that failed but may still land: the final save above stored
        // the current state, but nothing saves again after it, so an earlier write that the
        // store applies from here on would put an older copy back.
        let suspect_docs = self
            .docs
            .iter()
            .filter(|doc| doc.sync_kv().is_suspect())
            .count();
        if suspect_docs > 0 {
            tracing::warn!(
                suspect_docs,
                "shutting down with docs an earlier save of which may still be applied by the store"
            );
        }

        tracing::info!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            "shutdown finished"
        );
    }

    pub async fn serve(self, listener: TcpListener, redact_errors: bool) -> Result<()> {
        let s = Arc::new(self);
        let routes = s.routes();
        s.serve_internal(listener, redact_errors, routes).await
    }

    pub async fn serve_doc(self, listener: TcpListener, redact_errors: bool) -> Result<()> {
        let s = Arc::new(self);
        let routes = s.single_doc_routes();
        s.serve_internal(listener, redact_errors, routes).await
    }

    fn verify_doc_token(&self, token: Option<&str>, doc: &str) -> Result<DocAccess, AppError> {
        if let Some(authenticator) = &self.authenticator {
            if let Some(token) = token {
                let access = authenticator
                    .verify_doc_token(token, doc, current_time_epoch_millis())
                    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
                Ok(access)
            } else {
                Err((StatusCode::UNAUTHORIZED, anyhow!("No token provided.")))?
            }
        } else {
            Ok(DocAccess::full())
        }
    }

    fn get_single_doc_id(&self) -> Result<String, AppError> {
        self.docs
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .ok_or_else(|| AppError(StatusCode::NOT_FOUND, anyhow!("No document found")))
    }
}

#[derive(Deserialize)]
struct HandlerParams {
    token: Option<String>,
}

async fn get_doc_as_update(
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    // All authorization types allow reading the document.
    let token = get_token_from_header(auth_header);
    let _ = server_state.verify_doc_token(token.as_deref(), &doc_id)?;

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let update = dwskv.as_update();
    // The size only: doc content is never logged.
    tracing::debug!(doc_id = %doc_id, bytes = update.len(), "serving doc as update");
    Ok(update.into_response())
}

async fn get_doc_as_update_deprecated(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    tracing::warn!("/doc/:doc_id/as-update is deprecated; call /doc/:doc_id/auth instead and then call as-update on the returned base URL.");
    get_doc_as_update(State(server_state), Path(doc_id), auth_header).await
}

async fn update_doc_deprecated(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    body: Bytes,
) -> Result<Response, AppError> {
    tracing::warn!("/doc/:doc_id/update is deprecated; call /doc/:doc_id/auth instead and then call update on the returned base URL.");
    update_doc(Path(doc_id), State(server_state), auth_header, body).await
}

async fn get_doc_as_update_single(
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Result<Response, AppError> {
    let doc_id = server_state.get_single_doc_id()?;
    get_doc_as_update(State(server_state), Path(doc_id), auth_header).await
}

async fn update_doc(
    Path(doc_id): Path<String>,
    State(server_state): State<Arc<Server>>,
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    body: Bytes,
) -> Result<Response, AppError> {
    let token = get_token_from_header(auth_header);
    let access = server_state.verify_doc_token(token.as_deref(), &doc_id)?;
    update_doc_inner(doc_id, server_state, access, body).await
}

async fn update_doc_inner(
    doc_id: String,
    server_state: Arc<Server>,
    access: DocAccess,
    body: Bytes,
) -> Result<Response, AppError> {
    if !matches!(access.authorization, Authorization::Full) {
        return Err(AppError(StatusCode::FORBIDDEN, anyhow!("Unauthorized.")));
    }

    // Load the doc first, outside the write gate: loading can wait on the store, and must not
    // hold up shutdown. The awareness held from here on keeps GC from retiring the doc, so the
    // update is applied to a doc whose writes are saved, and no lookup or load is needed
    // under admission.
    let (awareness, _sync_kv) = server_state.live_doc(&doc_id).await?;

    // Admitted only while the gate is open, and held until the update is applied, so
    // shutdown's final save comes after it.
    let Some(admitted) = server_state.write_gate.enter().await else {
        return Err(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            anyhow!("The server is shutting down."),
        ));
    };
    if let Err(err) = apply_update_to(&awareness, &body, access.actor.as_ref()) {
        tracing::error!(?err, "Failed to apply update");
        return Err(AppError(StatusCode::INTERNAL_SERVER_ERROR, err));
    }
    // Shutdown stopped waiting for this write and started the final saves, which may not hold
    // it: refuse it like any write after the gate closed. Resending an update is harmless.
    if !admitted.in_time() {
        return Err(AppError(
            StatusCode::SERVICE_UNAVAILABLE,
            anyhow!("The server is shutting down."),
        ));
    }
    drop(admitted);
    drop(awareness);

    Ok(StatusCode::OK.into_response())
}

async fn update_doc_single(
    State(server_state): State<Arc<Server>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, AppError> {
    let doc_id = server_state.get_single_doc_id()?;
    // the doc server is meant to be run in Plane, so we expect verified plane
    // headers to be used for authorization.
    let authorization = get_authorization_from_plane_header(headers)?;
    let access = DocAccess {
        authorization,
        actor: None,
    };
    update_doc_inner(doc_id, server_state, access, body).await
}

async fn handle_socket_upgrade(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    access: DocAccess,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    if !matches!(access.authorization, Authorization::Full)
        && !server_state.docs.contains_key(&doc_id)
    {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            anyhow!("Doc {} not found", doc_id),
        ));
    }

    // A doc GC has not retired; the connection holds its awareness, which keeps GC off it.
    let (awareness, _sync_kv) = server_state.live_doc(&doc_id).await?;
    let cancellation_token = server_state.cancellation_token.clone();
    let write_gate = server_state.write_gate.clone();
    let connection_tracker = server_state.connection_tracker.clone();

    Ok(ws.on_upgrade(move |socket| {
        connection_tracker.track_future(handle_socket(
            socket,
            doc_id,
            awareness,
            access,
            cancellation_token,
            write_gate,
        ))
    }))
}

async fn handle_socket_upgrade_deprecated(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    tracing::warn!(
        "/doc/ws/:doc_id is deprecated; call /doc/:doc_id/auth instead and use the returned URL."
    );
    let access = server_state.verify_doc_token(params.token.as_deref(), &doc_id)?;
    handle_socket_upgrade(ws, Path(doc_id), access, State(server_state)).await
}

async fn handle_socket_upgrade_full_path(
    ws: WebSocketUpgrade,
    Path((doc_id, doc_id2)): Path<(String, String)>,
    Query(params): Query<HandlerParams>,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    if doc_id != doc_id2 {
        return Err(AppError(
            StatusCode::BAD_REQUEST,
            anyhow!("For Yjs compatibility, the doc_id appears twice in the URL. It must be the same in both places, but we got {} and {}.", doc_id, doc_id2),
        ));
    }
    let access = server_state.verify_doc_token(params.token.as_deref(), &doc_id)?;
    handle_socket_upgrade(ws, Path(doc_id), access, State(server_state)).await
}

async fn handle_socket_upgrade_single(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    headers: HeaderMap,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    let single_doc_id = server_state.get_single_doc_id()?;
    if doc_id != single_doc_id {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            anyhow!("Document not found"),
        ));
    }

    // the doc server is meant to be run in Plane, so we expect verified plane
    // headers to be used for authorization.
    let authorization = get_authorization_from_plane_header(headers)?;
    let access = DocAccess {
        authorization,
        actor: None,
    };
    handle_socket_upgrade(ws, Path(single_doc_id), access, State(server_state)).await
}

async fn handle_socket(
    socket: WebSocket,
    doc_id: String,
    awareness: Arc<RwLock<Awareness>>,
    access: DocAccess,
    cancellation_token: CancellationToken,
    write_gate: Arc<WriteGate>,
) {
    let DocAccess {
        authorization,
        actor,
    } = access;
    if let Some(actor) = &actor {
        // The writer kind only: user ids are never logged.
        tracing::debug!(
            doc_id = %doc_id,
            writer = actor.writer.as_deref(),
            has_user_id = actor.user_id.is_some(),
            "websocket opened with actor"
        );
    }

    let (mut sink, mut stream) = socket.split();
    let (send, mut recv) = channel(1024);

    let last_pong = Arc::new(RwLock::new(tokio::time::Instant::now()));
    let last_pong_clone = last_pong.clone();

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PING_EVERY);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                msg = recv.recv() => {
                    let Some(msg) = msg else {
                        break;
                    };
                    let _ = sink.send(Message::Binary(msg)).await;
                }
                _ = ticker.tick() => {
                    if last_pong_clone.read().expect("Failed to get read lock on last_pong").elapsed() > PONG_TIMEOUT {
                        tracing::info!("Pong timeout, closing connection");
                        break;
                    }
                    let _ = sink.send(Message::Ping(vec![])).await;
                }
            }
        }
    });

    let connection = DocConnection::new(awareness, authorization, actor, move |bytes| {
        if let Err(e) = send.try_send(bytes.to_vec()) {
            tracing::warn!(?e, "Error sending message");
        }
    });

    loop {
        tokio::select! {
            msg = stream.next() => {
                let Some(msg) = msg else {
                    break;
                };
                let msg = match msg {
                    Ok(Message::Binary(bytes)) => bytes,
                    Ok(Message::Close(_)) => break,
                    Ok(Message::Pong(_)) => {
                        *last_pong.write().expect("Failed to get write lock on last_pong") = tokio::time::Instant::now();
                        continue;
                    }
                    Err(_e) => {
                        // The stream will complain about things like
                        // connections being lost without handshake.
                        continue;
                    }
                    msg => {
                        tracing::warn!(?msg, "Received non-binary message");
                        continue;
                    }
                };

                // Held while the message is applied, so shutdown's final save comes after it.
                // Once shutdown has closed the gate, the message is not applied and the
                // connection ends; the client keeps the edit and sends it again on reconnect.
                let Some(admitted) = write_gate.enter().await else {
                    break;
                };
                if let Err(e) = connection.send(&msg).await {
                    tracing::warn!(?e, "Error handling message");
                }
                drop(admitted);
            }
            _ = cancellation_token.cancelled() => {
                tracing::debug!("Closing doc connection due to server cancel...");
                break;
            }
        }
    }
}

async fn check_store(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
) -> Result<Json<Value>, AppError> {
    server_state.check_auth(auth_header)?;

    if server_state.store.is_none() {
        return Ok(Json(json!({"ok": false, "error": "No store set."})));
    };

    // The check_store endpoint for the native server is kind of moot, since
    // the server will not start if store is not ok.
    Ok(Json(json!({"ok": true})))
}

async fn check_store_deprecated(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
) -> Result<Json<Value>, AppError> {
    tracing::warn!(
        "GET check_store is deprecated, use POST check_store with an empty body instead."
    );
    check_store(auth_header, State(server_state)).await
}

/// Always returns a 200 OK response, as long as we are listening.
async fn ready() -> Result<Json<Value>, AppError> {
    Ok(Json(json!({"ok": true})))
}

async fn new_doc(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    State(server_state): State<Arc<Server>>,
    Json(body): Json<DocCreationRequest>,
) -> Result<Json<NewDocResponse>, AppError> {
    server_state.check_auth(auth_header)?;

    let doc_id = if let Some(doc_id) = body.doc_id {
        if !validate_doc_name(doc_id.as_str()) {
            Err((StatusCode::BAD_REQUEST, anyhow!("Invalid document name")))?
        }

        server_state
            .get_or_create_doc(doc_id.as_str())
            .await
            .map_err(|e| {
                tracing::error!(?e, "Failed to create doc");
                (StatusCode::INTERNAL_SERVER_ERROR, e)
            })?;

        doc_id
    } else {
        server_state.create_doc().await.map_err(|d| {
            tracing::error!(?d, "Failed to create doc");
            (StatusCode::INTERNAL_SERVER_ERROR, d)
        })?
    };

    Ok(Json(NewDocResponse { doc_id }))
}

/// The body of an auth request. An empty body asks for the defaults (a full-access token), as
/// upstream allows. Any other body must be a JSON [AuthDocRequest]; one that is not is refused,
/// never read as the defaults, which would mint a full-access token for a request that may have
/// asked for read-only.
fn parse_auth_request(headers: &HeaderMap, body: &Bytes) -> Result<AuthDocRequest, AppError> {
    if body.is_empty() {
        return Ok(AuthDocRequest::default());
    }
    let is_json = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            let essence = value.split(';').next().unwrap_or("").trim();
            essence.eq_ignore_ascii_case("application/json")
                || (essence.starts_with("application/") && essence.ends_with("+json"))
        })
        .unwrap_or(false);
    if !is_json {
        return Err(AppError(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            anyhow!("Expected request with `Content-Type: application/json`"),
        ));
    }
    Json::<AuthDocRequest>::from_bytes(body)
        .map(|Json(request)| request)
        .map_err(|rejection| AppError(rejection.status(), anyhow!(rejection.body_text())))
}

async fn auth_doc(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    TypedHeader(host): TypedHeader<headers::Host>,
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ClientToken>, AppError> {
    server_state.check_auth(auth_header)?;

    let AuthDocRequest {
        authorization,
        valid_for_seconds,
        user_id,
        writer,
    } = parse_auth_request(&headers, &body)?;

    let actor_requested = user_id.is_some() || writer.is_some();
    let (user_id_bytes, writer_bytes) = (
        user_id.as_ref().map(String::len),
        writer.as_ref().map(String::len),
    );
    let actor = match Actor::from_request(user_id, writer) {
        Ok(actor) => actor,
        // With attributed tokens on, an oversize value would end up in the token: refuse it.
        Err(err) if server_state.attributed_tokens => {
            return Err(AppError(StatusCode::BAD_REQUEST, err.into()));
        }
        // With them off the fields are ignored, as in upstream Y-Sweet, so the request goes
        // through. Warn, because turning the switch on will start refusing it. Lengths only:
        // the values are user ids.
        Err(_) => {
            tracing::warn!(
                doc_id = %doc_id,
                user_id_bytes,
                writer_bytes,
                max_user_id_bytes = y_sweet_core::auth::MAX_ACTOR_USER_ID_BYTES,
                max_writer_bytes = y_sweet_core::auth::MAX_ACTOR_WRITER_BYTES,
                "auth request actor too long; ignored, would be rejected with attributed tokens on"
            );
            None
        }
    };

    if !server_state.doc_exists(&doc_id).await {
        Err((StatusCode::NOT_FOUND, anyhow!("Doc {} not found", doc_id)))?;
    }

    let valid_for_seconds = valid_for_seconds.unwrap_or(DEFAULT_EXPIRATION_SECONDS);
    let expiration_time =
        ExpirationTimeEpochMillis(current_time_epoch_millis() + valid_for_seconds * 1000);

    let requested_writer = actor.as_ref().and_then(|actor| actor.writer.clone());
    // Without the switch the actor is dropped and the token is the plain doc token every
    // earlier binary understands.
    let actor = actor.filter(|_| server_state.attributed_tokens);

    let token = if let Some(auth) = &server_state.authenticator {
        // The writer kind only: user ids and tokens are never logged.
        tracing::info!(
            doc_id = %doc_id,
            attributed = actor.is_some(),
            actor_requested,
            writer = requested_writer.as_deref(),
            "minted doc token"
        );
        let token = auth.gen_doc_token_with_actor(&doc_id, authorization, expiration_time, actor);
        Some(token)
    } else {
        None
    };

    let url = if let Some(url_prefix) = &server_state.url_prefix {
        let mut url = url_prefix.clone();
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme).unwrap();
        url = url.join(&format!("/d/{doc_id}/ws")).unwrap();
        url.to_string()
    } else {
        format!("ws://{host}/d/{doc_id}/ws")
    };

    let base_url = if let Some(url_prefix) = &server_state.url_prefix {
        let mut url_prefix = url_prefix.to_string();
        if !url_prefix.ends_with('/') {
            url_prefix = format!("{url_prefix}/");
        }

        format!("{url_prefix}d/{doc_id}")
    } else {
        format!("http://{host}/d/{doc_id}")
    };

    Ok(Json(ClientToken {
        url,
        base_url: Some(base_url),
        doc_id,
        token,
        authorization,
    }))
}

fn get_token_from_header(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
) -> Option<String> {
    if let Some(TypedHeader(headers::Authorization(bearer))) = auth_header {
        Some(bearer.token().to_string())
    } else {
        None
    }
}

#[derive(Deserialize)]
struct PlaneVerifiedUserData {
    authorization: Authorization,
}

fn get_authorization_from_plane_header(headers: HeaderMap) -> Result<Authorization, AppError> {
    if let Some(token) = headers.get(HeaderName::from_static(PLANE_VERIFIED_USER_DATA_HEADER)) {
        let token_str = token.to_str().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        let user_data: PlaneVerifiedUserData =
            serde_json::from_str(token_str).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
        Ok(user_data.authorization)
    } else {
        Err((StatusCode::UNAUTHORIZED, anyhow!("No token provided.")))?
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use y_sweet_core::api_types::Authorization;

    #[tokio::test]
    async fn test_auth_doc() {
        let server_state = Server::new(
            None,
            Duration::from_secs(60),
            None,
            None,
            CancellationToken::new(),
            true,
            None,
            false,
        )
        .await
        .unwrap();

        let doc_id = server_state.create_doc().await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(Arc::new(server_state)),
            Path(doc_id.clone()),
            json_headers(),
            Bytes::from_static(br#"{"authorization": "full"}"#),
        )
        .await
        .unwrap();

        let expected_url = format!("ws://localhost/d/{doc_id}/ws");
        assert_eq!(token.url, expected_url);
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
    }

    #[tokio::test]
    async fn test_auth_doc_with_prefix() {
        let prefix: Url = "https://foo.bar".parse().unwrap();
        let server_state = Server::new(
            None,
            Duration::from_secs(60),
            None,
            Some(prefix),
            CancellationToken::new(),
            true,
            None,
            false,
        )
        .await
        .unwrap();

        let doc_id = server_state.create_doc().await.unwrap();

        let token = auth_doc(
            None,
            TypedHeader(headers::Host::from(http::uri::Authority::from_static(
                "localhost",
            ))),
            State(Arc::new(server_state)),
            Path(doc_id.clone()),
            HeaderMap::new(),
            Bytes::new(),
        )
        .await
        .unwrap();

        let expected_url = format!("wss://foo.bar/d/{doc_id}/ws");
        assert_eq!(token.url, expected_url);
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
    }

    const DOC_ID: &str = "doc123";

    fn localhost() -> TypedHeader<headers::Host> {
        TypedHeader(headers::Host::from(http::uri::Authority::from_static(
            "localhost",
        )))
    }

    fn bearer(
        token: &str,
    ) -> Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>> {
        Some(TypedHeader(headers::Authorization::bearer(token).unwrap()))
    }

    /// A server with auth and one doc, plus a second authenticator over the same key to mint
    /// server tokens and verify what the server mints.
    async fn server_with_auth(attributed_tokens: bool) -> (Server, Authenticator) {
        let authenticator = Authenticator::gen_key().unwrap();
        let verifier = Authenticator::new(&authenticator.private_key()).unwrap();
        let server = Server::new(
            None,
            Duration::from_secs(60),
            Some(authenticator),
            None,
            CancellationToken::new(),
            true,
            None,
            false,
        )
        .await
        .unwrap()
        .with_attributed_tokens(attributed_tokens);
        server.load_doc(DOC_ID).await.unwrap();
        (server, verifier)
    }

    async fn mint(
        server: &Arc<Server>,
        verifier: &Authenticator,
        request: Option<AuthDocRequest>,
    ) -> Result<DocAccess, StatusCode> {
        let response = auth_doc(
            bearer(&verifier.server_token()),
            localhost(),
            State(server.clone()),
            Path(DOC_ID.to_string()),
            json_headers(),
            Bytes::from(json_body(request).to_string()),
        )
        .await;
        match response {
            Ok(Json(client_token)) => Ok(verifier
                .verify_doc_token(
                    &client_token.token.expect("a token"),
                    DOC_ID,
                    current_time_epoch_millis(),
                )
                .unwrap()),
            Err(AppError(status, _)) => Err(status),
        }
    }

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers
    }

    /// `request` as a client sends it; `None` is the empty object.
    fn json_body(request: Option<AuthDocRequest>) -> Value {
        let Some(request) = request else {
            return json!({});
        };
        json!({
            "authorization": request.authorization,
            "userId": request.user_id,
            "writer": request.writer,
            "validForSeconds": request.valid_for_seconds,
        })
    }

    fn request(user_id: Option<&str>, writer: Option<&str>) -> Option<AuthDocRequest> {
        Some(AuthDocRequest {
            authorization: Authorization::Full,
            user_id: user_id.map(str::to_string),
            writer: writer.map(str::to_string),
            valid_for_seconds: None,
        })
    }

    #[test]
    fn auth_request_accepts_user_id_and_writer() {
        let request: AuthDocRequest =
            serde_json::from_str(r#"{"userId": "user-1", "writer": "ui"}"#).unwrap();
        assert_eq!(request.user_id.as_deref(), Some("user-1"));
        assert_eq!(request.writer.as_deref(), Some("ui"));

        // What every existing client sends still parses.
        let request: AuthDocRequest = serde_json::from_str(r#"{"userId": "user-1"}"#).unwrap();
        assert_eq!(request.writer, None);
        let request: AuthDocRequest = serde_json::from_str("{}").unwrap();
        assert_eq!((request.user_id, request.writer), (None, None));
    }

    /// Posts `body` to the auth endpoint of a served server. Returns the status, and on `200`
    /// the authorization the minted token grants.
    async fn auth_over_http(
        content_type: Option<&str>,
        body: &'static str,
    ) -> (u16, Option<Authorization>) {
        let (server, verifier) = server_with_auth(true).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener, false));

        let mut request = reqwest::Client::new()
            .post(format!("http://{addr}/doc/{DOC_ID}/auth"))
            .bearer_auth(verifier.server_token())
            .body(body);
        if let Some(content_type) = content_type {
            request = request.header("content-type", content_type);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        if status != 200 {
            return (status, None);
        }
        let token: ClientToken = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        let access = verifier
            .verify_doc_token(&token.token.unwrap(), DOC_ID, current_time_epoch_millis())
            .unwrap();
        (status, Some(access.authorization))
    }

    #[tokio::test]
    async fn auth_without_a_body_mints_a_full_token() {
        // What upstream accepts, e.g. `curl -X POST` with no body.
        assert_eq!(
            auth_over_http(None, "").await,
            (200, Some(Authorization::Full))
        );
        assert_eq!(
            auth_over_http(Some("application/json"), "{}").await,
            (200, Some(Authorization::Full))
        );
        assert_eq!(
            auth_over_http(Some("application/json"), r#"{"authorization": "read-only"}"#).await,
            (200, Some(Authorization::ReadOnly))
        );
    }

    #[tokio::test]
    async fn auth_with_a_malformed_body_is_refused_not_defaulted_to_full() {
        // Each asks for read-only; none may come back with a token, least of all a full one.
        let json = Some("application/json");
        let cases: [(Option<&str>, &'static str, u16); 6] = [
            (json, r#"{"authorization": "read-only", "userId": 7}"#, 422),
            (json, r#"{"authorization": "read-only", "writer": {"kind": "ui"}}"#, 422),
            (json, r#"{"authorization": "read-only-ish"}"#, 422),
            (json, r#"{"authorization": "read-only""#, 400),
            (Some("text/plain"), r#"{"authorization": "read-only"}"#, 415),
            (None, r#"{"authorization": "read-only"}"#, 415),
        ];
        for (content_type, body, status) in cases {
            assert_eq!(
                auth_over_http(content_type, body).await,
                (status, None),
                "{content_type:?} {body}"
            );
        }
    }

    #[tokio::test]
    async fn mint_with_switch_off_ignores_the_actor() {
        let (server, verifier) = server_with_auth(false).await;
        let server = Arc::new(server);

        let access = mint(&server, &verifier, request(Some("user-1"), Some("ui")))
            .await
            .unwrap();
        assert_eq!(access, DocAccess::full());
    }

    #[tokio::test]
    async fn mint_with_switch_on_binds_the_actor() {
        let (server, verifier) = server_with_auth(true).await;
        let server = Arc::new(server);

        let access = mint(&server, &verifier, request(Some("user-1"), Some("ui")))
            .await
            .unwrap();
        assert_eq!(
            access.actor,
            Some(Actor {
                user_id: Some("user-1".to_string()),
                writer: Some("ui".to_string()),
            })
        );

        // Either field alone is enough.
        let access = mint(&server, &verifier, request(None, Some("agent")))
            .await
            .unwrap();
        assert_eq!(
            access.actor,
            Some(Actor {
                user_id: None,
                writer: Some("agent".to_string()),
            })
        );

        // A request that names no one still gets the plain doc token.
        let access = mint(&server, &verifier, request(None, None)).await.unwrap();
        assert_eq!(access, DocAccess::full());
        let access = mint(&server, &verifier, None).await.unwrap();
        assert_eq!(access, DocAccess::full());
    }

    #[tokio::test]
    async fn oversize_actor_fields_are_rejected_only_with_the_switch_on() {
        let max_user_id = "u".repeat(128);
        let max_writer = "w".repeat(64);
        let long_user_id = format!("{max_user_id}u");
        let long_writer = format!("{max_writer}w");

        for attributed_tokens in [false, true] {
            let (server, verifier) = server_with_auth(attributed_tokens).await;
            let server = Arc::new(server);

            assert!(mint(
                &server,
                &verifier,
                request(Some(&max_user_id), Some(&max_writer))
            )
            .await
            .is_ok());

            for oversize in [
                request(Some(&long_user_id), None),
                request(None, Some(&long_writer)),
                request(Some(&long_user_id), Some(&long_writer)),
            ] {
                let minted = mint(&server, &verifier, oversize).await;
                if attributed_tokens {
                    assert_eq!(minted, Err(StatusCode::BAD_REQUEST));
                } else {
                    // As upstream: the fields are ignored and a plain doc token is minted.
                    assert_eq!(minted, Ok(DocAccess::full()));
                }
            }
        }
    }

    #[tokio::test]
    async fn http_update_is_attributed_to_the_bearer_token() {
        use std::sync::Mutex;
        use y_sweet_core::update_events::AttributedUpdate;
        use yrs::{Doc, Text, Transact};

        let (mut server, verifier) = server_with_auth(true).await;
        let events: Arc<Mutex<Vec<AttributedUpdate>>> = Arc::default();
        server.on_update = Some({
            let events = events.clone();
            Arc::new(
                move |event: y_sweet_core::update_events::ObservedUpdate<'_>| {
                    events.lock().unwrap().push(event.to_owned())
                },
            )
        });
        // Docs pick the observer up when they are loaded.
        server.docs.remove(DOC_ID);
        server.load_doc(DOC_ID).await.unwrap();
        let server = Arc::new(server);

        let client = Doc::with_client_id(1);
        let text = client.get_or_insert_text("t");
        let edit = |chunk: &str| {
            let mut txn = client.transact_mut();
            text.push(&mut txn, chunk);
            Bytes::from(txn.encode_update_v1())
        };

        let alice = Actor {
            user_id: Some("alice".to_string()),
            writer: Some("server-fallback".to_string()),
        };
        let expiration = ExpirationTimeEpochMillis(current_time_epoch_millis() + 60_000);
        let attributed_token = verifier.gen_doc_token_with_actor(
            DOC_ID,
            Authorization::Full,
            expiration,
            Some(alice.clone()),
        );
        let plain_token = verifier.gen_doc_token(DOC_ID, Authorization::Full, expiration);

        for token in [attributed_token, plain_token, verifier.server_token()] {
            update_doc(
                Path(DOC_ID.to_string()),
                State(server.clone()),
                bearer(&token),
                edit("x"),
            )
            .await
            .unwrap();
        }

        let actors: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .map(|event| (event.doc_id.clone(), event.actor.clone()))
            .collect();
        assert_eq!(
            actors,
            vec![
                (DOC_ID.to_string(), Some(alice)),
                (DOC_ID.to_string(), None),
                (DOC_ID.to_string(), None),
            ]
        );
    }

    type Events = Arc<std::sync::Mutex<Vec<y_sweet_core::update_events::AttributedUpdate>>>;

    /// A server with auth and attributed tokens, serving on a local port, whose docs report
    /// their updates into `events`.
    struct Served {
        addr: std::net::SocketAddr,
        events: Events,
        verifier: Authenticator,
        token: CancellationToken,
        task: tokio::task::JoinHandle<Result<()>>,
    }

    impl Served {
        async fn start() -> Self {
            let authenticator = Authenticator::gen_key().unwrap();
            let verifier = Authenticator::new(&authenticator.private_key()).unwrap();
            let token = CancellationToken::new();
            let mut server = Server::new(
                None,
                Duration::from_secs(60),
                Some(authenticator),
                None,
                token.clone(),
                true,
                None,
                false,
            )
            .await
            .unwrap()
            .with_attributed_tokens(true);
            let events = Events::default();
            server.on_update = Some({
                let events = events.clone();
                Arc::new(
                    move |event: y_sweet_core::update_events::ObservedUpdate<'_>| {
                        events.lock().unwrap().push(event.to_owned())
                    },
                )
            });
            server.load_doc(DOC_ID).await.unwrap();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let task = tokio::spawn(server.serve(listener, false));
            Self {
                addr,
                events,
                verifier,
                token,
                task,
            }
        }

        fn doc_token(&self, authorization: Authorization, actor: Option<Actor>) -> String {
            let expiration = ExpirationTimeEpochMillis(current_time_epoch_millis() + 60_000);
            self.verifier
                .gen_doc_token_with_actor(DOC_ID, authorization, expiration, actor)
        }

        fn actors(&self) -> Vec<Option<Actor>> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .map(|event| event.actor.clone())
                .collect()
        }

        async fn wait_for_events(&self, count: usize) {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while self.events.lock().unwrap().len() < count {
                assert!(
                    std::time::Instant::now() < deadline,
                    "timed out waiting for {count} update events"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        async fn stop(self) {
            self.token.cancel();
            tokio::time::timeout(Duration::from_secs(10), self.task)
                .await
                .expect("server did not stop")
                .unwrap()
                .unwrap();
        }
    }

    /// The incremental update of one edit by a client that types into the text `t`.
    fn edit(client: &yrs::Doc, chunk: &str) -> Vec<u8> {
        use yrs::{Text, Transact};
        let text = client.get_or_insert_text("t");
        let mut txn = client.transact_mut();
        text.push(&mut txn, chunk);
        txn.encode_update_v1()
    }

    #[tokio::test]
    async fn websocket_updates_are_attributed_to_the_token_they_connected_with() {
        use tokio_tungstenite::tungstenite::Message as WsMessage;
        use y_sweet_core::sync::{Message as SyncProtocolMessage, SyncMessage};
        use yrs::updates::encoder::Encode;

        let served = Served::start().await;
        let alice = Actor {
            user_id: Some("alice".to_string()),
            writer: Some("ui".to_string()),
        };
        let client = yrs::Doc::with_client_id(1);

        for (expected, actor) in [(1, Some(alice.clone())), (2, None)] {
            let token = served.doc_token(Authorization::Full, actor);
            let url = format!("ws://{}/d/{DOC_ID}/ws/{DOC_ID}?token={token}", served.addr);
            let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            let message = SyncProtocolMessage::Sync(SyncMessage::Update(edit(&client, "x")));
            socket
                .send(WsMessage::Binary(message.encode_v1()))
                .await
                .unwrap();
            served.wait_for_events(expected).await;
            socket.close(None).await.unwrap();
        }

        assert_eq!(served.actors(), vec![Some(alice), None]);
        served.stop().await;
    }

    #[tokio::test]
    async fn http_update_with_a_read_only_token_is_forbidden_and_emits_nothing() {
        let served = Served::start().await;
        let client = yrs::Doc::with_client_id(1);
        let alice = Actor {
            user_id: Some("alice".to_string()),
            writer: Some("http".to_string()),
        };
        let http = reqwest::Client::new();
        let post = |token: String, body: Vec<u8>| {
            http.post(format!("http://{}/d/{DOC_ID}/update", served.addr))
                .bearer_auth(token)
                .body(body)
                .send()
        };

        let read_only = served.doc_token(Authorization::ReadOnly, Some(alice.clone()));
        let response = post(read_only, edit(&client, "x")).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // A full token goes through the same route, so the 403 was the token's doing; and the
        // only event is the full token's. (Another client: an edit by the first one would
        // depend on the rejected "x", and yrs would hold it back as pending.)
        let full = served.doc_token(Authorization::Full, Some(alice.clone()));
        let response = post(full, edit(&yrs::Doc::with_client_id(2), "y"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        served.wait_for_events(1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(served.actors(), vec![Some(alice)]);

        served.stop().await;
    }

    #[tokio::test]
    async fn serve_runs_the_update_webhook_flush_on_shutdown() {
        // The receiver answers slowly, so `serve` returning before it answered would show.
        let received: Arc<std::sync::Mutex<Vec<Value>>> = Arc::default();
        let receiver = {
            let received = received.clone();
            Router::new().route(
                "/updates",
                post(move |body: Bytes| {
                    let received = received.clone();
                    async move {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        received
                            .lock()
                            .unwrap()
                            .push(serde_json::from_slice(&body).unwrap());
                        StatusCode::NO_CONTENT
                    }
                }),
            )
        };
        let receiver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let receiver_url: Url =
            format!("http://{}/updates", receiver_listener.local_addr().unwrap())
                .parse()
                .unwrap();
        tokio::spawn(async move { axum::serve(receiver_listener, receiver).await.unwrap() });

        let token = CancellationToken::new();
        let server = Server::new(
            None,
            Duration::from_secs(60),
            None,
            None,
            token.clone(),
            true,
            None,
            false,
        )
        .await
        .unwrap()
        .with_update_webhook(UpdateWebhookConfig {
            // Only the shutdown flush can close this batch.
            batch_window: Duration::from_secs(3600),
            ..UpdateWebhookConfig::new(receiver_url, "secret".to_string())
        })
        .unwrap();
        server.load_doc(DOC_ID).await.unwrap();
        server
            .docs
            .get(DOC_ID)
            .unwrap()
            .apply_update(&edit(&yrs::Doc::with_client_id(1), "x"), None)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let serving = tokio::spawn(server.serve(listener, false));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(received.lock().unwrap().is_empty());

        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();

        // Already there when `serve` returns: it waited for the flush.
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0]["doc_id"], DOC_ID);
        assert_eq!(received[0]["events"].as_array().unwrap().len(), 1);
    }

    // --- Shutdown ---------------------------------------------------------------------------

    /// An in-memory store whose writes can be made to hang, and whose reads of one key wait
    /// until the test releases them.
    #[derive(Clone)]
    struct TestStore {
        data: Arc<DashMap<String, Vec<u8>>>,
        slow: Arc<std::sync::atomic::AtomicBool>,
        held_key: Arc<std::sync::Mutex<Option<String>>>,
        held_get_entered: Arc<tokio::sync::Notify>,
        held_get_release: Arc<tokio::sync::Semaphore>,
        /// How many reads of the held key started.
        held_gets: Arc<std::sync::atomic::AtomicUsize>,
        /// Every read takes this long, in milliseconds.
        get_delay_ms: Arc<std::sync::atomic::AtomicU64>,
        /// How many reads started, of any key.
        gets: Arc<std::sync::atomic::AtomicUsize>,
        /// Writes fail while set.
        fail_sets: Arc<std::sync::atomic::AtomicBool>,
        /// The next write times out as far as the caller can tell, but the store has all
        /// of it: it is kept in `stale_write`, to be applied late by `land_stale_write`.
        time_out_next_set: Arc<std::sync::atomic::AtomicBool>,
        stale_write: Arc<std::sync::Mutex<Option<StoredWrite>>>,
        /// When that write was failed: taken by the store as it returns the error, so it is
        /// never later than the moment the server learns of the failure.
        timed_out_at: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
        /// How many writes were stored.
        sets: Arc<std::sync::atomic::AtomicUsize>,
        /// Every write takes this long, in milliseconds.
        set_delay_ms: Arc<std::sync::atomic::AtomicU64>,
        /// Writes wait for `set_release` while set.
        hold_sets: Arc<std::sync::atomic::AtomicBool>,
        /// The next write is sent and then cannot be recalled: it runs on, and lands once
        /// `set_release` allows, even if the caller stops waiting for it (like an S3 PUT).
        detach_next_set: Arc<std::sync::atomic::AtomicBool>,
        set_entered: Arc<tokio::sync::Notify>,
        set_release: Arc<tokio::sync::Semaphore>,
    }

    impl Default for TestStore {
        fn default() -> Self {
            Self {
                data: Default::default(),
                slow: Default::default(),
                held_key: Default::default(),
                held_get_entered: Default::default(),
                held_get_release: Arc::new(tokio::sync::Semaphore::new(0)),
                held_gets: Default::default(),
                get_delay_ms: Default::default(),
                gets: Default::default(),
                fail_sets: Default::default(),
                time_out_next_set: Default::default(),
                stale_write: Default::default(),
                timed_out_at: Default::default(),
                sets: Default::default(),
                set_delay_ms: Default::default(),
                hold_sets: Default::default(),
                detach_next_set: Default::default(),
                set_entered: Default::default(),
                set_release: Arc::new(tokio::sync::Semaphore::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl Store for TestStore {
        async fn init(&self) -> y_sweet_core::store::Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> y_sweet_core::store::Result<Option<Vec<u8>>> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let delay = self.get_delay_ms.load(std::sync::atomic::Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let held = self.held_key.lock().unwrap().as_deref() == Some(key);
            if held {
                self.held_gets
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.held_get_entered.notify_one();
                self.held_get_release.acquire().await.unwrap().forget();
            }
            Ok(self.data.get(key).map(|v| v.clone()))
        }
        async fn set(&self, key: &str, value: Vec<u8>) -> y_sweet_core::store::Result<()> {
            use std::sync::atomic::Ordering::SeqCst;
            if self.slow.load(SeqCst) {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
            let delay = self.set_delay_ms.load(SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            if self.detach_next_set.swap(false, SeqCst) {
                let store = self.clone();
                let key = key.to_string();
                let write = tokio::spawn(async move {
                    store.set_entered.notify_one();
                    store.set_release.acquire().await.unwrap().forget();
                    store.data.insert(key, value);
                });
                write.await.unwrap();
                return Ok(());
            }
            if self.hold_sets.load(SeqCst) {
                self.set_entered.notify_one();
                self.set_release.acquire().await.unwrap().forget();
            }
            if self.time_out_next_set.swap(false, SeqCst) {
                *self.stale_write.lock().unwrap() = Some((key.to_string(), value));
                *self.timed_out_at.lock().unwrap() = Some(std::time::Instant::now());
                return Err(y_sweet_core::store::StoreError::Timeout {
                    limit: Duration::from_millis(1),
                    what: "waiting for",
                });
            }
            if self.fail_sets.load(SeqCst) {
                return Err(y_sweet_core::store::StoreError::ConnectionError(
                    "test failure".to_string(),
                ));
            }
            self.sets.fetch_add(1, SeqCst);
            self.data.insert(key.to_string(), value);
            Ok(())
        }
        async fn remove(&self, key: &str) -> y_sweet_core::store::Result<()> {
            self.data.remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> y_sweet_core::store::Result<bool> {
            Ok(self.data.contains_key(key))
        }
    }

    impl TestStore {
        /// The store applies the write that timed out, over whatever was saved since.
        /// Returns the bytes it stored.
        fn land_stale_write(&self) -> Vec<u8> {
            let (key, value) = self.stale_write.lock().unwrap().take().unwrap();
            self.data.insert(key, value.clone());
            value
        }
    }

    /// A key and the value written to it.
    type StoredWrite = (String, Vec<u8>);

    /// The server's docs, the task serving it, and when the save timed out.
    type TimedOutSave = (
        Arc<DashMap<String, DocWithSyncKv>>,
        tokio::task::JoinHandle<Result<()>>,
        std::time::Instant,
    );

    /// A served server with a 50 ms checkpoint and GC, no doc loaded, whose next store write
    /// times out. Returns once a save of `doc_id` holding edit 1 has timed out and a later
    /// save, holding edits 1 and 2, has succeeded.
    async fn server_after_a_timed_out_save(
        store: &TestStore,
        token: &CancellationToken,
        doc_id: &str,
        suspect_window: Duration,
    ) -> TimedOutSave {
        let mut server = Server::new(
            Some(Box::new(store.clone())),
            Duration::from_millis(50),
            None,
            None,
            token.clone(),
            true,
            None,
            false,
        )
        .await
        .unwrap();
        server.suspect_window = suspect_window;
        server.suspect_resave = Duration::from_millis(250);
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        store
            .time_out_next_set
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            post_update(addr, doc_id, map_edit(1)).await.unwrap(),
            Some(200)
        );
        eventually("a save times out", || {
            store.stale_write.lock().unwrap().is_some()
        })
        .await;
        // The store's own record of the moment, not the time this test noticed: the suspect
        // window is counted from the failure, and the checks below compare against it to
        // the millisecond (GC can collect the doc within moments of the window's end).
        let timed_out_at = store
            .timed_out_at
            .lock()
            .unwrap()
            .expect("set with the write");
        assert_eq!(
            post_update(addr, doc_id, map_edit(2)).await.unwrap(),
            Some(200)
        );
        wait_for_stored_key(store, doc_id, "2").await;
        (docs, serving, timed_out_at)
    }

    async fn wait_for_stored_key(store: &TestStore, doc_id: &str, key: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !stored_keys_of(store, doc_id).await.contains(key) {
            assert!(
                std::time::Instant::now() < deadline,
                "key {key} of {doc_id} was never stored"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn a_timed_out_save_that_lands_late_is_saved_over_and_the_doc_kept_meanwhile() {
        const DOC: &str = "suspect-doc";
        let store = TestStore::default();
        let token = CancellationToken::new();
        // Long against what the test does inside it (well under a second on an idle machine),
        // so that a loaded machine still gets its checks in before the window ends.
        let window = Duration::from_millis(4000);
        let (docs, serving, timed_out_at) =
            server_after_a_timed_out_save(&store, &token, DOC, window).await;
        assert!(
            timed_out_at.elapsed() < window / 2,
            "the test ran too slowly to check anything"
        );
        let unsaved = || docs.get(DOC).unwrap().sync_kv().has_unsaved_changes();

        // (a) The save that succeeded did not leave the doc clean...
        assert!(unsaved());
        // ...so when the store now applies the write that timed out, over the newer save,
        let stale = store.land_stale_write();
        assert!(
            !stored_keys_of(&store, DOC).await.contains("2") || {
                // (unless a checkpoint has already saved over it)
                *store.data.get(&format!("{DOC}/data.ysweet")).unwrap() != stale
            }
        );
        // the next checkpoint puts the current state back.
        wait_for_stored_key(&store, DOC, "2").await;

        // (b) GC leaves the doc alone for as long as it is suspect, idle though it is: here
        // for ten checkpoints, where two would do otherwise.
        let mut checked = 0;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Looked at only while the window is certainly still open, with a margin for
            // the time the three lines take themselves.
            if timed_out_at.elapsed() < window - Duration::from_millis(500) {
                assert!(docs.contains_key(DOC), "collected while suspect");
                assert!(!is_retired(&docs, DOC), "retired while suspect");
                assert!(unsaved());
                checked += 1;
            }
        }
        assert!(
            checked >= 5,
            "the test ran too slowly: only {checked} looks inside the window"
        );

        // (c) After the window a save clears the doc, and GC collects it.
        eventually("GC collects the doc after the window", || {
            !docs.contains_key(DOC)
        })
        .await;
        // Not a moment before the window, counted from the failure itself, had passed.
        assert!(timed_out_at.elapsed() >= window);
        // Meanwhile it was saved every 250 ms or so, not at each of the eighty checkpoints.
        let saves = store.sets.load(std::sync::atomic::Ordering::SeqCst);
        assert!((4..40).contains(&saves), "{saves} saves");
        let stored = stored_keys_of(&store, DOC).await;
        assert!(stored.contains("1") && stored.contains("2"), "{stored:?}");

        token.cancel();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_saves_a_suspect_doc_and_does_not_wait_out_its_window() {
        const DOC: &str = "suspect-doc";
        let store = TestStore::default();
        let token = CancellationToken::new();
        let (docs, serving, _) =
            server_after_a_timed_out_save(&store, &token, DOC, Duration::from_secs(3600)).await;
        let doc = docs.get(DOC).unwrap();
        apply_update_to(&doc.awareness(), &map_edit(3), None).unwrap();
        drop(doc);

        token.cancel();
        tokio::time::timeout(Duration::from_secs(5), serving)
            .await
            .expect("shutdown waited for the suspect doc")
            .unwrap()
            .unwrap();
        let stored = stored_keys_of(&store, DOC).await;
        assert!(stored.contains("3"), "{stored:?}");
        assert!(docs.get(DOC).unwrap().sync_kv().is_suspect());
    }

    async fn server_with_store(store: &TestStore, token: &CancellationToken) -> Server {
        // Long enough that only shutdown saves, and GC never runs.
        server_with_checkpoints(store, token, Duration::from_secs(3600)).await
    }

    async fn server_with_checkpoints(
        store: &TestStore,
        token: &CancellationToken,
        checkpoint_freq: Duration,
    ) -> Server {
        server_with_gc(store, token, checkpoint_freq, DEFAULT_DOC_WAIT).await
    }

    async fn server_with_gc(
        store: &TestStore,
        token: &CancellationToken,
        checkpoint_freq: Duration,
        doc_wait: Duration,
    ) -> Server {
        let mut server = Server::new(
            Some(Box::new(store.clone())),
            checkpoint_freq,
            None,
            None,
            token.clone(),
            true,
            None,
            false,
        )
        .await
        .unwrap();
        server.doc_wait = doc_wait;
        server.load_doc(DOC_ID).await.unwrap();
        server
    }

    /// An update that sets key `id` in the map `m`, from a client of its own, so that updates
    /// are independent of each other.
    fn map_edit(id: u64) -> Vec<u8> {
        use yrs::{Map, Transact};
        let client = yrs::Doc::with_client_id(id);
        let map = client.get_or_insert_map("m");
        let mut txn = client.transact_mut();
        map.insert(&mut txn, id.to_string(), true);
        txn.encode_update_v1()
    }

    /// The keys of map `m` in the doc as the store holds it.
    async fn stored_keys(store: &TestStore) -> std::collections::HashSet<String> {
        stored_keys_of(store, DOC_ID).await
    }

    async fn stored_keys_of(store: &TestStore, doc_id: &str) -> std::collections::HashSet<String> {
        use yrs::{Map, ReadTxn, Transact};
        let doc = DocWithSyncKv::new(
            doc_id,
            Some(Arc::new(Box::new(store.clone()) as Box<dyn Store>)),
            || {},
            false,
            None,
        )
        .await
        .unwrap();
        let awareness = doc.awareness();
        let awareness = awareness.read().unwrap();
        let txn = awareness.doc().transact();
        match txn.get_map("m") {
            Some(map) => map.keys(&txn).map(str::to_string).collect(),
            None => Default::default(),
        }
    }

    #[test]
    fn dirty_callback_does_not_panic_on_a_full_or_closed_channel() {
        let (send, recv) = tokio::sync::mpsc::channel(1);
        let notify = dirty_callback(send);
        notify();
        notify(); // full
        drop(recv);
        notify(); // closed
    }

    #[tokio::test]
    async fn an_edit_after_the_persistence_worker_stopped_does_not_panic() {
        let token = CancellationToken::new();
        let server = server_with_store(&TestStore::default(), &token).await;

        // The doc's persistence worker exits, closing its channel, as at shutdown.
        server.doc_workers_token.cancel();
        server.doc_worker_tracker.close();
        server.doc_worker_tracker.wait().await;

        // The first edit marks the doc dirty and notifies the gone worker, under the doc lock.
        // That used to panic and poison the lock.
        let doc = server.docs.get(DOC_ID).unwrap();
        doc.apply_update(&map_edit(1), None).unwrap();
        doc.apply_update(&map_edit(2), None).unwrap();
    }

    #[tokio::test]
    async fn an_update_in_flight_when_shutdown_starts_is_saved() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // An update whose body is still arriving when shutdown starts. Before the fix, the
        // doc's persistence worker made its final save right away and exited; the update was
        // then applied and acknowledged, and never saved (or the dirty notification to the
        // gone worker panicked). It must be acknowledged and saved, or refused.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        let body = map_edit(42);
        let (first, rest) = body.split_at(body.len() / 2);
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                format!(
                    "POST /d/{DOC_ID}/update HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(first).await.unwrap();
        // Let the server take the request in.
        tokio::time::sleep(Duration::from_millis(100)).await;

        token.cancel();
        // Give shutdown every chance to run ahead of the request.
        tokio::time::sleep(Duration::from_millis(300)).await;
        socket.write_all(rest).await.unwrap();

        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        tokio::time::timeout(Duration::from_secs(30), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();

        let stored = stored_keys(&store).await;
        if response.starts_with("HTTP/1.1 200") {
            assert!(stored.contains("42"), "acknowledged but not saved");
        } else {
            assert!(response.starts_with("HTTP/1.1 503"), "{response}");
        }
        // With the in-flight request allowed to finish, it is in fact acknowledged.
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    /// A stress version of the above: writers posting continuously through the shutdown.
    #[tokio::test]
    async fn edits_racing_shutdown_are_persisted_or_rejected() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/d/{DOC_ID}/update",
            listener.local_addr().unwrap()
        );
        let serving = tokio::spawn(server.serve(listener, false));

        // Writers that keep posting through the shutdown, each update from its own client.
        let next_id = Arc::new(AtomicU64::new(1));
        let writers: Vec<_> = (0..8)
            .map(|_| {
                let (url, next_id) = (url.clone(), next_id.clone());
                tokio::spawn(async move {
                    let http = reqwest::Client::new();
                    let mut outcomes = Vec::new();
                    loop {
                        let id = next_id.fetch_add(1, Ordering::SeqCst);
                        let status = http
                            .post(&url)
                            .body(map_edit(id))
                            .send()
                            .await
                            .map(|r| r.status().as_u16())
                            .ok();
                        outcomes.push((id, status));
                        if status != Some(200) {
                            return outcomes;
                        }
                    }
                })
            })
            .collect();

        tokio::time::sleep(Duration::from_millis(200)).await;
        token.cancel();
        tokio::time::timeout(Duration::from_secs(30), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();

        let mut acked = Vec::new();
        for writer in writers {
            let outcomes = tokio::time::timeout(Duration::from_secs(10), writer)
                .await
                .expect("a writer kept going after shutdown")
                .unwrap();
            for (id, status) in outcomes {
                match status {
                    Some(200) => acked.push(id),
                    // Refused at the write gate, or no connection: rejected, not acknowledged.
                    Some(503) | None => {}
                    Some(other) => panic!("unexpected status {other}"),
                }
            }
        }
        assert!(!acked.is_empty());

        let stored = stored_keys(&store).await;
        let lost: Vec<_> = acked
            .iter()
            .filter(|id| !stored.contains(&id.to_string()))
            .collect();
        assert!(lost.is_empty(), "acknowledged but not persisted: {lost:?}");
    }

    #[tokio::test]
    async fn a_slow_store_does_not_push_shutdown_past_its_budget() {
        let store = TestStore::default();
        store.slow.store(true, std::sync::atomic::Ordering::SeqCst);
        let token = CancellationToken::new();
        let budgets = ShutdownBudgets {
            connections: Duration::from_millis(200),
            total: Duration::from_millis(600),
            webhook: Duration::from_millis(100),
        };
        let server = server_with_store(&store, &token)
            .await
            .with_shutdown_budgets(budgets);
        // A pending edit, so the final save has something to write, and hangs on it.
        server
            .docs
            .get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(1), None)
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let serving = tokio::spawn(server.serve(listener, false));
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = std::time::Instant::now();
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();
        let took = started.elapsed();
        assert!(took >= budgets.total, "{took:?}");
        assert!(took < Duration::from_secs(3), "{took:?}");
    }

    #[tokio::test]
    async fn shutdown_saves_pending_edits_before_returning() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        server
            .docs
            .get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(7), None)
            .unwrap();
        // The checkpoint interval is an hour, so nothing has been saved yet.
        assert!(stored_keys(&store).await.is_empty());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let serving = tokio::spawn(server.serve(listener, false));
        token.cancel();
        serving.await.unwrap().unwrap();

        assert!(stored_keys(&store).await.contains("7"));
    }

    #[tokio::test]
    async fn an_http_server_that_already_finished_is_not_polled_again() {
        // The branch `serve` takes when the HTTP server finished its graceful shutdown before
        // `serve` saw the cancellation. It once polled the finished future again, which panics
        // (here: `Ready` polled after completion) and skipped the saves.
        use futures::FutureExt;

        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        server
            .docs
            .get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(5), None)
            .unwrap();

        let finished = std::future::ready(Ok(()));
        tokio::pin!(finished);
        let result = finished.as_mut().now_or_never().unwrap();
        token.cancel();
        server.finish_serving(Some(result), finished).await.unwrap();
        assert!(stored_keys(&store).await.contains("5"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shutdown_with_nothing_in_flight_still_saves() {
        // A stress version of the above through the real server: with no request in flight,
        // which branch `select!` takes in `serve` is a race, so run it many times.
        for round in 0..200 {
            let store = TestStore::default();
            let token = CancellationToken::new();
            let server = server_with_store(&store, &token).await;
            server
                .docs
                .get(DOC_ID)
                .unwrap()
                .apply_update(&map_edit(round), None)
                .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let serving = tokio::spawn(server.serve(listener, false));
            tokio::time::sleep(Duration::from_millis(5)).await;

            token.cancel();
            tokio::time::timeout(Duration::from_secs(10), serving)
                .await
                .expect("serve did not return")
                .expect("serve panicked")
                .unwrap();
            assert!(
                stored_keys(&store).await.contains(&round.to_string()),
                "round {round}: the pending edit was not saved"
            );
        }
    }

    #[tokio::test]
    async fn a_write_that_outlives_the_connection_budget_is_refused_not_lost() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // One request is stuck loading a doc from a slow store, so the connection stage runs
        // out of time. Another, for an already-loaded doc, is still receiving its body. Shutdown
        // must close the gate anyway: once the loaded doc has made its final save, the second
        // request may not be applied and acknowledged.
        let store = TestStore::default();
        *store.held_key.lock().unwrap() = Some("slow-doc/data.ysweet".to_string());
        let token = CancellationToken::new();
        let budgets = ShutdownBudgets {
            connections: Duration::from_millis(300),
            total: Duration::from_secs(5),
            webhook: Duration::from_secs(1),
        };
        let server = server_with_store(&store, &token)
            .await
            .with_shutdown_budgets(budgets);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // The slow load.
        let slow = tokio::spawn(async move {
            reqwest::Client::new()
                .post(format!("http://{addr}/d/slow-doc/update"))
                .body(map_edit(1))
                .send()
                .await
                .map(|r| r.status().as_u16())
        });
        store.held_get_entered.notified().await;

        // The request still receiving its body.
        let body = map_edit(2);
        let (first, rest) = body.split_at(body.len() / 2);
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        socket
            .write_all(
                format!(
                    "POST /d/{DOC_ID}/update HTTP/1.1\r\nHost: test\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        socket.write_all(first).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Shutdown runs out its connection budget, closes the gate and saves the loaded doc.
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();

        // Both requests now complete, after the final save. Neither may be acknowledged.
        socket.write_all(rest).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8_lossy(&response);
        assert!(response.starts_with("HTTP/1.1 503"), "{response}");

        store.held_get_release.add_permits(1);
        let slow = slow.await.unwrap();
        assert_eq!(slow.ok(), Some(503));

        *store.held_key.lock().unwrap() = None;
        assert!(!stored_keys(&store).await.contains("2"));
    }

    #[tokio::test]
    async fn a_write_still_applying_when_the_drain_times_out_is_not_acknowledged() {
        // Admitted before the gate closes, and still applying when the drain limit passes, so
        // the final saves start without it. Whatever it applies from then on may not be in
        // them: it must not be acknowledged. (The admission is held here the way a handler
        // holds it; a handler stuck on the doc lock would block a runtime thread.)
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token)
            .await
            .with_shutdown_budgets(ShutdownBudgets {
                connections: Duration::from_millis(300),
                total: Duration::from_secs(5),
                webhook: Duration::from_secs(1),
            });
        let (gate, docs) = (server.write_gate.clone(), server.docs.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // A write that applies while the gate is open is in time.
        let admitted = gate.enter().await.expect("the gate is open");
        docs.get(DOC_ID).unwrap().apply_update(&map_edit(1), None).unwrap();
        assert!(admitted.in_time());
        drop(admitted);

        let stuck = gate.enter().await.expect("the gate is open");
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();
        // The final saves are done; the stuck write applies now.
        docs.get(DOC_ID).unwrap().apply_update(&map_edit(7), None).unwrap();
        let stored = stored_keys(&store).await;
        assert!(stored.contains("1") && !stored.contains("7"), "{stored:?}");
        assert!(!stuck.in_time(), "acknowledged but not saved");
    }

    /// Posts `body` to `/d/{doc_id}/update` and returns the status, or `None` if the request
    /// failed.
    fn post_update(
        addr: std::net::SocketAddr,
        doc_id: &str,
        body: Vec<u8>,
    ) -> tokio::task::JoinHandle<Option<u16>> {
        let url = format!("http://{addr}/d/{doc_id}/update");
        tokio::spawn(async move {
            reqwest::Client::new()
                .post(url)
                .body(body)
                .send()
                .await
                .map(|r| r.status().as_u16())
                .ok()
        })
    }

    /// What GC does to a doc it finds without references, as `doc_gc_worker` does it.
    fn try_retire(docs: &DashMap<String, DocWithSyncKv>, doc_id: &str) -> bool {
        docs.get(doc_id).unwrap().retire_if_unused()
    }

    #[tokio::test]
    async fn gc_cannot_collect_a_doc_between_a_writers_load_and_its_admission() {
        // The writer has loaded its doc and is waiting for admission when GC looks at the doc,
        // and shutdown then starts. The writer must not need to load the doc again under
        // admission (which could finish after the final saves); its edit must be saved.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token)
            .await
            .with_shutdown_budgets(ShutdownBudgets {
                connections: Duration::from_millis(300),
                total: Duration::from_secs(5),
                webhook: Duration::from_secs(1),
            });
        let (gate, docs) = (server.write_gate.clone(), server.docs.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // Hold admission so the writer stops right after loading its doc.
        let holding_admission = gate.in_progress.write().await;
        let response = post_update(addr, "late-doc", map_edit(9));
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !docs.contains_key("late-doc") {
            assert!(
                std::time::Instant::now() < deadline,
                "the doc was never loaded"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;

        // GC finds the doc unreferenced in the map, but the writer holds it: no retirement.
        assert!(!try_retire(&docs, "late-doc"));
        // Any further load of the doc would hang.
        *store.held_key.lock().unwrap() = Some("late-doc/data.ysweet".to_string());

        drop(holding_admission);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // Admitted, the writer applied to the doc it holds: it did not go back to the store.
        assert_eq!(
            store.held_gets.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the doc was loaded again under admission"
        );
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();
        store.held_get_release.add_permits(1);

        assert_eq!(response.await.unwrap(), Some(200));
        *store.held_key.lock().unwrap() = None;
        assert!(stored_keys_of(&store, "late-doc").await.contains("9"));
    }

    #[tokio::test]
    async fn gc_cannot_retire_a_doc_an_http_write_is_applying_to() {
        // The handler has its doc and is about to apply when GC checks the doc. Upstream GC
        // retired it anyway (its map reference does not count), after which the doc ignored
        // the write's dirty mark and the acknowledged write was never saved.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let (gate, docs) = (server.write_gate.clone(), server.docs.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        let holding_admission = gate.in_progress.write().await;
        let response = post_update(addr, DOC_ID, map_edit(3));
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(!try_retire(&docs, DOC_ID));

        drop(holding_admission);
        assert_eq!(response.await.unwrap(), Some(200));
        token.cancel();
        serving.await.unwrap().unwrap();
        assert!(stored_keys(&store).await.contains("3"));
    }

    #[tokio::test]
    async fn a_write_to_a_retired_doc_waits_for_it_and_goes_to_a_fresh_one() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let docs = server.docs.clone();
        docs.get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(1), None)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // GC retires the doc...
        assert!(try_retire(&docs, DOC_ID));
        // ...and a write arriving now waits while the retired doc is still in the map...
        let response = post_update(addr, DOC_ID, map_edit(2));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!response.is_finished());

        // ...until GC has saved it and dropped it; then it goes to a fresh load.
        save_and_drop_retired(&docs, DOC_ID).await;
        assert_eq!(response.await.unwrap(), Some(200));
        token.cancel();
        serving.await.unwrap().unwrap();
        let stored = stored_keys(&store).await;
        assert!(stored.contains("1") && stored.contains("2"), "{stored:?}");
    }

    /// What GC does once it has retired a doc: save it the way every save is made, then drop
    /// it from the map.
    async fn save_and_drop_retired(docs: &DashMap<String, DocWithSyncKv>, doc_id: &str) {
        let sync_kv = docs.get(doc_id).unwrap().sync_kv();
        Server::compact_and_persist(&sync_kv, &tokio::sync::Mutex::new(()))
            .await
            .unwrap();
        docs.remove_if(doc_id, |_, doc| doc.sync_kv().is_shutdown());
    }

    /// Waits until `condition` holds, for up to 10 s.
    async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !condition() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting: {what}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn is_retired(docs: &DashMap<String, DocWithSyncKv>, doc_id: &str) -> bool {
        docs.get(doc_id)
            .is_some_and(|doc| doc.sync_kv().is_shutdown())
    }

    #[tokio::test]
    async fn gc_drops_a_doc_only_after_saving_it_and_a_later_write_reloads_it() {
        use std::sync::atomic::Ordering::SeqCst;

        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_checkpoints(&store, &token, Duration::from_millis(50)).await;
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // Every save of the doc is held until the test lets it through.
        store.hold_sets.store(true, SeqCst);
        assert_eq!(
            post_update(addr, DOC_ID, map_edit(1)).await.unwrap(),
            Some(200)
        );
        store.set_entered.notified().await;
        eventually("GC retires the doc", || is_retired(&docs, DOC_ID)).await;

        // While the save is held, the doc is not dropped and a writer cannot reload it.
        let response = post_update(addr, DOC_ID, map_edit(2));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(docs.contains_key(DOC_ID), "dropped before it was saved");
        assert!(
            !response.is_finished(),
            "the writer did not wait for the save"
        );
        assert!(!stored_keys(&store).await.contains("1"));

        // Once saved, GC drops it and the writer reloads it, with the saved edit.
        store.hold_sets.store(false, SeqCst);
        store.set_release.add_permits(100);
        assert_eq!(response.await.unwrap(), Some(200));
        token.cancel();
        serving.await.unwrap().unwrap();
        let stored = stored_keys(&store).await;
        assert!(stored.contains("1") && stored.contains("2"), "{stored:?}");
    }

    #[tokio::test]
    async fn gc_keeps_a_doc_it_could_not_save() {
        use std::sync::atomic::Ordering::SeqCst;

        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_checkpoints(&store, &token, Duration::from_millis(50)).await;
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // The store refuses every write; the acknowledged edit exists only in memory.
        store.fail_sets.store(true, SeqCst);
        assert_eq!(
            post_update(addr, DOC_ID, map_edit(1)).await.unwrap(),
            Some(200)
        );
        // Many GC rounds: each retires the doc, fails to save it, and must keep it.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(
            docs.contains_key(DOC_ID),
            "GC dropped a doc it could not save"
        );
        assert!(!stored_keys(&store).await.contains("1"));
        // It is still writable.
        assert_eq!(
            post_update(addr, DOC_ID, map_edit(2)).await.unwrap(),
            Some(200)
        );

        // The store recovers: the doc is saved (and then collected), with both edits.
        store.fail_sets.store(false, SeqCst);
        eventually("GC drops the doc once saved", || !docs.contains_key(DOC_ID)).await;
        let stored = stored_keys(&store).await;
        assert!(stored.contains("1") && stored.contains("2"), "{stored:?}");
        token.cancel();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_hung_save_makes_writers_fail_fast_and_shutdown_stays_bounded() {
        use std::sync::atomic::Ordering::SeqCst;

        let store = TestStore::default();
        let token = CancellationToken::new();
        let doc_wait = Duration::from_millis(500);
        let budgets = ShutdownBudgets {
            connections: Duration::from_millis(300),
            total: Duration::from_millis(800),
            webhook: Duration::from_millis(100),
        };
        let server = server_with_gc(&store, &token, Duration::from_millis(50), doc_wait)
            .await
            .with_shutdown_budgets(budgets);
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // Every store write now hangs, so GC's save of the retired doc never finishes. GC does
        // not abandon it (a sent write cannot be recalled), so the doc stays retired.
        store.slow.store(true, SeqCst);
        assert_eq!(
            post_update(addr, DOC_ID, map_edit(1)).await.unwrap(),
            Some(200)
        );
        eventually("GC retires the doc", || is_retired(&docs, DOC_ID)).await;

        // A writer is not stuck behind it: it gives up after `doc_wait`.
        let started = std::time::Instant::now();
        let status = tokio::time::timeout(
            Duration::from_secs(5),
            post_update(addr, DOC_ID, map_edit(2)),
        )
        .await
        .expect("the writer is stuck behind the hung save")
        .unwrap();
        assert_eq!(status, Some(503));
        assert!(started.elapsed() >= doc_wait);
        assert!(docs.contains_key(DOC_ID), "dropped without being saved");

        // Shutdown does not wait for the hung save past its budgets.
        let started = std::time::Instant::now();
        token.cancel();
        tokio::time::timeout(Duration::from_secs(10), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();
        assert!(started.elapsed() < budgets.total + Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_write_sent_by_gc_cannot_land_over_a_newer_save() {
        // GC sends the retired doc's snapshot, and the write is slow to land. It must not
        // give up on it and let the doc be written to and saved again meanwhile: the old write
        // would then land last and overwrite the newer state.
        let store = TestStore::default();
        let token = CancellationToken::new();
        // No GC worker of its own acts (an hour between checkpoints); the test runs one.
        let mut server = server_with_store(&store, &token).await;
        server.doc_wait = Duration::from_millis(500);
        let docs = server.docs.clone();
        docs.get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(1), None)
            .unwrap();

        store
            .detach_next_set
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let gc_token = CancellationToken::new();
        let gc = tokio::spawn(Server::doc_gc_worker(
            docs.clone(),
            DOC_ID.to_string(),
            Duration::from_millis(50),
            gc_token.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            Arc::default(),
        ));
        // GC has retired the doc and sent snapshot {1}, which has not landed.
        store.set_entered.notified().await;
        tokio::time::sleep(Duration::from_millis(500)).await;

        // A writer, and the persistence worker's next save.
        let acknowledged = match server.live_doc(DOC_ID).await {
            Ok((awareness, sync_kv)) => {
                apply_update_to(&awareness, &map_edit(2), None).unwrap();
                sync_kv.persist().await.unwrap();
                true
            }
            Err(AppError(status, _)) => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                false
            }
        };

        // The old write lands.
        store.set_release.add_permits(1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        gc_token.cancel();
        gc.await.unwrap();

        if acknowledged {
            assert!(
                stored_keys(&store).await.contains("2"),
                "an acknowledged edit was overwritten by an older save"
            );
        }
        assert!(stored_keys(&store).await.contains("1"));
    }

    #[tokio::test]
    async fn the_map_of_loads_is_emptied_after_concurrent_and_abandoned_loads() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = Arc::new(server_with_store(&store, &token).await);

        // Two concurrent loads of one doc.
        *store.held_key.lock().unwrap() = Some("a/data.ysweet".to_string());
        let loads: Vec<_> = (0..2)
            .map(|_| {
                let server = server.clone();
                tokio::spawn(async move { server.load_doc("a").await.unwrap() })
            })
            .collect();
        store.held_get_entered.notified().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        store.held_get_release.add_permits(1);
        for load in loads {
            load.await.unwrap();
        }
        assert!(
            server.loading.is_empty(),
            "left behind after concurrent loads"
        );

        // A load whose callers both stop waiting, while it waits on the store.
        *store.held_key.lock().unwrap() = Some("b/data.ysweet".to_string());
        let first = tokio::spawn({
            let server = server.clone();
            async move { server.load_doc("b").await }
        });
        store.held_get_entered.notified().await;
        let second = tokio::spawn({
            let server = server.clone();
            async move { server.load_doc("b").await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        first.abort();
        second.abort();
        let _ = first.await;
        let _ = second.await;

        // The load is still under way: it belongs to no caller. When the store answers, the
        // doc is there and the entry is gone.
        assert!(server.loading.contains_key("b"));
        assert!(!server.docs.contains_key("b"));
        store.held_get_release.add_permits(1);
        eventually("the abandoned load completes", || {
            server.docs.contains_key("b")
        })
        .await;
        eventually("its entry is removed", || server.loading.is_empty()).await;
        assert_eq!(
            store.held_gets.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "one read per doc"
        );
    }

    #[tokio::test]
    async fn a_failed_load_is_reported_to_every_waiter_and_can_be_retried() {
        /// A store whose reads fail while `failing` is set.
        struct FailingStore {
            inner: TestStore,
            failing: Arc<std::sync::atomic::AtomicBool>,
        }
        #[async_trait::async_trait]
        impl Store for FailingStore {
            async fn init(&self) -> y_sweet_core::store::Result<()> {
                Ok(())
            }
            async fn get(&self, key: &str) -> y_sweet_core::store::Result<Option<Vec<u8>>> {
                let result = self.inner.get(key).await;
                if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(y_sweet_core::store::StoreError::ConnectionError(
                        "test failure".to_string(),
                    ));
                }
                result
            }
            async fn set(&self, key: &str, value: Vec<u8>) -> y_sweet_core::store::Result<()> {
                self.inner.set(key, value).await
            }
            async fn remove(&self, key: &str) -> y_sweet_core::store::Result<()> {
                self.inner.remove(key).await
            }
            async fn exists(&self, key: &str) -> y_sweet_core::store::Result<bool> {
                self.inner.exists(key).await
            }
        }

        let inner = TestStore::default();
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        *inner.held_key.lock().unwrap() = Some("a/data.ysweet".to_string());
        let server = Arc::new(
            Server::new(
                Some(Box::new(FailingStore {
                    inner: inner.clone(),
                    failing: failing.clone(),
                })),
                Duration::from_secs(3600),
                None,
                None,
                CancellationToken::new(),
                true,
                None,
                false,
            )
            .await
            .unwrap(),
        );

        let loads: Vec<_> = (0..2)
            .map(|_| {
                let server = server.clone();
                tokio::spawn(async move { server.load_doc("a").await })
            })
            .collect();
        inner.held_get_entered.notified().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        inner.held_get_release.add_permits(1);
        for load in loads {
            let error = load.await.unwrap().expect_err("the load failed");
            assert!(format!("{error:#}").contains("test failure"), "{error:#}");
        }
        eventually("the failed load's entry is removed", || {
            server.loading.is_empty()
        })
        .await;
        assert!(!server.docs.contains_key("a"));

        // The next request starts a load of its own.
        failing.store(false, std::sync::atomic::Ordering::SeqCst);
        inner.held_get_release.add_permits(1);
        server.load_doc("a").await.unwrap();
        assert!(server.docs.contains_key("a"));
    }

    #[tokio::test]
    async fn a_doc_that_loads_slower_than_a_writer_waits_can_still_be_opened() {
        use std::sync::atomic::Ordering::SeqCst;

        // Reading the doc from the store takes several times longer than a writer waits.
        let doc_wait = Duration::from_millis(200);
        let load_time = Duration::from_millis(900);
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_gc(&store, &token, Duration::from_secs(3600), doc_wait).await;
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));
        store
            .get_delay_ms
            .store(load_time.as_millis() as u64, SeqCst);
        let reads_before = store.gets.load(SeqCst);

        // The first writer gives up, as it must.
        let started = std::time::Instant::now();
        assert_eq!(
            post_update(addr, "slow-doc", map_edit(1)).await.unwrap(),
            Some(503)
        );
        assert!(started.elapsed() < load_time);

        // Its load carries on without it, so retrying gets through once the load is done. If
        // each attempt started the load over, none ever would.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut attempt = 1;
        loop {
            attempt += 1;
            let status = post_update(addr, "slow-doc", map_edit(attempt))
                .await
                .unwrap();
            if status == Some(200) {
                break;
            }
            assert_eq!(status, Some(503));
            assert!(
                std::time::Instant::now() < deadline,
                "the doc could not be opened after {attempt} attempts"
            );
        }
        assert!(docs.contains_key("slow-doc"));
        assert_eq!(
            store.gets.load(SeqCst) - reads_before,
            1,
            "the doc was read from the store more than once"
        );

        token.cancel();
        serving.await.unwrap().unwrap();
        store.get_delay_ms.store(0, SeqCst);
        assert!(stored_keys_of(&store, "slow-doc")
            .await
            .contains(&attempt.to_string()));
    }

    #[tokio::test]
    async fn a_writer_waits_for_a_retired_doc_only_so_long() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        // No GC (an hour between checkpoints): nothing will drop or un-retire the doc.
        let mut server = server_with_store(&store, &token).await;
        server.doc_wait = Duration::from_millis(300);
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));
        assert!(try_retire(&docs, DOC_ID));

        // Bounded while the retired doc stays...
        let started = std::time::Instant::now();
        assert_eq!(
            post_update(addr, DOC_ID, map_edit(1)).await.unwrap(),
            Some(503)
        );
        assert!(started.elapsed() < Duration::from_secs(3));

        // ...and while its replacement load hangs, once GC dropped it.
        *store.held_key.lock().unwrap() = Some(format!("{DOC_ID}/data.ysweet"));
        docs.remove_if(DOC_ID, |_, doc| doc.sync_kv().is_shutdown());
        let started = std::time::Instant::now();
        assert_eq!(
            post_update(addr, DOC_ID, map_edit(2)).await.unwrap(),
            Some(503)
        );
        assert!(started.elapsed() < Duration::from_secs(3));

        // ...and by shutdown.
        let response = post_update(addr, DOC_ID, map_edit(3));
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
        let status = tokio::time::timeout(Duration::from_secs(2), response)
            .await
            .expect("the writer did not notice the shutdown")
            .unwrap();
        assert!(matches!(status, Some(503) | None), "{status:?}");
        serving.await.unwrap().unwrap();
        store.held_get_release.add_permits(10);
    }

    #[tokio::test]
    async fn concurrent_first_loads_of_a_doc_share_one_doc() {
        // Two writers load the same absent doc at once; the first load finishes first and its
        // writer has the doc. A second load must not then replace it: the first writer's edit
        // would go to a doc no longer saved.
        let store = TestStore::default();
        *store.held_key.lock().unwrap() = Some("race-doc/data.ysweet".to_string());
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let (gate, docs) = (server.write_gate.clone(), server.docs.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        let holding_admission = gate.in_progress.write().await;
        let first = post_update(addr, "race-doc", map_edit(1));
        store.held_get_entered.notified().await;
        let second = post_update(addr, "race-doc", map_edit(2));
        tokio::time::sleep(Duration::from_millis(100)).await;

        // The first load finishes; its writer takes the doc and waits for admission.
        store.held_get_release.add_permits(1);
        eventually("the first load completes", || docs.contains_key("race-doc")).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        // A second load, had one started, finishes now.
        store.held_get_release.add_permits(1);
        tokio::time::sleep(Duration::from_millis(100)).await;

        drop(holding_admission);
        assert_eq!(first.await.unwrap(), Some(200));
        assert_eq!(second.await.unwrap(), Some(200));
        token.cancel();
        serving.await.unwrap().unwrap();

        *store.held_key.lock().unwrap() = None;
        let stored = stored_keys_of(&store, "race-doc").await;
        assert!(stored.contains("1") && stored.contains("2"), "{stored:?}");
    }

    // --- Shutdown budget ----------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn the_default_budget_saves_many_dirty_docs_through_a_slow_store() {
        // A deploy while the store is slow: every save takes 30 s. (A paused clock: the test
        // does not really wait.) Upstream waited for these without limit; a 10 s cap on the
        // save stage abandoned all of them.
        let store = TestStore::default();
        store
            .set_delay_ms
            .store(30_000, std::sync::atomic::Ordering::SeqCst);
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let doc_ids: Vec<String> = (0..50).map(|i| format!("doc-{i}")).collect();
        for (i, doc_id) in doc_ids.iter().enumerate() {
            server.load_doc(doc_id).await.unwrap();
            server
                .docs
                .get(doc_id)
                .unwrap()
                .apply_update(&map_edit(i as u64 + 1), None)
                .unwrap();
        }

        let started = tokio::time::Instant::now();
        token.cancel();
        server.shut_down(None).await;
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(30), "{took:?}");
        assert!(took < DEFAULT_SHUTDOWN_TIMEOUT, "{took:?}");

        store
            .set_delay_ms
            .store(0, std::sync::atomic::Ordering::SeqCst);
        for (i, doc_id) in doc_ids.iter().enumerate() {
            assert!(
                stored_keys_of(&store, doc_id)
                    .await
                    .contains(&(i + 1).to_string()),
                "{doc_id} was not saved"
            );
            assert!(!server
                .docs
                .get(doc_id)
                .unwrap()
                .sync_kv()
                .has_unsaved_changes());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_final_save_that_fails_is_retried_while_budget_remains() {
        use std::sync::atomic::Ordering::SeqCst;

        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        server
            .docs
            .get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(1), None)
            .unwrap();

        // The store refuses writes for the first 20 s of the shutdown, then recovers.
        store.fail_sets.store(true, SeqCst);
        tokio::spawn({
            let store = store.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(20)).await;
                store.fail_sets.store(false, SeqCst);
            }
        });

        let started = tokio::time::Instant::now();
        token.cancel();
        server.shut_down(None).await;
        let took = started.elapsed();
        // It kept trying, with a backoff of at most 5 s, and stopped once saved.
        assert!(took >= Duration::from_secs(20), "{took:?}");
        assert!(took <= Duration::from_secs(26), "{took:?}");
        assert!(stored_keys(&store).await.contains("1"));
    }

    #[tokio::test(start_paused = true)]
    async fn the_webhook_flush_does_not_take_time_from_the_saves() {
        // Saves that need almost the whole budget still get it: the flush stage starts beside
        // them when only its own share is left, not instead of them.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token)
            .await
            .with_shutdown_budgets(ShutdownBudgets::with_total(Duration::from_secs(60)));
        server
            .docs
            .get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(1), None)
            .unwrap();
        store
            .set_delay_ms
            .store(58_000, std::sync::atomic::Ordering::SeqCst);

        token.cancel();
        server.shut_down(None).await;
        assert!(stored_keys(&store).await.contains("1"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_late_webhook_flush_ends_with_the_shutdown_deadline() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        let budgets = ShutdownBudgets {
            connections: Duration::from_secs(10),
            total: Duration::from_secs(12),
            webhook: Duration::from_secs(7),
        };
        let server = server_with_store(&store, &token)
            .await
            .with_shutdown_budgets(budgets);
        // A write that never finishes applying keeps the connection stage busy to its limit,
        // so the flush starts with 2 s left; and the webhook never finishes flushing.
        let gate = server.write_gate.clone();
        let _applying = gate.enter().await.unwrap();
        server.webhook_tracker.spawn(std::future::pending::<()>());

        let started = tokio::time::Instant::now();
        token.cancel();
        server.shut_down(None).await;
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(10), "{took:?}");
        assert!(took <= budgets.total, "{took:?}");
    }

    // --- Websockets through shutdown, GC and the write gate -----------------------------------

    type TestSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    async fn ws_connect(
        addr: std::net::SocketAddr,
        doc_id: &str,
    ) -> std::result::Result<TestSocket, tokio_tungstenite::tungstenite::Error> {
        tokio_tungstenite::connect_async(format!("ws://{addr}/d/{doc_id}/ws/{doc_id}"))
            .await
            .map(|(socket, _)| socket)
    }

    /// The websocket message that carries `update`.
    fn ws_update(update: Vec<u8>) -> tokio_tungstenite::tungstenite::Message {
        use y_sweet_core::sync::{Message as SyncProtocolMessage, SyncMessage};
        use yrs::updates::encoder::Encode;
        tokio_tungstenite::tungstenite::Message::Binary(
            SyncProtocolMessage::Sync(SyncMessage::Update(update)).encode_v1(),
        )
    }

    /// The keys of map `m` in the doc as the server holds it in memory.
    fn memory_keys(
        docs: &DashMap<String, DocWithSyncKv>,
        doc_id: &str,
    ) -> std::collections::HashSet<String> {
        use yrs::{Map, ReadTxn, Transact};
        let awareness = docs.get(doc_id).unwrap().awareness();
        let awareness = awareness.read().unwrap();
        let txn = awareness.doc().transact();
        match txn.get_map("m") {
            Some(map) => map.keys(&txn).map(str::to_string).collect(),
            None => Default::default(),
        }
    }

    #[tokio::test]
    async fn websocket_edits_racing_shutdown_are_saved_or_not_applied() {
        use std::sync::atomic::{AtomicU64, Ordering};

        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // Clients that keep sending edits until the server closes their socket.
        let next_id = Arc::new(AtomicU64::new(1));
        let (connected_tx, mut connected) = tokio::sync::mpsc::channel(6);
        let clients: Vec<_> = (0..6)
            .map(|_| {
                let (next_id, connected_tx) = (next_id.clone(), connected_tx.clone());
                tokio::spawn(async move {
                    let mut socket = ws_connect(addr, DOC_ID).await.unwrap();
                    connected_tx.send(()).await.unwrap();
                    loop {
                        let id = next_id.fetch_add(1, Ordering::SeqCst);
                        if socket.send(ws_update(map_edit(id))).await.is_err() {
                            return;
                        }
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();

        // Shutdown starts only once every client is connected and edits are landing, however
        // slow the machine.
        for _ in 0..6 {
            tokio::time::timeout(Duration::from_secs(30), connected.recv())
                .await
                .expect("a client never connected")
                .unwrap();
        }
        eventually("the first edit is applied", || {
            !memory_keys(&docs, DOC_ID).is_empty()
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        token.cancel();
        tokio::time::timeout(Duration::from_secs(30), serving)
            .await
            .expect("serve did not return")
            .unwrap()
            .unwrap();
        for client in clients {
            tokio::time::timeout(Duration::from_secs(10), client)
                .await
                .expect("a client's socket was never closed")
                .unwrap();
        }

        // A websocket edit has no acknowledgement to check, so the invariant is on the doc:
        // nothing was applied to it that the store does not have.
        let applied = memory_keys(&docs, DOC_ID);
        assert!(!applied.is_empty());
        assert_eq!(applied, stored_keys(&store).await);
    }

    #[tokio::test]
    async fn a_websocket_message_after_the_gate_closed_is_not_applied() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let (gate, docs) = (server.write_gate.clone(), server.docs.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        let mut socket = ws_connect(addr, DOC_ID).await.unwrap();
        socket.send(ws_update(map_edit(1))).await.unwrap();
        eventually("the first edit is applied", || {
            memory_keys(&docs, DOC_ID).contains("1")
        })
        .await;

        // The gate closes, as in shutdown after its connection stage, with the socket open.
        gate.close();
        socket.send(ws_update(map_edit(2))).await.unwrap();
        // The server drops the connection rather than apply the message.
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = socket.next().await {
                if message.is_close() {
                    break;
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "the connection stayed open");
        assert!(!memory_keys(&docs, DOC_ID).contains("2"));

        token.cancel();
        serving.await.unwrap().unwrap();
        let stored = stored_keys(&store).await;
        assert!(stored.contains("1") && !stored.contains("2"), "{stored:?}");
    }

    #[tokio::test]
    async fn gc_does_not_retire_a_doc_with_an_open_websocket() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_checkpoints(&store, &token, Duration::from_millis(50)).await;
        let docs = server.docs.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // Many GC rounds pass with the socket open: the doc stays, and stays writable.
        let mut socket = ws_connect(addr, DOC_ID).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(docs.contains_key(DOC_ID) && !is_retired(&docs, DOC_ID));
        assert!(!try_retire(&docs, DOC_ID));
        socket.send(ws_update(map_edit(1))).await.unwrap();
        eventually("the edit is applied", || {
            docs.get(DOC_ID).is_some() && memory_keys(&docs, DOC_ID).contains("1")
        })
        .await;

        // Once it closes, GC saves the doc and drops it.
        socket.close(None).await.unwrap();
        drop(socket);
        eventually("GC drops the doc", || !docs.contains_key(DOC_ID)).await;
        assert!(stored_keys(&store).await.contains("1"));
        token.cancel();
        serving.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_websocket_connecting_to_a_retiring_doc_waits_for_a_fresh_one() {
        let store = TestStore::default();
        let token = CancellationToken::new();
        let mut server = server_with_store(&store, &token).await;
        server.doc_wait = Duration::from_secs(2);
        let docs = server.docs.clone();
        docs.get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(1), None)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let serving = tokio::spawn(server.serve(listener, false));

        // GC has retired the doc and is saving it: the connection is not established on it.
        assert!(try_retire(&docs, DOC_ID));
        let connecting = tokio::spawn(async move { ws_connect(addr, DOC_ID).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!connecting.is_finished());

        // Saved and dropped: the connection gets a fresh load, with what was saved.
        save_and_drop_retired(&docs, DOC_ID).await;
        let mut socket = connecting.await.unwrap().unwrap();
        socket.send(ws_update(map_edit(2))).await.unwrap();
        eventually("the edit is applied to the fresh doc", || {
            docs.get(DOC_ID).is_some() && memory_keys(&docs, DOC_ID).contains("2")
        })
        .await;
        assert!(memory_keys(&docs, DOC_ID).contains("1"));

        // A doc that stays retired refuses the connection after the bounded wait.
        socket.close(None).await.unwrap();
        drop(socket);
        eventually("the connection is gone", || try_retire(&docs, DOC_ID)).await;
        let refused = ws_connect(addr, DOC_ID).await;
        match refused {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE)
            }
            other => panic!("expected a 503, got {other:?}"),
        }

        token.cancel();
        serving.await.unwrap().unwrap();
    }

    // --- Compaction on every save path --------------------------------------------------------

    /// How many updates wait un-merged in the doc's log, in memory.
    fn pending_log_len(docs: &DashMap<String, DocWithSyncKv>, doc_id: &str) -> usize {
        use yrs_kvstore::{
            keys::{key_oid, key_update},
            KVStore,
        };
        let sync_kv = docs.get(doc_id).unwrap().sync_kv();
        let oid_key: Vec<u8> = key_oid(DOC_NAME.as_bytes()).into();
        let Some(oid) = sync_kv.get(&oid_key).unwrap() else {
            return 0;
        };
        let oid = u32::from_be_bytes(oid.as_slice().try_into().unwrap());
        let from: Vec<u8> = key_update(oid, 0).into();
        let to: Vec<u8> = key_update(oid, u32::MAX).into();
        sync_kv.iter_range(&from, &to).unwrap().count()
    }

    #[tokio::test]
    async fn every_save_path_compacts_the_update_log() {
        // The final save at shutdown.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let docs = server.docs.clone();
        for id in 1..=3 {
            docs.get(DOC_ID)
                .unwrap()
                .apply_update(&map_edit(id), None)
                .unwrap();
        }
        assert_eq!(pending_log_len(&docs, DOC_ID), 3);
        token.cancel();
        server.shut_down(None).await;
        assert_eq!(pending_log_len(&docs, DOC_ID), 0);
        assert_eq!(stored_keys(&store).await.len(), 3);

        // The periodic checkpoint.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_checkpoints(&store, &token, Duration::from_millis(50)).await;
        let docs = server.docs.clone();
        // Held, so GC leaves the doc alone.
        let (held, sync_kv) = server.live_doc(DOC_ID).await.unwrap();
        apply_update_to(&held, &map_edit(1), None).unwrap();
        eventually("the checkpoint saves and compacts", || {
            !sync_kv.has_unsaved_changes() && pending_log_len(&docs, DOC_ID) == 0
        })
        .await;
        assert!(stored_keys(&store).await.contains("1"));
        drop(held);
        token.cancel();
        server.shut_down(None).await;

        // GC's save of the doc it retires, with nothing else saving the doc: the server's own
        // workers checkpoint once an hour, so the doc's persistence worker stays throttled and
        // the only save is the one made by the GC worker run here.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let docs = server.docs.clone();
        for id in 1..=2 {
            docs.get(DOC_ID)
                .unwrap()
                .apply_update(&map_edit(id), None)
                .unwrap();
        }
        assert_eq!(pending_log_len(&docs, DOC_ID), 2);
        assert!(!store.data.contains_key(&format!("{DOC_ID}/data.ysweet")));

        let gc = tokio::spawn(Server::doc_gc_worker(
            docs.clone(),
            DOC_ID.to_string(),
            Duration::from_millis(50),
            CancellationToken::new(),
            Arc::new(tokio::sync::Mutex::new(())),
            Arc::default(),
        ));
        tokio::time::timeout(Duration::from_secs(10), gc)
            .await
            .expect("GC never dropped the doc")
            .unwrap();
        assert!(!docs.contains_key(DOC_ID));

        // What GC wrote holds both edits, merged: no pending updates in the stored map.
        assert_eq!(stored_keys(&store).await.len(), 2);
        let stored: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = bincode_stored(&store);
        let oid_key: Vec<u8> = yrs_kvstore::keys::key_oid(DOC_NAME.as_bytes()).into();
        let oid = u32::from_be_bytes(stored[&oid_key].as_slice().try_into().unwrap());
        let from: Vec<u8> = yrs_kvstore::keys::key_update(oid, 0).into();
        let to: Vec<u8> = yrs_kvstore::keys::key_update(oid, u32::MAX).into();
        assert_eq!(
            stored.range(from..to).count(),
            0,
            "GC saved the doc without merging its update log"
        );
    }

    #[tokio::test]
    async fn a_dropped_docs_worker_does_not_save_over_its_successor() {
        // GC saved and dropped a doc; a fresh load of it then took newer edits and saved them.
        // The dropped copy's worker, stopping, must not write its older state on top.
        let store = TestStore::default();
        let token = CancellationToken::new();
        let server = server_with_store(&store, &token).await;
        let docs = server.docs.clone();
        docs.get(DOC_ID)
            .unwrap()
            .apply_update(&map_edit(1), None)
            .unwrap();
        let old = docs.get(DOC_ID).unwrap().sync_kv();

        let (send, recv) = channel(1);
        let worker_token = CancellationToken::new();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker = tokio::spawn(Server::doc_persistence_worker(
            recv,
            old.clone(),
            Duration::from_secs(3600),
            DOC_ID.to_string(),
            worker_token.clone(),
            Arc::new(tokio::sync::Mutex::new(())),
            dropped.clone(),
        ));

        // GC: retire, save (here without merging the log, as when the merge failed), drop.
        assert!(try_retire(&docs, DOC_ID));
        old.persist().await.unwrap();
        docs.remove_if(DOC_ID, |_, doc| doc.sync_kv().is_shutdown());

        // The successor takes an edit and saves it.
        let (awareness, sync_kv) = server.live_doc(DOC_ID).await.unwrap();
        apply_update_to(&awareness, &map_edit(2), None).unwrap();
        Server::compact_and_persist(&sync_kv, &tokio::sync::Mutex::new(()))
            .await
            .unwrap();

        // Now the dropped copy's worker is stopped, as GC stops it.
        dropped.store(true, std::sync::atomic::Ordering::SeqCst);
        worker_token.cancel();
        worker.await.unwrap();
        drop(send);

        let stored = stored_keys(&store).await;
        assert!(stored.contains("1") && stored.contains("2"), "{stored:?}");
    }

    /// The doc's kv map as the store holds it.
    fn bincode_stored(store: &TestStore) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
        let snapshot = store
            .data
            .get(&format!("{DOC_ID}/data.ysweet"))
            .unwrap()
            .clone();
        bincode::deserialize(&snapshot).unwrap()
    }
}

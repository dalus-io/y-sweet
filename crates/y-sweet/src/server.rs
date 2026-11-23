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
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::mpsc::{channel, Receiver},
    task::JoinHandle,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{span, Instrument, Level};
use url::Url;
use y_sweet_core::{
    api_types::{
        validate_doc_name, AuthDocRequest, Authorization, ClientToken, DocCreationRequest,
        NewDocResponse,
    },
    auth::{Authenticator, ExpirationTimeEpochMillis, DEFAULT_EXPIRATION_SECONDS},
    doc_connection::{DocConnection, DOC_NAME},
    doc_sync::DocWithSyncKv,
    store::Store,
    sync::awareness::Awareness,
    sync_kv::SyncKv,
};

const PLANE_VERIFIED_USER_DATA_HEADER: &str = "x-verified-user-data";

// Every 20 seconds, we send a ping to the client.
const PING_EVERY: Duration = Duration::from_secs(20);
// If we haven't received a pong in the last 40 seconds, we close the connection.
// All modern browsers will respond to websocket pings with a pong message.
const PONG_TIMEOUT: Duration = Duration::from_secs(40);

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

/// A request's or an unload's place in a document's lock. The lock table has an entry for a
/// document only while someone holds or waits on its lock; dropping this releases the lock and
/// removes the entry if nobody else holds or waits on it.
struct DocLock {
    doc_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    doc_id: String,
    lock: Option<Arc<tokio::sync::Mutex<()>>>,
    guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl DocLock {
    fn new(doc_locks: &Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>, doc_id: &str) -> Self {
        let lock = doc_locks.entry(doc_id.to_string()).or_default().clone();
        Self {
            doc_locks: doc_locks.clone(),
            doc_id: doc_id.to_string(),
            lock: Some(lock),
            guard: None,
        }
    }

    /// Waits for the lock. No table guard is held meanwhile, only this `DocLock`'s own clone.
    async fn lock(&mut self) {
        if let Some(lock) = &self.lock {
            self.guard = Some(lock.clone().lock_owned().await);
        }
    }
}

impl Drop for DocLock {
    fn drop(&mut self) {
        self.guard = None;
        // Everyone drops their clone while holding the table entry, so whoever leaves last sees
        // only the table's clone and its own, and removes the entry.
        let lock = self.lock.take();
        if let Entry::Occupied(entry) = self.doc_locks.entry(self.doc_id.clone()) {
            let last = Arc::strong_count(entry.get()) == 2;
            drop(lock);
            if last {
                entry.remove();
            }
        }
    }
}

pub struct Server {
    docs: Arc<DashMap<String, DocWithSyncKv>>,
    /// One lock per document id, held while that document is loaded into memory or unloaded
    /// from it, so that a document never has two copies in memory at once.
    doc_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// How long a request waits for another load or unload of the same document before it fails.
    doc_lock_wait: Duration,
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
}

impl Server {
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
            doc_locks: Arc::new(DashMap::new()),
            doc_lock_wait: Duration::from_secs(30),
            checkpoint_freq,
            authenticator,
            url_prefix,
            cancellation_token,
            doc_gc,
            max_body_size,
            skip_gc,
        })
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

    /// Loads a document from the store into memory and starts its save and unload tasks.
    ///
    /// The caller makes sure no other copy of `doc_id` can be loaded at the same time:
    /// `get_or_create_doc` calls this under the document's lock, and `create_doc` and the
    /// single-document start call it for an id that no request can know yet.
    pub async fn load_doc(&self, doc_id: &str) -> Result<()> {
        let (send, recv) = channel(1024);

        let dwskv = DocWithSyncKv::new(
            doc_id,
            self.store.clone(),
            move || {
                send.try_send(()).unwrap();
            },
            self.skip_gc,
        )
        .await?;

        dwskv
            .sync_kv()
            .persist()
            .await
            .map_err(|e| anyhow!("Error persisting: {:?}", e))?;

        {
            let sync_kv = dwskv.sync_kv();
            let checkpoint_freq = self.checkpoint_freq;
            let doc_id = doc_id.to_string();
            let cancellation_token = self.cancellation_token.clone();

            // Spawn a task to save the document to the store when it changes.
            let save_loop = self.doc_worker_tracker.spawn(
                Self::doc_persistence_worker(
                    recv,
                    sync_kv,
                    checkpoint_freq,
                    doc_id.clone(),
                    cancellation_token.clone(),
                )
                .instrument(span!(Level::INFO, "save_loop", doc_id=?doc_id)),
            );

            if self.doc_gc {
                self.doc_worker_tracker.spawn(
                    Self::doc_gc_worker(
                        self.docs.clone(),
                        self.doc_locks.clone(),
                        doc_id.clone(),
                        checkpoint_freq,
                        save_loop,
                        cancellation_token,
                    )
                    .instrument(span!(Level::INFO, "gc_loop", doc_id=?doc_id)),
                );
            }
        }

        self.docs.insert(doc_id.to_string(), dwskv);
        Ok(())
    }

    async fn doc_gc_worker(
        docs: Arc<DashMap<String, DocWithSyncKv>>,
        doc_locks: Arc<DashMap<String, Arc<tokio::sync::Mutex<()>>>>,
        doc_id: String,
        checkpoint_freq: Duration,
        mut save_loop: JoinHandle<()>,
        cancellation_token: CancellationToken,
    ) {
        let mut checkpoints_without_refs = 0;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(checkpoint_freq) => {
                    if let Some(doc) = docs.get(&doc_id) {
                        let awareness = Arc::downgrade(&doc.awareness());
                        if awareness.strong_count() > 1 {
                            checkpoints_without_refs = 0;
                            tracing::debug!("doc is still alive - it has {} references", awareness.strong_count());
                        } else {
                            checkpoints_without_refs += 1;
                            tracing::info!("doc has only one reference, candidate for GC. checkpoints_without_refs: {}", checkpoints_without_refs);
                        }
                    } else {
                        break;
                    }

                    if checkpoints_without_refs >= 2 {
                        // Under the document's lock, no request can load a second copy while
                        // this one leaves memory and writes its last save.
                        let mut lock = DocLock::new(&doc_locks, &doc_id);
                        lock.lock().await;

                        // Checked again as part of the removal: a request takes its handle under
                        // the table's read lock, so it either holds the doc now (and the doc
                        // stays) or finds it gone and loads it again after this unload.
                        let Some((_, doc)) = docs.remove_if(&doc_id, |_, doc| {
                            let awareness = Arc::downgrade(&doc.awareness());
                            awareness.strong_count() <= 1
                        }) else {
                            checkpoints_without_refs = 0;
                            tracing::info!("doc was opened again before unloading, keeping it");
                            continue;
                        };

                        tracing::info!("GCing doc");
                        doc.sync_kv().shutdown();
                        drop(doc);
                        // A new copy reads the store, so it must not load before this last save.
                        if let Err(e) = (&mut save_loop).await {
                            tracing::error!(?e, "Save loop failed while unloading.");
                        }
                        break;
                    }
                }
                _ = cancellation_token.cancelled() => {
                    break;
                }
            };
        }
        tracing::info!("Exiting gc_loop");
    }

    async fn doc_persistence_worker(
        mut recv: Receiver<()>,
        sync_kv: Arc<SyncKv>,
        checkpoint_freq: Duration,
        doc_id: String,
        cancellation_token: CancellationToken,
    ) {
        let mut last_save = std::time::Instant::now();

        loop {
            let mut is_done = tokio::select! {
                v = recv.recv() => v.is_none(),
                _ = cancellation_token.cancelled() => true,
                _ = tokio::time::sleep(checkpoint_freq) => {
                    sync_kv.is_shutdown()
                }
            };
            // An unloaded doc gets its last save right away, with no throttle wait: a new copy of
            // the doc waits for that save before it reads the store.
            is_done |= sync_kv.is_shutdown();

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
                            if sync_kv.is_shutdown() {
                                is_done = true;
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
            tracing::info!("Compacting.");
            let kv = sync_kv.clone();
            match tokio::task::spawn_blocking(move || kv.compact(DOC_NAME)).await {
                Ok(Ok(())) => tracing::info!("Done compacting."),
                Ok(Err(e)) => tracing::error!(?e, "Error compacting."),
                Err(e) => tracing::error!(?e, "Compaction task failed."),
            }
            tracing::info!("Persisting.");
            if let Err(e) = sync_kv.persist().await {
                tracing::error!(?e, "Error persisting.");
            } else {
                tracing::info!("Done persisting.");
            }
            last_save = std::time::Instant::now();

            if is_done {
                break;
            }
        }
        tracing::info!("Terminating loop for {}", doc_id);
    }

    pub async fn get_or_create_doc(
        &self,
        doc_id: &str,
    ) -> Result<MappedRef<String, DocWithSyncKv, DocWithSyncKv>> {
        if let Some(doc) = self.docs.get(doc_id) {
            return Ok(doc.map(|d| d));
        }

        // Not in memory. Load it under the document's lock, so requests that arrive together
        // load it once and share that copy, and a load waits for an unload of the same doc to
        // finish its last save.
        let mut lock = DocLock::new(&self.doc_locks, doc_id);
        if tokio::time::timeout(self.doc_lock_wait, lock.lock())
            .await
            .is_err()
        {
            tracing::warn!(
                doc_id=?doc_id,
                wait=?self.doc_lock_wait,
                "Timed out waiting for a document that is still loading or saving"
            );
            return Err(anyhow!(
                "Timed out after {:?} waiting for this document to finish loading or saving",
                self.doc_lock_wait
            ));
        }
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

        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(async move { token.cancelled().await })
            .await?;

        self.doc_worker_tracker.close();
        self.doc_worker_tracker.wait().await;

        Ok(())
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

    fn verify_doc_token(&self, token: Option<&str>, doc: &str) -> Result<Authorization, AppError> {
        if let Some(authenticator) = &self.authenticator {
            if let Some(token) = token {
                let authorization = authenticator
                    .verify_doc_token(token, doc, current_time_epoch_millis())
                    .map_err(|e| (StatusCode::UNAUTHORIZED, e))?;
                Ok(authorization)
            } else {
                Err((StatusCode::UNAUTHORIZED, anyhow!("No token provided.")))?
            }
        } else {
            Ok(Authorization::Full)
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
    tracing::debug!("update: {:?}", update);
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
    let authorization = server_state.verify_doc_token(token.as_deref(), &doc_id)?;
    update_doc_inner(doc_id, server_state, authorization, body).await
}

async fn update_doc_inner(
    doc_id: String,
    server_state: Arc<Server>,
    authorization: Authorization,
    body: Bytes,
) -> Result<Response, AppError> {
    if !matches!(authorization, Authorization::Full) {
        return Err(AppError(StatusCode::FORBIDDEN, anyhow!("Unauthorized.")));
    }

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if let Err(err) = dwskv.apply_update(&body) {
        tracing::error!(?err, "Failed to apply update");
        return Err(AppError(StatusCode::INTERNAL_SERVER_ERROR, err));
    }

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
    update_doc_inner(doc_id, server_state, authorization, body).await
}

async fn handle_socket_upgrade(
    ws: WebSocketUpgrade,
    Path(doc_id): Path<String>,
    authorization: Authorization,
    State(server_state): State<Arc<Server>>,
) -> Result<Response, AppError> {
    if !matches!(authorization, Authorization::Full) && !server_state.docs.contains_key(&doc_id) {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            anyhow!("Doc {} not found", doc_id),
        ));
    }

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let awareness = dwskv.awareness();
    let cancellation_token = server_state.cancellation_token.clone();

    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, awareness, authorization, cancellation_token)
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
    let authorization = server_state.verify_doc_token(params.token.as_deref(), &doc_id)?;
    handle_socket_upgrade(ws, Path(doc_id), authorization, State(server_state)).await
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
    let authorization = server_state.verify_doc_token(params.token.as_deref(), &doc_id)?;
    handle_socket_upgrade(ws, Path(doc_id), authorization, State(server_state)).await
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
    handle_socket_upgrade(ws, Path(single_doc_id), authorization, State(server_state)).await
}

async fn handle_socket(
    socket: WebSocket,
    awareness: Arc<RwLock<Awareness>>,
    authorization: Authorization,
    cancellation_token: CancellationToken,
) {
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

    let connection = DocConnection::new(awareness, authorization, move |bytes| {
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

                if let Err(e) = connection.send(&msg).await {
                    tracing::warn!(?e, "Error handling message");
                }
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

async fn auth_doc(
    auth_header: Option<TypedHeader<headers::Authorization<headers::authorization::Bearer>>>,
    TypedHeader(host): TypedHeader<headers::Host>,
    State(server_state): State<Arc<Server>>,
    Path(doc_id): Path<String>,
    body: Option<Json<AuthDocRequest>>,
) -> Result<Json<ClientToken>, AppError> {
    server_state.check_auth(auth_header)?;

    let Json(AuthDocRequest {
        authorization,
        valid_for_seconds,
        ..
    }) = body.unwrap_or_default();

    if !server_state.doc_exists(&doc_id).await {
        Err((StatusCode::NOT_FOUND, anyhow!("Doc {} not found", doc_id)))?;
    }

    let valid_for_seconds = valid_for_seconds.unwrap_or(DEFAULT_EXPIRATION_SECONDS);
    let expiration_time =
        ExpirationTimeEpochMillis(current_time_epoch_millis() + valid_for_seconds * 1000);

    let token = if let Some(auth) = &server_state.authenticator {
        let token = auth.gen_doc_token(&doc_id, authorization, expiration_time);
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
            Some(Json(AuthDocRequest {
                authorization: Authorization::Full,
                user_id: None,
                valid_for_seconds: None,
            })),
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
            None,
        )
        .await
        .unwrap();

        let expected_url = format!("wss://foo.bar/d/{doc_id}/ws");
        assert_eq!(token.url, expected_url);
        assert_eq!(token.doc_id, doc_id);
        assert!(token.token.is_none());
    }

    /// In-memory store whose reads and writes can be held back, so a test can fix the order
    /// in which loads, saves and unloads meet.
    #[derive(Clone)]
    struct HeldStore {
        data: Arc<DashMap<String, Vec<u8>>>,
        reads: Arc<std::sync::atomic::AtomicUsize>,
        read_gate: Arc<tokio::sync::Semaphore>,
        write_gate: Arc<tokio::sync::Semaphore>,
    }

    impl HeldStore {
        fn new(reads_open: bool, writes_open: bool) -> Self {
            let gate = |open: bool| {
                Arc::new(tokio::sync::Semaphore::new(if open {
                    tokio::sync::Semaphore::MAX_PERMITS
                } else {
                    0
                }))
            };
            Self {
                data: Default::default(),
                reads: Default::default(),
                read_gate: gate(reads_open),
                write_gate: gate(writes_open),
            }
        }

        fn open_reads(&self) {
            self.read_gate.add_permits(1 << 20);
        }

        fn open_writes(&self) {
            self.write_gate.add_permits(1 << 20);
        }

        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl Store for HeldStore {
        async fn init(&self) -> y_sweet_core::store::Result<()> {
            Ok(())
        }

        async fn get(&self, key: &str) -> y_sweet_core::store::Result<Option<Vec<u8>>> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _open = self.read_gate.acquire().await.unwrap();
            let value = self.data.get(key).map(|v| v.clone());
            Ok(value)
        }

        async fn set(&self, key: &str, value: Vec<u8>) -> y_sweet_core::store::Result<()> {
            let _open = self.write_gate.acquire().await.unwrap();
            self.data.insert(key.to_owned(), value);
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

    async fn server_on(store: &HeldStore, checkpoint_freq: Duration) -> Server {
        Server::new(
            Some(Box::new(store.clone())),
            checkpoint_freq,
            None,
            None,
            CancellationToken::new(),
            true,
            None,
            false,
        )
        .await
        .unwrap()
    }

    /// Stops the server the way a shutdown does and waits for every document's final save.
    async fn stop(server: &Server) {
        server.cancellation_token.cancel();
        server.doc_worker_tracker.close();
        server.doc_worker_tracker.wait().await;
    }

    async fn wait_until(done: impl Fn() -> bool, what: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(tokio::time::Instant::now() < deadline, "never {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn push_item(awareness: &Arc<RwLock<Awareness>>, item: &str) {
        use yrs::{Array, Transact};
        let guard = awareness.write().unwrap();
        let list = guard.doc.get_or_insert_array("list");
        let mut txn = guard.doc.transact_mut();
        list.push_back(&mut txn, item);
    }

    fn items(awareness: &Arc<RwLock<Awareness>>) -> Vec<String> {
        use yrs::{Array, Transact};
        let guard = awareness.read().unwrap();
        let list = guard.doc.get_or_insert_array("list");
        let txn = guard.doc.transact();
        list.iter(&txn).map(|v| v.to_string(&txn)).collect()
    }

    async fn saved_items(store: &HeldStore) -> Vec<String> {
        let server = server_on(store, Duration::from_secs(60)).await;
        let items = items(&server.get_or_create_doc("doc").await.unwrap().awareness());
        stop(&server).await;
        items
    }

    #[tokio::test]
    async fn concurrent_requests_for_an_unloaded_doc_share_one_copy() {
        let store = HeldStore::new(false, true);
        let server = server_on(&store, Duration::from_secs(60)).await;

        let requests =
            (0..8).map(|_| async { server.get_or_create_doc("doc").await.unwrap().awareness() });
        let mut requests = Box::pin(futures::future::join_all(requests));
        // Every request is now waiting, either on the store read or behind the one load.
        assert!(futures::poll!(&mut requests).is_pending());
        store.open_reads();
        let copies = requests.await;

        assert_eq!(
            store.reads(),
            1,
            "the document was read from the store more than once"
        );
        assert!(copies.iter().all(|c| Arc::ptr_eq(c, &copies[0])));
    }

    #[tokio::test]
    async fn edits_through_concurrent_requests_are_all_saved() {
        let store = HeldStore::new(false, true);
        let server = server_on(&store, Duration::from_secs(60)).await;

        let requests =
            (0..2).map(|_| async { server.get_or_create_doc("doc").await.unwrap().awareness() });
        let mut requests = Box::pin(futures::future::join_all(requests));
        assert!(futures::poll!(&mut requests).is_pending());
        store.open_reads();
        let copies = requests.await;

        push_item(&copies[0], "first");
        push_item(&copies[1], "second");
        stop(&server).await;

        assert_eq!(saved_items(&store).await, vec!["first", "second"]);
    }

    #[tokio::test]
    async fn reload_during_unload_waits_for_the_last_save() {
        let store = HeldStore::new(true, false);
        let server = server_on(&store, Duration::from_millis(20)).await;

        push_item(
            &server.get_or_create_doc("doc").await.unwrap().awareness(),
            "before unload",
        );
        // The save of that edit is held in the store while the idle doc is unloaded.
        wait_until(|| !server.docs.contains_key("doc"), "unloaded").await;

        let (reloaded, ()) = tokio::join!(
            async { server.get_or_create_doc("doc").await.unwrap().awareness() },
            async {
                // A reload that does not wait for the last save has read the store by now.
                tokio::time::sleep(Duration::from_millis(200)).await;
                store.open_writes();
            }
        );

        assert_eq!(items(&reloaded), vec!["before unload"]);

        push_item(&reloaded, "after reload");
        stop(&server).await;

        assert_eq!(
            saved_items(&store).await,
            vec!["before unload", "after reload"]
        );
    }

    #[tokio::test]
    async fn doc_in_use_stays_loaded_and_unloads_once_released() {
        let store = HeldStore::new(true, true);
        let server = server_on(&store, Duration::from_millis(20)).await;

        let socket = server.get_or_create_doc("doc").await.unwrap().awareness();
        assert!(
            server.doc_locks.is_empty(),
            "lock kept after the load returned"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(server.docs.contains_key("doc"), "a doc in use was unloaded");

        drop(socket);
        wait_until(|| !server.docs.contains_key("doc"), "unloaded").await;
        wait_until(|| server.doc_locks.is_empty(), "released the lock").await;

        server.get_or_create_doc("doc").await.unwrap();
        assert_eq!(store.reads(), 2);
        stop(&server).await;
    }

    #[tokio::test]
    async fn request_dropped_while_loading_leaves_no_lock_behind() {
        let store = HeldStore::new(false, true);
        let server = server_on(&store, Duration::from_secs(60)).await;

        {
            let request = server.get_or_create_doc("doc");
            tokio::pin!(request);
            assert!(futures::poll!(&mut request).is_pending());
            assert_eq!(store.reads(), 1, "the request is not reading the store");
            // The client goes away while the store read is still running.
        }
        assert!(
            server.doc_locks.is_empty(),
            "lock kept after the request was dropped"
        );

        store.open_reads();
        server.get_or_create_doc("doc").await.unwrap();
        assert_eq!(store.reads(), 2);
        stop(&server).await;
    }

    /// Unloads an idle doc with a 2 s save interval and returns how long a request made right
    /// after the unload takes to get the doc back. The first save is held until 1 s before the
    /// unload (the second idle check, 4 s after loading), so the save loop's throttle runs until
    /// 1 s after it. With `edit_while_throttled`, a second edit 0.2 s after that save puts the
    /// save loop inside its throttle at the unload; without it, the save loop is idle.
    async fn reload_time_after_unload(edit_while_throttled: bool) -> Duration {
        let store = HeldStore::new(true, false);
        let server = server_on(&store, Duration::from_secs(2)).await;
        let loaded = tokio::time::Instant::now();
        push_item(
            &server.get_or_create_doc("doc").await.unwrap().awareness(),
            "first",
        );

        tokio::time::sleep_until(loaded + Duration::from_secs(3)).await;
        store.open_writes();
        if edit_while_throttled {
            tokio::time::sleep(Duration::from_millis(200)).await;
            push_item(
                &server.get_or_create_doc("doc").await.unwrap().awareness(),
                "second",
            );
        }

        wait_until(|| !server.docs.contains_key("doc"), "unloaded").await;
        let start = tokio::time::Instant::now();
        server.get_or_create_doc("doc").await.unwrap();
        let elapsed = start.elapsed();
        stop(&server).await;
        elapsed
    }

    #[tokio::test]
    async fn reload_right_after_unload_does_not_wait_for_the_save_interval() {
        let (idle, throttled) = tokio::join!(
            reload_time_after_unload(false),
            reload_time_after_unload(true)
        );
        assert!(
            idle < Duration::from_millis(500),
            "save loop idle at unload: reload took {idle:?}"
        );
        assert!(
            throttled < Duration::from_millis(500),
            "save loop throttling at unload: reload took {throttled:?}"
        );
    }

    #[tokio::test]
    async fn request_for_doc_with_stuck_last_save_fails_after_the_wait_and_loads_once_saved() {
        let store = HeldStore::new(true, false);
        let mut server = server_on(&store, Duration::from_millis(20)).await;
        server.doc_lock_wait = Duration::from_millis(200);

        push_item(
            &server.get_or_create_doc("doc").await.unwrap().awareness(),
            "before unload",
        );
        // The save of that edit is stuck in the store while the idle doc is unloaded.
        wait_until(|| !server.docs.contains_key("doc"), "unloaded").await;

        let failed = tokio::time::timeout(Duration::from_secs(10), async {
            server.get_or_create_doc("doc").await.is_err()
        })
        .await;
        assert_eq!(failed, Ok(true), "the request did not fail after the wait");
        assert_eq!(store.reads(), 1, "a copy was loaded before the last save");

        // Other documents load as usual meanwhile.
        server.get_or_create_doc("other").await.unwrap();

        store.open_writes();
        wait_until(|| server.doc_locks.is_empty(), "released the lock").await;
        let reloaded = server.get_or_create_doc("doc").await.unwrap().awareness();
        assert_eq!(items(&reloaded), vec!["before unload"]);
        stop(&server).await;
    }
}

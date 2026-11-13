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
use dashmap::{mapref::one::MappedRef, DashMap};
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
    doc_connection::DocConnection,
    doc_sync::DocWithSyncKv,
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
            checkpoint_freq,
            authenticator,
            url_prefix,
            cancellation_token,
            doc_gc,
            max_body_size,
            skip_gc,
            attributed_tokens: false,
            on_update: None,
        })
    }

    /// Sets whether `POST /doc/:doc_id/auth` mints attributed tokens when the request names a
    /// `userId` or a `writer`. Verification of attributed tokens is always on.
    pub fn with_attributed_tokens(mut self, attributed_tokens: bool) -> Self {
        self.attributed_tokens = attributed_tokens;
        self
    }

    /// Delivers every update applied to a doc loaded from now on to the configured webhook.
    ///
    /// Spawns the dispatcher, so it must be called from within a Tokio runtime. The dispatcher
    /// stops when the server's cancellation token is cancelled, and `serve` waits for its final
    /// flush.
    pub fn with_update_webhook(mut self, config: UpdateWebhookConfig) -> Result<Self> {
        let (on_update, dispatcher) =
            update_webhook::start(config, self.cancellation_token.clone())?;
        self.doc_worker_tracker
            .spawn(dispatcher.instrument(span!(Level::INFO, "update_webhook")));
        self.on_update = Some(on_update);
        Ok(self)
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

    pub async fn load_doc(&self, doc_id: &str) -> Result<()> {
        let (send, recv) = channel(1024);

        let dwskv = DocWithSyncKv::new(
            doc_id,
            self.store.clone(),
            move || {
                send.try_send(()).unwrap();
            },
            self.skip_gc,
            self.on_update.clone(),
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
            self.doc_worker_tracker.spawn(
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
                        doc_id.clone(),
                        checkpoint_freq,
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
        doc_id: String,
        checkpoint_freq: Duration,
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
                        tracing::info!("GCing doc");
                        if let Some(doc) = docs.get(&doc_id) {
                            doc.sync_kv().shutdown();
                        }

                        docs.remove(&doc_id);
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
            let is_done = tokio::select! {
                v = recv.recv() => v.is_none(),
                _ = cancellation_token.cancelled() => true,
                _ = tokio::time::sleep(checkpoint_freq) => {
                    sync_kv.is_shutdown()
                }
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

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if let Err(err) = dwskv.apply_update(&body, access.actor.as_ref()) {
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

    let dwskv = server_state
        .get_or_create_doc(&doc_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let awareness = dwskv.awareness();
    let cancellation_token = server_state.cancellation_token.clone();

    Ok(ws.on_upgrade(move |socket| {
        handle_socket(socket, doc_id, awareness, access, cancellation_token)
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
        user_id,
        writer,
    }) = body.unwrap_or_default();

    // Oversize values are rejected whether or not attributed tokens are being minted, so that
    // turning the switch on cannot start failing requests that used to succeed.
    let actor = Actor::from_request(user_id, writer).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    if !server_state.doc_exists(&doc_id).await {
        Err((StatusCode::NOT_FOUND, anyhow!("Doc {} not found", doc_id)))?;
    }

    let valid_for_seconds = valid_for_seconds.unwrap_or(DEFAULT_EXPIRATION_SECONDS);
    let expiration_time =
        ExpirationTimeEpochMillis(current_time_epoch_millis() + valid_for_seconds * 1000);

    let actor_requested = actor.is_some();
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
            Some(Json(AuthDocRequest {
                authorization: Authorization::Full,
                user_id: None,
                writer: None,
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
            request.map(Json),
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
    async fn mint_rejects_oversize_actor_fields_whatever_the_switch() {
        let max_user_id = "u".repeat(128);
        let max_writer = "w".repeat(64);

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
            assert_eq!(
                mint(
                    &server,
                    &verifier,
                    request(Some(&format!("{max_user_id}u")), None)
                )
                .await,
                Err(StatusCode::BAD_REQUEST)
            );
            assert_eq!(
                mint(
                    &server,
                    &verifier,
                    request(None, Some(&format!("{max_writer}w")))
                )
                .await,
                Err(StatusCode::BAD_REQUEST)
            );
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
            Arc::new(move |event| events.lock().unwrap().push(event))
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
                Arc::new(move |event| events.lock().unwrap().push(event))
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
}

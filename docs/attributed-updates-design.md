# Attributed updates and the update webhook

**Status:** design, approved in conversation 2026-11-10, pending written review
**Tracks:** Dalus DEV-1839 (fork-level options 1A and 2A of the plan linked from that ticket)
**Companion:** thin wiring in the `dalus` repo, described in section 6

## 1. Problem

Model docs are Yjs documents served by this server. Two things are missing:

1. **Attribution.** A Yjs update carries no origin. The server mints client tokens with only a doc id and an
   authorization level, so it cannot say which user a websocket belongs to. The `user_id` field the mint
   endpoint already accepts is discarded. Server-side writers connect with an anonymous full-access token.
2. **Observation.** Nothing outside this process can learn that a doc changed without opening it. The only
   update observer marks the doc dirty for persistence.

Every feature in Dalus that needs either rebuilds a partial substitute in the browser, and dies with the tab.

## 2. Goals and non-goals

Goals:

- Every update applied by this server carries a server-verified actor: an optional user id and an opaque
  writer kind, both taken from the signed token that authenticated the writer.
- A configured HTTP endpoint receives attributed updates, batched per doc, in order per doc, with
  at-least-once delivery, an idempotency key, and an explicit gap signal.
- Existing tokens keep working through the deploy. The feature is inert unless configured.

Non-goals:

- Durable spooling of undelivered batches. Chosen explicitly: bounded memory plus a gap signal. The receiver
  recovers by fetching the doc's full state from the existing `as-update` endpoint.
- Observing awareness (presence). It is not doc content and is not persisted.
- Decoding updates into entity diffs. That is the receiver's job.
- `serve-doc` (single-doc, Plane) mode. Untouched.

## 3. Attribution

### 3.1 Token payload

The token payload is bincode and positional, so fields cannot be added to the existing `DocPermission`
without invalidating every outstanding token for its lifetime (one hour in Dalus). The actor goes in a new
enum variant instead:

```rust
pub struct Actor {
    pub user_id: Option<String>,
    pub writer: Option<String>,   // opaque, max 64 bytes; the app owns the taxonomy
}

pub enum Permission {
    Server,
    Doc(DocPermission),                       // unchanged, still minted when no actor is given
    AttributedDoc(DocPermission, Actor),      // new
}
```

Old tokens decode as `Doc` and verify with no actor. New tokens are minted only when the mint request
carries `user_id` or `writer`.

### 3.2 Mint endpoint

`POST /doc/:doc_id/auth` honours the `user_id` it already accepts and gains `writer: Option<String>`.
A `writer` longer than 64 bytes is rejected with 400. The `ClientToken` response is unchanged, so no SDK
change is needed.

### 3.3 Verification

`Authenticator::verify_doc_token` returns `DocAccess { authorization, actor: Option<Actor> }` instead of a
bare `Authorization`. Server tokens verify as full access with no actor. Every caller that only needs the
authorization reads `.authorization`.

### 3.4 Tagging updates

The server opens a transaction for every incoming update. That transaction gets an origin that encodes the
actor, so any observer on the doc can read the actor from the transaction it is called with.

- `DocConnection` stores the actor next to the authorization and passes it to the protocol handlers for
  `SyncStep2` and `Update`. The vendored protocol in `y-sweet-core/src/sync` gains `handle_sync_step2_with`
  and `handle_update_with`, which take an `Option<Origin>` and call `transact_mut_with` when present. The
  existing handlers delegate with `None`, so other users of the protocol are unaffected.
- `DocWithSyncKv::apply_update` gains an `actor: Option<&Actor>` parameter. The HTTP update route passes the
  actor from the bearer token. Server-token callers pass `None`.
- The origin encoding is `b"actor:" + serde_json(Actor)`. Observers that find any other origin, or none,
  emit the update as unattributed. Nothing is dropped.

Sync-step-2 catch-up replays a reconnecting client's offline edits and is attributed to that client, which is
correct. Edits the server already holds apply as no-ops and emit nothing, so attribution does not leak between
users.

## 4. Observation

### 4.1 Observer

When a webhook is configured, `DocWithSyncKv::new` registers a second `observe_update_v1` subscription next
to the persistence one. It decodes the actor from the transaction origin and sends

```rust
pub struct UpdateEvent {
    pub doc_id: String,
    pub actor: Option<Actor>,
    pub update: Vec<u8>,        // v1 update bytes exactly as applied
    pub occurred_at: SystemTime,
}
```

into a bounded `mpsc` channel (default 4096 events) owned by the dispatcher. If the channel is full the
event is dropped, a counter increments, and the doc is marked so its next delivered batch carries
`gap_before: true`. The observer never blocks the doc lock.

### 4.2 Batching

The dispatcher owns one state per doc:

- an open batch, closed when the window elapses (`Y_SWEET_UPDATE_WEBHOOK_BATCH_MS`, default 1000), when it
  reaches 256 events or 1 MiB of update bytes, or at shutdown;
- a queue of closed batches awaiting delivery, bounded at 64. Overflow drops the oldest queued batch and
  sets the gap flag for the next delivery;
- a per-doc sequence counter starting at 1 per process start;
- the in-flight delivery, if any. Batches for one doc are delivered strictly in order.

Updates inside a batch are never merged, so each keeps its actor.

### 4.3 Payload

```json
{
  "doc_id": "…",
  "instance_id": "…",
  "seq_start": 41,
  "seq_end": 44,
  "gap_before": false,
  "events": [
    { "seq": 41, "actor": { "user_id": "…", "writer": "ui" }, "update": "<base64 v1 update>", "occurred_at": "2026-11-10T12:00:00.000Z" },
    { "seq": 42, "actor": null, "update": "…", "occurred_at": "…" }
  ]
}
```

`instance_id` is a random id per process start. The receiver's idempotency key is
`(instance_id, doc_id, seq)`. A gap is `gap_before: true`, a `seq_start` other than the previous `seq_end + 1`,
or an unseen `instance_id`. Recovery in every case is the same: fetch the doc's state from `as-update` and
reconcile; attribution for the missed span is lost.

### 4.4 Signing and transport

Headers:

- `X-Y-Sweet-Timestamp`: unix seconds.
- `X-Y-Sweet-Signature`: `sha256=` plus hex HMAC-SHA256 over `"{timestamp}.{body}"` with
  `Y_SWEET_UPDATE_WEBHOOK_SECRET`.
- `Content-Type: application/json`.

The HTTP client is `reqwest` with rustls, already in the dependency tree through the S3 store. Request
timeout 10 seconds.

### 4.5 Delivery and failure

A 2xx is the ack. Any other status, or a timeout, retries the same batch with exponential backoff from 500 ms
capped at 30 s, without limit. The doc's later batches wait in its queue. A process restart loses everything
in memory, which the receiver sees as a new `instance_id`.

### 4.6 Shutdown

On cancellation the dispatcher closes open batches, attempts one delivery per doc with a 5 s budget, and exits.
Doc persistence to S3 is not delayed by this.

### 4.7 Configuration

| Variable | Meaning |
| --- | --- |
| `Y_SWEET_UPDATE_WEBHOOK_URL` | Target URL. Unset means no observer and no dispatcher. |
| `Y_SWEET_UPDATE_WEBHOOK_SECRET` | HMAC secret. Required when the URL is set. |
| `Y_SWEET_UPDATE_WEBHOOK_BATCH_MS` | Coalescing window per doc, default 1000. |

Both are also `--update-webhook-url` / `--update-webhook-secret` / `--update-webhook-batch-ms` on `serve`.

### 4.8 Logging

Structured `tracing` lines at info: batch sent (doc id, seq range, events, bytes, attempt), batch dropped,
channel overflow. Retries at warn with status and attempt. Never update bytes, never user ids, at any level.

## 5. Code layout in this repository

| Area | Files |
| --- | --- |
| Token payload, actor, verification | `crates/y-sweet-core/src/auth.rs`, `api_types.rs` |
| Origin tagging | `crates/y-sweet-core/src/sync/mod.rs`, `doc_connection.rs`, `doc_sync.rs` |
| Event type and observer | `crates/y-sweet-core/src/update_events.rs` (new) |
| Dispatcher, batching, signing, HTTP | `crates/y-sweet/src/update_webhook.rs` (new) |
| Wiring, CLI flags | `crates/y-sweet/src/server.rs`, `main.rs` |
| Operator docs | `docs/attributed-updates.md` (new, written from this design once implemented) |

`y-sweet-core` stays sans-IO: the event type and observer live there, the HTTP dispatcher lives in
`y-sweet`. The `y-sweet-worker` crate builds `y-sweet-core` without the `sync` feature and must keep
compiling; the observer is gated behind `sync`.

## 6. Companion changes in `dalus`

1. **Browser tokens.** `ModelYSweetService.createClientToken` adds `writer: 'ui'` next to the `userId` it
   already sends. The SDK request type is widened at the call site. Preview tokens stay anonymous.
2. **Server connections.** `createConnection` in `with-model-service.ts` mints the token with
   `userId: changeLog.actorId` and `writer: changeLog.source` when the caller passed a `changeLog` actor;
   otherwise anonymous, as today. The unacknowledged-update HTTP fallback uses the SDK `DocConnection`
   built from that same token instead of the server-token `updateDoc`.
3. **Receiver.** `POST /api/internal/y-sweet/updates`: verifies timestamp (±5 min) and HMAC against
   `Y_SWEET_UPDATE_WEBHOOK_SECRET`, validates the body with a Zod schema, logs one line per batch (doc id,
   instance, seq range, gap flag, event count, writer kinds), returns 204. It does not touch the change log.
4. **Config plumbing.** The two variables in the ECS Y-Sweet container command and compose file; the secret
   on the web task. Nothing enabled until the URL is set per environment.

## 7. Rollout

1. Build and deploy the fork image. Inert: no URL configured.
2. Deploy the app with attributed tokens. Old tokens still verify; no reconnect storm.
3. Set the URL and secret on staging. Watch the receiver's log line.
4. Production follows once staging shows ordered, gap-free delivery under normal load.

## 8. Testing

Fork, unit:

- Token round-trip for `Doc` and `AttributedDoc`; an old-format token verifies with no actor; oversize
  `writer` rejected at mint.
- A connection with an actor applies an `Update` and a `SyncStep2` whose observer sees that actor; a
  connection without one yields `None`; a no-op update emits nothing.
- Batcher: window close, size cap, byte cap, per-doc ordering, queue overflow sets the gap flag, channel
  overflow sets the gap flag.
- Signature matches a known HMAC vector.
- Dispatcher retries on 500 and delivers on the next 200, in order, using a local axum test server.

Fork, integration: the existing `tests/` suite runs unchanged against a server with no webhook configured.

App, Jest: signature and timestamp checks, schema rejection, token service passes `writer`, connection
helper mints attributed tokens only when an actor is given. No e2e: nothing user-visible changes.

## 9. Open items

- Push access to `dalus-io/y-sweet` is needed to land the branch.
- The fork has no `rust-toolchain` file; builds use the `rust:1.83` image from `crates/Dockerfile`.

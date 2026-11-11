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
- Existing tokens keep working through the deploy. The feature is inert unless configured: no new token
  format is minted and no observer runs until their switches are set.

Non-goals:

- Durable spooling of undelivered batches. Chosen explicitly: bounded memory plus a gap signal. The receiver
  recovers by fetching the doc's full state from the existing `as-update` endpoint.
- Attributing writes made with the server token. Those stay `actor: null` (section 6 lists them).
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
    pub user_id: Option<String>,  // opaque, max 128 bytes
    pub writer: Option<String>,   // opaque, max 64 bytes; the app owns the taxonomy
}

pub enum Permission {
    Server,
    Doc(DocPermission),                       // unchanged, still minted when no actor is given
    AttributedDoc(DocPermission, Actor),      // new
}
```

Old tokens decode as `Doc` and verify with no actor. Every build with this change verifies both variants.

A binary without this change cannot decode `AttributedDoc` and rejects such a token with 401. Dalus already
sends `userId` on every browser mint, so minting the new variant unconditionally would produce tokens the
draining task rejects during a rolling deploy, and that a rolled-back binary rejects for up to an hour.
Minting is therefore behind its own switch, `Y_SWEET_ATTRIBUTED_TOKENS` (`--attributed-tokens`), default
off. `AttributedDoc` is minted only when the switch is on and the mint request carries `user_id` or
`writer`; otherwise the server mints `Doc` exactly as today. Turning the switch off again is the rollback
step that must precede rolling back the binary.

### 3.2 Mint endpoint

`POST /doc/:doc_id/auth` honours the `user_id` it already accepts and gains `writer: Option<String>`.
A `writer` longer than 64 bytes or a `user_id` longer than 128 bytes is rejected with 400, whether or not
the switch is on. The token travels in the websocket query string, so both stay small. The `ClientToken`
response is unchanged, so no SDK change is needed.

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
correct. Edits the server already holds apply as no-ops and emit nothing.

One known inexactness: an update whose dependencies are missing is parked by yrs as pending and integrated
by whichever later transaction supplies them. Its content is then emitted under that later transaction's
actor. This needs out-of-order delivery across writers and is rare; it is accepted, and the receiver must
treat the actor as "the writer whose transaction made this visible", not as proof of authorship. Both this
and the no-op behaviour are pinned by tests (section 8) because they are yrs internals.

The `y-sweet-worker` crate calls `verify_doc_token`, `DocConnection::new` and `apply_update`
(`lib.rs`, `durable_object.rs`). Its call sites are updated to the new signatures and pass no actor.

## 4. Observation

### 4.1 Observer

`DocWithSyncKv::new` gains an optional `on_update: Option<Arc<dyn Fn(AttributedUpdate) + Send + Sync>>`.
When it is present, a second `observe_update_v1` subscription is registered next to the persistence one. It
decodes the actor from the transaction origin and calls the callback with

```rust
pub struct AttributedUpdate {
    pub doc_id: String,
    pub actor: Option<Actor>,
    pub update: Vec<u8>,        // v1 encoding of what the transaction changed
    pub occurred_at: SystemTime,
}
```

`update` is the transaction's own diff as yrs re-encodes it, not the bytes the client sent: parts the server
already held are absent. `y-sweet-core` has no async runtime, so the channel is not its concern; the callback
is supplied by `y-sweet` and is the only coupling.

The callback supplied by the dispatcher does three things, none of which block the doc lock:

1. If the update is larger than the event cap (8 MiB), drop it.
2. Reserve its size against the global byte budget (section 4.2). If the budget is exhausted, drop it.
3. `try_send` it into a bounded `mpsc` channel (4096 events). If the channel is full, release the
   reservation and drop it.

Every drop increments an atomic per-reason counter (oversize, budget, channel full, closed) and inserts the
doc id into a shared `Mutex<HashSet<String>>` of gapped docs. The dispatcher drains that set on every tick
and sets the doc's gap flag. The set cannot be full, so a drop is never itself lost; its size is bounded by
the number of loaded docs.

The callback never logs. It runs inside the yrs observer, under the doc write lock, and a log write is
synchronous IO: a slow stdout during an overflow would stall doc writes. The dispatcher reports the counters
instead, in one aggregated line per tick (section 4.8).

### 4.2 Batching

The dispatcher owns one state per doc:

- an open batch, closed when the window elapses (`Y_SWEET_UPDATE_WEBHOOK_BATCH_MS`, default 1000), when it
  reaches 256 events or 1 MiB of update bytes, or at shutdown. An event larger than 1 MiB closes the open
  batch and travels alone in its own;
- a queue of closed batches awaiting delivery, bounded at 64. Overflow drops the oldest queued batch and
  sets the gap flag;
- a gap flag, carried as `gap_before: true` on the next batch delivered for the doc and cleared when that
  batch is acked. If the flag is set and the doc has nothing open or queued when the window elapses, an
  empty batch (`events: []`) is queued so the receiver learns of the gap without waiting for the next edit;
- the in-flight delivery, if any. Batches for one doc are delivered strictly in order.

A doc's state is removed once it has no open batch, an empty queue, nothing in flight and no gap flag. This
keeps the map proportional to docs with undelivered work, not to docs ever touched.

One kind of state is not bounded by that, nor by the byte budget: a state that holds no events, only a gap
flag (or an empty batch carrying it). It lives until a batch carrying the flag is acked, so a receiver that
rejects everything would leave one per doc written, each with a recurring empty-batch delivery. These
gap-only states are capped at 4096. When the cap is exceeded the dispatcher discards all of them, aborts
their in-flight empty batches, and replaces `instance_id` with a fresh random id. An unseen `instance_id`
already means "resync this doc" (section 4.3), so the discarded flags are not silently lost. The sequence
counter is not reset. States with events open, queued or in flight are kept; their later batches carry the
new id.

Sequence numbers come from one process-wide counter starting at 1, assigned when the dispatcher takes an
event off the channel. They are therefore unique per `instance_id` regardless of doc eviction and reload,
and increase within a doc, but are not contiguous within a doc.

Updates inside a batch are never merged, so each keeps its actor.

Memory is bounded globally, not only per doc. One atomic counter tracks update bytes held anywhere in the
pipeline (channel, open batches, queues, in flight) against `Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES`, default
256 MiB. Bytes are reserved by the observer callback and released when a batch is acked or dropped. With the
budget exhausted, new events are dropped and their docs gapped, so a receiver outage costs attribution, not
the process.

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

`instance_id` is a random id, new on every process start. A new `instance_id` can also appear mid-process,
when gap tracking is reset (section 4.2); `seq` keeps increasing across that change. The receiver's
idempotency key is `(instance_id, seq)`.
`seq_start` and `seq_end` are the first and last `seq` in `events` and are `null` for an empty gap batch;
they are not contiguous across a doc's batches, so the receiver must not infer gaps from them. A gap is
exactly one of two things: `gap_before: true`, or an `instance_id` the receiver has not seen for this doc.
Recovery in both cases is the same: fetch the doc's state from `as-update` and reconcile; attribution for
the missed span is lost.

The largest body is one 8 MiB event, about 11 MiB once base64-encoded. The receiver must accept 12 MiB.

### 4.4 Signing and transport

Headers:

- `X-Y-Sweet-Timestamp`: unix seconds.
- `X-Y-Sweet-Signature`: `sha256=` plus hex HMAC-SHA256 over `"{timestamp}.{body}"` with
  `Y_SWEET_UPDATE_WEBHOOK_SECRET`.
- `Content-Type: application/json`.

The timestamp and signature are computed per attempt, never per batch, so a batch that has been retrying
for longer than the receiver's tolerance still verifies.

The HTTP client is `reqwest` with rustls and the MAC is `hmac`. Both are already in the lockfile through the
S3 store but only as dependencies of other crates; both become direct dependencies of `y-sweet`. Request
timeout 10 seconds.

### 4.5 Delivery and failure

A 2xx is the ack. The other outcomes split in two:

- **Retryable:** a timeout, a connection error, 408, 429, or any 5xx. The same batch is retried with
  exponential backoff from 500 ms capped at 30 s, until it has been in flight for 10 minutes.
- **Terminal:** any other status (a 4xx such as 400, 401 or 413 means this body will never be accepted), or
  a retryable batch that reached the 10 minute limit. The batch is dropped, its bytes released, the doc's
  gap flag set, and delivery moves on to the doc's next batch.

No batch can therefore block its doc indefinitely. The doc's later batches wait in its queue while one is in
flight. A process restart loses everything in memory, which the receiver sees as a new `instance_id`.

### 4.6 Shutdown

On cancellation the dispatcher closes open batches, attempts one delivery per doc with a 5 s budget, and exits.
Doc persistence to S3 is not delayed by this.

### 4.7 Configuration

| Variable | Meaning |
| --- | --- |
| `Y_SWEET_UPDATE_WEBHOOK_URL` | Target URL. Unset means no observer and no dispatcher. |
| `Y_SWEET_UPDATE_WEBHOOK_SECRET` | HMAC secret. Required when the URL is set. |
| `Y_SWEET_UPDATE_WEBHOOK_BATCH_MS` | Coalescing window per doc, default 1000. |
| `Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES` | Global budget for held update bytes, default 268435456. |
| `Y_SWEET_ATTRIBUTED_TOKENS` | `true` mints `AttributedDoc` tokens (section 3.1). Default off. Independent of the webhook. |

Each is also a flag on `serve`: `--update-webhook-url`, `--update-webhook-secret`,
`--update-webhook-batch-ms`, `--update-webhook-max-bytes`, `--attributed-tokens`.

### 4.8 Logging

Structured `tracing` lines at info: batch sent (doc id, seq range, events, bytes, attempt). At warn: retries
with status and attempt, batch dropped with its reason (status, age, queue overflow), events dropped as one
aggregated line per dispatcher tick with a count per reason (oversize, budget, channel full, closed) and no
doc id, and gap tracking reset with the number of discarded docs and the new `instance_id`. Dropped events
are never logged from the observer callback (section 4.1); per-doc visibility comes from `gap_before` on the
doc's next batch-sent line. Never update bytes, never user ids, at any level.

## 5. Code layout in this repository

| Area | Files |
| --- | --- |
| Token payload, actor, verification | `crates/y-sweet-core/src/auth.rs`, `api_types.rs` |
| Origin tagging | `crates/y-sweet-core/src/sync/mod.rs`, `doc_connection.rs`, `doc_sync.rs` |
| Event type and observer | `crates/y-sweet-core/src/update_events.rs` (new) |
| Dispatcher, batching, signing, HTTP | `crates/y-sweet/src/update_webhook.rs` (new) |
| Wiring, CLI flags | `crates/y-sweet/src/server.rs`, `main.rs`, `Cargo.toml` (`reqwest`, `hmac`) |
| Worker call sites | `crates/y-sweet-worker/src/lib.rs`, `durable_object.rs` |
| Worker build check | `.github/workflows/unit-tests.yml` |
| Operator docs | `docs/attributed-updates.md` (new, written from this design once implemented) |

`y-sweet-core` stays sans-IO: the event type and observer live there and hand events to a callback; the
channel, the dispatcher and all HTTP live in `y-sweet`.

The `y-sweet-worker` crate builds `y-sweet-core` without the `sync` feature; the observer is gated behind
`sync`. The worker is excluded from the workspace and no CI job compiles it today, so "keeps compiling" is
unenforced. This change adds a `cargo check` of the worker crate to the unit-test workflow. If that check
fails on `main` before any of this lands, the pre-existing failure is recorded in section 9 and the check
is left out rather than fixed here.

## 6. Companion changes in `dalus`

1. **Browser tokens.** `ModelYSweetService.createClientToken` adds `writer: 'ui'` next to the `userId` it
   already sends. The SDK request type is widened at the call site. Preview tokens stay anonymous.
2. **Server connections.** `YSweetConnectionOptions` gains `changeLog?: ServerWriteActor`, threaded from
   `WithModelServiceOptions` (it is not passed down today). `createConnection` mints the token with
   `userId: changeLog.actorId` (omitted when null) and `writer: changeLog.source` when it is present;
   otherwise anonymous, as today. The connection keeps the `ClientToken` it minted. The
   unacknowledged-update HTTP fallback builds an SDK `DocConnection` from that token instead of calling the
   server-token `updateDoc`, with `baseUrl` rewritten to the internal endpoint the way
   `model-migration.service.ts` already does, because the token's own `baseUrl` is the public prefix.
3. **Receiver.** `POST /api/internal/y-sweet/updates`: verifies timestamp (±5 min) and HMAC against
   `Y_SWEET_UPDATE_WEBHOOK_SECRET`, validates the body with a Zod schema, logs one line per batch (doc id,
   instance, seq range, gap flag, event count, writer kinds), returns 204. It accepts bodies up to 12 MiB
   and an empty `events` array. It does not touch the change log.
4. **Config plumbing.**
   - ECS: the Y-Sweet container command reads its environment through an `export_if_missing` allowlist
     (`infra/terraform/ecs-app.tf`). The five variables of section 4.7 are added to it; a variable not on
     the list never reaches the process. The secret also goes on the web task.
   - Compose: `infra/docker-compose.yaml` pins the upstream `ghcr.io/jamsocket/y-sweet` image, which
     ignores `writer` and exits on the new flags. It moves to the fork image, so local behaviour matches
     production, and passes the variables through the environment.
   - Nothing is enabled until the switches are set per environment.

Writers that keep using the server token, and so stay `actor: null` by design:

- `setStorageDocument` and the legacy-to-canonical migration writes in `lib/common/y-sweet/storage.ts`;
- model migrations (`model-migration.service.ts`, `migrations/model-migrations.ts`);
- test seeders and the agent eval context.

These are the replace-semantics and maintenance writes the change log already excludes. The receiver must
expect `actor: null` and must not read it as an error.

## 7. Rollout

1. Build and deploy the fork image with no switches set. Inert: it mints `Doc` tokens as before and runs no
   observer. It can verify `AttributedDoc`, which is what makes step 3 safe.
2. Deploy the app. It now sends `writer`; the server ignores it while the switch is off.
3. Once every Y-Sweet task in the environment runs the new image, set `Y_SWEET_ATTRIBUTED_TOKENS=true`.
   Old tokens still verify; no reconnect storm.
4. Set the webhook URL and secret on staging. Watch the receiver's log line.
5. Production follows once staging shows ordered, gap-free delivery under normal load.

Rollback runs the same steps backwards. In particular, unset `Y_SWEET_ATTRIBUTED_TOKENS` and wait out the
token lifetime (one hour) before rolling the image back, or the old binary rejects outstanding tokens.

## 8. Testing

Fork, unit:

- Token round-trip for `Doc` and `AttributedDoc`; an old-format token verifies with no actor; oversize
  `writer` and oversize `user_id` rejected at mint.
- Mint with the switch off yields a `Doc` token even when `user_id` and `writer` are given; with it on,
  `AttributedDoc`.
- A connection with an actor applies an `Update` and a `SyncStep2` whose observer sees that actor; a
  connection without one yields `None`; a no-op update emits nothing.
- Pending update: an update with a missing dependency emits nothing; when a second writer supplies the
  dependency, the content is emitted under the second writer. This documents the accepted inexactness of
  section 3.4 and fails loudly if a yrs upgrade changes it.
- Batcher: window close, size cap, byte cap, oversize event travels alone, per-doc ordering, queue overflow
  sets the gap flag, channel overflow sets the gap flag, an event over the event cap is dropped and gaps the
  doc, an exhausted byte budget drops and gaps and recovers once bytes are released.
- A gapped doc with no further edits gets an empty batch with `gap_before: true`.
- Sequence numbers stay unique after a doc's state is removed and the doc is written again.
- Signature matches a known HMAC vector; a retried attempt carries a newer timestamp and a signature that
  verifies against it.
- Dispatcher, using a local axum test server: retries on 500 and delivers on the next 200, in order; a 400
  drops the batch, gaps the doc and delivers the next batch; a batch past the retry age limit does the same.

Fork, integration: the existing `tests/` suite runs unchanged against a server with no switches set.

App, Jest: signature and timestamp checks, schema rejection, empty-events batch accepted, token service
passes `writer`, connection helper mints attributed tokens only when an actor is given, the HTTP fallback
uses the connection's own token and the internal base URL. No e2e: nothing user-visible changes.

## 9. Open items

- Push access to `dalus-io/y-sweet` is needed to land the branch.
- The fork has no `rust-toolchain` file; builds use the `rust:1.83` image from `crates/Dockerfile`.

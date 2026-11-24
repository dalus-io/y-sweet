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
  at-least-once delivery, an idempotency key, and a gap signal. The gap signal is best-effort in
  one respect: it lives in memory, and when it is lost the only trace is a new `instance_id`
  (section 4.3 states what the receiver must do about that).
- Existing tokens keep working through the deploy. The feature is inert unless configured: no new token
  format is minted and no observer runs until their switches are set. "Inert" is not "identical to
  upstream": the operator doc lists the remaining differences (attributed tokens verify, graceful and
  ordered shutdown on `SIGTERM`, new log lines, new flags).

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
    Server,                                            // 0
    Doc(DocPermission),                                // 1: unchanged, still minted when no actor is given
    ManagedDoc(DocPermission, Option<(String, u64)>),  // 2: user suspension, see below
    AttributedDoc(DocPermission, Actor),               // 3: new
    ManagedAttributedDoc(DocPermission, Option<(String, u64)>, Actor),  // 4: both
}
```

Old tokens decode as `Doc` and verify with no actor. Every build with this change verifies `Doc` and
`AttributedDoc`.

Index 2 is not free. The Dalus production image is built from fork revision 4f1909b plus a user-suspension
patch, and that patch appended `ManagedDoc(DocPermission, Option<(String, u64)>)` (a doc token bound to a
user id and the user's revocation generation) as variant 2. `AttributedDoc` was first written as variant 2
here, and the two layouts overlap: a managed token for a user at generation 0 is, byte for byte, an
attributed token for that user with no writer, and its signature verifies, because the signature is over
those bytes. So `ManagedDoc` is declared at index 2 with the patch's exact layout and `AttributedDoc` is
index 3. A server that does not enforce suspension rejects a `ManagedDoc` token with 401 (`The token is of a kind
this server does not accept`) rather than treating it as a doc token: it cannot check the generation the
token is bound to, so accepting it would make a revocable token irrevocable. Tests pin the bytes of every
variant, written out by hand from the layout.

User suspension and token expiry enforcement, formerly patches applied to revision 4f1909b when the
production and appliance images were built, are part of the server behind `Y_SWEET_USER_SUSPENSION` and
`Y_SWEET_ENFORCE_TOKEN_EXPIRY` (expiry off by default; suspension on by default for a server with auth
and a store that does not enforce expiry, which is where the production build enforced it unconditionally;
the operator page has the behaviour). What the port
had to settle:

- **One verification path.** `Server::verify_doc_token` returns the access, a cancellation token and a
  deadline. With suspension on it accepts the server token and managed tokens only and asks `UserAccess`
  (the patch's module, unchanged) whether the bound user is at the token's generation; the cancellation
  token it gets back fires when that user is suspended or restored. With expiry enforcement it applies
  the appliance rule (a doc token that can write must have a finite expiry). With both, both. With
  neither it is the code this branch had.
- **Websockets.** The connection loop ends on the user's cancellation, on the token's deadline and on
  shutdown, and checks both again for each frame, before and after the frame is admitted through the
  write gate, so that waiting for admission cannot carry a frame past a suspension. Ending the loop
  drops the `DocConnection`, which unregisters from the doc under the doc lock (the connection-churn fix
  below), and only then aborts the sender task so that the socket closes at once. A suspension that
  closes many sockets of one doc while others connect is therefore serialized like any other churn.
- **What the suspension answer guarantees.** Checking a flag before applying is not enough: a write can
  pass the check, wait for the doc lock, and be applied after the endpoint has answered. Each user has an
  activity guard, a read/write lock. A request takes it for reading at its last check (after its doc is in
  memory and, for writes, after write admission) and holds it until the read or write is done, the wait
  for the doc lock included. `UserAccess::set_suspended` cancels the user's token state and then takes the
  guard for writing before it returns. So a request either holds the guard before the suspension, and the
  endpoint waits for it, or takes it after, and finds the cancellation. Lock order is write gate, then
  activity guard, then doc lock; the endpoint takes only the user's own mutex and then the guard, and no
  holder of the guard takes that mutex, so there is no cycle. The guard is held across in-memory work
  only: never across a doc load, store IO or a socket write. The same check applies the token's deadline;
  for that, a write admitted just before the deadline may finish just after it.
- **HTTP reads.** `as-update` fetches the doc, then takes the guard, checks, and encodes the doc under it.
- **Revocation records.** The patch kept one object per user and overwrote it on each change, so a write
  that timed out and landed late could replace a later, acknowledged state. Records now form a chain per
  user, at positions 1, 2, 3 and so on; the last record is the state; a position never receives two
  different acknowledged contents; and a position is used only once all before it are stored, which is
  what lets the end be found by reading upwards without listing the store (the `Store` trait has no
  listing). The chain starts at a fixed position on purpose. An earlier version started it at the
  generation found in the single object, which made recovery depend on that mutable object: a write of the
  old build, pending since before the upgrade, could lower it afterwards, the scan then began below the
  chain and found nothing, and a suspended user came back. The single object is now only ever an input
  that can raise the state: it counts when its generation is above the chain's and is then appended to
  the chain. It is still written as a mirror for builds that know nothing else. The operator page has the
  details and what remains uncovered.
- **Shutdown, GC, loading.** Revocation records are written straight to the store by the suspension
  endpoint, with their own 3 s limit, and are durable before the endpoint answers; they are not docs, so
  the write gate, the final saves, doc GC and the suspect window do not involve them. A change whose
  write times out after reaching the store, and that is never followed by another change of that user,
  can still take effect at the next restart: no later generation exists to outrank it. That is inherent
  in a write of unknown outcome; what cannot happen any more is that it outranks a later change.
- **Tokens with attribution.** A token that must carry both the binding and the actor is variant 4.
  Whether a request's `userId` binds the token is decided as the patch decides it: it always does. There
  is no way out (an earlier revision of this port had `"userScoped": false`; the production build ignores
  that field and binds, so a token minted with it here survived a suspension the production build would
  have enforced). See the operator page for what that means for server-side writers.

Attributed tokens minted while `AttributedDoc` was index 2 (only builds of this branch up to 649406a with
the switch on) are rejected by later builds; they expire within their lifetime, an hour by default.

A binary without this change cannot decode `AttributedDoc` and rejects such a token with 401. Dalus already
sends `userId` on every browser mint, so minting the new variant unconditionally would produce tokens the
draining task rejects during a rolling deploy, and that a rolled-back binary rejects for up to an hour.
Minting is therefore behind its own switch, `Y_SWEET_ATTRIBUTED_TOKENS` (`--attributed-tokens`), default
off. `AttributedDoc` is minted only when the switch is on and the mint request carries `user_id` or
`writer`; otherwise the server mints `Doc` exactly as today. Turning the switch off again is the rollback
step that must precede rolling back the binary.

### 3.2 Mint endpoint

`POST /doc/:doc_id/auth` honours the `user_id` it already accepts and gains `writer: Option<String>`.
A `writer` longer than 64 bytes or a `user_id` longer than 128 bytes is rejected with 400 when the switch is
on. With the switch off the fields are ignored, as upstream ignores them, and the request succeeds; a warning
with the lengths (never the values) flags the request that would start failing once the switch is turned on. The token travels in the websocket query string, so both stay small. The `ClientToken`
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

Sync-step-2 catch-up replays a reconnecting client's offline edits and is attributed to that client. Edits
the server already holds apply as no-ops and emit nothing.

That is right only while the server holds everything it acknowledged. The actor is, precisely, the token
that delivered the update to this server process, and this is a limitation, not a property to rely on:

- After an unclean restart (crash, `SIGKILL`, a shutdown that ran out of time) the server has lost
  acknowledged edits that clients still hold. The first client to reconnect re-uploads all of them in its
  `SyncStep2`, other users' edits included, and they are emitted under that client's actor. If they had
  already been delivered before the restart, they are emitted again as new events with a different actor.
- An HTTP fallback that pushes a writer's full state is the actor of everything in it the server lacked.
- The missing-dependency case below.

The receiver must therefore treat `actor` as the deliverer, and treat content it already has as a duplicate
rather than a new write.

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
3. Copy it, and `try_send` the copy into a bounded `mpsc` channel (4096 events). If the channel is full,
   release the reservation and drop it.

The callback is lent the update (`ObservedUpdate`, a view of the buffer yrs built for the transaction) and
copies it only in step 3. An update refused in step 1 or 2 is therefore never copied: copying first would
spend time in proportion to the update under the doc lock, most of all for exactly the oversize updates
that are then thrown away.

Every drop increments an atomic per-reason counter (oversize, budget, channel full, closed) and inserts the
doc id into a shared `Mutex<HashSet<String>>` of gapped docs. The dispatcher drains that set on every tick
and sets the doc's gap flag. The set cannot be full, so recording a drop never fails; its size is bounded by
the number of loaded docs. (The record is still in memory: a restart or a gap-tracking reset loses it, see
section 4.3.)

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
- a gap flag, carried as `gap_before: true` on the first batch whose delivery starts after the loss (the
  batch carrying the doc's next updates, if any) and cleared when that batch is acked; if it is not acked
  the flag passes to the next batch. If the flag is set and the doc has nothing open or queued when the window elapses, an
  empty batch (`events: []`) is queued so the receiver learns of the gap without waiting for the next edit;
- the in-flight delivery, if any. Batches for one doc are delivered strictly in order.

A doc's state is removed once it has no open batch, an empty queue, nothing in flight and no gap flag. This
keeps the map proportional to docs with undelivered work, not to docs ever touched.

One kind of state is not bounded by that, nor by the byte budget: a state that holds no events, only a gap
flag (or an empty batch carrying it). It lives until a batch carrying the flag is acked, so a receiver that
rejects everything would leave one per doc written, each with a recurring empty-batch delivery. These
gap-only states are capped at 4096. When the cap is exceeded the dispatcher discards all of them, aborts
their in-flight empty batches, and replaces `instance_id` with a fresh random id. This deliberately drops
the per-doc gap signal of the discarded docs: none of them is sent `gap_before: true` or an empty gap batch
afterwards, and one that is never written again is never sent anything. The only trace is the new
`instance_id` on the next batch sent for any doc, which is why the receiver contract (section 4.3) makes a
new id mean "resync every doc", not "resync this doc". The sequence counter is not reset. States with events
open, queued or in flight are kept, with their own gap flags; their later batches carry the new id.

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
they are not contiguous across a doc's batches, so the receiver must not infer gaps from them.

Receiver contract for gaps:

1. `gap_before: true` means this doc lost updates since the last batch the receiver acknowledged for it.
   Resync this doc.
2. An `instance_id` the receiver has not seen before means the server lost its in-memory state (restart, or
   the gap-tracking reset of section 4.2), and with it possibly the gap flag of any doc. A doc whose flag
   was lost is not told separately; if it is never written again, it gets no batch at all. So on a new id
   the receiver must treat every doc it has received batches for under any other `instance_id` as possibly
   gapped and resync each one, not only the doc in that batch. With several servers the receiver cannot
   tell which id the new one replaced, so it resyncs every known doc not yet seen under the new id;
   resyncing a doc that had no gap is harmless.

Resync means: fetch the doc's state from `as-update` and reconcile; attribution for the missed span is lost.

Residual blind spot, accepted: the new `instance_id` arrives only with the next batch the server sends. If
nothing is written anywhere after a restart or reset, the receiver hears nothing until something is. A
receiver that needs a bound on detection must also reconcile on its own (on doc open, or on a schedule).

The largest body is one 8 MiB event, about 11 MiB once base64-encoded. The receiver must accept 12 MiB.

The budget counts estimated memory, not raw update bytes. Each event is charged 4/3 of its update size
(its base64 form, the larger of how it is held waiting and in flight), the lengths of its doc id and actor
strings, and a fixed 256 bytes for the structs and JSON framing around it. Counting raw bytes alone
undercounted badly in the case the budget exists for: with the receiver down for hours and many tiny edits,
each event was charged a byte or two while holding a few hundred. The charge is computed by the observer
with a few additions and no allocation.

For the charge to bound memory, each form an event takes must keep no more than the charge. Waiting, it is
the raw update plus about 110 bytes of structure; a batch drops its spare event slots when it closes. In
flight, it is the request body alone, which is why the body is measured first and then serialized into a
buffer of exactly that size, with base64 written straight into it. (Serializing into a growing buffer left
the body with up to twice the capacity it used: a doc with one large update in flight kept 2.0 times its
charge, and with the receiver down every doc has a batch in flight, so the pipeline could hold about twice
the budget.) Should a body still be larger than its events were charged, which takes strings that need
JSON escaping, the charge is raised to the body's length when the batch is serialized. With the budget
full, real memory is therefore the budget, plus the one batch being serialized at a time (raw and encoded
forms together, at most about 19 MiB), plus allocator overhead. The operator doc gives sizing guidance.

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

The client trusts the bundled webpki roots, not the OS store, so a receiver behind a private CA would fail
every delivery. `Y_SWEET_UPDATE_WEBHOOK_CA_FILE` names a PEM file whose certificates are added as extra
roots (`ClientBuilder::add_root_certificate`); no reqwest feature change is needed. The file is read at
startup; an unreadable file or one with no certificate disables the webhook (section 4.7).

### 4.5 Delivery and failure

A 2xx is the ack. The other outcomes split in two:

- **Retryable:** a timeout, a connection error, 408, 429, or any 5xx. The same batch is retried with
  exponential backoff from 500 ms capped at 30 s, until it has been in flight for 10 minutes. A 429 or 503
  with `Retry-After` (delta-seconds or HTTP-date) waits that long instead when it is longer than the
  backoff, but never past the 10 minute limit: the batch then gets a last attempt at the limit.
- **Terminal:** any other status (a 4xx such as 400, 401 or 413 means this body will never be accepted), or
  a retryable batch that reached the 10 minute limit. The batch is dropped, its bytes released, the doc's
  gap flag set, and delivery moves on to the doc's next batch.

No batch can therefore block its doc indefinitely. The doc's later batches wait in its queue while one is in
flight. A process restart loses everything in memory, which the receiver sees as a new `instance_id`
(section 4.3, rule 2).

Concurrency across docs is capped: at most 16 requests (`Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY`) are open at
once, through a semaphore taken per attempt. Without it, a receiver coming back from an outage would get one
POST per backlogged doc at the same moment, each up to 12 MiB. The permit is held for the request only, not
during a retry delay, so docs that are backing off do not starve the rest; a batch waiting for a permit
still counts as its doc's in-flight batch, so per-doc ordering is unchanged, and the wait for a permit is
bounded by the batch's remaining retry age (a batch that cannot get one in time is dropped like one that
kept failing). The shutdown flush uses the
same cap.

### 4.6 Shutdown

On cancellation the dispatcher closes open batches, attempts one delivery per doc with a 5 s budget, and exits.
Doc persistence to S3 is not delayed by this.

`serve` cancels on `SIGINT` and on `SIGTERM`; the latter is what `docker stop` and an ECS stop or scale-in
send, so without it the flush (and the existing persist-on-shutdown) would never run in production. The
handlers are installed before startup and startup races them, so a signal during a hung store init exits
cleanly instead of being held until init returns.

Upstream cancelled everything at once from one token: each doc's persistence worker saved and exited while
in-flight HTTP requests and websocket messages were still being applied. An edit applied after that save was
acknowledged and never stored, and its dirty notification `unwrap`ped a send on the closed channel, panicking
under the doc lock. With `SIGTERM` routing every deploy and scale-in through this path, the shutdown is now
ordered, with a budget per stage:

1. The cancelled token stops the listener and tells websockets to close.
2. In-flight HTTP requests finish (axum's graceful shutdown) and websocket tasks, now tracked, end. Then a
   write gate closes, in two steps: admission stops at once and unconditionally (later writes get `503`, or
   the websocket message is dropped unapplied), even if the requests above overran the budget; then it waits,
   bounded, for writes already admitted. A write is admitted only around applying the update, never across
   loading its doc or store I/O, so that wait is short. Budget 5 s.
3. The persistence and GC workers, on their own token, stop; each does a final save, and retries it with
   backoff (0.25 s doubling to 5 s) if it fails. The saves have until the shutdown timeout.
4. The dispatcher, on its own token, flushes. Budget 7 s (its internal budget is 5 s). It starts when the
   saves are done, or beside them when only its 7 s are left of the shutdown timeout.

The shutdown timeout is `Y_SWEET_SHUTDOWN_TIMEOUT_SECONDS`, default 110 s. The Dalus deployments stop
Y-Sweet with `SIGINT`, so before this change a deploy already ran upstream's shutdown, which waited for the
final saves without limit; the platform's stop timeout was the only bound. A fixed 10 s save stage (an
earlier revision of this design) was a regression: on a deploy with a slow store or many dirty docs it
abandoned saves and lost everything since the last checkpoint. So the saves are the one stage that is never
cut short in favour of another: they run until the total timeout, the connection stage and the webhook
flush are bounded so they cannot use that time up, and the flush, which is expendable, overlaps the saves
rather than replacing them. The default is sized against the Dalus ECS task's `stopTimeout` of 120 s,
leaving 10 s to exit. A platform with a shorter grace period (the on-prem compose file: 30 s) kills the
process at its own limit; until then the saves run as upstream's did, so the default loses nothing there,
and the operator doc tells such deployments to lower the setting to get the flush and the logs in. When the
timeout is reached with saves unfinished, each unsaved doc is logged by id.

A stage that overruns is logged with its name and the next one starts. The dirty callback ignores a closed
or full channel instead of panicking.

One more upstream race undermined the final save: `SyncKv::persist` cleared the doc's dirty flag after the
store write returned, so an edit applied while a checkpoint was being written lost its flag and the final
save skipped it. The flag is now cleared atomically with taking the snapshot (under the data lock every
write holds while marking the doc dirty) and set again if the store write fails.

Saving and the update log. Since the merge of `fix/compact-on-save`, an edit only appends to the doc's
update log; `SyncKv::compact` merges the log into the stored state before a save, on a blocking thread.
`SyncKv::persist` writes the whole key-value map, pending log entries included, and loading a doc applies
them, so compaction is an optimisation (a small stored form, a fast load) and not what makes a save
complete: a save without it loses nothing, and a compaction that fails is logged and the save goes ahead.
All the same, every save path makes the same save, `compact_and_persist`: the periodic checkpoint, the
final save at shutdown and each of its retries, and GC's save of a doc it retires. Compaction and the write
run under the doc's save lock, so they never interleave with another save or compaction of the doc, and
neither is skipped because a token was cancelled. `compact` sets the dirty flag under the map lock, the same
lock under which `persist` clears it and takes its snapshot, so a compaction or an edit during a save always
leaves the doc dirty for the next one. A persistence worker whose doc GC has saved and dropped stops without
saving again; its copy is no longer the doc and a fresh load may hold newer state. A compaction still
running when the shutdown timeout is reached does not hold the exit: the runtime is given one second to
stop, not left to wait for blocking work.

Doc GC had a similar upstream race. It retired an idle doc (`SyncKv::shutdown`, after which writes are no
longer marked dirty) based on the awareness reference count, which an HTTP write does not raise, so a write
being applied at that moment was acknowledged and never saved. Now:

- GC retires a doc only through `DocWithSyncKv::retire_if_unused`, which re-checks under the doc's write
  lock that nothing but the map holds its awareness.
- A writer (HTTP update or websocket upgrade) takes the doc with `Server::live_doc`: it holds the awareness
  and checks, under the doc lock, that the doc is not retired. From then on GC cannot retire it, and the
  write is applied to that doc without any lookup or load under write admission.
- GC saves the retired doc itself, under a per-doc lock it shares with the persistence worker (so it cannot
  see "nothing to save" while the worker's save of the same changes is still being written). Only if that
  save succeeds does it drop the doc and stop the doc's persistence worker. If the save fails, GC
  un-retires the doc (`SyncKv::resume`): it stays loaded and writable, its worker keeps retrying, and GC
  tries again later. A save that fails leaves the doc dirty.
- GC never abandons that save, however long it takes. A write already sent to the store cannot be recalled
  (S3 has no fencing here); abandoning it, letting the doc be written and saved again, would let the old
  write land last and overwrite newer state. The S3 store's own request timeout (below) is not such an
  abandonment: it closes the request's connection and returns an error, GC un-retires the doc, and the
  next save starts only after that. For the case where the store applies the timed-out write anyway, see
  the suspect window below.
- A writer takes its doc with `Server::live_doc`, and all of that is bounded by 15 s and by shutdown
  (`503` either way): loading the doc, waiting behind another load of it, and waiting for a retired doc to be
  dropped and loading it again. A doc that is there at once is taken even during shutdown, so in-flight
  requests can finish. A hung store thus holds up GC of that one doc and makes writes to it fail fast; it
  never reorders what is stored. Shutdown stays bounded by its stage budgets.
- A doc is loaded by a task of its own, one per doc at a time, and a load never replaces a doc already in
  the map. Every request that wants the doc meanwhile waits on that one load and gets its result. Upstream
  let two concurrent first requests both load the doc, the second replacing the first and dropping its
  persistence subscription while the first request's writer held it.
- The load belongs to no request. A writer that gives up after its 15 s, or a client that disconnects,
  stops waiting and nothing else: the load runs on, and the next request finds the doc loaded or joins the
  same load. (When the load ran inside the request that started it, the 15 s limit cancelled it, and the
  retry started it over; a doc that took longer than 15 s to load could never be opened.) A load ends when
  the store answers; with the S3 store that is bounded by its request timeout (below). A load that fails
  reports the error to everyone waiting and is forgotten, so the next request starts a new one.

This trades data loss for a narrower availability risk, which the operator doc lists: while the save of a
retired doc is stalled, that one doc answers `503` (after the 15 s wait) until the write completes or
fails, or the process restarts. Upstream dropped the doc immediately and lost the unsaved edits instead.

The S3 client has a request timeout (`Y_SWEET_S3_REQUEST_TIMEOUT_SECONDS`, default 60 s, plus 1 s per MiB
of request body so that it puts no ceiling on doc size; 10 s to connect; the same 60 s per chunk when
reading a response). A stalled write therefore fails, GC un-retires the doc and its persistence worker
retries, so the "being unloaded" state ends after about a minute instead of lasting until a restart. The
timeout is applied with a timer around the request, not through reqwest, whose wasm build has no timeout
setting; the wasm build (the Cloudflare worker) applies none. Timing out drops the request, which closes
its connection, before the error is returned, so the rule that a doc's saves never overlap holds for a
timed-out save as it does for one that failed any other way. The waits that writers and shutdown depend on
stay bounded independently of this, as above.

**Suspect window.** Before the timeout existed a hung save never returned, so nothing was saved after it.
Now it returns, the save lock is released, and a later save can succeed, while the store may still hold
the earlier write in full and apply it afterwards, over the newer copy. The same is true of a save whose
connection is reset after the body went out, or that the store answers with a `5xx`. There is no fence for
this that works on AWS S3, MinIO and LocalStack alike (conditional writes are not uniformly supported), so
it is mitigated by saving again.

The store sorts its failures (`StoreError::write_may_still_land`). `Timeout` (with the time the request
was given) and `Interrupted` may have left a write behind. `ConnectionError` and the refusals cannot have:
reqwest reports failures of the connect phase and of building the request as such (`is_connect`,
`is_builder`), and a request that never got a connection sent no body; everything else reqwest reports is
treated as possibly sent. `SyncKv::persist` marks the doc suspect on the first kind, until
`max(5 min, 5 x that time)` from then. While a doc is suspect:

- a successful save is recorded as the latest attempt, not as "saved": `has_unsaved_changes` stays true,
  and the doc is due another save 60 s later although nothing changed. The persistence worker calls
  `persist` at every checkpoint anyway; `persist` writes when the doc changed, or when that 60 s mark has
  passed, and otherwise returns as it does for any unchanged doc. So an idle suspect doc is rewritten once
  a minute instead of at every checkpoint (after a store brownout that is the difference between about
  five and about thirty full rewrites of every affected doc), and nothing can spin: there is no extra
  timer and no dirty callback;
- the save's drop guard is unchanged: a save that fails or is abandoned re-marks the doc dirty, suspect or
  not;
- GC does not retire the doc, and does not drop a doc whose save succeeded if it became suspect meanwhile
  (the worker's save failing just before GC's): it un-retires it instead;
- the last save a copy of a doc gets (the final save at shutdown, GC's save) is made whether or not the
  60 s are up;
- one more save is made after the window. Whether a save settles the doc is decided by when it started,
  not when it ended: one sent inside the window may itself be applied before the stale write. The save
  that started after the window clears the state, and GC can then collect the doc.

What is left is a stale write applied after the last save the process makes: after the final save at
shutdown (every suspect doc is saved and their number is logged in one warning), after the window if a
store holds a write that long, or in the gap of at most 60 s between a stale write landing and the next
save if the process is killed there. The shutdown report of unsaved docs counts a suspect doc as unsaved
even when its final save succeeded, which is the cautious reading.

Store error messages no longer include the request URL: it is presigned and carries a signature.

**Connection churn.** yrs 0.19 registers an observer with a compare-and-swap loop that does not reload
the list head it compares against (`Observer::subscribe_with`); if the head is unregistered concurrently,
the loop never ends. `DocConnection::new` registers its two observers under the doc write lock, and
upstream's `Drop` released them with no lock, so a socket connecting while another disconnected could spin
for ever holding the doc lock. `DocConnection`'s `Drop` now takes the doc write lock and unregisters under
it, which serializes every registration and removal on a doc (the doc's own two observers are registered
before the doc is shared and removed after its last connection is gone). A stress test with eight threads
opening and closing connections froze after a few hundred sessions before the change and completes 40,000
with it. Attribution makes this path hotter: the app reconnects on every actor switch.

### 4.7 Configuration

| Variable | Meaning |
| --- | --- |
| `Y_SWEET_UPDATE_WEBHOOK_URL` | Target URL. Unset means no observer and no dispatcher. |
| `Y_SWEET_UPDATE_WEBHOOK_SECRET` | HMAC secret. Required when the URL is set. |
| `Y_SWEET_SHUTDOWN_TIMEOUT_SECONDS` | Total time a graceful shutdown may take, default 110 (section 4.6). Not a webhook setting: it applies with everything off. Empty counts as unset; a value that is not a number is logged as an error and replaced by the default, so it cannot keep the server from starting. |
| `Y_SWEET_S3_REQUEST_TIMEOUT_SECONDS` | Request timeout of the S3 store, default 60 (section 4.6). Environment only, like the other S3 settings. Empty and invalid values are handled like the shutdown timeout's. |
| `Y_SWEET_UPDATE_WEBHOOK_BATCH_MS` | Coalescing window per doc, default 1000. |
| `Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES` | Global budget for the estimated memory of held updates, default 268435456. |
| `Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY` | Requests in flight at once across docs, default 16 (section 4.5). |
| `Y_SWEET_UPDATE_WEBHOOK_CA_FILE` | Extra CA certificates (PEM) to trust for the URL (section 4.4). |
| `Y_SWEET_ATTRIBUTED_TOKENS` | `true` mints `AttributedDoc` tokens (section 3.1). Default off. Independent of the webhook. As a flag, `--attributed-tokens <true\|false>` reads the next argument as its value, so `--attributed-tokens false` is off and a path there is an error. |

A webhook setting that is invalid (malformed URL, URL without a secret, a number that does not parse, an
unusable CA file) does not stop the server: it logs one error, without the URL or the secret, and starts
with the webhook disabled. The service is a singleton whose old task is stopped before the new one starts,
so refusing to start over an optional feature would be a full sync outage. Settings that are not optional
features (the store, auth, `Y_SWEET_ATTRIBUTED_TOKENS`, the shutdown timeout) remain hard errors.

Each is also a flag on `serve`: `--update-webhook-url`, `--update-webhook-secret`,
`--update-webhook-batch-ms`, `--update-webhook-max-bytes`, `--update-webhook-concurrency`,
`--update-webhook-ca-file`, `--attributed-tokens`.

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

Rollback runs the same steps backwards. In particular: an older image rejects every outstanding attributed
token with 401 until it expires, so first unset `Y_SWEET_ATTRIBUTED_TOKENS` and deploy that, then wait out
the longest token lifetime in use (Dalus mints browser tokens for up to 3600 s), and only then roll the image
back.

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
- Concurrency: many docs ready at once never have more requests open than the cap, still one per doc and
  in order; the shutdown flush respects the cap too. `Retry-After` delays the retry, and is bounded by the
  retry age.
- Gap-tracking reset: a doc whose gap state was discarded and that is never written again gets no batch;
  the only signal is the new `instance_id` on another doc's batch.
- Shutdown: an update whose body is still arriving when shutdown starts is acknowledged and saved (this
  fails against the old ordering); writers posting through a shutdown never get an acknowledged-but-unsaved
  update; pending edits are saved before `serve` returns, and by the real binary on `SIGTERM` with a
  filesystem store; an edit after the persistence worker stopped does not panic; a store whose writes hang
  does not push shutdown past its budget.
- Mint: oversize actor fields get 400 with the switch on and a plain token with it off.
- CLI: `--attributed-tokens false` is off and never a store path; `--attributed-tokens /data` is an error.
- Shutdown budget: with the default timeout, 50 dirty docs whose saves take 30 s each are all saved (a
  paused clock); a final save that fails for 20 s is retried and succeeds; saves that need nearly the whole
  timeout are not cut short by the flush stage; the real binary saves pending edits on `SIGINT`.
- Webhook settings: each kind of mistake yields no webhook rather than an error exit, and the real binary
  starts, serves and saves with each of them.
- Budget: an event's charge covers its serialized size; one-byte events fill a 1 MiB budget after about
  four thousand, not a million.
- Websockets: edits racing a shutdown leave nothing applied in memory that is not in the store; a message
  after the gate closed is not applied and the connection ends; GC does not retire a doc with an open
  websocket, and drops it once the socket closes; a connection to a doc being retired waits for a fresh
  load, or gets 503 if the doc stays retired.
- TLS: a receiver on a certificate from a private CA fails the handshake with the bundled roots only and is
  delivered to once `Y_SWEET_UPDATE_WEBHOOK_CA_FILE` names the CA.
- Through the real server: a websocket update carries the actor of the token it connected with (and none for
  a plain token); `POST /d/:doc_id/update` with a read-only token is 403 and emits nothing; `serve` waits for
  the webhook's final flush on cancellation; the real binary flushes on `SIGTERM` and exits cleanly.
- Observer: loading a non-empty doc from the store emits nothing; a delete-only update emits an event, with
  GC on and off.

Fork, integration: the existing `tests/` suite runs unchanged against a server with no switches set.

App, Jest: signature and timestamp checks, schema rejection, empty-events batch accepted, token service
passes `writer`, connection helper mints attributed tokens only when an actor is given, the HTTP fallback
uses the connection's own token and the internal base URL. No e2e: nothing user-visible changes.

## 9. Open items

- Push access to `dalus-io/y-sweet` is needed to land the branch.
- The fork has no `rust-toolchain` file; builds use the `rust:1.83` image from `crates/Dockerfile`.

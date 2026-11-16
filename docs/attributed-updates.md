# Attributed updates and the update webhook

This fork of Y-Sweet can do two things upstream cannot:

1. **Attribute writes.** A doc token can carry an *actor* (an opaque user id and an opaque writer
   kind). Every update applied through that token is tagged with the actor.
2. **Report writes.** A configured HTTP endpoint receives every update applied to a doc, with
   its actor, batched per doc, in order per doc, signed, with at-least-once delivery and a signal
   when something was lost (see [Gaps](#gaps) for what the receiver must do with it).

The two are independent and both are off by default.

### Differences from upstream with both switches off

With `Y_SWEET_ATTRIBUTED_TOKENS` off and no webhook URL, no attributed token is minted, no update
observer runs and nothing is sent anywhere. The binary still differs from upstream Y-Sweet in
these ways:

- **It verifies attributed tokens.** A token minted by a server with the switch on is accepted
  (upstream rejects it with `401`). This is what makes a rolling deploy safe.
- **Graceful shutdown on `SIGTERM`.** Upstream `serve` handles only Ctrl+C (`SIGINT`); `SIGTERM`
  kills it at once. Here both run the ordered shutdown described under [Shutdown](#shutdown).
  That also changes what happens on `SIGINT`, the signal the Dalus deployments stop Y-Sweet
  with: requests in flight are finished before docs are saved, writes arriving after that are
  refused with `503`, and a final save that fails is retried. Upstream waited for the final
  saves without limit; here they have until `Y_SWEET_SHUTDOWN_TIMEOUT_SECONDS` (default 110)
  after the signal, and docs still unsaved then are named in the log. A stop signal during
  startup exits cleanly.
- **New log lines.** `minted doc token` (info) on every mint when auth is set, and, when an auth
  request carries an oversize `userId` or `writer`, `auth request actor too long` (warn). The
  debug line for `as-update` logs the size of the update instead of its contents.
- **New CLI flags** (`--attributed-tokens`, `--update-webhook-*`). An upstream binary refuses to
  start with them; the environment-variable forms are simply ignored by it.
- **A doc edit no longer panics** when its persistence worker has already stopped (upstream
  `unwrap`s a send on the closed channel, under the doc lock).
- **Edits are not lost to doc garbage collection or checkpoints.** Upstream can unload an idle
  doc while an HTTP write to it is being applied (the write is then acknowledged and never
  saved), and a checkpoint that is still writing can clear the unsaved mark of an edit made
  meanwhile. Here an unloaded doc is saved before it is dropped, and kept (and retried) if that
  save fails; a save already sent is never abandoned, so an older snapshot cannot land over a
  newer one. A doc being written to is not unloaded. A writer waits at most 15 s for its doc
  (loading it, or waiting for one being unloaded), else `503`, so a hung store makes writes to
  that doc fail fast rather than hang. Two requests
  that load the same doc at once share one load; upstream could let the second replace the
  first while it was being written to, losing those writes.

- **A new way for one doc to be unavailable, for a while.** The price of the point above:
  while the store write that saves an idle doc before it is unloaded is stalled, that doc
  stays "being unloaded", and every HTTP update and websocket connection for it is answered
  `503` after a 15 s wait. It ends when the write completes or fails; the doc is then usable
  again. With an S3 store a stalled write fails after the request timeout (60 s by default,
  see [Store timeouts](#store-timeouts)), so this lasts about a minute, not until a restart.
  Other docs are unaffected. Upstream never waited: it dropped the doc at once, losing
  whatever was not saved.
- **S3 requests time out.** Upstream's S3 client waits on a request without limit. Here a
  request the endpoint does not answer fails, and whatever made it retries (see
  [Store timeouts](#store-timeouts)).

The request and response formats of every endpoint are unchanged. `userId` and `writer` in the
auth request are accepted and ignored, as upstream does (upstream ignores `writer` as an unknown
field), whatever their length.

The design and its rationale are in [attributed-updates-design.md](attributed-updates-design.md).
This page is for whoever runs the server or writes the receiver.

## Configuration

All of these apply to `y-sweet serve` only. `serve-doc` has neither feature.

| Variable | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `Y_SWEET_SHUTDOWN_TIMEOUT_SECONDS` | `--shutdown-timeout-seconds` | `110` | How long a graceful shutdown may take in all; docs are saved until then. Applies whether or not the two features are on. See [Shutdown](#shutdown). |
| `Y_SWEET_S3_REQUEST_TIMEOUT_SECONDS` | (none) | `60` | How long the S3 store waits on a request before failing it. Applies to every command that uses an S3 store, whether or not the two features are on. See [Store timeouts](#store-timeouts). |
| `Y_SWEET_ATTRIBUTED_TOKENS` | `--attributed-tokens [true\|false]` | `false` | Mint tokens that carry the actor of the auth request. |
| `Y_SWEET_UPDATE_WEBHOOK_URL` | `--update-webhook-url` | unset | Where update batches are POSTed. Unset means no observer and no dispatcher. Must be `http` or `https`. |
| `Y_SWEET_UPDATE_WEBHOOK_SECRET` | `--update-webhook-secret` | unset | HMAC secret. Required when the URL is set; without it the webhook stays off (see below). |
| `Y_SWEET_UPDATE_WEBHOOK_BATCH_MS` | `--update-webhook-batch-ms` | `1000` | How long one doc's updates are collected before a batch is sent. |
| `Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES` | `--update-webhook-max-bytes` | `268435456` | Upper bound on the memory held by updates awaiting delivery, across all docs, as estimated per update; see [Sizing](#sizing). |
| `Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY` | `--update-webhook-concurrency` | `16` | How many webhook requests may be in flight at once, across all docs. From 1 to 1024. |
| `Y_SWEET_UPDATE_WEBHOOK_CA_FILE` | `--update-webhook-ca-file` | unset | PEM file of extra CA certificates to trust for the webhook URL, in addition to the bundled public roots. For a receiver behind a private CA. If the file cannot be read or holds no certificate the webhook stays off (see below). |

A variable that is set but empty, or holds only whitespace, counts as unset for every setting
in this table, so passing the variables through an environment that does not define them (an
env file, a compose file) is safe. Whitespace around a value is ignored, except in the secret
(below).

`Y_SWEET_ATTRIBUTED_TOKENS` accepts exactly these values, in any letter case: `true`, `1`,
`yes`, `on` for on; `false`, `0`, `no`, `off` for off. Anything else is a startup error: the
switch decides what tokens are minted, so a typo must not silently pick one.

`Y_SWEET_SHUTDOWN_TIMEOUT_SECONDS` and `Y_SWEET_S3_REQUEST_TIMEOUT_SECONDS` are whole numbers
of seconds, kept within 1 and 86400. A value that is not a number does not stop the server: it
logs one error, `timeout setting is not a whole number of seconds; using the default` (with
the variable's name as `setting`), and runs with the default. For the shutdown timeout, the
`attributed updates configuration` line shows the value in use.

**A mistake in the webhook settings does not stop the server.** The webhook is optional, and
this server is the only copy of the sync service, so a malformed URL, a URL without a secret, a
`..._BATCH_MS`, `..._MAX_BYTES` or `..._CONCURRENCY` that is not a valid number, or a CA file
that cannot be used makes the server log one error,
`update webhook configuration is invalid; starting with the update webhook DISABLED` (with the
reason, never the URL or the secret), and start without the webhook. Check for that line, or for
`update_webhook_enabled=false` on the `attributed updates configuration` line, after changing
these settings. Prefer the environment
variable for the secret: a flag is visible in the process list. On the command line,
`--attributed-tokens` reads the next argument as its value: `--attributed-tokens false` is off,
`--attributed-tokens=true` and `--attributed-tokens true` are on, and a bare `--attributed-tokens`
is on only as the last argument. `--attributed-tokens /data` is an error (it would otherwise be
ambiguous between "on, store `/data`" and a typo); write `--attributed-tokens=true /data`. The secret is used as the HMAC key
exactly as given, including any leading or trailing whitespace; whitespace only decides whether
it counts as set.

Example:

```sh
docker run --rm -p 8080:8080 \
  -e Y_SWEET_AUTH="<private key from y-sweet gen-auth>" \
  -e Y_SWEET_ATTRIBUTED_TOKENS=true \
  -e Y_SWEET_UPDATE_WEBHOOK_URL="https://app.example.com/api/internal/y-sweet/updates" \
  -e Y_SWEET_UPDATE_WEBHOOK_SECRET="<shared secret>" \
  y-sweet-fork:dev-1839 \
  y-sweet serve --host 0.0.0.0 --prod /data
```

### Store timeouts

The S3 store gives up on a request the endpoint does not answer, so that a stalled connection
turns into an error that is retried instead of a save or a load that never ends:

- **Connecting** (TCP and TLS): 10 s.
- **Until the response starts**: `Y_SWEET_S3_REQUEST_TIMEOUT_SECONDS` (default 60), plus one
  second for every MiB of request body. A save of a 200 MiB doc therefore has 260 s; a link
  to the store slower than 1 MiB/s needs a higher setting to save docs larger than it can
  upload in the base time.
- **Reading a response** (loading a doc): the same setting for each chunk, so a download may
  take any time as long as it keeps moving.

A request that times out fails like any other store error: a checkpoint save is tried again at
the next checkpoint, the final save at shutdown is retried within the shutdown timeout, a doc
that could not be saved before being unloaded stays loaded and writable, and a load answers
`500` and is started afresh by the next request. The log line is the usual one for a failed
save (`Error persisting.`, or `could not save the doc being collected; keeping it loaded`),
with `Timed out after ... ms waiting for the S3-compatible API.` as the error.

Timing out closes the request's connection, so nothing of an abandoned save is still being
sent when the next one starts, and saves of one doc never overlap: each begins only when the
one before has succeeded or failed, and holds a newer copy of the whole doc. One case cannot
be excluded from this side: a store that had already received a save in full when the
connection was closed, and applies it only after a later save of the same doc has been
applied. The older copy would then be the stored one until the doc is saved again. S3 applies
a write before it answers, so for this the answer has to be more than the timeout late while
the retry overtakes it. The same exposure exists, as upstream, for any save whose connection
breaks after the body was sent.

The filesystem store has no timeout. Neither has the Cloudflare worker build, where the
platform bounds requests.

### Sizing

`Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES` is a budget for memory, not for update bytes. Every update
held anywhere in the pipeline is charged an estimate of the most it occupies there:

- 4/3 of its size, because it is sent as base64 (while it waits it is held raw, which is less);
- the lengths of its doc id and of its actor's `user_id` and `writer`;
- a fixed 256 bytes for the structures around it and its JSON framing.

So a 1-byte edit is charged about 260 bytes and a 1 MiB update about 1.33 MiB, and the budget
tracks real memory whether the receiver is behind on a few large updates or on hours of tiny
ones. With the budget full, the pipeline holds about the configured value. Two things are not in
the estimate: allocator overhead, and one batch at a time being serialized (its raw and encoded
forms coexist for a moment, at most about 19 MiB for an 8 MiB update). Give the container the
budget plus about 15% on top of what the server needs for its docs: roughly 300 MiB for the
default 256 MiB. The default holds about 190 MiB of large updates, or about a million small
edits. To fit a smaller container, lower the budget; a receiver outage then turns into gaps
sooner, which costs attribution, not correctness, as long as the receiver resyncs (see
[Gaps](#gaps)).

The other limits (8 MiB per update, 1 MiB per batch) and the `bytes` field in the logs remain in
update bytes; `held_bytes` in the logs is in budget units.

### Private CA

The webhook client trusts the public roots bundled into the binary, not the operating system's
store. A receiver whose certificate is issued by a private CA (on-prem, internal PKI) fails every
delivery with `error_kind=connect` until that CA is added with `Y_SWEET_UPDATE_WEBHOOK_CA_FILE`
(one or more PEM certificates in one file). The bundled roots stay trusted alongside it. The file
is read once, at startup.

## Attributed tokens

`POST /doc/:doc_id/auth` accepts two optional fields that describe who the token is for:

```json
{ "authorization": "full", "userId": "user_123", "writer": "ui" }
```

- `userId`: opaque, at most 128 bytes.
- `writer`: opaque, at most 64 bytes. The application owns the taxonomy (`ui`, `agent`, ...).

A longer value is rejected with `400` when the switch is on. With the switch off the fields are
ignored, as upstream does, and the request succeeds with a plain token; the server logs
`auth request actor too long` (warn, with the lengths only, never the values) so that the
problem shows up before the switch is turned on. The response (`ClientToken`) is unchanged.

What gets minted:

| `Y_SWEET_ATTRIBUTED_TOKENS` | Request has `userId` or `writer` | Token |
| --- | --- | --- |
| off | either | plain doc token, as before; the fields are ignored |
| on | no | plain doc token, as before |
| on | yes | attributed doc token |

Every write through an attributed token is tagged with its actor: websocket `Update` and
`SyncStep2` messages, and `POST /d/:doc_id/update` with the token as the bearer. Writes with the
server token, with a plain doc token, or on a server without auth are unattributed (`actor: null`).

### Turning it on and off

A binary without this feature cannot decode an attributed token and rejects it with `401`. So:

- **On:** only set `Y_SWEET_ATTRIBUTED_TOKENS=true` once every Y-Sweet instance that might
  verify the tokens runs a version with this feature. Old tokens keep verifying; nobody has to
  reconnect.
- **Off / rollback:** an older image cannot decode attributed tokens. Deploying it while
  attributed tokens are outstanding rejects **every** one of them with `401` until it expires:
  every browser tab and server connection minted while the switch was on is locked out. The safe
  order is:
  1. Unset `Y_SWEET_ATTRIBUTED_TOKENS` (or set it to `false`) and deploy that. New tokens are
     plain again; outstanding attributed tokens still verify on this image.
  2. Wait out the longest token lifetime in use: the largest `validForSeconds` any client mints
     with (Dalus mints browser tokens for up to 3600 s; the server default is one hour too).
  3. Only then deploy the older image.

  Turning the webhook off needs no such care: unset the URL and restart.

## The update webhook

### Request

`POST` to the configured URL, `Content-Type: application/json`:

```json
{
  "doc_id": "my-doc",
  "instance_id": "V1StGXR8_Z5jdHi6B-myT",
  "seq_start": 41,
  "seq_end": 42,
  "gap_before": false,
  "events": [
    {
      "seq": 41,
      "actor": { "user_id": "user_123", "writer": "ui" },
      "update": "AAEC...",
      "occurred_at": "2026-11-10T12:00:00.000Z"
    },
    { "seq": 42, "actor": null, "update": "...", "occurred_at": "2026-11-10T12:00:00.250Z" }
  ]
}
```

- `instance_id`: random. It changes on every process start, and can also change while the
  process runs (see [Gaps](#gaps)). Never assume one id per process.
- `seq`: unique per `instance_id`, increasing within a doc, **not contiguous** within a doc
  (one counter serves all docs). `(instance_id, seq)` is the idempotency key.
- `seq_start` / `seq_end`: first and last `seq` in `events`; both `null` when `events` is empty.
- `actor`: `null` for an unattributed write. Otherwise an object with both keys always present;
  either value may be `null`.
- `update`: standard base64 (with padding) of a Yjs **v1** update. It is what the transaction
  changed, as re-encoded by the server, not the bytes the client sent: anything the server
  already held is absent, and a write that changed nothing produces no event at all.
- `occurred_at`: when the server applied the update, UTC, millisecond precision.
- Updates in a batch are never merged, so each keeps its own actor.

A batch closes after the batch window, at 256 events, or at 1 MiB of update bytes. An update
larger than 1 MiB travels alone; one larger than 8 MiB is not delivered at all (the doc is
gapped instead). The largest possible body is therefore one 8 MiB update, about 11 MiB as JSON:
**the receiver must accept bodies of 12 MiB.**

### Verifying the signature

Two headers accompany every request:

- `X-Y-Sweet-Timestamp`: unix seconds at the time of *this attempt*.
- `X-Y-Sweet-Signature`: `sha256=` followed by the lowercase hex HMAC-SHA256, keyed with the
  secret, of the timestamp, a `.`, and the raw request body.

```ts
import { createHmac, timingSafeEqual } from 'node:crypto';

function verify(secret: string, timestamp: string, signature: string, rawBody: Buffer): boolean {
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false; // replay window
  const expected =
    'sha256=' + createHmac('sha256', secret).update(`${timestamp}.`).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(signature);
  return a.length === b.length && timingSafeEqual(a, b);
}
```

Verify against the raw bytes, before any JSON parsing. A retried batch has the same body but a
fresh timestamp and signature, so a batch that has been retrying for minutes still falls inside
the receiver's tolerance.

### Responses and retries

| Receiver answers | Server does |
| --- | --- |
| any `2xx` | Batch is acknowledged. |
| timeout (10 s), connection error, `408`, `429`, any `5xx` | Retries the same batch: 0.5 s, 1 s, 2 s, ... capped at 30 s, for up to 10 minutes. Then drops it. |
| anything else (`3xx`, other `4xx`) | Drops the batch immediately. Redirects are not followed. |

A `429` or `503` may carry `Retry-After`, as delta-seconds (`Retry-After: 30`) or an HTTP-date.
When it asks for longer than the backoff would wait, the server waits that long instead, but
never beyond the 10 minute retry limit: a batch told to wait past it gets one last attempt when
the limit is reached and is dropped if that fails too. `Retry-After` applies to the batch that
received it; other docs keep their own schedule.

One batch per doc is in flight at a time, so a doc's batches arrive in order; different docs are
delivered concurrently and do not block each other. While a doc's batch is retrying, up to 64
later batches wait behind it; beyond that the oldest waiting batch is dropped.

Across docs, at most `Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY` (default 16) requests are open at once.
This matters when the receiver comes back after an outage: every doc with a backlog is ready to
send, and without a cap they would all POST at once, each body up to 12 MiB. With the default, the
receiver sees at most 16 concurrent requests from one server, so at most about 16 x 12 MiB of
request bodies in flight; size its body buffering and worker count for that, times the number of
Y-Sweet servers. A batch waiting for a slot is still in flight as far as its doc is concerned, so
ordering is unaffected; the wait counts toward its 10 minute retry limit, so a batch that cannot
get a slot in time is dropped (and its doc gapped) like one that kept failing. The slot is held for the request only, not while a batch waits out its
retry delay, so docs that are backing off do not hold up the others.

Delivery is at-least-once: a batch whose `2xx` was lost on the way back is sent again. Deduplicate
on `(instance_id, seq)`.

### Gaps

Nothing is spooled to disk. When the server has to give up on updates, it tries to tell the
receiver instead of pretending. But the record of what was lost lives in memory too, and can be
lost with everything else. There are two signals, and they mean different things:

- **`gap_before: true`** on a batch means: since the last batch you acknowledged for this doc, at
  least one update was applied to *this doc* that you were not, and will not be, sent.
- **An `instance_id` the receiver has not seen before** means: the server lost its in-memory
  state, through a restart or a reset of its gap tracking (below). It may have lost gaps for
  **any** doc, not just the one in this batch. A doc whose gap was lost is not told about it
  separately, and if it is never written again it gets no batch at all.

Where `gap_before` lands: on the **first batch delivered for that doc after the loss**, whatever
that batch is. If the doc has later updates, that is the batch carrying them (its own events were
not lost; the loss was before them). If it has nothing else to send, the server sends an **empty
batch** (`"events": []`) just to carry the flag, after one batch window (below). Either way the
flag rides on exactly one acknowledged batch; if that batch is rejected or dropped, the flag moves
on to the next one.

So the receiver contract is:

1. On `gap_before: true`, resync that doc.
2. **On an `instance_id` it has not seen before, treat every doc it has received batches for
   under any other `instance_id` as possibly gapped, and resync each of them**, not only the doc
   in the batch that carried the new id. With one Y-Sweet server these are the docs seen under
   the previous id. With several servers the receiver cannot tell which id the new one replaced,
   so it resyncs every doc it knows that it has not yet seen under the new id; resyncing a doc
   that had no gap is harmless.

Resync means: fetch the doc's full state from `GET /d/:doc_id/as-update` and reconcile.
Attribution for the missed span is lost. Do not try to infer gaps from `seq`; it is not
contiguous.

Even with that contract one blind spot remains: the new `instance_id` arrives only with the next
batch the server sends, for any doc. If the server restarts (or resets) and then nothing is
written anywhere, the receiver hears nothing until something is. A receiver that needs a bound on
how long a lost update can go unnoticed must also reconcile on its own: for example resync a doc
when it is next opened, or on a schedule.

What causes a gap:

| Cause | In the log |
| --- | --- |
| An update larger than 8 MiB | `oversize` count on `events dropped` |
| The byte budget (`..._MAX_BYTES`) is exhausted | `budget` count on `events dropped` |
| The dispatcher is not keeping up (4096 events buffered) | `channel_full` count on `events dropped` |
| More than 64 batches waiting for one doc | `reason=queue_overflow` on `batch dropped` |
| The receiver rejected a batch | `reason=status` on `batch dropped` |
| A batch kept failing for 10 minutes | `reason=retry_age` on `batch dropped` |

If a doc is gapped and nobody edits it again, the server sends a batch with `"events": []`,
`"seq_start": null`, `"seq_end": null` and `"gap_before": true` after one batch window, so the
receiver learns of the gap without waiting for the next edit. If that batch is rejected too, the
server keeps trying with the retry backoff (up to one attempt per 30 s per gapped doc) until one
is acknowledged, or until the process stops or resets its gap tracking.

That bookkeeping is bounded. While the receiver rejects everything, every doc that is written
ends up remembered as "gapped, nothing else to send". Once more than 4096 docs are in that state
the server forgets all of them, aborts their empty-batch deliveries, and switches to a fresh
`instance_id` for everything it sends from then on. **This drops the per-doc gap signal for those
docs**: none of them gets `gap_before: true` or an empty gap batch afterwards. What is left is the
new `instance_id` on the next batch sent for any doc, which is why rule 2 above says to resync
every doc, not just the one in that batch. `seq` keeps counting across the switch. Docs with
updates still waiting keep their state and their own `gap_before`; their later batches carry the
new id. The server logs `update webhook gap tracking reset` when this happens.

The receiver must therefore accept: an empty `events` array, `null` sequence bounds, `actor: null`,
and an `instance_id` it has never seen.

### Shutdown

`y-sweet serve` shuts down gracefully on `SIGINT` (Ctrl+C; also what the Dalus images and the
on-prem compose file set as the stop signal) and on `SIGTERM` (what `docker stop` and ECS send by
default). Either one runs these stages:

| Stage | What happens | Time limit |
| --- | --- | --- |
| 1 | Stop accepting connections; tell every websocket to close. | (immediate) |
| 2 | Let in-flight HTTP requests finish and websockets close, then close the write gate, whether or not they did: from here on a write is refused (`503` on HTTP; a websocket is dropped without applying the message, and the client resends on reconnect), including one that was still loading its doc or receiving its body. Writes already applying finish first. No write is acknowledged after this point. | 5 s |
| 3 | Stop every doc's persistence worker; each makes a final save to the store, retrying a save that fails (after 0.25 s, 0.5 s, ... up to every 5 s). | until the shutdown timeout |
| 4 | Stop the update webhook; it flushes everything applied above. Starts when the saves are done, or beside them once only 7 s of the shutdown timeout are left. | 7 s (the flush itself has 5 s) |

**The shutdown timeout** is `Y_SWEET_SHUTDOWN_TIMEOUT_SECONDS`, default **110 s**, counted from
the stop signal. Saving docs is the stage that must not be cut short, so it gets all of it; the
connection stage and the webhook flush are the bounded, expendable ones and never take time from
the saves. Set the timeout a little below what the platform allows between the stop signal and
killing the process:

- The default fits the Dalus ECS task, whose `stopTimeout` is 120 s: 110 s for the saves, 10 s
  to exit.
- Where the platform allows less (Docker's default is 10 s; the on-prem compose file sets
  `stop_grace_period: 30s`), the platform kills the process at its own limit whatever this
  setting says. Until then the saves keep running, exactly as upstream's did, so the default
  loses nothing there; but lower the setting (to 25 for a 30 s grace period) to get the webhook
  flush and the log lines below before the kill. Better still, raise the platform's limit.
- With stages 2 and 4 at their limits, the short timeouts leave little for saving: at 30 s the
  saves have the whole 30 s, the flush runs in the last 7 s of it.

If the timeout is reached with saves unfinished (a store that is down or very slow), the server
logs one error per doc, `doc not saved before the shutdown deadline; its changes since the last
save are lost` with its `doc_id`, then `shutdown stage did not finish in time` with
`stage=persist` and `unsaved_docs`, and exits. A failed attempt logs `final save failed;
retrying`. The other stages log `shutdown stage did not finish in time` (warn) with their `stage`
(`http`, `websockets`, `write_gate` or `webhook`) and `budget_ms` when they overrun, and the next
stage starts anyway. `shutdown started` (with `budget_ms`) and `shutdown finished` (with
`elapsed_ms`) bracket the whole thing.

The flush stops accepting new updates into the pipeline, stops retrying, closes every open batch
and makes one delivery attempt per undelivered batch, in order per doc, within the concurrency
cap. The whole flush, including serializing the batches, has five seconds. Whatever does not
make it is lost; the receiver learns of it only through the new `instance_id` after the restart
(rule 2 under [Gaps](#gaps)). It never delays or shortens the doc saves.

A signal that arrives during startup, for example while the store is still being initialised,
abandons startup and exits at once; nothing has been served yet, so there is nothing to save or
flush. A `SIGKILL`, or a stop timeout shorter than the flush, skips all of this.

### What `actor` means, and where it is not the author

`actor` is **the token that delivered the update to this server process**. That is usually the
author. It is not proof of authorship, and in these cases it differs:

- **After an unclean restart.** If the server stopped without saving (a crash, a `SIGKILL`, a
  shutdown that ran out of time), edits it had acknowledged are gone from it but still held by
  the clients that saw them. Whichever client reconnects first sends everything the server
  lacks in its `SyncStep2`, including other users' edits it had received before the restart.
  The server reports all of it under that client's actor. And if those updates had already
  been delivered to the receiver before the restart, they are delivered again, as new events
  (new `instance_id`, new `seq`) with a different actor. A receiver that keeps attribution
  should treat an event whose content it already has as a duplicate, not as a new write by the
  new actor.
- **An update with a missing dependency.** An update that depends on something the server has
  not received yet is held back, and is integrated by whichever later write supplies the
  missing piece. It is then reported in *that* write's event, under *that* write's actor. This
  needs out-of-order delivery across writers and is rare.
- **A full-state push over HTTP.** A writer that falls back to `POST /d/:doc_id/update` with
  its whole doc state (as the Dalus server connection does for unacknowledged updates) is
  reported as the actor of everything in that state the server did not have yet, whoever made
  it.
- **A reconnecting client's own offline edits** are attributed to it, which is right; they are
  the ordinary case of the first point. The parts the server already had produce nothing.

## Logs

Everything below is emitted with `tracing` as structured fields. The message text is stable and
is the thing to filter on. Update bytes, user ids, tokens and the secret are never logged, at any
level; the webhook URL appears only as its host.

| Level | Message | Fields |
| --- | --- | --- |
| info | `attributed updates configuration` | `attributed_tokens`, `shutdown_timeout_seconds`, `update_webhook_enabled`, `update_webhook_host`, `update_webhook_batch_ms`, `update_webhook_max_bytes`, `update_webhook_concurrency`, `update_webhook_ca_file` (whether one is set; the last five only when enabled). Once, at startup. |
| info | `update webhook dispatcher starting` | `instance_id` |
| info | `minted doc token` | `doc_id`, `attributed`, `actor_requested`, `writer` |
| debug | `websocket opened with actor` | `doc_id`, `writer`, `has_user_id` |
| info | `update webhook batch sent` | `doc_id`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `gap_before` |
| warn | `update webhook batch retry` | `doc_id`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `error_kind`, `age_ms`, `retry_after_ms`, `retry_in_ms` |
| warn | `update webhook batch dropped` | `doc_id`, `reason`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `age_ms` |
| warn | `update webhook events dropped` | `oversize`, `budget`, `channel_full`, `closed`, `dropped_events_total`, `held_bytes` |
| warn | `update webhook gap tracking reset` | `discarded_docs`, `instance_id` (the new one) |
| warn | `auth request actor too long` (full message: `auth request actor too long; ignored, would be rejected with attributed tokens on`) | `doc_id`, `user_id_bytes`, `writer_bytes`, `max_user_id_bytes`, `max_writer_bytes`. Only with the switch off. |
| info | `shutdown started` / `shutdown finished` | `budget_ms` on the first, `elapsed_ms` on the second |
| warn / error | `shutdown stage did not finish in time` | `stage`, `budget_ms`; for `persist` (error): `unsaved_docs`, `workers_left` |
| error | `doc not saved before the shutdown deadline` (full message continues `; its changes since the last save are lost`) | `doc_id`. One per unsaved doc. |
| warn | `final save failed; retrying` | `retry_in_ms`; in the `save_loop` span, which carries the `doc_id` |
| error | `update webhook configuration is invalid; starting with the update webhook DISABLED` | `error` (the reason; never the URL or the secret) |
| error | `timeout setting is not a whole number of seconds; using the default` | `setting` (the variable's name), `default_seconds`. The rejected value is not logged. |
| info | `update webhook shutdown: nothing to flush` / `update webhook shutdown flush done` | `docs`, `batches`, `delivered` |
| warn | `update webhook shutdown flush incomplete` | `docs`, `batches`, `delivered`, `timed_out` |

Field notes:

- `bytes` is update bytes (before base64), the unit the limits and the budget are expressed in.
- `seq_start` / `seq_end` are absent on an empty gap batch.
- `status` is the HTTP status; absent when there was no response, in which case `error_kind` is
  `timeout`, `connect` or `request`. A `connect` error against an `https` receiver that is
  reachable usually means its certificate is not trusted (see [Private CA](#private-ca)).
- `retry_after_ms` is the receiver's `Retry-After`, when a `429` or `503` sent one;
  `retry_in_ms` is the delay actually used.
- `reason` on a dropped **batch**: `status`, `retry_age`, `queue_overflow`, `shutdown`.
  `attempt`, `status` and `age_ms` are absent for `queue_overflow` (the batch was never sent).
- `update webhook events dropped` is one line per dispatcher tick (at most every 250 ms) in which
  updates were dropped before reaching a batch. `oversize`, `budget`, `channel_full` and `closed`
  count the drops since the previous such line, by cause; `dropped_events_total` is the total
  since the process started. The line has no `doc_id`: the code that drops an update runs while
  the doc is locked and must not write logs. The affected docs show up as `gap_before=true` on
  their next `update webhook batch sent` line. (`closed` counts updates that arrived after the
  dispatcher shut down; nothing is left to report those, so expect it to be 0.)
- `actor_requested` on `minted doc token` is true when the request carried `userId` or `writer`.
  `actor_requested=true attributed=false` means the app is asking for attribution and the switch
  is off.
- Dispatcher lines are inside the `update_webhook` span.

What to watch:

- **Is it on?** The `attributed updates configuration` line at startup.
- **Are tokens attributed?** `minted doc token` with `attributed=true`.
- **Is delivery healthy?** `update webhook batch sent` with `attempt=1` and `gap_before=false`.
  A rising `attempt`, or any `update webhook batch retry`, means the receiver is slow or failing.
- **Is anything being lost?** Any `update webhook batch dropped`, `update webhook events dropped`
  or `update webhook gap tracking reset`.
  `reason=status` points at the receiver (check the `status`: `401` is a secret mismatch, `413` a
  body limit below 12 MiB). `reason=budget` or `channel_full` means the receiver has been down or
  slow long enough to fill the server's memory bound; `held_bytes` shows how full it is.
  `update webhook gap tracking reset` means the receiver has been rejecting batches for more than
  4096 docs; the per-doc gap signals for those docs are gone, and only the new `instance_id`
  tells the receiver to resync (rule 2 under [Gaps](#gaps)).

To see the debug line, raise the level for this crate, e.g. `RUST_LOG=info,y_sweet=debug`.

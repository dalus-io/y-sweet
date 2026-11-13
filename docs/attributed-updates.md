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
  kills it at once. Here both run the ordered, time-bounded shutdown described under
  [Shutdown](#shutdown), which also changes what happens on `SIGINT`: requests in flight are
  finished before docs are saved, writes arriving after that are refused with `503`, and the
  whole shutdown is bounded at about 22 s. A stop signal during startup exits cleanly.
- **New log lines.** `minted doc token` (info) on every mint when auth is set, and, when an auth
  request carries an oversize `userId` or `writer`, `auth request actor too long` (warn). The
  debug line for `as-update` logs the size of the update instead of its contents.
- **New CLI flags** (`--attributed-tokens`, `--update-webhook-*`). An upstream binary refuses to
  start with them; the environment-variable forms are simply ignored by it.
- **A doc edit no longer panics** when its persistence worker has already stopped (upstream
  `unwrap`s a send on the closed channel, under the doc lock).

The request and response formats of every endpoint are unchanged. `userId` and `writer` in the
auth request are accepted and ignored, as upstream does (upstream ignores `writer` as an unknown
field), whatever their length.

The design and its rationale are in [attributed-updates-design.md](attributed-updates-design.md).
This page is for whoever runs the server or writes the receiver.

## Configuration

All of these apply to `y-sweet serve` only. `serve-doc` has neither feature.

| Variable | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `Y_SWEET_ATTRIBUTED_TOKENS` | `--attributed-tokens [true\|false]` | `false` | Mint tokens that carry the actor of the auth request. |
| `Y_SWEET_UPDATE_WEBHOOK_URL` | `--update-webhook-url` | unset | Where update batches are POSTed. Unset means no observer and no dispatcher. Must be `http` or `https`. |
| `Y_SWEET_UPDATE_WEBHOOK_SECRET` | `--update-webhook-secret` | unset | HMAC secret. Required when the URL is set; the server refuses to start without it. |
| `Y_SWEET_UPDATE_WEBHOOK_BATCH_MS` | `--update-webhook-batch-ms` | `1000` | How long one doc's updates are collected before a batch is sent. |
| `Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES` | `--update-webhook-max-bytes` | `268435456` | Upper bound on update bytes held in memory awaiting delivery, across all docs. Actual memory use can reach about 1.5 times this; see [Sizing](#sizing). |
| `Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY` | `--update-webhook-concurrency` | `16` | How many webhook requests may be in flight at once, across all docs. At least 1. |
| `Y_SWEET_UPDATE_WEBHOOK_CA_FILE` | `--update-webhook-ca-file` | unset | PEM file of extra CA certificates to trust for the webhook URL, in addition to the bundled public roots. For a receiver behind a private CA. The server refuses to start if the file cannot be read or holds no certificate. |

A variable that is set but empty counts as unset, so passing the variables through an environment
that does not define them is safe. `Y_SWEET_ATTRIBUTED_TOKENS` accepts `true`/`false`
(also `1`/`0`, `yes`/`no`, `on`/`off`); anything else is a startup error. Prefer the environment
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

### Sizing

`Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES` counts raw update bytes. A batch is serialized when its
delivery starts, and the request body is base64 plus JSON, about 1.4 times the update bytes it
carries. So with the budget full and much of it in flight, the pipeline can hold about **1.4 to
1.5 times** the configured value. Size the container for that on top of what the server needs for
its docs: the default 256 MiB budget needs about 384 MiB of headroom. To fit a smaller container,
lower the budget; a receiver outage then turns into gaps sooner, which costs attribution, not
correctness, as long as the receiver resyncs (see [Gaps](#gaps)).

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

`y-sweet serve` shuts down gracefully on `SIGINT` (Ctrl+C) and on `SIGTERM` (what `docker stop`
and an ECS task stop or scale-in send). Either one runs these stages, in order, each with a time
budget:

| Stage | What happens | Budget |
| --- | --- | --- |
| 1 | Stop accepting connections; tell every websocket to close. | (immediate) |
| 2 | Let in-flight HTTP requests finish and websockets close, then close the write gate, whether or not they did: from here on a write is refused (`503` on HTTP; a websocket is dropped without applying the message, and the client resends on reconnect), including one that was still loading its doc or receiving its body. Writes already applying finish first. No write is acknowledged after this point. | 5 s |
| 3 | Stop every doc's persistence worker; each makes a final save to the store. | 10 s |
| 4 | Stop the update webhook; it flushes everything applied above. | 7 s (the flush itself has 5 s) |

The whole shutdown therefore takes at most about 22 s, inside the 30 s an ECS task gets between
`SIGTERM` and `SIGKILL` when its definition sets no `stopTimeout` (the Dalus y-sweet task sets
none). A stage that runs out of time logs `shutdown stage did not finish in time` (warn) with
`stage` (`http`, `websockets`, `write_gate`, `persist` or `webhook`) and `budget_ms`, and the next
stage starts anyway. A `persist` timeout (a slow or unreachable store) means docs that were still
saving lose what was not saved before; `workers_left` says how many. `shutdown started` and
`shutdown finished` (with `elapsed_ms`) bracket the whole thing.

The flush stops accepting new updates into the pipeline, stops retrying, closes every open batch
and makes one delivery attempt per undelivered batch, in order per doc, within the concurrency
cap. The whole flush, including serializing the batches, has five seconds, well inside the
default 30 s ECS stop timeout. Whatever does not make it is lost; the receiver learns of it only
through the new `instance_id` after the restart (rule 2 under [Gaps](#gaps)). It runs after the
docs are saved, so it does not delay them.

A signal that arrives during startup, for example while the store is still being initialised,
abandons startup and exits at once; nothing has been served yet, so there is nothing to save or
flush. A `SIGKILL`, or a stop timeout shorter than the flush, skips all of this.

### Attribution is "who made it visible"

Two properties of the underlying CRDT are worth knowing when reading `actor`:

- An update that depends on something the server has not received yet is held back, and is
  integrated by whichever later write supplies the missing piece. It is then reported in *that*
  write's event, under *that* write's actor. This needs out-of-order delivery across writers and
  is rare, but `actor` is "the writer whose write made this content visible", not proof of
  authorship.
- A reconnecting client replays its offline edits in a `SyncStep2`; those are attributed to that
  client, correctly. The parts the server already had produce nothing.

## Logs

Everything below is emitted with `tracing` as structured fields. The message text is stable and
is the thing to filter on. Update bytes, user ids, tokens and the secret are never logged, at any
level; the webhook URL appears only as its host.

| Level | Message | Fields |
| --- | --- | --- |
| info | `attributed updates configuration` | `attributed_tokens`, `update_webhook_enabled`, `update_webhook_host`, `update_webhook_batch_ms`, `update_webhook_max_bytes`, `update_webhook_concurrency`, `update_webhook_ca_file` (whether one is set; the last five only when enabled). Once, at startup. |
| info | `update webhook dispatcher starting` | `instance_id` |
| info | `minted doc token` | `doc_id`, `attributed`, `actor_requested`, `writer` |
| debug | `websocket opened with actor` | `doc_id`, `writer`, `has_user_id` |
| info | `update webhook batch sent` | `doc_id`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `gap_before` |
| warn | `update webhook batch retry` | `doc_id`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `error_kind`, `age_ms`, `retry_after_ms`, `retry_in_ms` |
| warn | `update webhook batch dropped` | `doc_id`, `reason`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `age_ms` |
| warn | `update webhook events dropped` | `oversize`, `budget`, `channel_full`, `closed`, `dropped_events_total`, `held_bytes` |
| warn | `update webhook gap tracking reset` | `discarded_docs`, `instance_id` (the new one) |
| warn | `auth request actor too long` (full message: `auth request actor too long; ignored, would be rejected with attributed tokens on`) | `doc_id`, `user_id_bytes`, `writer_bytes`, `max_user_id_bytes`, `max_writer_bytes`. Only with the switch off. |
| info | `shutdown started` / `shutdown finished` | `elapsed_ms` on the second |
| warn | `shutdown stage did not finish in time` | `stage`, `budget_ms`, `workers_left` (for `persist`) |
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

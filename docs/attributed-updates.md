# Attributed updates and the update webhook

This fork of Y-Sweet can do two things upstream cannot:

1. **Attribute writes.** A doc token can carry an *actor* (an opaque user id and an opaque writer
   kind). Every update applied through that token is tagged with the actor.
2. **Report writes.** A configured HTTP endpoint receives every update applied to a doc, with
   its actor, batched per doc, in order per doc, signed, with at-least-once delivery and an
   explicit signal when something was lost.

The two are independent and both are off by default. With no switches set the server behaves
exactly like the version before it, except that it can already *verify* attributed tokens.

The design and its rationale are in [attributed-updates-design.md](attributed-updates-design.md).
This page is for whoever runs the server or writes the receiver.

## Configuration

All of these apply to `y-sweet serve` only. `serve-doc` has neither feature.

| Variable | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `Y_SWEET_ATTRIBUTED_TOKENS` | `--attributed-tokens[=true\|false]` | `false` | Mint tokens that carry the actor of the auth request. |
| `Y_SWEET_UPDATE_WEBHOOK_URL` | `--update-webhook-url` | unset | Where update batches are POSTed. Unset means no observer and no dispatcher. Must be `http` or `https`. |
| `Y_SWEET_UPDATE_WEBHOOK_SECRET` | `--update-webhook-secret` | unset | HMAC secret. Required when the URL is set; the server refuses to start without it. |
| `Y_SWEET_UPDATE_WEBHOOK_BATCH_MS` | `--update-webhook-batch-ms` | `1000` | How long one doc's updates are collected before a batch is sent. |
| `Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES` | `--update-webhook-max-bytes` | `268435456` | Upper bound on update bytes held in memory awaiting delivery, across all docs. |

A variable that is set but empty counts as unset, so passing the variables through an environment
that does not define them is safe. `Y_SWEET_ATTRIBUTED_TOKENS` accepts `true`/`false`
(also `1`/`0`, `yes`/`no`, `on`/`off`); anything else is a startup error. Prefer the environment
variable for the secret: a flag is visible in the process list. The secret is used as the HMAC key
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

## Attributed tokens

`POST /doc/:doc_id/auth` accepts two optional fields that describe who the token is for:

```json
{ "authorization": "full", "userId": "user_123", "writer": "ui" }
```

- `userId`: opaque, at most 128 bytes.
- `writer`: opaque, at most 64 bytes. The application owns the taxonomy (`ui`, `agent`, ...).

A longer value is rejected with `400`, whether or not the switch is on. The response
(`ClientToken`) is unchanged.

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
- **Off / rollback:** unset the switch first, wait out the token lifetime (the `validForSeconds`
  the app mints with; one hour by default), and only then roll the binary back.

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

One batch per doc is in flight at a time, so a doc's batches arrive in order; different docs are
delivered concurrently and do not block each other. While a doc's batch is retrying, up to 64
later batches wait behind it; beyond that the oldest waiting batch is dropped.

Delivery is at-least-once: a batch whose `2xx` was lost on the way back is sent again. Deduplicate
on `(instance_id, seq)`.

### Gaps

Nothing is spooled to disk. When the server has to give up on updates, it tells the receiver
instead of pretending. A doc has a gap when **either** is true:

- a batch for it arrives with `gap_before: true`, or
- a batch for it arrives with an `instance_id` the receiver has not seen for that doc. Either
  the server restarted and whatever it held in memory is gone, or it reset its gap tracking
  (below).

`gap_before: true` means: since the last batch you acknowledged for this doc, at least one update
was applied to the doc that you were not, and will not be, sent. Do not try to infer gaps from
`seq`; it is not contiguous.

Recovery is the same in both cases: fetch the doc's full state from `GET /d/:doc_id/as-update`
and reconcile. Attribution for the missed span is lost.

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
is acknowledged.

That bookkeeping is bounded. While the receiver rejects everything, every doc that is written
ends up remembered as "gapped, nothing else to send". Once more than 4096 docs are in that state
the server forgets all of them, aborts their empty-batch deliveries, and switches to a fresh
`instance_id` for everything it sends from then on. No signal is lost by this: the next batch for
any of those docs arrives under an `instance_id` the receiver has not seen for it, which already
means "resync this doc". `seq` keeps counting across the switch. Docs with updates still waiting
are unaffected, except that their later batches carry the new id (so the receiver resyncs them
too). The server logs `update webhook gap tracking reset` when this happens.

The receiver must therefore accept: an empty `events` array, `null` sequence bounds, `actor: null`,
and an `instance_id` it has never seen.

### Shutdown

On shutdown the server stops accepting new updates into the pipeline, stops retrying, closes
every open batch and makes one delivery attempt per undelivered batch, in order per doc. The whole
flush, including serializing the batches, has five seconds. Whatever does not
make it is lost and shows up as a new `instance_id` after the restart. Saving docs to the store is
not delayed by this.

`y-sweet serve` shuts down gracefully on `SIGINT` only. A `SIGTERM` (what `docker stop` and ECS
send) is not handled, so the flush does not run and the process is killed after the grace period;
the receiver sees the restart as a new `instance_id` and resyncs.

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
| info | `attributed updates configuration` | `attributed_tokens`, `update_webhook_enabled`, `update_webhook_host`, `update_webhook_batch_ms`, `update_webhook_max_bytes` (the last three only when enabled). Once, at startup. |
| info | `update webhook dispatcher starting` | `instance_id` |
| info | `minted doc token` | `doc_id`, `attributed`, `actor_requested`, `writer` |
| debug | `websocket opened with actor` | `doc_id`, `writer`, `has_user_id` |
| info | `update webhook batch sent` | `doc_id`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `gap_before` |
| warn | `update webhook batch retry` | `doc_id`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `error_kind`, `age_ms`, `retry_in_ms` |
| warn | `update webhook batch dropped` | `doc_id`, `reason`, `seq_start`, `seq_end`, `events`, `bytes`, `attempt`, `status`, `age_ms` |
| warn | `update webhook events dropped` | `oversize`, `budget`, `channel_full`, `closed`, `dropped_events_total`, `held_bytes` |
| warn | `update webhook gap tracking reset` | `discarded_docs`, `instance_id` (the new one) |
| info | `update webhook shutdown: nothing to flush` / `update webhook shutdown flush done` | `docs`, `batches`, `delivered` |
| warn | `update webhook shutdown flush incomplete` | `docs`, `batches`, `delivered`, `timed_out` |

Field notes:

- `bytes` is update bytes (before base64), the unit the limits and the budget are expressed in.
- `seq_start` / `seq_end` are absent on an empty gap batch.
- `status` is the HTTP status; absent when there was no response, in which case `error_kind` is
  `timeout`, `connect` or `request`.
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
  4096 docs; expect it to resync every doc it hears about afterwards.

To see the debug line, raise the level for this crate, e.g. `RUST_LOG=info,y_sweet=debug`.

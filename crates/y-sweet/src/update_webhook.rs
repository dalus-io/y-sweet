//! Delivers attributed doc updates to an HTTP endpoint.
//!
//! `y-sweet-core` hands every update a doc applies to a callback (see
//! [y_sweet_core::update_events]). This module supplies that callback and everything behind it:
//!
//! - [UpdateSink] is the callback. It runs while the doc is locked, so it only does bounded,
//!   non-blocking work: check the event against the size cap, reserve its bytes against the
//!   global budget, and `try_send` it into a bounded channel. Anything it cannot accept is
//!   dropped, counted, and the doc is recorded as gapped. It never logs: a log write is IO, and
//!   it would happen under the doc lock.
//! - [Batcher] is the per-doc state machine: it assigns sequence numbers, groups events into
//!   batches, bounds each doc's queue and tracks the gap flag. It is synchronous and does no IO.
//! - The dispatcher task drives the batcher from the channel and a timer, and delivers at most
//!   one batch per doc at a time, signing every attempt. Across docs, at most
//!   [UpdateWebhookConfig::max_concurrent_deliveries] requests are in flight at once.
//!
//! Nothing here is durable. A batch that cannot be delivered is dropped and the doc's next batch
//! says so with `gap_before: true`. Gap state lives only in memory, though: a restart, or a reset
//! of gap tracking (see [Batcher::enforce_gap_only_cap]), discards it, and all that is left is a
//! new `instance_id` on whatever batch is sent next, for any doc. A doc whose gap was discarded
//! and that is never written again gets no batch of its own. The receiver therefore has to treat
//! a new `instance_id` as "every doc may have a gap", not just the doc in that batch.
//!
//! Update bytes, user ids and the signing secret are never logged, at any level.

use axum::body::Bytes;
use data_encoding::{BASE64, HEXLOWER};
use futures::{
    future::{abortable, AbortHandle, Aborted},
    stream::{self, FuturesUnordered},
    StreamExt,
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    Semaphore,
};
use tokio_util::sync::CancellationToken;
use url::Url;
use y_sweet_core::{
    auth::Actor,
    update_events::{AttributedUpdate, UpdateCallback},
};

const MIB: usize = 1024 * 1024;

pub const DEFAULT_BATCH_WINDOW: Duration = Duration::from_millis(1000);
pub const DEFAULT_MAX_HELD_BYTES: usize = 256 * MIB;
pub const DEFAULT_MAX_CONCURRENT_DELIVERIES: usize = 16;
/// The most [UpdateWebhookConfig::max_concurrent_deliveries] may be. Far above any useful
/// value, and far below what the semaphore behind it accepts.
pub const MAX_CONCURRENT_DELIVERIES: usize = 1024;

pub const TIMESTAMP_HEADER: &str = "X-Y-Sweet-Timestamp";
pub const SIGNATURE_HEADER: &str = "X-Y-Sweet-Signature";

/// How many events the dispatcher takes off the channel before looking at anything else.
const MAX_EVENTS_PER_WAKEUP: usize = 256;

/// Configuration of the update webhook. Only the first six fields are operator-facing; the
/// rest are fixed by the design and exist as fields so tests can shrink them.
#[derive(Clone)]
pub struct UpdateWebhookConfig {
    /// Where batches are POSTed.
    pub url: Url,
    /// The HMAC-SHA256 key requests are signed with.
    pub secret: String,
    /// How long a doc's batch stays open collecting events.
    pub batch_window: Duration,
    /// The global budget for memory held by the pipeline, in bytes of estimated cost (see
    /// [event_cost]), not raw update bytes.
    pub max_held_bytes: usize,
    /// How many requests may be in flight at once, across all docs (each doc has at most one).
    /// Bounds the burst when the receiver comes back after an outage. Clamped to
    /// 1..=[MAX_CONCURRENT_DELIVERIES].
    pub max_concurrent_deliveries: usize,
    /// A PEM file of extra CA certificates to trust for the webhook URL, on top of the bundled
    /// public roots. For a receiver behind a private CA.
    pub ca_file: Option<PathBuf>,

    /// An event larger than this is dropped.
    pub max_event_bytes: usize,
    /// A batch is closed when it holds this many events.
    pub max_batch_events: usize,
    /// A batch is closed when it holds this many update bytes; a larger event travels alone.
    pub max_batch_bytes: usize,
    /// How many closed batches may wait per doc. Overflow drops the oldest.
    pub max_queued_batches: usize,
    /// How many docs may be tracked that hold no events, only an undelivered gap flag. Beyond
    /// this, gap tracking is reset (see [Batcher::enforce_gap_only_cap]).
    pub max_gap_only_docs: usize,
    /// Capacity of the channel between the doc observers and the dispatcher, in events.
    pub channel_capacity: usize,
    /// Timeout of one delivery attempt.
    pub request_timeout: Duration,
    /// Delay before the first retry of a batch. Doubles on every further retry.
    pub retry_backoff_initial: Duration,
    /// Upper bound of the retry delay.
    pub retry_backoff_max: Duration,
    /// A batch that is still failing after this long in flight is dropped. A `Retry-After` from
    /// the receiver is honoured only up to this age.
    pub max_retry_age: Duration,
    /// How long the final flush may take at shutdown.
    pub shutdown_budget: Duration,
}

impl UpdateWebhookConfig {
    pub fn new(url: Url, secret: String) -> Self {
        Self {
            url,
            secret,
            batch_window: DEFAULT_BATCH_WINDOW,
            max_held_bytes: DEFAULT_MAX_HELD_BYTES,
            max_concurrent_deliveries: DEFAULT_MAX_CONCURRENT_DELIVERIES,
            ca_file: None,
            max_event_bytes: 8 * MIB,
            max_batch_events: 256,
            max_batch_bytes: MIB,
            max_queued_batches: 64,
            max_gap_only_docs: 4096,
            channel_capacity: 4096,
            request_timeout: Duration::from_secs(10),
            retry_backoff_initial: Duration::from_millis(500),
            retry_backoff_max: Duration::from_secs(30),
            max_retry_age: Duration::from_secs(10 * 60),
            shutdown_budget: Duration::from_secs(5),
        }
    }
}

/// State shared between the doc observers (any thread, under a doc lock) and the dispatcher.
struct Shared {
    max_held_bytes: usize,
    /// Estimated memory ([event_cost]) of the events currently held in the channel, in
    /// batches, in queues or in flight.
    held_bytes: AtomicUsize,
    /// Docs that lost an event since the dispatcher last looked. A set cannot be full, so
    /// recording a drop never fails; it is bounded by the number of loaded docs.
    gapped: Mutex<HashSet<String>>,
    /// Events dropped by the observers since the process started, per [DropReason].
    dropped: [AtomicU64; DropReason::COUNT],
}

/// Why an observer could not accept an event.
#[derive(Clone, Copy)]
enum DropReason {
    /// Larger than the event cap.
    Oversize = 0,
    /// The global byte budget is exhausted.
    Budget = 1,
    /// The channel to the dispatcher is full.
    ChannelFull = 2,
    /// The dispatcher has shut down.
    Closed = 3,
}

impl DropReason {
    const COUNT: usize = 4;
}

impl Shared {
    fn new(max_held_bytes: usize) -> Self {
        Self {
            max_held_bytes,
            held_bytes: AtomicUsize::new(0),
            gapped: Mutex::new(HashSet::new()),
            dropped: Default::default(),
        }
    }

    /// Records a dropped event. Called under the doc lock, so it only counts and marks.
    fn record_drop(&self, doc_id: &str, reason: DropReason) {
        self.dropped[reason as usize].fetch_add(1, Ordering::Relaxed);
        self.mark_gapped(doc_id);
    }

    fn drop_counts(&self) -> [u64; DropReason::COUNT] {
        std::array::from_fn(|reason| self.dropped[reason].load(Ordering::Relaxed))
    }

    fn try_reserve(&self, bytes: usize) -> bool {
        self.held_bytes
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                held.checked_add(bytes)
                    .filter(|total| *total <= self.max_held_bytes)
            })
            .is_ok()
    }

    /// Adds to what is held without asking: for bytes that are held already, whatever the
    /// budget says (see [Batcher::start_delivery]).
    fn charge(&self, bytes: usize) {
        self.held_bytes.fetch_add(bytes, Ordering::SeqCst);
    }

    fn release(&self, bytes: usize) {
        self.held_bytes.fetch_sub(bytes, Ordering::SeqCst);
    }

    fn held_bytes(&self) -> usize {
        self.held_bytes.load(Ordering::SeqCst)
    }

    fn mark_gapped(&self, doc_id: &str) {
        let mut gapped = self.gapped.lock().unwrap();
        if !gapped.contains(doc_id) {
            gapped.insert(doc_id.to_string());
        }
    }

    fn take_gapped(&self) -> HashSet<String> {
        std::mem::take(&mut *self.gapped.lock().unwrap())
    }
}

/// What every event is charged on top of its payload: the structs that hold it while it waits
/// (the event, its strings' headers, its slot in a queue) or, once its batch is serialized, its
/// JSON framing (keys, sequence number, timestamp). Either is well under this.
const EVENT_OVERHEAD_BYTES: usize = 256;

/// The memory an event is charged against the budget: an estimate of the most it occupies at
/// any point in the pipeline. Waiting, it is held raw; in flight, as base64 inside a JSON body
/// (4/3 of the update). So the charge is the base64 size plus the strings that travel with it
/// and a fixed overhead. Without the overhead, a long outage with many tiny edits would hold
/// hundreds of bytes per event while being charged one or two.
///
/// The estimate only bounds memory if each form keeps no more than its size: a closed batch
/// drops its spare event slots ([DocState::close_open]), and a body is allocated at exactly
/// its length ([prepare]) and its charge raised to that length should it be larger
/// ([Batcher::start_delivery]).
///
/// Called by the observer under the doc lock: a few additions, no allocation.
fn event_cost(event: &AttributedUpdate) -> usize {
    let actor = event.actor.as_ref().map_or(0, |actor| {
        actor.user_id.as_ref().map_or(0, String::len) + actor.writer.as_ref().map_or(0, String::len)
    });
    event.update.len().div_ceil(3) * 4 + event.doc_id.len() + actor + EVENT_OVERHEAD_BYTES
}

/// The observer side of the pipeline: accepts or drops each event without ever blocking.
struct UpdateSink {
    tx: mpsc::Sender<AttributedUpdate>,
    shared: Arc<Shared>,
    max_event_bytes: usize,
}

impl UpdateSink {
    /// Runs inside the yrs observer, under the doc write lock: no IO, no logging, no waiting.
    /// The dispatcher reports the drops recorded here on its next tick.
    fn offer(&self, event: AttributedUpdate) {
        if event.update.len() > self.max_event_bytes {
            return self.shared.record_drop(&event.doc_id, DropReason::Oversize);
        }
        let cost = event_cost(&event);
        if !self.shared.try_reserve(cost) {
            return self.shared.record_drop(&event.doc_id, DropReason::Budget);
        }
        let (event, reason) = match self.tx.try_send(event) {
            Ok(()) => return,
            Err(TrySendError::Full(event)) => (event, DropReason::ChannelFull),
            // The dispatcher is gone: the server is shutting down.
            Err(TrySendError::Closed(event)) => (event, DropReason::Closed),
        };
        self.shared.release(cost);
        self.shared.record_drop(&event.doc_id, reason);
    }
}

struct SeqEvent {
    seq: u64,
    /// What the event holds against the budget ([event_cost]).
    cost: usize,
    actor: Option<Actor>,
    update: Vec<u8>,
    occurred_at: SystemTime,
}

/// A closed batch waiting for its turn. It is serialized only when its delivery starts, because
/// that is when `gap_before` is known.
#[derive(Default)]
struct Batch {
    events: Vec<SeqEvent>,
    /// Update bytes, the unit of the batch and event caps and of the logs.
    bytes: usize,
    /// What the batch holds against the budget.
    cost: usize,
}

impl Batch {
    fn push(&mut self, event: SeqEvent) {
        self.bytes += event.update.len();
        self.cost += event.cost;
        self.events.push(event);
    }

    fn seq_start(&self) -> Option<u64> {
        self.events.first().map(|e| e.seq)
    }

    fn seq_end(&self) -> Option<u64> {
        self.events.last().map(|e| e.seq)
    }
}

struct OpenBatch {
    batch: Batch,
    opened_at: Instant,
}

/// A batch whose delivery has started: the request body plus what the log lines need.
struct PreparedBatch {
    doc_id: String,
    seq_start: Option<u64>,
    seq_end: Option<u64>,
    events: usize,
    /// Update bytes in the batch.
    bytes: usize,
    /// What the batch holds against the global budget.
    cost: usize,
    gap_before: bool,
    body: Bytes,
}

/// An update as it appears in the payload: standard base64. It is encoded straight into the
/// output, a piece at a time, so the encoded form never exists as a string of its own beside
/// the body.
struct Base64<'a>(&'a [u8]);

impl std::fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        BASE64.encode_write(self.0, f)
    }
}

impl Serialize for Base64<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Serialize)]
struct PayloadEvent<'a> {
    seq: u64,
    actor: Option<&'a Actor>,
    update: Base64<'a>,
    occurred_at: String,
}

/// Counts what is written to it.
struct ByteCount(usize);

impl std::io::Write for ByteCount {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct Payload<'a> {
    doc_id: &'a str,
    instance_id: &'a str,
    seq_start: Option<u64>,
    seq_end: Option<u64>,
    gap_before: bool,
    events: Vec<PayloadEvent<'a>>,
}

fn prepare(doc_id: &str, instance_id: &str, batch: Batch, gap_before: bool) -> PreparedBatch {
    let payload = Payload {
        doc_id,
        instance_id,
        seq_start: batch.seq_start(),
        seq_end: batch.seq_end(),
        gap_before,
        events: batch
            .events
            .iter()
            .map(|event| PayloadEvent {
                seq: event.seq,
                actor: event.actor.as_ref(),
                update: Base64(&event.update),
                occurred_at: rfc3339_millis(event.occurred_at),
            })
            .collect(),
    };
    // Measured first, then written into a buffer of exactly that size. A buffer left to grow
    // as it is appended to ends up with up to twice the capacity it needs, and the body
    // keeps that capacity for as long as the batch is in flight (ten minutes of retries with
    // the receiver down), which the budget would not know about.
    const INFALLIBLE: &str = "Serializing a batch to JSON cannot fail.";
    let mut size = ByteCount(0);
    serde_json::to_writer(&mut size, &payload).expect(INFALLIBLE);
    let mut body = Vec::with_capacity(size.0);
    serde_json::to_writer(&mut body, &payload).expect(INFALLIBLE);
    debug_assert_eq!(body.len(), body.capacity());

    PreparedBatch {
        doc_id: doc_id.to_string(),
        seq_start: payload.seq_start,
        seq_end: payload.seq_end,
        events: batch.events.len(),
        bytes: batch.bytes,
        cost: batch.cost,
        gap_before,
        body: Bytes::from(body),
    }
}

#[derive(Default)]
struct DocState {
    open: Option<OpenBatch>,
    queue: VecDeque<Batch>,
    /// The gap flag: set (with the time it was raised) while the doc has lost updates that no
    /// delivery has told the receiver about yet. It is handed to the next batch whose delivery
    /// starts, and raised again if that delivery fails.
    gap_since: Option<Instant>,
    in_flight: Option<Arc<PreparedBatch>>,
    /// Deliveries dropped in a row. Only spaces out empty gap batches, so that a receiver
    /// that rejects everything is not sent one per doc per window forever.
    consecutive_failures: u32,
}

impl DocState {
    fn mark_gap(&mut self, now: Instant) {
        self.gap_since.get_or_insert(now);
    }

    fn close_open(&mut self) {
        if let Some(mut open) = self.open.take() {
            // It may wait in the queue for a long time: without the room it grew for events
            // that did not come.
            open.batch.events.shrink_to_fit();
            self.queue.push_back(open.batch);
        }
    }

    /// True for a state that exists only because of the gap flag: no event is open, queued or
    /// in flight, just the flag or an empty batch carrying it. Such a state holds no bytes, so
    /// the byte budget does not bound how many there are.
    fn holds_no_events(&self) -> bool {
        self.open.is_none()
            && self.queue.iter().all(|batch| batch.events.is_empty())
            && self
                .in_flight
                .as_ref()
                .is_none_or(|batch| batch.events == 0)
    }

    fn is_idle(&self) -> bool {
        self.open.is_none()
            && self.queue.is_empty()
            && self.in_flight.is_none()
            && self.gap_since.is_none()
    }
}

/// Per-doc batching state. Synchronous and IO-free; time is passed in.
struct Batcher {
    config: UpdateWebhookConfig,
    shared: Arc<Shared>,
    instance_id: String,
    /// Process-wide, so sequence numbers stay unique when a doc's state is removed and the doc
    /// is written again.
    next_seq: u64,
    docs: HashMap<String, DocState>,
    /// Docs whose next delivery may be startable.
    dirty: HashSet<String>,
    /// The observers' drop counters as of the last report.
    reported_drops: [u64; DropReason::COUNT],
}

/// One doc's undelivered batches at shutdown, oldest first.
struct ShutdownDoc {
    doc_id: String,
    batches: Vec<ShutdownBatch>,
}

enum ShutdownBatch {
    /// Was in flight: already serialized.
    InFlight(Arc<PreparedBatch>),
    /// Not serialized yet. That is left to the flush, so it happens inside the shutdown budget.
    Queued { batch: Batch, gap_before: bool },
}

impl ShutdownBatch {
    fn into_prepared(self, doc_id: &str, instance_id: &str) -> Arc<PreparedBatch> {
        match self {
            ShutdownBatch::InFlight(prepared) => prepared,
            ShutdownBatch::Queued { batch, gap_before } => {
                Arc::new(prepare(doc_id, instance_id, batch, gap_before))
            }
        }
    }
}

impl Batcher {
    fn new(config: UpdateWebhookConfig, shared: Arc<Shared>, instance_id: String) -> Self {
        Self {
            config,
            shared,
            instance_id,
            next_seq: 1,
            docs: HashMap::new(),
            dirty: HashSet::new(),
            reported_drops: [0; DropReason::COUNT],
        }
    }

    /// Takes an event off the channel into its doc's open batch.
    fn push(&mut self, event: AttributedUpdate, now: Instant) {
        let cost = event_cost(&event);
        let AttributedUpdate {
            doc_id,
            actor,
            update,
            occurred_at,
        } = event;
        let seq = self.next_seq;
        self.next_seq += 1;
        let bytes = update.len();
        let event = SeqEvent {
            seq,
            cost,
            actor,
            update,
            occurred_at,
        };

        if !self.docs.contains_key(&doc_id) {
            self.docs.insert(doc_id.clone(), DocState::default());
        }
        let state = self.docs.get_mut(&doc_id).expect("Inserted above.");

        if bytes > self.config.max_batch_bytes {
            // Too big to share a batch: it travels alone, after whatever was already open.
            state.close_open();
            let mut batch = Batch::default();
            batch.push(event);
            state.queue.push_back(batch);
        } else {
            let max_batch_bytes = self.config.max_batch_bytes;
            if state
                .open
                .as_ref()
                .is_some_and(|open| open.batch.bytes + bytes > max_batch_bytes)
            {
                state.close_open();
            }
            let open = state.open.get_or_insert_with(|| OpenBatch {
                batch: Batch::default(),
                opened_at: now,
            });
            open.batch.push(event);
            if open.batch.events.len() >= self.config.max_batch_events
                || open.batch.bytes >= max_batch_bytes
            {
                state.close_open();
            }
        }

        Self::enforce_queue_bound(&self.config, &self.shared, &doc_id, state, now);
        self.dirty.insert(doc_id);
    }

    fn enforce_queue_bound(
        config: &UpdateWebhookConfig,
        shared: &Shared,
        doc_id: &str,
        state: &mut DocState,
        now: Instant,
    ) {
        while state.queue.len() > config.max_queued_batches {
            let Some(batch) = state.queue.pop_front() else {
                break;
            };
            shared.release(batch.cost);
            state.mark_gap(now);
            tracing::warn!(
                doc_id = %doc_id,
                reason = "queue_overflow",
                seq_start = batch.seq_start(),
                seq_end = batch.seq_end(),
                events = batch.events.len(),
                bytes = batch.bytes,
                "update webhook batch dropped"
            );
        }
    }

    /// How long a doc's gap flag must have been up before an empty gap batch is queued for it:
    /// the batch window, or the retry backoff once deliveries for the doc are being dropped.
    fn gap_batch_delay(config: &UpdateWebhookConfig, consecutive_failures: u32) -> Duration {
        if consecutive_failures == 0 {
            return config.batch_window;
        }
        config
            .retry_backoff_initial
            .saturating_mul(1u32 << (consecutive_failures - 1).min(16))
            .min(config.retry_backoff_max)
            .max(config.batch_window)
    }

    /// Raises the gap flag of every doc the observers dropped an event for.
    fn absorb_gapped(&mut self, now: Instant) {
        for doc_id in self.shared.take_gapped() {
            self.docs.entry(doc_id).or_default().mark_gap(now);
        }
    }

    /// Logs what the observers dropped since the last report, in one line. The observers
    /// cannot log themselves: they run under the doc lock.
    fn report_drops(&mut self) {
        let counts = self.shared.drop_counts();
        if counts == self.reported_drops {
            return;
        }
        let since_last =
            |reason: DropReason| counts[reason as usize] - self.reported_drops[reason as usize];
        tracing::warn!(
            oversize = since_last(DropReason::Oversize),
            budget = since_last(DropReason::Budget),
            channel_full = since_last(DropReason::ChannelFull),
            closed = since_last(DropReason::Closed),
            dropped_events_total = counts.iter().sum::<u64>(),
            held_bytes = self.shared.held_bytes(),
            "update webhook events dropped"
        );
        self.reported_drops = counts;
    }

    /// Bounds the states that hold nothing but a gap flag.
    ///
    /// Such a state lives until a batch carrying its flag is acked, which never happens while
    /// the receiver rejects everything: each doc written during the outage would keep a state,
    /// and an empty-batch delivery, forever. So past the cap all of them are discarded and
    /// `instance_id` is replaced. Sequence numbers keep running.
    ///
    /// This loses information on purpose: a discarded doc is never sent its own gap signal. What
    /// remains is the new `instance_id` on the next batch sent for any doc, and by the payload
    /// contract a receiver that sees an `instance_id` for the first time must resync every doc it
    /// knew under earlier ids, not only the doc in that batch. If nothing at all is sent after
    /// the reset, the receiver learns nothing until something is.
    ///
    /// Docs with events open, queued or in flight are kept; their later batches carry the new
    /// id. Returns the discarded docs that had an (empty) batch in flight, for the dispatcher
    /// to abort.
    fn enforce_gap_only_cap(&mut self) -> Vec<String> {
        let gap_only = self
            .docs
            .values()
            .filter(|state| state.holds_no_events())
            .count();
        if gap_only <= self.config.max_gap_only_docs {
            return Vec::new();
        }

        let mut in_flight = Vec::new();
        self.docs.retain(|doc_id, state| {
            if !state.holds_no_events() {
                return true;
            }
            if state.in_flight.is_some() {
                in_flight.push(doc_id.clone());
            }
            false
        });
        self.instance_id = nanoid::nanoid!();
        tracing::warn!(
            discarded_docs = gap_only,
            instance_id = %self.instance_id,
            "update webhook gap tracking reset"
        );
        in_flight
    }

    /// Periodic work: report drops, pick up docs gapped by the observers, close batches whose
    /// window elapsed, and queue an empty batch for a gapped doc that has nothing else to carry
    /// the flag. Returns docs whose in-flight delivery must be aborted (see
    /// [Batcher::enforce_gap_only_cap]).
    fn tick(&mut self, now: Instant) -> Vec<String> {
        self.report_drops();
        self.absorb_gapped(now);
        let aborted = self.enforce_gap_only_cap();

        for (doc_id, state) in self.docs.iter_mut() {
            let mut changed = false;

            if state.open.as_ref().is_some_and(|open| {
                now.saturating_duration_since(open.opened_at) >= self.config.batch_window
            }) {
                state.close_open();
                Self::enforce_queue_bound(&self.config, &self.shared, doc_id, state, now);
                changed = true;
            }

            if let Some(gap_since) = state.gap_since {
                let delay = Self::gap_batch_delay(&self.config, state.consecutive_failures);
                if state.open.is_none()
                    && state.queue.is_empty()
                    && now.saturating_duration_since(gap_since) >= delay
                {
                    state.queue.push_back(Batch::default());
                    changed = true;
                }
            }

            if changed {
                self.dirty.insert(doc_id.clone());
            }
        }

        aborted
    }

    /// Starts the next delivery of every doc that has one waiting and none in flight.
    fn take_startable(&mut self, now: Instant) -> Vec<Arc<PreparedBatch>> {
        // A gap raised since the last tick belongs on the batch that starts now, not a later one.
        self.absorb_gapped(now);

        let mut startable = Vec::new();
        for doc_id in std::mem::take(&mut self.dirty) {
            let Some(state) = self.docs.get_mut(&doc_id) else {
                continue;
            };
            if state.in_flight.is_some() {
                continue;
            }
            while let Some(batch) = state.queue.pop_front() {
                let gap_before = state.gap_since.take().is_some();
                if batch.events.is_empty() && !gap_before {
                    // An empty batch exists only to carry the gap flag, and an earlier batch
                    // already took it.
                    continue;
                }
                let prepared = Arc::new(Self::start_delivery(
                    &self.shared,
                    prepare(&doc_id, &self.instance_id, batch, gap_before),
                ));
                state.in_flight = Some(prepared.clone());
                startable.push(prepared);
                break;
            }
            if state.is_idle() {
                self.docs.remove(&doc_id);
            }
        }
        startable
    }

    /// Makes the charge of a batch that was just serialized cover its body.
    ///
    /// From here until it is acked or dropped, what the batch holds is its body. The estimate
    /// its events were charged on arrival ([event_cost]) covers that, except for strings that
    /// grow when escaped as JSON (a control character takes six bytes). The difference is
    /// charged now, over the budget if need be: the memory is in use either way, and counting
    /// it is what makes the observers hold back.
    ///
    /// An empty gap batch is exempt. It carries no events, and how many of those there can be
    /// is bounded on its own (see [Batcher::enforce_gap_only_cap]).
    fn start_delivery(shared: &Shared, mut batch: PreparedBatch) -> PreparedBatch {
        if batch.events > 0 {
            let uncharged = batch.body.len().saturating_sub(batch.cost);
            shared.charge(uncharged);
            batch.cost += uncharged;
        }
        batch
    }

    /// Records the end of a doc's in-flight delivery: acked, or dropped for good.
    fn finish(&mut self, doc_id: &str, acked: bool, now: Instant) {
        let Some(state) = self.docs.get_mut(doc_id) else {
            return;
        };
        if let Some(batch) = state.in_flight.take() {
            self.shared.release(batch.cost);
        }
        if acked {
            state.consecutive_failures = 0;
        } else {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            // Restart the clock, so the empty gap batch that may follow is spaced from now.
            state.gap_since = Some(now);
        }
        if state.is_idle() {
            self.docs.remove(doc_id);
        } else {
            self.dirty.insert(doc_id.to_string());
        }
    }

    /// Empties the batcher for the final flush: for every doc, its undelivered batches in
    /// order, starting with the one that was in flight. Nothing is serialized here. Stops early,
    /// returning `false`, if `deadline` passes first.
    fn drain_for_shutdown(&mut self, deadline: Instant) -> (Vec<ShutdownDoc>, bool) {
        self.absorb_gapped(Instant::now());

        let mut plan = Vec::new();
        let mut complete = true;
        for (index, (doc_id, mut state)) in std::mem::take(&mut self.docs).into_iter().enumerate() {
            if index % 256 == 255 && Instant::now() >= deadline {
                complete = false;
                break;
            }
            let mut batches = Vec::new();
            if let Some(in_flight) = state.in_flight.take() {
                batches.push(ShutdownBatch::InFlight(in_flight));
            }
            state.close_open();
            let mut gap = state.gap_since.is_some();
            for batch in state.queue.drain(..) {
                if batch.events.is_empty() {
                    continue;
                }
                let gap_before = std::mem::take(&mut gap);
                batches.push(ShutdownBatch::Queued { batch, gap_before });
            }
            if gap {
                // Nothing left to carry the flag.
                batches.push(ShutdownBatch::Queued {
                    batch: Batch::default(),
                    gap_before: true,
                });
            }
            if !batches.is_empty() {
                plan.push(ShutdownDoc { doc_id, batches });
            }
        }
        self.dirty.clear();
        (plan, complete)
    }
}

/// `sha256=` plus the hex HMAC-SHA256 of `"{timestamp}.{body}"` under `secret`.
pub fn sign(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts a key of any length.");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("sha256={}", HEXLOWER.encode(&mac.finalize().into_bytes()))
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Formats a time as RFC 3339 in UTC with millisecond precision, e.g.
/// `2026-11-10T12:00:00.000Z`.
fn rfc3339_millis(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since_epoch.as_secs();
    let millis = since_epoch.subsec_millis();
    let (hour, minute, second) = (secs % 86400 / 3600, secs % 3600 / 60, secs % 60);

    // Days since the epoch to a civil date (Howard Hinnant's `civil_from_days`).
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

enum Attempt {
    Acked {
        status: u16,
    },
    /// Worth trying the same body again: a timeout, a connection error, 408, 429 or a 5xx.
    Retryable {
        status: Option<u16>,
        error_kind: Option<&'static str>,
        /// What a 429 or 503 asked for in `Retry-After`, if it parsed.
        retry_after: Option<Duration>,
    },
    /// This body will never be accepted.
    Terminal {
        status: u16,
    },
}

/// Reads `Retry-After` in either form: delta-seconds, or an HTTP-date (a date in the past means
/// no wait). `None` when the header is absent or unparsable.
fn parse_retry_after(headers: &reqwest::header::HeaderMap, now: SystemTime) -> Option<Duration> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let at = httpdate::parse_http_date(value).ok()?;
    Some(at.duration_since(now).unwrap_or(Duration::ZERO))
}

/// Reads the CA certificates to trust on top of the bundled roots.
fn load_ca_file(path: &std::path::Path) -> anyhow::Result<Vec<reqwest::Certificate>> {
    let pem = std::fs::read(path).map_err(|e| {
        anyhow::anyhow!(
            "Cannot read the update webhook CA file {}: {e}",
            path.display()
        )
    })?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
        anyhow::anyhow!(
            "Invalid PEM in the update webhook CA file {}: {e}",
            path.display()
        )
    })?;
    if certs.is_empty() {
        anyhow::bail!(
            "The update webhook CA file {} holds no certificate",
            path.display()
        );
    }
    Ok(certs)
}

/// How long to wait before retrying a batch that is `age` old. A longer `Retry-After` wins
/// over the backoff, but nothing waits past the retry age: the batch then gets its last attempt
/// right at that age. Called only while `age < max_retry_age`.
fn retry_delay(
    backoff: Duration,
    retry_after: Option<Duration>,
    age: Duration,
    max_retry_age: Duration,
) -> Duration {
    backoff
        .max(retry_after.unwrap_or_default())
        .min(max_retry_age.saturating_sub(age))
}

struct Deliverer {
    client: reqwest::Client,
    config: UpdateWebhookConfig,
    /// One permit per request in flight, across all docs. Held for the request only, never
    /// while a batch waits out its retry delay, so a doc that is backing off does not hold
    /// back the others.
    permits: Semaphore,
}

impl Deliverer {
    fn new(config: UpdateWebhookConfig) -> anyhow::Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(config.request_timeout)
            // A redirect is not an ack, and a signed body must not follow one elsewhere.
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &config.ca_file {
            for cert in load_ca_file(path)? {
                builder = builder.add_root_certificate(cert);
            }
        }
        let client = builder.build()?;
        let permits = Semaphore::new(
            config
                .max_concurrent_deliveries
                .clamp(1, MAX_CONCURRENT_DELIVERIES),
        );
        Ok(Self {
            client,
            config,
            permits,
        })
    }

    /// One signed POST. The timestamp and signature are computed here, per attempt, so a batch
    /// that has been retrying for a long time still verifies. The caller holds a permit.
    async fn attempt(&self, batch: &PreparedBatch) -> Attempt {
        let timestamp = unix_seconds();
        let signature = sign(self.config.secret.as_bytes(), timestamp, &batch.body);

        let result = self
            .client
            .post(self.config.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .header(SIGNATURE_HEADER, signature)
            .body(batch.body.clone())
            .send()
            .await;

        match result {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    Attempt::Acked {
                        status: status.as_u16(),
                    }
                } else if status == reqwest::StatusCode::REQUEST_TIMEOUT
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status.is_server_error()
                {
                    let retry_after = if status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    {
                        parse_retry_after(response.headers(), SystemTime::now())
                    } else {
                        None
                    };
                    Attempt::Retryable {
                        status: Some(status.as_u16()),
                        error_kind: None,
                        retry_after,
                    }
                } else {
                    Attempt::Terminal {
                        status: status.as_u16(),
                    }
                }
            }
            // The error itself is not logged: its text can include the URL.
            Err(err) => Attempt::Retryable {
                status: None,
                error_kind: Some(if err.is_timeout() {
                    "timeout"
                } else if err.is_connect() {
                    "connect"
                } else {
                    "request"
                }),
                retry_after: None,
            },
        }
    }

    /// Delivers a batch, retrying until it is acked or has to be dropped. Returns whether it
    /// was acked.
    async fn deliver(&self, batch: &PreparedBatch) -> bool {
        let started = Instant::now();
        let mut backoff = self.config.retry_backoff_initial;
        let mut attempt = 0u32;
        let mut last_status = None;

        loop {
            // Waiting for a slot counts against the retry age like any other time in flight: a
            // batch that cannot get one in time is dropped, and its doc moves on (gapped),
            // instead of every later batch of the doc queueing behind it. A free slot is still
            // taken at zero remaining age, so the last attempt at the limit happens.
            let remaining = self.config.max_retry_age.saturating_sub(started.elapsed());
            let Ok(permit) = tokio::time::timeout(remaining, self.permits.acquire()).await else {
                log_dropped(batch, "retry_age", last_status, attempt, started.elapsed());
                return false;
            };
            let permit = permit.expect("The semaphore is never closed.");
            attempt += 1;
            let outcome = self.attempt(batch).await;
            drop(permit);

            match outcome {
                Attempt::Acked { status } => {
                    log_sent(batch, attempt, status);
                    return true;
                }
                Attempt::Terminal { status } => {
                    log_dropped(batch, "status", Some(status), attempt, started.elapsed());
                    return false;
                }
                Attempt::Retryable {
                    status,
                    error_kind,
                    retry_after,
                } => {
                    last_status = status;
                    let age = started.elapsed();
                    if age >= self.config.max_retry_age {
                        log_dropped(batch, "retry_age", status, attempt, age);
                        return false;
                    }
                    let delay = retry_delay(backoff, retry_after, age, self.config.max_retry_age);
                    tracing::warn!(
                        doc_id = %batch.doc_id,
                        seq_start = batch.seq_start,
                        seq_end = batch.seq_end,
                        events = batch.events,
                        bytes = batch.bytes,
                        attempt,
                        status,
                        error_kind,
                        age_ms = age.as_millis() as u64,
                        retry_after_ms = retry_after.map(|d| d.as_millis() as u64),
                        retry_in_ms = delay.as_millis() as u64,
                        "update webhook batch retry"
                    );
                    tokio::time::sleep(delay).await;
                    backoff = backoff.saturating_mul(2).min(self.config.retry_backoff_max);
                }
            }
        }
    }

    /// The shutdown variant: one attempt, no retry. The wait for a slot is bounded by the
    /// shutdown budget, which the caller enforces.
    async fn deliver_once(&self, batch: &PreparedBatch) -> bool {
        let _permit = self
            .permits
            .acquire()
            .await
            .expect("The semaphore is never closed.");
        match self.attempt(batch).await {
            Attempt::Acked { status } => {
                log_sent(batch, 1, status);
                true
            }
            Attempt::Terminal { status } => {
                log_dropped(batch, "shutdown", Some(status), 1, Duration::ZERO);
                false
            }
            Attempt::Retryable { status, .. } => {
                log_dropped(batch, "shutdown", status, 1, Duration::ZERO);
                false
            }
        }
    }
}

fn log_sent(batch: &PreparedBatch, attempt: u32, status: u16) {
    tracing::info!(
        doc_id = %batch.doc_id,
        seq_start = batch.seq_start,
        seq_end = batch.seq_end,
        events = batch.events,
        bytes = batch.bytes,
        attempt,
        status,
        gap_before = batch.gap_before,
        "update webhook batch sent"
    );
}

fn log_dropped(
    batch: &PreparedBatch,
    reason: &'static str,
    status: Option<u16>,
    attempt: u32,
    age: Duration,
) {
    tracing::warn!(
        doc_id = %batch.doc_id,
        reason,
        seq_start = batch.seq_start,
        seq_end = batch.seq_end,
        events = batch.events,
        bytes = batch.bytes,
        attempt,
        status,
        age_ms = age.as_millis() as u64,
        "update webhook batch dropped"
    );
}

struct Dispatcher {
    rx: mpsc::Receiver<AttributedUpdate>,
    batcher: Batcher,
    deliverer: Arc<Deliverer>,
    cancellation_token: CancellationToken,
}

impl Dispatcher {
    async fn run(mut self) {
        let tick_period = (self.batcher.config.batch_window / 4)
            .clamp(Duration::from_millis(5), Duration::from_millis(250));
        let mut ticker = tokio::time::interval(tick_period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // One future per doc with a batch in flight; resolves to (doc id, acked), or to
        // `Aborted` when the doc's state was discarded under it.
        let mut deliveries = FuturesUnordered::new();
        let mut abort_handles: HashMap<String, AbortHandle> = HashMap::new();

        loop {
            tokio::select! {
                _ = self.cancellation_token.cancelled() => break,
                event = self.rx.recv() => {
                    let Some(event) = event else {
                        // Every sender is gone, so no doc can produce another event.
                        break;
                    };
                    let now = Instant::now();
                    self.batcher.push(event, now);
                    for _ in 1..MAX_EVENTS_PER_WAKEUP {
                        let Ok(event) = self.rx.try_recv() else {
                            break;
                        };
                        self.batcher.push(event, now);
                    }
                }
                Some(outcome) = deliveries.next(), if !deliveries.is_empty() => {
                    let outcome: Result<(String, bool), Aborted> = outcome;
                    if let Ok((doc_id, acked)) = outcome {
                        abort_handles.remove(&doc_id);
                        self.batcher.finish(&doc_id, acked, Instant::now());
                    }
                }
                _ = ticker.tick() => {
                    // Deliveries of discarded gap-only docs stop here, so the number of empty
                    // batches in flight stays within the gap-only cap.
                    for doc_id in self.batcher.tick(Instant::now()) {
                        if let Some(handle) = abort_handles.remove(&doc_id) {
                            handle.abort();
                        }
                    }
                }
            }

            for batch in self.batcher.take_startable(Instant::now()) {
                let deliverer = self.deliverer.clone();
                let doc_id = batch.doc_id.clone();
                let (delivery, abort_handle) = abortable(async move {
                    let acked = deliverer.deliver(&batch).await;
                    (batch.doc_id.clone(), acked)
                });
                abort_handles.insert(doc_id, abort_handle);
                deliveries.push(delivery);
            }
        }

        // Stop retrying: whatever was in flight is attempted once more below.
        drop(deliveries);
        self.shutdown().await;
    }

    /// The final flush: every doc's undelivered batches, in order, one attempt each, stopping
    /// at a doc's first failure.
    ///
    /// Everything here, not just the HTTP requests, happens inside the shutdown budget: the
    /// deadline is set first and checked while draining the channel, while collecting the
    /// batches and before each batch is serialized and sent.
    async fn shutdown(mut self) {
        let deadline = Instant::now() + self.batcher.config.shutdown_budget;
        // Closed first, so observers that are still running cannot keep refilling it. What is
        // already buffered can still be received.
        self.rx.close();

        let now = Instant::now();
        let mut drained = 0usize;
        let mut complete = true;
        while let Ok(event) = self.rx.try_recv() {
            self.batcher.push(event, now);
            drained += 1;
            if drained % 64 == 0 && Instant::now() >= deadline {
                complete = false;
                break;
            }
        }
        self.batcher.report_drops();

        let (plan, drained_all_docs) = self.batcher.drain_for_shutdown(deadline);
        complete &= drained_all_docs;
        let docs = plan.len();
        let batches: usize = plan.iter().map(|doc| doc.batches.len()).sum();
        if batches == 0 && complete {
            tracing::info!(docs, batches, "update webhook shutdown: nothing to flush");
            return;
        }

        let delivered = AtomicUsize::new(0);
        let instance_id = self.batcher.instance_id.clone();
        // The deliveries that were retrying are gone, so every permit is free again; the cap
        // still applies, inside each attempt.
        let concurrency = self
            .batcher
            .config
            .max_concurrent_deliveries
            .clamp(1, MAX_CONCURRENT_DELIVERIES);
        let flush = stream::iter(plan).for_each_concurrent(concurrency, |doc| {
            let deliverer = &self.deliverer;
            let delivered = &delivered;
            let instance_id = &instance_id;
            async move {
                for batch in doc.batches {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let batch = batch.into_prepared(&doc.doc_id, instance_id);
                    if !deliverer.deliver_once(&batch).await {
                        break;
                    }
                    delivered.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        let timed_out = tokio::time::timeout_at(deadline.into(), flush)
            .await
            .is_err();

        let delivered = delivered.load(Ordering::Relaxed);
        if delivered == batches && complete {
            tracing::info!(
                docs,
                batches,
                delivered,
                "update webhook shutdown flush done"
            );
        } else {
            tracing::warn!(
                docs,
                batches,
                delivered,
                timed_out = timed_out || !complete,
                "update webhook shutdown flush incomplete"
            );
        }
    }
}

/// Builds the update webhook pipeline.
///
/// Returns the callback to register on every doc, and the dispatcher as a future the caller must
/// spawn. The dispatcher runs until `cancellation_token` is cancelled, then flushes what it
/// holds and completes.
pub fn start(
    config: UpdateWebhookConfig,
    cancellation_token: CancellationToken,
) -> anyhow::Result<(UpdateCallback, impl Future<Output = ()> + Send + 'static)> {
    let shared = Arc::new(Shared::new(config.max_held_bytes));
    let (tx, rx) = mpsc::channel(config.channel_capacity);
    let sink = UpdateSink {
        tx,
        shared: shared.clone(),
        max_event_bytes: config.max_event_bytes,
    };
    let instance_id = nanoid::nanoid!();
    tracing::info!(instance_id = %instance_id, "update webhook dispatcher starting");

    let dispatcher = Dispatcher {
        rx,
        deliverer: Arc::new(Deliverer::new(config.clone())?),
        batcher: Batcher::new(config, shared, instance_id),
        cancellation_token,
    };
    let callback: UpdateCallback = Arc::new(move |event| sink.offer(event));

    Ok((callback, dispatcher.run()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::HeaderMap, http::StatusCode, response::IntoResponse, routing::post, Router};
    use serde_json::Value;

    const SECRET: &str = "test-secret";
    const WINDOW: Duration = Duration::from_millis(1000);

    fn test_config() -> UpdateWebhookConfig {
        UpdateWebhookConfig::new(
            "http://127.0.0.1:9/unused".parse().unwrap(),
            SECRET.to_string(),
        )
    }

    fn event(doc_id: &str, size: usize) -> AttributedUpdate {
        AttributedUpdate {
            doc_id: doc_id.to_string(),
            actor: None,
            update: vec![7; size],
            occurred_at: UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
        }
    }

    /// What `event(doc_id, size)` is charged against the budget.
    fn cost(doc_id: &str, size: usize) -> usize {
        event_cost(&event(doc_id, size))
    }

    fn body(batch: &PreparedBatch) -> Value {
        serde_json::from_slice(&batch.body).unwrap()
    }

    fn seqs(batch: &PreparedBatch) -> Vec<u64> {
        body(batch)["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["seq"].as_u64().unwrap())
            .collect()
    }

    /// A sink and a batcher wired together the way [start] does, minus the dispatcher task:
    /// the test moves events from the channel into the batcher itself.
    struct Pipeline {
        sink: UpdateSink,
        rx: mpsc::Receiver<AttributedUpdate>,
        batcher: Batcher,
        shared: Arc<Shared>,
        now: Instant,
    }

    impl Pipeline {
        fn new(config: UpdateWebhookConfig) -> Self {
            let shared = Arc::new(Shared::new(config.max_held_bytes));
            let (tx, rx) = mpsc::channel(config.channel_capacity);
            Self {
                sink: UpdateSink {
                    tx,
                    shared: shared.clone(),
                    max_event_bytes: config.max_event_bytes,
                },
                rx,
                batcher: Batcher::new(config, shared.clone(), "instance-1".to_string()),
                shared,
                now: Instant::now(),
            }
        }

        /// What the doc observer does.
        fn offer(&self, doc_id: &str, size: usize) {
            self.sink.offer(event(doc_id, size));
        }

        /// What the dispatcher does when the channel is readable.
        fn pump(&mut self) {
            while let Ok(event) = self.rx.try_recv() {
                self.batcher.push(event, self.now);
            }
        }

        fn emit(&mut self, doc_id: &str, size: usize) {
            self.offer(doc_id, size);
            self.pump();
        }

        fn advance(&mut self, by: Duration) {
            self.now += by;
            self.batcher.tick(self.now);
        }

        fn start(&mut self) -> Vec<Arc<PreparedBatch>> {
            let mut started = self.batcher.take_startable(self.now);
            started.sort_by(|a, b| a.doc_id.cmp(&b.doc_id));
            started
        }

        fn start_one(&mut self) -> Arc<PreparedBatch> {
            let mut started = self.start();
            assert_eq!(started.len(), 1, "expected exactly one startable batch");
            started.pop().unwrap()
        }

        fn ack(&mut self, batch: &PreparedBatch) {
            self.batcher.finish(&batch.doc_id, true, self.now);
        }

        fn fail(&mut self, batch: &PreparedBatch) {
            self.batcher.finish(&batch.doc_id, false, self.now);
        }
    }

    #[test]
    fn batch_closes_when_the_window_elapses() {
        let mut p = Pipeline::new(test_config());
        p.emit("doc", 10);
        p.advance(WINDOW / 2);
        p.emit("doc", 10);
        assert!(p.start().is_empty());

        // The window runs from the batch's first event, not its last.
        p.advance(WINDOW / 2 - Duration::from_millis(1));
        assert!(p.start().is_empty());
        p.advance(Duration::from_millis(1));

        let batch = p.start_one();
        assert_eq!(seqs(&batch), vec![1, 2]);
        assert!(!batch.gap_before);
    }

    #[test]
    fn batch_closes_at_the_event_cap() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_batch_events: 3,
            ..test_config()
        });
        for _ in 0..7 {
            p.emit("doc", 10);
        }

        // No time has passed: the cap alone closed two batches.
        let first = p.start_one();
        assert_eq!(seqs(&first), vec![1, 2, 3]);
        p.ack(&first);
        let second = p.start_one();
        assert_eq!(seqs(&second), vec![4, 5, 6]);
        p.ack(&second);
        assert!(p.start().is_empty());

        p.advance(WINDOW);
        assert_eq!(seqs(&p.start_one()), vec![7]);
    }

    #[test]
    fn batch_closes_at_the_byte_cap() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_batch_bytes: 100,
            ..test_config()
        });
        p.emit("doc", 60);
        p.emit("doc", 60); // would make 120: closes the first batch
        p.emit("doc", 40); // makes exactly 100: closes the second

        let first = p.start_one();
        assert_eq!(seqs(&first), vec![1]);
        assert_eq!(first.bytes, 60);
        p.ack(&first);
        let second = p.start_one();
        assert_eq!(seqs(&second), vec![2, 3]);
        assert_eq!(second.bytes, 100);
    }

    #[test]
    fn oversize_event_travels_alone() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_batch_bytes: 100,
            ..test_config()
        });
        p.emit("doc", 10);
        p.emit("doc", 10);
        p.emit("doc", 150); // over the batch cap, under the event cap
        p.emit("doc", 10);

        let first = p.start_one();
        assert_eq!(seqs(&first), vec![1, 2]);
        p.ack(&first);
        let alone = p.start_one();
        assert_eq!(seqs(&alone), vec![3]);
        assert_eq!(alone.bytes, 150);
        p.ack(&alone);
        assert!(p.start().is_empty());
        p.advance(WINDOW);
        assert_eq!(seqs(&p.start_one()), vec![4]);
    }

    #[test]
    fn one_delivery_per_doc_in_order_and_docs_are_independent() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_batch_events: 1,
            ..test_config()
        });
        p.emit("a", 10);
        p.emit("b", 10);
        p.emit("a", 10);
        p.emit("a", 10);
        p.emit("b", 10);

        // Each doc starts its oldest batch; nothing else starts while those are in flight.
        let started = p.start();
        assert_eq!(started.len(), 2);
        assert_eq!(
            (started[0].doc_id.as_str(), seqs(&started[0])),
            ("a", vec![1])
        );
        assert_eq!(
            (started[1].doc_id.as_str(), seqs(&started[1])),
            ("b", vec![2])
        );
        p.advance(WINDOW);
        assert!(p.start().is_empty());

        // Acking b does not release a.
        p.ack(&started[1]);
        let next = p.start_one();
        assert_eq!((next.doc_id.as_str(), seqs(&next)), ("b", vec![5]));

        p.ack(&started[0]);
        let next = p.start_one();
        assert_eq!((next.doc_id.as_str(), seqs(&next)), ("a", vec![3]));
        p.ack(&next);
        let next = p.start_one();
        assert_eq!((next.doc_id.as_str(), seqs(&next)), ("a", vec![4]));
    }

    #[test]
    fn queue_overflow_drops_the_oldest_batch_and_sets_the_gap_flag() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_batch_events: 1,
            max_queued_batches: 2,
            ..test_config()
        });
        p.emit("doc", 10);
        let in_flight = p.start_one();
        assert_eq!(seqs(&in_flight), vec![1]);

        // Three more batches pile up behind it; the queue holds two.
        p.emit("doc", 10);
        p.emit("doc", 10);
        p.emit("doc", 10);
        // In flight + two queued; seq 2 was released.
        assert_eq!(p.shared.held_bytes(), 3 * cost("doc", 10));

        assert!(!in_flight.gap_before);
        p.ack(&in_flight);
        let next = p.start_one();
        assert_eq!(seqs(&next), vec![3]);
        assert!(next.gap_before);
        p.ack(&next);

        // The flag is cleared once a batch carrying it is acked.
        let last = p.start_one();
        assert_eq!(seqs(&last), vec![4]);
        assert!(!last.gap_before);
        p.ack(&last);
        assert!(p.batcher.docs.is_empty());
        assert_eq!(p.shared.held_bytes(), 0);
    }

    #[test]
    fn channel_overflow_drops_the_event_and_sets_the_gap_flag() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            channel_capacity: 2,
            ..test_config()
        });
        // The dispatcher is not keeping up: three events arrive before it reads any.
        p.offer("doc", 10);
        p.offer("doc", 10);
        p.offer("doc", 10);
        assert_eq!(p.shared.held_bytes(), 2 * cost("doc", 10));
        assert_eq!(p.shared.drop_counts(), [0, 0, 1, 0]);

        p.pump();
        p.advance(WINDOW);
        let batch = p.start_one();
        assert_eq!(seqs(&batch), vec![1, 2]);
        assert!(batch.gap_before);
    }

    #[test]
    fn event_over_the_event_cap_is_dropped_and_gaps_the_doc() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_event_bytes: 100,
            ..test_config()
        });
        p.emit("doc", 101);
        assert_eq!(p.shared.held_bytes(), 0);
        assert_eq!(p.shared.drop_counts(), [1, 0, 0, 0]);
        assert!(p.batcher.docs.is_empty());

        p.emit("doc", 100);
        p.advance(WINDOW);
        let batch = p.start_one();
        assert_eq!(seqs(&batch), vec![1]);
        assert!(batch.gap_before);
    }

    #[test]
    fn exhausted_byte_budget_drops_and_gaps_then_recovers() {
        let budget = cost("a", 60) + cost("a", 40);
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_held_bytes: budget,
            max_batch_events: 1,
            ..test_config()
        });
        p.emit("a", 60);
        p.emit("b", 60); // over the budget: dropped
        p.emit("a", 40); // exactly at the budget: accepted
        p.emit("b", 1); // dropped
        assert_eq!(p.shared.held_bytes(), budget);
        assert_eq!(p.shared.drop_counts(), [0, 2, 0, 0]);

        // Acking releases the bytes, and the budget is usable again.
        let first = p.start_one();
        assert_eq!((first.doc_id.as_str(), first.bytes), ("a", 60));
        p.ack(&first);
        assert_eq!(p.shared.held_bytes(), cost("a", 40));
        p.emit("b", 60);
        assert_eq!(p.shared.held_bytes(), budget);

        // b lost updates, so its first delivered batch says so. a lost nothing.
        p.advance(Duration::ZERO);
        let started = p.start();
        assert_eq!(started.len(), 2);
        assert_eq!(
            (started[0].doc_id.as_str(), started[0].gap_before),
            ("a", false)
        );
        assert_eq!(
            (started[1].doc_id.as_str(), started[1].gap_before),
            ("b", true)
        );
        p.ack(&started[0]);
        p.ack(&started[1]);
        assert_eq!(p.shared.held_bytes(), 0);
        assert!(p.batcher.docs.is_empty());
    }

    #[test]
    fn dropped_batch_releases_its_bytes_and_gaps_the_next() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_batch_events: 1,
            ..test_config()
        });
        p.emit("doc", 10);
        p.emit("doc", 10);
        let first = p.start_one();
        p.fail(&first);
        assert_eq!(p.shared.held_bytes(), cost("doc", 10));

        let second = p.start_one();
        assert_eq!(seqs(&second), vec![2]);
        assert!(second.gap_before);
    }

    #[test]
    fn gapped_doc_with_no_further_edits_gets_an_empty_gap_batch() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_event_bytes: 100,
            ..test_config()
        });
        p.emit("doc", 101); // dropped; the doc is never written again
        p.advance(Duration::ZERO);
        assert!(p.start().is_empty());
        p.advance(WINDOW - Duration::from_millis(1));
        assert!(p.start().is_empty());
        p.advance(Duration::from_millis(1));

        let batch = p.start_one();
        assert_eq!(
            body(&batch),
            serde_json::json!({
                "doc_id": "doc",
                "instance_id": "instance-1",
                "seq_start": null,
                "seq_end": null,
                "gap_before": true,
                "events": [],
            })
        );

        // Nothing more is sent while it is in flight, and acking it clears the doc's state.
        p.advance(WINDOW * 3);
        assert!(p.start().is_empty());
        p.ack(&batch);
        p.advance(WINDOW * 3);
        assert!(p.start().is_empty());
        assert!(p.batcher.docs.is_empty());
    }

    #[test]
    fn rejected_empty_gap_batches_back_off() {
        let mut p = Pipeline::new(test_config()); // backoff 500ms doubling, window 1s
        p.shared.mark_gapped("doc");
        p.advance(Duration::ZERO);
        p.advance(WINDOW);
        let first = p.start_one();
        assert!(first.gap_before && first.events == 0);

        // One failure: the 500ms backoff is below the window, so the window still rules.
        p.fail(&first);
        p.advance(WINDOW - Duration::from_millis(1));
        assert!(p.start().is_empty());
        p.advance(Duration::from_millis(1));
        let second = p.start_one();

        // Three failures: 2s.
        p.fail(&second);
        p.advance(WINDOW);
        let third = p.start_one();
        p.fail(&third);
        p.advance(Duration::from_millis(1999));
        assert!(p.start().is_empty());
        p.advance(Duration::from_millis(1));
        let fourth = p.start_one();
        assert!(fourth.gap_before && fourth.events == 0);

        // The delay is capped, and an ack ends it.
        for _ in 0..20 {
            p.batcher.finish("doc", false, p.now);
            p.advance(Duration::from_secs(30));
            p.start_one();
        }
        p.batcher.finish("doc", true, p.now);
        assert!(p.batcher.docs.is_empty());
    }

    #[test]
    fn sequence_numbers_stay_unique_after_a_docs_state_is_removed() {
        let mut p = Pipeline::new(test_config());
        p.emit("a", 10);
        p.emit("b", 10);
        p.advance(WINDOW);
        for batch in p.start() {
            p.ack(&batch);
        }
        assert!(p.batcher.docs.is_empty());

        // The same docs are written again, as after an eviction and reload.
        p.emit("b", 10);
        p.emit("a", 10);
        p.advance(WINDOW);
        let started = p.start();
        assert_eq!(seqs(&started[0]), vec![4]);
        assert_eq!(seqs(&started[1]), vec![3]);
    }

    #[test]
    fn payload_carries_each_event_with_its_actor() {
        let mut p = Pipeline::new(test_config());
        p.sink.offer(AttributedUpdate {
            doc_id: "doc".to_string(),
            actor: Some(Actor {
                user_id: Some("user-1".to_string()),
                writer: Some("ui".to_string()),
            }),
            update: vec![0, 1, 2, 250, 251, 252],
            occurred_at: UNIX_EPOCH + Duration::from_millis(1_794_312_000_000),
        });
        p.sink.offer(AttributedUpdate {
            doc_id: "doc".to_string(),
            actor: Some(Actor {
                user_id: None,
                writer: Some("agent".to_string()),
            }),
            update: vec![3],
            occurred_at: UNIX_EPOCH + Duration::from_millis(1_794_312_000_250),
        });
        p.sink.offer(event("doc", 2));
        p.pump();
        p.advance(WINDOW);

        assert_eq!(
            body(&p.start_one()),
            serde_json::json!({
                "doc_id": "doc",
                "instance_id": "instance-1",
                "seq_start": 1,
                "seq_end": 3,
                "gap_before": false,
                "events": [
                    {
                        "seq": 1,
                        "actor": { "user_id": "user-1", "writer": "ui" },
                        "update": "AAEC+vv8",
                        "occurred_at": "2026-11-10T12:00:00.000Z",
                    },
                    {
                        "seq": 2,
                        "actor": { "user_id": null, "writer": "agent" },
                        "update": "Aw==",
                        "occurred_at": "2026-11-10T12:00:00.250Z",
                    },
                    {
                        "seq": 3,
                        "actor": null,
                        "update": "Bwc=",
                        "occurred_at": "2023-11-14T22:13:20.123Z",
                    },
                ],
            })
        );
    }

    #[test]
    fn shutdown_drain_keeps_order_and_carries_the_gap_once() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_batch_events: 2,
            ..test_config()
        });
        for _ in 0..5 {
            p.emit("doc", 10);
        }
        let in_flight = p.start_one();
        p.shared.mark_gapped("doc");
        p.shared.mark_gapped("quiet");

        let (plan, complete) = p
            .batcher
            .drain_for_shutdown(Instant::now() + Duration::from_secs(60));
        assert!(complete);
        let mut plan: Vec<(String, Vec<Arc<PreparedBatch>>)> = plan
            .into_iter()
            .map(|doc| {
                let batches = doc
                    .batches
                    .into_iter()
                    .map(|batch| batch.into_prepared(&doc.doc_id, "instance-1"))
                    .collect();
                (doc.doc_id, batches)
            })
            .collect();
        plan.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(plan.len(), 2);

        let doc: Vec<_> = plan[0].1.iter().map(|b| (seqs(b), b.gap_before)).collect();
        assert_eq!(
            doc,
            vec![(vec![1, 2], false), (vec![3, 4], true), (vec![5], false)]
        );
        assert!(Arc::ptr_eq(&plan[0].1[0], &in_flight));

        let quiet: Vec<_> = plan[1].1.iter().map(|b| (seqs(b), b.gap_before)).collect();
        assert_eq!(quiet, vec![(vec![], true)]);
        assert!(p.batcher.docs.is_empty());
    }

    #[test]
    fn gap_only_states_are_capped_by_rotating_the_instance_id() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_gap_only_docs: 3,
            max_batch_events: 1,
            ..test_config()
        });
        let instance_id =
            |batch: &PreparedBatch| body(batch)["instance_id"].as_str().unwrap().to_string();

        // A doc with real work, which also lost an update.
        p.emit("real", 10);
        p.emit("real", 10);
        let real_in_flight = p.start_one();
        assert_eq!(instance_id(&real_in_flight), "instance-1");
        p.shared.mark_gapped("real");

        // Three docs that hold nothing but a gap flag: at the cap, nothing happens. Their empty
        // batches go out and are rejected, so the flags stay.
        for doc_id in ["g1", "g2", "g3"] {
            p.shared.mark_gapped(doc_id);
        }
        p.advance(Duration::ZERO);
        p.advance(WINDOW);
        let empties = p.start();
        assert_eq!(empties.len(), 3);
        assert!(empties.iter().all(|b| b.events == 0 && b.gap_before));
        p.fail(&empties[0]);
        assert_eq!(p.batcher.docs.len(), 4);
        assert_eq!(p.batcher.instance_id, "instance-1");

        // A fourth pushes it over: every gap-only state goes, whether its flag is waiting (g1),
        // in flight (g2, g3) or new (g4), and the two in flight are handed back to be aborted.
        p.shared.mark_gapped("g4");
        p.now += Duration::from_millis(1);
        let mut aborted = p.batcher.tick(p.now);
        aborted.sort();
        assert_eq!(aborted, vec!["g2".to_string(), "g3".to_string()]);
        assert_eq!(
            p.batcher.docs.keys().collect::<Vec<_>>(),
            vec![&"real".to_string()]
        );
        let rotated = p.batcher.instance_id.clone();
        assert_ne!(rotated, "instance-1");

        // Nothing more is sent for the discarded docs.
        p.advance(WINDOW * 100);
        assert!(p.start().is_empty());

        // The doc with real work kept its state and its gap flag; its next batch carries the
        // new instance id, and sequence numbers were not reset.
        p.ack(&real_in_flight);
        let next = p.start_one();
        assert_eq!((seqs(&next), next.gap_before), (vec![2], true));
        assert_eq!(instance_id(&next), rotated);

        // A discarded doc that is written again carries no gap flag: the new instance id is all
        // that is left of its gap. (One that is never written again gets nothing; see
        // `an_idle_doc_loses_its_gap_signal_when_gap_tracking_resets`.)
        p.ack(&next);
        p.emit("g1", 10);
        let again = p.start_one();
        assert_eq!((seqs(&again), again.gap_before), (vec![3], false));
        assert_eq!(instance_id(&again), rotated);
    }

    #[test]
    fn observer_drops_are_counted_per_reason_without_logging() {
        let mut p = Pipeline::new(UpdateWebhookConfig {
            max_event_bytes: 100,
            max_held_bytes: cost("a", 100) + cost("c", 10),
            channel_capacity: 1,
            ..test_config()
        });
        p.offer("a", 101); // oversize
        p.offer("a", 100); // accepted, fills the channel
        p.offer("b", 60); // over the budget
        p.offer("c", 10); // channel full
        assert_eq!(p.shared.drop_counts(), [1, 1, 1, 0]);

        // The dispatcher's report consumes the delta, so the next tick has nothing to say.
        p.batcher.report_drops();
        assert_eq!(p.batcher.reported_drops, [1, 1, 1, 0]);

        // Once the dispatcher is gone, drops are still counted and still never block.
        p.rx.close();
        while p.rx.try_recv().is_ok() {}
        p.offer("a", 10);
        assert_eq!(p.shared.drop_counts(), [1, 1, 1, 1]);
        // Only the event the dispatcher never took.
        assert_eq!(p.shared.held_bytes(), cost("a", 100));
    }

    #[test]
    fn rfc3339_formatting() {
        let at = |millis: u64| rfc3339_millis(UNIX_EPOCH + Duration::from_millis(millis));
        assert_eq!(at(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(951_782_399_999), "2000-02-28T23:59:59.999Z");
        assert_eq!(at(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(at(1_709_251_199_000), "2024-02-29T23:59:59.000Z");
        assert_eq!(at(1_735_689_600_007), "2025-01-01T00:00:00.007Z");
        assert_eq!(at(4_102_444_800_000), "2100-01-01T00:00:00.000Z");
    }

    #[test]
    fn signature_matches_a_known_hmac_vector() {
        // Computed independently:
        // python3 -c 'import hmac, hashlib; print(hmac.new(b"test-secret",
        //     b"1700000000.{\"hello\":\"world\"}", hashlib.sha256).hexdigest())'
        assert_eq!(
            sign(b"test-secret", 1_700_000_000, br#"{"hello":"world"}"#),
            "sha256=f85455a1b55ea86f7a15f5f9923d0abc4b888da84ec485f2ff358f427776beca"
        );
        // The timestamp is part of what is signed.
        assert_ne!(
            sign(b"test-secret", 1_700_000_001, br#"{"hello":"world"}"#),
            sign(b"test-secret", 1_700_000_000, br#"{"hello":"world"}"#),
        );
    }

    // --- Dispatcher tests, against a local HTTP receiver -----------------------------------

    #[derive(Clone)]
    struct Request {
        timestamp: u64,
        signature: String,
        content_type: String,
        raw_body: Vec<u8>,
        body: Value,
        status: u16,
    }

    impl Request {
        fn seqs(&self) -> Vec<u64> {
            self.body["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["seq"].as_u64().unwrap())
                .collect()
        }

        fn gap_before(&self) -> bool {
            self.body["gap_before"].as_bool().unwrap()
        }
    }

    type Requests = Arc<Mutex<Vec<Request>>>;

    /// Serves `POST /updates`, answering with whatever `respond` says for the request's
    /// position (0-based) and body, and recording every request.
    async fn receiver<F>(respond: F) -> (Url, Requests)
    where
        F: Fn(usize, &Value) -> StatusCode + Clone + Send + Sync + 'static,
    {
        let requests = Requests::default();
        let app = {
            let requests = requests.clone();
            Router::new().route(
                "/updates",
                post(move |headers: HeaderMap, raw_body: Bytes| {
                    let requests = requests.clone();
                    let respond = respond.clone();
                    async move {
                        let header = |name: &str| {
                            headers
                                .get(name)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or_default()
                                .to_string()
                        };
                        let body: Value = serde_json::from_slice(&raw_body).unwrap();
                        let mut requests = requests.lock().unwrap();
                        let status = respond(requests.len(), &body);
                        requests.push(Request {
                            timestamp: header(TIMESTAMP_HEADER).parse().unwrap(),
                            signature: header(SIGNATURE_HEADER),
                            content_type: header("content-type"),
                            raw_body: raw_body.to_vec(),
                            body,
                            status: status.as_u16(),
                        });
                        status
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/updates", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, requests)
    }

    /// A dispatcher tuned for tests: every event is its own batch, and timings are short.
    fn dispatcher_config(url: Url) -> UpdateWebhookConfig {
        UpdateWebhookConfig {
            batch_window: Duration::from_millis(20),
            max_batch_events: 1,
            retry_backoff_initial: Duration::from_millis(10),
            retry_backoff_max: Duration::from_millis(40),
            ..UpdateWebhookConfig::new(url, SECRET.to_string())
        }
    }

    struct Running {
        callback: UpdateCallback,
        cancellation_token: CancellationToken,
        task: tokio::task::JoinHandle<()>,
    }

    fn run(config: UpdateWebhookConfig) -> Running {
        let cancellation_token = CancellationToken::new();
        let (callback, dispatcher) = start(config, cancellation_token.clone()).unwrap();
        Running {
            callback,
            cancellation_token,
            task: tokio::spawn(dispatcher),
        }
    }

    impl Running {
        fn emit(&self, doc_id: &str) {
            (self.callback)(event(doc_id, 10));
        }
    }

    async fn wait_for_requests(requests: &Requests, count: usize) -> Vec<Request> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let seen = requests.lock().unwrap().clone();
            if seen.len() >= count {
                return seen;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {count} requests, got {}",
                seen.len()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Asserts nothing more arrives for a while.
    async fn assert_settled(requests: &Requests, count: usize) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(requests.lock().unwrap().len(), count);
    }

    fn assert_signed(request: &Request) {
        assert_eq!(request.content_type, "application/json");
        assert_eq!(
            request.signature,
            sign(SECRET.as_bytes(), request.timestamp, &request.raw_body)
        );
        let age = unix_seconds().abs_diff(request.timestamp);
        assert!(age <= 5, "timestamp is {age}s off");
    }

    #[tokio::test]
    async fn delivers_signed_batches() {
        let (url, requests) = receiver(|_, _| StatusCode::NO_CONTENT).await;
        let running = run(UpdateWebhookConfig {
            max_batch_events: 256,
            ..dispatcher_config(url)
        });
        running.emit("doc");
        running.emit("doc");

        let seen = wait_for_requests(&requests, 1).await;
        assert_signed(&seen[0]);
        assert_eq!(seen[0].seqs(), vec![1, 2]);
        assert_eq!(seen[0].body["doc_id"], "doc");
        assert_eq!(seen[0].body["seq_start"], 1);
        assert_eq!(seen[0].body["seq_end"], 2);
        assert!(!seen[0].gap_before());
        assert!(!seen[0].body["instance_id"].as_str().unwrap().is_empty());
        assert_settled(&requests, 1).await;
    }

    #[tokio::test]
    async fn retries_on_500_and_then_delivers_in_order() {
        let (url, requests) = receiver(|index, _| match index {
            0 | 1 => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::OK,
        })
        .await;
        let running = run(dispatcher_config(url));
        running.emit("doc");
        running.emit("doc");
        running.emit("doc");

        let seen = wait_for_requests(&requests, 5).await;
        let order: Vec<_> = seen.iter().map(|r| (r.seqs(), r.status)).collect();
        assert_eq!(
            order,
            vec![
                (vec![1], 500),
                (vec![1], 500),
                (vec![1], 200),
                (vec![2], 200),
                (vec![3], 200),
            ]
        );
        // A retry is the same batch, byte for byte, and nothing was lost.
        assert_eq!(seen[0].raw_body, seen[2].raw_body);
        assert!(seen.iter().all(|r| !r.gap_before()));
        seen.iter().for_each(assert_signed);
        assert_settled(&requests, 5).await;
    }

    #[tokio::test]
    async fn retries_on_408_429_and_connection_errors() {
        let (url, requests) = receiver(|index, _| match index {
            0 => StatusCode::REQUEST_TIMEOUT,
            1 => StatusCode::TOO_MANY_REQUESTS,
            2 => StatusCode::BAD_GATEWAY,
            _ => StatusCode::OK,
        })
        .await;
        let running = run(dispatcher_config(url));
        running.emit("doc");

        let seen = wait_for_requests(&requests, 4).await;
        let statuses: Vec<_> = seen.iter().map(|r| r.status).collect();
        assert_eq!(statuses, vec![408, 429, 502, 200]);
        assert!(seen.iter().all(|r| r.seqs() == vec![1]));

        // Nothing listens on port 1: the connection is refused, the batch retried, then aged
        // out. (A port freed by this test could be handed to another test's receiver.)
        let dead_url: Url = "http://127.0.0.1:1/updates".parse().unwrap();
        let deliverer = Deliverer::new(UpdateWebhookConfig {
            max_retry_age: Duration::from_millis(100),
            ..dispatcher_config(dead_url)
        })
        .unwrap();
        let batch = prepare("doc", "instance-1", Batch::default(), true);
        assert!(matches!(
            deliverer.attempt(&batch).await,
            Attempt::Retryable {
                status: None,
                error_kind: Some("connect"),
                ..
            }
        ));
        let started = Instant::now();
        assert!(!deliverer.deliver(&batch).await);
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn a_400_drops_the_batch_gaps_the_doc_and_delivers_the_next() {
        let (url, requests) = receiver(|index, _| match index {
            0 => StatusCode::BAD_REQUEST,
            _ => StatusCode::OK,
        })
        .await;
        let running = run(dispatcher_config(url));
        running.emit("doc");
        running.emit("doc");
        running.emit("doc");

        let seen = wait_for_requests(&requests, 3).await;
        let order: Vec<_> = seen
            .iter()
            .map(|r| (r.seqs(), r.status, r.gap_before()))
            .collect();
        assert_eq!(
            order,
            vec![
                (vec![1], 400, false), // not retried
                (vec![2], 200, true),
                (vec![3], 200, false),
            ]
        );
        assert_settled(&requests, 3).await;
    }

    #[tokio::test]
    async fn a_dropped_last_batch_is_followed_by_an_empty_gap_batch() {
        let (url, requests) = receiver(|index, _| match index {
            0 => StatusCode::UNAUTHORIZED,
            _ => StatusCode::OK,
        })
        .await;
        let running = run(dispatcher_config(url));
        running.emit("doc");

        let seen = wait_for_requests(&requests, 2).await;
        assert_eq!((seen[0].seqs(), seen[0].status), (vec![1], 401));
        assert_eq!(seen[1].seqs(), Vec::<u64>::new());
        assert!(seen[1].gap_before());
        assert!(seen[1].body["seq_start"].is_null());
        assert!(seen[1].body["seq_end"].is_null());
        assert_signed(&seen[1]);
        assert_settled(&requests, 2).await;
    }

    #[tokio::test]
    async fn a_batch_past_the_retry_age_is_dropped_and_the_next_delivered() {
        // The receiver never accepts the first batch, and accepts everything else.
        let (url, requests) = receiver(|_, body| {
            if body["seq_start"] == 1 {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            }
        })
        .await;
        let running = run(UpdateWebhookConfig {
            max_retry_age: Duration::from_millis(150),
            ..dispatcher_config(url)
        });
        running.emit("doc");
        running.emit("doc");

        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = loop {
            let seen = requests.lock().unwrap().clone();
            if seen.last().is_some_and(|r| r.status == 200) {
                break seen;
            }
            assert!(Instant::now() < deadline, "second batch never arrived");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };

        let (retries, delivered) = seen.split_at(seen.len() - 1);
        assert!(retries.len() >= 3, "only {} attempts", retries.len());
        assert!(retries
            .iter()
            .all(|r| r.seqs() == vec![1] && r.status == 503));
        assert_eq!(delivered[0].seqs(), vec![2]);
        assert!(delivered[0].gap_before());
        let total = seen.len();
        assert_settled(&requests, total).await;
    }

    #[tokio::test]
    async fn a_retried_attempt_is_signed_with_a_newer_timestamp() {
        let (url, requests) = receiver(|index, _| match index {
            0 => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::OK,
        })
        .await;
        // The timestamp has one-second resolution, so the retry has to wait out a second.
        let running = run(UpdateWebhookConfig {
            retry_backoff_initial: Duration::from_millis(1100),
            retry_backoff_max: Duration::from_millis(1100),
            ..dispatcher_config(url)
        });
        running.emit("doc");

        let seen = wait_for_requests(&requests, 2).await;
        assert_eq!(seen[0].raw_body, seen[1].raw_body);
        assert!(
            seen[1].timestamp > seen[0].timestamp,
            "{} then {}",
            seen[0].timestamp,
            seen[1].timestamp
        );
        assert_ne!(seen[0].signature, seen[1].signature);
        assert_signed(&seen[0]);
        assert_signed(&seen[1]);
    }

    #[tokio::test]
    async fn docs_do_not_block_each_other() {
        // Doc "stuck" is never accepted; doc "ok" must still flow.
        let (url, requests) = receiver(|_, body| {
            if body["doc_id"] == "stuck" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            }
        })
        .await;
        let running = run(dispatcher_config(url));
        running.emit("stuck");
        running.emit("ok");
        running.emit("ok");

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ok: Vec<_> = requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.body["doc_id"] == "ok")
                .map(|r| r.seqs())
                .collect();
            if ok.len() == 2 {
                assert_eq!(ok, vec![vec![2], vec![3]]);
                break;
            }
            assert!(Instant::now() < deadline, "doc 'ok' was blocked");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn shutdown_flushes_open_batches() {
        let (url, requests) = receiver(|_, _| StatusCode::OK).await;
        let running = run(UpdateWebhookConfig {
            // Long enough that only shutdown can close the batches.
            batch_window: Duration::from_secs(3600),
            max_batch_events: 256,
            ..dispatcher_config(url)
        });
        running.emit("a");
        running.emit("a");
        running.emit("b");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(requests.lock().unwrap().is_empty());

        running.cancellation_token.cancel();
        tokio::time::timeout(Duration::from_secs(5), running.task)
            .await
            .expect("dispatcher did not exit")
            .unwrap();

        let mut seen: Vec<_> = requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| (r.body["doc_id"].as_str().unwrap().to_string(), r.seqs()))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![("a".to_string(), vec![1, 2]), ("b".to_string(), vec![3])]
        );

        // After shutdown the observer still must not block or panic.
        (running.callback)(event("a", 10));
    }

    #[tokio::test]
    async fn shutdown_stops_retrying_and_respects_its_budget() {
        // A receiver that never answers within the budget.
        let app = Router::new().route(
            "/updates",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                StatusCode::OK
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Url = format!("http://{}/updates", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let running = run(UpdateWebhookConfig {
            shutdown_budget: Duration::from_millis(200),
            ..dispatcher_config(url)
        });
        running.emit("doc");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let started = Instant::now();
        running.cancellation_token.cancel();
        tokio::time::timeout(Duration::from_secs(5), running.task)
            .await
            .expect("dispatcher did not exit")
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_rejecting_receiver_cannot_grow_gap_tracking_without_bound() {
        use std::sync::atomic::AtomicBool;

        let accept = Arc::new(AtomicBool::new(false));
        let (url, requests) = receiver({
            let accept = accept.clone();
            move |_, _| {
                if accept.load(Ordering::SeqCst) {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
        })
        .await;
        let running = run(UpdateWebhookConfig {
            max_gap_only_docs: 2,
            ..dispatcher_config(url)
        });
        for doc_id in ["a", "b", "c"] {
            running.emit(doc_id);
        }

        // Each doc's batch is rejected, leaving three gap-only states: one over the cap. They
        // are discarded, so the empty gap batches stop instead of repeating forever. The price
        // is the gap signal itself (see the next test).
        wait_for_requests(&requests, 3).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut settled = requests.lock().unwrap().len();
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let now = requests.lock().unwrap().len();
            if now == settled {
                break;
            }
            settled = now;
            assert!(Instant::now() < deadline, "requests never stopped");
        }
        let first_instance = requests.lock().unwrap()[0].body["instance_id"].clone();

        // The receiver recovers. The next write to a discarded doc arrives under a new instance
        // id but without `gap_before`: the unseen id is the only trace of the lost gap.
        accept.store(true, Ordering::SeqCst);
        running.emit("a");
        let seen = wait_for_requests(&requests, settled + 1).await;
        let last = seen.last().unwrap();
        assert_eq!((last.status, last.seqs()), (200, vec![4]));
        assert_ne!(last.body["instance_id"], first_instance);
        assert!(!last.gap_before());
        assert_settled(&requests, settled + 1).await;
    }

    #[tokio::test]
    async fn shutdown_stays_within_its_budget_under_backlog_and_live_producers() {
        use std::sync::atomic::AtomicBool;

        // A receiver that never answers, so every delivery is still pending at the deadline.
        let app = Router::new().route(
            "/updates",
            post(|| async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                StatusCode::OK
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url: Url = format!("http://{}/updates", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let budget = Duration::from_millis(300);
        let running = run(UpdateWebhookConfig {
            shutdown_budget: budget,
            // Nothing closes before shutdown, so the whole backlog is still to be serialized.
            batch_window: Duration::from_secs(3600),
            max_batch_events: 256,
            ..dispatcher_config(url)
        });

        // A large backlog: 400 docs, 96 MiB of updates, none of it serialized yet.
        let big = |doc: usize| AttributedUpdate {
            doc_id: format!("doc-{doc}"),
            actor: None,
            update: vec![7; 48 * 1024],
            occurred_at: SystemTime::now(),
        };
        for round in 0..5 {
            for doc in 0..400 {
                (running.callback)(big(doc));
            }
            // Let the dispatcher take them off the channel.
            tokio::time::sleep(Duration::from_millis(if round == 4 { 100 } else { 20 })).await;
        }

        // Producers that keep writing straight through the shutdown.
        let stop = Arc::new(AtomicBool::new(false));
        let producers: Vec<_> = (0..2)
            .map(|producer| {
                let callback = running.callback.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut calls = 0u64;
                    while !stop.load(Ordering::SeqCst) {
                        callback(big(1000 + producer));
                        calls += 1;
                    }
                    calls
                })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let started = Instant::now();
        running.cancellation_token.cancel();
        tokio::time::timeout(Duration::from_secs(10), running.task)
            .await
            .expect("dispatcher did not exit")
            .unwrap();
        let took = started.elapsed();

        stop.store(true, Ordering::SeqCst);
        let calls: u64 = producers.into_iter().map(|p| p.join().unwrap()).sum();
        assert!(calls > 0);
        assert!(
            took <= budget + Duration::from_millis(500),
            "shutdown took {took:?} with a budget of {budget:?}"
        );
        // It did wait for the receiver rather than give up at once.
        assert!(took >= budget - Duration::from_millis(50), "took {took:?}");
    }

    #[tokio::test]
    async fn an_idle_doc_loses_its_gap_signal_when_gap_tracking_resets() {
        use std::sync::atomic::AtomicBool;

        let accept = Arc::new(AtomicBool::new(false));
        let (url, requests) = receiver({
            let accept = accept.clone();
            move |_, _| {
                if accept.load(Ordering::SeqCst) {
                    StatusCode::OK
                } else {
                    StatusCode::UNAUTHORIZED
                }
            }
        })
        .await;
        let running = run(UpdateWebhookConfig {
            max_gap_only_docs: 2,
            ..dispatcher_config(url)
        });
        for doc_id in ["a", "b", "c"] {
            running.emit(doc_id);
        }

        // All three are rejected and their gap states discarded by the reset.
        wait_for_requests(&requests, 3).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut settled = requests.lock().unwrap().len();
        loop {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let now = requests.lock().unwrap().len();
            if now == settled {
                break;
            }
            settled = now;
            assert!(Instant::now() < deadline, "requests never stopped");
        }
        let first_instance = requests.lock().unwrap()[0].body["instance_id"].clone();

        // The receiver recovers and only an unrelated doc is written. a, b and c are never
        // written again, so they never get a batch of their own, with or without
        // `gap_before`: their lost updates are signalled only by the new instance id on d's
        // batch. That is why the receiver must resync every doc it knew under the old id.
        accept.store(true, Ordering::SeqCst);
        running.emit("d");
        let seen = wait_for_requests(&requests, settled + 1).await;
        let last = seen.last().unwrap();
        assert_eq!(
            (last.body["doc_id"].as_str(), last.status),
            (Some("d"), 200)
        );
        assert_ne!(last.body["instance_id"], first_instance);
        assert!(!last.gap_before());

        tokio::time::sleep(Duration::from_millis(500)).await;
        let after_recovery: Vec<_> = requests.lock().unwrap()[settled..]
            .iter()
            .map(|r| r.body["doc_id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(after_recovery, vec!["d".to_string()]);
    }

    /// A receiver that counts how many of its requests are open at once.
    async fn concurrency_probe(hold: Duration) -> (Url, Requests, Arc<AtomicUsize>) {
        let open = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let requests = Requests::default();
        let app = {
            let (open, peak, requests) = (open.clone(), peak.clone(), requests.clone());
            Router::new().route(
                "/updates",
                post(move |raw_body: Bytes| {
                    let (open, peak, requests) = (open.clone(), peak.clone(), requests.clone());
                    async move {
                        let now_open = open.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now_open, Ordering::SeqCst);
                        tokio::time::sleep(hold).await;
                        open.fetch_sub(1, Ordering::SeqCst);
                        requests.lock().unwrap().push(Request {
                            timestamp: 0,
                            signature: String::new(),
                            content_type: String::new(),
                            body: serde_json::from_slice(&raw_body).unwrap(),
                            raw_body: raw_body.to_vec(),
                            status: 200,
                        });
                        StatusCode::OK
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/updates", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, requests, peak)
    }

    #[tokio::test]
    async fn concurrent_deliveries_never_exceed_the_cap() {
        let (url, requests, peak) = concurrency_probe(Duration::from_millis(50)).await;
        let running = run(UpdateWebhookConfig {
            max_concurrent_deliveries: 4,
            ..dispatcher_config(url)
        });
        // 30 docs with two batches each, all ready at once, as after an outage.
        for _ in 0..2 {
            for doc in 0..30 {
                running.emit(&format!("doc-{doc}"));
            }
        }

        let seen = wait_for_requests(&requests, 60).await;
        assert_eq!(
            peak.load(Ordering::SeqCst),
            4,
            "the cap was not reached or exceeded"
        );

        // Still one batch per doc at a time, in order.
        let mut per_doc: HashMap<String, Vec<u64>> = HashMap::new();
        for request in &seen {
            per_doc
                .entry(request.body["doc_id"].as_str().unwrap().to_string())
                .or_default()
                .extend(request.seqs());
        }
        assert_eq!(per_doc.len(), 30);
        assert!(per_doc
            .values()
            .all(|seqs| seqs.len() == 2 && seqs[0] < seqs[1]));
    }

    #[tokio::test]
    async fn shutdown_flush_respects_the_cap() {
        let (url, requests, peak) = concurrency_probe(Duration::from_millis(50)).await;
        let running = run(UpdateWebhookConfig {
            max_concurrent_deliveries: 3,
            batch_window: Duration::from_secs(3600),
            max_batch_events: 256,
            ..dispatcher_config(url)
        });
        for doc in 0..12 {
            running.emit(&format!("doc-{doc}"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        running.cancellation_token.cancel();
        running.task.await.unwrap();
        assert_eq!(requests.lock().unwrap().len(), 12);
        assert_eq!(peak.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn an_absurd_concurrency_is_clamped_instead_of_panicking() {
        for max_concurrent_deliveries in [0, usize::MAX] {
            let deliverer = Deliverer::new(UpdateWebhookConfig {
                max_concurrent_deliveries,
                ..test_config()
            })
            .unwrap();
            assert!(
                (1..=MAX_CONCURRENT_DELIVERIES).contains(&deliverer.permits.available_permits())
            );
        }
    }

    #[test]
    fn retry_after_parsing() {
        use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
        let now = UNIX_EPOCH + Duration::from_secs(1_794_312_000);
        let parse = |value: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(value) = value {
                headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            }
            parse_retry_after(&headers, now)
        };
        assert_eq!(parse(Some("120")), Some(Duration::from_secs(120)));
        assert_eq!(parse(Some(" 0 ")), Some(Duration::ZERO));
        // 2026-11-10T12:00:30Z, 30 s after `now`.
        assert_eq!(
            parse(Some("Tue, 10 Nov 2026 12:00:30 GMT")),
            Some(Duration::from_secs(30))
        );
        // A date in the past means no wait.
        assert_eq!(
            parse(Some("Tue, 10 Nov 2026 11:00:00 GMT")),
            Some(Duration::ZERO)
        );
        assert_eq!(parse(Some("-5")), None);
        assert_eq!(parse(Some("soon")), None);
        assert_eq!(parse(None), None);
    }

    /// A receiver that answers 429 with `Retry-After: {retry_after}` to the first `rejections`
    /// requests and 200 after, recording when each arrived.
    async fn throttling_receiver(
        rejections: usize,
        retry_after: &'static str,
    ) -> (Url, Arc<Mutex<Vec<(Instant, u16)>>>) {
        let seen: Arc<Mutex<Vec<(Instant, u16)>>> = Arc::default();
        let app = {
            let seen = seen.clone();
            Router::new().route(
                "/updates",
                post(move || {
                    let seen = seen.clone();
                    async move {
                        let mut seen = seen.lock().unwrap();
                        let throttle = seen.len() < rejections;
                        let status = if throttle { 429 } else { 200 };
                        seen.push((Instant::now(), status));
                        if throttle {
                            (
                                StatusCode::TOO_MANY_REQUESTS,
                                [("retry-after", retry_after)],
                            )
                                .into_response()
                        } else {
                            StatusCode::OK.into_response()
                        }
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/updates", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    #[tokio::test]
    async fn retry_after_delays_the_retry() {
        let (url, seen) = throttling_receiver(1, "1").await;
        // The backoff alone would retry after 10 ms.
        let running = run(dispatcher_config(url));
        running.emit("doc");

        let deadline = Instant::now() + Duration::from_secs(10);
        let seen = loop {
            let seen = seen.lock().unwrap().clone();
            if seen.len() >= 2 {
                break seen;
            }
            assert!(Instant::now() < deadline, "the retry never arrived");
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!((seen[0].1, seen[1].1), (429, 200));
        let waited = seen[1].0 - seen[0].0;
        assert!(
            waited >= Duration::from_millis(950),
            "retried after {waited:?}"
        );
    }

    #[test]
    fn retry_delay_takes_the_longer_wait_but_never_passes_the_retry_age() {
        let ms = Duration::from_millis;
        let max = ms(10_000);
        // The backoff alone.
        assert_eq!(retry_delay(ms(500), None, ms(0), max), ms(500));
        // A longer Retry-After wins; a shorter one does not shorten the backoff.
        assert_eq!(retry_delay(ms(500), Some(ms(3_000)), ms(0), max), ms(3_000));
        assert_eq!(retry_delay(ms(500), Some(ms(100)), ms(0), max), ms(500));
        // Either is cut to what is left of the retry age, so the last attempt lands at the
        // limit.
        assert_eq!(
            retry_delay(ms(500), Some(ms(3_600_000)), ms(9_000), max),
            ms(1_000)
        );
        assert_eq!(retry_delay(ms(30_000), None, ms(9_900), max), ms(100));
    }

    #[tokio::test]
    async fn retry_after_is_bounded_by_the_retry_age() {
        let (url, seen) = throttling_receiver(usize::MAX, "3600").await;
        let max_retry_age = Duration::from_millis(300);
        let deliverer = Deliverer::new(UpdateWebhookConfig {
            max_retry_age,
            ..dispatcher_config(url)
        })
        .unwrap();
        let batch = prepare("doc", "instance-1", Batch::default(), true);

        let started = Instant::now();
        assert!(!deliverer.deliver(&batch).await);
        let took = started.elapsed();

        // Holds however slow the machine is: if the first round trip ends inside the retry
        // age, the one retry waits for the limit (not an hour) and is the last; if it ends
        // after, the batch is dropped then. Either way it is dropped at or after the limit,
        // after at most two attempts. The exact delay is pinned by
        // `retry_delay_takes_the_longer_wait_but_never_passes_the_retry_age`.
        assert!(took >= max_retry_age, "{took:?}");
        assert!(took < Duration::from_secs(60), "{took:?}");
        let attempts = seen.lock().unwrap().len();
        assert!((1..=2).contains(&attempts), "{attempts} attempts");
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_for_a_slot_counts_against_the_retry_age() {
        let max_retry_age = Duration::from_secs(600);
        let deliverer = Deliverer::new(UpdateWebhookConfig {
            max_concurrent_deliveries: 1,
            max_retry_age,
            ..test_config()
        })
        .unwrap();
        let batch = prepare("doc", "instance-1", Batch::default(), true);

        // Every slot is taken (by other docs' requests) and never freed.
        let _taken = deliverer.permits.acquire().await.unwrap();

        // The batch is not stuck behind them past its retry age: it is dropped at the limit
        // without sending anything. (The URL is unreachable; an attempt would fail at once and
        // retry, which the clock below would show.)
        let started = tokio::time::Instant::now();
        assert!(!deliverer.deliver(&batch).await);
        // (The remaining age is measured on the real clock, which moved a little.)
        let waited = started.elapsed();
        assert!(
            waited > max_retry_age - Duration::from_secs(1) && waited <= max_retry_age,
            "{waited:?}"
        );
    }

    #[test]
    fn ca_file_adds_roots_and_rejects_bad_files() {
        const CA: &str = "-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUIYVrdJ+QbMDQL9LYjjLN5Uo3FuEwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPeS1zd2VldCB0ZXN0IENBMCAXDTI2MTExMzE3MDEyOVoYDzIx
MjYxMDIwMTcwMTI5WjAaMRgwFgYDVQQDDA95LXN3ZWV0IHRlc3QgQ0EwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAATL9sRso32b7wKN4Or88QrqprgiF2s+D0reLlz6
dmhL5ZXNrwXAWB59nHYB2aXMUNORbzjAQodyDrjsvQEmBKTPo1MwUTAdBgNVHQ4E
FgQUXwpKRB+MUt+ROtKyI7dXSeiwt3IwHwYDVR0jBBgwFoAUXwpKRB+MUt+ROtKy
I7dXSeiwt3IwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA3rus
Nv3Pj/1aQbUzlTudc5SL6WbHJW6NGeiuxZrrbOYCIBnzzqodPn3zgPEKRRdjJ+9d
GZuNFD2CfzKu6mHIOnyE
-----END CERTIFICATE-----
";
        let dir = std::env::temp_dir().join(format!("y-sweet-ca-test-{}", nanoid::nanoid!()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = |name: &str, contents: &str| {
            let path = dir.join(name);
            std::fs::write(&path, contents).unwrap();
            path
        };
        let with_ca = |path: PathBuf| {
            Deliverer::new(UpdateWebhookConfig {
                ca_file: Some(path),
                ..test_config()
            })
        };

        assert!(with_ca(file("ca.pem", CA)).is_ok());
        // A bundle of two works too.
        assert!(with_ca(file("bundle.pem", &format!("{CA}{CA}"))).is_ok());

        let error = |path| with_ca(path).err().expect("expected an error").to_string();
        assert!(error(dir.join("missing.pem")).contains("Cannot read"));
        assert!(error(file("empty.pem", "not a certificate\n")).contains("no certificate"));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The private CA, and a receiver certificate it signed for `127.0.0.1`. Test-only keys,
    /// generated once with openssl (P-256, valid until 2126); see `testdata/private-ca`.
    const PRIVATE_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/private-ca/ca.pem");
    const RECEIVER_CERT: &str = include_str!("../testdata/private-ca/leaf.pem");
    const RECEIVER_KEY: &str = include_str!("../testdata/private-ca/leaf.key");

    /// An HTTPS receiver on a certificate signed by [PRIVATE_CA]. Answers every request with
    /// 204 and counts the requests it got (handshakes that fail are not requests).
    fn tls_receiver() -> (Url, Arc<AtomicUsize>) {
        use std::io::{Read, Write};

        let certs = rustls_pemfile::certs(&mut RECEIVER_CERT.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut RECEIVER_KEY.as_bytes())
            .unwrap()
            .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
        );

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://{}/updates", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let counter = served.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let (config, counter) = (config.clone(), counter.clone());
                std::thread::spawn(move || {
                    let Ok(stream) = stream else { return };
                    let connection = rustls::ServerConnection::new(config).unwrap();
                    let mut tls = rustls::StreamOwned::new(connection, stream);
                    // Read the head, then as much body as it announces.
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let head_end = loop {
                        match tls.read(&mut chunk) {
                            // A failed handshake ends up here.
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&chunk[..n]),
                        }
                        if let Some(at) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            break at + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&request[..head_end]).to_lowercase();
                    let length: usize = head
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .map(|v| v.trim().parse().unwrap())
                        .unwrap_or(0);
                    while request.len() < head_end + length {
                        match tls.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&chunk[..n]),
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    let _ = tls.write_all(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                });
            }
        });
        (url, served)
    }

    #[tokio::test]
    async fn a_receiver_behind_a_private_ca_is_trusted_only_with_the_ca_file() {
        let (url, served) = tls_receiver();
        let batch = prepare("doc", "instance-1", Batch::default(), true);

        // Bundled public roots only: the handshake fails, nothing reaches the receiver.
        let without =
            Deliverer::new(UpdateWebhookConfig::new(url.clone(), SECRET.to_string())).unwrap();
        let _permit = without.permits.acquire().await.unwrap();
        assert!(matches!(
            without.attempt(&batch).await,
            Attempt::Retryable { status: None, .. }
        ));
        assert_eq!(served.load(Ordering::SeqCst), 0);

        // With the private CA added, the same receiver is trusted and the batch delivered.
        let with = Deliverer::new(UpdateWebhookConfig {
            ca_file: Some(PathBuf::from(PRIVATE_CA)),
            ..UpdateWebhookConfig::new(url, SECRET.to_string())
        })
        .unwrap();
        let _permit = with.permits.acquire().await.unwrap();
        assert!(matches!(
            with.attempt(&batch).await,
            Attempt::Acked { status: 204 }
        ));
        assert_eq!(served.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn event_cost_covers_base64_strings_and_a_fixed_overhead() {
        assert_eq!(cost("doc", 0), 3 + EVENT_OVERHEAD_BYTES);
        assert_eq!(cost("doc", 1), 4 + 3 + EVENT_OVERHEAD_BYTES);
        assert_eq!(cost("doc", 3000), 4000 + 3 + EVENT_OVERHEAD_BYTES);
        let attributed = AttributedUpdate {
            actor: Some(Actor {
                user_id: Some("u".repeat(128)),
                writer: Some("w".repeat(64)),
            }),
            ..event("doc", 3)
        };
        assert_eq!(
            event_cost(&attributed),
            4 + 3 + 128 + 64 + EVENT_OVERHEAD_BYTES
        );

        // The charge is at least what the event occupies once serialized.
        let batch = {
            let mut p = Pipeline::new(test_config());
            p.sink.offer(attributed.clone());
            p.pump();
            p.advance(WINDOW);
            p.start_one()
        };
        let envelope = body(&prepare("doc", "instance-1", Batch::default(), false))
            .to_string()
            .len();
        assert!(batch.body.len() - envelope <= batch.cost);
    }

    #[test]
    fn many_tiny_events_fill_the_budget_at_about_the_memory_they_hold() {
        // A receiver that is down while a doc gets a stream of one-byte edits. Charged by
        // update bytes alone, a 1 MiB budget would admit a million events, hundreds of
        // megabytes of structs; charged by cost it admits what fits in about 1 MiB.
        let budget = MIB;
        let p = Pipeline::new(UpdateWebhookConfig {
            max_held_bytes: budget,
            channel_capacity: 1 << 20,
            ..test_config()
        });
        let mut accepted = 0usize;
        while p.shared.drop_counts() == [0; DropReason::COUNT] {
            p.offer("doc", 1);
            accepted += 1;
        }
        accepted -= 1; // the last one was the drop
        assert_eq!(p.shared.drop_counts(), [0, 1, 0, 0]);

        assert_eq!(accepted, budget / cost("doc", 1));
        // Between 250 and 300 bytes each, so the budget is the memory to within the estimate.
        assert!(
            (budget / 300..=budget / 250).contains(&accepted),
            "{accepted}"
        );
        // What an event really holds while it waits: the struct plus its heap blocks.
        let held = std::mem::size_of::<AttributedUpdate>() + "doc".len() + 1;
        assert!(
            held <= cost("doc", 1),
            "{held} bytes held, {} charged",
            cost("doc", 1)
        );
    }

    /// The bytes the body of a batch keeps allocated, once the batcher has let go of it.
    fn retained(batch: Arc<PreparedBatch>) -> usize {
        let batch = Arc::try_unwrap(batch)
            .ok()
            .expect("the batcher still holds the batch");
        batch
            .body
            .try_into_mut()
            .expect("the body is not shared")
            .capacity()
    }

    #[test]
    fn a_batch_in_flight_keeps_no_more_memory_than_it_is_charged() {
        // With the receiver down every doc ends up with one batch serialized and in flight,
        // for up to ten minutes. The budget is only a bound on memory if such a batch keeps
        // allocated no more than it holds against the budget. A body built by appending to a
        // growing buffer keeps the buffer's spare capacity, up to as much again.
        for (events, size) in [
            (1, 1),
            (1, 700),
            (1, 100_000),
            (1, MIB + 1),
            (1, 3 * MIB),
            (1, 8 * MIB),
            (7, 100_000),
            (256, 3_000),
            (256, 1),
        ] {
            let mut p = Pipeline::new(test_config());
            for _ in 0..events {
                p.emit("doc", size);
            }
            p.advance(WINDOW);
            let batch = p.start_one();
            assert_eq!(batch.events, events);
            let (charged, body) = (batch.cost, batch.body.len());
            assert_eq!(p.shared.held_bytes(), charged);
            p.ack(&batch);
            let retained = retained(batch);
            assert_eq!(retained, body, "{events} events of {size} bytes");
            assert!(
                retained <= charged,
                "{events} events of {size} bytes: {retained} bytes kept, {charged} charged"
            );
        }
    }

    #[test]
    fn a_batch_whose_strings_need_escaping_is_charged_for_its_real_size() {
        // Control characters take six bytes each in JSON. The estimate made when the event
        // arrives does not know that; the charge is corrected when the batch is serialized.
        let mut p = Pipeline::new(test_config());
        let escaped = AttributedUpdate {
            actor: Some(Actor {
                user_id: Some("\u{1}".repeat(128)),
                writer: Some("\u{2}".repeat(64)),
            }),
            ..event("doc", 1)
        };
        let estimate = event_cost(&escaped);
        p.sink.offer(escaped);
        p.pump();
        assert_eq!(p.shared.held_bytes(), estimate);
        p.advance(WINDOW);
        let batch = p.start_one();
        assert!(batch.body.len() > estimate);
        assert_eq!(batch.cost, batch.body.len());
        assert_eq!(p.shared.held_bytes(), batch.body.len());
        // And all of it is released again.
        p.ack(&batch);
        assert_eq!(p.shared.held_bytes(), 0);
    }

    #[test]
    fn a_closed_batch_keeps_no_spare_room_for_events() {
        let mut p = Pipeline::new(test_config());
        for _ in 0..5 {
            p.emit("doc", 1);
        }
        p.advance(WINDOW);
        let state = &p.batcher.docs["doc"];
        assert!(state.open.is_none());
        let batch = &state.queue[0];
        assert_eq!(batch.events.len(), 5);
        assert_eq!(batch.events.capacity(), 5);
    }

    /// The wire contract shared with the receiver: see `testdata/update-webhook-contract`.
    /// Fails when the sender's output differs from the fixture files by a byte. After an
    /// intended format change, `UPDATE_CONTRACT_FIXTURES=1` rewrites them (then update the
    /// receiver's copy).
    #[test]
    fn contract_fixtures_match_what_the_sender_produces() {
        const DOC_ID: &str = "contract-doc";
        const INSTANCE_ID: &str = "contract-instance";
        const CONTRACT_SECRET: &str = "contract-secret";
        const TIMESTAMP: u64 = 1_794_312_000;

        let at = |millis: u64| UNIX_EPOCH + Duration::from_millis(1_794_312_000_000 + millis);
        let event = |seq, actor, update: &[u8], millis| SeqEvent {
            seq,
            cost: 0,
            actor,
            update: update.to_vec(),
            occurred_at: at(millis),
        };
        let mut batch = Batch::default();
        batch.push(event(
            41,
            Some(Actor {
                user_id: Some("user-1".to_string()),
                writer: Some("ui".to_string()),
            }),
            &[0, 1, 2, 250, 251, 252],
            0,
        ));
        batch.push(event(
            42,
            Some(Actor {
                user_id: None,
                writer: Some("integration-pull".to_string()),
            }),
            &[3],
            250,
        ));
        batch.push(event(43, None, &[7, 7], 1_500));

        let batch = prepare(DOC_ID, INSTANCE_ID, batch, true);
        let empty = prepare(DOC_ID, INSTANCE_ID, Batch::default(), true);
        let mut signature = serde_json::to_string_pretty(&serde_json::json!({
            "secret": CONTRACT_SECRET,
            "timestamp": TIMESTAMP.to_string(),
            "batch": sign(CONTRACT_SECRET.as_bytes(), TIMESTAMP, &batch.body),
            "emptyGapBatch": sign(CONTRACT_SECRET.as_bytes(), TIMESTAMP, &empty.body),
        }))
        .unwrap();
        signature.push('\n');

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/update-webhook-contract");
        let regenerate = std::env::var("UPDATE_CONTRACT_FIXTURES").is_ok_and(|v| v == "1");
        for (name, produced) in [
            ("batch.json", &batch.body[..]),
            ("empty-gap-batch.json", &empty.body[..]),
            ("signature.json", signature.as_bytes()),
        ] {
            let path = dir.join(name);
            if regenerate {
                std::fs::write(&path, produced).unwrap();
            }
            let fixture = std::fs::read(&path).unwrap();
            assert!(
                fixture == produced,
                "{name} differs from what the sender produces:\n fixture: {}\nproduced: {}",
                String::from_utf8_lossy(&fixture),
                String::from_utf8_lossy(produced),
            );
        }
        if regenerate {
            std::fs::write(dir.join(CONTRACT_CHECKSUMS), contract_checksums(&dir)).unwrap();
        }
        assert_contract_checksums(&dir);
    }

    const CONTRACT_CHECKSUMS: &str = "CHECKSUMS.sha256";

    /// The fixture files of the contract: every `.json` file in the directory, by name.
    fn contract_fixture_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.ends_with(".json"))
            .collect();
        names.sort();
        names
    }

    /// What `CHECKSUMS.sha256` must contain: the output of `sha256sum *.json` in the fixture
    /// directory (hex digest, two spaces, file name, one line per file, sorted by name).
    fn contract_checksums(dir: &std::path::Path) -> String {
        use sha2::Digest;
        contract_fixture_names(dir)
            .iter()
            .map(|name| {
                let digest = Sha256::digest(std::fs::read(dir.join(name)).unwrap());
                format!("{}  {name}\n", HEXLOWER.encode(&digest))
            })
            .collect()
    }

    fn assert_contract_checksums(dir: &std::path::Path) {
        let recorded = std::fs::read_to_string(dir.join(CONTRACT_CHECKSUMS)).unwrap();
        assert_eq!(
            recorded,
            contract_checksums(dir),
            "{CONTRACT_CHECKSUMS} does not match the fixture files. If the change to the wire \
             format is intended, regenerate (see the README beside the fixtures) and make the \
             same change to the receiver repo's copy of the fixtures and of {CONTRACT_CHECKSUMS}."
        );
    }

    /// The fixtures are kept in two repos, this one and the receiver's. `CHECKSUMS.sha256`
    /// is what ties the copies together: each repo has the same file and a test like this
    /// one, so a fixture edited in either repo fails that repo's test until the checksums
    /// are updated, and the checksum file then differs between the repos until the other
    /// copy follows.
    #[test]
    fn contract_fixtures_match_their_checksums() {
        if std::env::var("UPDATE_CONTRACT_FIXTURES").is_ok_and(|v| v == "1") {
            // Being regenerated, and checked, by the test above.
            return;
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/update-webhook-contract");
        assert_eq!(
            contract_fixture_names(&dir),
            ["batch.json", "empty-gap-batch.json", "signature.json"],
            "a fixture was added or removed: update this list, the README and the receiver repo"
        );
        assert_contract_checksums(&dir);
    }
}

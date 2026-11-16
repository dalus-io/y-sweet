use crate::api_types::Authorization;
use crate::auth::Actor;
use crate::sync::{
    self, actor_origin, awareness::Awareness, DefaultProtocol, Message, Protocol, SyncMessage,
    MSG_SYNC, MSG_SYNC_UPDATE,
};
use std::sync::{Arc, OnceLock, RwLock};
use yrs::{
    block::ClientID,
    encoding::write::Write,
    updates::{
        decoder::Decode,
        encoder::{Encode, Encoder, EncoderV1},
    },
    Origin, ReadTxn, Subscription, Transact, Update,
};

// TODO: this is an implementation detail and should not be exposed.
pub const DOC_NAME: &str = "doc";

#[cfg(not(feature = "sync"))]
type Callback = Arc<dyn Fn(&[u8]) + 'static>;

#[cfg(feature = "sync")]
type Callback = Arc<dyn Fn(&[u8]) + 'static + Send + Sync>;

const SYNC_STATUS_MESSAGE: u8 = 102;

pub struct DocConnection {
    awareness: Arc<RwLock<Awareness>>,
    /// The connection's observers of the doc and of its awareness; dropping one unregisters
    /// it. Registered and dropped only under the doc write lock (see the `Drop` impl).
    subscriptions: Option<(Subscription, Subscription)>,
    authorization: Authorization,
    /// The origin every write from this connection is applied under. It encodes the actor the
    /// connection authenticated as; `None` for an unattributed connection.
    origin: Option<Origin>,
    callback: Callback,
    closed: Arc<OnceLock<()>>,

    /// If the client sends an awareness state, this will be set to its client ID.
    /// It is used to clear the awareness state when a client disconnects.
    client_id: OnceLock<ClientID>,
}

impl DocConnection {
    #[cfg(not(feature = "sync"))]
    pub fn new<F>(
        awareness: Arc<RwLock<Awareness>>,
        authorization: Authorization,
        actor: Option<Actor>,
        callback: F,
    ) -> Self
    where
        F: Fn(&[u8]) + 'static,
    {
        Self::new_inner(awareness, authorization, actor, Arc::new(callback))
    }

    #[cfg(feature = "sync")]
    pub fn new<F>(
        awareness: Arc<RwLock<Awareness>>,
        authorization: Authorization,
        actor: Option<Actor>,
        callback: F,
    ) -> Self
    where
        F: Fn(&[u8]) + 'static + Send + Sync,
    {
        Self::new_inner(awareness, authorization, actor, Arc::new(callback))
    }

    pub fn new_inner(
        awareness: Arc<RwLock<Awareness>>,
        authorization: Authorization,
        actor: Option<Actor>,
        callback: Callback,
    ) -> Self {
        let closed = Arc::new(OnceLock::new());

        let subscriptions = {
            // Held while the observers are registered. Registration must not run beside the
            // removal of another connection's observers (see the `Drop` impl), and this lock is
            // what keeps the two apart.
            let mut awareness = awareness.write().unwrap();

            // Initial handshake is based on this:
            // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/sync.rs#L45-L54

            {
                // Send a server-side state vector, so that the client can send
                // updates that happened offline.
                let sv = awareness.doc().transact().state_vector();
                let sync_step_1 = Message::Sync(SyncMessage::SyncStep1(sv)).encode_v1();
                callback(&sync_step_1);
            }

            {
                // Send the initial awareness state.
                let update = awareness.update().unwrap();
                let awareness = Message::Awareness(update).encode_v1();
                callback(&awareness);
            }

            let doc_subscription = {
                let doc = awareness.doc();
                let callback = callback.clone();
                let closed = closed.clone();
                doc.observe_update_v1(move |_, event| {
                    if closed.get().is_some() {
                        return;
                    }
                    // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/net/broadcast.rs#L47-L52
                    let mut encoder = EncoderV1::new();
                    encoder.write_var(MSG_SYNC);
                    encoder.write_var(MSG_SYNC_UPDATE);
                    encoder.write_buf(&event.update);
                    let msg = encoder.to_vec();
                    callback(&msg);
                })
                .unwrap()
            };

            let callback = callback.clone();
            let closed = closed.clone();
            let awareness_subscription = awareness.on_update(move |awareness, e| {
                if closed.get().is_some() {
                    return;
                }

                // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/net/broadcast.rs#L59
                let added = e.added();
                let updated = e.updated();
                let removed = e.removed();
                let mut changed = Vec::with_capacity(added.len() + updated.len() + removed.len());
                changed.extend_from_slice(added);
                changed.extend_from_slice(updated);
                changed.extend_from_slice(removed);

                if let Ok(u) = awareness.update_with_clients(changed) {
                    let msg = Message::Awareness(u).encode_v1();
                    callback(&msg);
                }
            });

            (doc_subscription, awareness_subscription)
        };

        Self {
            awareness,
            subscriptions: Some(subscriptions),
            authorization,
            origin: actor.as_ref().map(actor_origin),
            callback,
            client_id: OnceLock::new(),
            closed,
        }
    }

    pub async fn send(&self, update: &[u8]) -> Result<(), anyhow::Error> {
        let msg = Message::decode_v1(update)?;
        let result = self.handle_msg(&DefaultProtocol, msg)?;

        if let Some(result) = result {
            let msg = result.encode_v1();
            (self.callback)(&msg);
        }

        Ok(())
    }

    // Adapted from:
    // https://github.com/y-crdt/y-sync/blob/56958e83acfd1f3c09f5dd67cf23c9c72f000707/src/net/conn.rs#L184C1-L222C1
    pub fn handle_msg<P: Protocol>(
        &self,
        protocol: &P,
        msg: Message,
    ) -> Result<Option<Message>, sync::Error> {
        let can_write = matches!(self.authorization, Authorization::Full);
        let a = &self.awareness;
        match msg {
            Message::Sync(msg) => match msg {
                SyncMessage::SyncStep1(sv) => {
                    let awareness = a.read().unwrap();
                    protocol.handle_sync_step1(&awareness, sv)
                }
                SyncMessage::SyncStep2(update) => {
                    if can_write {
                        let mut awareness = a.write().unwrap();
                        protocol.handle_sync_step2_with(
                            &mut awareness,
                            Update::decode_v1(&update)?,
                            self.origin.clone(),
                        )
                    } else {
                        Err(sync::Error::PermissionDenied {
                            reason: "Token does not have write access".to_string(),
                        })
                    }
                }
                SyncMessage::Update(update) => {
                    if can_write {
                        let mut awareness = a.write().unwrap();
                        protocol.handle_update_with(
                            &mut awareness,
                            Update::decode_v1(&update)?,
                            self.origin.clone(),
                        )
                    } else {
                        Err(sync::Error::PermissionDenied {
                            reason: "Token does not have write access".to_string(),
                        })
                    }
                }
            },
            Message::Auth(reason) => {
                let awareness = a.read().unwrap();
                protocol.handle_auth(&awareness, reason)
            }
            Message::AwarenessQuery => {
                let awareness = a.read().unwrap();
                protocol.handle_awareness_query(&awareness)
            }
            Message::Awareness(update) => {
                if update.clients.len() == 1 {
                    let client_id = update.clients.keys().next().unwrap();
                    self.client_id.get_or_init(|| *client_id);
                } else {
                    tracing::warn!("Received awareness update with more than one client");
                }
                let mut awareness = a.write().unwrap();
                protocol.handle_awareness_update(&mut awareness, update)
            }
            Message::Custom(SYNC_STATUS_MESSAGE, data) => {
                // Respond to the client with the same payload it sent.
                Ok(Some(Message::Custom(SYNC_STATUS_MESSAGE, data)))
            }
            Message::Custom(tag, data) => {
                let mut awareness = a.write().unwrap();
                protocol.missing_handle(&mut awareness, tag, data)
            }
        }
    }
}

impl Drop for DocConnection {
    fn drop(&mut self) {
        self.closed.set(()).unwrap();

        // The doc write lock, always, and held until the observers are unregistered.
        //
        // yrs (0.19) registers an observer with a compare-and-swap loop that never reloads the
        // list head it compares against. If the head is unregistered in between, that loop
        // spins for ever, under the doc write lock [DocConnection::new] holds, and the doc is
        // frozen for everyone: no reads, no writes, no saves. Unregistering here under the
        // same lock means a connection is never closed while another is being opened. (It
        // also keeps two concurrent closes from undoing each other's removal.)
        //
        // A poisoned lock is taken all the same: this runs during unwinding too, where a
        // second panic would abort the process.
        let mut awareness = self
            .awareness
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // If this client had an awareness state, remove it.
        if let Some(client_id) = self.client_id.get() {
            awareness.remove_state(*client_id);
        }
        drop(self.subscriptions.take());
    }
}

#[cfg(all(test, feature = "sync"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    /// Connections to one doc opened and closed from several threads at once, as websocket
    /// sessions are.
    ///
    /// yrs 0.19 registers an observer with a compare-and-swap loop that never reloads the list
    /// head it compares against (`Observer::subscribe_with`). If another thread unsubscribes
    /// the head in between, the loop spins for ever, and it does so inside
    /// [DocConnection::new], under the doc write lock: every other user of the doc then blocks
    /// behind it. So a connection must never be closed while another is being opened.
    ///
    /// The sessions run on plain threads and a watchdog fails the test, rather than hanging it,
    /// if they stop making progress.
    #[test]
    fn connections_opening_and_closing_at_once_do_not_freeze_the_doc() {
        const THREADS: usize = 8;
        const SESSIONS_PER_THREAD: usize = 5_000;

        let awareness = Arc::new(RwLock::new(Awareness::new(yrs::Doc::new())));
        let sessions = Arc::new(AtomicUsize::new(0));
        let give_up = Arc::new(AtomicBool::new(false));

        let workers: Vec<_> = (0..THREADS)
            .map(|thread| {
                let awareness = awareness.clone();
                let sessions = sessions.clone();
                let give_up = give_up.clone();
                std::thread::spawn(move || {
                    for session in 0..SESSIONS_PER_THREAD {
                        if give_up.load(Ordering::Relaxed) {
                            return;
                        }
                        let connection = DocConnection::new(
                            awareness.clone(),
                            Authorization::Full,
                            None,
                            |_| {},
                        );
                        if session % 2 == 0 {
                            // Half the sessions also publish an awareness state, which the
                            // close then has to clear.
                            let mut update = Awareness::new(yrs::Doc::new());
                            update.set_local_state(format!("{{\"t\":{thread}}}"));
                            let msg = Message::Awareness(update.update().unwrap());
                            connection.handle_msg(&DefaultProtocol, msg).unwrap();
                        }
                        drop(connection);
                        sessions.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        // The watchdog: a freeze shows as the count standing still.
        let total = THREADS * SESSIONS_PER_THREAD;
        let mut last = (0, Instant::now());
        loop {
            let done = sessions.load(Ordering::Relaxed);
            if done == total {
                break;
            }
            if done != last.0 {
                last = (done, Instant::now());
            } else if last.1.elapsed() > Duration::from_secs(10) {
                // The stuck threads cannot be stopped; they are left behind and the test
                // process ends with the failure.
                give_up.store(true, Ordering::Relaxed);
                panic!("the doc froze after {done} of {total} sessions");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for worker in workers {
            worker.join().unwrap();
        }

        // Every connection is gone, and so is everything it registered: a write still works
        // and no awareness state is left behind.
        let awareness = awareness.try_write().expect("the doc lock is free");
        assert!(awareness.clients().is_empty());
    }
}

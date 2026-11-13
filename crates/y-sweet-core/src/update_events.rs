//! Attributed update events.
//!
//! This module turns the updates a doc applies into [AttributedUpdate]s and hands them to a
//! callback. It does no IO and knows nothing about where the events go: the callback is the only
//! coupling to whoever consumes them.

use crate::{auth::Actor, sync::actor_from_origin};
use std::{sync::Arc, time::SystemTime};
use yrs::{Doc, Subscription};

/// One transaction's worth of changes to a doc, with the actor that made them visible.
#[derive(Debug, Clone, PartialEq)]
pub struct AttributedUpdate {
    pub doc_id: String,
    /// The actor of the transaction that applied the update. `None` when the writer was not
    /// attributed (a server token, a token minted without an actor, or no auth at all).
    pub actor: Option<Actor>,
    /// The v1 encoding of what the transaction changed. This is the transaction's own diff, not
    /// the bytes the writer sent: anything the doc already held is absent.
    pub update: Vec<u8>,
    pub occurred_at: SystemTime,
}

/// Receives every [AttributedUpdate] of a doc.
///
/// It is called synchronously while the doc is locked for writing, so it must not block.
pub type UpdateCallback = Arc<dyn Fn(AttributedUpdate) + Send + Sync>;

/// Calls `on_update` for every update applied to `doc` for as long as the returned subscription
/// is alive.
///
/// The actor is read from the origin of the transaction that produced the update (see
/// [crate::sync::actor_origin]). A transaction with any other origin, or none, is reported with
/// `actor: None`; nothing is dropped.
pub fn observe_attributed_updates(
    doc: &Doc,
    doc_id: &str,
    on_update: UpdateCallback,
) -> anyhow::Result<Subscription> {
    let doc_id = doc_id.to_string();
    doc.observe_update_v1(move |txn, event| {
        on_update(AttributedUpdate {
            doc_id: doc_id.clone(),
            actor: actor_from_origin(txn.origin()),
            update: event.update.clone(),
            occurred_at: SystemTime::now(),
        });
    })
    .map_err(|_| anyhow::anyhow!("Failed to subscribe to updates"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api_types::Authorization,
        doc_connection::DocConnection,
        doc_sync::DocWithSyncKv,
        sync::{self, DefaultProtocol, Message, SyncMessage},
    };
    use std::sync::Mutex;
    use yrs::{updates::decoder::Decode, GetString, ReadTxn, StateVector, Text, Transact, Update};

    type Events = Arc<Mutex<Vec<AttributedUpdate>>>;

    fn actor(user_id: &str, writer: &str) -> Actor {
        Actor {
            user_id: Some(user_id.to_string()),
            writer: Some(writer.to_string()),
        }
    }

    async fn observed_doc() -> (DocWithSyncKv, Events) {
        let events = Events::default();
        let on_update: UpdateCallback = {
            let events = events.clone();
            Arc::new(move |event| events.lock().unwrap().push(event))
        };
        let doc = DocWithSyncKv::new("doc123", None, || {}, false, Some(on_update))
            .await
            .unwrap();
        (doc, events)
    }

    fn connect(
        doc: &DocWithSyncKv,
        authorization: Authorization,
        actor: Option<Actor>,
    ) -> DocConnection {
        DocConnection::new(doc.awareness(), authorization, actor, |_| {})
    }

    fn send(connection: &DocConnection, msg: SyncMessage) -> Result<Option<Message>, sync::Error> {
        connection.handle_msg(&DefaultProtocol, Message::Sync(msg))
    }

    /// A client that types into the text `t`, returning the incremental update of each edit.
    struct Client {
        doc: Doc,
    }

    impl Client {
        fn new(client_id: u64) -> Self {
            Self {
                doc: Doc::with_client_id(client_id),
            }
        }

        fn push(&self, chunk: &str) -> Vec<u8> {
            let text = self.doc.get_or_insert_text("t");
            let mut txn = self.doc.transact_mut();
            text.push(&mut txn, chunk);
            txn.encode_update_v1()
        }

        fn full_state(&self) -> Vec<u8> {
            self.doc
                .transact()
                .encode_state_as_update_v1(&StateVector::default())
        }
    }

    fn server_text(doc: &DocWithSyncKv) -> String {
        let awareness = doc.awareness();
        let awareness = awareness.read().unwrap();
        let txn = awareness.doc().transact();
        txn.get_text("t")
            .map(|text| text.get_string(&txn))
            .unwrap_or_default()
    }

    /// The text a fresh doc holds after applying the emitted updates in order.
    fn replay(events: &[AttributedUpdate]) -> String {
        let doc = Doc::new();
        let text = doc.get_or_insert_text("t");
        for event in events {
            doc.transact_mut()
                .apply_update(Update::decode_v1(&event.update).unwrap());
        }
        let txn = doc.transact();
        text.get_string(&txn)
    }

    #[tokio::test]
    async fn update_from_attributed_connection_carries_its_actor() {
        let (doc, events) = observed_doc().await;
        let alice = actor("alice", "ui");
        let connection = connect(&doc, Authorization::Full, Some(alice.clone()));

        send(
            &connection,
            SyncMessage::Update(Client::new(1).push("hello")),
        )
        .unwrap();

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].doc_id, "doc123");
        assert_eq!(events[0].actor, Some(alice));
        assert_eq!(replay(&events), "hello");
    }

    #[tokio::test]
    async fn sync_step2_from_attributed_connection_carries_its_actor() {
        let (doc, events) = observed_doc().await;
        let alice = actor("alice", "ui");
        let connection = connect(&doc, Authorization::Full, Some(alice.clone()));

        let client = Client::new(1);
        client.push("offline ");
        client.push("edits");
        send(&connection, SyncMessage::SyncStep2(client.full_state())).unwrap();

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].actor, Some(alice));
        assert_eq!(replay(&events), "offline edits");
    }

    #[tokio::test]
    async fn connection_without_actor_is_unattributed() {
        let (doc, events) = observed_doc().await;
        let connection = connect(&doc, Authorization::Full, None);

        let client = Client::new(1);
        send(&connection, SyncMessage::Update(client.push("a"))).unwrap();
        client.push("b");
        send(&connection, SyncMessage::SyncStep2(client.full_state())).unwrap();

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].actor, None);
        assert_eq!(events[1].actor, None);
        assert_eq!(replay(&events), "ab");
    }

    #[tokio::test]
    async fn each_connection_tags_its_own_writes() {
        let (doc, events) = observed_doc().await;
        let alice = actor("alice", "ui");
        let agent = Actor {
            user_id: None,
            writer: Some("agent".to_string()),
        };
        let alice_connection = connect(&doc, Authorization::Full, Some(alice.clone()));
        let agent_connection = connect(&doc, Authorization::Full, Some(agent.clone()));
        let anonymous_connection = connect(&doc, Authorization::Full, None);

        send(
            &alice_connection,
            SyncMessage::Update(Client::new(1).push("a")),
        )
        .unwrap();
        send(
            &agent_connection,
            SyncMessage::Update(Client::new(2).push("b")),
        )
        .unwrap();
        send(
            &anonymous_connection,
            SyncMessage::Update(Client::new(3).push("c")),
        )
        .unwrap();

        let actors: Vec<_> = events
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.actor.clone())
            .collect();
        assert_eq!(actors, vec![Some(alice), Some(agent), None]);
    }

    #[tokio::test]
    async fn apply_update_tags_the_given_actor() {
        let (doc, events) = observed_doc().await;
        let alice = actor("alice", "http");
        let client = Client::new(1);

        doc.apply_update(&client.push("a"), Some(&alice)).unwrap();
        doc.apply_update(&client.push("b"), None).unwrap();

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].actor, Some(alice));
        assert_eq!(events[1].actor, None);
        assert_eq!(replay(&events), "ab");
    }

    #[tokio::test]
    async fn foreign_origin_is_unattributed_not_dropped() {
        let (doc, events) = observed_doc().await;
        {
            let awareness = doc.awareness();
            let awareness = awareness.write().unwrap();
            let text = awareness.doc().get_or_insert_text("t");
            let mut txn = awareness.doc().transact_mut_with("some-other-origin");
            text.push(&mut txn, "x");
        }
        {
            // Looks like an actor origin, but is not valid JSON.
            let awareness = doc.awareness();
            let awareness = awareness.write().unwrap();
            let text = awareness.doc().get_or_insert_text("t");
            let mut txn = awareness.doc().transact_mut_with("actor:not-json");
            text.push(&mut txn, "y");
        }

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].actor, None);
        assert_eq!(events[1].actor, None);
        assert_eq!(replay(&events), "xy");
    }

    #[tokio::test]
    async fn read_only_connection_writes_nothing() {
        let (doc, events) = observed_doc().await;
        let connection = connect(&doc, Authorization::ReadOnly, Some(actor("alice", "ui")));

        let client = Client::new(1);
        assert!(send(&connection, SyncMessage::Update(client.push("a"))).is_err());
        assert!(send(&connection, SyncMessage::SyncStep2(client.full_state())).is_err());

        assert!(events.lock().unwrap().is_empty());
        assert_eq!(server_text(&doc), "");
    }

    /// Pins a yrs internal (design section 3.4): an update the doc already holds commits a
    /// transaction that changed nothing, and yrs emits no update event for it.
    #[tokio::test]
    async fn no_op_update_emits_nothing() {
        let (doc, events) = observed_doc().await;
        let alice_connection = connect(&doc, Authorization::Full, Some(actor("alice", "ui")));
        let bob_connection = connect(&doc, Authorization::Full, Some(actor("bob", "ui")));

        let client = Client::new(1);
        let update = client.push("hello");
        send(&alice_connection, SyncMessage::Update(update.clone())).unwrap();
        assert_eq!(events.lock().unwrap().len(), 1);

        // The very same update again, from the same writer and from another one.
        send(&alice_connection, SyncMessage::Update(update.clone())).unwrap();
        send(&bob_connection, SyncMessage::Update(update)).unwrap();
        // A reconnect catch-up that carries nothing the server lacks.
        send(&bob_connection, SyncMessage::SyncStep2(client.full_state())).unwrap();
        // The HTTP update route with the same content.
        doc.apply_update(&client.full_state(), None).unwrap();

        assert_eq!(events.lock().unwrap().len(), 1);
        assert_eq!(server_text(&doc), "hello");
    }

    /// Pins a yrs internal and the accepted inexactness of design section 3.4: an update whose
    /// dependency is missing is parked as pending and emits nothing; it is integrated by the
    /// transaction that supplies the dependency, and is emitted under that transaction's actor.
    #[tokio::test]
    async fn pending_update_is_emitted_under_the_writer_that_unblocks_it() {
        let (doc, events) = observed_doc().await;
        let alice = actor("alice", "ui");
        let bob = actor("bob", "ui");
        let alice_connection = connect(&doc, Authorization::Full, Some(alice));
        let bob_connection = connect(&doc, Authorization::Full, Some(bob.clone()));

        let client = Client::new(1);
        let first = client.push("a");
        let second = client.push("b"); // depends on `first`

        // Alice delivers the second edit before anyone delivered the first.
        send(&alice_connection, SyncMessage::Update(second)).unwrap();
        assert!(events.lock().unwrap().is_empty());
        assert_eq!(server_text(&doc), "");

        // Bob supplies the missing dependency.
        send(&bob_connection, SyncMessage::Update(first)).unwrap();
        assert_eq!(server_text(&doc), "ab");

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 1);
        // Alice's "b" is reported under Bob.
        assert_eq!(events[0].actor, Some(bob));
        assert_eq!(replay(&events), "ab");
    }

    #[tokio::test]
    async fn loading_a_stored_doc_emits_nothing() {
        use crate::{store::Store, sync_kv::test::MemoryStore};

        let store = MemoryStore::default();
        let store_handle = || Some(Arc::new(Box::new(store.clone()) as Box<dyn Store>));
        {
            let doc = DocWithSyncKv::new("doc123", store_handle(), || {}, false, None)
                .await
                .unwrap();
            doc.apply_update(&Client::new(1).push("hello"), None)
                .unwrap();
            doc.sync_kv().persist().await.unwrap();
        }

        let events = Events::default();
        let on_update: UpdateCallback = {
            let events = events.clone();
            Arc::new(move |event| events.lock().unwrap().push(event))
        };
        let doc = DocWithSyncKv::new("doc123", store_handle(), || {}, false, Some(on_update))
            .await
            .unwrap();
        // The stored content is there, and loading it was not reported as an update.
        assert_eq!(server_text(&doc), "hello");
        assert!(events.lock().unwrap().is_empty());

        // The observer is live for what comes after.
        doc.apply_update(&Client::new(2).push("!"), None).unwrap();
        assert_eq!(events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn delete_only_update_emits_an_event_with_and_without_gc() {
        for skip_gc in [false, true] {
            let events = Events::default();
            let on_update: UpdateCallback = {
                let events = events.clone();
                Arc::new(move |event| events.lock().unwrap().push(event))
            };
            let doc = DocWithSyncKv::new("doc123", None, || {}, skip_gc, Some(on_update))
                .await
                .unwrap();
            let alice = actor("alice", "ui");
            let client = Client::new(1);
            doc.apply_update(&client.push("hello"), None).unwrap();

            // An update that only deletes: no new blocks, just a delete set.
            let delete = {
                let text = client.doc.get_or_insert_text("t");
                let mut txn = client.doc.transact_mut();
                text.remove_range(&mut txn, 0, 5);
                txn.encode_update_v1()
            };
            doc.apply_update(&delete, Some(&alice)).unwrap();

            let events = events.lock().unwrap();
            assert_eq!(events.len(), 2, "skip_gc={skip_gc}");
            assert_eq!(events[1].actor, Some(alice), "skip_gc={skip_gc}");
            assert_eq!(server_text(&doc), "", "skip_gc={skip_gc}");
            // Replaying the emitted updates reproduces the deletion.
            assert_eq!(replay(&events), "", "skip_gc={skip_gc}");
            assert_eq!(replay(&events[..1]), "hello", "skip_gc={skip_gc}");
        }
    }
}

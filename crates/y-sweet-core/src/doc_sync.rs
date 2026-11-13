#[cfg(feature = "sync")]
use crate::update_events::{observe_attributed_updates, UpdateCallback};
use crate::{
    auth::Actor,
    doc_connection::DOC_NAME,
    store::Store,
    sync::{actor_origin, awareness::Awareness},
    sync_kv::SyncKv,
};
use anyhow::{anyhow, Context, Result};
use std::sync::{Arc, RwLock};
use yrs::{updates::decoder::Decode, ReadTxn, StateVector, Subscription, Transact, Update};
use yrs_kvstore::DocOps;

pub struct DocWithSyncKv {
    awareness: Arc<RwLock<Awareness>>,
    sync_kv: Arc<SyncKv>,
    #[allow(unused)] // acts as RAII guard
    subscription: Subscription,
    #[cfg(feature = "sync")]
    #[allow(unused)] // acts as RAII guard
    update_subscription: Option<Subscription>,
}

impl DocWithSyncKv {
    pub fn awareness(&self) -> Arc<RwLock<Awareness>> {
        self.awareness.clone()
    }

    pub fn sync_kv(&self) -> Arc<SyncKv> {
        self.sync_kv.clone()
    }

    pub async fn new<F>(
        key: &str,
        store: Option<Arc<Box<dyn Store>>>,
        dirty_callback: F,
        skip_gc: bool,
        #[cfg(feature = "sync")] on_update: Option<UpdateCallback>,
    ) -> Result<Self>
    where
        F: Fn() + Send + Sync + 'static,
    {
        let sync_kv = SyncKv::new(store, key, dirty_callback)
            .await
            .context("Failed to create SyncKv")?;

        let sync_kv = Arc::new(sync_kv);
        let doc = yrs::Doc::with_options(yrs::Options {
            skip_gc,
            ..yrs::Options::default()
        });

        {
            let mut txn = doc.transact_mut();
            sync_kv
                .load_doc(DOC_NAME, &mut txn)
                .map_err(|_| anyhow!("Failed to load doc"))?;
        }

        let subscription = {
            let sync_kv = sync_kv.clone();
            doc.observe_update_v1(move |_, event| {
                sync_kv.push_update(DOC_NAME, &event.update).unwrap();
                sync_kv
                    .flush_doc_with(DOC_NAME, Default::default())
                    .unwrap();
            })
            .map_err(|_| anyhow!("Failed to subscribe to updates"))?
        };

        // Registered after the initial load, so loading a doc from the store emits nothing.
        #[cfg(feature = "sync")]
        let update_subscription = match on_update {
            Some(on_update) => Some(
                observe_attributed_updates(&doc, key, on_update)
                    .map_err(|_| anyhow!("Failed to subscribe to attributed updates"))?,
            ),
            None => None,
        };

        let awareness = Arc::new(RwLock::new(Awareness::new(doc)));
        Ok(Self {
            awareness,
            sync_kv,
            subscription,
            #[cfg(feature = "sync")]
            update_subscription,
        })
    }

    pub fn as_update(&self) -> Vec<u8> {
        let awareness_guard = self.awareness.read().unwrap();
        let doc = &awareness_guard.doc;

        let txn = doc.transact();

        txn.encode_state_as_update_v1(&StateVector::default())
    }

    /// Applies a v1 update to the doc. When `actor` is given, the transaction is tagged with it
    /// so that update observers can attribute the change.
    pub fn apply_update(&self, update: &[u8], actor: Option<&Actor>) -> Result<()> {
        apply_update_to(&self.awareness, update, actor)
    }

    /// Retires the doc, so it can be dropped, if nothing but this struct holds its awareness:
    /// no connection, and no writer that took it with [DocWithSyncKv::awareness]. After this
    /// the doc's writes are no longer saved (see [SyncKv::shutdown]).
    ///
    /// The check and the retirement happen under the doc's write lock. A writer that holds the
    /// awareness and has seen [is_live] return `true` therefore cannot have the doc retired
    /// under it, and a writer that checks after retirement sees it.
    // The write lock is for exclusion: with a read lock, a writer's `is_live` check (a read
    // lock) could run between the count below and `shutdown`.
    pub fn retire_if_unused(&self) -> bool {
        let _guard = self.awareness.write().unwrap();
        if Arc::strong_count(&self.awareness) > 1 {
            return false;
        }
        self.sync_kv.shutdown();
        true
    }
}

/// Applies a v1 update to a doc through its awareness (see [DocWithSyncKv::apply_update]).
// The doc's write lock, as every writer takes it: it orders the write with other writers,
// readers of the doc, and retirement (see `retire_if_unused`).
#[allow(clippy::readonly_write_lock)]
pub fn apply_update_to(
    awareness: &RwLock<Awareness>,
    update: &[u8],
    actor: Option<&Actor>,
) -> Result<()> {
    let awareness_guard = awareness.write().unwrap();
    let doc = &awareness_guard.doc;

    let update: Update =
        Update::decode_v1(update).map_err(|_| anyhow!("Failed to decode update"))?;

    let mut txn = match actor {
        Some(actor) => doc.transact_mut_with(actor_origin(actor)),
        None => doc.transact_mut(),
    };
    txn.apply_update(update);

    Ok(())
}

/// Whether a doc still saves its writes: false once it was retired (see
/// [DocWithSyncKv::retire_if_unused]). Checked under the doc lock, so it is ordered with
/// retirement. A caller that holds `awareness` and gets `true` can write to the doc for as long
/// as it holds it.
pub fn is_live(awareness: &RwLock<Awareness>, sync_kv: &SyncKv) -> bool {
    let _guard = awareness.read().unwrap();
    !sync_kv.is_shutdown()
}

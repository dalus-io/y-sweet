use crate::store::Store;
use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    ops::Bound,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use yrs_kvstore::{DocOps, KVEntry};

pub struct SyncKv {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
    store: Option<Arc<Box<dyn Store>>>,
    key: String,
    dirty: AtomicBool,
    dirty_callback: Box<dyn Fn() + Send + Sync>,
    shutdown: AtomicBool,
}

impl SyncKv {
    pub async fn new<Callback: Fn() + Send + Sync + 'static>(
        store: Option<Arc<Box<dyn Store>>>,
        key: &str,
        callback: Callback,
    ) -> Result<Self> {
        let key = format!("{}/data.ysweet", key);

        let data = if let Some(store) = &store {
            if let Some(snapshot) = store.get(&key).await.context("Failed to get from store.")? {
                tracing::info!(size=?snapshot.len(), "Loaded snapshot");
                bincode::deserialize(&snapshot).context("Failed to deserialize.")?
            } else {
                BTreeMap::new()
            }
        } else {
            BTreeMap::new()
        };

        Ok(Self {
            data: Arc::new(Mutex::new(data)),
            store,
            key,
            dirty: AtomicBool::new(false),
            dirty_callback: Box::new(callback),
            shutdown: AtomicBool::new(false),
        })
    }

    fn mark_dirty(&self) {
        if !self.shutdown.load(Ordering::SeqCst) {
            let was_updated = !self.dirty.swap(true, Ordering::SeqCst);
            if was_updated {
                (self.dirty_callback)();
            }
        }
    }

    pub async fn persist(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Only persist if actually dirty
        if !self.dirty.load(Ordering::SeqCst) {
            tracing::info!("Not persisting, no changes detected");
            return Ok(());
        }

        if let Some(store) = &self.store {
            let snapshot = {
                let data = self.data.lock().unwrap();
                bincode::serialize(&*data)?
            };

            tracing::info!(size=?snapshot.len(), "Persisting snapshot");
            store.set(&self.key, snapshot).await?;
        }
        self.dirty.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Merge the pending update log into the stored document state.
    /// Copies the state and the log under the map lock, but decodes, merges and encodes
    /// with no lock held, so edits keep flowing. Removes only the updates it merged:
    /// updates pushed meanwhile have higher keys and stay for the next run.
    pub fn compact(&self, name: &str) -> Result<()> {
        use yrs::updates::{decoder::Decode, encoder::Encode};
        use yrs::{ReadTxn, StateVector, Transact, Update};
        use yrs_kvstore::keys::{key_doc, key_oid, key_state_vector, key_update};

        let (oid, state, updates) = {
            let map = self.data.lock().unwrap();
            let oid_key: Vec<u8> = key_oid(name.as_bytes()).into();
            let Some(v) = map.get(&oid_key) else {
                return Ok(());
            };
            let oid = u32::from_be_bytes(v.as_slice().try_into().context("bad oid")?);
            let start: Vec<u8> = key_update(oid, 0).into();
            let end: Vec<u8> = key_update(oid, u32::MAX).into();
            let updates: Vec<(Vec<u8>, Vec<u8>)> = map
                .range(start..end)
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if updates.is_empty() {
                return Ok(());
            }
            let doc_key: Vec<u8> = key_doc(oid).into();
            (oid, map.get(&doc_key).cloned(), updates)
        };

        let doc = yrs::Doc::new();
        {
            let mut txn = doc.transact_mut();
            for bytes in state.iter().chain(updates.iter().map(|(_, u)| u)) {
                let update = Update::decode_v1(bytes).with_context(|| {
                    format!(
                        "Failed to decode while compacting {} pending updates",
                        updates.len()
                    )
                })?;
                txn.apply_update(update);
            }
        }
        let (new_state, sv) = {
            let txn = doc.transact();
            (
                txn.encode_state_as_update_v1(&StateVector::default()),
                txn.state_vector().encode_v1(),
            )
        };

        {
            let mut map = self.data.lock().unwrap();
            map.insert(key_doc(oid).into(), new_state);
            map.insert(key_state_vector(oid).into(), sv);
            for (k, _) in updates {
                map.remove(&k);
            }
        }
        // Set directly rather than through mark_dirty: after shutdown the final save
        // must still write the updates merged here. The caller persists right after,
        // so the dirty callback is not needed.
        self.dirty.store(true, Ordering::SeqCst);
        Ok(())
    }

    #[cfg(test)]
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let map = self.data.lock().unwrap();
        map.get(key).cloned()
    }

    #[cfg(test)]
    fn set(&self, key: &[u8], value: &[u8]) {
        let mut map = self.data.lock().unwrap();
        map.insert(key.to_vec(), value.to_vec());
        self.mark_dirty();
    }

    pub fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.lock().unwrap().is_empty()
    }

    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Call the callback one last time to wake up the persistence worker
        (self.dirty_callback)();
    }
}

impl<'d> DocOps<'d> for SyncKv {}

pub struct SyncKvEntry {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl KVEntry for SyncKvEntry {
    fn key(&self) -> &[u8] {
        &self.key
    }

    fn value(&self) -> &[u8] {
        &self.value
    }
}

pub struct SyncKvCursor {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
    next_key: Bound<Vec<u8>>,
    to: Vec<u8>,
}

impl Iterator for SyncKvCursor {
    type Item = SyncKvEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let map = self.data.lock().unwrap();
        let next = map
            .range((self.next_key.clone(), Bound::Excluded(self.to.clone())))
            .next()?;
        self.next_key = Bound::Excluded(next.0.clone());
        Some(SyncKvEntry {
            key: next.0.clone(),
            value: next.1.clone(),
        })
    }
}

impl<'a> yrs_kvstore::KVStore<'a> for SyncKv {
    type Error = std::convert::Infallible;
    type Cursor = SyncKvCursor;
    type Entry = SyncKvEntry;
    type Return = Vec<u8>;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
        let map = self.data.lock().unwrap();
        Ok(map.get(key).cloned())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        let mut map = self.data.lock().unwrap();
        map.remove(key);
        self.mark_dirty();
        Ok(())
    }

    fn iter_range(&self, from: &[u8], to: &[u8]) -> Result<Self::Cursor, Self::Error> {
        Ok(SyncKvCursor {
            data: self.data.clone(),
            next_key: Bound::Included(from.to_vec()),
            to: to.to_vec(),
        })
    }

    fn peek_back(&self, key: &[u8]) -> Result<Option<Self::Entry>, Self::Error> {
        let map = self.data.lock().unwrap();
        let prev = map.range(..key.to_vec()).next_back();
        Ok(prev.map(|(k, v)| SyncKvEntry {
            key: k.clone(),
            value: v.clone(),
        }))
    }

    fn upsert(&self, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        let mut map = self.data.lock().unwrap();
        map.insert(key.to_vec(), value.to_vec());
        self.mark_dirty();
        Ok(())
    }

    fn remove_range(&self, from: &[u8], to: &[u8]) -> Result<(), Self::Error> {
        for entry in self.iter_range(from, to)? {
            let mut map = self.data.lock().unwrap();
            map.remove(&entry.key);
        }
        self.mark_dirty();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::store::Result;
    use async_trait::async_trait;
    use dashmap::DashMap;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio;

    #[derive(Default, Clone)]
    struct MemoryStore {
        data: Arc<DashMap<String, Vec<u8>>>,
        set_delay: Duration,
    }

    #[cfg_attr(not(feature = "single-threaded"), async_trait)]
    #[cfg_attr(feature = "single-threaded", async_trait(?Send))]
    impl Store for MemoryStore {
        async fn init(&self) -> Result<()> {
            Ok(())
        }

        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            Ok(self.data.get(key).map(|v| v.clone()))
        }

        async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
            tokio::time::sleep(self.set_delay).await;
            self.data.insert(key.to_owned(), value);
            Ok(())
        }

        async fn remove(&self, key: &str) -> Result<()> {
            self.data.remove(key);
            Ok(())
        }

        async fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.data.contains_key(key))
        }
    }

    #[derive(Default, Clone)]
    struct CallbackCounter {
        data: Arc<AtomicUsize>,
    }

    impl CallbackCounter {
        fn callback(&self) -> Box<dyn Fn() + Send + Sync> {
            let data = self.data.clone();
            Box::new(move || {
                data.fetch_add(1, Ordering::Relaxed);
            })
        }

        fn count(&self) -> usize {
            self.data.load(Ordering::Relaxed)
        }
    }

    #[tokio::test]
    async fn calls_sync_callback() {
        let store = MemoryStore::default();
        let c = CallbackCounter::default();
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", c.callback())
            .await
            .unwrap();

        assert_eq!(c.count(), 0);
        sync_kv.set(b"foo", b"bar");
        assert_eq!(sync_kv.get(b"foo"), Some(b"bar".to_vec()));

        assert!(store.data.is_empty());

        // We should have received a dirty callback.
        assert_eq!(c.count(), 1);

        sync_kv.set(b"abc", b"def");

        // We should not receive a dirty callback.
        assert_eq!(c.count(), 1);
    }

    #[tokio::test]
    async fn persists_to_store() {
        let store = MemoryStore::default();

        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap();

            sync_kv.set(b"foo", b"bar");
            assert_eq!(sync_kv.get(b"foo"), Some(b"bar".to_vec()));

            assert!(store.data.is_empty());

            sync_kv.persist().await.unwrap();
        }

        {
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap();

            assert_eq!(sync_kv.get(b"foo"), Some(b"bar".to_vec()));
        }
    }

    #[tokio::test]
    async fn only_persists_when_dirty() {
        let store = MemoryStore::default();
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
            .await
            .unwrap();

        assert!(!sync_kv.dirty.load(Ordering::SeqCst));

        sync_kv.set(b"foo", b"bar");
        assert!(sync_kv.dirty.load(Ordering::SeqCst));

        sync_kv.persist().await.unwrap();
        assert!(!sync_kv.dirty.load(Ordering::SeqCst));
        assert_eq!(store.data.len(), 1);

        store.data.clear();

        assert!(!sync_kv.dirty.load(Ordering::SeqCst));
        sync_kv.persist().await.unwrap();

        // Should not persist when not dirty
        assert!(store.data.is_empty());
    }

    fn update_log_len(sync_kv: &SyncKv) -> usize {
        use yrs_kvstore::keys::{key_oid, key_update};
        let map = sync_kv.data.lock().unwrap();
        let oid_key: Vec<u8> = key_oid(crate::doc_connection::DOC_NAME.as_bytes()).into();
        let oid = u32::from_be_bytes(map[&oid_key].as_slice().try_into().unwrap());
        let start: Vec<u8> = key_update(oid, 0).into();
        let end: Vec<u8> = key_update(oid, u32::MAX).into();
        map.range(start..end).count()
    }

    fn push_item(doc: &crate::doc_sync::DocWithSyncKv, item: &str) {
        use yrs::{Array, Transact};
        let awareness = doc.awareness();
        let guard = awareness.write().unwrap();
        let list = guard.doc.get_or_insert_array("list");
        let mut txn = guard.doc.transact_mut();
        list.push_back(&mut txn, item);
    }

    fn items(doc: &crate::doc_sync::DocWithSyncKv) -> Vec<String> {
        use yrs::{Array, Transact};
        let awareness = doc.awareness();
        let guard = awareness.read().unwrap();
        let list = guard.doc.get_or_insert_array("list");
        let txn = guard.doc.transact();
        list.iter(&txn).map(|v| v.to_string(&txn)).collect()
    }

    async fn reload(store: &MemoryStore) -> crate::doc_sync::DocWithSyncKv {
        crate::doc_sync::DocWithSyncKv::new(
            "doc",
            Some(Arc::new(Box::new(store.clone()))),
            || (),
            false,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn compact_while_editing_keeps_every_edit_once() {
        let store = MemoryStore::default();
        let doc = reload(&store).await;
        let sync_kv = doc.sync_kv();

        for i in 0..2000 {
            push_item(&doc, &format!("seed{i}"));
        }
        // Edits are appended to the log; merging waits for compaction.
        assert_eq!(update_log_len(&sync_kv), 2000);

        let stop = Arc::new(AtomicBool::new(false));
        let compactor = {
            let (sync_kv, stop) = (sync_kv.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    sync_kv.compact(crate::doc_connection::DOC_NAME).unwrap();
                }
            })
        };
        for i in 0..2000 {
            push_item(&doc, &format!("edit{i}"));
            if i % 50 == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        stop.store(true, Ordering::SeqCst);
        compactor.join().unwrap();

        sync_kv.compact(crate::doc_connection::DOC_NAME).unwrap();
        assert_eq!(update_log_len(&sync_kv), 0);
        sync_kv.persist().await.unwrap();

        let expected = items(&doc);
        assert_eq!(expected.len(), 4000);
        assert_eq!(items(&reload(&store).await), expected);
    }

    /// Saves "a" through a slow store while "b" is edited in mid-save, then runs `before_next_save`
    /// and the next save as the persistence worker does, and returns the items read back.
    async fn edit_during_save(before_next_save: impl FnOnce(&SyncKv)) -> Vec<String> {
        let store = MemoryStore {
            set_delay: Duration::from_millis(300),
            ..Default::default()
        };
        let doc = reload(&store).await;
        let sync_kv = doc.sync_kv();

        push_item(&doc, "a");
        let (saved, _) = tokio::join!(sync_kv.persist(), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            push_item(&doc, "b");
        });
        saved.unwrap();

        before_next_save(&sync_kv);
        sync_kv.compact(crate::doc_connection::DOC_NAME).unwrap();
        sync_kv.persist().await.unwrap();
        items(&reload(&store).await)
    }

    #[tokio::test]
    async fn edit_during_save_is_kept_by_next_save() {
        assert_eq!(edit_during_save(|_| ()).await, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn edit_during_save_is_kept_by_final_save_after_shutdown() {
        // The doc is unloaded before the next tick; the final save still runs.
        assert_eq!(edit_during_save(SyncKv::shutdown).await, vec!["a", "b"]);
    }
}

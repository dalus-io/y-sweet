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
        // The dirty flag is cleared together with taking the snapshot, under the data lock that
        // every write holds while it marks the doc dirty. A write that lands while the snapshot
        // is being stored therefore sets the flag again and is saved by the next persist.
        // (Clearing it after the store write, as before, erased that write's flag: the final
        // save at shutdown then skipped it.)
        let snapshot = {
            let data = self.data.lock().unwrap();
            if !self.dirty.swap(false, Ordering::SeqCst) {
                tracing::info!("Not persisting, no changes detected");
                return Ok(());
            }
            match &self.store {
                Some(_) => match bincode::serialize(&*data) {
                    Ok(snapshot) => Some(snapshot),
                    Err(err) => {
                        self.dirty.store(true, Ordering::SeqCst);
                        return Err(err.into());
                    }
                },
                None => None,
            }
        };

        if let (Some(store), Some(snapshot)) = (&self.store, snapshot) {
            tracing::info!(size=?snapshot.len(), "Persisting snapshot");
            if let Err(err) = store.set(&self.key, snapshot).await {
                // Not saved: stay dirty so the next persist tries again. No callback: the
                // persistence worker retries on its own schedule.
                self.dirty.store(true, Ordering::SeqCst);
                return Err(err.into());
            }
        }
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
pub(crate) mod test {
    use super::*;
    use crate::store::Result;
    use async_trait::async_trait;
    use dashmap::DashMap;
    use std::sync::atomic::AtomicUsize;
    use tokio;

    #[derive(Default, Clone)]
    pub(crate) struct MemoryStore {
        data: Arc<DashMap<String, Vec<u8>>>,
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

    /// A store whose writes wait for the test to release them, and can be made to fail once.
    #[derive(Clone)]
    struct HeldStore {
        inner: MemoryStore,
        set_entered: Arc<tokio::sync::Notify>,
        set_release: Arc<tokio::sync::Semaphore>,
        fail_next_set: Arc<AtomicBool>,
    }

    impl HeldStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::default(),
                set_entered: Default::default(),
                set_release: Arc::new(tokio::sync::Semaphore::new(0)),
                fail_next_set: Default::default(),
            }
        }

        fn stored(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
            let snapshot = self.inner.data.get("foo/data.ysweet").unwrap().clone();
            bincode::deserialize(&snapshot).unwrap()
        }
    }

    #[cfg_attr(not(feature = "single-threaded"), async_trait)]
    #[cfg_attr(feature = "single-threaded", async_trait(?Send))]
    impl Store for HeldStore {
        async fn init(&self) -> Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
            self.set_entered.notify_one();
            self.set_release.acquire().await.unwrap().forget();
            if self.fail_next_set.swap(false, Ordering::SeqCst) {
                return Err(crate::store::StoreError::ConnectionError(
                    "test failure".to_string(),
                ));
            }
            self.inner.set(key, value).await
        }
        async fn remove(&self, key: &str) -> Result<()> {
            self.inner.remove(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool> {
            self.inner.exists(key).await
        }
    }

    #[tokio::test]
    async fn a_write_during_a_save_is_saved_by_the_next_persist() {
        let store = HeldStore::new();
        let sync_kv = Arc::new(
            SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap(),
        );

        // A checkpoint snapshots A and is waiting on the store...
        sync_kv.set(b"a", b"1");
        let checkpoint = tokio::spawn({
            let sync_kv = sync_kv.clone();
            async move { sync_kv.persist().await.map_err(|e| e.to_string()) }
        });
        store.set_entered.notified().await;

        // ...when B lands. Then the checkpoint completes.
        sync_kv.set(b"b", b"2");
        store.set_release.add_permits(1);
        checkpoint.await.unwrap().unwrap();
        assert!(!store.stored().contains_key(b"b".as_slice()));

        // The final save must still see B as unsaved, and save it.
        store.set_release.add_permits(1);
        sync_kv.persist().await.unwrap();
        assert_eq!(store.stored().get(b"b".as_slice()), Some(&b"2".to_vec()));
    }

    #[tokio::test]
    async fn a_failed_save_keeps_the_doc_dirty() {
        let store = HeldStore::new();
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
            .await
            .unwrap();
        sync_kv.set(b"a", b"1");

        store.fail_next_set.store(true, Ordering::SeqCst);
        store.set_release.add_permits(1);
        assert!(sync_kv.persist().await.is_err());
        assert!(sync_kv.dirty.load(Ordering::SeqCst));

        store.set_release.add_permits(1);
        sync_kv.persist().await.unwrap();
        assert_eq!(store.stored().get(b"a".as_slice()), Some(&b"1".to_vec()));
    }
}

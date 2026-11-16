use crate::store::{Store, StoreError};
use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    ops::Bound,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

/// How long a doc stays suspect after a save of it timed out (see [SyncKv::is_suspect]), at
/// least. Longer when the timeout itself was long: [SUSPECT_WINDOW_TIMEOUTS] times it.
pub const DEFAULT_SUSPECT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// The suspect window is never shorter than this many times the timeout that started it.
pub const SUSPECT_WINDOW_TIMEOUTS: u32 = 5;
use yrs_kvstore::{DocOps, KVEntry};

pub struct SyncKv {
    data: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
    store: Option<Arc<Box<dyn Store>>>,
    key: String,
    dirty: AtomicBool,
    /// True while a snapshot is being written to the store.
    saving: AtomicBool,
    dirty_callback: Box<dyn Fn() + Send + Sync>,
    shutdown: AtomicBool,
    /// Set when a save timed out: until then, a write the store may still apply late can
    /// replace what later saves stored. See [SyncKv::is_suspect].
    suspect_until: Mutex<Option<Instant>>,
    /// The least a suspect window lasts, in milliseconds ([DEFAULT_SUSPECT_WINDOW]).
    suspect_window_ms: AtomicU64,
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
            saving: AtomicBool::new(false),
            dirty_callback: Box::new(callback),
            shutdown: AtomicBool::new(false),
            suspect_until: Mutex::new(None),
            suspect_window_ms: AtomicU64::new(DEFAULT_SUSPECT_WINDOW.as_millis() as u64),
        })
    }

    /// Sets the least a suspect window lasts (default [DEFAULT_SUSPECT_WINDOW]).
    pub fn set_suspect_window(&self, window: Duration) {
        self.suspect_window_ms
            .store(window.as_millis() as u64, Ordering::SeqCst);
    }

    /// Whether a save of this doc timed out recently enough that the store may still apply
    /// it.
    ///
    /// A save that times out has an unknown outcome: the store may have received the whole
    /// write and apply it only later, after a newer save, and so put an older copy of the doc
    /// back. Nothing can stop that write, so for a window after the timeout the doc is
    /// treated as never safely stored: every save leaves it dirty, so that it is saved again
    /// at the next checkpoint, over whatever landed meanwhile; and it must not be dropped
    /// from memory, which holds the only copy known to be current. The first save that
    /// starts after the window clears the doc as usual.
    // `Instant::now` is reached only once a save has timed out. On wasm, where there is no
    // clock behind `Instant`, no store times out, so it never is.
    pub fn is_suspect(&self) -> bool {
        let mut suspect_until = self.suspect_until.lock().unwrap();
        match *suspect_until {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                *suspect_until = None;
                false
            }
            None => false,
        }
    }

    /// Starts, or extends, the suspect window after a save timed out after `limit`.
    fn mark_suspect(&self, limit: Duration) {
        let window = Duration::from_millis(self.suspect_window_ms.load(Ordering::SeqCst))
            .max(limit.saturating_mul(SUSPECT_WINDOW_TIMEOUTS));
        let until = Instant::now() + window;
        let mut suspect_until = self.suspect_until.lock().unwrap();
        *suspect_until = Some(suspect_until.map_or(until, |current| current.max(until)));
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
        /// Marks the doc dirty again unless disarmed: a save that fails, or is abandoned
        /// mid-write (its future dropped, e.g. by a timeout), has not saved anything. Left
        /// armed on purpose by a save made while the doc is suspect.
        struct StillDirty<'a> {
            dirty: &'a AtomicBool,
            saving: &'a AtomicBool,
            armed: bool,
        }
        impl Drop for StillDirty<'_> {
            fn drop(&mut self) {
                if self.armed {
                    self.dirty.store(true, Ordering::SeqCst);
                }
                self.saving.store(false, Ordering::SeqCst);
            }
        }

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
                    Ok(snapshot) => {
                        // Set under the data lock, so the doc never looks saved in between.
                        self.saving.store(true, Ordering::SeqCst);
                        Some(snapshot)
                    }
                    Err(err) => {
                        self.dirty.store(true, Ordering::SeqCst);
                        return Err(err.into());
                    }
                },
                None => None,
            }
        };

        if let (Some(store), Some(snapshot)) = (&self.store, snapshot) {
            // Not saved until the write returns Ok: stay dirty so the next persist tries
            // again. No callback: the persistence worker retries on its own schedule.
            let mut still_dirty = StillDirty {
                dirty: &self.dirty,
                saving: &self.saving,
                armed: true,
            };
            // Asked before the write is sent: a write sent inside the window may itself be
            // applied before the stale one, so it does not settle anything.
            let suspect = self.is_suspect();
            tracing::info!(size=?snapshot.len(), "Persisting snapshot");
            if let Err(error) = store.set(&self.key, snapshot).await {
                if let StoreError::Timeout { limit, .. } = &error {
                    self.mark_suspect(*limit);
                }
                return Err(error.into());
            }
            // Saved. While suspect the doc stays dirty all the same (the guard sets it): the
            // next checkpoint saves it again. No dirty callback, so that is the cadence.
            still_dirty.armed = suspect;
        }
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
            // Set directly rather than through mark_dirty: after shutdown the final save
            // must still write the updates merged here. The caller persists right after,
            // so the dirty callback is not needed. Set under the map lock, like every other
            // change to the map: `persist` clears the flag and takes its snapshot under the
            // same lock, so it either sees this change in its snapshot or finds the flag set
            // afterwards.
            self.dirty.store(true, Ordering::SeqCst);
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

    /// Whether the store may not hold the doc's latest state: it has changes not yet saved, or
    /// a save of them is still being written.
    pub fn has_unsaved_changes(&self) -> bool {
        self.dirty.load(Ordering::SeqCst) || self.saving.load(Ordering::SeqCst)
    }

    /// Undoes [SyncKv::shutdown]: writes are marked dirty again. For a doc that GC retired but
    /// could not save, and so keeps.
    pub fn resume(&self) {
        self.shutdown.store(false, Ordering::SeqCst);
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Call the callback one last time to wake up the persistence worker
        (self.dirty_callback)();
    }
}

impl DocOps<'_> for SyncKv {}

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

impl yrs_kvstore::KVStore<'_> for SyncKv {
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
    use std::time::Duration;
    use tokio;

    #[derive(Default, Clone)]
    pub(crate) struct MemoryStore {
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

    /// A store whose writes wait for the test to release them, and can be made to fail once.
    #[derive(Clone)]
    struct HeldStore {
        inner: MemoryStore,
        set_entered: Arc<tokio::sync::Notify>,
        set_release: Arc<tokio::sync::Semaphore>,
        fail_next_set: Arc<AtomicBool>,
        /// The next write times out, after this long by the store's account.
        time_out_next_set: Arc<Mutex<Option<Duration>>>,
    }

    impl HeldStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::default(),
                set_entered: Default::default(),
                set_release: Arc::new(tokio::sync::Semaphore::new(0)),
                fail_next_set: Default::default(),
                time_out_next_set: Default::default(),
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
            if let Some(limit) = self.time_out_next_set.lock().unwrap().take() {
                return Err(StoreError::Timeout {
                    limit,
                    what: "waiting for",
                });
            }
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

    #[tokio::test]
    async fn after_a_save_timed_out_saves_leave_the_doc_dirty_until_the_window_has_passed() {
        let store = HeldStore::new();
        store.set_release.add_permits(100);
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
            .await
            .unwrap();
        let window = Duration::from_millis(300);
        sync_kv.set_suspect_window(window);
        sync_kv.set(b"a", b"1");
        assert!(!sync_kv.is_suspect());

        // An ordinary failure does not make the doc suspect.
        store.fail_next_set.store(true, Ordering::SeqCst);
        assert!(sync_kv.persist().await.is_err());
        assert!(!sync_kv.is_suspect());

        // A timeout does: the store may still apply that write.
        *store.time_out_next_set.lock().unwrap() = Some(Duration::from_millis(1));
        assert!(sync_kv.persist().await.is_err());
        let timed_out_at = Instant::now();
        assert!(sync_kv.is_suspect());
        assert!(sync_kv.has_unsaved_changes());

        // Saves now succeed, and each leaves the doc dirty, so there is always another.
        for _ in 0..2 {
            sync_kv.persist().await.unwrap();
            assert_eq!(store.stored().get(b"a".as_slice()), Some(&b"1".to_vec()));
            assert!(sync_kv.dirty.load(Ordering::SeqCst));
            assert!(!sync_kv.saving.load(Ordering::SeqCst));
        }
        assert!(timed_out_at.elapsed() < window, "the test ran too slowly");

        // The first save that starts after the window clears the doc.
        tokio::time::sleep(window).await;
        assert!(!sync_kv.is_suspect());
        assert!(sync_kv.dirty.load(Ordering::SeqCst));
        sync_kv.persist().await.unwrap();
        assert!(!sync_kv.has_unsaved_changes());
    }

    #[tokio::test]
    async fn the_suspect_window_is_several_times_the_timeout_that_started_it() {
        let store = HeldStore::new();
        store.set_release.add_permits(100);
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
            .await
            .unwrap();
        sync_kv.set_suspect_window(Duration::ZERO);
        sync_kv.set(b"a", b"1");

        let limit = Duration::from_secs(600);
        *store.time_out_next_set.lock().unwrap() = Some(limit);
        assert!(sync_kv.persist().await.is_err());
        let until = sync_kv.suspect_until.lock().unwrap().unwrap();
        let window = until - Instant::now();
        assert!(window > limit * (SUSPECT_WINDOW_TIMEOUTS - 1) && window <= limit * 5);
        assert!(DEFAULT_SUSPECT_WINDOW >= crate::store::s3::DEFAULT_REQUEST_TIMEOUT * 5);
    }

    #[tokio::test]
    async fn an_abandoned_save_keeps_the_doc_dirty() {
        let store = HeldStore::new();
        let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
            .await
            .unwrap();
        sync_kv.set(b"a", b"1");

        // The write never returns; the save is given up on.
        let abandoned =
            tokio::time::timeout(std::time::Duration::from_millis(50), sync_kv.persist()).await;
        assert!(abandoned.is_err());
        assert!(sync_kv.dirty.load(Ordering::SeqCst));
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
            None,
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

    /// `persist` writes the whole map, pending update log included, so a save without a
    /// compaction before it is complete: compaction keeps the stored form small, it is not
    /// what makes a save correct.
    #[tokio::test]
    async fn a_save_without_compaction_still_holds_every_edit() {
        let store = MemoryStore::default();
        let doc = reload(&store).await;
        push_item(&doc, "a");
        push_item(&doc, "b");
        assert_eq!(update_log_len(&doc.sync_kv()), 2);
        doc.sync_kv().persist().await.unwrap();
        assert_eq!(items(&reload(&store).await), vec!["a", "b"]);
    }

    /// The same schedule as `edit_during_save`, without the compaction that used to be what
    /// rescued "b": the save itself now leaves the doc dirty for an edit that lands during it.
    #[tokio::test]
    async fn edit_during_save_leaves_the_doc_dirty_without_compaction() {
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
        assert!(sync_kv.has_unsaved_changes());
        sync_kv.persist().await.unwrap();
        assert!(!sync_kv.has_unsaved_changes());
        assert_eq!(items(&reload(&store).await), vec!["a", "b"]);
    }

    /// A compaction that runs while a save is being written does not leave the doc looking
    /// saved: what it merged is written by the next save.
    #[tokio::test]
    async fn compaction_during_a_save_leaves_the_doc_dirty() {
        let store = MemoryStore {
            set_delay: Duration::from_millis(300),
            ..Default::default()
        };
        let doc = reload(&store).await;
        let sync_kv = doc.sync_kv();
        push_item(&doc, "a");
        let (saved, _) = tokio::join!(sync_kv.persist(), async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            sync_kv.compact(crate::doc_connection::DOC_NAME).unwrap();
        });
        saved.unwrap();
        assert!(sync_kv.has_unsaved_changes());
        assert_eq!(update_log_len(&sync_kv), 0);
        sync_kv.persist().await.unwrap();
        assert!(!sync_kv.has_unsaved_changes());
        assert_eq!(items(&reload(&store).await), vec!["a"]);
    }
}

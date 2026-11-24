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

/// How long a doc stays suspect after a save of it failed in a way that may still land (see
/// [SyncKv::is_suspect]), at least. Longer when the request was given long:
/// [SUSPECT_WINDOW_TIMEOUTS] times that.
pub const DEFAULT_SUSPECT_WINDOW: Duration = Duration::from_secs(5 * 60);

/// The suspect window is never shorter than this many times the timeout that started it.
pub const SUSPECT_WINDOW_TIMEOUTS: u32 = 5;

/// How often a suspect doc that has no changes of its own is saved again during its window.
pub const DEFAULT_SUSPECT_RESAVE_INTERVAL: Duration = Duration::from_secs(60);

/// A doc's suspect window (see [SyncKv::is_suspect]).
struct Suspect {
    /// The end of the window.
    until: Instant,
    /// When the doc is next saved again although nothing in it changed.
    resave_at: Instant,
}
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
    /// Set when a save failed in a way that may still land, until a save that started after
    /// the window has succeeded. See [SyncKv::is_suspect].
    suspect: Mutex<Option<Suspect>>,
    /// The least a suspect window lasts, in milliseconds ([DEFAULT_SUSPECT_WINDOW]).
    suspect_window_ms: AtomicU64,
    /// [DEFAULT_SUSPECT_RESAVE_INTERVAL], in milliseconds.
    suspect_resave_ms: AtomicU64,
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
            suspect: Mutex::new(None),
            suspect_window_ms: AtomicU64::new(DEFAULT_SUSPECT_WINDOW.as_millis() as u64),
            suspect_resave_ms: AtomicU64::new(DEFAULT_SUSPECT_RESAVE_INTERVAL.as_millis() as u64),
        })
    }

    /// Sets the least a suspect window lasts (default [DEFAULT_SUSPECT_WINDOW]) and how
    /// often a suspect doc without changes is saved again within it (default
    /// [DEFAULT_SUSPECT_RESAVE_INTERVAL]).
    pub fn set_suspect_window(&self, window: Duration, resave_interval: Duration) {
        self.suspect_window_ms
            .store(window.as_millis() as u64, Ordering::SeqCst);
        self.suspect_resave_ms
            .store(resave_interval.as_millis() as u64, Ordering::SeqCst);
    }

    /// Whether a save of this doc failed, recently enough to matter, in a way that leaves
    /// the store free to apply it still.
    ///
    /// A save that times out, or whose connection breaks once the request may have been
    /// sent, has an unknown outcome: the store may hold the whole write and apply it only
    /// later, after a newer save, and so put an older copy of the doc back. Nothing can stop
    /// that write, so for a window after the failure the doc is treated as never safely
    /// stored:
    ///
    /// - it is saved again every [DEFAULT_SUSPECT_RESAVE_INTERVAL] although nothing in it
    ///   changed, over whatever landed meanwhile (changes are saved at the next checkpoint
    ///   as always, and each such save counts as one of these);
    /// - it must not be dropped from memory, which holds the only copy known to be current;
    /// - it counts as having unsaved changes ([SyncKv::has_unsaved_changes]) until a save
    ///   that *started* after the window has succeeded. A save sent inside the window may
    ///   itself be applied before the stale one, so it settles nothing.
    // `Instant::now` is reached only once a save has failed that way. On wasm, where there
    // is no clock behind `Instant`, the doc is never marked (see `mark_suspect`).
    pub fn is_suspect(&self) -> bool {
        let suspect = self.suspect.lock().unwrap();
        suspect
            .as_ref()
            .is_some_and(|suspect| Instant::now() < suspect.until)
    }

    /// Whether the doc has been suspect and no save has settled it yet: it is inside its
    /// window, or past it with the settling save still to come.
    pub fn is_unsettled(&self) -> bool {
        self.suspect.lock().unwrap().is_some()
    }

    /// Whether the doc is due a save although nothing in it changed: it is suspect and its
    /// resave interval has passed, or its window has and the save that ends it is to come.
    fn suspect_resave_due(&self) -> bool {
        let suspect = self.suspect.lock().unwrap();
        suspect
            .as_ref()
            .is_some_and(|suspect| Instant::now() >= suspect.resave_at.min(suspect.until))
    }

    /// Makes the next save of a suspect doc happen whether or not its interval has passed.
    /// For the last save a doc gets: after it, nothing would save over a stale write.
    pub fn resave_now(&self) {
        if let Some(suspect) = self.suspect.lock().unwrap().as_mut() {
            suspect.resave_at = Instant::now();
        }
    }

    /// Starts, or extends, the suspect window after a save failed that had been given
    /// `limit` (zero if it had no limit of its own).
    #[cfg(not(target_arch = "wasm32"))]
    fn mark_suspect(&self, limit: Duration) {
        let window = Duration::from_millis(self.suspect_window_ms.load(Ordering::SeqCst))
            .max(limit.saturating_mul(SUSPECT_WINDOW_TIMEOUTS));
        let now = Instant::now();
        let mut suspect = self.suspect.lock().unwrap();
        *suspect = Some(match suspect.take() {
            Some(current) => Suspect {
                until: current.until.max(now + window),
                ..current
            },
            None => Suspect {
                until: now + window,
                // The failed save left the doc dirty, so the next checkpoint saves it; the
                // interval counts from that save.
                resave_at: now,
            },
        });
    }

    /// No clock on wasm, and no store there reports such a failure.
    #[cfg(target_arch = "wasm32")]
    fn mark_suspect(&self, _limit: Duration) {}

    /// Records a successful save that started at `started` (`None` if the doc was not
    /// suspect then).
    fn saved(&self, started: Option<Instant>) {
        let mut suspect = self.suspect.lock().unwrap();
        let Some(current) = suspect.as_mut() else {
            return;
        };
        match started {
            // Sent after the window: this is the save that settles it.
            Some(started) if started >= current.until => *suspect = None,
            _ => {
                current.resave_at = Instant::now()
                    + Duration::from_millis(self.suspect_resave_ms.load(Ordering::SeqCst));
            }
        }
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
        /// mid-write (its future dropped, e.g. by a timeout), has not saved anything.
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
            // A suspect doc is saved from time to time without having changed (see
            // `is_suspect`). Short-circuit: the common case takes no second lock.
            if !self.dirty.swap(false, Ordering::SeqCst) && !self.suspect_resave_due() {
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
            // Taken before the write is sent: what counts is when the save started.
            let started = self.suspect.lock().unwrap().is_some().then(Instant::now);
            tracing::info!(size=?snapshot.len(), "Persisting snapshot");
            if let Err(error) = store.set(&self.key, snapshot).await {
                if let Some(limit) = StoreError::write_may_still_land(&error) {
                    self.mark_suspect(limit);
                }
                return Err(error.into());
            }
            still_dirty.armed = false;
            self.saved(started);
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
        self.dirty.load(Ordering::SeqCst)
            || self.saving.load(Ordering::SeqCst)
            || self.suspect.lock().unwrap().is_some()
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
        /// The next write fails with this.
        fail_next_set_with: Arc<Mutex<Option<StoreError>>>,
        /// How many writes were stored.
        sets: Arc<AtomicUsize>,
    }

    impl HeldStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::default(),
                set_entered: Default::default(),
                set_release: Arc::new(tokio::sync::Semaphore::new(0)),
                fail_next_set: Default::default(),
                fail_next_set_with: Default::default(),
                sets: Default::default(),
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
            if let Some(error) = self.fail_next_set_with.lock().unwrap().take() {
                return Err(error);
            }
            if self.fail_next_set.swap(false, Ordering::SeqCst) {
                return Err(crate::store::StoreError::ConnectionError(
                    "test failure".to_string(),
                ));
            }
            self.sets.fetch_add(1, Ordering::SeqCst);
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
    async fn after_a_save_that_may_still_land_the_doc_is_saved_again_until_the_window_has_passed() {
        for interrupted in [false, true] {
            let store = HeldStore::new();
            store.set_release.add_permits(100);
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap();
            let (window, interval) = (Duration::from_millis(600), Duration::from_millis(150));
            sync_kv.set_suspect_window(window, interval);
            sync_kv.set(b"a", b"1");
            assert!(!sync_kv.is_suspect());

            // A failure that cannot have left a write behind does not make the doc suspect.
            store.fail_next_set.store(true, Ordering::SeqCst);
            assert!(sync_kv.persist().await.is_err());
            assert!(!sync_kv.is_suspect());

            // A timeout does, and so does a connection lost after the request went out.
            *store.fail_next_set_with.lock().unwrap() = Some(if interrupted {
                StoreError::Interrupted {
                    message: "reset".to_string(),
                    limit: Duration::from_millis(1),
                }
            } else {
                StoreError::Timeout {
                    limit: Duration::from_millis(1),
                    what: "waiting for",
                }
            });
            assert!(sync_kv.persist().await.is_err());
            let failed_at = Instant::now();
            assert!(sync_kv.is_suspect());
            assert!(sync_kv.dirty.load(Ordering::SeqCst));
            let writes = || store.sets.load(Ordering::SeqCst);
            assert_eq!(writes(), 0);

            // The next save succeeds. The doc is not dirty, and not safely stored either.
            sync_kv.persist().await.unwrap();
            assert_eq!(writes(), 1);
            assert!(!sync_kv.dirty.load(Ordering::SeqCst));
            assert!(sync_kv.has_unsaved_changes());

            // It is not written at every checkpoint...
            for _ in 0..3 {
                sync_kv.persist().await.unwrap();
            }
            assert_eq!(writes(), 1);
            // ...but once per interval, changed or not,
            tokio::time::sleep(interval).await;
            sync_kv.persist().await.unwrap();
            sync_kv.persist().await.unwrap();
            assert_eq!(writes(), 2);
            // at once when it changes,
            sync_kv.set(b"b", b"2");
            sync_kv.persist().await.unwrap();
            assert_eq!(writes(), 3);
            // and when it is the last save the doc gets.
            sync_kv.resave_now();
            sync_kv.persist().await.unwrap();
            assert_eq!(writes(), 4);
            assert!(failed_at.elapsed() < window, "the test ran too slowly");
            assert!(sync_kv.is_suspect());

            // After the window one more save is made, and that one settles it.
            tokio::time::sleep(window.saturating_sub(failed_at.elapsed())).await;
            assert!(!sync_kv.is_suspect());
            assert!(sync_kv.has_unsaved_changes());
            sync_kv.persist().await.unwrap();
            assert_eq!(writes(), 5);
            assert!(!sync_kv.has_unsaved_changes());
            sync_kv.persist().await.unwrap();
            assert_eq!(writes(), 5);
            assert_eq!(store.stored().get(b"b".as_slice()), Some(&b"2".to_vec()));
        }
    }

    #[tokio::test]
    async fn the_suspect_window_is_several_times_the_timeout_that_started_it() {
        // The same for a save that timed out and one cut off sooner (reset, `5xx`): both may
        // be held by the store for as long as the request was given.
        let limit = Duration::from_secs(600);
        let failures = [
            StoreError::Timeout {
                limit,
                what: "waiting for",
            },
            StoreError::Interrupted {
                message: "reset".to_string(),
                limit,
            },
        ];
        for failure in failures {
            let store = HeldStore::new();
            store.set_release.add_permits(100);
            let sync_kv = SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap();
            sync_kv.set_suspect_window(Duration::ZERO, Duration::ZERO);
            sync_kv.set(b"a", b"1");

            *store.fail_next_set_with.lock().unwrap() = Some(failure);
            assert!(sync_kv.persist().await.is_err());
            let until = sync_kv.suspect.lock().unwrap().as_ref().unwrap().until;
            let window = until - Instant::now();
            assert!(window > limit * (SUSPECT_WINDOW_TIMEOUTS - 1) && window <= limit * 5);
        }
        assert!(DEFAULT_SUSPECT_WINDOW >= crate::store::s3::DEFAULT_REQUEST_TIMEOUT * 5);
    }

    #[tokio::test]
    async fn a_save_sent_inside_the_window_that_ends_after_it_does_not_settle_the_doc() {
        // It may be applied before the stale write, so only a save started after the window
        // settles the doc, however late this one finishes.
        let store = HeldStore::new();
        let sync_kv = Arc::new(
            SyncKv::new(Some(Arc::new(Box::new(store.clone()))), "foo", || ())
                .await
                .unwrap(),
        );
        let window = Duration::from_millis(300);
        sync_kv.set_suspect_window(window, Duration::ZERO);
        sync_kv.set(b"a", b"1");
        *store.fail_next_set_with.lock().unwrap() = Some(StoreError::Timeout {
            limit: Duration::from_millis(1),
            what: "waiting for",
        });
        store.set_release.add_permits(1);
        assert!(sync_kv.persist().await.is_err());
        let failed_at = Instant::now();

        // Sent inside the window, held by the store until the window has passed.
        let spanning = tokio::spawn({
            let sync_kv = sync_kv.clone();
            async move { sync_kv.persist().await.map_err(|e| e.to_string()) }
        });
        store.set_entered.notified().await;
        assert!(failed_at.elapsed() < window, "the test ran too slowly");
        tokio::time::sleep(window).await;
        assert!(!sync_kv.is_suspect());
        store.set_release.add_permits(1);
        spanning.await.unwrap().unwrap();
        assert!(sync_kv.is_unsettled());
        assert!(sync_kv.has_unsaved_changes());

        // The next save, sent after the window, does.
        store.set_release.add_permits(1);
        sync_kv.persist().await.unwrap();
        assert!(!sync_kv.is_unsettled());
        assert!(!sync_kv.has_unsaved_changes());
        assert_eq!(store.sets.load(Ordering::SeqCst), 2);
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
        let store: Option<Arc<Box<dyn Store>>> = Some(Arc::new(Box::new(store.clone())));
        // `new` takes the update callback only with the `sync` feature.
        #[cfg(feature = "sync")]
        let doc = crate::doc_sync::DocWithSyncKv::new("doc", store, || (), false, None).await;
        #[cfg(not(feature = "sync"))]
        let doc = crate::doc_sync::DocWithSyncKv::new("doc", store, || (), false).await;
        doc.unwrap()
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

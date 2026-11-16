//! Durable, singleton-server user revocation. Old generations never become valid on restore.
//!
//! A user's state is a [Record]: a generation and whether the user is suspended. Every change
//! is a new generation, stored under a key of its own (`__dalus_auth/users/<user>/<n>.json`),
//! and the record with the highest generation is the user's state. A key is written with one
//! acknowledged content at most, and only once every lower generation is in the store, so:
//!
//! - a write that timed out for this server and is applied by the store later (an S3 write
//!   can be) lands on a key that is, by then, not the highest. It cannot replace a state that
//!   was acknowledged after it, which a single overwritten object could not rule out;
//! - the highest generation is found by reading upwards until a key is missing.
//!
//! The single object earlier builds used (`__dalus_auth/users/<user>.json`) is still read,
//! as the generation to start reading from, and still written after every change, so that a
//! build that knows only that object sees the change too.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, RwLock},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use y_sweet_core::store::Store;

#[derive(Clone, Default, Serialize, Deserialize)]
struct Record {
    generation: u64,
    suspended: bool,
}

/// How long one read or write of a record may take.
const STORAGE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Default)]
struct Entry {
    record: Record,
    cancellation: CancellationToken,
    /// Held for reading by whoever acts on this entry's authorization (applies a write,
    /// serves a read) from its last check of `cancellation` until it is done; taken for
    /// writing by [UserAccess::set_suspended] after it cancelled, before it returns. So once
    /// a suspension is acknowledged, nothing authorized before it is still under way.
    activity: Arc<RwLock<()>>,
    /// Whether the key of the next generation may have been written already: by a write of
    /// this process whose outcome is unknown, or by an earlier process (which this one
    /// cannot know). The next change must not put its record there.
    next_key_used: bool,
}

/// What [UserAccess::authorize_guarded] grants.
pub struct Authorized {
    /// Cancelled when the user is suspended or restored.
    pub cancellation: CancellationToken,
    /// To be held for reading from the last check of `cancellation` until the authorized
    /// action is done (see [UserAccess::set_suspended]).
    pub activity: Arc<RwLock<()>>,
}

#[derive(Default)]
pub struct UserAccess {
    entries: Mutex<HashMap<String, Arc<Mutex<Option<Entry>>>>>,
}

impl UserAccess {
    fn key(user: &str) -> Result<String> {
        if user.is_empty()
            || user.len() > 128
            || !user
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(anyhow!("Invalid user identifier"));
        }
        Ok(format!("__dalus_auth/users/{user}.json"))
    }

    /// The key of the user's record of one generation.
    fn generation_key(user: &str, generation: u64) -> Result<String> {
        Self::key(user)?;
        Ok(format!("__dalus_auth/users/{user}/{generation}.json"))
    }

    async fn read(store: &Arc<Box<dyn Store>>, key: &str) -> Result<Option<Record>> {
        Ok(match timeout(STORAGE_TIMEOUT, store.get(key)).await?? {
            Some(bytes) => Some(serde_json::from_slice(&bytes)?),
            None => None,
        })
    }

    async fn write(store: &Arc<Box<dyn Store>>, key: &str, record: &Record) -> Result<()> {
        timeout(STORAGE_TIMEOUT, store.set(key, serde_json::to_vec(record)?)).await??;
        Ok(())
    }

    /// The user's record of generation `generation`, if the store has one.
    async fn read_generation(
        store: &Arc<Box<dyn Store>>,
        user: &str,
        generation: u64,
    ) -> Result<Option<Record>> {
        let record = Self::read(store, &Self::generation_key(user, generation)?).await?;
        if record
            .as_ref()
            .is_some_and(|record| record.generation != generation)
        {
            return Err(anyhow!("Access record does not match its generation"));
        }
        Ok(record)
    }

    fn next_generation(record: &Record) -> Result<u64> {
        record
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow!("Access generation exhausted"))
    }

    async fn cell(&self, user: &str) -> Result<Arc<Mutex<Option<Entry>>>> {
        Self::key(user)?;
        Ok(self
            .entries
            .lock()
            .await
            .entry(user.to_owned())
            .or_default()
            .clone())
    }

    async fn load(
        cached: &mut Option<Entry>,
        store: &Option<Arc<Box<dyn Store>>>,
        user: &str,
    ) -> Result<Entry> {
        let key = Self::key(user)?;
        if let Some(entry) = cached.as_ref() {
            return Ok(entry.clone());
        }
        let record = match store {
            Some(store) => {
                // The single object of earlier builds says where to start. A record under
                // a generation key takes precedence over it, at the same generation too.
                let legacy = Self::read(store, &key).await?;
                let mut record = legacy.clone().unwrap_or_default();
                if legacy.is_some() {
                    if let Some(same) =
                        Self::read_generation(store, user, record.generation).await?
                    {
                        record = same;
                    }
                }
                // Then upwards until a generation is missing: the highest one stored.
                while let Some(next) =
                    Self::read_generation(store, user, Self::next_generation(&record)?).await?
                {
                    record = next;
                }
                record
            }
            None => return Err(anyhow!("User-scoped access requires durable storage")),
        };
        let entry = Entry {
            record,
            // An earlier process may have left a write behind that has yet to land.
            next_key_used: true,
            ..Entry::default()
        };
        *cached = Some(entry.clone());
        Ok(entry)
    }

    pub async fn generation(&self, store: &Option<Arc<Box<dyn Store>>>, user: &str) -> Result<u64> {
        let cell = self.cell(user).await?;
        let entry = Self::load(&mut *cell.lock().await, store, user).await?;
        if entry.record.suspended {
            return Err(anyhow!("User access denied"));
        }
        Ok(entry.record.generation)
    }

    // The server uses `authorize_guarded`; this is kept as the patch has it, with its tests.
    #[allow(dead_code)]
    pub async fn authorize(
        &self,
        store: &Option<Arc<Box<dyn Store>>>,
        user: &str,
        generation: u64,
    ) -> Result<CancellationToken> {
        let cell = self.cell(user).await?;
        let entry = Self::load(&mut *cell.lock().await, store, user).await?;
        if entry.record.suspended || entry.record.generation != generation {
            return Err(anyhow!("User access denied"));
        }
        Ok(entry.cancellation)
    }

    /// [UserAccess::authorize], with the guard that lets the caller finish what it does on
    /// this authorization before a suspension is acknowledged.
    pub async fn authorize_guarded(
        &self,
        store: &Option<Arc<Box<dyn Store>>>,
        user: &str,
        generation: u64,
    ) -> Result<Authorized> {
        let cell = self.cell(user).await?;
        let entry = Self::load(&mut *cell.lock().await, store, user).await?;
        if entry.record.suspended || entry.record.generation != generation {
            return Err(anyhow!("User access denied"));
        }
        Ok(Authorized {
            cancellation: entry.cancellation,
            activity: entry.activity,
        })
    }

    /// Moves the user to `record`, which is in the store: what was authorized under `old`
    /// is cancelled, and whatever of it is still under way is waited for.
    async fn advance(cached: &mut Option<Entry>, old: &Entry, record: Record) -> Entry {
        old.cancellation.cancel();
        let entry = Entry {
            record,
            ..Entry::default()
        };
        *cached = Some(entry.clone());
        // Holders keep this only across a check and an in-memory read or write, never across
        // IO, so the wait is short. New holders queue behind this and then find the
        // cancellation.
        drop(old.activity.write().await);
        entry
    }

    pub async fn set_suspended(
        &self,
        store: &Option<Arc<Box<dyn Store>>>,
        user: &str,
        suspended: bool,
    ) -> Result<()> {
        let cell = self.cell(user).await?;
        let mut cached = cell.lock().await;
        let mut old = Self::load(&mut cached, store, user).await?;
        let store = store
            .as_ref()
            .ok_or_else(|| anyhow!("Durable storage required"))?;

        if old.next_key_used {
            // The next generation's key may hold, or may yet receive, a write this process
            // never confirmed. The record of this change must not share a key with it, or
            // that write could replace it later. So that key is settled first, with a record
            // that changes nothing but the generation, and the change goes one higher. If
            // the unconfirmed write lands on the settled key after all, it is below the
            // change by then.
            let unchanged = Record {
                generation: Self::next_generation(&old.record)?,
                suspended: old.record.suspended,
            };
            Self::write(
                store,
                &Self::generation_key(user, unchanged.generation)?,
                &unchanged,
            )
            .await?;
            old = Self::advance(&mut cached, &old, unchanged).await;
        }

        let record = Record {
            generation: Self::next_generation(&old.record)?,
            suspended,
        };
        // Persist before acknowledging. Failure leaves the old state and allows a safe retry.
        if let Err(error) = Self::write(
            store,
            &Self::generation_key(user, record.generation)?,
            &record,
        )
        .await
        {
            // The write may have reached the store all the same: its key is used.
            if let Some(entry) = cached.as_mut() {
                entry.next_key_used = true;
            }
            return Err(error);
        }
        // The change is made. Earlier builds read only the single object: keep it current
        // for them (a rolling deploy, a rollback). It is not what this build decides by, so
        // failing to write it does not fail the change.
        if Self::write(store, &Self::key(user)?, &record)
            .await
            .is_err()
        {
            tracing::warn!("could not update the single-object copy of a user access record");
        }
        Self::advance(&mut cached, &old, record).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::filesystem::FileSystemStore;

    #[tokio::test]
    async fn suspension_survives_restart_and_restore_never_revives_tokens() {
        let path = std::env::temp_dir().join(format!("user-access-{}", nanoid::nanoid!()));
        let store: Option<Arc<Box<dyn Store>>> = Some(Arc::new(Box::new(
            FileSystemStore::new(path.clone()).unwrap(),
        )));
        let access = UserAccess::default();
        let generation = access.generation(&store, "member").await.unwrap();
        let connection = access
            .authorize(&store, "member", generation)
            .await
            .unwrap();
        let other = access.authorize(&store, "other", 0).await.unwrap();
        access.set_suspended(&store, "member", true).await.unwrap();
        assert!(connection.is_cancelled());
        assert!(!other.is_cancelled());
        let restarted = UserAccess::default();
        assert!(restarted.generation(&store, "member").await.is_err());
        restarted
            .set_suspended(&store, "member", false)
            .await
            .unwrap();
        assert!(restarted
            .authorize(&store, "member", generation)
            .await
            .is_err());
        let fresh = restarted.generation(&store, "member").await.unwrap();
        assert!(restarted.authorize(&store, "member", fresh).await.is_ok());
        assert!(restarted.generation(&store, "../escape").await.is_err());
        assert!(UserAccess::default()
            .set_suspended(&None, "member", true)
            .await
            .is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    struct StalledStore;
    #[async_trait::async_trait]
    impl Store for StalledStore {
        async fn init(&self) -> y_sweet_core::store::Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> y_sweet_core::store::Result<Option<Vec<u8>>> {
            if key.contains("stalled") {
                std::future::pending().await
            } else {
                Ok(None)
            }
        }
        async fn set(&self, _: &str, _: Vec<u8>) -> y_sweet_core::store::Result<()> {
            std::future::pending().await
        }
        async fn remove(&self, _: &str) -> y_sweet_core::store::Result<()> {
            Ok(())
        }
        async fn exists(&self, _: &str) -> y_sweet_core::store::Result<bool> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn stalled_storage_is_bounded_and_does_not_block_other_users() {
        let store: Option<Arc<Box<dyn Store>>> = Some(Arc::new(Box::new(StalledStore)));
        let access = UserAccess::default();
        access.generation(&store, "other").await.unwrap();
        let (stalled, other) = tokio::join!(
            timeout(Duration::from_secs(4), access.generation(&store, "stalled")),
            async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                timeout(
                    Duration::from_millis(100),
                    access.authorize(&store, "other", 0),
                )
                .await
            }
        );
        assert!(stalled.unwrap().is_err());
        assert!(other.unwrap().is_ok());
        let connection = access.authorize(&store, "other", 0).await.unwrap();
        assert!(timeout(
            Duration::from_secs(4),
            access.set_suspended(&store, "other", true)
        )
        .await
        .unwrap()
        .is_err());
        assert!(!connection.is_cancelled());
        assert!(access.authorize(&store, "other", 0).await.is_ok());
    }

    /// A key and the value written to it.
    type StoredWrite = (String, Vec<u8>);

    /// An in-memory store in which a write can time out for the caller and still be applied
    /// by the store later, as an S3 write can.
    #[derive(Clone, Default)]
    struct LateStore {
        data: Arc<std::sync::Mutex<HashMap<String, Vec<u8>>>>,
        /// How many more writes go through before one hangs. What that one would have
        /// written is kept in `late`.
        stall_after: Arc<std::sync::Mutex<Option<usize>>>,
        late: Arc<std::sync::Mutex<Vec<StoredWrite>>>,
        /// Writes to keys ending in this fail outright.
        fail_sets_to: Arc<std::sync::Mutex<Option<String>>>,
    }

    impl LateStore {
        fn handle(&self) -> Option<Arc<Box<dyn Store>>> {
            Some(Arc::new(Box::new(self.clone())))
        }

        /// The store applies every write that timed out, now. Returns how many.
        fn land_late_writes(&self) -> usize {
            let late: Vec<_> = self.late.lock().unwrap().drain(..).collect();
            let landed = late.len();
            self.data.lock().unwrap().extend(late);
            landed
        }

        fn keys(&self) -> Vec<String> {
            let mut keys: Vec<_> = self.data.lock().unwrap().keys().cloned().collect();
            keys.sort();
            keys
        }
    }

    #[async_trait::async_trait]
    impl Store for LateStore {
        async fn init(&self) -> y_sweet_core::store::Result<()> {
            Ok(())
        }
        async fn get(&self, key: &str) -> y_sweet_core::store::Result<Option<Vec<u8>>> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }
        async fn set(&self, key: &str, value: Vec<u8>) -> y_sweet_core::store::Result<()> {
            let stall = {
                let mut stall_after = self.stall_after.lock().unwrap();
                match *stall_after {
                    Some(0) => {
                        *stall_after = None;
                        true
                    }
                    Some(left) => {
                        *stall_after = Some(left - 1);
                        false
                    }
                    None => false,
                }
            };
            if stall {
                self.late.lock().unwrap().push((key.to_string(), value));
                return std::future::pending().await;
            }
            let failing = self.fail_sets_to.lock().unwrap().clone();
            if failing.is_some_and(|end| key.ends_with(&end)) {
                return Err(y_sweet_core::store::StoreError::ConnectionError(
                    "test failure".to_string(),
                ));
            }
            self.data.lock().unwrap().insert(key.to_string(), value);
            Ok(())
        }
        async fn remove(&self, key: &str) -> y_sweet_core::store::Result<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> y_sweet_core::store::Result<bool> {
            Ok(self.data.lock().unwrap().contains_key(key))
        }
    }

    // Paused time: the three-second storage limit passes at once.
    #[tokio::test(start_paused = true)]
    async fn a_write_that_timed_out_and_lands_late_cannot_undo_a_later_suspension() {
        // Whichever of a restore's writes it is that times out.
        for stalled_write in 0..4 {
            let backing = LateStore::default();
            let store = backing.handle();
            let access = UserAccess::default();
            access.set_suspended(&store, "member", true).await.unwrap();

            // A restore whose n-th write reaches the store but times out for the server.
            *backing.stall_after.lock().unwrap() = Some(stalled_write);
            let restore = access.set_suspended(&store, "member", false).await;
            let timed_out = backing.stall_after.lock().unwrap().take().is_none();
            if restore.is_err() {
                // The retry succeeds.
                access.set_suspended(&store, "member", false).await.unwrap();
            }
            // The restored user gets a token.
            let restored = access.generation(&store, "member").await.unwrap();
            let connection = access.authorize(&store, "member", restored).await.unwrap();

            // The user is suspended again, and the server confirms it.
            access.set_suspended(&store, "member", true).await.unwrap();
            assert!(connection.is_cancelled());

            // Only now does the store apply the write that timed out.
            assert_eq!(backing.land_late_writes(), usize::from(timed_out));

            // Still suspended, in this process and after a restart, and the token minted
            // while the user was restored stays dead.
            for access in [access, UserAccess::default()] {
                assert!(
                    access.generation(&store, "member").await.is_err(),
                    "write {stalled_write} of the restore undid the suspension"
                );
                assert!(access.authorize(&store, "member", restored).await.is_err());
            }
        }
    }

    #[tokio::test]
    async fn records_of_earlier_builds_are_read_and_kept_current() {
        let backing = LateStore::default();
        let store = backing.handle();
        const SINGLE: &str = "__dalus_auth/users/member.json";
        let stored = |key: &str| {
            let data = backing.data.lock().unwrap();
            String::from_utf8(data.get(key).expect(key).clone()).unwrap()
        };

        // What the production build wrote for a user it suspended, twice restored before.
        backing.data.lock().unwrap().insert(
            SINGLE.to_string(),
            br#"{"generation":3,"suspended":true}"#.to_vec(),
        );
        let access = UserAccess::default();
        assert!(access.generation(&store, "member").await.is_err());
        assert!(access.authorize(&store, "member", 3).await.is_err());

        // Restoring continues from that generation. The first change of a process settles
        // the next key before using the one after it.
        access.set_suspended(&store, "member", false).await.unwrap();
        assert_eq!(access.generation(&store, "member").await.unwrap(), 5);
        assert_eq!(
            backing.keys(),
            [
                SINGLE,
                "__dalus_auth/users/member/4.json",
                "__dalus_auth/users/member/5.json"
            ]
        );
        assert_eq!(
            stored("__dalus_auth/users/member/4.json"),
            r#"{"generation":4,"suspended":true}"#
        );
        // The single object is in the format, and at the state, an earlier build expects.
        assert_eq!(stored(SINGLE), r#"{"generation":5,"suspended":false}"#);
        assert_eq!(stored("__dalus_auth/users/member/5.json"), stored(SINGLE));

        // A later change in the same process takes the next key and nothing else.
        access.set_suspended(&store, "member", true).await.unwrap();
        assert_eq!(backing.keys().len(), 4);
        assert_eq!(stored(SINGLE), r#"{"generation":6,"suspended":true}"#);

        // If the single object cannot be written the change stands, and a restart finds it
        // through the generation keys although the single object is behind.
        *backing.fail_sets_to.lock().unwrap() = Some("users/member.json".to_string());
        access.set_suspended(&store, "member", false).await.unwrap();
        assert_eq!(stored(SINGLE), r#"{"generation":6,"suspended":true}"#);
        let restarted = UserAccess::default();
        assert_eq!(restarted.generation(&store, "member").await.unwrap(), 7);

        // An earlier build that suspends the user afterwards writes only the single object,
        // one generation on from the one it read there. That is honoured.
        backing.data.lock().unwrap().insert(
            SINGLE.to_string(),
            br#"{"generation":8,"suspended":true}"#.to_vec(),
        );
        assert!(UserAccess::default()
            .generation(&store, "member")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_suspension_is_acknowledged_only_once_authorized_work_has_finished() {
        let backing = LateStore::default();
        let store = backing.handle();
        let access = Arc::new(UserAccess::default());
        let authorized = access.authorize_guarded(&store, "member", 0).await.unwrap();
        let other = access.authorize_guarded(&store, "other", 0).await.unwrap();

        // Someone is in the middle of applying a write for the user, and for another user.
        let applying = authorized.activity.clone().read_owned().await;
        let _other_applying = other.activity.clone().read_owned().await;
        assert!(!authorized.cancellation.is_cancelled());

        let suspension = tokio::spawn({
            let (access, store) = (access.clone(), store.clone());
            async move { access.set_suspended(&store, "member", true).await }
        });
        // The suspension takes effect (new work is refused) but is not acknowledged yet.
        tokio::time::timeout(Duration::from_secs(5), authorized.cancellation.cancelled())
            .await
            .expect("the suspension never took effect");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!suspension.is_finished());

        // When that write is done, it is. Another user's work never held it up.
        drop(applying);
        tokio::time::timeout(Duration::from_secs(5), suspension)
            .await
            .expect("the suspension was never acknowledged")
            .unwrap()
            .unwrap();
        assert!(!other.cancellation.is_cancelled());
    }
}

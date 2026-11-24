//! Durable, singleton-server user revocation. Old generations never become valid on restore.
//!
//! A user's state is a [Record]: a generation and whether the user is suspended. Every change
//! is a new record with a higher generation, appended to the user's *chain*: the objects
//! `__dalus_auth/users/<user>/1.json`, `2.json`, and so on. The last record of the chain is
//! the user's state. A position in the chain is written with one acknowledged content at
//! most, and only once every position before it is in the store, so:
//!
//! - a write that timed out for this server and is applied by the store later (an S3 write
//!   can be) lands on a position that is, by then, not the last. It cannot replace a state
//!   that was acknowledged after it, which a single overwritten object could not rule out;
//! - the chain always starts at position 1, whatever else the store holds, and its end is
//!   found by reading positions upwards until one is missing.
//!
//! Earlier builds kept one object per user (`__dalus_auth/users/<user>.json`) and overwrote
//! it. It is still read, but it can only raise a user's state, never lower it: it counts
//! when its generation is higher than the one the chain's state binds tokens to (a change an
//! earlier build made, before this build first saw the user or during a rollback), and it is
//! then copied to the end of the chain, after which nothing written to that object later with
//! a lower generation, such as an earlier build's write that timed out and lands late, matters
//! any more. It is written first in every change, and a change is acknowledged only once it is
//! there too, so that a build that knows only that object sees every acknowledged change and
//! the object is never behind the chain's last change.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    sync::{Mutex, RwLock},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use y_sweet_core::store::Store;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
struct Record {
    generation: u64,
    suspended: bool,
    /// Set on a record that only settles a position of the chain (see
    /// [UserAccess::set_suspended]): the generation of the change whose state it keeps. Tokens
    /// are bound to the generation of the last real change, so settling invalidates none.
    /// Never set in the single object, which holds real changes only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keeps: Option<u64>,
}

impl Record {
    /// The generation tokens of this state are minted at and checked against: that of the
    /// change that made it. The production build mints at, and checks against, the
    /// generation in the single object, which is the same number.
    fn token_generation(&self) -> u64 {
        self.keeps.unwrap_or(self.generation)
    }
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
    /// How many positions of the user's chain are known to be in the store.
    chain_len: u64,
    /// Whether the next position of the chain may have been written already: by a write of
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

    /// The key of one position (from 1) of the user's chain of records.
    fn chain_key(user: &str, position: u64) -> Result<String> {
        Self::key(user)?;
        Ok(format!("__dalus_auth/users/{user}/{position}.json"))
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
        let Some(store) = store else {
            return Err(anyhow!("User-scoped access requires durable storage"));
        };
        // The chain, from its fixed start to its last record.
        let mut chain_len = 0;
        let mut last = None;
        while let Some(record) = Self::read(store, &Self::chain_key(user, chain_len + 1)?).await? {
            last = Some(record);
            chain_len += 1;
        }
        // The single object of earlier builds counts only where it is ahead of the chain:
        // when its generation is above the one the chain's state binds tokens to. This build
        // writes it first in every change, with that generation, so it is never behind a
        // change this build acknowledged; an earlier build writes it one generation on from
        // what it read there, so a change it made after this build's last one is always
        // above. That holds also when this build's last record is a settling one whose own
        // generation is the same or higher: the earlier build's change is newer than it.
        let single = Self::read(store, &key).await?;
        let mut record = last.clone().unwrap_or_default();
        let ahead = |single: &Record| {
            last.as_ref()
                .map_or(true, |last| single.generation > last.token_generation())
        };
        if let Some(single) = single.filter(ahead) {
            // A change by an earlier build. Make it part of the chain, so that it holds
            // whatever is written to the single object after this. Its generation stays the
            // one tokens are bound to; the record takes a generation above the chain's if it
            // is not already, so that generations along the chain only grow. If the copy
            // cannot be made now, the user's state is the same; the next change settles the
            // position (it is marked as possibly used below, like any first position).
            record = match &last {
                Some(last) if single.generation <= last.generation => Record {
                    generation: Self::next_generation(last)?,
                    suspended: single.suspended,
                    keeps: Some(single.generation),
                },
                _ => single,
            };
            if Self::write(store, &Self::chain_key(user, chain_len + 1)?, &record)
                .await
                .is_ok()
            {
                chain_len += 1;
            }
        }
        let entry = Entry {
            record,
            chain_len,
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
        Ok(entry.record.token_generation())
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
        if entry.record.suspended || entry.record.token_generation() != generation {
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
        if entry.record.suspended || entry.record.token_generation() != generation {
            return Err(anyhow!("User access denied"));
        }
        Ok(Authorized {
            cancellation: entry.cancellation,
            activity: entry.activity,
        })
    }

    /// Moves the user to `record`, a change that is in the store as the next position of the
    /// chain: what was authorized under `old` is cancelled, and whatever of it is still
    /// under way is waited for.
    async fn advance(cached: &mut Option<Entry>, old: &Entry, record: Record) -> Entry {
        old.cancellation.cancel();
        let entry = Entry {
            record,
            chain_len: old.chain_len + 1,
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
            // The next position of the chain may hold, or may yet receive, a write this
            // process never confirmed. The record of this change must not share a position
            // with it, or that write could replace it later. So that position is settled
            // first, with a record that changes nothing but the generation, and the change
            // goes one higher. If the unconfirmed write lands on the settled position after
            // all, it is below the change by then.
            //
            // Settling changes nothing for the user: the record keeps the state and the token
            // generation, so their tokens and connections stay good. If the change then
            // fails, the user is exactly as before.
            let unchanged = Record {
                generation: Self::next_generation(&old.record)?,
                suspended: old.record.suspended,
                keeps: Some(old.record.token_generation()),
            };
            Self::write(
                store,
                &Self::chain_key(user, old.chain_len + 1)?,
                &unchanged,
            )
            .await?;
            old = Entry {
                record: unchanged,
                chain_len: old.chain_len + 1,
                next_key_used: false,
                ..old
            };
            *cached = Some(old.clone());
        }

        let record = Record {
            generation: Self::next_generation(&old.record)?,
            suspended,
            keeps: None,
        };
        // Persist before acknowledging, in both places: the single object first, then the
        // chain. The single object is what an earlier build reads after a rollback, so a
        // change it does not hold is not acknowledged; and written first, it is never behind
        // the chain's last change, which is what lets this build tell an earlier build's
        // later change from its own (see [UserAccess::load]). Failure leaves this process
        // in the old state and allows a safe retry.
        for key in [Self::key(user)?, Self::chain_key(user, old.chain_len + 1)?] {
            if let Err(error) = Self::write(store, &key, &record).await {
                // The write may have reached the store all the same: the generation and the
                // chain position are used. The next change settles them first.
                if let Some(entry) = cached.as_mut() {
                    entry.next_key_used = true;
                }
                return Err(error);
            }
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
        /// How many more writes go through before one fails outright (and stores nothing).
        fail_after: Arc<std::sync::Mutex<Option<usize>>>,
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
            let fail_now = {
                let mut fail_after = self.fail_after.lock().unwrap();
                match *fail_after {
                    Some(0) => {
                        *fail_after = None;
                        true
                    }
                    Some(left) => {
                        *fail_after = Some(left - 1);
                        false
                    }
                    None => false,
                }
            };
            let failing = self.fail_sets_to.lock().unwrap().clone();
            if fail_now || failing.is_some_and(|end| key.ends_with(&end)) {
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
        let chain = |position: u64| stored(&format!("__dalus_auth/users/member/{position}.json"));

        // What the production build wrote for a user it suspended, twice restored before.
        backing.data.lock().unwrap().insert(
            SINGLE.to_string(),
            br#"{"generation":3,"suspended":true}"#.to_vec(),
        );
        let access = UserAccess::default();
        assert!(access.generation(&store, "member").await.is_err());
        assert!(access.authorize(&store, "member", 3).await.is_err());
        // Seeing the user started their chain with that state. A user with nothing in the
        // store gets nothing written.
        assert_eq!(chain(1), r#"{"generation":3,"suspended":true}"#);
        assert_eq!(access.generation(&store, "nobody").await.unwrap(), 0);
        assert_eq!(backing.keys().len(), 2);

        // Restoring continues from that generation. The first change of a process settles
        // the next position before using the one after it.
        access.set_suspended(&store, "member", false).await.unwrap();
        assert_eq!(access.generation(&store, "member").await.unwrap(), 5);
        // The settling record keeps the state and the generation tokens are bound to.
        assert_eq!(chain(2), r#"{"generation":4,"suspended":true,"keeps":3}"#);
        assert_eq!(chain(3), r#"{"generation":5,"suspended":false}"#);
        assert_eq!(backing.keys().len(), 4);
        // The single object is in the format, and at the state, an earlier build expects.
        assert_eq!(stored(SINGLE), r#"{"generation":5,"suspended":false}"#);

        // A later change in the same process takes the next position and nothing else.
        access.set_suspended(&store, "member", true).await.unwrap();
        assert_eq!(backing.keys().len(), 5);
        assert_eq!(stored(SINGLE), r#"{"generation":6,"suspended":true}"#);
        assert_eq!(chain(4), stored(SINGLE));

        // If the single object cannot be written the change is not made: an earlier build
        // would not see it. Nothing else is written, and a restart finds the old state.
        *backing.fail_sets_to.lock().unwrap() = Some("users/member.json".to_string());
        assert!(access.set_suspended(&store, "member", false).await.is_err());
        assert_eq!(stored(SINGLE), r#"{"generation":6,"suspended":true}"#);
        assert_eq!(backing.keys().len(), 5);
        *backing.fail_sets_to.lock().unwrap() = None;
        assert!(UserAccess::default()
            .generation(&store, "member")
            .await
            .is_err());
        // The retry settles the generation the failed write may have used, then restores.
        access.set_suspended(&store, "member", false).await.unwrap();
        assert_eq!(chain(5), r#"{"generation":7,"suspended":true,"keeps":6}"#);
        assert_eq!(stored(SINGLE), r#"{"generation":8,"suspended":false}"#);
        let restarted = UserAccess::default();
        assert_eq!(restarted.generation(&store, "member").await.unwrap(), 8);

        // An earlier build that suspends the user afterwards (a rollback) writes only the
        // single object, one generation on from the one it read there. That is honoured,
        // and a build like this one continues from it.
        backing.data.lock().unwrap().insert(
            SINGLE.to_string(),
            br#"{"generation":9,"suspended":true}"#.to_vec(),
        );
        let upgraded = UserAccess::default();
        assert!(upgraded.generation(&store, "member").await.is_err());
        upgraded
            .set_suspended(&store, "member", false)
            .await
            .unwrap();
        assert_eq!(upgraded.generation(&store, "member").await.unwrap(), 11);
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

    /// The app treats any answer but `204` as "the account change was not completed": it rolls
    /// back its own change and asks the admin to retry. So a change that fails must leave the
    /// user as they were: open connections stay open and tokens keep working, in this process
    /// and after a restart. Here the change's first write (settling the position an earlier
    /// process may have used) succeeds and its own write fails.
    #[tokio::test]
    async fn a_change_that_fails_leaves_the_users_connections_and_tokens_alone() {
        for suspended_before in [false, true] {
            let backing = LateStore::default();
            let store = backing.handle();
            if suspended_before {
                UserAccess::default()
                    .set_suspended(&store, "member", true)
                    .await
                    .unwrap();
                UserAccess::default()
                    .set_suspended(&store, "member", false)
                    .await
                    .unwrap();
            }
            let access = UserAccess::default();
            let generation = access.generation(&store, "member").await.unwrap();
            let connection = access
                .authorize_guarded(&store, "member", generation)
                .await
                .unwrap();

            // The settling write (the call's first) lands on the next position; the change's
            // own first write (the second) fails.
            let chain_len = backing
                .keys()
                .iter()
                .filter(|key| key.contains("member/"))
                .count();
            *backing.fail_after.lock().unwrap() = Some(1);
            assert!(access.set_suspended(&store, "member", true).await.is_err());
            assert_eq!(*backing.fail_after.lock().unwrap(), None);
            assert!(
                backing
                    .keys()
                    .contains(&format!("__dalus_auth/users/member/{}.json", chain_len + 1)),
                "the settling write was not made, so this tests nothing"
            );

            assert!(
                !connection.cancellation.is_cancelled(),
                "the user was disconnected"
            );
            for access in [access, UserAccess::default()] {
                assert_eq!(
                    access.generation(&store, "member").await.unwrap(),
                    generation
                );
                assert!(access.authorize(&store, "member", generation).await.is_ok());
            }
        }
    }

    /// What the production build (4f1909b with user-suspension.patch) does with the store:
    /// it knows only the single object, reads it (absent is generation 0), and writes it one
    /// generation on. Tokens it mints carry that generation, and it accepts a token only at it.
    async fn production_sets(store: &Option<Arc<Box<dyn Store>>>, suspended: bool) {
        let store = store.as_ref().unwrap();
        let current = UserAccess::read(store, SINGLE_OBJECT)
            .await
            .unwrap()
            .unwrap_or_default();
        let record = Record {
            generation: current.generation + 1,
            suspended,
            keeps: None,
        };
        UserAccess::write(store, SINGLE_OBJECT, &record)
            .await
            .unwrap();
    }

    /// The state the production build sees.
    async fn production_view(store: &Option<Arc<Box<dyn Store>>>) -> Record {
        UserAccess::read(store.as_ref().unwrap(), SINGLE_OBJECT)
            .await
            .unwrap()
            .unwrap_or_default()
    }

    /// Histories this build may leave a user in before a rollback: changes that succeeded, and
    /// a last change one of whose writes failed (counted from the first write of that call).
    async fn leave_history(backing: &LateStore, history: &[bool], failing_write: Option<usize>) {
        let store = backing.handle();
        let access = UserAccess::default();
        for (i, suspended) in history.iter().enumerate() {
            let last = i + 1 == history.len();
            if last {
                *backing.fail_after.lock().unwrap() = failing_write;
            }
            let result = access.set_suspended(&store, "member", *suspended).await;
            // A call makes two or three writes: a later one may not get to the failing one.
            let failed = failing_write.is_some() && backing.fail_after.lock().unwrap().is_none();
            assert_eq!(result.is_ok(), !(last && failed));
            *backing.fail_after.lock().unwrap() = None;
        }
    }

    const HISTORIES: &[&[bool]] = &[&[true], &[true, false], &[false, true, false]];

    /// Rolled back, the production build suspends or restores the user and acknowledges it.
    /// Rolled forward, this build must enforce that, whatever it left behind: also when its
    /// own last change failed half way and the production build's write lands on the same
    /// generation as this build's last record.
    #[tokio::test]
    async fn a_change_the_production_build_made_during_a_rollback_holds_after_rolling_forward() {
        for history in HISTORIES {
            for failing_write in [None, Some(0), Some(1), Some(2)] {
                for production_suspends in [true, false] {
                    let case = format!("{history:?}, write {failing_write:?} failed, production suspends: {production_suspends}");
                    let backing = LateStore::default();
                    let store = backing.handle();
                    leave_history(&backing, history, failing_write).await;
                    // Rolled back: the production build makes its change. A user it restores
                    // gets a token bound to its generation.
                    production_sets(&store, production_suspends).await;
                    let production_token = production_view(&store).await.generation;

                    // Rolled forward, in a fresh process, twice (the first one may have moved
                    // what it found into the chain).
                    for _ in 0..2 {
                        let access = UserAccess::default();
                        let generation = access.generation(&store, "member").await;
                        assert_eq!(generation.is_err(), production_suspends, "{case}");
                        if !production_suspends {
                            assert_eq!(generation.unwrap(), production_token, "{case}");
                            assert!(
                                access
                                    .authorize(&store, "member", production_token)
                                    .await
                                    .is_ok(),
                                "{case}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The reverse: this build suspends or restores the user and acknowledges it, then the
    /// production build is deployed again. It must see the change, and a restored user's
    /// tokens from this build must be good there.
    #[tokio::test]
    async fn a_change_this_build_acknowledged_holds_after_rolling_back() {
        for history in HISTORIES {
            for failing_write in [None, Some(0), Some(1), Some(2)] {
                for suspends in [true, false] {
                    let case = format!(
                        "{history:?}, write {failing_write:?} failed, then suspends: {suspends}"
                    );
                    for failing_single in [false, true] {
                        let backing = LateStore::default();
                        let store = backing.handle();
                        leave_history(&backing, history, failing_write).await;
                        let access = UserAccess::default();
                        if failing_single {
                            // The single object cannot be written: the change is not
                            // acknowledged, and the retry is.
                            *backing.fail_sets_to.lock().unwrap() =
                                Some("users/member.json".to_string());
                            assert!(
                                access
                                    .set_suspended(&store, "member", suspends)
                                    .await
                                    .is_err(),
                                "{case}: acknowledged without the single object"
                            );
                            *backing.fail_sets_to.lock().unwrap() = None;
                        }
                        access
                            .set_suspended(&store, "member", suspends)
                            .await
                            .unwrap();
                        let seen = production_view(&store).await;
                        assert_eq!(seen.suspended, suspends, "{case}");
                        if !suspends {
                            assert_eq!(
                                access.generation(&store, "member").await.unwrap(),
                                seen.generation,
                                "{case}: a token minted here would be refused there"
                            );
                        }
                    }
                }
            }
        }
    }

    const SINGLE_OBJECT: &str = "__dalus_auth/users/member.json";

    /// The store as an earlier build (one object per user, overwritten) left it: the user
    /// was suspended at generation 1, restored at 2, suspended again at 3. The first attempt
    /// at the restore timed out and is still on its way: `late_restore` is what it will
    /// write when it lands.
    fn store_after_an_earlier_build() -> (LateStore, Vec<u8>) {
        let backing = LateStore::default();
        backing.data.lock().unwrap().insert(
            SINGLE_OBJECT.to_string(),
            br#"{"generation":3,"suspended":true}"#.to_vec(),
        );
        (backing, br#"{"generation":2,"suspended":false}"#.to_vec())
    }

    async fn assert_still_suspended(store: &Option<Arc<Box<dyn Store>>>) {
        // In a process that starts now, and with the token the user got at generation 2.
        let restarted = UserAccess::default();
        assert!(restarted.generation(store, "member").await.is_err());
        assert!(restarted.authorize(store, "member", 2).await.is_err());
    }

    #[tokio::test]
    async fn a_restore_an_earlier_build_left_pending_cannot_resurrect_a_suspended_user() {
        let (backing, late_restore) = store_after_an_earlier_build();
        let store = backing.handle();

        // This build takes over and suspends the user once more.
        let access = UserAccess::default();
        assert!(access.generation(&store, "member").await.is_err());
        access.set_suspended(&store, "member", true).await.unwrap();

        // Now the earlier build's restore lands, on the only object it knows.
        backing
            .data
            .lock()
            .unwrap()
            .insert(SINGLE_OBJECT.to_string(), late_restore);

        assert_still_suspended(&store).await;
        // The running process is not fooled either, and the user can be restored properly.
        assert!(access.generation(&store, "member").await.is_err());
        let restarted = UserAccess::default();
        restarted
            .set_suspended(&store, "member", false)
            .await
            .unwrap();
        let fresh = restarted.generation(&store, "member").await.unwrap();
        assert!(fresh > 3);
        assert!(restarted.authorize(&store, "member", 2).await.is_err());
    }

    #[tokio::test]
    async fn seeing_a_user_is_enough_to_outlast_an_earlier_builds_late_write() {
        // No change by this build: it only looked the user up (a refused mint), which
        // copies what the single object says into the chain.
        let (backing, late_restore) = store_after_an_earlier_build();
        let store = backing.handle();
        assert!(UserAccess::default()
            .generation(&store, "member")
            .await
            .is_err());
        backing
            .data
            .lock()
            .unwrap()
            .insert(SINGLE_OBJECT.to_string(), late_restore);
        assert_still_suspended(&store).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_or_late_first_chain_write_does_not_weaken_a_later_suspension() {
        for first_write in ["fails", "times out and lands late"] {
            let (backing, late_restore) = store_after_an_earlier_build();
            let store = backing.handle();
            match first_write {
                "fails" => {
                    *backing.fail_sets_to.lock().unwrap() = Some("member/1.json".to_string())
                }
                _ => *backing.stall_after.lock().unwrap() = Some(0),
            }

            // Looking the user up works although the copy into the chain did not.
            let access = UserAccess::default();
            assert!(access.generation(&store, "member").await.is_err());
            assert!(!backing.keys().iter().any(|key| key.ends_with("/1.json")));
            *backing.fail_sets_to.lock().unwrap() = None;

            // A suspension by this build then stands on its own.
            access.set_suspended(&store, "member", true).await.unwrap();
            backing.land_late_writes();
            backing
                .data
                .lock()
                .unwrap()
                .insert(SINGLE_OBJECT.to_string(), late_restore);
            assert_still_suspended(&store).await;
        }
    }

    #[tokio::test]
    async fn the_single_object_can_raise_the_state_but_not_lower_it() {
        let backing = LateStore::default();
        let store = backing.handle();
        let set_single = |record: &str| {
            backing
                .data
                .lock()
                .unwrap()
                .insert(SINGLE_OBJECT.to_string(), record.as_bytes().to_vec());
        };
        // A user this build suspended, with nothing from an earlier build.
        UserAccess::default()
            .set_suspended(&store, "member", true)
            .await
            .unwrap();
        let suspended_at = {
            let data = backing.data.lock().unwrap();
            let record: Record = serde_json::from_slice(data.get(SINGLE_OBJECT).unwrap()).unwrap();
            record.generation
        };

        // Lower or equal generations in the single object change nothing.
        for generation in [0, suspended_at - 1, suspended_at] {
            set_single(&format!(
                r#"{{"generation":{generation},"suspended":false}}"#
            ));
            assert!(UserAccess::default()
                .generation(&store, "member")
                .await
                .is_err());
        }
        // A higher one is a change made by an earlier build after this one (a rollback): it
        // is the state, and stays the state once this build has seen it.
        let restored_at = suspended_at + 1;
        set_single(&format!(
            r#"{{"generation":{restored_at},"suspended":false}}"#
        ));
        assert_eq!(
            UserAccess::default()
                .generation(&store, "member")
                .await
                .unwrap(),
            restored_at
        );
        set_single(r#"{"generation":1,"suspended":true}"#);
        assert_eq!(
            UserAccess::default()
                .generation(&store, "member")
                .await
                .unwrap(),
            restored_at
        );
    }
}

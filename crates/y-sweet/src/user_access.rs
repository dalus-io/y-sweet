//! Durable, singleton-server user revocation. Old generations never become valid on restore.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::timeout};
use tokio_util::sync::CancellationToken;
use y_sweet_core::store::Store;

#[derive(Clone, Default, Serialize, Deserialize)]
struct Record {
    generation: u64,
    suspended: bool,
}

#[derive(Clone, Default)]
struct Entry {
    record: Record,
    cancellation: CancellationToken,
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
            Some(store) => match timeout(Duration::from_secs(3), store.get(&key)).await?? {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => Record::default(),
            },
            None => return Err(anyhow!("User-scoped access requires durable storage")),
        };
        let entry = Entry {
            record,
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

    pub async fn set_suspended(
        &self,
        store: &Option<Arc<Box<dyn Store>>>,
        user: &str,
        suspended: bool,
    ) -> Result<()> {
        let cell = self.cell(user).await?;
        let mut cached = cell.lock().await;
        let old = Self::load(&mut cached, store, user).await?;
        let record = Record {
            generation: old
                .record
                .generation
                .checked_add(1)
                .ok_or_else(|| anyhow!("Access generation exhausted"))?,
            suspended,
        };
        // Persist before acknowledging. Failure leaves the old state and allows a safe retry.
        timeout(
            Duration::from_secs(3),
            store
                .as_ref()
                .ok_or_else(|| anyhow!("Durable storage required"))?
                .set(&Self::key(user)?, serde_json::to_vec(&record)?),
        )
        .await??;
        old.cancellation.cancel();
        *cached = Some(Entry {
            record,
            cancellation: CancellationToken::new(),
        });
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
}

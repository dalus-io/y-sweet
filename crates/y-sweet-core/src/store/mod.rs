pub mod s3;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Store bucket does not exist. {0}")]
    BucketDoesNotExist(String),
    #[error("Object does not exist. {0}")]
    DoesNotExist(String),
    #[error("Not authorized to access store. {0}")]
    NotAuthorized(String),
    #[error("Error connecting to store. {0}")]
    ConnectionError(String),
    /// The request failed after it may have been sent in full: the connection broke, or the
    /// endpoint answered with a server error. Like [StoreError::Timeout], and unlike the
    /// errors above, this leaves the outcome of a write unknown.
    #[error("The request to the store was interrupted. {0}")]
    Interrupted(String),
    /// The store gave up waiting on a request after `limit`. This leaves the outcome of a
    /// write unknown: the endpoint may have received all of it and may still apply it,
    /// later (see `SyncKv::persist`).
    #[error("Timed out after {} ms {what} the store.", limit.as_millis())]
    Timeout {
        limit: std::time::Duration,
        /// What was being done, for the message: "waiting for", "reading from".
        what: &'static str,
    },
}

impl StoreError {
    /// For a failed write: whether the store may nevertheless have received it in full, and
    /// so may still apply it. `Some` with the time the request was given, where that is
    /// known. `None` for failures that are certain to have left nothing behind: the request
    /// never left (no connection), or the endpoint refused it.
    pub fn write_may_still_land(&self) -> Option<std::time::Duration> {
        match self {
            StoreError::Timeout { limit, .. } => Some(*limit),
            StoreError::Interrupted(_) => Some(std::time::Duration::ZERO),
            StoreError::BucketDoesNotExist(_)
            | StoreError::DoesNotExist(_)
            | StoreError::NotAuthorized(_)
            | StoreError::ConnectionError(_) => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
pub trait Store: 'static {
    async fn init(&self) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()>;
    async fn remove(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
pub trait Store: Send + Sync {
    async fn init(&self) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()>;
    async fn remove(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
}

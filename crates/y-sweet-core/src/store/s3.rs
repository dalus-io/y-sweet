use super::{Result, StoreError};
use crate::store::Store;
use async_trait::async_trait;
use reqwest::{Client, Method, Response, StatusCode, Url};
use rusty_s3::{Bucket, Credentials, S3Action};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::Duration;
use time::OffsetDateTime;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct S3Config {
    pub key: String,
    pub endpoint: String,
    pub secret: String,
    pub token: Option<String>,
    pub bucket: String,
    pub region: String,
    pub bucket_prefix: Option<String>,

    // Use old path-style URLs, needed to support some S3-compatible APIs (including some minio setups)
    pub path_style: bool,
}

const PRESIGNED_URL_DURATION: Duration = Duration::from_secs(60 * 60);

/// The default of [S3Store::with_request_timeout].
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How long establishing a connection (TCP and TLS) may take, at most; never more than the
/// request timeout.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The slowest upload a write is given time for: on top of the request timeout, a write gets
/// one second for each of these many bytes of its body. Without it, the timeout would put a
/// ceiling on the size of a doc that can be saved at all.
pub const MIN_UPLOAD_BYTES_PER_SECOND: usize = 1024 * 1024;

pub struct S3Store {
    bucket: Bucket,
    _bucket_checked: OnceLock<()>,
    client: Client,
    credentials: Credentials,
    prefix: Option<String>,
    /// See [S3Store::with_request_timeout].
    request_timeout: Duration,
}

/// How long a request with a body of `body_len` bytes may take in all.
fn write_timeout(request_timeout: Duration, body_len: usize) -> Duration {
    request_timeout + Duration::from_secs((body_len / MIN_UPLOAD_BYTES_PER_SECOND) as u64)
}

/// `what`, given up on after `limit`. Giving up drops the request, which closes its
/// connection: when the error is returned, nothing of the request is still being sent.
#[cfg(not(target_arch = "wasm32"))]
async fn within<T>(
    limit: Duration,
    what: &'static str,
    request: impl std::future::Future<Output = T>,
) -> Result<T> {
    tokio::time::timeout(limit, request)
        .await
        .map_err(|_| StoreError::Timeout { limit, what })
}

/// On wasm (the Cloudflare worker) there is no timer here; the platform bounds the request.
#[cfg(target_arch = "wasm32")]
async fn within<T>(
    _limit: Duration,
    _what: &'static str,
    request: impl std::future::Future<Output = T>,
) -> Result<T> {
    Ok(request.await)
}

impl S3Store {
    pub fn new(config: S3Config) -> Self {
        let credentials = if let Some(token) = config.token {
            Credentials::new_with_token(config.key, config.secret, token)
        } else {
            Credentials::new(config.key, config.secret)
        };
        let endpoint: Url = config.endpoint.parse().expect("endpoint is a valid url");

        let path_style = if config.path_style {
            rusty_s3::UrlStyle::Path
        } else if endpoint.host_str() == Some("localhost") {
            // Since this was the old behavior before we added AWS_S3_USE_PATH_STYLE,
            // we continue to support it, but complain a bit.
            tracing::warn!("Inferring path-style URLs for localhost for backwards-compatibility. This behavior may change in the future. Set AWS_S3_USE_PATH_STYLE=true to ensure that path-style URLs are used.");
            rusty_s3::UrlStyle::Path
        } else {
            rusty_s3::UrlStyle::VirtualHost
        };

        let bucket = Bucket::new(endpoint, path_style, config.bucket, config.region)
            .expect("Url has a valid scheme and host");
        #[cfg(not(target_arch = "wasm32"))]
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("The S3 HTTP client can be built.");
        #[cfg(target_arch = "wasm32")]
        let client = Client::new();

        S3Store {
            bucket,
            _bucket_checked: OnceLock::new(),
            client,
            credentials,
            prefix: config.bucket_prefix,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    /// Sets how long the store waits on a request before failing it with
    /// [StoreError::ConnectionError], so that a request the endpoint never answers fails
    /// instead of hanging, and whoever made it can retry. Default [DEFAULT_REQUEST_TIMEOUT].
    ///
    /// What it bounds, per request:
    ///
    /// - until the response headers arrive: this long, plus one second per
    ///   [MIN_UPLOAD_BYTES_PER_SECOND] of request body, so a large doc is not cut off for
    ///   being large;
    /// - reading a response body: this long for each chunk, so a download may take any time
    ///   as long as it keeps moving.
    ///
    /// Connecting is bounded separately, by [CONNECT_TIMEOUT]. Not applied on wasm.
    pub fn with_request_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
    }

    async fn store_request<'a, A: S3Action<'a>>(
        &self,
        method: Method,
        action: A,
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        let url = action.sign_with_time(PRESIGNED_URL_DURATION, &OffsetDateTime::now_utc());
        let mut request = self.client.request(method, url);

        let limit = write_timeout(self.request_timeout, body.as_ref().map_or(0, Vec::len));
        request = if let Some(body) = body {
            request.body(body)
        } else {
            request
        };

        let response = within(limit, "waiting for", request.send()).await?;

        let response = match response {
            Ok(response) => response,
            Err(e) => return Err(StoreError::ConnectionError(e.to_string())),
        };

        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::NOT_FOUND => Err(StoreError::DoesNotExist(
                "Received NOT_FOUND from S3-compatible API.".to_string(),
            )),
            StatusCode::FORBIDDEN => Err(StoreError::NotAuthorized(
                "Received FORBIDDEN from S3-compatible API.".to_string(),
            )),
            StatusCode::UNAUTHORIZED => Err(StoreError::NotAuthorized(
                "Received UNAUTHORIZED from S3-compatible API.".to_string(),
            )),
            _ => Err(StoreError::ConnectionError(format!(
                "Received {} from S3-compatible API.",
                response.status()
            ))),
        }
    }

    /// Reads a response body. Each chunk has the request timeout to arrive, so a body that
    /// stops coming fails, and one that keeps coming is read however long it is.
    #[cfg(not(target_arch = "wasm32"))]
    async fn read_response_bytes(&self, mut response: Response) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        loop {
            let chunk = within(self.request_timeout, "reading from", response.chunk())
                .await?
                .map_err(|e| StoreError::ConnectionError(e.to_string()))?;
            match chunk {
                Some(chunk) if body.is_empty() => body = Vec::from(chunk),
                Some(chunk) => body.extend_from_slice(&chunk),
                None => return Ok(body),
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    async fn read_response_bytes(&self, response: Response) -> Result<Vec<u8>> {
        match response.bytes().await {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(e) => Err(StoreError::ConnectionError(e.to_string())),
        }
    }

    pub async fn init(&self) -> Result<()> {
        if self._bucket_checked.get().is_some() {
            return Ok(());
        }

        let action = self.bucket.head_bucket(Some(&self.credentials));
        let result = self.store_request(Method::HEAD, action, None).await;

        match result {
            // Normally a 404 indicates that we are attempting to fetch an object that does
            // not exist, but we have only attempted to retrieve a bucket, so here it
            // indicates that the bucket does not exist.
            Err(StoreError::DoesNotExist(_)) => {
                return Err(StoreError::BucketDoesNotExist(
                    "Bucket does not exist.".to_string(),
                ))
            }
            Err(e) => return Err(e),
            Ok(response) => response,
        };

        self._bucket_checked.set(()).unwrap();
        Ok(())
    }

    fn prefixed_key(&self, key: &str) -> String {
        if let Some(path_prefix) = &self.prefix {
            format!("{}/{}", path_prefix, key)
        } else {
            key.to_string()
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let object_get = self
            .bucket
            .get_object(Some(&self.credentials), &prefixed_key);
        let response = self.store_request(Method::GET, object_get, None).await;

        match response {
            Ok(response) => Ok(Some(self.read_response_bytes(response).await?)),
            Err(StoreError::DoesNotExist(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let action = self
            .bucket
            .put_object(Some(&self.credentials), &prefixed_key);
        self.store_request(Method::PUT, action, Some(value)).await?;
        Ok(())
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let action = self
            .bucket
            .delete_object(Some(&self.credentials), &prefixed_key);
        self.store_request(Method::DELETE, action, None).await?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.init().await?;
        let prefixed_key = self.prefixed_key(key);
        let action = self
            .bucket
            .head_object(Some(&self.credentials), &prefixed_key);
        let response = self.store_request(Method::HEAD, action, None).await;
        match response {
            Ok(_) => Ok(true),
            Err(StoreError::DoesNotExist(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[async_trait]
impl Store for S3Store {
    async fn init(&self) -> Result<()> {
        self.init().await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get(key).await
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.set(key, value).await
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.remove(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.exists(key).await
    }
}

#[cfg(target_arch = "wasm32")]
#[async_trait(?Send)]
impl Store for S3Store {
    async fn init(&self) -> Result<()> {
        self.init().await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get(key).await
    }

    async fn set(&self, key: &str, value: Vec<u8>) -> Result<()> {
        self.set(key, value).await
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.remove(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        self.exists(key).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::time::Instant;

    /// What the fake endpoint does with the object requests it gets. The bucket check (`HEAD`)
    /// is always answered.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// Reads the whole request, then never answers. Reports when the client hangs up.
        NeverAnswer,
        /// Answers a `GET` with `total` bytes, one every `every`, stopping for good after
        /// `stall_after` bytes if that is set.
        Drip {
            total: usize,
            every: Duration,
            stall_after: Option<usize>,
        },
    }

    /// A minimal S3-compatible endpoint on a local port. Returns its URL and a channel that
    /// gets a message each time a client hangs up on a request it was never answered.
    fn endpoint(behaviour: Behaviour) -> (String, mpsc::Receiver<Instant>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (hung_up, hung_up_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let hung_up = hung_up.clone();
                std::thread::spawn(move || serve(stream, behaviour, hung_up));
            }
        });
        (url, hung_up_rx)
    }

    fn serve(stream: TcpStream, behaviour: Behaviour, hung_up: mpsc::Sender<Instant>) {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut stream = stream;
        loop {
            // The request line and headers.
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                return;
            }
            let mut content_length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 {
                    return;
                }
                if header == "\r\n" {
                    break;
                }
                if let Some((name, value)) = header.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap();
                    }
                }
            }
            let mut body = vec![0; content_length];
            if reader.read_exact(&mut body).is_err() {
                return;
            }

            if request_line.starts_with("HEAD") {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
                continue;
            }
            match behaviour {
                Behaviour::NeverAnswer => {
                    // Blocks until the client closes the connection.
                    let mut rest = Vec::new();
                    let _ = reader.read_to_end(&mut rest);
                    let _ = hung_up.send(Instant::now());
                    return;
                }
                Behaviour::Drip {
                    total,
                    every,
                    stall_after,
                } => {
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {total}\r\n\r\n");
                    let _ = stream.write_all(head.as_bytes());
                    for sent in 0..total {
                        if stall_after == Some(sent) {
                            let mut rest = Vec::new();
                            let _ = reader.read_to_end(&mut rest);
                            let _ = hung_up.send(Instant::now());
                            return;
                        }
                        std::thread::sleep(every);
                        if stream.write_all(b"x").is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }

    fn store(endpoint: String, request_timeout: Duration) -> S3Store {
        S3Store::new(S3Config {
            key: "key".to_string(),
            endpoint,
            secret: "secret".to_string(),
            token: None,
            bucket: "bucket".to_string(),
            region: "us-east-1".to_string(),
            bucket_prefix: None,
            path_style: true,
        })
        .with_request_timeout(request_timeout)
    }

    /// The store call under a watchdog, so that a missing timeout fails the test instead of
    /// hanging it.
    async fn watched<T>(call: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), call)
            .await
            .expect("the store call hung")
    }

    fn assert_timed_out<T: std::fmt::Debug>(result: Result<T>) {
        match result {
            Err(StoreError::Timeout { .. }) => {}
            other => panic!("expected a timeout, got {other:?}"),
        }
    }

    // Multi-threaded, here and below: the connection is closed by the HTTP client's own
    // task, which must be able to run while the test waits (blocking) to hear of it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_write_the_endpoint_never_answers_fails_and_is_hung_up_on() {
        let (url, hung_up) = endpoint(Behaviour::NeverAnswer);
        let timeout = Duration::from_millis(300);
        let store = store(url, timeout);

        let started = Instant::now();
        let result = watched(store.set("doc/data.ysweet", vec![7; 4096])).await;
        let failed_at = Instant::now();
        assert_timed_out(result);
        assert!(failed_at - started >= timeout);

        // Failing the write abandons the request for real: its connection is closed, so
        // nothing of it is still on its way when the caller starts the next save.
        let closed_at = hung_up
            .recv_timeout(Duration::from_secs(5))
            .expect("the connection of the timed-out write was left open");
        assert!(closed_at.saturating_duration_since(failed_at) < Duration::from_secs(2));

        // The store is usable afterwards: the next request gets a connection of its own
        // (the endpoint answers every `HEAD`).
        assert!(watched(store.exists("doc/data.ysweet")).await.unwrap());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_read_that_keeps_coming_is_not_cut_off_but_one_that_stalls_is() {
        let timeout = Duration::from_millis(400);

        // 8 bytes, 100 ms apart: twice the timeout in all, but never 400 ms without progress.
        let (url, _hung_up) = endpoint(Behaviour::Drip {
            total: 8,
            every: Duration::from_millis(100),
            stall_after: None,
        });
        let read = watched(store(url, timeout).get("doc/data.ysweet")).await;
        assert_eq!(read.unwrap(), Some(b"xxxxxxxx".to_vec()));

        // The same, but the endpoint stops after 3 bytes.
        let (url, hung_up) = endpoint(Behaviour::Drip {
            total: 8,
            every: Duration::from_millis(100),
            stall_after: Some(3),
        });
        assert_timed_out(watched(store(url, timeout).get("doc/data.ysweet")).await);
        hung_up
            .recv_timeout(Duration::from_secs(5))
            .expect("the connection of the stalled read was left open");
    }

    #[test]
    fn a_large_write_gets_time_in_proportion_to_its_size() {
        let base = Duration::from_secs(60);
        assert_eq!(write_timeout(base, 0), base);
        assert_eq!(write_timeout(base, MIN_UPLOAD_BYTES_PER_SECOND - 1), base);
        assert_eq!(
            write_timeout(base, 200 * MIN_UPLOAD_BYTES_PER_SECOND),
            Duration::from_secs(260)
        );
    }
}

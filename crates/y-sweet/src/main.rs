use anyhow::Context;
use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;
use y_sweet::cli::{print_auth_message, print_server_url};
use y_sweet::stores::filesystem::FileSystemStore;
use y_sweet::update_webhook::UpdateWebhookConfig;
use y_sweet_core::{
    auth::Authenticator,
    store::{
        s3::{S3Config, S3Store},
        Store,
    },
};

const DEFAULT_S3_REGION: &str = "us-east-1";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
struct Opts {
    #[clap(subcommand)]
    subcmd: ServSubcommand,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // Parsed once at startup; boxing the options buys nothing.
enum ServSubcommand {
    Serve {
        #[clap(env = "Y_SWEET_STORE")]
        store: Option<String>,

        #[clap(long, default_value = "8080", env = "PORT")]
        port: u16,
        #[clap(long, env = "Y_SWEET_HOST")]
        host: Option<IpAddr>,
        #[clap(long, default_value = "10", env = "Y_SWEET_CHECKPOINT_FREQ_SECONDS")]
        checkpoint_freq_seconds: u64,

        #[clap(long, env = "Y_SWEET_AUTH")]
        auth: Option<String>,

        #[clap(long, env = "Y_SWEET_URL_PREFIX")]
        url_prefix: Option<Url>,

        #[clap(long)]
        prod: bool,

        #[clap(long, env = "Y_SWEET_MAX_BODY_SIZE")]
        max_body_size: Option<usize>,

        #[clap(long, default_value = "false", env = "Y_SWEET_SKIP_GC")]
        skip_gc: bool,

        /// Mint doc tokens that carry the `userId` and `writer` of the auth request, so that
        /// updates can be attributed. Only turn this on once every server that verifies the
        /// tokens runs a version that understands them. Accepts `true` or `false`, either as
        /// the next argument or after `=`; on its own (as the last argument) it means `true`.
        ///
        /// The next argument is always read as the value, so `--attributed-tokens false` is
        /// off, and `--attributed-tokens /data` is an error rather than "on, store `/data`".
        #[clap(
            long,
            env = "Y_SWEET_ATTRIBUTED_TOKENS",
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            default_value = "false",
            default_missing_value = "true",
            value_parser = parse_switch,
        )]
        attributed_tokens: bool,

        /// URL that receives attributed doc updates. Unset (or empty) disables the webhook.
        #[clap(long, env = "Y_SWEET_UPDATE_WEBHOOK_URL")]
        update_webhook_url: Option<String>,

        /// Secret the update webhook requests are signed with. Required with the URL.
        #[clap(long, env = "Y_SWEET_UPDATE_WEBHOOK_SECRET", hide_env_values = true)]
        update_webhook_secret: Option<String>,

        /// How long updates to one doc are collected into a batch, in milliseconds.
        /// Defaults to 1000.
        #[clap(long, env = "Y_SWEET_UPDATE_WEBHOOK_BATCH_MS")]
        update_webhook_batch_ms: Option<String>,

        /// Upper bound, in bytes, on the updates held in memory awaiting delivery.
        /// Defaults to 268435456.
        #[clap(long, env = "Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES")]
        update_webhook_max_bytes: Option<String>,

        /// How many update webhook requests may be in flight at once, across all docs.
        /// Defaults to 16.
        #[clap(long, env = "Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY")]
        update_webhook_concurrency: Option<String>,

        /// PEM file of extra CA certificates to trust for the update webhook URL, in addition
        /// to the bundled public roots.
        #[clap(long, env = "Y_SWEET_UPDATE_WEBHOOK_CA_FILE")]
        update_webhook_ca_file: Option<String>,
    },

    GenAuth {
        #[clap(long)]
        json: bool,
    },

    /// Convert from a YDoc v1 update format to a .ysweet file.
    /// The YDoc update should be passed in via stdin.
    ConvertFromUpdate {
        /// The store to write the document to.
        #[clap(env = "Y_SWEET_STORE")]
        store: String,

        /// The ID of the document to write.
        doc_id: String,
    },

    Version,

    ServeDoc {
        #[clap(long, default_value = "8080", env = "PORT")]
        port: u16,

        #[clap(long, env = "Y_SWEET_HOST")]
        host: Option<IpAddr>,

        #[clap(long, default_value = "10", env = "Y_SWEET_CHECKPOINT_FREQ_SECONDS")]
        checkpoint_freq_seconds: u64,

        #[clap(long, env = "Y_SWEET_MAX_BODY_SIZE")]
        max_body_size: Option<usize>,

        #[clap(long, default_value = "false", env = "Y_SWEET_SKIP_GC")]
        skip_gc: bool,
    },
}

const S3_ACCESS_KEY_ID: &str = "AWS_ACCESS_KEY_ID";
const S3_SECRET_ACCESS_KEY: &str = "AWS_SECRET_ACCESS_KEY";
const S3_SESSION_TOKEN: &str = "AWS_SESSION_TOKEN";
const S3_REGION: &str = "AWS_REGION";
const S3_ENDPOINT: &str = "AWS_ENDPOINT_URL_S3";
const S3_USE_PATH_STYLE: &str = "AWS_S3_USE_PATH_STYLE";
fn parse_s3_config_from_env_and_args(
    bucket: String,
    prefix: Option<String>,
) -> anyhow::Result<S3Config> {
    let use_path_style = env::var(S3_USE_PATH_STYLE).ok();
    let path_style = if let Some(use_path_style) = use_path_style {
        if use_path_style.to_lowercase() == "true" {
            true
        } else if use_path_style.to_lowercase() == "false" || use_path_style.is_empty() {
            false
        } else {
            anyhow::bail!(
                "If AWS_S3_USE_PATH_STYLE is set, it must be either \"true\" or \"false\""
            )
        }
    } else {
        false
    };

    Ok(S3Config {
        key: env::var(S3_ACCESS_KEY_ID)
            .map_err(|_| anyhow::anyhow!("{} env var not supplied", S3_ACCESS_KEY_ID))?,
        region: env::var(S3_REGION).unwrap_or_else(|_| DEFAULT_S3_REGION.to_string()),
        endpoint: env::var(S3_ENDPOINT).unwrap_or_else(|_| {
            format!(
                "https://s3.dualstack.{}.amazonaws.com",
                env::var(S3_REGION).unwrap_or_else(|_| DEFAULT_S3_REGION.to_string())
            )
        }),
        secret: env::var(S3_SECRET_ACCESS_KEY)
            .map_err(|_| anyhow::anyhow!("{} env var not supplied", S3_SECRET_ACCESS_KEY))?,
        token: env::var(S3_SESSION_TOKEN).ok(),
        bucket,
        bucket_prefix: prefix,
        // If the endpoint is overridden, we assume that the user wants path-style URLs.
        path_style,
    })
}

/// Parses an on/off switch. An empty value is off, so that an environment that passes the
/// variable through unset (`VAR=`) behaves like one that does not pass it at all.
fn parse_switch(value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "false" | "0" | "no" | "off" => Ok(false),
        "true" | "1" | "yes" | "on" => Ok(true),
        other => Err(format!(
            "expected `true` or `false`, got `{other}`. A value after `--attributed-tokens` \
             is read as the switch's value: to turn it on and also pass a store, write \
             `--attributed-tokens=true` or `--attributed-tokens true` before the store."
        )),
    }
}

/// `None` for an option that is unset or set to nothing.
fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

fn parse_number<T: std::str::FromStr>(name: &str, value: &Option<String>) -> Result<Option<T>> {
    non_empty(value)
        .map(|v| {
            v.parse::<T>()
                .map_err(|_| anyhow::anyhow!("{name} must be a non-negative integer"))
        })
        .transpose()
}

/// Builds the update webhook configuration from the `serve` options. `Ok(None)` means the
/// webhook is not configured.
fn update_webhook_config_from_opts(
    url: &Option<String>,
    secret: &Option<String>,
    batch_ms: &Option<String>,
    max_bytes: &Option<String>,
    concurrency: &Option<String>,
    ca_file: &Option<String>,
) -> Result<Option<UpdateWebhookConfig>> {
    let Some(url) = non_empty(url) else {
        if non_empty(secret).is_some() {
            tracing::warn!(
                "Y_SWEET_UPDATE_WEBHOOK_SECRET is set but Y_SWEET_UPDATE_WEBHOOK_URL is not; the update webhook stays disabled."
            );
        }
        return Ok(None);
    };

    // Errors never echo the URL: it may carry credentials.
    let url = Url::parse(url).map_err(|e| anyhow::anyhow!("Invalid update webhook URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        anyhow::bail!("The update webhook URL must be an http or https URL");
    }
    // Whitespace decides only whether a secret was given. The key is the value exactly as
    // configured: trimming it would make the server sign with a different key than the receiver.
    let Some(secret) = secret.as_deref().filter(|s| !s.trim().is_empty()) else {
        anyhow::bail!(
            "Y_SWEET_UPDATE_WEBHOOK_SECRET is required when Y_SWEET_UPDATE_WEBHOOK_URL is set"
        );
    };

    let mut config = UpdateWebhookConfig::new(url, secret.to_string());
    if let Some(batch_ms) = parse_number::<u64>("Y_SWEET_UPDATE_WEBHOOK_BATCH_MS", batch_ms)? {
        config.batch_window = std::time::Duration::from_millis(batch_ms.max(1));
    }
    if let Some(max_bytes) = parse_number::<usize>("Y_SWEET_UPDATE_WEBHOOK_MAX_BYTES", max_bytes)? {
        config.max_held_bytes = max_bytes;
    }
    if let Some(concurrency) =
        parse_number::<usize>("Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY", concurrency)?
    {
        if concurrency == 0 {
            anyhow::bail!("Y_SWEET_UPDATE_WEBHOOK_CONCURRENCY must be at least 1");
        }
        config.max_concurrent_deliveries = concurrency;
    }
    config.ca_file = non_empty(ca_file).map(PathBuf::from);
    Ok(Some(config))
}

/// Resolves when the process is asked to stop: on `SIGINT` (Ctrl+C) or, on Unix, `SIGTERM`
/// (what `docker stop` and ECS send). Returns the signal's name.
///
/// The handlers are installed when this is called, not when the future is first polled, so a
/// signal that arrives between the two is not missed (and does not kill the process outright).
fn shutdown_signal() -> impl std::future::Future<Output = &'static str> {
    #[cfg(unix)]
    let mut handlers = {
        use tokio::signal::unix::{signal, SignalKind};
        let install = |kind: SignalKind, name: &str| {
            signal(kind)
                .map_err(|e| tracing::error!("Failed to install {name} handler: {e}"))
                .ok()
        };
        (
            install(SignalKind::interrupt(), "SIGINT"),
            install(SignalKind::terminate(), "SIGTERM"),
        )
    };

    async move {
        #[cfg(unix)]
        {
            async fn recv(signal: &mut Option<tokio::signal::unix::Signal>) {
                match signal {
                    Some(signal) => {
                        signal.recv().await;
                    }
                    None => std::future::pending().await,
                }
            }
            tokio::select! {
                _ = recv(&mut handlers.0) => "SIGINT",
                _ = recv(&mut handlers.1) => "SIGTERM",
            }
        }

        #[cfg(not(unix))]
        {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C signal handler");
            "SIGINT"
        }
    }
}

fn get_store_from_opts(store_path: &str) -> Result<Box<dyn Store>> {
    if store_path.starts_with("s3://") {
        let url = url::Url::parse(store_path)?;
        let bucket = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid S3 URL"))?
            .to_owned();
        let bucket_prefix = url.path().trim_start_matches('/').to_owned();
        let bucket_prefix = (!bucket_prefix.is_empty()).then_some(bucket_prefix); // "" => None
        let config = parse_s3_config_from_env_and_args(bucket, bucket_prefix)?;
        let store = S3Store::new(config);
        Ok(Box::new(store))
    } else {
        Ok(Box::new(FileSystemStore::new(PathBuf::from(store_path))?))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    match &opts.subcmd {
        ServSubcommand::Serve {
            port,
            host,
            checkpoint_freq_seconds,
            store,
            auth,
            url_prefix,
            prod,
            max_body_size,
            skip_gc,
            attributed_tokens,
            update_webhook_url,
            update_webhook_secret,
            update_webhook_batch_ms,
            update_webhook_max_bytes,
            update_webhook_concurrency,
            update_webhook_ca_file,
        } => {
            // Before anything else, so a stop request during startup is not lost either. Once
            // installed, the handlers replace the default "terminate the process", so the
            // startup below races them: a signal while the store is initialising (an S3 endpoint
            // that never answers, say) abandons startup instead of being held until it is done.
            let mut shutdown = Box::pin(shutdown_signal());

            let startup = async {
                let update_webhook = update_webhook_config_from_opts(
                    update_webhook_url,
                    update_webhook_secret,
                    update_webhook_batch_ms,
                    update_webhook_max_bytes,
                    update_webhook_concurrency,
                    update_webhook_ca_file,
                )?;

                let auth = if let Some(auth) = auth {
                    Some(Authenticator::new(auth)?)
                } else {
                    tracing::warn!("No auth key set. Only use this for local development!");
                    None
                };
                let server_has_no_auth = auth.is_none();

                let addr = SocketAddr::new(
                    host.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                    *port,
                );

                let listener = TcpListener::bind(addr).await?;
                let addr = listener.local_addr()?;

                let store = if let Some(store) = store {
                    let store = get_store_from_opts(store)?;
                    store.init().await?;
                    Some(store)
                } else {
                    tracing::warn!("No store set. Documents will be stored in memory only.");
                    None
                };

                if !prod {
                    print_server_url(auth.as_ref(), url_prefix.as_ref(), addr);
                }

                let token = CancellationToken::new();

                let server = y_sweet::server::Server::new(
                    store,
                    std::time::Duration::from_secs(*checkpoint_freq_seconds),
                    auth,
                    url_prefix.clone(),
                    token.clone(),
                    true,
                    *max_body_size,
                    *skip_gc,
                )
                .await?
                .with_attributed_tokens(*attributed_tokens);

                // One line that says what this process will do about attribution. The host only:
                // the rest of the URL and the secret are never logged.
                tracing::info!(
                    attributed_tokens = *attributed_tokens,
                    update_webhook_enabled = update_webhook.is_some(),
                    update_webhook_host = update_webhook
                        .as_ref()
                        .and_then(|config| config.url.host_str()),
                    update_webhook_batch_ms = update_webhook
                        .as_ref()
                        .map(|config| config.batch_window.as_millis() as u64),
                    update_webhook_max_bytes = update_webhook
                        .as_ref()
                        .map(|config| config.max_held_bytes as u64),
                    update_webhook_concurrency = update_webhook
                        .as_ref()
                        .map(|config| config.max_concurrent_deliveries as u64),
                    update_webhook_ca_file = update_webhook
                        .as_ref()
                        .map(|config| config.ca_file.is_some()),
                    "attributed updates configuration"
                );
                if *attributed_tokens && server_has_no_auth {
                    tracing::warn!(
                    "Attributed tokens are enabled but no auth key is set, so no tokens are minted and every update is unattributed."
                );
                }

                let server = match update_webhook {
                    Some(config) => server.with_update_webhook(config)?,
                    None => server,
                };
                Ok::<_, anyhow::Error>((server, listener, addr, token))
            };

            let (server, listener, addr, token) = tokio::select! {
                started = startup => started?,
                signal = &mut shutdown => {
                    // Nothing is serving yet: no doc is loaded and no update was accepted, so
                    // there is nothing to persist or flush.
                    tracing::info!(signal, "Received {signal} during startup, exiting.");
                    return Ok(());
                }
            };

            let prod = *prod;
            let handle = tokio::spawn(async move {
                server.serve(listener, prod).await.unwrap();
            });

            tracing::info!("Listening on ws://{}", addr);

            let signal = shutdown.await;

            // Cancelling stops the listener and every doc worker; `serve` returns once docs are
            // persisted and the update webhook has made its final flush.
            tracing::info!(signal, "Shutting down.");
            token.cancel();

            handle.await?;
            tracing::info!("Server shut down.");
        }
        ServSubcommand::GenAuth { json } => {
            let auth = Authenticator::gen_key()?;

            if *json {
                let result = json!({
                    "private_key": auth.private_key(),
                    "server_token": auth.server_token(),
                });

                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_auth_message(&auth);
            }
        }
        ServSubcommand::ConvertFromUpdate { store, doc_id } => {
            let store = get_store_from_opts(store)?;
            store.init().await?;

            let mut stdin = tokio::io::stdin();
            let mut buf = Vec::new();
            stdin.read_to_end(&mut buf).await?;

            y_sweet::convert::convert(store, &buf, doc_id).await?;
        }
        ServSubcommand::Version => {
            println!("{}", VERSION);
        }
        ServSubcommand::ServeDoc {
            port,
            host,
            checkpoint_freq_seconds,
            max_body_size,
            skip_gc,
        } => {
            let doc_id = env::var("SESSION_BACKEND_KEY").expect("SESSION_BACKEND_KEY must be set");

            let store = if let Ok(bucket) = env::var("STORAGE_BUCKET") {
                let prefix = if let Ok(prefix) = env::var("STORAGE_PREFIX") {
                    // If the prefix is set, it should contain the document ID as its last '/'-separated part.
                    // We want to pop that, because we will add it back when accessing the doc.
                    let mut parts: Vec<&str> = prefix.split('/').collect();
                    if let Some(last) = parts.pop() {
                        if last != doc_id {
                            anyhow::bail!("STORAGE_PREFIX must end with the document ID. Found: {} Expected: {}", last, doc_id);
                        }

                        let prefix = parts.join("/");

                        Some(prefix)
                    } else {
                        // As far as y-sweet is concerned, `STORAGE_BUCKET` = "" is equivalent to `STORAGE_BUCKET` not being set.
                        None
                    }
                } else {
                    None
                };

                let s3_config = parse_s3_config_from_env_and_args(bucket, prefix)?;
                let store = S3Store::new(s3_config);
                let store: Box<dyn Store> = Box::new(store);
                store.init().await?;
                Some(store)
            } else {
                if env::var("STORAGE_PREFIX").is_ok() {
                    anyhow::bail!("If STORAGE_PREFIX is set, STORAGE_BUCKET must also be set.");
                }

                None
            };

            let cancellation_token = CancellationToken::new();
            let server = y_sweet::server::Server::new(
                store,
                std::time::Duration::from_secs(*checkpoint_freq_seconds),
                None, // No authenticator
                None, // No URL prefix
                cancellation_token.clone(),
                false,
                *max_body_size,
                *skip_gc,
            )
            .await?;

            // Load the one document we're operating with
            server
                .load_doc(&doc_id)
                .await
                .context("Failed to load document")?;

            let addr = SocketAddr::new(
                host.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                *port,
            );

            let listener = TcpListener::bind(addr).await?;
            let addr = listener.local_addr()?;

            tokio::spawn(async move {
                server.serve_doc(listener, false).await.unwrap();
            });

            tracing::info!("Listening on http://{}", addr);

            let signal = shutdown_signal().await;
            tracing::info!(signal, "Received {signal}, shutting down.");

            cancellation_token.cancel();
            tracing::info!("Server shut down.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt(value: &str) -> Option<String> {
        Some(value.to_string())
    }

    #[test]
    fn switch_parsing() {
        for on in ["true", "TRUE", "1", "yes", "on", " true "] {
            assert_eq!(parse_switch(on), Ok(true), "{on}");
        }
        for off in ["", "false", "False", "0", "no", "off"] {
            assert_eq!(parse_switch(off), Ok(false), "{off}");
        }
        assert!(parse_switch("maybe").is_err());
    }

    /// `(attributed_tokens, store)` as parsed from `y-sweet serve <args>`.
    fn parse_serve(args: &[&str]) -> Result<(bool, Option<String>), String> {
        let opts = Opts::try_parse_from([&["y-sweet", "serve"], args].concat())
            .map_err(|e| e.to_string())?;
        match opts.subcmd {
            ServSubcommand::Serve {
                attributed_tokens,
                store,
                ..
            } => Ok((attributed_tokens, store)),
            _ => unreachable!(),
        }
    }

    #[test]
    fn attributed_tokens_flag() {
        // The environment variable is not set under `cargo test`, so these see only the flag.
        let parsed = |args: &[&str]| parse_serve(args).unwrap();
        let data = Some("/data".to_string());
        assert_eq!(parsed(&[]), (false, None));
        assert_eq!(parsed(&["--attributed-tokens"]), (true, None));
        assert_eq!(parsed(&["--attributed-tokens=true"]), (true, None));
        assert_eq!(parsed(&["--attributed-tokens=false"]), (false, None));

        // With a space, the value is the switch's, never the store.
        assert_eq!(parsed(&["--attributed-tokens", "false"]), (false, None));
        assert_eq!(parsed(&["--attributed-tokens", "true"]), (true, None));
        assert_eq!(
            parsed(&["--attributed-tokens", "false", "/data"]),
            (false, data.clone())
        );
        assert_eq!(
            parsed(&["/data", "--attributed-tokens"]),
            (true, data.clone())
        );
        assert_eq!(
            parsed(&["--attributed-tokens=true", "/data"]),
            (true, data.clone())
        );

        // A store path right after a bare flag is an error that says what to write instead,
        // not a silent "on".
        let error = parse_serve(&["--attributed-tokens", "/data"]).unwrap_err();
        assert!(error.contains("--attributed-tokens=true"), "{error}");
    }

    #[test]
    fn webhook_is_off_without_a_url() {
        assert!(
            update_webhook_config_from_opts(&None, &None, &None, &None, &None, &None)
                .unwrap()
                .is_none()
        );
        // Variables passed through empty count as unset.
        assert!(update_webhook_config_from_opts(
            &opt(""),
            &opt(""),
            &opt(""),
            &opt(""),
            &opt(""),
            &opt("")
        )
        .unwrap()
        .is_none());
        // A secret alone does not enable anything.
        assert!(
            update_webhook_config_from_opts(&None, &opt("secret"), &None, &None, &None, &None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn webhook_defaults_and_overrides() {
        let url = opt("https://app.example.com/api/internal/y-sweet/updates");
        let config =
            update_webhook_config_from_opts(&url, &opt("secret"), &None, &opt(""), &None, &None)
                .unwrap()
                .unwrap();
        assert_eq!(config.url.host_str(), Some("app.example.com"));
        assert_eq!(config.secret, "secret");
        assert_eq!(config.batch_window, std::time::Duration::from_millis(1000));
        assert_eq!(config.max_held_bytes, 268_435_456);
        assert_eq!(config.max_concurrent_deliveries, 16);
        assert_eq!(config.ca_file, None);

        let config = update_webhook_config_from_opts(
            &url,
            &opt("secret"),
            &opt("250"),
            &opt("1048576"),
            &opt("4"),
            &opt("/etc/ssl/private-ca.pem"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(config.batch_window, std::time::Duration::from_millis(250));
        assert_eq!(config.max_held_bytes, 1_048_576);
        assert_eq!(config.max_concurrent_deliveries, 4);
        assert_eq!(
            config.ca_file,
            Some(PathBuf::from("/etc/ssl/private-ca.pem"))
        );
    }

    #[test]
    fn webhook_secret_is_used_exactly_as_given() {
        let url = opt("https://app.example.com/hook");
        for secret in [" padded ", "trailing-newline\n", "\tin ner "] {
            let config =
                update_webhook_config_from_opts(&url, &opt(secret), &None, &None, &None, &None)
                    .unwrap()
                    .unwrap();
            assert_eq!(config.secret, secret);
            // And that exact value is the HMAC key.
            assert_eq!(
                y_sweet::update_webhook::sign(config.secret.as_bytes(), 1, b"{}"),
                y_sweet::update_webhook::sign(secret.as_bytes(), 1, b"{}"),
            );
            assert_ne!(
                y_sweet::update_webhook::sign(config.secret.as_bytes(), 1, b"{}"),
                y_sweet::update_webhook::sign(secret.trim().as_bytes(), 1, b"{}"),
            );
        }
    }

    #[test]
    fn webhook_misconfiguration_is_an_error() {
        let url = opt("https://app.example.com/hook");
        fn error(
            url: &Option<String>,
            secret: &Option<String>,
            batch_ms: &Option<String>,
            max_bytes: &Option<String>,
        ) -> String {
            update_webhook_config_from_opts(url, secret, batch_ms, max_bytes, &None, &None)
                .err()
                .expect("expected an error")
                .to_string()
        }

        assert!(error(&url, &None, &None, &None).contains("SECRET is required"));
        assert!(error(&url, &opt(" "), &None, &None).contains("SECRET is required"));
        assert!(error(&url, &opt("s"), &opt("soon"), &None).contains("BATCH_MS"));
        assert!(error(&url, &opt("s"), &None, &opt("-1")).contains("MAX_BYTES"));
        assert!(error(&opt("ftp://example.com/x"), &opt("s"), &None, &None).contains("http"));
        for concurrency in ["0", "-1", "many"] {
            let message = update_webhook_config_from_opts(
                &url,
                &opt("s"),
                &None,
                &None,
                &opt(concurrency),
                &None,
            )
            .err()
            .expect("expected an error")
            .to_string();
            assert!(message.contains("CONCURRENCY"), "{message}");
        }

        // The message does not repeat the URL, which may carry credentials.
        let message = error(
            &opt("https://user:hunter2@exa mple.com"),
            &opt("s"),
            &None,
            &None,
        );
        assert!(!message.contains("hunter2"), "{message}");
    }
}

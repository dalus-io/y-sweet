//! Runs the real `y-sweet serve` binary and stops it with `SIGTERM`, the way `docker stop` and
//! ECS do: once serving, to check that the update webhook's final flush still happens, and
//! during startup, to check that a hung store does not make the stop wait forever.
#![cfg(unix)]

use axum::{body::Bytes, http::StatusCode, routing::post, Router};
use serde_json::Value;
use std::{
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use yrs::{Text, Transact};

#[tokio::test]
async fn sigterm_flushes_the_update_webhook_before_exit() {
    let received: Arc<Mutex<Vec<Value>>> = Arc::default();
    let receiver = {
        let received = received.clone();
        Router::new().route(
            "/updates",
            post(move |body: Bytes| {
                let received = received.clone();
                async move {
                    received
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&body).unwrap());
                    StatusCode::NO_CONTENT
                }
            }),
        )
    };
    let receiver_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_url = format!("http://{}/updates", receiver_listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(receiver_listener, receiver).await.unwrap() });

    // A free port for the server. Another process could take it before the server binds it;
    // unlikely enough for a test.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let mut child = Command::new(env!("CARGO_BIN_EXE_y-sweet"))
        .args([
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--prod",
        ])
        .env_clear()
        .env("Y_SWEET_UPDATE_WEBHOOK_URL", &receiver_url)
        .env("Y_SWEET_UPDATE_WEBHOOK_SECRET", "secret")
        // Only the shutdown flush can close the batch.
        .env("Y_SWEET_UPDATE_WEBHOOK_BATCH_MS", "3600000")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(response) = http.get(format!("{base}/ready")).send().await {
            if response.status().is_success() {
                break;
            }
        }
        assert!(Instant::now() < deadline, "server never became ready");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let update = {
        let doc = yrs::Doc::with_client_id(1);
        let text = doc.get_or_insert_text("t");
        let mut txn = doc.transact_mut();
        text.push(&mut txn, "hello");
        txn.encode_update_v1()
    };
    let response = http
        .post(format!("{base}/d/doc1/update"))
        .body(update)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(received.lock().unwrap().is_empty());

    // The shell's builtin `kill`, so no `kill` binary needs to be installed.
    let killed = Command::new("sh")
        .args(["-c", &format!("kill -TERM {}", child.id())])
        .status()
        .unwrap();
    assert!(killed.success());

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("server did not exit after SIGTERM");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // A clean exit, not death by the signal.
    assert!(status.success(), "{status:?}");

    let received = received.lock().unwrap();
    assert_eq!(received.len(), 1, "the pending batch was not flushed");
    assert_eq!(received[0]["doc_id"], "doc1");
    assert_eq!(received[0]["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn sigterm_during_a_hung_store_init_exits_promptly() {
    use tokio::io::AsyncReadExt;

    // An S3 endpoint that accepts the connection, reads the request and never answers. The S3
    // client has no timeout, so without the fix startup waits here for good and swallows the
    // signal.
    let s3 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let s3_url = format!("http://{}", s3.local_addr().unwrap());
    let (request_seen_tx, request_seen) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut socket, _) = s3.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await.unwrap();
        assert!(n > 0);
        request_seen_tx.send(()).unwrap();
        // Hold the connection open, unanswered.
        tokio::time::sleep(Duration::from_secs(3600)).await;
        drop(socket);
    });

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_y-sweet"))
        .args([
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--prod",
            "s3://bucket",
        ])
        .env_clear()
        .env("AWS_ACCESS_KEY_ID", "test")
        .env("AWS_SECRET_ACCESS_KEY", "test")
        .env("AWS_REGION", "us-east-1")
        .env("AWS_ENDPOINT_URL_S3", &s3_url)
        .env("AWS_S3_USE_PATH_STYLE", "true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Startup is now inside the store's init, waiting on the endpoint.
    tokio::time::timeout(Duration::from_secs(30), request_seen)
        .await
        .expect("the server never reached the store")
        .unwrap();

    let killed = Command::new("sh")
        .args(["-c", &format!("kill -TERM {}", child.id())])
        .status()
        .unwrap();
    assert!(killed.success());

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            panic!("SIGTERM during startup was ignored");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(status.success(), "{status:?}");
}

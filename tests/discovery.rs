mod support;
use std::{path::PathBuf, time::Duration};
use tcp_bench_rs::{
    discovery::{DiscoveryConfig, remote},
    http::Client,
    scheduler::Cancellation,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn cache_path() -> PathBuf {
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    std::env::temp_dir().join(format!(
        "tcp-bench-cache-test-{:x}.json",
        u64::from_ne_bytes(nonce)
    ))
}
#[tokio::test]
async fn node_cache_has_expiry_and_exact_url_scope_identity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/nodes?tenant=test",
        listener.local_addr().unwrap()
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            request.push(stream.read_u8().await.unwrap());
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .starts_with("GET /nodes?tenant=test&format=tsv&scope=cdn HTTP/1.1\r\n")
        );
        let body = "cdn\t4\tlab\tExample\tfixed.test\t127.0.0.1\t8443\t/data\n";
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let cache = cache_path();
    let client = Client::default();
    let cancel = Cancellation::default();
    let config = |scope, ttl| DiscoveryConfig {
        url: &url,
        scope,
        cache: Some(&cache),
        expiry: Duration::from_secs(ttl),
        timeout: Duration::from_secs(1),
        retries: 0,
        allow_http: true,
    };
    let first = remote(config("cdn", 300), &client, &cancel).await.unwrap();
    assert_eq!(first[0].primary.port, 8443);
    server.await.unwrap();
    assert!(remote(config("cdn", 300), &client, &cancel).await.is_ok()); // server is gone
    assert!(remote(config("cdn", 0), &client, &cancel).await.is_err());
    assert!(remote(config("v6", 300), &client, &cancel).await.is_err());
    std::fs::remove_file(cache).unwrap();
}

#[tokio::test]
async fn malformed_data_is_not_cached_or_retried() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        support::request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbad")
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    });
    let cache = cache_path();
    let result = remote(
        DiscoveryConfig {
            url: &url,
            scope: "cdn",
            cache: Some(&cache),
            expiry: Duration::from_secs(300),
            timeout: Duration::from_secs(1),
            retries: 3,
            allow_http: true,
        },
        &Client::default(),
        &Cancellation::default(),
    )
    .await;
    assert!(matches!(result, Err(tcp_bench_rs::Error::Nodes(_))));
    assert!(!cache.exists());
    server.await.unwrap();
}

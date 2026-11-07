mod support;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Duration,
};
use tcp_bench_rs::{
    enrichment::{
        Metadata,
        remote::{self, Config, Provider, Status},
    },
    http::Client,
    scheduler::Cancellation,
};
use tokio::{io::AsyncWriteExt, net::TcpListener};

fn ips(values: &[&str]) -> BTreeSet<IpAddr> {
    values.iter().map(|ip| ip.parse().unwrap()).collect()
}
fn config(base_url: String) -> Config {
    Config {
        provider: Provider::Json,
        base_url,
        token: None,
        cache: None,
        expiry: Duration::from_secs(3600),
        timeout: Duration::from_secs(1),
        requests_per_second: 10,
        max_requests: 128,
        allow_http: true,
        include_private: false,
    }
}
async fn server(status: u16, body: String) -> (Config, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(format!(
        "http://{}/metadata",
        listener.local_addr().unwrap()
    ));
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = String::from_utf8(support::request(&mut socket).await).unwrap();
        socket
            .write_all(
                format!(
                    "HTTP/1.1 {status} Result\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        request
    });
    (config, task)
}

#[tokio::test]
async fn local_precedence_private_filter_request_budget_and_cache_identity() {
    let (mut config, server) = server(
        200,
        r#"{"ip":"1.1.1.1","asn":64500,"organization":"Fixture"}"#.into(),
    )
    .await;
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "tcp-bench-enrich-{:x}.json",
        u64::from_ne_bytes(nonce)
    ));
    config.cache = Some(path.clone());
    config.max_requests = 1;
    let candidates = ips(&["1.1.1.1", "8.8.8.8", "9.9.9.9", "127.0.0.1"]);
    let local = BTreeMap::from([(
        "9.9.9.9".parse().unwrap(),
        Metadata {
            asn: Some(64501),
            organization: None,
            location: None,
        },
    )]);
    let client = Client::default();
    let first = remote::enrich(
        &config,
        &client,
        &candidates,
        &local,
        &Cancellation::default(),
    )
    .await
    .unwrap();
    let ip: IpAddr = "1.1.1.1".parse().unwrap();
    assert_eq!(first.lookups[&ip].status, Status::Remote);
    assert_eq!(
        first.lookups[&"8.8.8.8".parse().unwrap()].status,
        Status::RequestLimit
    );
    assert_eq!(
        first.lookups[&"9.9.9.9".parse().unwrap()].status,
        Status::Local
    );
    assert_eq!(
        first.lookups[&"127.0.0.1".parse().unwrap()].status,
        Status::SkippedNonpublic
    );
    assert!(first.cache_error.is_none());
    let request = server.await.unwrap();
    assert!(request.starts_with("GET /metadata/1.1.1.1 HTTP/1.1\r\n"));
    assert!(!request.contains("Authorization:"));
    let cancelled = Cancellation::default();
    cancelled.cancel();
    let hit = remote::enrich(&config, &client, &ips(&["1.1.1.1"]), &local, &cancelled)
        .await
        .unwrap();
    assert_eq!(hit.lookups[&ip].status, Status::Cache);
    assert_eq!(hit.metadata[&ip].asn, Some(64500));
    // Provider identity mismatch must not use cached metadata.
    config.base_url.push_str("/other");
    let miss = remote::enrich(&config, &client, &ips(&["1.1.1.1"]), &local, &cancelled)
        .await
        .unwrap();
    assert_eq!(miss.lookups[&ip].status, Status::Cancelled);
    assert!(miss.metadata.is_empty());
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn expiry_future_dates_and_invalid_cache_records_are_not_used() {
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "tcp-bench-expiry-{:x}.json",
        u64::from_ne_bytes(nonce)
    ));
    let mut config = config("http://127.0.0.1:1".into());
    config.cache = Some(path.clone());
    let cancel = Cancellation::default();
    cancel.cancel();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (fetched, asn) in [(now - 3601, 64500), (now + 3600, 64500), (now, 0)] {
        let cache = serde_json::json!({"version":1,"provider":"json","base_url":config.base_url,
            "entries":{"1.1.1.1":{"fetched":fetched,"metadata":{"asn":asn}}}});
        std::fs::write(&path, serde_json::to_vec(&cache).unwrap()).unwrap();
        let result = remote::enrich(
            &config,
            &Client::default(),
            &ips(&["1.1.1.1"]),
            &BTreeMap::new(),
            &cancel,
        )
        .await
        .unwrap();
        assert!(result.metadata.is_empty());
        assert_eq!(
            result.lookups[&"1.1.1.1".parse().unwrap()].status,
            Status::Cancelled
        );
    }
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn authorization_and_rate_limit_stop_further_requests() {
    for (code, status) in [
        (401, Status::Unauthorized),
        (403, Status::Unauthorized),
        (429, Status::RateLimited),
    ] {
        let (config, server) = server(code, "do not put this response in a report".into()).await;
        let result = remote::enrich(
            &config,
            &Client::default(),
            &ips(&["1.1.1.1", "8.8.8.8"]),
            &BTreeMap::new(),
            &Cancellation::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.lookups[&"1.1.1.1".parse().unwrap()].status, status);
        assert_eq!(
            result.lookups[&"8.8.8.8".parse().unwrap()].status,
            Status::ProviderUnavailable
        );
        assert!(result.lookups.values().all(|v| v.error.is_none()));
        server.await.unwrap();
    }
}

#[tokio::test]
async fn malformed_wrong_ip_oversize_and_missing_responses_have_statuses() {
    for (code, body, status) in [
        (200, "not JSON".into(), Status::Error),
        (200, r#"{"ip":"8.8.8.8","asn":64500}"#.into(), Status::Error),
        (200, "x".repeat(16385), Status::Error),
        (404, String::new(), Status::NotFound),
    ] {
        let (config, server) = server(code, body).await;
        let result = remote::enrich(
            &config,
            &Client::default(),
            &ips(&["1.1.1.1"]),
            &BTreeMap::new(),
            &Cancellation::default(),
        )
        .await
        .unwrap();
        assert!(result.metadata.is_empty());
        assert_eq!(result.lookups[&"1.1.1.1".parse().unwrap()].status, status);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn stalled_provider_timeout_and_cancellation_are_bounded() {
    for cancelled in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = config(format!("http://{}", listener.local_addr().unwrap()));
        config.timeout = Duration::from_millis(200);
        let cancel = Cancellation::default();
        let trigger = cancel.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            support::request(&mut socket).await;
            if cancelled {
                trigger.cancel();
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let started = std::time::Instant::now();
        let result = remote::enrich(
            &config,
            &Client::default(),
            &ips(&["1.1.1.1"]),
            &BTreeMap::new(),
            &cancel,
        )
        .await
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            result.lookups[&"1.1.1.1".parse().unwrap()].status,
            if cancelled {
                Status::Cancelled
            } else {
                Status::Timeout
            }
        );
        server.abort();
    }
}

#[test]
fn provider_configuration_never_accepts_insecure_credentials() {
    let mut config = config("http://127.0.0.1:1".into());
    config.token = Some("test-token".into());
    assert!(config.validate().is_err());
    config.base_url = "https://example.test/".into();
    assert!(config.validate().is_ok());
    config.token = Some("token\r\nHeader: injected".into());
    assert!(config.validate().is_err());
    config.token = None;
    config.base_url.push_str("?token=secret");
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn cli_enrichment_is_opt_in_and_runs_after_transfer() {
    for enabled in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = String::from_utf8(support::request(&mut socket).await).unwrap();
            assert!(request.starts_with("GET /data HTTP/1.1"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
                .await
                .unwrap();
            drop(socket);
            if enabled {
                let (mut socket, _) = listener.accept().await.unwrap();
                let request = String::from_utf8(support::request(&mut socket).await).unwrap();
                assert!(request.starts_with("GET /metadata/127.0.0.1 HTTP/1.1"));
                let body = r#"{"ip":"127.0.0.1","asn":64500,"location":"Test lab"}"#;
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let output = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_tcp-bench-rs"));
            command.args([
                "--target",
                "127.0.0.1",
                "--only-speedtest",
                "--allow-http",
                "--max-bytes",
                "3",
                "--budget",
                "5",
                "--url",
                &format!("http://{address}/data"),
            ]);
            if enabled {
                command.args([
                    "--enrich-provider",
                    "json",
                    "--enrich-url",
                    &format!("http://{address}/metadata"),
                    "--enrich-private",
                ]);
            }
            command.output().unwrap()
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["nodes"][0]["throughput"]["data"]["body_bytes"], 3);
        if enabled {
            assert_eq!(report["enrichment"]["127.0.0.1"]["asn"], 64500);
            assert_eq!(
                report["enrichment_lookups"]["127.0.0.1"]["status"],
                "remote"
            );
        } else {
            assert!(report["enrichment_lookups"].as_object().unwrap().is_empty());
        }
        server.await.unwrap();
    }
}

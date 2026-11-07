mod support;
use std::{collections::BTreeMap, io::Read, time::Duration};
use tcp_bench_rs::{
    Error,
    http::Client,
    report::{Measurement, Report},
    scheduler::Cancellation,
    upload::{self, Config},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn fixture() -> Report {
    serde_json::from_value(serde_json::json!({
        "schema_version":1,"application_version":"fixture","started_unix_seconds":0,
        "elapsed_seconds":1.5,"cancelled":false,"enrichment":{"192.0.2.10":{"asn":64500,"organization":"Fixture ASN","location":null}},
        "nodes":[{
            "node":{"kind":"cdn","family":4,"province":"Lab","isp":"Example, Inc.","primary":{"host":"fixed.test","ip":"192.0.2.10","port":443,"target":"/"},"backup":null},
            "quality":{"status":"complete","data":{"source":"192.0.2.1","packet_size":40,"completion":"complete","summary":{"attempted":2,"sent":2,"received":1,"timeouts":1,"send_errors":0,"cancelled":0,"icmp_errors":0,"unanswered_percent":50.0,"min_rtt_ms":1.25,"mean_rtt_ms":1.25,"max_rtt_ms":1.25,"population_stddev_ms":0.0},"probes":[]}},
            "traces":[{"status":"complete","data":{"direction":"outward","protocol":"tcp","source":"192.0.2.1","packet_size":40,"initial_port":443,"reached":true,"completion":"complete","hops":[]}}],
            "throughput":{"status":"not_requested"}
        }]
    })).unwrap()
}
fn config(url: String) -> Config {
    Config {
        url,
        timeout: Duration::from_secs(3),
        allow_http: true,
        public_ipv4: Some("192.0.2.1".parse().unwrap()),
        public_ipv6: None,
        debug: false,
    }
}
async fn read_request(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let headers = String::from_utf8(support::request(socket).await).unwrap();
    let len = headers
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(len <= 32 * 1024 * 1024);
    let mut body = vec![0; len];
    socket.read_exact(&mut body).await.unwrap();
    (headers, body)
}
async fn reply(socket: &mut tokio::net::TcpStream, code: u16, body: &str) {
    socket
        .write_all(
            format!(
                "HTTP/1.1 {code} Result\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
}
fn archive(bytes: &[u8]) -> BTreeMap<String, serde_json::Value> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut tar = tar::Archive::new(decoder);
    tar.entries()
        .unwrap()
        .map(|entry| {
            let mut entry = entry.unwrap();
            assert!(entry.header().entry_type().is_file());
            let path = entry.path().unwrap().to_str().unwrap().to_owned();
            assert!(!path.contains('/') && !path.contains(".."));
            let mut body = Vec::new();
            entry.read_to_end(&mut body).unwrap();
            (path, serde_json::from_slice(&body).unwrap())
        })
        .collect()
}

#[test]
fn csv_preserves_wire_columns_and_separates_large_packets() {
    let mut report = fixture();
    report.nodes[0].large_quality = report.nodes[0].quality.clone();
    let text = String::from_utf8(upload::csv::encode(&report).unwrap()).unwrap();
    assert!(text.starts_with('\u{feff}'));
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0].split(',').count(), 18);
    assert_eq!(
        lines[1],
        "三网,IPv4,Lab,\"Example, Inc.\",fixed.test,192.0.2.10,OK,2,1,50.000,1.250,dst AS64500,,,,,,"
    );
    assert!(lines[2].starts_with("IPv4大包,IPv4,"));
    if let Measurement::Complete { data } = &mut report.nodes[0].quality {
        data.completion = "cancelled".into();
        data.summary.unanswered_percent = None;
    }
    let text = String::from_utf8(upload::csv::encode(&report).unwrap()).unwrap();
    assert!(text.contains(",SKIP,2,1,,1.250,"));
    report.nodes[0].node.province = "bad\r\nline".into();
    assert!(upload::csv::encode(&report).is_err());
}

fn labels(report: &Report) -> Vec<String> {
    String::from_utf8(upload::csv::encode(report).unwrap())
        .unwrap()
        .lines()
        .skip(1)
        .map(|line| line.rsplit(',').nth(6).unwrap().to_owned())
        .collect()
}

#[test]
fn upload_labels_use_only_matching_observations_and_keep_large_packets_distinct() {
    use tcp_bench_rs::{
        enrichment::Metadata,
        packet::Protocol,
        probe::{ProbeOutcome, ProbeStatus},
        traceroute::Hop,
    };
    let mut report = fixture();
    report.nodes[0].large_quality = report.nodes[0].quality.clone();
    if let Measurement::Complete { data } = &mut report.nodes[0].large_quality {
        data.packet_size = 1200;
    }
    for (ip, asn) in [
        ("192.0.2.2", 64501),
        ("192.0.2.3", 64502),
        ("192.0.2.4", 64503),
    ] {
        report.enrichment.insert(
            ip.parse().unwrap(),
            Metadata {
                asn: Some(asn),
                organization: None,
                location: None,
            },
        );
    }
    if let Measurement::Complete { data } = &mut report.nodes[0].traces[0] {
        data.reached = false;
        data.hops = [
            (2, "192.0.2.2", ProbeStatus::Reply),
            (7, "192.0.2.3", ProbeStatus::Reply),
            (9, "192.0.2.4", ProbeStatus::Timeout),
        ]
        .into_iter()
        .map(|(ttl, ip, status)| Hop {
            hop_limit: ttl,
            probes: vec![ProbeOutcome {
                attempt: 1,
                status,
                responder: Some(ip.parse().unwrap()),
                rtt_ms: Some(1.0),
                reply: None,
                error: None,
            }],
        })
        .collect();
    }
    assert_eq!(labels(&report), ["out AS64502", "dst AS64500"]);
    // UDP may follow a different path; it must not substitute for TCP SYN traces.
    let mut udp = report.nodes[0].traces[0].clone();
    if let Measurement::Complete { data } = &mut udp {
        data.protocol = Protocol::Udp;
        data.packet_size = 28;
    }
    report.nodes[0].traces.insert(0, udp);
    assert_eq!(labels(&report), ["out AS64502", "dst AS64500"]);
    if let Measurement::Complete { data } = &mut report.nodes[0].traces[1] {
        data.initial_port = 80;
    }
    assert_eq!(labels(&report), ["dst AS64500", "dst AS64500"]);
    if let Measurement::Complete { data } = &mut report.nodes[0].traces[1] {
        data.initial_port = 443;
        data.direction = "reverse".into();
    }
    assert_eq!(labels(&report), ["dst AS64500", "dst AS64500"]);
    // Route-only UDP observations are valid, and retain SKIP for absent quality.
    report.nodes[0].quality = Measurement::NotRequested;
    report.nodes[0].large_quality = Measurement::NotRequested;
    assert_eq!(labels(&report), ["out AS64502"]);
}

#[test]
fn unavailable_asn_reasons_are_not_renderer_failure_sentinels() {
    use tcp_bench_rs::enrichment::remote::{Lookup, Status};
    let mut report = fixture();
    report.enrichment.clear();
    assert_eq!(labels(&report), ["ASN unavailable"]);
    for (status, label) in [
        (Status::Timeout, "ASN timeout"),
        (Status::RateLimited, "ASN limited"),
        (Status::RequestLimit, "ASN limited"),
        (Status::Unauthorized, "ASN denied"),
        (Status::Cancelled, "ASN cancelled"),
        (Status::NotFound, "ASN unknown"),
        (Status::Error, "ASN error"),
        (Status::SkippedNonpublic, "N/A"),
        (Status::ProviderUnavailable, "ASN unavailable"),
        (Status::Remote, "ASN unavailable"),
    ] {
        report.enrichment_lookups.insert(
            "192.0.2.10".parse().unwrap(),
            Lookup {
                status,
                provider: Some("json".into()),
                attribution: None,
                fetched_unix_seconds: None,
                error: None,
            },
        );
        assert_eq!(labels(&report), [label]);
    }
    report.nodes[0].quality = Measurement::Skipped {
        message: "No usable local route".into(),
    };
    assert_eq!(labels(&report), ["ASN unavailable"]);
    let text = String::from_utf8(upload::csv::encode(&report).unwrap()).unwrap();
    assert!(text.contains(",SKIP,,,,,ASN unavailable,"));
}

#[test]
fn destination_asn_is_not_a_route_claim_and_handles_ipv6_and_multiple_origins() {
    use tcp_bench_rs::enrichment::Metadata;
    let mut report = fixture();
    report.nodes[0].node.family = 6;
    report.nodes[0].node.primary.ip = "2001:db8::10".parse().unwrap();
    report.enrichment.insert(
        "2001:db8::10".parse().unwrap(),
        Metadata {
            asn: Some(u32::MAX),
            organization: None,
            location: None,
        },
    );
    assert_eq!(labels(&report), ["dst AS4294967295"]);
    report
        .enrichment
        .get_mut(&"2001:db8::10".parse().unwrap())
        .unwrap()
        .asn = None;
    report
        .enrichment
        .get_mut(&"2001:db8::10".parse().unwrap())
        .unwrap()
        .organization = Some("Multiple BGP origins: AS64500, AS64501".into());
    assert_eq!(labels(&report), ["ASN unavailable"]);
    report
        .enrichment
        .get_mut(&"2001:db8::10".parse().unwrap())
        .unwrap()
        .asn = Some(0);
    assert_eq!(labels(&report), ["ASN unavailable"]);
}

#[test]
fn iperf_csv_converts_units_and_keeps_sender_counters_directional() {
    use tcp_bench_rs::{
        iperf3::{Direction, ServerResult, Transfer},
        report::IperfMeasurement,
        tcp_stats,
    };
    let mut report = fixture();
    report.nodes[0].node.isp = "Example".into();
    report.nodes[0].quality = Measurement::NotRequested;
    report.nodes[0].traces.clear();
    for direction in [Direction::Upload, Direction::Download] {
        report.nodes[0].iperf3.push(IperfMeasurement {
            direction,
            measurement: Measurement::Complete {
                data: Transfer {
                    protocol: "iperf3_tcp".into(),
                    direction,
                    peer: "192.0.2.10:5201".parse().unwrap(),
                    stream_bytes: 1_000_000,
                    stream_seconds: 1.0,
                    bits_per_second: Some(8_000_000.0),
                    requested_bitrate: 10_000_000,
                    stop_reason: "byte_limit".into(),
                    setup_ms: 2.0,
                    tcp_before: tcp_stats::decode_linux(&[]),
                    tcp_after: tcp_stats::decode_linux(&[]),
                    local_sender_retransmissions_delta: Some(2),
                    server: Some(ServerResult {
                        role: "sender".into(),
                        bytes: 1_000_000,
                        seconds: Some(1.0),
                        bits_per_second: Some(8_000_000.0),
                        sender_retransmissions: Some(7),
                    }),
                    result_exchange: "complete".into(),
                    error: None,
                },
            },
        });
    }
    let text = String::from_utf8(upload::csv::encode(&report).unwrap()).unwrap();
    let rows = text
        .lines()
        .skip(1)
        .map(|line| line.split(',').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(&rows[0][7..10], &["8.000", "2", "-"]);
    assert_eq!(&rows[1][7..10], &["-", "7", "8.000"]);
    assert_eq!(&rows[0][16..18], &["2", "upload"]);
    assert_eq!(&rows[1][16..18], &["7", "download"]);
    report.nodes[0].iperf3[0].measurement = Measurement::Cancelled;
    if let Measurement::Complete { data } = &mut report.nodes[0].iperf3[1].measurement {
        data.server = None;
    }
    let text = String::from_utf8(upload::csv::encode(&report).unwrap()).unwrap();
    let rows = text
        .lines()
        .skip(1)
        .map(|line| line.split(',').collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(rows[0][6], "SKIP");
    assert_eq!(rows[1][8], "-");
    assert_eq!(rows[1][16], "");
}

#[tokio::test]
async fn csv_post_and_native_trace_and_debug_archives_follow_wire_contract() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = config(format!(
        "http://{}/custom/generate",
        listener.local_addr().unwrap()
    ));
    config.debug = true;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let (headers, body) = read_request(&mut socket).await;
        assert!(headers.starts_with("POST /custom/generate HTTP/1.1\r\n"));
        assert!(headers.contains("Content-Type: text/csv; charset=utf-8\r\n"));
        assert!(headers.contains("X-Report-Time: 1970-01-01 08:00:00 CST\r\n"));
        assert!(headers.contains("X-TcpQuality-Public-IPv4: 192.0.2.1\r\n"));
        assert!(
            headers.contains("X-TcpQuality-Rank-Disabled-Reason: tcp-bench-rs-report-only\r\n")
        );
        assert!(!headers.contains("Rank-Token:"));
        assert_eq!(body, upload::csv::encode(&fixture()).unwrap());
        reply(&mut socket,200,r#"{"id":"fixture-17","url":"https://reports.example/r/fixture-17.svg","todayUses":3,"totalUses":9,"rankUpdated":false}"#).await;
        for (path, file) in [
            (
                "route-traces/fixture-17.ipv4.tar.gz",
                "summary_route4_trace_0.json",
            ),
            ("probe-debug/fixture-17.tar.gz", "report.json"),
        ] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (headers, body) = read_request(&mut socket).await;
            assert!(headers.starts_with(&format!("POST /custom/{path} HTTP/1.1\r\n")));
            assert!(headers.contains("Content-Type: application/gzip\r\n"));
            let files = archive(&body);
            assert!(files.contains_key(file));
            if file.ends_with("_0.json") {
                assert_eq!(files[file]["direction"], "outward");
                assert_eq!(files[file]["enrichment"]["192.0.2.10"]["asn"], 64500);
            }
            reply(&mut socket, 200, "{}").await;
        }
    });
    let receipt = upload::upload(
        &config,
        &Client::default(),
        &fixture(),
        &Cancellation::default(),
    )
    .await
    .unwrap();
    assert_eq!(receipt.id, "fixture-17");
    assert_eq!(receipt.today_uses, Some(3));
    assert_eq!(receipt.attachments.len(), 2);
    assert!(
        receipt
            .attachments
            .iter()
            .all(|a| matches!(a.status, Measurement::Complete { .. }))
    );
    server.await.unwrap();
}

#[tokio::test]
async fn attachment_failure_preserves_report_url() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(format!(
        "http://{}/generate",
        listener.local_addr().unwrap()
    ));
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        reply(
            &mut socket,
            200,
            r#"{"id":"saved","url":"https://reports.example/saved.svg"}"#,
        )
        .await;
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        reply(&mut socket, 503, "unavailable").await;
    });
    let receipt = upload::upload(
        &config,
        &Client::default(),
        &fixture(),
        &Cancellation::default(),
    )
    .await
    .unwrap();
    assert_eq!(receipt.url, "https://reports.example/saved.svg");
    assert!(receipt.attachments[0].status.failed());
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_redirect_oversized_and_failed_responses_are_not_retried() {
    for (code, body) in [
        (200, "{}".into()),
        (
            200,
            r#"{"id":"../escape","url":"https://example.test/r"}"#.into(),
        ),
        (200, r#"{"id":"x","url":"javascript:bad"}"#.into()),
        (200, "x".repeat(65537)),
        (302, String::new()),
        (500, String::new()),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = config(format!(
            "http://{}/generate",
            listener.local_addr().unwrap()
        ));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request(&mut socket).await;
            reply(&mut socket, code, &body).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
        });
        assert!(
            upload::upload(
                &config,
                &Client::default(),
                &fixture(),
                &Cancellation::default()
            )
            .await
            .is_err()
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn header_injection_and_plaintext_are_rejected_before_connection() {
    let client = Client::default();
    for headers in [
        vec![("X-Test", "ok\r\nInjected: yes")],
        vec![("Content-Length", "0")],
        vec![("Bad Name", "value")],
    ] {
        assert!(matches!(
            client
                .post(
                    "http://127.0.0.1:1/generate",
                    &headers,
                    b"x",
                    Duration::from_secs(1)
                )
                .await,
            Err(Error::Config(_))
        ));
    }
    let mut config = config("http://127.0.0.1:1/generate".into());
    config.allow_http = false;
    assert!(matches!(
        upload::upload(&config, &client, &fixture(), &Cancellation::default()).await,
        Err(Error::Config(_))
    ));
}

#[tokio::test]
async fn upload_cancellation_stops_a_stalled_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(format!(
        "http://{}/generate",
        listener.local_addr().unwrap()
    ));
    let cancel = Cancellation::default();
    let signal = cancel.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        signal.cancel();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
    });
    assert!(matches!(
        upload::upload(&config, &Client::default(), &fixture(), &cancel).await,
        Err(Error::Cancelled)
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn upload_total_deadline_bounds_response_body() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = config(format!(
        "http://{}/generate",
        listener.local_addr().unwrap()
    ));
    config.timeout = Duration::from_millis(100);
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{")
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
    });
    assert!(matches!(
        upload::upload(
            &config,
            &Client::default(),
            &fixture(),
            &Cancellation::default()
        )
        .await,
        Err(Error::Timeout(_))
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn cli_upload_is_opt_in_and_failures_preserve_local_measurements() {
    for outcome in [None, Some(200), Some(503)] {
        let download = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let download_url = format!("http://{}/data", download.local_addr().unwrap());
        let download_server = tokio::spawn(async move {
            let (mut socket, _) = download.accept().await.unwrap();
            support::request(&mut socket).await;
            reply(&mut socket, 200, "abcd").await;
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let report_url = format!("http://{}/generate", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            if let Some(code) = outcome {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (_, csv) = read_request(&mut socket).await;
                assert!(String::from_utf8(csv).unwrap().contains("三网单线程速度"));
                reply(
                    &mut socket,
                    code,
                    r#"{"id":"cli","url":"https://reports.example/cli.svg"}"#,
                )
                .await;
                if code == 200 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let (headers, bytes) = read_request(&mut socket).await;
                    assert!(headers.starts_with("POST /speedtest-debug/cli.tar.gz"));
                    assert_eq!(
                        archive(&bytes)["transfer_0.json"]["throughput"]["data"]["body_bytes"],
                        4
                    );
                    reply(&mut socket, 200, "{}").await;
                }
            } else {
                assert!(
                    tokio::time::timeout(Duration::from_millis(250), listener.accept())
                        .await
                        .is_err()
                );
            }
        });
        let output = tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_tcp-bench-rs"));
            command.args([
                "--target",
                "127.0.0.1",
                "--only-speedtest",
                "--allow-http",
                "--url",
                &download_url,
                "--max-bytes",
                "4",
                "--duration",
                "1",
                "--budget",
                "5",
            ]);
            // Merely setting the reference environment variable must never opt in.
            command.env("TCPQUALITY_REPORT_API", report_url);
            if outcome.is_some() {
                command.arg("--upload-report");
            }
            command.output().unwrap()
        })
        .await
        .unwrap();
        assert_eq!(
            output.status.code(),
            Some(if outcome == Some(503) { 1 } else { 0 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["nodes"][0]["throughput"]["data"]["body_bytes"], 4);
        assert_eq!(
            json["upload"]["status"],
            match outcome {
                None => "not_requested",
                Some(200) => "complete",
                _ => "error",
            }
        );
        if outcome == Some(200) {
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("Report URL: https://reports.example/cli.svg")
            );
        }
        download_server.await.unwrap();
        server.await.unwrap();
    }
}

#[test]
fn conflicting_upload_controls_fail_without_networking() {
    for args in [
        vec!["--upload-report", "--no-rank-upload"],
        vec!["--upload-report", "--list-nodes"],
        vec!["--report-url", "https://example.test/generate"],
        vec![
            "--upload-report",
            "--report-url",
            "http://example.test/generate",
        ],
        vec![
            "--upload-report",
            "--report-url",
            "https://example.test/other",
        ],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_tcp-bench-rs"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

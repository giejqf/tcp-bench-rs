//! Explicit, bounded Linux loopback tests for the no-argument product entry point.
#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{
    io::{Read, Write},
    process::Command,
};

fn gate() {
    assert_eq!(
        std::env::var("TCP_BENCH_BENCHMARK_LAB").as_deref(),
        Ok("loopback")
    );
}
fn temp(name: &str) -> std::path::PathBuf {
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    std::env::temp_dir().join(format!("tcp-bench-{name}-{:x}", u64::from_ne_bytes(nonce)))
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW and TCP_BENCH_BENCHMARK_LAB=loopback; <=80 loopback probes"]
fn no_arguments_run_quality_large_traces_and_default_enrichment_policy() {
    gate();
    let nodes = temp("default-nodes");
    std::fs::write(
        &nodes,
        "cdn\t4\tlab\tLocal\t\t127.0.0.1\t443\t\ncdn\t6\tlab\tLocal\t\t::1\t443\t\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tcp-bench-rs"))
        .env("TCP_BENCH_NODES_FILE", &nodes)
        .output()
        .unwrap();
    std::fs::remove_file(nodes).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Selected 2/2 matching nodes"), "{report}");
    assert!(report.contains("25 sent / 25 replies"), "{report}");
    assert!(report.contains("Large SYN quality: 1200 bytes"), "{report}");
    assert!(report.contains("Tcp outward trace") && report.contains("Udp outward trace"));
    assert!(report.contains("SkippedNonpublic"));
    assert!(report.contains("RIPEstat"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Enrichment: ripe_stat"));
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW and TCP_BENCH_BENCHMARK_LAB=loopback; <=10 loopback probes"]
fn custom_enrichment_and_json_sidecar_preserve_measurements() {
    gate();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 8192);
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .starts_with("GET /lookup/127.0.0.1 HTTP/1.1")
        );
        let body = r#"{"ip":"127.0.0.1","asn":64500,"organization":"Local fixture"}"#;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
    });
    let path = temp("benchmark-json");
    let output = Command::new(env!("CARGO_BIN_EXE_tcp-bench-rs"))
        .args([
            "--benchmark",
            "--target",
            "127.0.0.1",
            "--count",
            "2",
            "--max-hops",
            "2",
            "--budget",
            "5",
            "--enrich-provider",
            "json",
            "--enrich-private",
            "--allow-http",
            "--enrich-url",
            &format!("http://127.0.0.1:{port}/lookup"),
            "--json-output",
        ])
        .arg(&path)
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(report["nodes"][0]["quality"]["data"]["summary"]["sent"], 2);
    assert_eq!(
        report["nodes"][0]["large_quality"]["data"]["packet_size"],
        1200
    );
    assert_eq!(report["nodes"][0]["traces"].as_array().unwrap().len(), 2);
    assert_eq!(report["enrichment"]["127.0.0.1"]["asn"], 64500);
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("AS64500 | Local fixture")
    );
}

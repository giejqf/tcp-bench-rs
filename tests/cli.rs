use std::process::Command;

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tcp-bench-rs"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn discovery_selection_and_json_are_usable_without_privilege() {
    let output = cli(&[
        "--nodes-file",
        "examples/nodes.tsv",
        "-v6",
        "--province",
        "lab",
        "--list-nodes",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(json["nodes"][0]["primary"]["ip"], "::1");
}
#[test]
fn unsupported_modes_and_unbounded_downloads_fail_before_networking() {
    for args in [
        vec!["--target", "127.0.0.1", "--iperf3"],
        vec!["--target", "127.0.0.1", "--only-speedtest"],
        vec!["--target", "127.0.0.1", "--route", "--format", "csv"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}
#[test]
fn report_output_never_overwrites_an_existing_file() {
    let mut nonce = [0; 8];
    getrandom::getrandom(&mut nonce).unwrap();
    let path =
        std::env::temp_dir().join(format!("tcp-bench-output-{:x}", u64::from_ne_bytes(nonce)));
    std::fs::write(&path, b"keep me").unwrap();
    let output = cli(&[
        "--nodes-file",
        "examples/nodes.tsv",
        "--list-nodes",
        "--output",
        path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(std::fs::read(&path).unwrap(), b"keep me");
    std::fs::remove_file(path).unwrap();
}

#[test]
fn unprivileged_download_cli_emits_actual_bytes_and_fixed_peer() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        loop {
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() < 32768);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .contains(&format!("Host: fixed.test:{}", address.port()))
        );
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest")
            .unwrap();
    });
    let output = cli(&[
        "--target",
        "127.0.0.1",
        "--only-speedtest",
        "--allow-http",
        "--url",
        &format!("http://fixed.test:{}/data", address.port()),
        "--max-bytes",
        "4",
        "--duration",
        "1",
        "--budget",
        "3",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let row = &json["nodes"][0];
    assert_eq!(row["quality"]["status"], "not_requested");
    assert_eq!(row["throughput"]["data"]["body_bytes"], 4);
    assert_eq!(row["throughput"]["data"]["peer"], address.to_string());
    server.join().unwrap();
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_raw_platform_is_explicit() {
    let output = cli(&["--target", "127.0.0.1", "--count", "1"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Linux"));
}

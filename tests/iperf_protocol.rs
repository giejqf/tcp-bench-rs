//! Independent wire fixtures: no upstream implementation is embedded here.
use serde_json::{Value, json};
use std::time::Duration;
use tcp_bench_rs::{
    Error,
    iperf3::{self, Config, Direction},
    scheduler::Cancellation,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn frame(socket: &mut TcpStream) -> Value {
    let size = socket.read_u32().await.unwrap();
    assert!(size <= 65536);
    let mut bytes = vec![0; size as usize];
    socket.read_exact(&mut bytes).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
async fn send_frame(socket: &mut TcpStream, value: Value) {
    let bytes = serde_json::to_vec(&value).unwrap();
    let mut framed = (bytes.len() as u32).to_be_bytes().to_vec();
    framed.extend(bytes);
    for part in framed.chunks(3) {
        socket.write_all(part).await.unwrap();
        tokio::task::yield_now().await;
    }
}
async fn negotiate(listener: &TcpListener, direction: Direction) -> (TcpStream, TcpStream) {
    let (mut control, _) = listener.accept().await.unwrap();
    let mut cookie = [0; 37];
    control.read_exact(&mut cookie).await.unwrap();
    assert_eq!(cookie[36], 0);
    assert!(cookie[..36].iter().all(u8::is_ascii_hexdigit));
    control.write_u8(9).await.unwrap();
    let parameters = frame(&mut control).await;
    assert_eq!(parameters["tcp"], true);
    assert_eq!(parameters["parallel"], 1);
    assert_eq!(
        parameters.get("reverse").is_some(),
        direction == Direction::Download
    );
    control.write_u8(10).await.unwrap();
    let (mut data, _) = listener.accept().await.unwrap();
    let mut other_cookie = [0; 37];
    data.read_exact(&mut other_cookie).await.unwrap();
    assert_eq!(cookie, other_cookie);
    control.write_all(&[1, 2]).await.unwrap();
    (control, data)
}
fn config(listener: &TcpListener, direction: Direction) -> Config {
    Config {
        peer: listener.local_addr().unwrap(),
        direction,
        max_bytes: 10001,
        duration: Duration::from_secs(2),
        setup_timeout: Duration::from_secs(1),
        bitrate: 0,
    }
}
async fn results(control: &mut TcpStream, bytes: u64) {
    assert_eq!(control.read_u8().await.unwrap(), 4);
    control.write_u8(13).await.unwrap();
    let client = frame(control).await;
    assert_eq!(client["streams"][0]["bytes"], bytes);
    send_frame(
        control,
        json!({"sender_has_retransmits":1,
        "streams":[{"id":1,"bytes":bytes,"retransmits":7,"start_time":0,"end_time":0.5}]}),
    )
    .await;
    control.write_u8(14).await.unwrap();
    assert_eq!(control.read_u8().await.unwrap(), 16);
}

#[tokio::test]
async fn fragmented_control_exact_bytes_and_directional_counters() {
    for direction in [Direction::Upload, Direction::Download] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = config(&listener, direction);
        let server = tokio::spawn(async move {
            let (mut control, mut data) = negotiate(&listener, direction).await;
            if direction == Direction::Upload {
                let mut bytes = vec![0; 10001];
                data.read_exact(&mut bytes).await.unwrap();
            } else {
                data.write_all(&vec![0xa5; 10010]).await.unwrap();
            }
            results(&mut control, 10001).await;
            if direction == Direction::Upload {
                assert_eq!(
                    data.read_u8().await.unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            }
        });
        let result = iperf3::run(&config, &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(result.stream_bytes, 10001);
        assert_eq!(result.result_exchange, "complete", "{result:?}");
        assert_eq!(
            result.server.unwrap().sender_retransmissions,
            if direction == Direction::Download {
                Some(7)
            } else {
                None
            }
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn stalled_data_duration_and_cancellation_preserve_partial_bytes() {
    for cancelled in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = config(&listener, Direction::Download);
        config.duration = Duration::from_millis(200);
        let cancel = Cancellation::default();
        let trigger = cancel.clone();
        let server = tokio::spawn(async move {
            let (mut control, mut data) = negotiate(&listener, Direction::Download).await;
            data.write_all(b"abc").await.unwrap();
            if cancelled {
                tokio::time::sleep(Duration::from_millis(50)).await;
                trigger.cancel();
                assert_eq!(control.read_u8().await.unwrap(), 12);
            } else {
                results(&mut control, 3).await;
            }
        });
        let result = iperf3::run(&config, &cancel).await.unwrap();
        assert_eq!(result.stream_bytes, 3);
        assert_eq!(
            result.stop_reason,
            if cancelled {
                "cancelled"
            } else {
                "duration_limit"
            }
        );
        assert!(result.stream_seconds < 1.0);
        assert_eq!(
            result.result_exchange,
            if cancelled { "cancelled" } else { "complete" }
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn oversized_truncated_and_stalled_results_preserve_measurement() {
    for fault in 0..3 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = config(&listener, Direction::Download);
        config.max_bytes = 3;
        config.setup_timeout = Duration::from_millis(300);
        let server = tokio::spawn(async move {
            let (mut control, mut data) = negotiate(&listener, Direction::Download).await;
            data.write_all(b"abc").await.unwrap();
            assert_eq!(control.read_u8().await.unwrap(), 4);
            control.write_u8(13).await.unwrap();
            frame(&mut control).await;
            match fault {
                0 => control.write_u32(65537).await.unwrap(),
                1 => {
                    control.write_u32(10).await.unwrap();
                    control.write_all(b"{}").await.unwrap();
                }
                _ => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });
        let result = iperf3::run(&config, &Cancellation::default())
            .await
            .unwrap();
        assert_eq!(result.stream_bytes, 3);
        assert_eq!(result.stop_reason, "byte_limit");
        assert_eq!(result.result_exchange, "error");
        assert!(result.error.is_some());
        server.abort();
    }
}

#[tokio::test]
async fn setup_timeout_busy_and_unexpected_state_are_explicit() {
    for state in [None, Some(255), Some(42)] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = config(&listener, Direction::Upload);
        config.setup_timeout = Duration::from_millis(100);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut cookie = [0; 37];
            socket.read_exact(&mut cookie).await.unwrap();
            if let Some(state) = state {
                socket.write_u8(state).await.unwrap();
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let error = iperf3::run(&config, &Cancellation::default())
            .await
            .unwrap_err();
        if state.is_none() {
            assert!(matches!(error, Error::Timeout(_)));
        } else {
            assert!(matches!(error, Error::Iperf(_)));
        }
        server.abort();
    }
}

#[tokio::test]
async fn cli_iperf_selection_reports_both_directions_without_raw_privilege() {
    for node_file in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for direction in [Direction::Upload, Direction::Download] {
                let (mut control, mut data) = negotiate(&listener, direction).await;
                if direction == Direction::Upload {
                    let mut bytes = [0; 3];
                    data.read_exact(&mut bytes).await.unwrap();
                } else {
                    data.write_all(b"abc").await.unwrap();
                }
                results(&mut control, 3).await;
            }
        });
        let output = tokio::task::spawn_blocking(move || {
            let path = std::env::temp_dir().join(format!(
                "tcp-bench-iperf-cli-{}-{port}.tsv",
                std::process::id()
            ));
            let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_tcp-bench-rs"));
            if node_file {
                std::fs::write(
                    &path,
                    format!("iperf3\t4\tlab\ttest\t\t127.0.0.1\t{port}\t\n"),
                )
                .unwrap();
                command
                    .arg("--nodes-file")
                    .arg(&path)
                    .arg("--only-speedtest");
            } else {
                command.args([
                    "--target",
                    "127.0.0.1",
                    "--iperf3",
                    "--port",
                    &port.to_string(),
                ]);
            }
            let output = command
                .args([
                    "--iperf-direction",
                    "both",
                    "--max-bytes",
                    "3",
                    "--budget",
                    "5",
                ])
                .output()
                .unwrap();
            if node_file {
                std::fs::remove_file(path).unwrap();
            }
            output
        })
        .await
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        let row = &report["nodes"][0];
        assert_eq!(row["quality"]["status"], "not_requested");
        assert_eq!(row["throughput"]["status"], "not_requested");
        for (index, direction) in ["upload", "download"].iter().enumerate() {
            assert_eq!(row["iperf3"][index]["direction"], *direction);
            assert_eq!(
                row["iperf3"][index]["measurement"]["data"]["stream_bytes"],
                3
            );
            assert_eq!(
                row["iperf3"][index]["measurement"]["data"]["result_exchange"],
                "complete"
            );
        }
        assert_eq!(
            row["iperf3"][1]["measurement"]["data"]["server"]["sender_retransmissions"],
            7
        );
        server.await.unwrap();
    }
}

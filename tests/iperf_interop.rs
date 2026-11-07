//! External program is a development oracle only, never a runtime dependency.
use std::{
    net::{IpAddr, SocketAddr},
    process::{Child, Command, Stdio},
    time::Duration,
};
use tcp_bench_rs::{
    iperf3::{self, Config, Direction},
    scheduler::Cancellation,
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires explicit TCP_BENCH_IPERF_INTEROP=1 and a development iperf3 server binary"]
async fn upstream_upload_and_reverse_both_families() {
    assert_eq!(std::env::var("TCP_BENCH_IPERF_INTEROP").as_deref(), Ok("1"));
    let program = std::env::var("TCP_BENCH_IPERF_BIN").unwrap_or_else(|_| "iperf3".into());
    for ip in ["127.0.0.1", "::1"] {
        for (direction, duration_limited) in [
            (Direction::Upload, false),
            (Direction::Download, false),
            (Direction::Upload, true),
            (Direction::Download, true),
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            let reservation = std::net::TcpListener::bind((ip, 0)).unwrap();
            let port = reservation.local_addr().unwrap().port();
            drop(reservation);
            let mut server = Server(
                Command::new(&program)
                    .args(["-s", "-1", "-B", &ip.to_string(), "-p", &port.to_string()])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
            let config = Config {
                peer: SocketAddr::new(ip, port),
                direction,
                max_bytes: if duration_limited { 1_000_000 } else { 65536 },
                duration: if duration_limited {
                    Duration::from_millis(300)
                } else {
                    Duration::from_secs(2)
                },
                setup_timeout: Duration::from_secs(3),
                bitrate: 1_000_000,
            };
            let transfer = iperf3::run(&config, &Cancellation::default())
                .await
                .unwrap();
            if duration_limited {
                assert!(transfer.stream_bytes > 0 && transfer.stream_bytes < config.max_bytes);
                assert_eq!(transfer.stop_reason, "duration_limit", "{transfer:?}");
            } else {
                assert_eq!(transfer.stream_bytes, 65536, "{transfer:?}");
                assert_eq!(transfer.stop_reason, "byte_limit", "{transfer:?}");
            }
            assert_eq!(transfer.result_exchange, "complete", "{transfer:?}");
            assert!(transfer.error.is_none(), "{transfer:?}");
            let remote = transfer.server.unwrap();
            assert!(remote.bytes > 0);
            assert_eq!(
                remote.role,
                if direction == Direction::Upload {
                    "receiver"
                } else {
                    "sender"
                }
            );
            if direction == Direction::Upload {
                assert_eq!(remote.sender_retransmissions, None);
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let Some(status) = server.0.try_wait().unwrap() {
                        assert!(status.success());
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
        }
    }
}

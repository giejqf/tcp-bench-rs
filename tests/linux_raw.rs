//! Explicitly gated live tests. Only loopback destinations; fewer than 40 packets.
#![cfg(target_os = "linux")]
use std::{net::IpAddr, time::Duration};
use tcp_bench_rs::{
    packet::{Protocol, ReplyKind},
    probe::{ProbeEngine, ProbeStatus},
    scheduler::{Cancellation, RateLimiter},
    traceroute::{TraceConfig, trace},
};

fn gate() {
    assert_eq!(
        std::env::var("TCP_BENCH_LAB").as_deref(),
        Ok("loopback"),
        "set TCP_BENCH_LAB=loopback and grant CAP_NET_RAW in an isolated Linux test environment"
    );
}

#[tokio::test]
#[ignore = "requires Linux CAP_NET_RAW and TCP_BENCH_LAB=loopback"]
async fn syn_open_and_closed_ports_both_families() {
    gate();
    let rate = RateLimiter::new(100).unwrap();
    let cancel = Cancellation::default();
    for ip in ["127.0.0.1", "::1"] {
        let ip: IpAddr = ip.parse().unwrap();
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut engine = ProbeEngine::new(ip, Protocol::Tcp).await.unwrap();
        for size in [0, 128, 1400] {
            let result = engine
                .attempt(port, size, 64, Duration::from_secs(1), &rate, &cancel)
                .await
                .unwrap();
            assert_eq!(
                result.status,
                ProbeStatus::Reply,
                "{ip} size {size}: {result:?}"
            );
            assert_eq!(result.reply, Some(ReplyKind::SynAck));
        }
        drop(listener);
        let result = engine
            .attempt(port, 0, 64, Duration::from_secs(1), &rate, &cancel)
            .await
            .unwrap();
        assert_eq!(result.reply, Some(ReplyKind::Reset), "{ip}: {result:?}");
    }
}

#[tokio::test]
#[ignore = "requires Linux CAP_NET_RAW and TCP_BENCH_LAB=loopback"]
async fn traceroute_three_protocols_both_families() {
    gate();
    let rate = RateLimiter::new(100).unwrap();
    let cancel = Cancellation::default();
    for ip in ["127.0.0.1", "::1"] {
        let destination = ip.parse().unwrap();
        for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
            let result = trace(
                &TraceConfig {
                    destination,
                    port: 49199,
                    protocol,
                    size: 128,
                    max_hops: 2,
                    probes_per_hop: 1,
                    timeout: Duration::from_secs(1),
                },
                &rate,
                &cancel,
            )
            .await
            .unwrap();
            assert!(result.reached, "{ip} {protocol:?}: {result:?}");
            assert_eq!(result.hops.len(), 1);
            assert_eq!(result.direction, "outward");
        }
    }
}

#[tokio::test]
#[ignore = "requires Linux CAP_NET_RAW and TCP_BENCH_LAB=loopback"]
async fn udp_timeouts_and_cancellation() {
    gate();
    let ip = "127.0.0.1".parse().unwrap();
    let rate = RateLimiter::new(100).unwrap();
    let cancel = Cancellation::default();
    // A bound UDP port consumes probes without sending port-unreachable responses.
    let sink = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
    let port = sink.local_addr().unwrap().port();
    let mut engine = ProbeEngine::new(ip, Protocol::Udp).await.unwrap();
    let first = engine
        .attempt(port, 64, 64, Duration::from_millis(40), &rate, &cancel)
        .await
        .unwrap();
    assert_eq!(first.status, ProbeStatus::Timeout);
    cancel.cancel();
    let start = std::time::Instant::now();
    assert!(
        engine
            .attempt(port, 64, 64, Duration::from_secs(10), &rate, &cancel)
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_millis(100));
}

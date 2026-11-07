#![cfg(target_os = "linux")]
use std::time::Duration;
use tcp_bench_rs::{
    packet::Protocol,
    probe::{ProbeEngine, ProbeStatus},
    scheduler::{Cancellation, RateLimiter},
    traceroute::{TraceConfig, trace},
};

#[tokio::test]
#[ignore = "isolated namespace topology from tests/lab.sh only"]
async fn routed_hops_and_delay() {
    assert_eq!(std::env::var("TCP_BENCH_LAB").as_deref(), Ok("routed"));
    let rate = RateLimiter::new(100).unwrap();
    let cancel = Cancellation::default();
    for destination in ["198.18.0.6", "fd42:1::2"] {
        let destination = destination.parse().unwrap();
        for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
            let trace = trace(
                &TraceConfig {
                    destination,
                    port: 49199,
                    protocol,
                    size: 128,
                    max_hops: 4,
                    probes_per_hop: 2,
                    timeout: Duration::from_secs(1),
                },
                &rate,
                &cancel,
            )
            .await
            .unwrap();
            assert!(trace.reached, "{destination} {protocol:?}: {trace:?}");
            assert_eq!(trace.hops.len(), 2, "{trace:?}");
            assert_eq!(
                trace.hops[0].probes[0].reply,
                Some(tcp_bench_rs::packet::ReplyKind::TimeExceeded)
            );
            let delay = trace.hops[1].probes[0].rtt_ms.unwrap();
            assert!(
                (15.0..1000.0).contains(&delay),
                "expected >=20ms netem delay with scheduler tolerance: {delay}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "isolated namespace topology with 100% loss from tests/lab.sh only"]
async fn routed_loss_and_active_cancellation() {
    assert_eq!(std::env::var("TCP_BENCH_LAB").as_deref(), Ok("loss"));
    let rate = RateLimiter::new(100).unwrap();
    for destination in ["198.18.0.6", "fd42:1::2"] {
        let mut engine = ProbeEngine::new(destination.parse().unwrap(), Protocol::Tcp)
            .await
            .unwrap();
        let cancel = Cancellation::default();
        for _ in 0..3 {
            let outcome = engine
                .attempt(49199, 128, 64, Duration::from_millis(50), &rate, &cancel)
                .await
                .unwrap();
            assert_eq!(outcome.status, ProbeStatus::Timeout);
        }
        let copy = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            copy.cancel();
        });
        let start = std::time::Instant::now();
        let outcome = engine
            .attempt(49199, 128, 64, Duration::from_secs(10), &rate, &cancel)
            .await
            .unwrap();
        assert_eq!(outcome.status, ProbeStatus::Cancelled);
        assert!(start.elapsed() < Duration::from_millis(500));
    }
}

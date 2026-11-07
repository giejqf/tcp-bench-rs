use crate::{Error, Result, http::Client, scheduler::Cancellation, tcp_stats::TcpStats};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transfer {
    pub direction: String,
    pub url: String,
    pub peer: SocketAddr,
    pub body_bytes: u64,
    pub body_seconds: f64,
    pub body_bits_per_second: Option<f64>,
    pub stop_reason: String,
    pub dns_ms: f64,
    pub connect_ms: f64,
    pub tls_ms: Option<f64>,
    pub headers_ms: f64,
    pub tcp_before: TcpStats,
    pub tcp_after: TcpStats,
    pub local_sender_retransmissions_delta: Option<u32>,
    pub error: Option<String>,
}
pub struct TransferConfig<'a> {
    pub url: &'a str,
    pub fixed_ip: Option<IpAddr>,
    pub max_bytes: u64,
    pub duration: Duration,
    pub setup_timeout: Duration,
}
pub async fn download(
    client: &Client,
    config: TransferConfig<'_>,
    cancel: &Cancellation,
) -> Result<Transfer> {
    if config.max_bytes == 0
        || config.max_bytes > 1024 * 1024 * 1024 * 1024
        || config.duration.is_zero()
        || config.duration > Duration::from_secs(600)
        || config.setup_timeout.is_zero()
        || config.setup_timeout > Duration::from_secs(60)
    {
        return Err(Error::Config(
            "transfer requires 1..=1 TiB and duration 1..=600 seconds".into(),
        ));
    }
    let mut response = cancel
        .run(client.get(config.url, config.fixed_ip, config.setup_timeout))
        .await?;
    let started = Instant::now();
    let deadline = started + config.duration;
    let mut buffer = vec![0; 64 * 1024];
    let mut bytes = 0;
    let mut error = None;
    let stop_reason = loop {
        if cancel.is_cancelled() {
            break "cancelled";
        }
        if Instant::now() >= deadline {
            break "duration_limit";
        }
        if bytes == config.max_bytes {
            break "byte_limit";
        }
        let limit = (buffer.len() as u64).min(config.max_bytes - bytes) as usize;
        match tokio::time::timeout_at(deadline, cancel.run(response.read(&mut buffer[..limit])))
            .await
        {
            Ok(Ok(0)) => break "eof",
            Ok(Ok(n)) => bytes += n as u64,
            Ok(Err(Error::Cancelled)) => break "cancelled",
            Ok(Err(e)) => {
                error = Some(e.to_string());
                break "error";
            }
            Err(_) => break "duration_limit",
        }
    };
    let body_seconds = started.elapsed().as_secs_f64();
    let after = response.stats();
    let delta = response
        .stats_before
        .local_sender_total_retransmissions
        .zip(after.local_sender_total_retransmissions)
        .map(|(before, after)| after.wrapping_sub(before));
    Ok(Transfer {
        direction: "download".into(),
        url: config.url.to_owned(),
        peer: response.peer,
        body_bytes: bytes,
        body_seconds,
        body_bits_per_second: (body_seconds > 0.0).then(|| bytes as f64 * 8.0 / body_seconds),
        stop_reason: stop_reason.into(),
        dns_ms: response.dns_ms,
        connect_ms: response.connect_ms,
        tls_ms: response.tls_ms,
        headers_ms: response.headers_ms,
        tcp_before: response.stats_before.clone(),
        tcp_after: after,
        local_sender_retransmissions_delta: delta,
        error,
    })
}

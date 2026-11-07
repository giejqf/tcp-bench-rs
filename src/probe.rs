use crate::{
    Error, Result,
    packet::{self, ProbePacket, Protocol, ReplyKind},
    platform::{CaptureSocket, RawSocket},
    scheduler::{Cancellation, RateLimiter},
};
use serde::{Deserialize, Serialize};
use socket2::Socket;
#[cfg(target_os = "linux")]
use socket2::{Domain, Type};
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::{net::IpAddr, time::Duration};
use tokio::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeOutcome {
    pub attempt: u32,
    pub status: ProbeStatus,
    pub responder: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
    pub reply: Option<ReplyKind>,
    pub error: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Reply,
    Timeout,
    SendError,
    Cancelled,
}

pub struct ProbeEngine {
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    sender: RawSocket,
    capture: CaptureSocket,
    receive_buffer: Vec<u8>,
    protocol: Protocol,
    token: u32,
    ordinal: u32,
    _reservation: Socket,
}
impl ProbeEngine {
    pub async fn new(destination: IpAddr, protocol: Protocol) -> Result<Self> {
        #[cfg(not(target_os = "linux"))]
        return Err(Error::Unsupported(format!(
            "{protocol:?} raw probes to {destination} require Linux"
        )));
        #[cfg(target_os = "linux")]
        {
            let route = tokio::net::UdpSocket::bind(SocketAddr::new(
                if destination.is_ipv6() {
                    "::".parse().unwrap()
                } else {
                    "0.0.0.0".parse().unwrap()
                },
                0,
            ))
            .await
            .map_err(|e| Error::io("source selection socket", e))?;
            route
                .connect(SocketAddr::new(destination, 9))
                .await
                .map_err(|e| Error::io("select source route", e))?;
            let source = route
                .local_addr()
                .map_err(|e| Error::io("source route address", e))?
                .ip();
            let reservation = Socket::new(
                if destination.is_ipv6() {
                    Domain::IPV6
                } else {
                    Domain::IPV4
                },
                if protocol == Protocol::Tcp {
                    Type::STREAM
                } else {
                    Type::DGRAM
                },
                None,
            )
            .map_err(|e| Error::io("reserve probe port", e))?;
            reservation
                .bind(&SocketAddr::new(source, 0).into())
                .map_err(|e| Error::io("bind probe port reservation", e))?;
            let source_port = reservation
                .local_addr()
                .map_err(|e| Error::io("reserved port", e))?
                .as_socket()
                .ok_or_else(|| Error::Config("expected IP socket".into()))?
                .port();
            let sender = RawSocket::new(source, protocol.number(source.is_ipv6()))?;
            let capture = CaptureSocket::new(source, source_port)?;
            let mut random = [0; 4];
            getrandom::getrandom(&mut random)
                .map_err(|e| Error::Config(format!("OS random source: {e}")))?;
            Ok(Self {
                source,
                destination,
                source_port,
                sender,
                capture,
                receive_buffer: vec![0; 65535],
                protocol,
                token: u32::from_ne_bytes(random),
                ordinal: 0,
                _reservation: reservation,
            })
        }
    }
    pub fn source(&self) -> IpAddr {
        self.source
    }
    pub async fn attempt(
        &mut self,
        port: u16,
        size: usize,
        hop_limit: u8,
        timeout: Duration,
        rate: &RateLimiter,
        cancel: &Cancellation,
    ) -> Result<ProbeOutcome> {
        if port == 0
            || timeout.is_zero()
            || timeout > Duration::from_secs(30)
            || self.ordinal >= 60000
        {
            return Err(Error::Config("probe requires nonzero port, timeout <=30s, and fewer than 60000 attempts per engine".into()));
        }
        rate.acquire(cancel).await?;
        let ordinal = self.ordinal;
        self.ordinal += 1;
        let destination_port = if self.protocol == Protocol::Udp {
            ((port as u32 - 1 + ordinal) % 65535 + 1) as u16
        } else {
            port
        };
        let spec = ProbePacket {
            source: self.source,
            destination: self.destination,
            source_port: self.source_port,
            destination_port,
            token: self.token.wrapping_add(ordinal),
            protocol: self.protocol,
            hop_limit,
            size,
        };
        let bytes = spec.encode()?;
        let started = Instant::now();
        let mut outcome = ProbeOutcome {
            attempt: ordinal + 1,
            status: ProbeStatus::Timeout,
            responder: None,
            rtt_ms: None,
            reply: None,
            error: None,
        };
        let send = cancel
            .run(async {
                tokio::time::timeout_at(started + timeout, self.sender.send(&spec, &bytes))
                    .await
                    .map_err(|_| Error::Timeout("raw send"))?
            })
            .await;
        let started = match send {
            Ok(sent_at) => sent_at,
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(error) => {
                outcome.status = ProbeStatus::SendError;
                outcome.error = Some(error.to_string());
                return Ok(outcome);
            }
        };
        let received = cancel.run(async {
            loop {
                let (n, checksum_offloaded) =
                    self.capture.receive(&mut self.receive_buffer).await?;
                if let Some(datagram) = packet::decode_ip(&self.receive_buffer[..n], false) {
                    let source = datagram.source;
                    if let Some(reply) =
                        packet::correlate_received(&spec, datagram, checksum_offloaded)
                    {
                        return Ok((source, reply));
                    }
                }
                // Give cancellation and deadlines a turn under unrelated traffic.
                tokio::task::yield_now().await;
            }
        });
        match tokio::time::timeout_at(started + timeout, received).await {
            Ok(Ok((source, reply))) => {
                outcome.status = ProbeStatus::Reply;
                outcome.responder = Some(source);
                outcome.rtt_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                outcome.reply = Some(reply);
            }
            Ok(Err(Error::Cancelled)) => outcome.status = ProbeStatus::Cancelled,
            Ok(Err(error)) => return Err(error),
            Err(_) => {}
        }
        Ok(outcome)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualitySummary {
    pub attempted: u32,
    pub sent: u32,
    pub received: u32,
    pub timeouts: u32,
    pub icmp_errors: u32,
    pub send_errors: u32,
    pub cancelled: u32,
    pub unanswered_percent: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub mean_rtt_ms: Option<f64>,
    pub max_rtt_ms: Option<f64>,
    pub population_stddev_ms: Option<f64>,
}
pub fn summarize(outcomes: &[ProbeOutcome]) -> QualitySummary {
    let mut result = QualitySummary {
        attempted: outcomes.len() as u32,
        sent: 0,
        received: 0,
        timeouts: 0,
        icmp_errors: 0,
        send_errors: 0,
        cancelled: 0,
        unanswered_percent: None,
        min_rtt_ms: None,
        mean_rtt_ms: None,
        max_rtt_ms: None,
        population_stddev_ms: None,
    };
    let mut mean = 0.0;
    let mut m2 = 0.0;
    for outcome in outcomes {
        if outcome.status == ProbeStatus::SendError {
            result.send_errors += 1;
            continue;
        }
        result.sent += 1;
        if outcome.status == ProbeStatus::Cancelled {
            result.cancelled += 1;
            continue;
        }
        if outcome.status == ProbeStatus::Timeout {
            result.timeouts += 1;
            continue;
        }
        if !outcome
            .reply
            .as_ref()
            .is_some_and(ReplyKind::endpoint_reply)
        {
            result.icmp_errors += 1;
            continue;
        }
        if let Some(rtt) = outcome.rtt_ms {
            result.received += 1;
            let delta = rtt - mean;
            mean += delta / result.received as f64;
            m2 += delta * (rtt - mean);
            result.min_rtt_ms = Some(result.min_rtt_ms.map_or(rtt, |old| old.min(rtt)));
            result.max_rtt_ms = Some(result.max_rtt_ms.map_or(rtt, |old| old.max(rtt)));
        }
    }
    let completed = result.sent - result.cancelled;
    if completed > 0 && result.cancelled == 0 {
        result.unanswered_percent =
            Some(100.0 * (completed - result.received) as f64 / completed as f64);
    }
    if result.received > 0 {
        result.mean_rtt_ms = Some(mean);
        result.population_stddev_ms = Some((m2 / result.received as f64).sqrt());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn moments_denominator_and_cancelled_observation() {
        let mut outcomes = (1..=3)
            .map(|n| ProbeOutcome {
                attempt: n,
                status: ProbeStatus::Reply,
                responder: None,
                rtt_ms: Some(n as f64),
                reply: Some(ReplyKind::SynAck),
                error: None,
            })
            .collect::<Vec<_>>();
        outcomes.push(ProbeOutcome {
            attempt: 4,
            status: ProbeStatus::Timeout,
            responder: None,
            rtt_ms: None,
            reply: None,
            error: None,
        });
        outcomes.push(ProbeOutcome {
            attempt: 5,
            status: ProbeStatus::Reply,
            responder: None,
            rtt_ms: Some(100.0),
            reply: Some(ReplyKind::TimeExceeded),
            error: None,
        });
        outcomes.push(ProbeOutcome {
            attempt: 6,
            status: ProbeStatus::SendError,
            responder: None,
            rtt_ms: None,
            reply: None,
            error: Some("test send failure".into()),
        });
        let summary = summarize(&outcomes);
        assert_eq!(
            (
                summary.attempted,
                summary.sent,
                summary.received,
                summary.timeouts,
                summary.icmp_errors,
                summary.send_errors
            ),
            (6, 5, 3, 1, 1, 1)
        );
        assert_eq!(summary.mean_rtt_ms, Some(2.0));
        assert_eq!(summary.unanswered_percent, Some(40.0));
        assert!((summary.population_stddev_ms.unwrap() - (2.0_f64 / 3.0).sqrt()).abs() < 1e-12);
        outcomes[3].status = ProbeStatus::Cancelled;
        let summary = summarize(&outcomes);
        assert_eq!(summary.cancelled, 1);
        assert_eq!(summary.unanswered_percent, None);
    }
    #[test]
    fn missing_and_zero_are_distinct() {
        assert_eq!(summarize(&[]).unanswered_percent, None);
        let mut outcome = ProbeOutcome {
            attempt: 1,
            status: ProbeStatus::Reply,
            responder: None,
            rtt_ms: Some(0.0),
            reply: Some(ReplyKind::Reset),
            error: None,
        };
        assert_eq!(summarize(&[outcome.clone()]).mean_rtt_ms, Some(0.0));
        outcome.status = ProbeStatus::Timeout;
        outcome.rtt_ms = None;
        outcome.reply = None;
        let result = summarize(&[outcome]);
        assert_eq!(result.unanswered_percent, Some(100.0));
        assert_eq!(result.mean_rtt_ms, None);
    }
}

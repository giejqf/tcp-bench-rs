use crate::{
    Error, Result,
    packet::{Protocol, ReplyKind},
    probe::{ProbeEngine, ProbeOutcome},
    scheduler::{Cancellation, RateLimiter},
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub hop_limit: u8,
    pub probes: Vec<ProbeOutcome>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trace {
    pub direction: String,
    pub protocol: Protocol,
    pub source: IpAddr,
    pub packet_size: usize,
    pub initial_port: u16,
    pub reached: bool,
    pub completion: String,
    pub hops: Vec<Hop>,
}
pub struct TraceConfig {
    pub destination: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub size: usize,
    pub max_hops: u8,
    pub probes_per_hop: u8,
    pub timeout: Duration,
}
pub async fn trace(
    config: &TraceConfig,
    rate: &RateLimiter,
    cancel: &Cancellation,
) -> Result<Trace> {
    if config.max_hops == 0 || !(1..=10).contains(&config.probes_per_hop) {
        return Err(Error::Config(
            "trace requires 1..=255 hops and 1..=10 probes per hop".into(),
        ));
    }
    let mut engine = cancel
        .run(ProbeEngine::new(config.destination, config.protocol))
        .await?;
    let mut trace = Trace {
        direction: "outward".into(),
        protocol: config.protocol,
        source: engine.source(),
        packet_size: config
            .size
            .max(config.protocol.minimum_size(config.destination.is_ipv6())),
        initial_port: config.port,
        reached: false,
        completion: "complete".into(),
        hops: Vec::new(),
    };
    for hop_limit in 1..=config.max_hops {
        let mut probes = Vec::new();
        for _ in 0..config.probes_per_hop {
            let outcome = match engine
                .attempt(
                    config.port,
                    config.size,
                    hop_limit,
                    config.timeout,
                    rate,
                    cancel,
                )
                .await
            {
                Ok(outcome) => outcome,
                Err(Error::Cancelled) => {
                    trace.completion = "cancelled".into();
                    if !probes.is_empty() {
                        trace.hops.push(Hop { hop_limit, probes });
                    }
                    return Ok(trace);
                }
                Err(error) => return Err(error),
            };
            let port_unreachable = matches!(outcome.reply,Some(ReplyKind::Unreachable{code}) if code==if config.destination.is_ipv6(){4}else{3});
            trace.reached |= outcome.responder == Some(config.destination)
                && (outcome
                    .reply
                    .as_ref()
                    .is_some_and(ReplyKind::endpoint_reply)
                    || (config.protocol == Protocol::Udp && port_unreachable));
            let interrupted = outcome.status == crate::probe::ProbeStatus::Cancelled;
            probes.push(outcome);
            if interrupted {
                trace.completion = "cancelled".into();
                trace.hops.push(Hop { hop_limit, probes });
                return Ok(trace);
            }
        }
        trace.hops.push(Hop { hop_limit, probes });
        if trace.reached {
            break;
        }
    }
    Ok(trace)
}

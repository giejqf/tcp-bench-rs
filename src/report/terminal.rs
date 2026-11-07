//! Plain terminal output: no ANSI commands, and all external text is escaped.
use super::{Measurement, Quality, Report};
use std::{collections::BTreeSet, fmt::Write, net::IpAddr};

fn safe(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            if c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}') {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}
fn number(value: Option<f64>) -> String {
    value
        .map(|v| format!("{v:.2}"))
        .unwrap_or_else(|| "--".into())
}
fn status<T>(measurement: &Measurement<T>) -> String {
    match measurement {
        Measurement::NotRequested => "not requested".into(),
        Measurement::Complete { .. } => "complete".into(),
        Measurement::Cancelled => "cancelled".into(),
        Measurement::Skipped { message } => format!("skipped: {}", safe(message)),
        Measurement::Error { message } => format!("error: {}", safe(message)),
        Measurement::Unsupported { message } => format!("unsupported: {}", safe(message)),
    }
}
fn metadata(report: &Report, ip: IpAddr) -> String {
    let mut fields = Vec::new();
    if let Some(data) = report.enrichment.get(&ip) {
        if let Some(asn) = data.asn {
            fields.push(format!("AS{asn}"));
        }
        for text in [&data.organization, &data.location].into_iter().flatten() {
            fields.push(safe(text));
        }
    }
    if let Some(lookup) = report.enrichment_lookups.get(&ip) {
        fields.push(format!("[{:?}]", lookup.status));
        if let Some(error) = &lookup.error {
            fields.push(safe(error));
        }
    }
    if fields.is_empty() {
        "metadata not requested".into()
    } else {
        fields.join(" | ")
    }
}
fn quality(out: &mut String, label: &str, measurement: &Measurement<Quality>) {
    if let Measurement::Complete { data } = measurement {
        let s = &data.summary;
        let _ = writeln!(
            out,
            "  {label}: {} bytes; {} sent / {} replies; unanswered {}%; {}",
            data.packet_size,
            s.sent,
            s.received,
            number(s.unanswered_percent),
            safe(&data.completion)
        );
        let _ = writeln!(
            out,
            "    RTT ms: min {}  avg {}  max {}  stddev {}",
            number(s.min_rtt_ms),
            number(s.mean_rtt_ms),
            number(s.max_rtt_ms),
            number(s.population_stddev_ms)
        );
        let _ = writeln!(
            out,
            "    Timeouts {} | ICMP errors {} | send errors {} | cancelled {}",
            s.timeouts, s.icmp_errors, s.send_errors, s.cancelled
        );
        let errors = data
            .probes
            .iter()
            .filter_map(|p| p.error.as_ref())
            .collect::<BTreeSet<_>>();
        for error in errors {
            let _ = writeln!(out, "    {}", safe(error));
        }
    } else {
        let _ = writeln!(out, "  {label}: {}", status(measurement));
    }
}

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "tcp-bench-rs {} — network benchmark",
        safe(&report.application_version)
    );
    let _ = writeln!(
        out,
        "Started (Unix UTC): {} | Elapsed: {:.2}s | Nodes: {} | Cancelled: {}",
        report.started_unix_seconds,
        report.elapsed_seconds,
        report.nodes.len(),
        report.cancelled
    );
    if let Some(plan) = &report.benchmark {
        let _ = writeln!(
            out,
            "Selected {}/{} matching nodes | {} probes/check | {} probes/s | {}s budget",
            plan.selected_nodes, plan.matching_nodes, plan.count, plan.rate, plan.budget_seconds
        );
        for note in &plan.notes {
            let _ = writeln!(out, "{}", safe(note));
        }
    }
    let _ = writeln!(
        out,
        "Unanswered probes are not proof of congestion. Missing values: --. No report uploads.\n"
    );
    for (index, row) in report.nodes.iter().enumerate() {
        let n = &row.node;
        let _ = writeln!(
            out,
            "[{}] IPv{} | {} | {} | {}",
            index + 1,
            n.family,
            safe(&n.province),
            safe(&n.isp),
            std::net::SocketAddr::new(n.primary.ip, n.primary.port)
        );
        if !n.primary.host.is_empty() {
            let _ = writeln!(out, "  Host: {}", safe(&n.primary.host));
        }
        let _ = writeln!(out, "  {}", metadata(report, n.primary.ip));
        quality(&mut out, "SYN quality", &row.quality);
        if !matches!(row.large_quality, Measurement::NotRequested) {
            quality(&mut out, "Large SYN quality", &row.large_quality);
        }
        for trace in &row.traces {
            if let Measurement::Complete { data } = trace {
                let _ = writeln!(
                    out,
                    "  {:?} outward trace | {} bytes | reached {} | {}",
                    data.protocol,
                    data.packet_size,
                    data.reached,
                    safe(&data.completion)
                );
                for hop in &data.hops {
                    for probe in &hop.probes {
                        let address = probe
                            .responder
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "*".into());
                        let _ = writeln!(
                            out,
                            "    {:>2}  {:<39} {:>8} ms  {:?} {}",
                            hop.hop_limit,
                            address,
                            number(probe.rtt_ms),
                            probe.status,
                            probe
                                .responder
                                .map(|ip| metadata(report, ip))
                                .unwrap_or_default()
                        );
                        if let Some(error) = &probe.error {
                            let _ = writeln!(out, "        {}", safe(error));
                        }
                    }
                }
            } else {
                let _ = writeln!(out, "  Trace: {}", status(trace));
            }
        }
        if let Measurement::Complete { data } = &row.throughput {
            let _ = writeln!(
                out,
                "  HTTP download: {} bytes | {} Mbit/s | {}",
                data.body_bytes,
                number(data.body_bits_per_second.map(|v| v / 1e6)),
                safe(&data.stop_reason)
            );
            if let Some(error) = &data.error {
                let _ = writeln!(out, "    {}", safe(error));
            }
        } else if !matches!(row.throughput, Measurement::NotRequested) {
            let _ = writeln!(out, "  HTTP: {}", status(&row.throughput));
        }
        for session in &row.iperf3 {
            if let Measurement::Complete { data } = &session.measurement {
                let _ = writeln!(
                    out,
                    "  iPerf3 {:?}: {} bytes | {} Mbit/s | {} / {}",
                    session.direction,
                    data.stream_bytes,
                    number(data.bits_per_second.map(|v| v / 1e6)),
                    safe(&data.stop_reason),
                    safe(&data.result_exchange)
                );
                let _ = writeln!(
                    out,
                    "    Local sender retransmissions: {}",
                    data.local_sender_retransmissions_delta
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "--".into())
                );
                if let Some(server) = &data.server {
                    let _ = writeln!(
                        out,
                        "    Server {}: {} bytes | {} Mbit/s | sender retransmissions {}",
                        safe(&server.role),
                        server.bytes,
                        number(server.bits_per_second.map(|v| v / 1e6)),
                        server
                            .sender_retransmissions
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "--".into())
                    );
                }
                if let Some(error) = &data.error {
                    let _ = writeln!(out, "    {}", safe(error));
                }
            } else {
                let _ = writeln!(
                    out,
                    "  iPerf3 {:?}: {}",
                    session.direction,
                    status(&session.measurement)
                );
            }
        }
        out.push('\n');
    }
    let sources = report
        .enrichment_lookups
        .values()
        .filter_map(|v| v.attribution.as_ref())
        .collect::<BTreeSet<_>>();
    for source in sources {
        let _ = writeln!(out, "Metadata attribution: {}", safe(source));
    }
    if let Some(error) = &report.enrichment_cache_error {
        let _ = writeln!(out, "Metadata cache error: {}", safe(error));
    }
    let _ = writeln!(
        out,
        "Use --json-output FILE to retain the complete structured report and per-probe samples."
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_escapes_controls_and_distinguishes_missing_from_zero() {
        assert_eq!(number(None), "--");
        assert_eq!(number(Some(0.0)), "0.00");
        assert!(!safe("host\x1b[2J\n\u{202e}name").contains(['\x1b', '\n', '\u{202e}']));
        let mut report:Report=serde_json::from_value(serde_json::json!({
            "schema_version":1,"application_version":"test","started_unix_seconds":0,"elapsed_seconds":1,
            "cancelled":false,"enrichment":{},"nodes":[{
                "node":{"kind":"cdn","family":4,"province":"bad\u{001b}[2J","isp":"test","primary":{"host":"host","ip":"127.0.0.1","port":443,"target":""},"backup":null},
                "quality":{"status":"skipped","message":"no local route"},"traces":[],"throughput":{"status":"not_requested"}
            }]
        })).unwrap();
        let text = render(&report);
        assert!(!text.contains('\x1b'));
        assert!(text.contains("skipped: no local route"));
        report.nodes[0].quality = Measurement::Complete {
            data: Quality {
                source: "127.0.0.1".parse().unwrap(),
                packet_size: 40,
                completion: "complete".into(),
                summary: crate::probe::summarize(&[]),
                probes: vec![],
            },
        };
        assert!(render(&report).contains("RTT ms: min --  avg --"));
    }
}

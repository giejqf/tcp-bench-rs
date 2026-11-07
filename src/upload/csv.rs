//! Independently implemented adapter for the observable /generate CSV interface.
use crate::{
    Error, Result,
    iperf3::Direction,
    report::{Measurement, NodeReport, Quality, Report},
};

const HEADER: &str = "网络,IP版本,省份,运营商,域名,IP,状态,发送,收到,丢包率(%),平均延迟ms,线路,回程连接耗时ms,回程TLS握手耗时ms,去程连接耗时ms,去程TLS握手耗时ms,iPerf3重传次数,iPerf3方向\r\n";

fn number(value: Option<f64>) -> String {
    value
        .filter(|v| v.is_finite())
        .map(|v| format!("{v:.3}"))
        .unwrap_or_default()
}
fn missing_status<T>(measurement: &Measurement<T>) -> &'static str {
    match measurement {
        Measurement::Cancelled
        | Measurement::Skipped { .. }
        | Measurement::Unsupported { .. }
        | Measurement::NotRequested => "SKIP",
        _ => "FAIL",
    }
}
fn base(row: &NodeReport, category: &str) -> Vec<String> {
    let mut fields = vec![String::new(); 18];
    fields[0] = category.into();
    fields[1] = format!("IPv{}", row.node.family);
    fields[2] = row.node.province.clone();
    fields[3] = row.node.isp.clone();
    fields[4] = row.node.primary.host.clone();
    fields[5] = row.node.primary.ip.to_string();
    fields
}
fn append(out: &mut String, fields: Vec<String>) -> Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if field.chars().any(|c| c.is_control()) {
            return Err(Error::Config(
                "upload CSV contains a control character in a field".into(),
            ));
        }
        if index != 0 {
            out.push(',');
        }
        if field.contains([',', '"']) {
            out.push('"');
            out.push_str(&field.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(field);
        }
    }
    out.push_str("\r\n");
    if out.len() > 2 * 1024 * 1024 {
        return Err(Error::Config("upload CSV exceeds 2 MiB".into()));
    }
    Ok(())
}
fn quality(
    out: &mut String,
    row: &NodeReport,
    category: &str,
    measurement: &Measurement<Quality>,
) -> Result<()> {
    if matches!(measurement, Measurement::NotRequested) {
        return Ok(());
    }
    let mut f = base(row, category);
    f[11] = "Hidden".into(); // No proprietary route classification is claimed.
    f[6] = match measurement {
        Measurement::Complete { data } => {
            f[7] = data.summary.sent.to_string();
            f[8] = data.summary.received.to_string();
            f[9] = number(data.summary.unanswered_percent);
            f[10] = number(data.summary.mean_rtt_ms);
            if data.completion != "complete" {
                "SKIP"
            } else if data.summary.send_errors > 0 || data.summary.received == 0 {
                "FAIL"
            } else {
                "OK"
            }
        }
        Measurement::Skipped { .. } | Measurement::Cancelled | Measurement::Unsupported { .. } => {
            "SKIP"
        }
        _ => "FAIL",
    }
    .into();
    append(out, f)
}
pub fn encode(report: &Report) -> Result<Vec<u8>> {
    let mut out = format!("\u{feff}{HEADER}");
    for row in &report.nodes {
        let category = match row.node.kind.as_str() {
            "cernet" => "CERNET",
            "cernet2" => "CERNET2",
            "intl" | "internet" => "国际互联",
            _ => "三网",
        };
        quality(&mut out, row, category, &row.quality)?;
        quality(&mut out, row, "IPv4大包", &row.large_quality)?;
        // Speed rows overload columns 8..10 with upload Mbit/s, sender retransmits,
        // and download Mbit/s. Keep directions and unknown counters separate.
        for result in &row.iperf3 {
            let mut f = base(row, "三网单线程速度");
            f[7] = "-".into();
            f[8] = "-".into();
            f[9] = "-".into();
            f[17] = match result.direction {
                Direction::Upload => "upload",
                Direction::Download => "download",
            }
            .into();
            f[6] = missing_status(&result.measurement).into();
            if let Measurement::Complete { data } = &result.measurement {
                f[6] = if data.error.is_some() {
                    "FAIL"
                } else if data.stop_reason == "cancelled" {
                    "SKIP"
                } else {
                    "OK"
                }
                .into();
                let rate = number(data.bits_per_second.map(|v| v / 1_000_000.0));
                let retrans = if result.direction == Direction::Upload {
                    data.local_sender_retransmissions_delta.map(u64::from)
                } else {
                    data.server.as_ref().and_then(|s| s.sender_retransmissions)
                };
                f[if result.direction == Direction::Upload {
                    7
                } else {
                    9
                }] = rate;
                f[8] = retrans.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
                f[16] = retrans.map(|v| v.to_string()).unwrap_or_default();
            }
            append(&mut out, f)?;
        }
        if !matches!(row.throughput, Measurement::NotRequested) {
            let mut f = base(row, "三网单线程速度");
            f[6] = missing_status(&row.throughput).into();
            f[7] = "-".into();
            f[8] = "-".into();
            if let Measurement::Complete { data } = &row.throughput {
                f[6] = if data.error.is_some() {
                    "FAIL"
                } else if data.stop_reason == "cancelled" {
                    "SKIP"
                } else {
                    "OK"
                }
                .into();
                f[9] = number(data.body_bits_per_second.map(|v| v / 1_000_000.0));
                // Reference download labels refer to a locally initiated connection.
                f[14] = number(Some(data.connect_ms));
                f[15] = number(data.tls_ms);
            }
            append(&mut out, f)?;
        }
        if matches!(row.quality, Measurement::NotRequested) && !row.traces.is_empty() {
            let mut f = base(row, category);
            f[6] = "SKIP".into();
            f[11] = "Hidden".into();
            append(&mut out, f)?;
        }
    }
    if out.len() == HEADER.len() + 3 {
        return Err(Error::Config("no report rows to upload".into()));
    }
    Ok(out.into_bytes())
}

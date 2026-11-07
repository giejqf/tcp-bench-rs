use crate::{
    Error, Result,
    enrichment::Metadata,
    enrichment::remote::Lookup,
    iperf3,
    nodes::Node,
    probe::{ProbeOutcome, QualitySummary},
    throughput::Transfer,
    traceroute::Trace,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};
pub mod terminal;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Measurement<T> {
    NotRequested,
    Complete { data: T },
    Error { message: String },
    Unsupported { message: String },
    Cancelled,
    Skipped { message: String },
}
impl<T> Measurement<T> {
    pub fn from_result(result: Result<T>) -> Self {
        match result {
            Ok(data) => Self::Complete { data },
            Err(Error::Cancelled) => Self::Cancelled,
            Err(Error::Unsupported(message)) => Self::Unsupported { message },
            Err(error) => Self::Error {
                message: error.to_string(),
            },
        }
    }
    pub fn failed(&self) -> bool {
        matches!(
            self,
            Self::Error { .. } | Self::Unsupported { .. } | Self::Cancelled
        )
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quality {
    pub source: IpAddr,
    pub packet_size: usize,
    pub completion: String,
    pub summary: QualitySummary,
    pub probes: Vec<ProbeOutcome>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReport {
    pub node: Node,
    pub quality: Measurement<Quality>,
    pub traces: Vec<Measurement<Trace>>,
    pub throughput: Measurement<Transfer>,
    #[serde(default)]
    pub iperf3: Vec<IperfMeasurement>,
    #[serde(default = "not_requested")]
    pub large_quality: Measurement<Quality>,
}
fn not_requested<T>() -> Measurement<T> {
    Measurement::NotRequested
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IperfMeasurement {
    pub direction: iperf3::Direction,
    pub measurement: Measurement<iperf3::Transfer>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u8,
    pub application_version: String,
    pub started_unix_seconds: u64,
    pub elapsed_seconds: f64,
    pub cancelled: bool,
    pub nodes: Vec<NodeReport>,
    pub enrichment: BTreeMap<IpAddr, Metadata>,
    #[serde(default)]
    pub enrichment_lookups: BTreeMap<IpAddr, Lookup>,
    #[serde(default)]
    pub enrichment_cache_error: Option<String>,
    #[serde(default)]
    pub benchmark: Option<BenchmarkInfo>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkInfo {
    pub matching_nodes: usize,
    pub selected_nodes: usize,
    pub count: u16,
    pub rate: u32,
    pub budget_seconds: u64,
    pub notes: Vec<String>,
}
pub fn csv(report: &Report) -> String {
    // Names and meanings of the first eleven columns are observed public interface.
    // Additional columns have explicit native meanings; no reverse-path labels.
    let mut out = String::from(
        "网络,IP版本,省份,运营商,域名,IP,状态,发送,收到,丢包率(%),平均延迟ms,下载字节,下载bit/s,本地发送重传,错误,下载状态,下载错误,iPerf3上传字节,iPerf3上传bit/s,iPerf3上传状态,iPerf3下载字节,iPerf3下载bit/s,iPerf3下载状态,iPerf3远端发送重传,iPerf3错误\r\n",
    );
    for row in &report.nodes {
        let (status, sent, received, loss, mean, error) = match &row.quality {
            Measurement::Complete { data } => (
                if data.summary.send_errors > 0 {
                    "send_error"
                } else {
                    &*data.completion
                },
                data.summary.sent.to_string(),
                data.summary.received.to_string(),
                number(data.summary.unanswered_percent),
                number(data.summary.mean_rtt_ms),
                data.probes
                    .iter()
                    .find_map(|probe| probe.error.clone())
                    .unwrap_or_default(),
            ),
            Measurement::NotRequested => (
                "not_requested",
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
            Measurement::Cancelled => (
                "cancelled",
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
            ),
            Measurement::Error { message } => (
                "error",
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                message.clone(),
            ),
            Measurement::Unsupported { message } | Measurement::Skipped { message } => (
                "unsupported",
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                message.clone(),
            ),
        };
        let (bytes, rate, retrans) = match &row.throughput {
            Measurement::Complete { data } => (
                data.body_bytes.to_string(),
                number(data.body_bits_per_second),
                data.local_sender_retransmissions_delta
                    .map(|v| v.to_string())
                    .unwrap_or_default(),
            ),
            _ => (String::new(), String::new(), String::new()),
        };
        let (download_status, download_error) = match &row.throughput {
            Measurement::Complete { data } => (
                data.stop_reason.clone(),
                data.error.clone().unwrap_or_default(),
            ),
            Measurement::NotRequested => ("not_requested".into(), String::new()),
            Measurement::Cancelled => ("cancelled".into(), String::new()),
            Measurement::Error { message } => ("error".into(), message.clone()),
            Measurement::Unsupported { message } => ("unsupported".into(), message.clone()),
            Measurement::Skipped { message } => ("skipped".into(), message.clone()),
        };
        let mut fields = vec![
            row.node.kind.clone(),
            row.node.family.to_string(),
            row.node.province.clone(),
            row.node.isp.clone(),
            row.node.primary.host.clone(),
            row.node.primary.ip.to_string(),
            status.to_string(),
            sent,
            received,
            loss,
            mean,
            bytes,
            rate,
            retrans,
            error,
            download_status,
            download_error,
        ];
        let mut iperf_errors = Vec::new();
        let mut remote_retrans = String::new();
        for direction in [iperf3::Direction::Upload, iperf3::Direction::Download] {
            match row
                .iperf3
                .iter()
                .find(|result| result.direction == direction)
                .map(|result| &result.measurement)
            {
                Some(Measurement::Complete { data }) => {
                    fields.extend([
                        data.stream_bytes.to_string(),
                        number(data.bits_per_second),
                        format!("{}/{}", data.stop_reason, data.result_exchange),
                    ]);
                    if let Some(error) = &data.error {
                        iperf_errors.push(format!("{direction:?}: {error}"));
                    }
                    if direction == iperf3::Direction::Download {
                        remote_retrans = data
                            .server
                            .as_ref()
                            .and_then(|server| server.sender_retransmissions)
                            .map(|n| n.to_string())
                            .unwrap_or_default();
                    }
                }
                Some(Measurement::Error { message } | Measurement::Unsupported { message }) => {
                    fields.extend([String::new(), String::new(), "error".into()]);
                    iperf_errors.push(format!("{direction:?}: {message}"));
                }
                Some(Measurement::Cancelled) => {
                    fields.extend([String::new(), String::new(), "cancelled".into()])
                }
                _ => fields.extend([String::new(), String::new(), "not_requested".into()]),
            }
        }
        fields.extend([remote_retrans, iperf_errors.join("; ")]);
        out.push_str(
            &fields
                .iter()
                .map(|field| format!("\"{}\"", field.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}
fn number(value: Option<f64>) -> String {
    value.map(|value| format!("{value:.6}")).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_and_missing_status_are_explicit() {
        let report = Report {
            schema_version: 1,
            application_version: "test".into(),
            started_unix_seconds: 0,
            elapsed_seconds: 0.0,
            cancelled: false,
            nodes: vec![],
            enrichment: BTreeMap::new(),
            enrichment_lookups: BTreeMap::new(),
            enrichment_cache_error: None,
            benchmark: None,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(
            serde_json::to_value(Measurement::<Quality>::NotRequested).unwrap()["status"],
            "not_requested"
        );
        let _: Report = serde_json::from_value(value).unwrap();
    }
}

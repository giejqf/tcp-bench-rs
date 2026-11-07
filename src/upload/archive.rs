use super::*;
use flate2::{Compression, write::GzEncoder};
use std::{collections::BTreeMap, io::Write};

const MAX: usize = 16 * 1024 * 1024;
struct Limited(Vec<u8>);
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("upload archive exceeds 16 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub(super) struct Bundle {
    pub path: String,
    pub bytes: Vec<u8>,
}
struct Archive {
    tar: tar::Builder<Limited>,
    used: usize,
}
impl Archive {
    fn new() -> Self {
        Self {
            tar: tar::Builder::new(Limited(Vec::new())),
            used: 0,
        }
    }
    fn json(&mut self, name: &str, value: &impl Serialize) -> Result<()> {
        let mut content = Limited(Vec::new());
        serde_json::to_writer(&mut content, value)?;
        self.used += content.0.len();
        if self.used > MAX {
            return Err(Error::Config("upload attachments exceed 16 MiB".into()));
        }
        let mut header = tar::Header::new_ustar();
        header.set_size(content.0.len() as u64);
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        self.tar
            .append_data(&mut header, name, content.0.as_slice())
            .map_err(|e| Error::io("build upload archive", e))
    }
    fn finish(self, path: String) -> Result<Bundle> {
        let raw = self
            .tar
            .into_inner()
            .map_err(|e| Error::io("finish upload tar", e))?;
        let mut gzip = GzEncoder::new(Limited(Vec::new()), Compression::fast());
        gzip.write_all(&raw.0)
            .map_err(|e| Error::io("compress upload archive", e))?;
        let bytes = gzip
            .finish()
            .map_err(|e| Error::io("finish upload gzip", e))?
            .0;
        Ok(Bundle { path, bytes })
    }
}
pub(super) fn bundles(report: &Report, id: &str, debug: bool) -> Result<Vec<Bundle>> {
    let generated = timestamp(report.started_unix_seconds)?;
    let mut groups: BTreeMap<(&str, &str), Vec<_>> = BTreeMap::new();
    for (index, row) in report.nodes.iter().enumerate() {
        if row.traces.is_empty() {
            continue;
        }
        let group = match (row.node.kind.as_str(), row.node.family) {
            ("cernet", 4) => ("cernet_ipv4", "edu_route4"),
            ("cernet2", 6) => ("cernet2_ipv6", "edu_route6"),
            (_, 6) => ("ipv6", "summary_route6"),
            _ => ("ipv4", "summary_route4"),
        };
        groups.entry(group).or_default().push((index, row));
    }
    let mut bundles = Vec::new();
    let mut total = 0;
    for ((section, prefix), rows) in groups {
        let mut archive = Archive::new();
        archive.json(&format!("{prefix}_trace_manifest.json"), &serde_json::json!({"reportId":id,"section":section,"prefix":prefix,"generatedAt":generated,"traceFiles":rows.len(),"application":"tcp-bench-rs","schemaVersion":1,"direction":"outward"}))?;
        for (index, row) in rows {
            let mut ips = std::collections::BTreeSet::from([row.node.primary.ip]);
            for trace in &row.traces {
                if let Measurement::Complete { data } = trace {
                    ips.extend(
                        data.hops
                            .iter()
                            .flat_map(|hop| &hop.probes)
                            .filter_map(|probe| probe.responder),
                    );
                }
            }
            let metadata = ips
                .iter()
                .filter_map(|ip| report.enrichment.get(ip).map(|value| (*ip, value)))
                .collect::<BTreeMap<_, _>>();
            let lookups = ips
                .iter()
                .filter_map(|ip| report.enrichment_lookups.get(ip).map(|value| (*ip, value)))
                .collect::<BTreeMap<_, _>>();
            // Native schema, never pretend to emit NextTrace's proprietary output.
            archive.json(&format!("{prefix}_trace_{index}.json"), &serde_json::json!({"node":row.node,"traces":row.traces,"direction":"outward","schema_version":1,"enrichment":metadata,"enrichment_lookups":lookups}))?;
        }
        total += archive.used;
        bundles.push(archive.finish(format!("route-traces/{id}.{section}.tar.gz"))?);
    }
    if report
        .nodes
        .iter()
        .any(|n| !n.iperf3.is_empty() || !matches!(n.throughput, Measurement::NotRequested))
    {
        let mut archive = Archive::new();
        archive.json("manifest.json", &serde_json::json!({"reportId":id,"generatedAt":generated,"type":"speedtest-debug","application":"tcp-bench-rs"}))?;
        for (index, row) in report.nodes.iter().enumerate() {
            if row.iperf3.is_empty() && matches!(row.throughput, Measurement::NotRequested) {
                continue;
            }
            archive.json(&format!("transfer_{index}.json"), &serde_json::json!({"node":row.node,"iperf3":row.iperf3,"throughput":row.throughput}))?;
        }
        total += archive.used;
        bundles.push(archive.finish(format!("speedtest-debug/{id}.tar.gz"))?);
    }
    if debug {
        let mut archive = Archive::new();
        archive.json("probe_debug_manifest.json", &serde_json::json!({"reportId":id,"generatedAt":generated,"type":"probe-debug","files":1,"application":"tcp-bench-rs"}))?;
        archive.json("report.json", report)?;
        total += archive.used;
        bundles.push(archive.finish(format!("probe-debug/{id}.tar.gz"))?);
    }
    if total > MAX || bundles.iter().map(|b| b.bytes.len()).sum::<usize>() > MAX {
        return Err(Error::Config(
            "total upload attachments exceed 16 MiB".into(),
        ));
    }
    Ok(bundles)
}

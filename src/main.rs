use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tcp_bench_rs::{
    Error, Result,
    cli::{Cli, Format},
    discovery::{self, DiscoveryConfig},
    enrichment,
    http::{Client, Endpoint},
    iperf3,
    nodes::{Node, Target},
    packet::Protocol,
    probe::{self, ProbeEngine},
    report::{self, IperfMeasurement, Measurement, NodeReport, Quality, Report},
    scheduler::{Cancellation, RateLimiter},
    throughput::{self, TransferConfig},
    traceroute::{self, TraceConfig},
};

#[tokio::main]
async fn main() {
    let args = Cli::parse_args();
    match execute(args).await {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("tcp-bench-rs: {error}");
            std::process::exit(2);
        }
    }
}
async fn execute(args: Cli) -> Result<i32> {
    args.validate()?;
    let remote_config = args.remote_enrichment()?;
    let started = tokio::time::Instant::now();
    let started_unix_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Config("system clock predates UNIX epoch".into()))?
        .as_secs();
    let cancel = Cancellation::default();
    let signal_cancel = cancel.clone();
    let deadline = started + Duration::from_secs(args.budget);
    let watcher = tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|e| Error::io("install SIGTERM handler", e))?;
            tokio::select! {result=tokio::signal::ctrl_c()=>{result.map_err(|e|Error::io("install SIGINT handler",e))?;},_=terminate.recv()=>{},_=tokio::time::sleep_until(deadline)=>{}}
        }
        #[cfg(not(unix))]
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=tokio::time::sleep_until(deadline)=>{}}
        signal_cancel.cancel();
        Ok::<_, Error>(())
    });
    let client = Client::default();
    let mut nodes = if let Some(path) = &args.nodes_file {
        discovery::local(path)?
    } else if let Some(url) = &args.nodes_url {
        discovery::remote(
            DiscoveryConfig {
                url,
                scope: &args.scope,
                cache: args.cache.as_deref(),
                expiry: Duration::from_secs(args.cache_ttl),
                timeout: Duration::from_secs(args.setup_timeout),
                retries: args.retries,
                allow_http: args.allow_http,
            },
            &client,
            &cancel,
        )
        .await?
    } else {
        args.target
            .iter()
            .map(|&ip| Node {
                kind: "explicit".into(),
                family: if ip.is_ipv6() { 6 } else { 4 },
                province: String::new(),
                isp: String::new(),
                primary: Target {
                    host: String::new(),
                    ip,
                    port: args.target_port(),
                    target: String::new(),
                },
                backup: None,
            })
            .collect()
    };
    nodes.retain(|node| {
        (!args.v4 || node.family == 4)
            && (!args.v6 || node.family == 6)
            && (!args.only_large || node.family == 4)
            && (!args.cernet || matches!(node.kind.as_str(), "cernet" | "cernet2"))
            && (args.province.is_empty() || args.province.contains(&node.province))
    });
    if nodes.is_empty() {
        return Err(Error::Config(
            "no nodes match the selected family/type/province (province matches TSV text exactly)"
                .into(),
        ));
    }
    if args.list_nodes {
        output(
            &args,
            &serde_json::to_vec_pretty(&serde_json::json!({"schema_version":1,"nodes":nodes}))?,
        )?;
        watcher.abort();
        return Ok(0);
    }
    let per_node = if args.route {
        args.max_hops as usize
            * args.probes_per_hop as usize
            * args.route_protocol.protocols().len()
    } else if args.speed_only() {
        0
    } else {
        args.count as usize
    };
    if per_node * nodes.len() > 100_000 {
        return Err(Error::Config(
            "run exceeds 100000 planned probes; reduce node selection, count, or trace hops/probes"
                .into(),
        ));
    }
    // Capability checks do not depend on any target being reachable.
    if !args.speed_only() {
        for v6 in [false, true] {
            if nodes.iter().any(|node| node.primary.ip.is_ipv6() == v6) {
                for protocol in if args.route {
                    args.route_protocol.protocols()
                } else {
                    vec![Protocol::Tcp]
                } {
                    tcp_bench_rs::platform::check_capabilities(v6, protocol)?;
                }
            }
        }
    }
    let database = if let Some(path) = &args.enrichment_file {
        enrichment::load(path)?
    } else {
        BTreeMap::new()
    };
    let rate = Arc::new(RateLimiter::new(args.rate)?);
    let args = Arc::new(args);
    let mut pending = nodes.into_iter().enumerate();
    let mut tasks = tokio::task::JoinSet::new();
    let mut rows = Vec::new();
    loop {
        while tasks.len() < (args.parallel as usize) {
            let Some((index, node)) = pending.next() else {
                break;
            };
            let args = args.clone();
            let client = client.clone();
            let rate = rate.clone();
            let cancel = cancel.clone();
            tasks.spawn(async move { (index, measure(node, args, client, rate, cancel).await) });
        }
        match tasks.join_next().await {
            Some(Ok(row)) => rows.push(row),
            Some(Err(error)) => {
                return Err(Error::Config(format!("measurement task failed: {error}")));
            }
            None => break,
        }
    }
    rows.sort_by_key(|(index, _)| *index);
    let rows = rows.into_iter().map(|(_, row)| row).collect::<Vec<_>>();
    let mut candidates = BTreeSet::new();
    for row in &rows {
        candidates.insert(row.node.primary.ip);
        for trace in &row.traces {
            if let Measurement::Complete { data } = trace {
                for probe in data.hops.iter().flat_map(|hop| &hop.probes) {
                    if let Some(ip) = probe.responder {
                        candidates.insert(ip);
                    }
                }
            }
        }
    }
    let (metadata, enrichment_lookups, enrichment_cache_error) = if let Some(config) = remote_config
    {
        let enriched =
            enrichment::remote::enrich(&config, &client, &candidates, &database, &cancel).await?;
        (enriched.metadata, enriched.lookups, enriched.cache_error)
    } else {
        let metadata = candidates
            .iter()
            .filter_map(|ip| database.get(ip).map(|entry| (*ip, entry.clone())))
            .collect::<BTreeMap<_, _>>();
        let lookups = metadata
            .keys()
            .map(|ip| (*ip, enrichment::remote::Lookup::local()))
            .collect();
        (metadata, lookups, None)
    };
    let failed = cancel.is_cancelled()
        || enrichment_cache_error.is_some()
        || enrichment_lookups.values().any(enrichment::remote::Lookup::failed)
        || rows.iter().any(|row| {
            row.quality.failed()
                || row.throughput.failed()
                || row.iperf3.iter().any(|result|result.measurement.failed()||matches!(&result.measurement,Measurement::Complete{data} if data.error.is_some()||data.result_exchange=="cancelled"||data.stop_reason=="cancelled"))
                || row.traces.iter().any(Measurement::failed)
                || row.traces.iter().any(|trace|matches!(trace,Measurement::Complete{data} if data.hops.iter().flat_map(|hop|&hop.probes).any(|probe|probe.status==probe::ProbeStatus::SendError)))
                || matches!(&row.quality,Measurement::Complete{data} if data.summary.send_errors>0)
                || matches!(&row.throughput,Measurement::Complete{data} if data.error.is_some())
        });
    let report = Report {
        schema_version: 1,
        application_version: env!("CARGO_PKG_VERSION").into(),
        started_unix_seconds,
        elapsed_seconds: started.elapsed().as_secs_f64(),
        cancelled: cancel.is_cancelled(),
        nodes: rows,
        enrichment: metadata,
        enrichment_lookups,
        enrichment_cache_error,
    };
    let bytes = match args.format {
        Format::Json => serde_json::to_vec_pretty(&report)?,
        Format::Csv => report::csv(&report).into_bytes(),
    };
    output(&args, &bytes)?;
    watcher.abort();
    Ok(if failed { 1 } else { 0 })
}
async fn measure(
    node: Node,
    args: Arc<Cli>,
    client: Client,
    rate: Arc<RateLimiter>,
    cancel: Cancellation,
) -> NodeReport {
    if args.debug {
        eprintln!("measuring {}:{}", node.primary.ip, node.primary.port);
    }
    let mut row = NodeReport {
        node: node.clone(),
        quality: Measurement::NotRequested,
        traces: Vec::new(),
        throughput: Measurement::NotRequested,
        iperf3: Vec::new(),
    };
    if args.route {
        for protocol in args.route_protocol.protocols() {
            row.traces.push(Measurement::from_result(
                traceroute::trace(
                    &TraceConfig {
                        destination: node.primary.ip,
                        port: node.primary.port,
                        protocol,
                        size: args.size as usize,
                        max_hops: args.max_hops,
                        probes_per_hop: args.probes_per_hop,
                        timeout: Duration::from_millis(args.timeout_ms),
                    },
                    &rate,
                    &cancel,
                )
                .await,
            ));
        }
    } else if !args.speed_only() {
        let quality = async {
            let mut engine = ProbeEngine::new(node.primary.ip, Protocol::Tcp).await?;
            let mut probes = Vec::new();
            let mut completion = "complete";
            for _ in 0..args.count {
                match engine
                    .attempt(
                        node.primary.port,
                        args.size as usize,
                        64,
                        Duration::from_millis(args.timeout_ms),
                        &rate,
                        &cancel,
                    )
                    .await
                {
                    Ok(outcome) => {
                        let interrupted = outcome.status == probe::ProbeStatus::Cancelled;
                        probes.push(outcome);
                        if interrupted {
                            completion = "cancelled";
                            break;
                        }
                    }
                    Err(Error::Cancelled) => {
                        completion = "cancelled";
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            let mut summary = probe::summarize(&probes);
            if completion == "cancelled" {
                summary.unanswered_percent = None;
            }
            Ok(Quality {
                source: engine.source(),
                packet_size: (args.size as usize)
                    .max(Protocol::Tcp.minimum_size(node.primary.ip.is_ipv6())),
                completion: completion.into(),
                summary,
                probes,
            })
        };
        row.quality = if cancel.is_cancelled() {
            Measurement::Cancelled
        } else {
            Measurement::from_result(quality.await)
        };
    }
    if args.speed_enabled() {
        if args.iperf3 || node.kind == "iperf3" {
            for direction in args.iperf_direction.directions() {
                let config = iperf3::Config {
                    peer: std::net::SocketAddr::new(node.primary.ip, node.primary.port),
                    direction,
                    max_bytes: args.max_bytes.unwrap_or(0),
                    duration: Duration::from_secs(args.duration),
                    setup_timeout: Duration::from_secs(args.setup_timeout),
                    bitrate: args.iperf_bitrate,
                };
                row.iperf3.push(IperfMeasurement {
                    direction,
                    measurement: Measurement::from_result(iperf3::run(&config, &cancel).await),
                });
            }
            return row;
        }
        let transfer = async {
            let url = transfer_url(&node, &args)?;
            throughput::download(
                &client,
                TransferConfig {
                    url: &url,
                    fixed_ip: Some(node.primary.ip),
                    max_bytes: args
                        .max_bytes
                        .ok_or_else(|| Error::Config("missing byte budget".into()))?,
                    duration: Duration::from_secs(args.duration),
                    setup_timeout: Duration::from_secs(args.setup_timeout),
                },
                &cancel,
            )
            .await
        };
        row.throughput = Measurement::from_result(transfer.await);
    }
    row
}
fn transfer_url(node: &Node, args: &Cli) -> Result<String> {
    let url = if let Some(url) = &args.url {
        url.clone()
    } else if node.primary.target.starts_with("https://")
        || node.primary.target.starts_with("http://")
    {
        node.primary.target.clone()
    } else if node.primary.target.starts_with('/') && !node.primary.host.is_empty() {
        format!(
            "https://{}:{}{}",
            node.primary.host, node.primary.port, node.primary.target
        )
    } else {
        return Err(Error::Config("speed tests need --url or a node target containing an explicit URL/path; service-specific region names are not download URLs".into()));
    };
    if !Endpoint::parse(&url)?.tls && !args.allow_http {
        return Err(Error::Config("plain HTTP requires --allow-http".into()));
    }
    Ok(url)
}
fn output(args: &Cli, bytes: &[u8]) -> Result<()> {
    let mut writer: Box<dyn Write> = if let Some(path) = &args.output {
        Box::new(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| {
                    Error::io(
                        format!(
                            "create report {} (existing files are refused)",
                            path.display()
                        ),
                        e,
                    )
                })?,
        )
    } else {
        Box::new(std::io::stdout().lock())
    };
    writer
        .write_all(bytes)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|e| Error::io("write report", e))
}

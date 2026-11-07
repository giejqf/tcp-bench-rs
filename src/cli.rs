use crate::{Error, Result, http::Endpoint, nodes::validate_ip, packet::Protocol};
use crate::{
    enrichment::remote::{self, Provider},
    iperf3::Direction,
};
use clap::{CommandFactory, FromArgMatches, Parser, ValueEnum, parser::ValueSource};
use std::{net::IpAddr, path::PathBuf};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum IperfDirection {
    Upload,
    Download,
    Both,
}
impl IperfDirection {
    pub fn directions(self) -> Vec<Direction> {
        match self {
            Self::Upload => vec![Direction::Upload],
            Self::Download => vec![Direction::Download],
            Self::Both => vec![Direction::Upload, Direction::Download],
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Csv,
}
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TraceProtocol {
    Tcp,
    Udp,
    Icmp,
    Both,
}
impl TraceProtocol {
    pub fn protocols(self) -> Vec<Protocol> {
        match self {
            Self::Tcp => vec![Protocol::Tcp],
            Self::Udp => vec![Protocol::Udp],
            Self::Icmp => vec![Protocol::Icmp],
            Self::Both => vec![Protocol::Tcp, Protocol::Udp],
        }
    }
}

#[derive(Debug, Clone, Parser)]
#[command(
    version,
    about = "Native TCP SYN quality, outward traceroute, HTTPS and iPerf3 throughput",
    after_help = "No arguments runs the bounded default benchmark with ASN enrichment.\nRaw measurements require Linux CAP_NET_RAW. Uploads require --upload-report.\nUse --no-enrichment to disable remote metadata. See docs/compatibility.md."
)]
pub struct Cli {
    /// Standard/large SYN quality and outward TCP/UDP traces; implicit without a source or mode
    #[arg(long,conflicts_with_all=["route","only_speedtest","only_large","list_nodes"])]
    pub benchmark: bool,
    /// Maximum selected nodes (benchmark default 32, other modes 4096)
    #[arg(long,default_value_t=4096,value_parser=clap::value_parser!(u16).range(1..=4096))]
    pub max_nodes: u16,
    /// Explicit destination IP; repeat to measure several hosts
    #[arg(long,conflicts_with_all=["nodes_file","nodes_url"])]
    pub target: Vec<IpAddr>,
    #[arg(long, conflicts_with = "nodes_url")]
    pub nodes_file: Option<PathBuf>,
    /// getNodes service base URL; default benchmark uses TcpQuality's catalog
    #[arg(long)]
    pub nodes_url: Option<String>,
    #[arg(long,default_value="cdn",value_parser=["cdn","v4","v6","cernet","all","tos","apple6","telegram"])]
    pub scope: String,
    #[arg(long)]
    pub cache: Option<PathBuf>,
    #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(0..=86400))]
    pub cache_ttl: u64,
    #[arg(long,default_value_t=1,value_parser=clap::value_parser!(u8).range(0..=3))]
    pub retries: u8,
    #[arg(long)]
    pub allow_http: bool,
    #[arg(long)]
    pub list_nodes: bool,
    #[arg(short='c',long,default_value_t=30,value_parser=clap::value_parser!(u16).range(1..=600))]
    pub count: u16,
    /// Complete IP packet size; 0 means minimal protocol headers
    #[arg(short='s',long,default_value_t=0,value_parser=clap::value_parser!(u32).range(0..=65535))]
    pub size: u32,
    #[arg(short='p',long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=31))]
    pub parallel: u8,
    #[arg(long, conflicts_with = "v6")]
    pub v4: bool,
    #[arg(long, conflicts_with = "v4")]
    pub v6: bool,
    #[arg(long)]
    pub province: Vec<String>,
    /// Explicit-target port (default 443, or 5201 with --iperf3)
    #[arg(long,value_parser=clap::value_parser!(u16).range(1..))]
    pub port: Option<u16>,
    /// Global maximum probes per second across all nodes
    #[arg(long,default_value_t=10,value_parser=clap::value_parser!(u32).range(1..=1000))]
    pub rate: u32,
    #[arg(long,default_value_t=1000,value_parser=clap::value_parser!(u64).range(10..=30000))]
    pub timeout_ms: u64,
    /// Total wall-clock budget including discovery and transfers
    #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=3600))]
    pub budget: u64,
    #[arg(long,conflicts_with_all=["speedtest","only_speedtest","iperf3"])]
    pub route: bool,
    #[arg(long,value_enum,default_value_t=TraceProtocol::Tcp)]
    pub route_protocol: TraceProtocol,
    #[arg(long,default_value_t=30,value_parser=clap::value_parser!(u8).range(1..=255))]
    pub max_hops: u8,
    #[arg(long,default_value_t=3,value_parser=clap::value_parser!(u8).range(1..=10))]
    pub probes_per_hop: u8,
    #[arg(long, conflicts_with = "only_speedtest")]
    pub speedtest: bool,
    #[arg(long)]
    pub only_speedtest: bool,
    /// Download URL. Fixed --target or node IP keeps this URL's TLS hostname
    #[arg(long)]
    pub url: Option<String>,
    /// Maximum application bytes PER NODE AND DIRECTION (required for speed tests)
    #[arg(long,value_parser=clap::value_parser!(u64).range(1..=1_099_511_627_776))]
    pub max_bytes: Option<u64>,
    #[arg(long,default_value_t=10,value_parser=clap::value_parser!(u64).range(1..=600))]
    pub duration: u64,
    #[arg(long,default_value_t=10,value_parser=clap::value_parser!(u64).range(1..=60))]
    pub setup_timeout: u64,
    #[arg(long)]
    pub only_large: bool,
    #[arg(long)]
    pub cernet: bool,
    #[arg(long)]
    pub all: bool,
    #[arg(long)]
    pub intl: bool,
    /// Native iPerf3 TCP; speed-only unless --speedtest appends it to SYN probes
    #[arg(long, conflicts_with = "url")]
    pub iperf3: bool,
    #[arg(long,value_enum,default_value_t=IperfDirection::Download)]
    pub iperf_direction: IperfDirection,
    /// iPerf3 target bits/second per stream; 0 explicitly means unlimited
    #[arg(long,default_value_t=1_000_000,value_parser=clap::value_parser!(u64).range(0..=100_000_000_000))]
    pub iperf_bitrate: u64,
    /// Disable report publication and ranking (the default)
    #[arg(long, conflicts_with = "upload_report")]
    pub no_rank_upload: bool,
    /// OPT IN: publish measurements and trace attachments; print the shareable URL
    #[arg(long, conflicts_with = "list_nodes")]
    pub upload_report: bool,
    /// TcpQuality-compatible /generate URL (default: TCPQUALITY_REPORT_API or official service)
    #[arg(long, requires = "upload_report")]
    pub report_url: Option<String>,
    /// Total upload timeout including attachments, also subject to --budget
    #[arg(long, default_value_t=30, value_parser=clap::value_parser!(u64).range(1..=120))]
    pub upload_timeout: u64,
    /// Optional public IPv4 metadata to disclose; no automatic public-IP lookup
    #[arg(long, requires = "upload_report")]
    pub report_public_ipv4: Option<std::net::Ipv4Addr>,
    /// Optional public IPv6 metadata to disclose; no automatic public-IP lookup
    #[arg(long, requires = "upload_report")]
    pub report_public_ipv6: Option<std::net::Ipv6Addr>,
    #[arg(long)]
    pub debug: bool,
    /// Local exact-IP metadata JSON; never triggers remote enrichment
    #[arg(long)]
    pub enrichment_file: Option<PathBuf>,
    /// Disable remote enrichment, including the default benchmark's ASN lookups
    #[arg(long, conflicts_with_all=["enrich_provider","enrich_url","enrich_token_env","enrich_cache","enrich_private"])]
    pub no_enrichment: bool,
    /// OPT IN: disclose target/hop IPs to this remote provider after measurements
    #[arg(long, value_enum)]
    pub enrich_provider: Option<Provider>,
    /// Provider base URL; lookups append /IP. Required for the json adapter
    #[arg(long)]
    pub enrich_url: Option<String>,
    /// Environment variable containing a bearer token (IPinfo default: IPINFO_TOKEN)
    #[arg(long)]
    pub enrich_token_env: Option<String>,
    #[arg(long)]
    pub enrich_cache: Option<PathBuf>,
    #[arg(long,default_value_t=3600,value_parser=clap::value_parser!(u64).range(0..=86400))]
    pub enrich_cache_ttl: u64,
    #[arg(long,default_value_t=5,value_parser=clap::value_parser!(u64).range(1..=30))]
    pub enrich_timeout: u64,
    #[arg(long,default_value_t=2,value_parser=clap::value_parser!(u32).range(1..=10))]
    pub enrich_rate: u32,
    #[arg(long,default_value_t=128,value_parser=clap::value_parser!(u16).range(1..=4096))]
    pub enrich_max_requests: u16,
    /// Also disclose nonpublic IPs to a user-configured JSON provider
    #[arg(long)]
    pub enrich_private: bool,
    #[arg(long,value_enum,default_value_t=Format::Json)]
    pub format: Format,
    /// Write report to a new file instead of stdout (existing files are refused)
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,
    /// Also save the complete JSON report to a new file
    #[arg(long)]
    pub json_output: Option<PathBuf>,
}
impl Cli {
    pub fn report_upload(&self) -> Result<Option<crate::upload::Config>> {
        if !self.upload_report {
            return Ok(None);
        }
        if self.no_rank_upload || self.list_nodes {
            return Err(Error::Config(
                "report upload conflicts with --no-rank-upload/--list-nodes".into(),
            ));
        }
        let config = crate::upload::Config {
            url: self
                .report_url
                .clone()
                .or_else(|| std::env::var("TCPQUALITY_REPORT_API").ok())
                .unwrap_or_else(|| crate::upload::DEFAULT_URL.into()),
            timeout: std::time::Duration::from_secs(self.upload_timeout),
            allow_http: self.allow_http,
            public_ipv4: self.report_public_ipv4,
            public_ipv6: self.report_public_ipv6,
            debug: self.debug,
        };
        config.validate()?;
        Ok(Some(config))
    }
    /// Resolve preset defaults without overriding explicitly supplied options.
    pub fn from_matches_with_defaults(
        matches: &clap::ArgMatches,
    ) -> std::result::Result<Self, clap::Error> {
        let mut args = Self::from_arg_matches(matches)?;
        let no_source =
            args.target.is_empty() && args.nodes_file.is_none() && args.nodes_url.is_none();
        args.benchmark |= no_source
            && !args.route
            && !args.speed_enabled()
            && !args.list_nodes
            && !args.only_large;
        if no_source {
            if let Some(path) = std::env::var_os("TCP_BENCH_NODES_FILE") {
                args.nodes_file = Some(path.into());
            } else if args.speed_enabled() && !args.benchmark {
                // A missing speed-test target must not turn CDN hosts into iPerf3 endpoints.
                args.nodes_url = std::env::var("TCP_BENCH_NODES_URL").ok();
            } else {
                args.nodes_url = Some(
                    std::env::var("TCP_BENCH_NODES_URL")
                        .unwrap_or_else(|_| "https://tcpquality.ibsgss.uk/getNodes".into()),
                );
            }
        }
        let default = |name| matches.value_source(name) != Some(ValueSource::CommandLine);
        if args.benchmark {
            if default("count") {
                args.count = 25;
            }
            if default("parallel") {
                args.parallel = 8;
            }
            if default("rate") {
                args.rate = 50;
            }
            if default("timeout_ms") {
                args.timeout_ms = 500;
            }
            if default("max_hops") {
                args.max_hops = 16;
            }
            if default("probes_per_hop") {
                args.probes_per_hop = 1;
            }
            if default("route_protocol") {
                args.route_protocol = TraceProtocol::Both;
            }
            if default("max_nodes") {
                args.max_nodes = 32;
            }
            if default("format") {
                args.format = Format::Text;
            }
            if !args.no_enrichment && args.enrich_provider.is_none() {
                args.enrich_provider = Some(Provider::RipeStat);
            }
        }
        if args.enrich_provider.is_none()
            && [
                "enrich_url",
                "enrich_token_env",
                "enrich_cache",
                "enrich_cache_ttl",
                "enrich_timeout",
                "enrich_rate",
                "enrich_max_requests",
                "enrich_private",
            ]
            .iter()
            .any(|name| matches.value_source(name) == Some(ValueSource::CommandLine))
        {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::MissingRequiredArgument,
                "enrichment controls require --enrich-provider outside the default benchmark",
            ));
        }
        Ok(args)
    }
    pub fn speed_enabled(&self) -> bool {
        self.speedtest || self.only_speedtest || self.iperf3
    }
    pub fn speed_only(&self) -> bool {
        self.only_speedtest || (self.iperf3 && !self.speedtest)
    }
    pub fn target_port(&self) -> u16 {
        self.port.unwrap_or(if self.iperf3 { 5201 } else { 443 })
    }
    pub fn remote_enrichment(&self) -> Result<Option<remote::Config>> {
        let Some(provider) = self.enrich_provider else {
            return Ok(None);
        };
        let base_url = match (&self.enrich_url, provider) {
            (Some(url), _) => url.clone(),
            (None, Provider::IpinfoLite) => "https://api.ipinfo.io/lite".into(),
            (None, Provider::RipeStat) => {
                "https://stat.ripe.net/data/prefix-overview/data.json".into()
            }
            _ => {
                return Err(Error::Config(
                    "--enrich-provider json requires --enrich-url".into(),
                ));
            }
        };
        let name = self
            .enrich_token_env
            .as_deref()
            .or(if provider == Provider::IpinfoLite {
                Some("IPINFO_TOKEN")
            } else {
                None
            });
        let token = name
            .map(|name| {
                std::env::var(name).map_err(|_| {
                    Error::Config(format!(
                        "enrichment token environment variable {name} is missing or not UTF-8"
                    ))
                })
            })
            .transpose()?;
        let config = remote::Config {
            provider,
            base_url,
            token,
            cache: self.enrich_cache.clone(),
            expiry: std::time::Duration::from_secs(self.enrich_cache_ttl),
            timeout: std::time::Duration::from_secs(self.enrich_timeout),
            requests_per_second: self.enrich_rate,
            max_requests: self.enrich_max_requests as usize,
            allow_http: self.allow_http,
            include_private: self.enrich_private,
        };
        config.validate()?;
        Ok(Some(config))
    }
    pub fn parse_args() -> Self {
        let matches = Self::command().get_matches_from(std::env::args_os().map(|arg| {
            if arg == "-v4" {
                "--v4".into()
            } else if arg == "-v6" {
                "--v6".into()
            } else {
                arg
            }
        }));
        Self::from_matches_with_defaults(&matches).unwrap_or_else(|error| error.exit())
    }
    pub fn validate(&self) -> Result<()> {
        if self.output.is_some() && self.output == self.json_output {
            return Err(Error::Config(
                "--output and --json-output must use different new files".into(),
            ));
        }
        if self.list_nodes && self.json_output.is_some() {
            return Err(Error::Config(
                "--json-output is for measurement reports; use --output with --list-nodes".into(),
            ));
        }
        if self.benchmark
            && (self.route || self.only_speedtest || self.only_large || self.list_nodes)
        {
            return Err(Error::Config("--benchmark cannot be combined with a route-only, speed-only, large-only or list-only mode".into()));
        }
        if self.benchmark && self.iperf3 && !self.speedtest {
            return Err(Error::Config(
                "use --benchmark --speedtest --iperf3 to append iPerf3 transfers".into(),
            ));
        }
        if self.all || self.intl {
            return Err(Error::Unsupported("--all and --intl service catalogs are not implemented; select explicit targets or nodes, optionally with --iperf3".into()));
        }
        if self.target.len() > 4096 {
            return Err(Error::Config("at most 4096 targets".into()));
        }
        for &ip in &self.target {
            validate_ip(ip)?;
        }
        if self.target.is_empty() && self.nodes_file.is_none() && self.nodes_url.is_none() {
            return Err(Error::Config(
                "provide --target IP, --nodes-file PATH, or --nodes-url URL".into(),
            ));
        }
        if self.only_large && (self.v6 || self.size <= 40) {
            return Err(Error::Config(
                "--only-large requires --size >40 and IPv4".into(),
            ));
        }
        if self.speed_enabled() {
            if self.max_bytes.is_none() {
                return Err(Error::Config(
                    "speed tests require an explicit --max-bytes budget per node".into(),
                ));
            }
        } else if self.url.is_some() || self.max_bytes.is_some() {
            return Err(Error::Config(
                "--url and --max-bytes require --speedtest, --only-speedtest, or --iperf3".into(),
            ));
        }
        if let Some(url) = &self.url {
            if !Endpoint::parse(url)?.tls && !self.allow_http {
                return Err(Error::Config("plain HTTP requires --allow-http".into()));
            }
        }
        if self.list_nodes && self.format != Format::Json {
            return Err(Error::Config("--list-nodes uses JSON".into()));
        }
        if (self.route || self.benchmark) && self.format == Format::Csv {
            return Err(Error::Config(
                "traceroute/benchmark requires text or JSON output to preserve hop details".into(),
            ));
        }
        if self.enrich_provider.is_some() && (self.list_nodes || self.format == Format::Csv) {
            return Err(Error::Config("remote enrichment requires a measurement run with text or JSON output to retain per-IP status and attribution".into()));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn resolved(args: &[&str]) -> Cli {
        let matches = Cli::command().try_get_matches_from(args).unwrap();
        Cli::from_matches_with_defaults(&matches).unwrap()
    }
    #[test]
    fn default_preset_and_overrides_are_explicit() {
        let default = resolved(&["x"]);
        assert!(default.benchmark);
        assert_eq!(default.format, Format::Text);
        assert_eq!(default.enrich_provider, Some(Provider::RipeStat));
        assert_eq!(
            (
                default.count,
                default.parallel,
                default.rate,
                default.max_nodes
            ),
            (25, 8, 50, 32)
        );
        assert_eq!(
            (default.max_hops, default.probes_per_hop, default.timeout_ms),
            (16, 1, 500)
        );
        assert!(!default.speed_enabled());
        assert!(default.validate().is_ok());
        let custom = resolved(&[
            "x",
            "--benchmark",
            "--nodes-file",
            "nodes.tsv",
            "--count",
            "30",
            "--parallel",
            "4",
            "--rate",
            "10",
            "--format",
            "json",
            "--no-enrichment",
        ]);
        assert_eq!((custom.count, custom.parallel, custom.rate), (30, 4, 10));
        assert_eq!(custom.format, Format::Json);
        assert!(custom.enrich_provider.is_none());
        let explicit = resolved(&["x", "--target", "127.0.0.1"]);
        assert!(!explicit.benchmark);
        assert_eq!(explicit.format, Format::Json);
        assert!(explicit.enrich_provider.is_none());
        let filters = resolved(&["x", "--v6", "--province", "lab"]);
        assert!(filters.benchmark && filters.v6);
        let metadata = resolved(&["x", "--enrich-max-requests", "5", "--enrich-rate", "1"]);
        assert_eq!(metadata.enrich_provider, Some(Provider::RipeStat));
        assert_eq!(metadata.enrich_max_requests, 5);
    }
    #[test]
    fn cli_bounds_and_conflicts() {
        for args in [
            vec!["x", "--target", "127.0.0.1", "-c", "0"],
            vec!["x", "-p", "32"],
            vec!["x", "--v4", "--v6"],
            vec!["x", "--route", "--only-speedtest"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
        let cli = Cli::try_parse_from(["x", "--target", "127.0.0.1"]).unwrap();
        assert_eq!(cli.count, 30);
        assert_eq!(cli.size, 0);
        assert!(cli.validate().is_ok());
    }
}

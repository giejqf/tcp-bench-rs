# Default benchmark (v0.2)

Running the native executable or launcher without arguments runs a bounded
benchmark and prints a readable terminal report. `--help` only prints help.
The preset is also implicit with selection controls such as `--v4`, `--v6` or
`--province` when no explicit source/specialized mode is selected. `--benchmark`
enables it with `--target`, `--nodes-file` or `--nodes-url` overrides.

| Setting | Preset default |
| --- | --- |
| Catalog | `https://tcpquality.ibsgss.uk/getNodes?format=tsv&scope=cdn` |
| Selection | Up to 32 unique primary IP/port pairs, round-robin across family/ISP groups |
| Parallelism | 8 active nodes |
| Quality | 25 TCP SYN probes per node; standard IP size 40/60 bytes |
| Large packets | Separate 25-probe, 1200-byte IPv4 SYN measurement |
| Traces | Native outward TCP and UDP, up to 16 hops, one probe/hop |
| Pacing/timeout | Globally at most 50 probes/s, 500 ms per attempt |
| Total budget | 300 seconds including discovery, measurement and enrichment |
| Enrichment | RIPEstat BGP-origin ASN and organization, after measurements |
| Output | Readable text; `--format json` or `--json-output FILE` retain per-probe records |

All existing explicit flags override preset defaults. `--max-nodes` expands or
reduces the sample; report metadata states selected versus matching node counts.
Selection is deterministic in service order within each family/ISP group, not a
random or statistically representative sample. No province/ISP classification
tables or endpoint datasets from the GPL reference are bundled.

Use `TCP_BENCH_NODES_URL` to configure the catalog for a no-argument run, or
`TCP_BENCH_NODES_FILE` for a local TSV (file takes precedence over the environment
URL). Explicit CLI sources override both environment variables. Network retrieval
uses the existing bounded TLS/TSV discovery engine and optional expiring cache.
Service availability/access is not guaranteed. Discovery failure is an explicit
error with instructions to supply another source; there is no invented fallback
dataset. The provider sees your connection IP. Catalog contents are read at runtime,
not redistributed with the application. Existing provider terms still apply.

Raw capability checks occur before fetching the catalog. Linux CAP_NET_RAW or root
is required; no automatic sudo, firewall or routing changes. Each selected address
gets a local UDP socket route-selection check without sending a packet. Addresses
without a usable local route are reported as skipped; this is not a global Internet
reachability claim and does not convert filtering/timeouts into skipped results.
If every node is skipped, the process exits 1. Missing measurements are never zero.

Standard and large SYN results remain separate. Traces are labeled **outward**;
they do not claim genuine reverse-path measurements. A large SYN can be treated
differently by a destination even when ordinary SYNs work. A completed partial path
does not prove a fault. The report shows hop timings and metadata, not proprietary
route classifications. Speed tests remain explicit and require a byte budget.
No results are uploaded and no ranking service is contacted.

## Default enrichment

The reference's normal report uses ASN/organization metadata. As requested, this
preset includes remote ASN enrichment without requiring a token. Public target and
responding-hop IPs are sent to RIPEstat; private/nonpublic addresses are skipped.
Local `--enrichment-file` records take precedence. Request count, response size,
rate, timeout, cancellation and optional cache bounds remain enforced. The shared
wall budget may leave some lookups cancelled; these states stay visible.

Use `--no-enrichment` to disable remote lookups, or `--enrich-provider` to select
IPinfo Lite/custom JSON. RIPEstat does not supply city/country information through
this adapter, and BGP origins do not establish router ownership. Multiple origins
remain explicit. See [provider schemas, usage terms and attribution](remote-enrichment.md).

## Examples

```sh
# Default benchmark, metadata and text report (Linux with CAP_NET_RAW/root).
tcp-bench-rs

# Same preset with full JSON sidecar and fewer nodes.
tcp-bench-rs --max-nodes 12 --json-output report.json

# Explicit offline lab selection; disables remote enrichment.
tcp-bench-rs --benchmark --nodes-file examples/nodes.tsv --no-enrichment \
  --count 3 --max-hops 3 --budget 10

# Keep the existing single-target measurement semantics and JSON default.
tcp-bench-rs --target 127.0.0.1 --count 3 --budget 10
```

Text rendering escapes terminal control/bidirectional formatting characters from
external labels and metadata. JSON v1 adds `benchmark`, per-node `large_quality`,
`unresolved_backup` metadata where needed, and a `skipped` measurement status.
`--json-output` creates a new file and refuses overwrite, independently of `--output`.
The human report summarizes quality probes; the sidecar retains each observation.

## Validation boundary

`TCP_BENCH_BENCHMARK_LAB=loopback cargo test --locked --test default_benchmark -- --ignored`
requires Linux CAP_NET_RAW and uses only loopback: at most 80 probes for a true
no-argument run and 10 for the custom-enrichment/JSON-sidecar test. CI explicitly
gates these tests. They never fetch the public catalog or metadata services.
Independent tests cover selection, overrides, prefix validation/multiple origins,
terminal escaping, and absent-versus-zero values. Catalog schema and one RIPEstat
response are checked separately without running a public benchmark.

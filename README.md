# tcp-bench-rs

A single native executable for TCP SYN quality measurements, outward traceroute,
and bounded single-stream HTTPS/iPerf3 transfers, with optional remote enrichment.
Apache-2.0. Linux is the raw measurement platform; discovery, reports, enrichment,
HTTP/TLS and iPerf3 also work on macOS.

This is an independent implementation with a documented subset of TcpQuality's
interfaces. It does not execute measurement helpers, install software, change
firewall/routing settings, or upload results without `--upload-report`. The default benchmark fetches a node catalog
and ASN metadata; see the documented sources and opt-out controls.
It does not claim full TcpQuality, NextTrace, or iPerf3 compatibility.

## One-command Linux entry point

On Linux x86-64 or ARM64 with **glibc 2.35+** (Bash, curl, GNU tar and coreutils):

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/giejqf/tcp-bench-rs/main/runTcpBench.sh)
```

With no arguments this runs the default benchmark and prints a readable report:
standard SYN quality, a separate IPv4 1200-byte SYN check, outward TCP/UDP traces,
and ASN/organization enrichment. Run from a root shell or use an installed binary
with CAP_NET_RAW. `--help` shows help without starting a benchmark.

From an ordinary user account, use a pipe when invoking `sudo`:

```sh
curl -fsSL https://raw.githubusercontent.com/giejqf/tcp-bench-rs/main/runTcpBench.sh | sudo bash -s -- --upload-report
```

Omit `--upload-report` to keep results local. Do not prepend `sudo` to the
process-substitution form: sudo normally closes its `/dev/fd/...` descriptor.

The preset selects up to 32 nodes from TcpQuality's configurable `getNodes` CDN
catalog, interleaved by family and ISP, with 25 probes/check and a five-minute
budget. RIPEstat metadata lookups are enabled; use `--no-enrichment` to disable them.
It sends no results to reporting/ranking services and runs no speed test by default.
See [default benchmark](docs/default-benchmark.md) for bounds and service terms.

To measure a specific target instead:

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/giejqf/tcp-bench-rs/main/runTcpBench.sh) \
  --target 127.0.0.1 --count 3 --budget 10
```

Speed-only tests need no root. For a cooperating local iPerf3 server:

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/giejqf/tcp-bench-rs/main/runTcpBench.sh) \
  --target 127.0.0.1 --iperf3 --iperf-direction both \
  --max-bytes 65536 --duration 2 --budget 10
```

The launcher downloads only this application's release archive and checksum over
HTTPS, verifies SHA-256, runs it from a private temporary directory and cleans up.
It forwards arguments and exit status, leaves stdout for the selected report format, and
never invokes sudo or changes capabilities. Node selection and the benchmark run in Rust.
It does not install anything persistently or check for updates. The native
executable still performs every measurement itself. See [launcher and releases](docs/launcher.md)
for pinned URLs, manual installation and release verification.

## Build from source

Stable Rust **1.85 or newer**, a C compiler, and the platform linker are required
at build time. TLS uses Rustls with ring, which includes C/assembly compiled from
source. See [architecture](docs/architecture.md) and the
[dependency license inventory](third-party/README.md).

```sh
cargo build --release --locked
./target/release/tcp-bench-rs --help
```

The resulting executable needs no helper programs. It uses normal OS networking,
the system resolver when discovery URLs require DNS, and bundled WebPKI trust
anchors. Ship `LICENSE`, `NOTICE`, and `third-party/` with binary distributions.

## Examples

The examples below use explicit targets instead of the default preset. They target loopback;
replace them with addresses you are authorized to measure. Raw measurements need
Linux `CAP_NET_RAW` in the active network namespace. Grant that capability to the
installed executable using your normal deployment tooling, or run it as root.
Discovery, enrichment and speed-only transfers require neither privilege.

```sh
# 5 real SYN packets, at most 10 globally per second, total budget 10 seconds.
tcp-bench-rs --target 127.0.0.1 --port 443 --count 5 --budget 10

# Native outward traces. Also accepts tcp, udp, and icmp separately.
tcp-bench-rs --target ::1 --route --route-protocol both --max-hops 5 --budget 10

# IP total length, including IP and TCP headers; payload is present above 40/60 B.
tcp-bench-rs --target 127.0.0.1 --count 5 --size 1400 --budget 10

# Offline discovery/selection requires no raw-socket capability.
tcp-bench-rs --nodes-file examples/nodes.tsv --v4 --province lab --list-nodes

# Explicit configurable service, bounded fetch, optional on-disk cache.
tcp-bench-rs --nodes-url https://nodes.example.test/getNodes --scope cdn \
  --cache nodes-cache.json --cache-ttl 300 --list-nodes

# HTTPS download pinned to 192.0.2.10; SNI, certificate and Host use fixed.test.
# This illustrative host/IP needs to be replaced by your own download endpoint.
tcp-bench-rs --target 192.0.2.10 --only-speedtest \
  --url https://fixed.test/data --max-bytes 10485760 --duration 5 --budget 15

# Native iPerf3 TCP against an existing local server, upload then download.
tcp-bench-rs --target 127.0.0.1 --iperf3 --iperf-direction both \
  --max-bytes 65536 --duration 2 --budget 10
```

Use `--speedtest` to append a download after SYN probes. `--max-bytes` is required
and applies **per selected node and direction**. `--allow-http` explicitly permits HTTP for a
local lab or an intentionally unencrypted service. HTTPS certificate verification
cannot be disabled. There are no redirects, proxies, or automatic transfer retries.

iPerf3 defaults to a 1 Mbit/s pacing target; explicitly choose `--iperf-bitrate 0`
for an unlimited speed test within the byte/time budgets. Only single-stream TCP
is supported. See [iPerf3 controls and accounting](docs/iperf3.md).

The default preset includes RIPEstat ASN/organization metadata. For explicit-target
runs, metadata remains opt-in. Choose `--enrich-provider ipinfo-lite` with an
`IPINFO_TOKEN` environment variable, or a user-configured JSON endpoint. This
discloses requested target/hop IPs to that provider after measurements; nonpublic
addresses are skipped by default. Local metadata takes precedence. See
[enrichment, privacy, cache and provider terms](docs/remote-enrichment.md).

The default benchmark prints text; explicit-target runs keep JSON by default
(`schema_version: 1`). Use `--format text|json|csv` to select output, or
`--json-output report.json` to save complete per-probe data alongside the text report.
Diagnostics/progress go to stderr. CSV is a quality/throughput subset; traces and
remote enrichment require text or JSON.
`--output PATH` creates a new report and refuses existing files. SIGINT, SIGTERM,
or the total `--budget` stop work and retain measurements already obtained.

## Documentation and checks

- [Compatibility, flags, node schema, and limitations](docs/compatibility.md)
- [Measurement definitions and report fields](docs/measurements.md)
- [Architecture, platform boundaries, and dependencies](docs/architecture.md)
- [Deterministic tests and isolated Linux lab](docs/validation.md)

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

Ordinary tests use local servers and independently authored packet fixtures.
Privileged networking tests are ignored unless explicitly selected and gated.

Publish a shareable report with `--upload-report` (opt-in). Use `--json-output report.json`
to retain measurements and the upload receipt locally. See [publication, disclosure and
compatibility details](docs/report-upload.md).

In v0.3.1, hosted ASN cells show `out AS…` (observed outward hop) or `dst AS…`
(destination lookup), with explicit unavailable states. Older uploaded reports
need a new run to replace the v0.3.0 `Hidden` placeholders.

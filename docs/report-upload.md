# Report publication

`--upload-report` opts into TcpQuality-compatible report publication. The normal
benchmark and explicit-target runs never upload without this flag. From an ordinary
Linux account, use:

```sh
curl -fsSL https://raw.githubusercontent.com/giejqf/tcp-bench-rs/main/runTcpBench.sh | sudo bash -s -- --upload-report --json-output report.json
```

If already root, omit `sudo`. The JSON file is owned by the user running the
benchmark (root in the example). Avoid `sudo bash <(curl ...)`: sudo normally
closes the process-substitution descriptor. See [launcher instructions](launcher.md).

The service receives the CSV measurements, target names/addresses, route traces
(including source and responding-hop IPs, available ASN metadata and attribution),
and transfer diagnostics when present.
It also sees the uploading connection's public address. Reports may be public;
only upload data you intend to share. `--debug` additionally publishes the complete
native JSON report, including probe samples, metadata/provider attribution and
configured transfer URLs. No credentials, arbitrary local files or environment
contents are collected. Enrichment providers' terms continue to apply to their data.

The client displays the returned report URL and records the receipt in JSON v1's
additive `upload` field. `todayUses`, `totalUses`, `rankUpdated` and
`rankRejectReason` are preserved if the server supplies them. A partial attachment
failure retains the report URL and per-attachment status. Upload failures produce
exit status 1 and leave local measurement output available. This also applies to
`--json-output`/`--output` (new files only). The reported measurement elapsed time
excludes publication.

## Wire contract

The independently implemented adapter follows the observable upload interface of
TcpQuality commit `6017af3fcb83b300b9a15b058d58062551d1c682`:

- `POST /generate`, UTF-8 CSV with BOM, `Content-Type: text/csv; charset=utf-8`,
  and the reference's 18 column names/order. This adapter is separate from our
  native `--format csv` export. Quality, separate large-packet results, and speed
  measurements retain their distinct meanings. Speed values use decimal Mbit/s.
- `X-Report-Time` uses the measurement start time in UTC+8 with a `CST` suffix.
  `X-TcpQuality-Rank-Finished-At` uses RFC3339 UTC.
- `X-TcpQuality-Public-IPv4`/`IPv6` are empty unless supplied with
  `--report-public-ipv4`/`--report-public-ipv6`. There are no automatic public-IP
  lookup requests. `X-TcpQuality-Rank-Disabled-Reason` is
  `tcp-bench-rs-report-only`; no ranking session/token is requested or sent.
- The JSON response must contain a bounded safe `id` and HTTP(S) `url`.
- Route bundles are posted as `application/gzip` to
  `/route-traces/{id}.{section}.tar.gz`; sections include `ipv4`, `ipv6`,
  `cernet_ipv4`, and `cernet2_ipv6` when available. Manifests retain `reportId`,
  `section`, `prefix`, `generatedAt`, and `traceFiles`.
- Transfer diagnostics use `/speedtest-debug/{id}.tar.gz`; `--debug` also sends
  `/probe-debug/{id}.tar.gz`. Tar/gzip creation and HTTP/TLS run inside Rust.

Native trace/diagnostic JSON is deliberately identified as `tcp-bench-rs` data,
with outward direction labels. It is not a fabricated NextTrace/nping log format.
No large-packet trace is synthesized from a normal trace. Unknown route
classifications use the service's `Hidden` marker. Missing measurements stay
empty/`SKIP`, never measured zeros. Unknown remote retransmissions are not derived
from local counters. The hosted renderer decides how to present these values;
this does not claim identical SVG layout or proprietary route classifications.
Ranking participation and its particular speed-test workflow remain unsupported.

## Configuration and bounds

`--report-url https://HOST/PREFIX/generate` overrides `TCPQUALITY_REPORT_API`,
which overrides `https://tcpquality.ibsgss.uk/generate`. Setting the environment
variable alone does not opt in. Endpoints must end in `/generate`, without a query
or credentials. Attachment endpoints are derived from this configured endpoint,
never from server-returned links. `--no-rank-upload` conflicts with
`--upload-report`; help/version/list-nodes never publish.

HTTPS and normal certificate validation are required unless `--allow-http` is
explicitly supplied for a local test service. Redirects and proxies are disabled.
The client supports IPv4 and IPv6 service connections instead of forcing IPv4.
The overall upload deadline is `--upload-timeout` (default 30, maximum 120 seconds),
also limited by the remaining `--budget`. Ctrl-C/SIGTERM cancel pending uploads.
CSV is capped at 2 MiB, attachment content at 16 MiB total, each response at 64 KiB,
and HTTP response headers at 32 KiB. Archive paths are generated, regular files
only, with no filesystem traversal or extraction. Compression buffers are bounded.

There are no automatic POST retries: a lost response can occur after the server
has already created a public report, and the observed protocol has no idempotency
key. An interrupted request may therefore have published a report even if the
client has no receipt. This is an intentional difference from the shell client's
retry behavior. The original service's availability and acceptance policies remain
outside this client's control.

## Validation

`cargo test --locked --test report_upload` uses independently authored fixtures and
local HTTP servers to check headers, CSV, decoded tar/gzip contents, receipt
validation, no-retry errors, timeouts, cancellation, CLI opt-in and retained output.
The existing TLS tests exercise the shared HTTP transport and certificate checks.
No report is submitted to the public service by development tests or CI; hosted
SVG rendering and server-side retention are not validated by these tests.

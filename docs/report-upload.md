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
No large-packet trace is synthesized from a normal trace. Since v0.3.1 the
CSV route cell carries a compact evidence label:

- `out AS<number>`: the known ASN at the greatest responding hop limit in an
  eligible outward trace. For SYN results the trace must use TCP, the same
  packet size and destination port. Route-only runs prefer TCP, then UDP, then
  ICMP. This is a single observed hop, not a complete AS path or a backbone
  classification; the native JSON retains every hop and provider attribution.
- `dst AS<number>`: destination-IP ASN when no eligible enriched trace observation
  is available. This can also label a large-packet result when only a standard
  trace exists; it does not claim a large-packet route was measured.
- `ASN unavailable`, `ASN timeout`, `ASN limited`, `ASN denied`, `ASN cancelled`,
  `ASN unknown`, `ASN error`, or `N/A`: explicit metadata availability/reasons.
  Multiple BGP origins without a single ASN are not reduced to an invented ASN.

The hosted renderer converts `Hidden` and `NoData` to `failed`. Version 0.3.0
always sent `Hidden`, discarding successful enrichment from the displayed cells.
Version 0.3.1 avoids both sentinels. Labels do not change quality status, loss,
RTT or missing values: missing measurements remain empty/`SKIP`, never zeros. Unknown remote retransmissions are not derived
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
Automated development tests and CI never submit to the public service.
For the v0.3.1 fix, a one-off nine-row synthetic CSV (documentation IP 192.0.2.1,
private ASNs 64500/64501, ranking disabled, no probes) was submitted and read back
from the hosted renderer. It confirmed that `Hidden`/`NoData` display as `failed`
and that `out AS64500`, `dst AS64500`, `ASN unavailable` and `N/A` are retained.
The check sent an explicit synthetic-test time header, but the service replaced
that unrecognized header value with its own report timestamp. No hosted HTML or
provider datasets are bundled as test fixtures. Server-side retention is not
validated. Regression tests use independently authored local data.

Already-published v0.3.0 reports retain their stored values. Run v0.3.1 with
`--upload-report` to create a corrected report; existing reports are not rewritten.

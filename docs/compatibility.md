# Compatibility contract, version 0.2

Interface observations used the separate `../TcpQuality` checkout at commit
`6017af3fcb83b300b9a15b058d58062551d1c682`. Only CLI, serialized field meanings,
node schema, and observable defaults were inspected. Its GPL source, comments,
classification tables, tests, and server datasets were not incorporated here.
The checkout and its license remain untouched.

The reference README says an unspecified size is random; its core source and
help use **0 (empty SYN)**. This implementation follows that observed default.

## CLI

| Interface | Behavior here |
| --- | --- |
| no arguments / `--benchmark` | Bounded catalog-based SYN/large-SYN/TCP+UDP trace preset, default RIPEstat metadata, text report; see default-benchmark.md |
| `-h`, `--help`, `--version` | Native help/version; no networking |
| `-c`, `--count` | 1–600, default 25 in benchmark, 30 otherwise |
| `-s`, `--size` | IP total bytes, 0–65535, default 0; smaller sizes raised to protocol minimum |
| `-p`, `--parallel` | 1–31 active nodes, fixed default 4; no memory-based auto-tuning |
| `-v4`, `--v4`, `-v6`, `--v6` | Filter family; conflicting choices rejected |
| `--province TEXT` | Repeatable exact match against the TSV province; no translated aliases |
| `--only-large` | IPv4 only; requires an explicit size above 40 bytes |
| `--cernet` | Select `cernet`/`cernet2` records from the supplied node set |
| `--route` | Outward hop discovery only; no loss run or upload |
| `--route-protocol` | `tcp` (default), `udp`, `both`, plus native `icmp` |
| `--max-hops`, `--probes-per-hop` | 1–255 (default 30), 1–10 (default 3) |
| `--port` | Explicit target port, default 5201 with `--iperf3`, otherwise 443; node records retain their own ports |
| `--speedtest`, `--only-speedtest` | Append/only HTTP(S) download or native iPerf3 for `iperf3` nodes |
| `--url`, `--max-bytes`, `--duration` | Explicit URL override, required byte budget, default 10 seconds of body transfer |
| `--no-rank-upload` | Accepted; already the unconditional behavior |
| `--debug` | Progress on stderr; no raw packet or credential logging |
| `--iperf3` | Native single-stream TCP; implies speed-only unless `--speedtest` is also set |
| `--iperf-direction`, `--iperf-bitrate` | upload/download/both (default download); pacing bits/s (default 1 Mbit/s, 0 unlimited) |
| `--enrich-provider` | RIPEstat (default benchmark), IPinfo Lite or custom JSON; --no-enrichment disables remote lookups; see remote-enrichment.md |
| `--all`, `--intl` | Unsupported service catalogs; explicit targets/node files still work |
| `-bj` and other province shorthands | Unsupported; use `--province` matching node data |

Native controls include `--target` (repeatable IP literal), `--nodes-file`,
`--nodes-url`, `--scope`, `--list-nodes`, `--cache`, `--cache-ttl`, `--retries`,
`--rate`, `--timeout-ms`, `--budget`, `--setup-timeout`, `--allow-http`,
`--enrichment-file`, `--format`, and `--output`. See `--help` for bounds.
Unknown flags are errors. `--scope` affects the discovery request only; `--cernet`
and family/province flags filter the returned data. Omitting a source selects the configurable TcpQuality getNodes URL; omitting both
a source and a specialized mode selects the benchmark preset. Explicit inputs
retain their existing JSON/measurement behavior unless --benchmark is selected.

## getNodes adapter

Remote requests add `format=tsv&scope=SCOPE` to a configured base URL. Supported
scope identifiers are `cdn`, `v4`, `v6`, `cernet`, `all`, `tos`, `apple6`, and
`telegram`. Existing `format`/`scope` query parameters are rejected. This describes
request construction, not a guarantee that any particular service accepts a scope.

UTF-8 records use these positional columns:

| Position | Meaning |
| --- | --- |
| 1–4 | type, family (`4`/`6`), province, ISP |
| 5–8 | hostname, primary IP, primary port, target URL/path/provider identifier |
| 9–12 | backup hostname, IP, port, target |

A 12-column header beginning with `type` is optional. Eight-column primary-only
records and twelve-column records with empty backup fields are accepted. Blank
lines, `#` comment lines, CRLF, and an initial UTF-8 BOM are supported. Empty fields
stay in their positions. All fields are data, never shell text.

Types: `cdn`, `cernet`, `cernet2`, `telegram`, `tos`, `tosutil`, `speedtest`,
`applecdn`, and `iperf3` (native TCP when speed testing is requested).
CERNET is IPv4 and CERNET2 IPv6. Unknown types and malformed records fail with line
numbers. Primary empty ports default to 80 (as observed in the reference), backup
ports to 443 for CERNET/CERNET2 and 80 otherwise. Explicit zero/invalid ports fail.
Backups with a hostname but no resolved IP are retained in `unresolved_backup`
(host, port, target), with `backup: null`; no implicit DNS resolution or failover
is performed. IP literals must match the family. Broadcast, multicast, unspecified, IPv4-mapped
IPv6, and unscoped link-local IPv6 destinations are rejected. No zone/interface
selection for link-local IPv6 is implemented.

Backups are validated and retained in JSON; **automatic failover is not
implemented**. Measurements report the primary address, so failures cannot be
silently replaced by results from another host. Provider identifiers in `target`
are retained without interpretation. Downloads need an explicit full URL, or a
slash-prefixed path plus hostname; use `--url` for TOS region identifiers. No
provider-specific object paths or proprietary datasets are bundled.

Responses are limited to 2 MiB, 4096 nodes, and 8192 bytes per record. HTTP headers
are limited to 32 KiB/128 fields. Optional disk caching stores URL+scope identity,
a format version, and fetch time; expiry defaults to 300 seconds, max 86400.
`--cache-ttl 0` disables hits. Future-dated, expired, corrupt, or mismatched caches
are not used, including on network failure. Writes use a new temporary file and
atomic rename. No implicit cache location is created. Fetches have a bounded total
per-attempt timeout (default 10 seconds) and at most 3 retries (default 1), with
bounded backoff. Invalid TSV is not retried or cached.

## Reports and deliberate differences

JSON is the native versioned schema. CSV keeps the first eleven quality column
meanings: network category, family, province, ISP, hostname, IP, status, sent,
received, unanswered percentage, mean RTT milliseconds. Native download byte,
bit-rate, local sender retransmission, and error/status columns follow. Proper CSV
quoting preserves commas and quotes. Missing values are empty cells; JSON uses
explicit statuses and nulls. Text cells are data, not spreadsheet expressions;
import them as text in spreadsheet software.

CSV status strings and category values are native identifiers, not a byte-for-byte
replica of the reference's Chinese labels. No route classification, reverse-path
connection/TLS times, or iPerf3 counters are invented. Traceroute requires text or JSON.
Partial/cancelled runs have no loss percentage. A transfer stopped at its explicit
budget retains its actual counted bytes and stop reason.

Native iPerf3 and selectable remote enrichment are detailed in [iperf3.md](iperf3.md)
and [remote-enrichment.md](remote-enrichment.md). JSON v1 adds per-direction
`nodes[].iperf3`, `enrichment_lookups`, and `enrichment_cache_error`; existing
fields keep their meanings. CSV appends separate iPerf3 upload/download counters,
statuses, remote sender retransmissions and errors after the existing 17 columns.

Not implemented: iPerf3 UDP/SCTP/multistream/authentication/server mode, HTTPS upload
throughput, reverse-path tracing, Internet/CDN endpoint catalogs, AS route classification, report uploads,
ranking, automatic updates, automatic backup failover, automatic UDP traces during
quality runs, Paris traceroute, MPLS decoding, PTR lookups, and interactive UI. Plain text reports are supported.
Unknown flags fail. Local and remote enrichment (default in the benchmark preset) are independent
of probes, and no remote reporting is implemented. These
limits mean there is no claim of full TcpQuality or NextTrace compatibility.

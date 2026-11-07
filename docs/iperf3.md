# Native iPerf3 TCP client

`tcp-bench-rs` implements the iPerf3 control and data protocol directly in Rust.
It never launches an iPerf3 executable. It supports one TCP data stream per
session, IPv4/IPv6, upload (client sends), and download (server sends). `both`
runs two independent sessions, upload then download; it is not simultaneous
bidirectional mode. No elevated capability is needed for speed-only sessions.

```sh
# A cooperating local server must already be listening on TCP 5201.
tcp-bench-rs --target 127.0.0.1 --iperf3 --iperf-direction both \
  --max-bytes 65536 --duration 2 --iperf-bitrate 1000000 --budget 10
```

`--iperf3` selects speed-only unless `--speedtest` explicitly appends the transfer
to SYN probes. Its explicit-target port defaults to 5201; `--port` overrides it.
With `--only-speedtest` or `--speedtest`, TSV nodes whose type is `iperf3` select
this engine automatically, using their primary IP and port. Other node types use
HTTP(S). Supplying `--iperf3` forces all selected nodes to use iPerf3. TSV default
port rules remain unchanged, so specify the iPerf3 server port in node records.
The hostname, target string and backup fields are not iPerf3 discovery mechanisms.

`--iperf-direction upload|download|both` defaults to download. `--max-bytes` is
required and applies to **each node and each direction**, up to 1 TiB per session.
`--duration` defaults to 10 seconds, maximum 600. `--iperf-bitrate` defaults to
1,000,000 bits/second per stream; use an explicit `0` for unlimited speed, up to
your byte/time budgets. A nonzero rate is a pacing target, not measured capacity.
Upload pacing allows an initial block of up to 16 KiB; download pacing is requested
from the server. Parallelism controls independent nodes, not streams in a session.

## Protocol and accounting

The client uses a random 37-byte session cookie, a dedicated TCP control connection,
length-prefixed JSON parameters/results (maximum 64 KiB), and a separate TCP data
connection carrying the same cookie. Control states and stream identity are
validated. The negotiation and result exchange each have a whole-phase
`--setup-timeout` (default 10 seconds, maximum 60). Data transfer has a separate
monotonic duration limit. The global budget/cancellation applies to all phases.
Busy, denied, terminated, unexpected-state, truncated, malformed and oversized
responses produce explicit errors. There is no automatic session retry.

`nodes[].iperf3` contains a direction and a `measurement` status for each requested
session. A session that reached data transfer preserves a `Transfer`, even if
data I/O or result exchange subsequently fails:

| Field | Meaning |
| --- | --- |
| `protocol`, `direction`, `peer` | `iperf3_tcp`, local upload/download direction, selected peer |
| `stream_bytes` | Application bytes successfully written/read on the local data socket |
| `stream_seconds`, `bits_per_second` | Data phase including pacing/waiting; bytes × 8 / seconds |
| `setup_ms`, `requested_bitrate` | Negotiation duration and requested pacing target |
| `stop_reason` | `byte_limit`, `duration_limit`, `cancelled`, or `error` |
| `tcp_before`, `tcp_after`, `local_sender_retransmissions_delta` | Local data-socket TCP_INFO; unavailable fields stay null |
| `server` | Separately reported peer role, bytes, timing, bit rate and sender retransmissions |
| `result_exchange`, `error` | `complete`, `not_attempted`, `cancelled`, or `error`, with error context |

Upload bytes accepted by the local kernel are not proof of delivery. Download
bytes count only bytes read by the application. Peer counters can differ because
of in-flight/buffered data and control/data timing; they never replace local
counts. The exact local byte ceiling excludes headers, cookies and control JSON.
The server can transmit buffered data beyond that ceiling. Native CPU utilization
is unmeasured; only an unavailable sentinel is sent on the control channel.

Remote retransmissions are populated only for download sessions whose server
advertises sender retransmission support. They are not inferred from local
TCP_INFO. Old servers may omit timing; their rate remains null. The legacy
unsigned encoding of an unavailable retransmission sentinel is treated as missing,
never as a large count. Server result fields are untrusted, validated observations.

## Sources, validation and limits

Independent implementation based on ESnet's
[protocol state description](https://github.com/esnet/iperf/wiki/IperfProtocolStates)
and observed control fields in official
[3.12](https://github.com/esnet/iperf/tree/3.12/src) and
[3.18](https://github.com/esnet/iperf/tree/3.18/src) interfaces. No implementation or
tests were copied. No upstream C library is linked or bundled.

Interoperability tests passed against upstream 3.12 and 3.18 servers in isolated Linux
container: IPv4 and IPv6, upload and download, byte and duration stops. Each
session has a 1 Mbit/s target and at most 1 MB/2 seconds of data budget.
Independent local mock servers additionally exercise fragmented frames, exact
byte accounting, directional counters, stalls, cancellation, busy responses,
malformed results and CLI selection. See [validation](validation.md) to reproduce.

Not implemented: UDP, SCTP, multiple data streams per session, simultaneous
bidirectional transfers, authenticated iPerf3 endpoints, server mode, omit/warmup
intervals, zero-copy transfers and per-interval reports. This is a tested subset,
not a claim of full iPerf3 compatibility or throughput at every hardware line rate.

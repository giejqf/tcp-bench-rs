# Measurements and JSON v1

The v0.2 [default benchmark](default-benchmark.md) combines standard/large SYN
measurements and outward traces, then adds ASN enrichment and readable text output.
Explicit-target modes retain their prior JSON default. The same definitions below
apply to both modes; `large_quality` remains separate from `quality`. Skipped local
routes have a `skipped` status/reason and no invented RTT or loss values.

## SYN quality

Each attempt emits one actual TCP SYN. It does not connect, retry, or substitute
connect timing. Packet size includes the complete IP datagram: 20-byte IPv4 or
40-byte IPv6 header plus a 20-byte TCP header without options. `--size 0` is thus
40 or 60 bytes; smaller explicit values clamp to the minimum. Bytes above that
are deterministic payload carrying the probe identity. IPv4 DF and IPv6 DONTFRAG
prevent silently converting a large probe into fragments; MTU errors are reported
as send failures or matched ICMP packet-too-big messages.

RTT uses a monotonic clock immediately before the successful send syscall through
userspace receipt/correlation. It includes local syscall/receive scheduling and is
not a hardware timestamp. Rate-limit waits and raw-socket writability waits do not
inflate RTT. The receive deadline starts at that send timestamp; sending has its
own bounded timeout. One request is outstanding per node, and the global paced
gate bounds emission across nodes. The default is 10 packets/second, max 1000.

TCP replies must match both addresses, both ports, ACK, flags, and checksum or
kernel checksum metadata. ACK must cover the SYN alone or the entire SYN payload;
only SYN/ACK or RST/ACK are endpoint replies. ICMP errors must quote the original
IP tuple and first eight transport bytes (ports+sequence for TCP, ports+length+
checksum for UDP, type/code/checksum+identifier/sequence for echo). Checksums are
computed using the appropriate pseudoheaders. AF_PACKET auxiliary data distinguishes
pending/validated checksum offload from malformed packets. IPv4 options and bounded
IPv6 extension chains are parsed; fragments requiring reassembly and jumbograms
are rejected. A late reply belongs only to its original identity; duplicates cannot
complete a second attempt. No IP classification table is involved.

The bound unconnected source socket reserves the local port against ordinary TCP
connections. Linux normally sends RST for the unsolicited SYN/ACK; this application
does not suppress those resets or alter the host firewall. Large SYN payloads can
be ignored/dropped by peers or middleboxes; this is distinct from an empty SYN.

`attempted` counts recorded attempts, including send errors. `sent` excludes send
errors. `received` counts matched endpoint replies (SYN/ACK **and** RST/ACK), not
ICMP errors. `timeouts`, `icmp_errors`, `send_errors`, and `cancelled` remain distinct.
A cancelled in-flight send that was confirmed sent is recorded as cancelled, with
null RTT. For a completed run with sent > 0, `unanswered_percent = 100 * (sent -
received) / sent`. It is null for no sends or cancelled observations. This is an
unanswered-probe ratio, **not proof of network congestion or end-to-end packet
loss**; filtering, rate limits, and local capture drops can all cause nonresponse.

RTT min/mean/max and population standard deviation use endpoint replies only.
Welford's algorithm computes variance; all durations are milliseconds. No replies
means null RTT fields, while an actual measured zero stays zero.

## Traceroute

TTL/hop limit steps from 1 to `--max-hops`. Each hop has separate per-probe outcomes,
addresses, RTTs, and reply kinds. TCP uses the configured destination port. UDP
starts at that port and increments per attempt, wrapping 65535 to 1, to distinguish
minimum-length ICMP quotes even with zero UDP payload. This can change the flow's
load-balanced route; this is not Paris traceroute. ICMP uses a fresh 32-bit
identifier/sequence pair. Minimum UDP/ICMP IP sizes are 28/48 bytes.

Time-exceeded identifies intermediate hops. A TCP endpoint response, ICMP echo
reply, or UDP port-unreachable from the destination sets `reached`. Other errors
are retained without declaring destination success. The current hop is finished
before stopping. Exhausting the hop bound is a valid incomplete path, with
`reached: false`. Cancellation preserves completed hops and observations already
made in the current hop. Trace `direction` is always **outward**: nothing here
measures a genuine reverse path.

## HTTP(S) throughput

A download opens one TCP connection and issues one HTTP/1.1 GET. DNS (if any),
connection establishment, TLS handshake, and response-header receipt share the
setup timeout. TCP destination uses the explicitly selected IP while TLS/SNI and
HTTP Host use the URL hostname. Certificate and hostname verification remain on.
The URL controls the HTTP port. No redirects, connection pool, HTTP/2 multiplexing,
compression, proxy environment variables, transfer retries, or automatic URLs.

`body_bytes` counts decoded HTTP response body bytes delivered to the measurement
loop, not TLS records, TCP/IP headers, chunk framing, retransmitted bytes, or bytes
merely buffered by the OS/TLS layer. The exact application byte ceiling is enforced;
the server/kernel may already have sent additional buffered bytes when the socket
is closed. Transport buffers are bounded independently of object size. Duration
starts after response headers and includes waiting for the first body byte. This
is body-phase throughput, not curl's total-transaction speed metric.

`body_bits_per_second = body_bytes * 8 / body_seconds` in decimal bits/second.
Stops are `eof`, `byte_limit`, `duration_limit`, `cancelled`, or `error`. A duration
limit with zero bytes is an actual measured zero, not a missing setup measurement.
Partial bytes survive a body error/cancellation. Setup failures are separate
measurement errors. Truncated Content-Length/chunked responses fail. Connections
using EOF framing must close cleanly (including TLS close_notify).

Timing fields: `dns_ms`, TCP-only `connect_ms`, optional TLS-only `tls_ms`, and
`headers_ms` from setup start through response headers. DNS uses the OS resolver
for discovery and configured enrichment (transfers always have a selected fixed IP). The caller deadline
cannot interrupt libc's internal DNS worker, but no result is accepted past it.

TCP_INFO samples the same connection before/after body consumption. Linux field
lengths are checked before reading native-endian offsets. Local total retransmission
counter differences account for u32 wrapping. Local RTT and congestion window are
kernel estimates. **Remote sender retransmissions are always null**: downloading
data does not make local counters describe the server's retransmissions. macOS
returns `unsupported_platform`, not zero.

## iPerf3 and metadata

See [native iPerf3 accounting](iperf3.md) for upload/download byte definitions,
separate peer results, pacing, control timeouts and supported protocol modes.
Remote sender retransmissions are available only from the iPerf3 sender's result,
never synthesized from local TCP_INFO. [Remote enrichment](remote-enrichment.md)
describes explicit disclosure, normalized metadata, cache rules and per-IP status.

## Resources and output

Maximum 31 active nodes, 4096 selected nodes, 100000 planned probes, 60000 probes
per library engine, 255 trace hops, 10 probes per hop, 65535 IP bytes per packet,
and 30-second per-probe deadlines. A global wall budget defaults to 300 seconds,
max 3600. Transfer duration is at most 600 seconds and the explicitly supplied
per-node, per-direction application-byte ceiling is at most 1 TiB. Disk/node/enrichment inputs
and HTTP framing are bounded. Report retention grows only to the planned-probe
ceiling; a receiver reuses its 64 KiB packet buffer, and downloads use a 64 KiB
application buffer plus bounded HTTP/TLS buffers. Destination/port socket filters
keep unrelated high-volume TCP traffic out of probe receive queues.

JSON top level: `schema_version`, `application_version`, `started_unix_seconds`,
`elapsed_seconds`, `cancelled`, `nodes`, `enrichment`, `enrichment_lookups`, and
`enrichment_cache_error`. Each node includes original primary/backup metadata,
a `quality` measurement, optional `large_quality`, `traces`, HTTP(S) `throughput`,
and per-direction `iperf3`. Optional `benchmark` metadata records selection/budgets.
Measurement `status` is `not_requested`, `complete` (data is present), `error`,
`unsupported`, or `cancelled`. Present quality/trace data has its own `completion`;
present transfer data has `stop_reason`. Null values never imply zero.

Exit code 0 means a completed measurement run, including observed timeouts and
paths that did not reach a destination. Code 1 means cancellation or a measurement
error (including remote-provider/cache-write failures); code 2 means
CLI/configuration/discovery/privilege/report-output failure.
Machine-readable stdout is separated from stderr diagnostics. A cancelled run
before discovery completes cannot produce target results and exits with an error.

Opt-in publication adds JSON v1 `upload`: `not_requested`, `complete` with the
server receipt and attachment statuses, or an explicit error/cancelled state.
Upload status is independent of measurement success; see [report-upload.md](report-upload.md).

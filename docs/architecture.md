# Architecture and decisions

One Cargo package separates packet codecs, Linux sockets, probe scheduling,
traceroute, node discovery, HTTP/TLS and iPerf3 transfers, TCP statistics, enrichment, and
reporting. All measurements execute in this binary. No subprocesses, executable
downloads, updates, firewall changes, reporting uploads, or ranking participation.

The separately invoked `runTcpBench.sh` is distribution tooling explicitly requested
for one-command setup. It downloads and verifies a pinned application release,
then launches the native executable. This is the sole distribution exception to
the no-download architecture; no helper programs are installed and the Rust
runtime retains the boundaries above. See [launcher.md](launcher.md).

## Dependency exception, recorded before introduction

TLS uses Rustls with the explicitly selected `ring` cryptographic provider, not
its default AWS-LC provider. Ring includes C and assembly compiled from source
at build time. This is a deliberate exception for established TLS cryptography
and performance; this application is **not** an entirely Rust dependency tree.
No OpenSSL shared-library or helper executable is used. Ring's aggregate license
expression is Apache-2.0 AND ISC; its complete upstream license, including embedded
third-party notices, accompanies redistribution. Rustls/WebPKI and root data retain
their original licenses. Locked WebPKI root data is CDLA-Permissive-2.0.
DNS uses Tokio's bounded caller deadline around the OS resolver; the OS resolver
may finish a pending lookup in its blocking worker after cancellation. Fixed-IP
transfers perform no DNS lookup. Kernel networking and libc syscall bindings are
another explicit platform boundary. Build tooling is separate from runtime.

The locked source audit found native sources in ring, C/C++ compiler detection in
the build-only `cc` crate, and Windows import libraries in target-specific packages
that are not built into Linux/macOS binaries. `zeroize` and `zmij` use inline
assembly compiler barriers. No AWS-LC, OpenSSL, libcurl, C DNS library, or external
measurement binary is linked into the Linux application. This inventory is specific
to Cargo.lock; rerun the audit when updating dependencies. 67 dependency packages
(including build and other-target dependencies) have license/notice files retained
under `third-party/`. Unicode-ident's Unicode-3.0 notice is included as well.

## Design

Raw probes have one outstanding request per node and a global paced send gate.
Every request uses a fresh sequence/identity and matches the full address tuple.
Independent nodes run concurrently with a fixed upper limit. This keeps reply
correlation and timeout accounting auditable without an unbounded event table.
TCP source ports are reserved by a bound, unconnected socket. No connection is
established by a SYN probe; Linux's normal TCP stack resets unsolicited SYN/ACKs.
IPv4 packets use IP_HDRINCL; IPv6 raw sockets send transport segments with a
bound source and a kernel-generated IP header. No Ethernet or route-table parser
is needed for transmission. Reception uses non-promiscuous AF_PACKET/SOCK_DGRAM
with classic destination/port filters and PACKET_AUXDATA. This retains IP headers
and kernel checksum-offload status, which plain IP raw receive sockets cannot
reliably provide for local/virtual-network TCP traffic. Invalid checksums without
offload metadata are rejected. Non-Linux raw probing fails explicitly.

HTTPS downloads use one HTTP/1.1 connection, no redirects, compression, proxy,
retries, or connection pool. TLS validates the URL hostname even when the TCP
destination is pinned to an IP. HTTP framing is bounded and decoded incrementally.
TCP_INFO is read from that same connection and reports local sender counters only.
The deliberately limited HTTP client uses the established `http` URI parser and
`httparse` response parser, with a small bounded body-framing layer. Owning the
TCP stream throughout TLS and body consumption makes same-connection TCP_INFO
sampling and an exact application byte ceiling possible without relying on a
general client's hidden pooling, resolver, decompression, or retry behavior.

`iperf3.rs` owns an independently implemented control state machine and one TCP
data stream per session. No upstream library or executable is a runtime dependency.
Local and server-reported statistics remain separate. `enrichment/remote.rs`
contains RIPEstat, IPinfo Lite and custom JSON adapters (RIPEstat defaults on
in the benchmark preset), executed only after the
measurement pass. Provider parsing, disclosure filtering, rate/response/request
bounds and optional caches are separate from packet engines. Bearer authentication
uses the existing HTTP/TLS client with strict header validation and no redirects.
Neither feature adds Cargo dependencies or changes the recorded native-code audit.
See [iPerf3](iperf3.md) and [remote enrichment](remote-enrichment.md) for contracts.

## Protocol sources

Independently written from RFC 791, 792, 768, 8200, 9293, 4443, 3542, and 9112,
plus Linux raw(7), ipv6(7), tcp(7) and linux/tcp.h. Interface observations of the
separate GPL reference are recorded in compatibility.md. No implementation,
classification tables, tests, or bundled service datasets are imported from it.

Primary references: [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html),
[IPv6 socket API](https://www.rfc-editor.org/rfc/rfc3542.html),
[ICMPv6](https://www.rfc-editor.org/rfc/rfc4443.html),
[Linux raw sockets](https://man7.org/linux/man-pages/man7/raw.7.html),
[packet sockets](https://man7.org/linux/man-pages/man7/packet.7.html), and
[kernel checksum offloads](https://docs.kernel.org/networking/checksum-offloads.html).

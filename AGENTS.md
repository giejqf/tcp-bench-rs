# tcp-bench-rs

## Purpose

Build `tcp-bench-rs`, an Apache-2.0 Rust network benchmarking application compatible with the useful interfaces and measurement behavior of TcpQuality. Deliver a single executable that performs its own measurements, including native traceroute functionality comparable to the NextTrace features used by TcpQuality.

The motivation is a small, auditable runtime: no downloaded executables, shell pipelines, rootfs environments, or external measurement programs.

## Repository and licensing boundaries

- This is the standalone `tcp-bench-rs` repository. Place the Cargo manifest and Apache-2.0 `LICENSE` at the repository root, and Rust source files under `src/`. Use package and executable name `tcp-bench-rs` and Cargo license identifier `Apache-2.0`.
- The GPL-3.0-only TcpQuality reference implementation lives in the separate sibling checkout `../TcpQuality`. Preserve its license and notices; the Apache-2.0 decision applies only to the new project.
- Implement from documented protocols, observable interfaces, and independently developed designs. Do not copy or mechanically translate GPL implementation code, comments, tests, or classification tables into the Apache-licensed project. Functional compatibility does not authorize relicensing source material.
- Check dependency and bundled-data licenses before incorporating them. Keep required notices. Do not assume an API's public accessibility grants redistribution rights to its datasets or unrestricted use of its servers.

## Runtime architecture

- Implement application logic and measurement engines in Rust. Compile dependencies from source; keep them minimal, pinned through a committed `Cargo.lock`, and reviewable.
- Do not invoke `curl`, `nping`, `iperf3`, `traceroute`, `nexttrace`, `ss`, `ip`, `tc`, `bpftrace`, package managers, or shell scripts to implement runtime functionality.
- Do not download, compile, install, or execute helper programs at runtime. Do not implement automatic executable updates.
- Prefer Rust implementations for HTTP, TLS, DNS, packet handling, and serialization. Audit transitive dependencies and enabled features for bundled C/C++ or assembly; do not describe a dependency tree as entirely Rust without verifying it. Document any required exception before introducing it.
- Kernel networking and narrow OS syscall bindings are expected. Encapsulate platform-specific and unsafe code behind small interfaces, with documented safety invariants.
- Target Linux first, with IPv4 and IPv6. Keep portable parsing, scheduling, and reporting separate from platform-specific sockets and statistics. Unsupported platforms or capabilities must produce explicit errors.
- Keep node discovery, packet probes, traceroute, throughput, TCP statistics, enrichment, scheduling, and reporting as distinct modules. Start with one Cargo package unless multiple crates serve a concrete need.

## Compatibility contract

- Track compatibility explicitly in project documentation: supported CLI flags, defaults, node schemas, report fields, measurement semantics, and deliberate differences. Verify behavior against the reference source when its README disagrees with the implementation.
- Preserve familiar selection controls such as address family, province, packet count and size, parallelism, route-only mode, and speed-test mode as features are implemented. Reject unsupported modes rather than silently accepting them.
- Support the `getNodes` TSV interface through a configurable URL, including its node types, scopes, IP addresses, ports, and backup fields. Allow a local node file so the engine can run without that service.
- Treat remote node data as untrusted input. Bound response size, validate addresses and ports, and reject malformed records with actionable errors. Never execute values from responses.
- Cache node responses with an explicit expiry and provide bounded timeouts and retries. Keep service-specific adapters out of the measurement engine.
- Preserve CSV field meanings where compatibility is implemented and provide versioned structured JSON output. Distinguish missing measurements, unsupported capabilities, timeouts, and actual zero values.
- Keep report uploads and ranking participation disabled unless explicitly requested. Per the user’s updated requirement, the default benchmark includes ASN enrichment; provide --no-enrichment, disclose the provider, preserve attribution, and keep explicit-target runs opt-in. Document this difference from the original defaults. Never silently transmit results or public-IP metadata to a reporting service.

## Measurement correctness

- TCP quality probes must use actual SYN packets with correct checksums and reply matching. Do not substitute TCP connection timing for SYN RTT or loss without exposing it as a separate measurement mode.
- Match replies using addresses, ports, sequence/acknowledgment information, and quoted packet data as appropriate. Handle late, duplicate, unrelated, truncated, and malformed packets without corrupting results.
- Define packet size precisely, including protocol headers. Preserve the distinction between standard SYN probes and payload-bearing large-packet probes.
- Use monotonic clocks for durations. Define attempt counts, timeout rules, loss denominators, transfer timing, and units explicitly. A timeout alone does not prove congestion or end-to-end packet loss.
- Implement traceroute directly using TTL/hop-limit stepping and ICMP error decoding, with TCP, UDP, and ICMP probe support. Include configurable packet size, port, hop limit, probes per hop, and timeout.
- Keep traceroute independent of enrichment. Hop addresses and timings must work without geolocation or ASN services; enrichment may use explicit remote providers or user-supplied local databases.
- Label trace direction accurately. A local trace observes the outward path; a genuine reverse-path trace requires a cooperating remote system.
- HTTPS throughput must support a fixed destination IP while retaining the hostname for SNI, certificate validation, and HTTP routing. Use a single connection for single-stream tests, stream data with bounded memory, and report actual transferred bytes.
- If supporting existing iPerf3 endpoints, implement and test their control and data protocol in Rust. Arbitrary TCP traffic is not iPerf3 compatibility.
- Read per-connection TCP statistics directly where supported. Respect kernel ABI differences and available field lengths. Local sender retransmissions and remote sender retransmissions are different metrics; do not invent the latter from local counters.
- Avoid changing host firewall rules, routing, or traffic-control settings by default. Features requiring those changes must be explicit, document the effect, and restore state on failure and cancellation.

## Resource and privilege handling

- Bound node concurrency, probe rates, hop counts, retries, transfer duration, transferred bytes, and memory use. Cancellation must stop work promptly and release sockets and tasks.
- Check required privileges early and explain missing capabilities. Use the minimum privileges the selected measurement requires; ordinary API access and HTTPS transfers should not require root.
- Provide explicit targets and budgets for live tests. Do not run bandwidth-heavy tests against public endpoints as part of routine development or CI.

## Development and validation

- Use stable Rust and declare the minimum supported Rust version. Prefer established, maintained crates over unnecessary custom infrastructure, while keeping the dependency policy above.
- Return structured errors from library code. Include useful context in CLI errors and avoid panics on network input. Separate diagnostics from machine-readable output.
- Test packet encoding and checksums, reply correlation, IPv6 handling, malformed inputs, TSV parsing, statistics, and report schemas with independently authored fixtures.
- Use local servers for HTTP, TLS, and protocol integration tests. Keep ordinary tests deterministic and independent of public services.
- Gate privileged Linux network tests explicitly. Use controlled network namespaces or a documented lab to validate hop discovery, loss, delays, retransmissions, and cancellation. Development test tooling is separate from runtime dependencies.
- For compatibility claims, compare schemas and measurement definitions, and use controlled observations with tolerances. Do not require identical timings on a live network.
- Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --locked` from the new project directory when Rust code changes. Run additional feature/platform checks where relevant. Report checks that could not run and why.
- Do not claim full TcpQuality, NextTrace, or iPerf3 compatibility until the relevant paths are implemented and validated. Keep incomplete features explicit in documentation and errors.

## Working conventions

- Make focused changes in this repository. Keep the sibling reference checkout separate and preserve it for comparison.
- Record architectural decisions and compatibility tradeoffs in repository documentation as they arise. Keep this file current when the project structure or requirements change.
- Explain what changed, what was verified, and remaining limitations. Never imply that a successful build alone validates raw networking behavior.

## Current implementation layout

- `src/packet.rs` contains portable codecs/correlation; `src/platform/` owns Linux raw transmission and packet capture, including checksum-offload metadata.
- `src/probe.rs`, `src/traceroute.rs`, and `src/scheduler.rs` implement bounded raw measurements and cancellation.
- `src/nodes.rs`, `src/discovery.rs`, `src/http.rs`, `src/throughput.rs`, `src/tcp_stats.rs`, `src/enrichment.rs`, and `src/report.rs` remain separate concerns.
- `src/benchmark.rs` selects a bounded default catalog sample; `src/report/terminal.rs` renders readable reports. The user authorized default discovery and ASN enrichment; see `docs/default-benchmark.md`. Live development/CI tests must still use explicit local fixtures and budgets.
- `src/iperf3.rs` implements native single-stream TCP upload/download; `src/enrichment/remote.rs` contains explicit IPinfo Lite/custom JSON adapters. Keep protocol/result accounting and remote metadata separate from probes. Their contracts are in `docs/iperf3.md` and `docs/remote-enrichment.md`.
- `docs/compatibility.md` records implemented interfaces and explicit omissions; `docs/measurements.md` defines units, denominators, and JSON v1 semantics.
- `tests/linux_raw.rs` and `tests/routed_lab.rs` are ignored privileged tests. `tests/lab.sh` and `tests/lab.Dockerfile` are disposable development tooling, never runtime dependencies. Follow `docs/validation.md` for their explicit targets, budgets, and isolation.
- Ship `third-party/` notices with binaries. Refresh its locked license inventory and the native-code audit when dependencies change.
- `runTcpBench.sh` is an explicitly requested distribution launcher, separate from the Rust runtime: it downloads a pinned release, verifies its checksum, unpacks notices and runs the application. It must never install measurement helpers, escalate privileges automatically or check for newer versions. `.github/workflows/release.yml` builds/tests native Linux release archives; `tests/launcher.py` tests the launcher offline.

- `src/upload.rs` and `src/upload/` implement opt-in report publication with a separate
  TcpQuality CSV adapter, evidence-based ASN display labels, and native tar/gzip attachments. Keep uploads behind
  `--upload-report`, ranking disabled, and local tests isolated from public services.
  See `docs/report-upload.md` for the wire contract and deliberate differences.

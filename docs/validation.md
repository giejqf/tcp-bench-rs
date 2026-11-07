# Validation and bounded lab tests

Run from this repository, never from the sibling reference:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

The normal suite needs no elevated capabilities or public services. It covers IP
and transport checksums (including an independently calculated golden SYN), IPv6
extension/fragment handling, reply matching, malformed/truncated inputs, node TSV,
cache URL identity/expiry, bounded HTTP framing, local TLS, fixed-IP SNI/Host,
certificate rejection, streaming byte/duration budgets, cancellation, missing/zero
statistics, TCP_INFO lengths, and JSON status/version fields.

Native iPerf3 fixtures exercise independent control/data connections, fragmented
JSON, exact byte ceilings, sender/receiver counters, setup/data/result stalls,
busy/malformed/truncated responses, cancellation and CLI/TSV engine selection.
Remote enrichment fixtures cover IPinfo field mapping, IP matching, nonpublic
filtering, local precedence, cache identity/expiry, response/request bounds,
authentication/rate-limit stops, TLS Bearer headers and explicit CLI opt-in.

## Explicit iPerf3 interoperability tests

Install an upstream iPerf3 **development test server**, then run:

```sh
TCP_BENCH_IPERF_INTEROP=1 cargo test --locked --test iperf_interop -- --ignored
```

Optionally set `TCP_BENCH_IPERF_BIN` to a particular upstream server executable.
This test alone launches that server, bound only to loopback on an ephemeral port.
It exercises IPv4/IPv6 × upload/download × byte/duration stops (eight sessions),
at 1 Mbit/s and at most 1 MB/2 seconds per session. No public bandwidth test is
performed and no raw privileges are needed. Each server process is reaped.
`tests/lab.Dockerfile` includes Debian's iPerf3 3.12 for this purpose. CI runs the
gated test explicitly after installing its distribution's server package.

For the network-isolated Docker environment documented below:

```sh
docker run --rm --network none -e TCP_BENCH_IPERF_INTEROP=1 \
  -v "$PWD:/work:ro" -v /tmp/tcp-bench-vendor:/vendor:ro \
  -v tcp-bench-rs-test-target:/build tcp-bench-rs-lab \
  cargo test --offline --locked --target-dir /build \
  --config 'source.crates-io.replace-with="vendored-sources"' \
  --config 'source.vendored-sources.directory="/vendor"' \
  --test iperf_interop -- --ignored
```

## Explicit loopback tests

Only on Linux, in a disposable test environment with CAP_NET_RAW:

```sh
TCP_BENCH_LAB=loopback cargo test --locked --test linux_raw -- --ignored
```

The gate must be exactly `loopback`; no user-supplied public target is used. Tests
send fewer than 40 packets, max 1400 bytes each, to `127.0.0.1` and `::1`, with
one-second deadlines. They validate SYN/ACKs, RSTs, standard and payload-bearing
SYNs, TCP/UDP/ICMP terminal hops, a nonresponding UDP port, and cancellation.
They leave no firewall/routing changes. Normal tests never run these implicitly.

## Two-hop, delay, loss, and active cancellation lab

`tests/lab.sh` is **development tooling**, not part of the application. It requires
Linux `ip`, `tc`, `sysctl`, and namespace permissions and must run only in the
isolated, disposable container below. It creates two private network namespaces,
veth links, routes and a qdisc; all cleanup is trapped, and container removal is
the final isolation boundary. It never changes the host network namespace.

Topology: source `198.18.0.1`/`fd42::1` → router `198.18.0.2`/`fd42::2` → target
`198.18.0.6`/`fd42:1::2`. TCP/UDP target port is 49199. Tests use 128-byte packets,
at most four hops, two probes/hop, and <=40 total probes. First the router applies
20 ms delay and tests require two discovered hops (RTT tolerance 15–1000 ms).
Then 100% loss verifies timeout accounting and cancellation during a sent probe.
Test assertions do not depend on identical wall-clock timings.

Example from the repository root on a Docker-capable host:

```sh
cargo vendor --locked /tmp/tcp-bench-vendor
docker build -t tcp-bench-rs-lab -f tests/lab.Dockerfile tests
docker run --rm --network none \
  --cap-add NET_RAW --cap-add NET_ADMIN --cap-add SYS_ADMIN \
  --security-opt seccomp=unconfined --security-opt systempaths=unconfined \
  -e TCP_BENCH_ISOLATED_LAB=1 \
  -v "$PWD:/work:ro" -v /tmp/tcp-bench-vendor:/vendor:ro \
  -v tcp-bench-rs-test-target:/build \
  tcp-bench-rs-lab sh tests/lab.sh
```

On macOS, use `/private/tmp/tcp-bench-vendor` for the vendor bind mount if Docker
requires the canonical path. Building the image downloads development dependencies;
the actual test container has **no external network**. Extra capabilities and
system-path access are solely for this disposable namespace lab. The application
itself needs CAP_NET_RAW only. Do not run this script against the host namespace.

For Linux Clippy in the same image, place `--config` after `clippy` so its Cargo
subprocess receives the vendored source configuration:

```sh
docker run --rm --network none \
  -v "$PWD:/work:ro" -v /tmp/tcp-bench-vendor:/vendor:ro \
  -v tcp-bench-rs-test-target:/build tcp-bench-rs-lab \
  cargo clippy --offline --locked --target-dir /build --all-targets \
  --config 'source.crates-io.replace-with="vendored-sources"' \
  --config 'source.vendored-sources.directory="/vendor"' -- -D warnings
```

## Validation record and remaining limits

The iPerf3/enrichment implementation passed 48 deterministic tests on macOS and
47 on Linux, including Linux Rust 1.85. Formatting and Clippy with warnings denied
passed on current Rust. Eight gated interoperability sessions each passed against
Debian iPerf3 3.12 and upstream iPerf3 3.18 (built separately from the official
source tag, with no runtime linkage). Enrichment used only local fixture servers;
live IPinfo account behavior and service availability were not tested.

The initial implementation was tested on macOS and Linux x86_64 with Rust 1.99.1,
and the deterministic Linux suite also passed on Rust 1.85. The Linux loopback
and two-hop labs passed, including all three protocols over both address families,
large SYNs, controlled delay/loss, and active cancellation. The first loopback run
exposed pending checksum offload; reception was corrected to use packet metadata
and the same tests then passed.

This validates bounded local/lab behavior, not all Internet paths, NAT/firewall
combinations, kernel versions, NICs, or performance at line rate. TCP_INFO ABI
decoding and available local counters are checked; controlled retransmission
injection for a throughput connection is not yet covered. No public speed tests,
live service availability claims, or end-to-end TcpQuality/NextTrace timing
equivalence claims are made. Benchmark performance on your deployment hardware.

Dependency review uses `cargo metadata --locked`, `cargo tree -e features`, source
license files, and scans for C/C++/assembly/import libraries and inline assembly.
Recheck licenses/features after any lockfile update, refresh `third-party/`, and
preserve upstream notices. Test fixtures are independently generated; their TLS
test key is public by design.

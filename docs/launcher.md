# Linux launcher and releases

Repository: https://github.com/giejqf/tcp-bench-rs

The one-command distribution entry point is:

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/giejqf/tcp-bench-rs/main/runTcpBench.sh)
```

No arguments starts the [default benchmark](default-benchmark.md), including a
configurable CDN catalog, standard/large SYN probes, outward traces, default ASN
enrichment and a text report. `--help` shows help instead. Append normal CLI
options after the closing parenthesis. `--no-enrichment` disables remote metadata.
No reports are uploaded without `--upload-report`, and no default speed tests run. Raw modes need CAP_NET_RAW
or root; the launcher never escalates privileges itself.

## Reproducible invocation and inspection

For a launcher and binary pinned together to this release:

```sh
bash <(curl -fsSL https://raw.githubusercontent.com/giejqf/tcp-bench-rs/v0.3.0/runTcpBench.sh) \
  --target 127.0.0.1 --iperf3 --max-bytes 65536 --duration 2 --budget 10
```

Alternatively download the script first, inspect it, then run it:

```sh
curl -fSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/giejqf/tcp-bench-rs/v0.3.0/runTcpBench.sh \
  -o runTcpBench.sh
less runTcpBench.sh
bash runTcpBench.sh --help
# For raw probes, explicitly use elevated privileges:
sudo bash runTcpBench.sh --target 127.0.0.1 --count 3 --budget 10
```

`TCP_BENCH_RS_VERSION=vX.Y.Z` explicitly selects another published binary release.
There is no latest-version API request, update check, executable cache or persistent
installation. Each invocation downloads the same pinned version unless selected
otherwise. A future main-branch launcher may pin a newer version; use a tag URL
when the launcher itself must stay fixed.

## Distribution contract

Supported prebuilt targets are `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu`, built natively on Ubuntu 22.04 runners. They require
glibc 2.35+ and normal libgcc/libm runtime libraries. Old glibc, musl/Alpine and
other CPU architectures receive an explicit preflight error; build from source
there. The launcher requires Bash, curl, GNU tar and coreutils. It installs no
packages or measurement helpers and changes no firewall, routing or capabilities.

Each release has, for each target:

```text
tcp-bench-rs-v0.3.0-x86_64-unknown-linux-gnu.tar.gz
tcp-bench-rs-v0.3.0-x86_64-unknown-linux-gnu.tar.gz.sha256
```

The archive contains the single executable, Apache license, NOTICE, all locked
third-party license notices, README and documentation. Downloads require HTTPS
including redirects, with connection/transfer timeouts and bounded retries. The
archive is capped at 32 MiB, the checksum file at 1 KiB. The launcher verifies the
exact expected asset filename and SHA-256 before extracting. Absolute paths,
parent traversal, unexpected paths, duplicate binaries, links and special files
are rejected. Extraction occurs in a new private temporary directory; normal
exit, SIGINT and SIGTERM remove it. Signals are forwarded to the application and
its normal exit status is preserved (launcher errors use 2).

The checksum detects corruption/mismatched assets; it is fetched from the same
GitHub release and is not an independent signature or defense against a compromised
publisher. Downloading and executing the launcher trusts that repository, just as
downloading a release does. Nothing in the Rust measurement runtime invokes curl,
tar, a package manager or a measurement program.

To keep a permanent installation, download the matching archive and `.sha256`
from [Releases](https://github.com/giejqf/tcp-bench-rs/releases), then in the download
directory run, adjusting the target if needed:

```sh
sha256sum --check tcp-bench-rs-v0.3.0-x86_64-unknown-linux-gnu.tar.gz.sha256
mkdir tcp-bench-rs-v0.3.0
tar -xzf tcp-bench-rs-v0.3.0-x86_64-unknown-linux-gnu.tar.gz -C tcp-bench-rs-v0.3.0
./tcp-bench-rs-v0.3.0/tcp-bench-rs --help
```

Keep the license/notice files with redistributed binaries. Repeated tests can
use that executable directly without additional downloads.

## Maintainer workflow

`scripts/package-release.sh VERSION TARGET` packages a tested native binary from
`target/TARGET/release/`, verifies its version matches the tag, includes license
files and writes the archive checksum. The `release` GitHub workflow runs on
version tags, checks formatting, Clippy, deterministic tests, launcher tests and
upstream iPerf3 loopback interoperability on both native architectures. It only
publishes after both jobs succeed. Releases are created once; failed reruns do not
silently overwrite published assets. Existing versions should remain immutable.

Run `bash -n runTcpBench.sh scripts/package-release.sh`, ShellCheck on both scripts,
and `python3 tests/launcher.py` on Linux. The launcher tests substitute local download
fixtures and check argument/status forwarding, no-argument passthrough, unsupported hosts,
checksum failures, invalid archives, notice inclusion, download failures and SIGTERM
cleanup. Real release downloads are smoke-tested separately after publication.

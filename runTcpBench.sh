#!/usr/bin/env bash
# Distribution entry point only. The Rust executable performs all measurements.
set -euo pipefail
umask 077

readonly repository='giejqf/tcp-bench-rs'
readonly version="${TCP_BENCH_RS_VERSION:-v0.3.0}"
temporary=''
child=''

fail() { printf 'tcp-bench-rs launcher: %s\n' "$*" >&2; exit 2; }
# Invoked indirectly by EXIT; older ShellCheck versions miss trap references.
# shellcheck disable=SC2317
cleanup() { if [[ -n "$temporary" ]]; then rm -rf -- "$temporary"; fi; }
# Invoked indirectly by INT/TERM traps.
# shellcheck disable=SC2317
interrupt() {
    local signal=$1 code=$2
    if [[ -n "$child" ]]; then
        kill -s "$signal" "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
    exit "$code"
}
trap cleanup EXIT
trap 'interrupt INT 130' INT
trap 'interrupt TERM 143' TERM

[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'TCP_BENCH_RS_VERSION must be a release tag such as v0.1.0'
for tool in uname getconf curl tar sha256sum mktemp mkdir chmod rm; do
    command -v "$tool" >/dev/null 2>&1 || fail "required tool is missing: $tool"
done
[[ "$(uname -s)" == Linux ]] || fail 'this launcher supports Linux; build from source on other platforms'
case "$(uname -m)" in
    x86_64|amd64) target=x86_64-unknown-linux-gnu ;;
    aarch64|arm64) target=aarch64-unknown-linux-gnu ;;
    *) fail 'supported Linux architectures are x86_64 and aarch64; build from source for other architectures' ;;
esac
libc=$(getconf GNU_LIBC_VERSION 2>/dev/null) || fail 'release binaries require glibc 2.35+; build from source for musl/Alpine'
[[ "$libc" =~ ^glibc\ ([0-9]+)\.([0-9]+)$ ]] || fail "cannot identify glibc version: $libc"
(( BASH_REMATCH[1] > 2 || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] >= 35) )) || fail 'release binaries require glibc 2.35+; build from source on this host'

readonly asset="tcp-bench-rs-${version}-${target}.tar.gz"
readonly base="https://github.com/${repository}/releases/download/${version}"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/tcp-bench-rs.XXXXXXXX") || fail 'cannot create temporary directory'
download() {
    curl --disable --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 180 \
        --max-filesize "$3" --output "$2" "$1" || fail "download failed: $1"
}
printf 'tcp-bench-rs launcher: downloading %s for %s\n' "$version" "$target" >&2
download "$base/$asset.sha256" "$temporary/checksum" 1024
download "$base/$asset" "$temporary/$asset" 33554432
checksum=$(<"$temporary/checksum")
expected=${checksum%% *}
[[ "$expected" =~ ^[0-9a-f]{64}$ && "$checksum" == "$expected  $asset" ]] || fail 'invalid release checksum file'
actual=$(sha256sum "$temporary/$asset")
[[ "${actual%% *}" == "$expected" ]] || fail 'release checksum mismatch; refusing to execute'

# Validate names and types before extraction. No symlinks, hardlinks, devices,
# absolute paths, parent traversal, shell metacharacters or duplicate binaries.
tar -tzf "$temporary/$asset" > "$temporary/members" || fail 'invalid release archive'
tar -tvzf "$temporary/$asset" > "$temporary/types" || fail 'invalid release archive metadata'
binaries=0
while IFS= read -r member; do
    [[ "$member" =~ ^[a-zA-Z0-9_-][a-zA-Z0-9.+_-]*(/[a-zA-Z0-9_-][a-zA-Z0-9.+_-]*)*/?$ ]] || fail 'unsafe archive path'
    case "$member" in
        tcp-bench-rs) binaries=$((binaries + 1)) ;;
        LICENSE|NOTICE|README.md|third-party/|third-party/*|docs/|docs/*) ;;
        *) fail 'unexpected archive member' ;;
    esac
done < "$temporary/members"
[[ "$binaries" == 1 ]] || fail 'release archive must contain exactly one executable'
while IFS= read -r entry; do
    [[ "$entry" == -* || "$entry" == d* ]] || fail 'archive links and special files are forbidden'
done < "$temporary/types"
mkdir "$temporary/unpacked"
tar -xzf "$temporary/$asset" -C "$temporary/unpacked" --no-same-owner --no-same-permissions
[[ -f "$temporary/unpacked/tcp-bench-rs" ]] || fail 'release executable is not a regular file'
[[ -f "$temporary/unpacked/LICENSE" && -f "$temporary/unpacked/NOTICE" && -d "$temporary/unpacked/third-party" ]] || fail 'release license notices are missing'
chmod 700 "$temporary/unpacked/tcp-bench-rs"
"$temporary/unpacked/tcp-bench-rs" "$@" <&0 &
child=$!
status=0
wait "$child" || status=$?
child=''
exit "$status"

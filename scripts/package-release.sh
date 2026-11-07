#!/usr/bin/env bash
# Run after native build/tests on the matching Linux release runner.
set -euo pipefail
version=${1:?usage: package-release.sh VERSION TARGET}
target=${2:?usage: package-release.sh VERSION TARGET}
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
case "$target" in x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;; *) exit 2 ;; esac
binary="target/$target/release/tcp-bench-rs"
[[ -f "$binary" ]]
actual=$("$binary" --version)
[[ "$actual" == "tcp-bench-rs ${version#v}" ]] || { printf 'binary version does not match tag\n' >&2; exit 2; }
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
cp "$binary" "$stage/tcp-bench-rs"
cp LICENSE NOTICE README.md "$stage/"
cp -R third-party docs "$stage/"
mkdir -p dist
asset="tcp-bench-rs-${version}-${target}.tar.gz"
tar -czf "dist/$asset" -C "$stage" tcp-bench-rs LICENSE NOTICE README.md third-party docs
(cd dist && sha256sum "$asset" > "$asset.sha256")

#!/bin/sh
# ONLY inside the disposable container described in docs/validation.md.
# No public destinations, host namespaces, host routes or host firewall changes.
set -eu
test "${TCP_BENCH_ISOLATED_LAB:-}" = 1 || { echo 'Isolated container gate missing' >&2; exit 2; }
cleanup() { ip netns del bench-router 2>/dev/null || true; ip netns del bench-target 2>/dev/null || true; ip link del bench-source 2>/dev/null || true; }
trap cleanup EXIT INT TERM
ip netns add bench-router
ip netns add bench-target
ip link add bench-source type veth peer name bench-router-in
ip link set bench-router-in netns bench-router
ip -n bench-router link add br-out type veth peer name bench-target-in
ip -n bench-router link set bench-target-in netns bench-target
ip addr add 198.18.0.1/30 dev bench-source
ip -6 addr add fd42::1/64 dev bench-source nodad
ip link set bench-source up
ip -n bench-router addr add 198.18.0.2/30 dev bench-router-in
ip -n bench-router -6 addr add fd42::2/64 dev bench-router-in nodad
ip -n bench-router addr add 198.18.0.5/30 dev br-out
ip -n bench-router -6 addr add fd42:1::1/64 dev br-out nodad
ip -n bench-router link set lo up
ip -n bench-router link set bench-router-in up
ip -n bench-router link set br-out up
ip -n bench-target addr add 198.18.0.6/30 dev bench-target-in
ip -n bench-target -6 addr add fd42:1::2/64 dev bench-target-in nodad
ip -n bench-target link set lo up
ip -n bench-target link set bench-target-in up
ip route add 198.18.0.4/30 via 198.18.0.2
ip -6 route add fd42:1::/64 via fd42::2
ip -n bench-target route add default via 198.18.0.5
ip -n bench-target -6 route add default via fd42:1::1
ip netns exec bench-router sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
ip netns exec bench-router tc qdisc add dev br-out root netem delay 20ms
TCP_BENCH_LAB=routed cargo --config 'source.crates-io.replace-with="vendored-sources"' --config 'source.vendored-sources.directory="/vendor"' test --locked --offline --target-dir /build --test routed_lab routed_hops_and_delay -- --ignored
ip netns exec bench-router tc qdisc replace dev br-out root netem loss 100%
TCP_BENCH_LAB=loss cargo --config 'source.crates-io.replace-with="vendored-sources"' --config 'source.vendored-sources.directory="/vendor"' test --locked --offline --target-dir /build --test routed_lab routed_loss_and_active_cancellation -- --ignored

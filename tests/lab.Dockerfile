# Development tooling only. The executable never invokes these tools.
FROM rust:1-bookworm
RUN rustup component add clippy rustfmt
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iproute2 procps iperf3 && rm -rf /var/lib/apt/lists/*
WORKDIR /work

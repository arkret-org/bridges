# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.96
ARG BRIDGE_BIN=arkret-bridge-discord

FROM rust:${RUST_VERSION}-bookworm AS chef
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /workspace

FROM chef AS planner
COPY bridges ./bridges
COPY arkret-rust-sdk ./arkret-rust-sdk
WORKDIR /workspace/bridges
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG BRIDGE_BIN
COPY --from=planner /workspace/bridges/recipe.json ./bridges/recipe.json
COPY bridges ./bridges
COPY arkret-rust-sdk ./arkret-rust-sdk
WORKDIR /workspace/bridges
RUN cargo chef cook --release --locked --bin "${BRIDGE_BIN}"
RUN cargo build --release --locked --bin "${BRIDGE_BIN}"

FROM debian:bookworm-slim AS runtime
ARG BRIDGE_BIN
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /workspace/bridges/target/release/${BRIDGE_BIN} /usr/local/bin/arkret-bridge
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/arkret-bridge"]
CMD ["--config", "/etc/arkret-bridge/config.yaml"]

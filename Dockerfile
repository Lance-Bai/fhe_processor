FROM docker.m.daocloud.io/library/rust:1.82-bookworm AS builder
WORKDIR /app

COPY . .
RUN cargo build --release --package fhe_processor --bin fhe_processor

FROM docker.m.daocloud.io/library/debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/fhe_processor /usr/local/bin/fhe_processor

ENTRYPOINT ["/usr/local/bin/fhe_processor"]

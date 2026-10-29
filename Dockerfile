FROM rust:1.95.0-slim-bookworm AS build
ARG TARGETARCH
WORKDIR /source
COPY . .
RUN --mount=type=cache,id=lumen-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=lumen-target-${TARGETARCH},target=/source/target,sharing=locked \
    cargo +1.95.0 build --locked --release --package lumen && \
    cp /source/target/release/lumen /lumen

FROM debian:bookworm-slim
RUN useradd --system --uid 65532 --create-home lumen
COPY --from=build /lumen /usr/local/bin/lumen
COPY config/lumen.toml /etc/lumen/lumen.toml
USER lumen
ENTRYPOINT ["/usr/local/bin/lumen"]
CMD ["--config", "/etc/lumen/lumen.toml"]

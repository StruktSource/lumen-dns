FROM rust:1.99.0-slim-bookworm AS build
ARG TARGETARCH
WORKDIR /source
COPY . .
RUN --mount=type=cache,id=lumen-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=lumen-target-${TARGETARCH},target=/source/target,sharing=locked \
    cargo +1.95.0 build --locked --release --package lumen --package lumenctl && \
    cp /source/target/release/lumen /lumen && \
    cp /source/target/release/lumenctl /lumenctl

FROM debian:bookworm-slim
RUN useradd --system --uid 65532 --create-home lumen
COPY --from=build /lumen /usr/local/bin/lumen
COPY --from=build /lumenctl /usr/local/bin/lumenctl
COPY config/lumen.toml /etc/lumen/lumen.toml
USER lumen
EXPOSE 5353/udp 5353/tcp 8080/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/lumen"]
CMD ["--config", "/etc/lumen/lumen.toml"]

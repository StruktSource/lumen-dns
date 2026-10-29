FROM rust:1.95.0-slim-bookworm AS build
WORKDIR /source
COPY . .
RUN cargo build --locked --release --package lumen

FROM debian:bookworm-slim
RUN useradd --system --uid 65532 --create-home lumen
COPY --from=build /source/target/release/lumen /usr/local/bin/lumen
USER lumen
ENTRYPOINT ["/usr/local/bin/lumen"]

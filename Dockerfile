# ZenoLlull-Cloud-Prover
#   docker build -t zenollull-cloud-prover .
#   docker run -p 8080:8080 -e ZENO_LICENSE_PUBLIC_KEY=<hex> \
#       -e ZENO_USAGE_LOG=/data/usage.jsonl -v zeno-usage:/data zenollull-cloud-prover
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p cloud-prover

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 zeno && mkdir /data && chown zeno /data
COPY --from=build /src/target/release/zenollull-cloud-prover /usr/local/bin/
USER zeno
ENV ZENO_BIND=0.0.0.0:8080
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["zenollull-cloud-prover"]

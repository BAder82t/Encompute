# Encompute Confidential Space workload (ADR-011): attests to key brokers,
# receives the asset keys sealed to its session, then serves the artifact
# with receipts bound to that attestation.
#
#   docker build -f deploy/confidential-space/Dockerfile -t encompute-cs .
#
# VARIANT changes the image (and so its digest) without changing the code:
# the demo's "modified workload" that must receive no key.

FROM rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p encompute-cli -p encompute-evaluator \
 && ./target/release/encompute compile deploy/confidential-space/demo.eir -o /model.encompute

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/encompute /src/target/release/encompute-evaluator /usr/local/bin/
COPY --from=build /model.encompute /app/model.encompute
COPY deploy/confidential-space/run-workload.sh /app/run-workload.sh
# The key brokers' grant-signing keys ("ASSET KEY" lines, written by
# deploy.sh): part of the measured image, so the host cannot choose them.
# Without the file, run-workload.sh refuses to start.
COPY deploy/confidential-space/broker-key[s] /app/
ARG VARIANT=approved
RUN echo "${VARIANT}" > /app/variant
# The operator may set these through VM metadata (tee-env-*); nothing else.
LABEL "tee.launch_policy.allow_env_override"="BROKER_URLS"
LABEL "tee.launch_policy.log_redirect"="always"
EXPOSE 8750
ENTRYPOINT ["/app/run-workload.sh"]

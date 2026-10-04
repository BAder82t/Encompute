# TLS client sidecar (stunnel) for the reference production topology: the
# database tunnel and the root-key-provider tunnel. See compose.yaml.
#
#   docker build -t encompute-tunnel:stunnel deploy/production/tunnel
#
# The base image is pinned by digest. The stunnel package is the one Alpine
# 3.20 ships; its version is recorded by `docker run --rm --entrypoint stunnel
# encompute-tunnel:stunnel -version`.
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache stunnel
COPY entrypoint.sh /usr/local/bin/tunnel-entrypoint
ENTRYPOINT ["tunnel-entrypoint"]

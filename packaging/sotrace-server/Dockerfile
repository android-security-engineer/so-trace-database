# Package for the release HTTP server only.
# Distinct from .github/workflows/deploy-website.yml.
#
# Build from the repository root after `cargo build --release -p sotrace-server`:
#   docker build -f packaging/sotrace-server/Dockerfile -t sotrace-server:local .
# The image runs `sotrace-server` and refuses to start without SOTRACE_AUTH_TOKEN.

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY target/release/sotrace-server /usr/local/bin/sotrace-server

ENV SOTRACE_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sotrace-server"]

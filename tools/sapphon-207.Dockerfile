# SAPPHON-207 source-owned build candidate.
# BASE must be a fully qualified repository@sha256:... image.
# The workflow refuses missing/mutable BASE and uses --network=none.
ARG BASE
FROM ${BASE}
WORKDIR /src
COPY .cargo/config.toml /src/.cargo/config.toml
COPY rust/ /src/rust/
COPY Cargo.lock /src/rust/sapphon-liveness/Cargo.lock
COPY vendor.tar /src/vendor/
ENV CARGO_NET_OFFLINE=true
RUN cargo check --manifest-path /src/rust/sapphon-liveness/Cargo.toml --locked --offline --all-targets
CMD ["cargo","test","--manifest-path","/src/rust/sapphon-liveness/Cargo.toml","--locked","--offline","--all-targets"]

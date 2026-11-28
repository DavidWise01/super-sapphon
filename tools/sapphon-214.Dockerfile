# SAPPHON-214: pinned-base, offline Cargo image candidate.
# BASE is supplied as an immutable repository@sha256:... reference.
ARG BASE
FROM ${BASE}
WORKDIR /src
COPY .cargo/config.toml /src/.cargo/config.toml
COPY rust/ /src/rust/
COPY Cargo.lock /src/rust/sapphon-liveness/Cargo.lock
# Docker ADD unpacks a local tar into the destination directory; COPY would
# leave vendor.tar as a single file and Cargo would not find vendored crates.
ADD vendor.tar /src/vendor/
ENV CARGO_NET_OFFLINE=true
RUN cargo check --manifest-path /src/rust/sapphon-liveness/Cargo.toml --locked --offline --all-targets
CMD ["cargo","test","--manifest-path","/src/rust/sapphon-liveness/Cargo.toml","--locked","--offline","--all-targets"]

# ABOUTME: Builds the compilation service for Cloud Run NVIDIA L4 instances
# ABOUTME: Runtime includes CUDA, NVENC-capable FFmpeg, Noto fonts, and reviewed Divine branding

FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && printf 'pub fn placeholder() {}' > src/lib.rs \
    && printf 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -r src

COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM nvidia/cuda:12.2.2-runtime-ubuntu22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        ffmpeg \
        fonts-noto-core \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/divine-compiler /usr/local/bin/divine-compiler
COPY assets/divine-logo.png /opt/divine/divine-logo.png

ENV PORT=8080 \
    DIVINE_LOGO_PATH=/opt/divine/divine-logo.png \
    NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,video,utility

USER 65532:65532
EXPOSE 8080
CMD ["/usr/local/bin/divine-compiler"]

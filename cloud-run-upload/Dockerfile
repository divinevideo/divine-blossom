# ABOUTME: Dockerfile for Rust Blossom upload Cloud Run service
# ABOUTME: Multi-stage build for small production image

# Build stage
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Create dummy source to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Copy actual source
COPY src ./src

# Build for release (touch to force rebuild)
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (including ffmpeg for video thumbnails)
RUN apt-get update && apt-get install -y ca-certificates ffmpeg && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/blossom-upload /app/blossom-upload

ENV PORT=8080

CMD ["/app/blossom-upload"]

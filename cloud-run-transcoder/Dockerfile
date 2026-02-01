# ABOUTME: Dockerfile for GPU video transcoding Cloud Run service
# ABOUTME: NVIDIA CUDA base with FFmpeg NVENC for hardware-accelerated HLS encoding

# Build stage - use Rust image for compilation
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

# Runtime stage - NVIDIA CUDA with FFmpeg
# Use the official NVIDIA L4-compatible CUDA runtime image
FROM nvidia/cuda:12.2.2-runtime-ubuntu22.04

WORKDIR /app

# Install FFmpeg with NVENC support and other runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/divine-transcoder /app/divine-transcoder

ENV PORT=8080
# Enable CUDA device visibility
ENV NVIDIA_VISIBLE_DEVICES=all
ENV NVIDIA_DRIVER_CAPABILITIES=compute,video,utility

CMD ["/app/divine-transcoder"]

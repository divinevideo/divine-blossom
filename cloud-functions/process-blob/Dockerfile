# ABOUTME: Dockerfile for process-blob Cloud Run service
# ABOUTME: Includes c2patool binary for C2PA content credential validation

FROM python:3.12-slim

WORKDIR /app

# Install c2patool for C2PA validation. Pin the archive digest because GitHub
# release assets are mutable even when the tag remains unchanged.
ARG C2PATOOL_VERSION=0.26.53
ARG C2PATOOL_SHA256=7e2f6adaf31da3ec141dfd1865444832ab413529d5c4ac892c9bc07b7343c3d9
RUN apt-get update && apt-get install -y ca-certificates curl && \
    curl --retry 3 --retry-all-errors -fsSL -o /tmp/c2patool.tar.gz \
      "https://github.com/contentauth/c2pa-rs/releases/download/c2patool-v${C2PATOOL_VERSION}/c2patool-v${C2PATOOL_VERSION}-x86_64-unknown-linux-gnu.tar.gz" && \
    echo "${C2PATOOL_SHA256}  /tmp/c2patool.tar.gz" | sha256sum -c - && \
    tar xzf /tmp/c2patool.tar.gz -C /usr/local/bin/ \
      --strip-components=1 c2patool/c2patool && \
    c2patool --version && \
    rm /tmp/c2patool.tar.gz && \
    apt-get purge -y curl && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and trust config
COPY main.py .
COPY trust_anchors.pem .

ENV PORT=8080

CMD exec gunicorn --bind :$PORT --workers 2 --threads 2 --timeout 300 main:app

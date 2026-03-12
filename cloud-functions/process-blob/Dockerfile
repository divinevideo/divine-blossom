# ABOUTME: Dockerfile for process-blob Cloud Run service
# ABOUTME: Includes c2patool binary for C2PA content credential validation

FROM python:3.12-slim

WORKDIR /app

# Install c2patool for C2PA validation
RUN apt-get update && apt-get install -y ca-certificates curl && \
    curl -L https://github.com/contentauth/c2patool/releases/download/v0.26.33/c2patool-v0.26.33-x86_64-unknown-linux-gnu.tar.gz | \
    tar xz -C /usr/local/bin/ && \
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

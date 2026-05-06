# ABOUTME: Cloud Run GPU image running NVIDIA NeMo Parakeet TDT 0.6B v3 ASR.
# ABOUTME: Uses NVIDIA's prebuilt NeMo container so CUDA / cuDNN / PyTorch /
# ABOUTME: NeMo are all version-matched and tested on L4-class hardware.
#
# Why nvcr.io/nvidia/nemo and not nvidia/cuda:
#   We hit repeated SIGSEGV at model load when DIY-ing the CUDA stack on top
#   of nvidia/cuda:12.4.1-cudnn-runtime. NeMo's TDT decoder ships CUDA kernels
#   that need a precise driver/cuDNN/torch combo — NVIDIA tests this combo
#   in their NGC container, we don't. Trading image size (~18 GB) for a
#   reliable runtime; Cloud Run handles big images fine.

FROM nvcr.io/nvidia/nemo:25.07

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/opt/hf-cache \
    HF_HUB_DISABLE_TELEMETRY=1

WORKDIR /app

# We just need the web layer on top of what NeMo's container already has.
RUN pip install --no-cache-dir \
        fastapi==0.115.0 \
        "uvicorn[standard]==0.30.6"

COPY app /app/app

# Pre-download the Parakeet checkpoint so cold start doesn't depend on
# HuggingFace at request time. snapshot_download just fetches files; it
# does NOT instantiate the model (that segfaults on the CPU-only
# Cloud Build VM).
ARG PARAKEET_MODEL_NAME=nvidia/parakeet-tdt-0.6b-v3
ENV PARAKEET_MODEL_NAME=${PARAKEET_MODEL_NAME}
RUN python -c "from huggingface_hub import snapshot_download; snapshot_download(repo_id='${PARAKEET_MODEL_NAME}')"

ENV PORT=8080
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]

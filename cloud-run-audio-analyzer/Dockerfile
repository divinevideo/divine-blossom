# ABOUTME: Cloud Run CPU image for the audio analyzer (PANNs CNN14 AudioSet tagger).
# ABOUTME: Bakes the checkpoint and label list into the image so cold start needs no network.

FROM python:3.11-slim

# panns_inference reads ~/panns_data at import time, so HOME points at the
# baked files. matplotlib and numba (pulled in by librosa) want writable caches.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOME=/opt/panns \
    MPLCONFIGDIR=/tmp/matplotlib \
    NUMBA_CACHE_DIR=/tmp/numba

RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --index-url https://download.pytorch.org/whl/cpu torch==2.15.0
COPY requirements.txt .
RUN pip install -r requirements.txt

# PANNs CNN14 (Kong et al., 2020), CC BY 4.0: https://zenodo.org/records/3987831
ARG PANNS_CHECKPOINT_URL="https://zenodo.org/records/3987831/files/Cnn14_mAP%3D0.431.pth?download=1"
ARG PANNS_CHECKPOINT_SHA256=0dc499e40e9761ef5ea061ffc77697697f277f6a960894903df3ada000e34b31
ARG AUDIOSET_LABELS_URL=https://storage.googleapis.com/us_audioset/youtube_corpus/v1/csv/class_labels_indices.csv
ARG AUDIOSET_LABELS_SHA256=cdd1049833c4b86127c2773ac0d14a2754b6a6d0d1798002ed5c66e699708429
RUN mkdir -p /opt/panns/panns_data \
    && cd /opt/panns/panns_data \
    && curl -fsSL -o "Cnn14_mAP=0.431.pth" "${PANNS_CHECKPOINT_URL}" \
    && curl -fsSL -o class_labels_indices.csv "${AUDIOSET_LABELS_URL}" \
    && echo "${PANNS_CHECKPOINT_SHA256}  Cnn14_mAP=0.431.pth" | sha256sum -c - \
    && echo "${AUDIOSET_LABELS_SHA256}  class_labels_indices.csv" | sha256sum -c -

COPY app /app/app

ENV PORT=8080
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]

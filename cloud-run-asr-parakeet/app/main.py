# ABOUTME: FastAPI front-end for the Parakeet ASR sidecar.
# ABOUTME: One worker, one model, sync POST /v1/transcribe.

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from .transcribe import ParakeetTranscriber

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("parakeet-sidecar")

# Reject inputs above this size to protect the GPU. ffmpeg-extracted
# 16 kHz mono PCM s16le is 32 KB/s; 60 minutes ≈ 115 MB. Cap at 200 MB
# so we have headroom but cannot be DoS'd by a giant body.
MAX_AUDIO_BYTES = int(os.environ.get("PARAKEET_MAX_AUDIO_BYTES", str(200 * 1024 * 1024)))


_transcriber: Optional[ParakeetTranscriber] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _transcriber
    _transcriber = ParakeetTranscriber()
    logger.info(
        "Sidecar ready (model=%s device=%s)",
        _transcriber.model_name,
        _transcriber.device,
    )
    yield
    _transcriber = None


app = FastAPI(lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    if _transcriber is None:
        return JSONResponse({"status": "loading"}, status_code=503)
    return JSONResponse(
        {
            "status": "ok",
            "model": _transcriber.model_name,
            "device": _transcriber.device,
        }
    )


@app.post("/v1/transcribe")
async def transcribe(
    request: Request,
    language: Optional[str] = Query(default=None, description="BCP-47 hint"),
) -> JSONResponse:
    if _transcriber is None:
        raise HTTPException(status_code=503, detail="model not loaded")

    audio = await request.body()
    if not audio:
        raise HTTPException(status_code=400, detail="empty body")
    if len(audio) > MAX_AUDIO_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"audio too large: {len(audio)} bytes > {MAX_AUDIO_BYTES}",
        )

    try:
        result = _transcriber.transcribe(audio, language=language)
    except Exception as exc:  # noqa: BLE001 - we want any model failure to surface
        logger.exception("Parakeet transcription failed")
        raise HTTPException(status_code=500, detail=f"parakeet failure: {exc}") from exc

    return JSONResponse(result.to_dict())

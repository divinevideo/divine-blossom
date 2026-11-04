# ABOUTME: FastAPI front-end for the audio analyzer sidecar.
# ABOUTME: POST raw audio bytes to /v1/analyze; get kind, tags and scores back.

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from . import audio
from .rules import analyze_scores

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("audio-analyzer")

# Only the first 30 s are analyzed, so a large body is either a long recording
# or abuse. 50 MB still covers 30 s of uncompressed 48 kHz stereo WAV many times over.
MAX_AUDIO_BYTES = int(os.environ.get("ANALYZER_MAX_AUDIO_BYTES", str(50 * 1024 * 1024)))
PIPELINE_VERSION = 1

_tagger = None


def _load_tagger():
    from .tagger import PannsTagger

    return PannsTagger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _tagger
    _tagger = _load_tagger()
    logger.info("Analyzer ready (model=%s)", _tagger.model_name)
    yield
    _tagger = None


app = FastAPI(lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    if _tagger is None:
        return JSONResponse({"status": "loading"}, status_code=503)
    return JSONResponse({"status": "ok", "model": _tagger.model_name})


def _analyze(body: bytes) -> dict:
    started = time.perf_counter()
    try:
        samples = audio.decode(body)
    except audio.DecodeError as exc:
        raise HTTPException(status_code=422, detail=f"could not decode audio: {exc}") from exc
    seconds = round(len(samples) / audio.SAMPLE_RATE, 3)
    loudness = audio.measure_loudness(samples)
    result: dict = {
        "model": _tagger.model_name,
        "pipeline_version": PIPELINE_VERSION,
        "analyzed_seconds": seconds,
        "silent": loudness.silent,
        "loudness": loudness.to_dict(),
    }
    if result["silent"]:
        result.update(kind=None, detected=None, scores=None, tags=[], audioset=[])
    else:
        result.update(analyze_scores(_tagger.scores(samples), seconds).to_dict())
    logger.info(
        "analyzed %.1fs silent=%s audible=%.2fs kind=%s tags=%s in %.0f ms",
        seconds, loudness.silent, loudness.audible_seconds, result["kind"], result["tags"],
        (time.perf_counter() - started) * 1000,
    )
    return result


@app.post("/v1/analyze")
async def analyze(request: Request) -> JSONResponse:
    if _tagger is None:
        raise HTTPException(status_code=503, detail="model not loaded")
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_AUDIO_BYTES:
        # Refuse before buffering when the client says up front it is too big.
        raise HTTPException(
            status_code=413, detail=f"audio too large: {declared} bytes > {MAX_AUDIO_BYTES}"
        )
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty body")
    if len(body) > MAX_AUDIO_BYTES:
        raise HTTPException(
            status_code=413, detail=f"audio too large: {len(body)} bytes > {MAX_AUDIO_BYTES}"
        )
    return JSONResponse(await run_in_threadpool(_analyze, body))

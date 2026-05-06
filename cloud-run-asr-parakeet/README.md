# divine-asr-parakeet

NVIDIA NeMo Parakeet TDT 0.6B v3 ASR sidecar for `divine-transcoder`.
Self-hosted, GPU-only, private (no public ingress).

## API

| Method | Path | Body | Response |
|---|---|---|---|
| `GET`  | `/healthz` | — | `{ "status": "ok" \| "loading", "model": "...", "device": "cuda" \| "cpu" }` |
| `POST` | `/v1/transcribe?language=en` | raw 16 kHz mono PCM WAV bytes | `{ "language": "...", "segments": [{ "start", "end", "text", "words": [...] }] }` |

`language` is an optional BCP-47 hint; Parakeet auto-detects when omitted.

## Local dev

```sh
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PARAKEET_MODEL_NAME=nvidia/parakeet-tdt-0.6b-v3 \
  uvicorn app.main:app --host 0.0.0.0 --port 8080
```

Pure-mapping unit tests (no model required):

```sh
python -m unittest discover tests -v
```

## Deploy

```sh
PROJECT_ID=rich-compiler-479518-d2 ./deploy.sh
```

Defaults:
- Region `us-central1`
- GPU `nvidia-l4`, 1 GPU per instance
- `concurrency=1` (NeMo isn't safe under request-level parallelism on a single GPU)
- `--no-allow-unauthenticated` (private)
- Model weights are baked into the image at build time so cold start is just CUDA init

After the first deploy, grant the transcoder runtime SA invoker on the sidecar:

```sh
gcloud run services add-iam-policy-binding divine-asr-parakeet \
  --region us-central1 --project "$PROJECT_ID" \
  --member="serviceAccount:149672065768-compute@developer.gserviceaccount.com" \
  --role=roles/run.invoker
```

Then point the transcoder at the sidecar:

```sh
gcloud run services update divine-transcoder \
  --region us-central1 --project "$PROJECT_ID" \
  --update-env-vars PARAKEET_ASR_URL=$(gcloud run services describe divine-asr-parakeet \
      --region us-central1 --project "$PROJECT_ID" --format='value(status.url)'),\
TRANSCRIPTION_PROVIDER=parakeet
```

## Notes

- The sidecar caps request bodies at `PARAKEET_MAX_AUDIO_BYTES` (default 200 MB ≈ 100 minutes of 16 kHz mono PCM). Inputs above that get a 413.
- Parakeet TDT 0.6B v3 is multilingual across ~25 European languages. For other languages the transcoder's `TRANSCRIPTION_FALLBACK_PROVIDER` chain still applies.
- `concurrency=1` means scale-out happens via Cloud Run instance count, not in-process. Tune `--max-instances` based on observed queueing.

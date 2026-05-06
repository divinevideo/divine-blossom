# Gemini 2.5 Pro Transcription: Design Spec

## Problem

OpenAI's transcription API (`gpt-4o-mini-transcribe`) is rate-limiting us at 50 RPM, causing `provider_rate_limited` terminal failures on new video VTTs.

## Solution

Switch the transcoder's transcription provider from OpenAI to Gemini 2.5 Pro via Vertex AI. Gemini has higher rate limits (~2000 RPM), better quality on noisy/short audio, and we're already on GCP so auth is free.

## Design

### API Call

```
POST https://us-central1-aiplatform.googleapis.com/v1/projects/rich-compiler-479518-d2/locations/us-central1/publishers/google/models/gemini-2.5-pro:generateContent

Auth: Bearer {GCP service account token from metadata server}

{
  "contents": [{
    "role": "user",
    "parts": [
      {"text": "Transcribe this audio. Return segments with start/end timestamps in seconds and the spoken text."},
      {"inlineData": {"mimeType": "audio/wav", "data": "<base64>"}}
    ]
  }],
  "generationConfig": {
    "audioTimestamp": true,
    "responseMimeType": "application/json",
    "responseSchema": {
      "type": "object",
      "properties": {
        "language": {"type": "string"},
        "segments": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "start": {"type": "number"},
              "end": {"type": "number"},
              "text": {"type": "string"}
            }
          }
        }
      }
    }
  }
}
```

Response: `candidates[0].content.parts[0].text` contains JSON matching the schema. Passed directly to existing `normalize_transcript_to_vtt()`.

### What changes

- `transcribe_audio_via_provider_once()` — swap multipart form POST for JSON POST with base64 audio
- Auth — fetch GCP service account token from metadata server
- Response parsing — extract `candidates[0].content.parts[0].text` from Vertex AI response
- Config — `TRANSCRIPTION_PROVIDER` env var: `gemini` (default) or `openai` (fallback)
- `deploy.sh` — update env vars
- Helper functions get Gemini branches (no-ops for logprobs/response_format)

### What doesn't change

- `normalize_transcript_to_vtt()` — already parses `{segments: [{start, end, text}]}`
- Confidence/hallucination detection
- Phantom phrase matching
- Webhook callbacks
- Retry logic
- VTT upload to GCS

### Constraints

- Max video length: 6 seconds (Vine-style app). Audio is ~192KB WAV at 16kHz mono. Always inline base64.
- No GCS URI path needed — all audio fits comfortably under Vertex AI's 20MB inline limit.
- Keep OpenAI as configurable fallback via `TRANSCRIPTION_PROVIDER=openai`.

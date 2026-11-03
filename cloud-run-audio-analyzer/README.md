# divine-audio-analyzer

Classifies a sound by what it sounds like, so sound search does not depend on
tags uploaders rarely set (divinevideo/divine-blossom#319). For every sound it
returns:
- whether it belongs under **music**, **sfx** or only **All**;
- for music, a genre and the instruments it hears;
- the scores behind those decisions;
- the top AudioSet labels as searchable words.

It runs the PANNs CNN14 AudioSet tagger on CPU and is private (no public
ingress), like the Parakeet ASR sidecar.

## API

| Method | Path | Body | Response |
|---|---|---|---|
| `GET` | `/healthz` | — | `{ "status": "ok" \| "loading", "model": "..." }` |
| `POST` | `/v1/analyze` | raw audio bytes in any format ffmpeg reads (WAV, M4A/MP4, MP3, …), at most 50 MB | see below |

Errors:

| Status | When |
|---|---|
| `400` | empty body |
| `413` | body over the limit |
| `422` | the body is not decodable audio |
| `503` | the model is still loading |

Only the first 30 s are analyzed. Clips shorter than a second are padded with silence to one second, because the model cannot take less than about 0.35 s. A 6-second piano clip returns:

```json
{
  "model": "panns-cnn14-mAP0.431",
  "pipeline_version": 1,
  "analyzed_seconds": 6.292,
  "silent": false,
  "kind": "music",
  "detected": "music",
  "scores": {
    "kind": {"music": 0.7524, "speech": 0.0268, "effect": 0.1232},
    "genre": {"classical": 0.0751, "rock": 0.0006, "hiphop": 0.0004, "electronic": 0.0022, "pop": 0.0036, "jazz": 0.0117, "folk": 0.0012},
    "instrument": {"piano": 0.5445, "guitar": 0.0029, "drums": 0.0062, "violin": 0.0059, "synthesizer": 0.0016, "vocals": 0.0047},
    "mood": {"calm": 0.0231, "happy": 0.0054, "sad": 0.0055, "energetic": 0.0012, "scary": 0.0001}
  },
  "tags": ["music", "classical", "piano"],
  "audioset": [
    {"label": "Music", "score": 0.7524},
    {"label": "Piano", "score": 0.5445},
    {"label": "Keyboard (musical)", "score": 0.5037}
  ]
}
```

`audioset` is shortened here; it lists up to ten classes scoring at least 0.1.

A silent upload (digital silence or below −70 dBFS) returns `"silent": true`, no kind, no tags and no scores.

## Rules

`detected` is the strongest of three AudioSet groups:
- **speech** is the Speech subtree;
- **music** is the Music and Singing subtrees;
- **effect** is every other class, except acoustic environment, background noise and silence.

`kind` and `tags` then follow these product rules:

| Rule | Default | Environment variable |
|---|---|---|
| `music` when music is the top group and scores at least this | 0.5 | `ANALYZER_MUSIC_MIN` |
| `sfx` when an effect is the top group | no threshold | – |
| Pure speech gets no kind, so the sound is listed only under All | – | – |
| …unless it is shorter than this; short sound bites such as "bruh" are `sfx` | 2.5 s | `ANALYZER_SHORT_SPEECH_MAX_S` |
| Music gets its top genre as a tag if it scores at least this | 0.01 | `ANALYZER_GENRE_MIN` |
| Music gets every instrument scoring at least this | 0.2 | `ANALYZER_INSTRUMENT_MIN` |
| Mood is returned as scores but never as a tag | – | – |

Mood never becomes a tag because AudioSet mood scores on 6-second clips sit around 0.01, too low to threshold.

The grouping of the 527 AudioSet classes is in `app/audioset_groups.json`. It was derived from the [AudioSet ontology](https://github.com/audioset/ontology). The coarse genre, instrument and mood groups are in `app/rules.py`. At startup the service fails if any configured class name is missing from the model's labels.

## Measured quality

Measured on 213 hand-labelled Divine sounds (the evaluation in #319: real relay sounds plus the app's bundled sounds), running this service end to end:

| | Precision | Share of the class found |
|---|---:|---:|
| `music` tag | 95% | 85% of music |
| `sfx` tag (effects and short sound bites) | 98% | 77% of effects |
| Genre on sounds tagged `music` | 24 of 27 correct (one known genre falls below the 0.01 floor) | – |

The acoustic kind (`detected`) was right for 84% of clips, or 92% when a clip mixing speech and music counts as either. Pop is the weakest genre; classical, rock and jazz were reliable.

Labels came from titles, transcripts and spectrograms, not from listening. Have a person listen to about 100 sounds before tightening the thresholds.

## Cost and latency

| | Value |
|---|---|
| Latency, end to end on one Apple M5 CPU core | ~130 ms per 6-second sound |
| Memory | ~1.2 GB resident |
| Cost on Cloud Run (1 vCPU / 2 GiB, `min-instances 0`), today's ~2,500 new sounds a month | about $1–2 a month |
| Cost per million sounds | about $10–30 |
| Ceiling | `max-instances` (default 2, so at most about $150 a month) |

These cost figures are estimates from list prices.

## Local dev

```sh
python3.11 -m venv .venv && source .venv/bin/activate
pip install torch==2.15.0 -r requirements-dev.txt
mkdir -p ~/panns_data && cd ~/panns_data \
  && curl -fsSLO https://storage.googleapis.com/us_audioset/youtube_corpus/v1/csv/class_labels_indices.csv \
  && curl -fsSL -o "Cnn14_mAP=0.431.pth" "https://zenodo.org/records/3987831/files/Cnn14_mAP%3D0.431.pth?download=1" \
  && cd -
uvicorn app.main:app --host 127.0.0.1 --port 8080
curl --data-binary @some-sound.m4a http://127.0.0.1:8080/v1/analyze
```

Tests: the rule tests need only the standard library. The decode and HTTP tests need ffmpeg and `requirements-dev.txt`. No test loads the model.

```sh
python -m unittest discover -s tests -v
```

## Deploy

Deploy by hand, like the other sidecars (see `docs/runbooks/deployment.md`):

```sh
PROJECT_ID=rich-compiler-479518-d2 ./deploy.sh
```

The script prints the two commands that wire it up. The first grants the transcoder's runtime service account `roles/run.invoker`. The second sets `AUDIO_ANALYZER_URL` on `divine-transcoder`.

## How it is wired

1. Every audio upload reaches divine-transcoder's `POST /transcribe` (from the upload service, or from the edge for small uploads). The transcoder also starts a classification in the background.
2. The classification skips blobs that are not `audio/*` or exceed 50 MB. It also skips sounds that already have a verdict.
3. Otherwise it sends the original blob to this service and stores the JSON beside the transcript as `{sha256}/audio/analysis.json`.
4. The edge serves that file at `GET /<sha256>/sound`, with the same moderation gate as transcripts. Until the verdict exists the route returns `404`. Funnelcake reads it from there for its sound index (divinevideo/divine-funnelcake#1422).
5. `POST /analyze-sound {"hash": "<sha256>"}` on the transcoder runs the same step for one stored sound. It needs the `X-Divine-Transcribe-Secret` header, like `/transcribe/audio`. It is idempotent, and an instance never analyzes the same hash twice at once. It answers with a `status`: `classified`, `already_exists`, `not_audio`, `too_large`, `missing` (no such blob), `in_progress` or `not_configured`.
6. `scripts/backfill_sound_analysis.py` calls it for every Blossom-hosted sound that Funnelcake's `/api/sounds` lists, to classify sounds published before this shipped. It reads the secret from `TRANSCRIBE_SHARED_SECRET` and prints every hash that failed.

A failed classification is only logged; re-running the backfill script retries it.

## Licence

The PANNs CNN14 weights are by Qiuqiang Kong et al. ([PANNs: Large-Scale Pretrained Audio Neural Networks for Audio Pattern Recognition](https://arxiv.org/abs/1912.10211), 2020). They are published on [Zenodo](https://zenodo.org/records/3987831) under CC BY 4.0, and the `panns_inference` code is MIT. The AudioSet label list and ontology are by Google, CC BY 4.0.

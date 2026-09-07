# Media readiness fixtures

These files are synthetic and contain no account, upload, or user identifiers.

- `readiness_ok.mp4` is a one-second, 64×64 H.264 test pattern.
- `readiness_terminal.mp4` is the same file truncated immediately before its
  `moov` atom. FFmpeg rejects it with `moov atom not found`, which the
  transcoder's classifier maps to terminal `invalid_media`.

Regenerate both fixtures from this directory with FFmpeg:

```bash
ffmpeg -hide_banner -loglevel error \
  -f lavfi -i testsrc=size=64x64:rate=10 -t 1 \
  -c:v libx264 -pix_fmt yuv420p -an -movflags -faststart \
  readiness_ok.mp4

MOOV_OFFSET="$(LC_ALL=C grep -abo 'moov' readiness_ok.mp4 | tail -1 | cut -d: -f1)"
dd if=readiness_ok.mp4 of=readiness_terminal.mp4 \
  bs=1 count="$((MOOV_OFFSET - 4))" status=none
```

Verify the expected behavior:

```bash
ffprobe -v error -show_entries stream=codec_name,width,height,duration \
  -of default=noprint_wrappers=1 readiness_ok.mp4
ffmpeg -v error -i readiness_terminal.mp4 -f null -
```

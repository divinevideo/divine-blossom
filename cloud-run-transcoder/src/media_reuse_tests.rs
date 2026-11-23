use super::*;
use serde_json::json;

fn compatible() -> Value {
    json!({
        "format": {"format_name":"mov,mp4,m4a,3gp,3g2,mj2", "duration":"6.0"},
        "streams":[
            {"codec_type":"video", "codec_name":"h264", "profile":"Constrained Baseline",
             "level":30, "pix_fmt":"yuv420p", "width":480, "height":480,
             "sample_aspect_ratio":"1:1", "field_order":"progressive", "has_b_frames":0,
             "avg_frame_rate":"30/1", "duration":"6.0", "start_time":"0.0"},
            {"codec_type":"audio", "codec_name":"aac", "profile":"LC", "channels":2,
             "sample_rate":"44100", "bit_rate":"64000", "duration":"6.02", "start_time":"0.0"}
        ]
    })
}

#[test]
fn low_bitrate_compatible_media_is_reused_with_or_without_audio() {
    let mut p = compatible();
    assert!(eligible(&p, 300_000));
    p["streams"].as_array_mut().unwrap().pop();
    assert!(eligible(&p, 300_000));
    p["streams"][0]
        .as_object_mut()
        .unwrap()
        .remove("sample_aspect_ratio");
    assert!(eligible(&p, 300_000));
}

#[test]
fn unknown_or_incompatible_streams_keep_encoding() {
    let cases = [
        ("codec_name", json!("hevc")),
        ("profile", json!("High 10")),
        ("level", json!(40)),
        ("pix_fmt", json!("yuv420p10le")),
        ("width", json!(720)),
        ("height", json!(720)),
        ("width", json!(479)),
        ("sample_aspect_ratio", json!("4:3")),
        ("sample_aspect_ratio", json!("broken")),
        ("sample_aspect_ratio", json!(1)),
        ("side_data_list", json!({})),
        ("field_order", json!("tt")),
        ("has_b_frames", json!(2)),
        ("avg_frame_rate", json!("60/1")),
        ("avg_frame_rate", json!("0/0")),
        ("duration", json!("11")),
        ("start_time", json!("1.0")),
        ("tags", json!({"rotate":"90"})),
        ("tags", json!({"rotate":"bad"})),
        (
            "side_data_list",
            json!([{"side_data_type":"Display Matrix", "rotation":0}]),
        ),
    ];
    for (key, value) in cases {
        let mut p = compatible();
        p["streams"][0][key] = value;
        assert!(!eligible(&p, 300_000), "unexpected reuse for {key}");
    }
    for key in [
        "codec_name",
        "profile",
        "level",
        "pix_fmt",
        "width",
        "height",
        "has_b_frames",
        "avg_frame_rate",
        "duration",
        "start_time",
    ] {
        let mut p = compatible();
        p["streams"][0].as_object_mut().unwrap().remove(key);
        assert!(!eligible(&p, 300_000), "missing {key} accepted");
    }
    let mut p = compatible();
    let extra = p["streams"][0].clone();
    p["streams"].as_array_mut().unwrap().push(extra);
    assert!(!eligible(&p, 300_000));
}

#[test]
fn high_bitrate_or_unknown_duration_does_not_bypass_compression() {
    // 900_000 bytes over 6.0s = 1.2 Mbps (typical 480x480 Vine) qualifies;
    // 1_125_001 bytes over 6.0s > 1.5 Mbps must fall back to compression.
    assert!(eligible(&compatible(), 900_000));
    assert!(!eligible(&compatible(), 1_125_001));
    assert!(!eligible(&compatible(), 0));
    for value in [
        json!(null),
        json!("0"),
        json!("NaN"),
        json!("inf"),
        json!("11"),
        json!("5.0"),
    ] {
        let mut p = compatible();
        p["format"]["duration"] = value;
        assert!(!eligible(&p, 300_000));
    }
    let mut p = compatible();
    p["format"]["format_name"] = json!("matroska,webm");
    assert!(!eligible(&p, 300_000));
}

#[test]
fn incompatible_or_unbounded_audio_keeps_encoding() {
    let mut at_ceiling = compatible();
    at_ceiling["streams"][1]["bit_rate"] = json!("128000");
    assert!(eligible(&at_ceiling, 900_000));

    for (key, value) in [
        ("codec_name", json!("opus")),
        ("profile", json!("HE-AAC")),
        ("channels", json!(6)),
        ("sample_rate", json!("96000")),
        ("bit_rate", json!("192000")),
        ("bit_rate", json!(null)),
        ("duration", json!("7")),
        ("start_time", json!("0.5")),
    ] {
        let mut p = compatible();
        p["streams"][1][key] = value;
        assert!(!eligible(&p, 300_000), "unexpected reuse for audio {key}");
    }
}

fn packets() -> Value {
    json!({"packets":[
        {"pts_time":"0.0","dts_time":"0.0","duration_time":"0.04","flags":"K_"},
        {"pts_time":"0.04","dts_time":"0.04","duration_time":"0.04","flags":"__"}
    ]})
}

#[test]
fn ordered_video_packets_starting_with_a_keyframe_can_be_copied() {
    assert!(safe_packets(&packets(), 0.08));
}

#[test]
fn bad_packets_do_not_reach_stream_copy() {
    for (index, key, value) in [
        (0, "flags", json!("__")),
        (1, "pts_time", json!("0.0")),
        (1, "dts_time", json!("-0.1")),
        (1, "duration_time", json!("NaN")),
        (1, "duration_time", json!("1.0")),
    ] {
        let mut p = packets();
        p["packets"][index][key] = value;
        assert!(!safe_packets(&p, 0.08));
    }
    assert!(!safe_packets(&json!({"packets":[]}), 6.0));
    assert!(
        !safe_packets(&packets(), 6.0),
        "truncated timeline accepted"
    );
    let mut gap = packets();
    gap["packets"][1]["pts_time"] = json!("0.08");
    gap["packets"][1]["dts_time"] = json!("0.08");
    assert!(!safe_packets(&gap, 0.12), "timeline gap accepted");
}

async fn media_tool(name: &str, args: &[&str]) -> std::process::Output {
    let out = crate::media_command::output(
        tokio::process::Command::new(name).args(args),
        std::time::Duration::from_secs(30),
    )
    .await
    .unwrap();
    assert!(
        out.status.success(),
        "{name}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

async fn make_source(path: &Path, audio: bool) {
    make_source_at_quality(path, audio, "36").await;
}

async fn make_source_at_quality(path: &Path, audio: bool, crf: &str) {
    make_source_with_sar(path, audio, crf, "1").await;
}

async fn make_source_with_sar(path: &Path, audio: bool, crf: &str, sar: &str) {
    let filter = format!("setsar={sar}");
    let mut args = vec![
        "-v",
        "error",
        "-y",
        "-f",
        "lavfi",
        "-i",
        "testsrc2=size=320x320:rate=25:duration=2",
    ];
    if audio {
        args.extend([
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=44100:duration=2",
        ]);
    }
    args.extend([
        "-vf",
        &filter,
        "-c:v",
        "libx264",
        "-profile:v",
        "baseline",
        "-level:v",
        "3.0",
        "-pix_fmt",
        "yuv420p",
        "-bf",
        "0",
        "-crf",
        crf,
        "-preset",
        "fast",
        "-g",
        "25",
    ]);
    if audio {
        args.extend(["-c:a", "aac", "-b:a", "64k"]);
    }
    args.extend(["-movflags", "+faststart", path.to_str().unwrap()]);
    media_tool("ffmpeg", &args).await;
}

async fn frames(path: &Path) -> Vec<String> {
    let out = media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-i",
            path.to_str().unwrap(),
            "-map",
            "0:v:0",
            "-f",
            "framemd5",
            "-",
        ],
    )
    .await;
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.rsplit(',').next().unwrap().trim().to_string())
        .collect()
}

async fn probe(path: &Path) -> Value {
    let out = media_tool(
        "ffprobe",
        &[
            "-v",
            "error",
            "-show_streams",
            "-show_format",
            "-of",
            "json",
            path.to_str().unwrap(),
        ],
    )
    .await;
    serde_json::from_slice(&out.stdout).unwrap()
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn stream_copy_preserves_frames_original_and_all_playback_files() {
    for audio in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.mp4");
        let output = dir.path().join("hls");
        tokio::fs::create_dir(&output).await.unwrap();
        make_source(&input, audio).await;
        let original = tokio::fs::read(&input).await.unwrap();
        assert!(
            eligible(&probe(&input).await, original.len() as u64),
            "fixture must qualify"
        );
        assert!(
            try_reuse(&input, &output).await.unwrap(),
            "must copy a compatible original"
        );
        crate::remux_ts_to_fmp4(&output, crate::MediaPolicy::AllowEncode)
            .await
            .unwrap();
        let expected = frames(&input).await;
        assert_eq!(expected.len(), 50);
        for variant in ["stream_720p", "stream_480p"] {
            let mp4 = output.join(format!("{variant}.mp4"));
            let hls = output.join(format!("{variant}.m3u8"));
            assert_eq!(frames(&mp4).await, expected);
            assert_eq!(frames(&hls).await, expected);
            let actual = probe(&mp4).await;
            assert_eq!(
                actual["streams"].as_array().unwrap().len(),
                if audio { 2 } else { 1 }
            );
            let duration = number(&actual["format"]["duration"]).unwrap();
            assert!((duration - 2.0).abs() < 0.06, "duration {duration}");
            assert!(tokio::fs::metadata(&mp4).await.unwrap().len() < original.len() as u64 + 8192);
        }
        assert_eq!(tokio::fs::read(&input).await.unwrap(), original);
        assert!(
            tokio::fs::metadata(output.join("master.m3u8"))
                .await
                .unwrap()
                .len()
                > 0
        );
    }
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn stream_copy_accepts_unspecified_pixel_aspect() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source.mp4");
    let output = dir.path().join("hls");
    tokio::fs::create_dir(&output).await.unwrap();
    make_source_with_sar(&input, false, "36", "0").await;

    let inspection = super::probe(&input, true).await.unwrap();
    let video_frames: Vec<_> = inspection["packets_and_frames"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["type"] == "frame" && item["media_type"] == "video")
        .collect();
    assert_eq!(video_frames.len(), 50);
    assert!(video_frames.iter().all(|frame| {
        frame["sample_aspect_ratio"].is_null()
            || matches!(frame["sample_aspect_ratio"].as_str(), Some("0:1" | "N/A"))
    }));
    assert!(try_reuse(&input, &output).await.unwrap());
    assert_eq!(
        frames(&input).await,
        frames(&output.join("stream_720p.m3u8")).await
    );
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn failed_candidate_publication_leaves_existing_outputs_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source.mp4");
    let output = dir.path().join("hls");
    make_source(&input, true).await;
    tokio::fs::create_dir(&output).await.unwrap();
    tokio::fs::write(output.join("keep"), b"existing")
        .await
        .unwrap();
    assert!(try_reuse(&input, &output).await.is_err());
    let mut entries = tokio::fs::read_dir(&output).await.unwrap();
    assert_eq!(
        entries.next_entry().await.unwrap().unwrap().file_name(),
        "keep"
    );
    assert!(entries.next_entry().await.unwrap().is_none());
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        2,
        "candidate staging leaked"
    );
}

async fn audio_packets(path: &Path) -> Vec<String> {
    let out = media_tool(
        "ffprobe",
        &[
            "-v",
            "error",
            "-select_streams",
            "a:0",
            "-show_packets",
            "-show_data_hash",
            "sha256",
            "-show_entries",
            "packet=data_hash",
            "-of",
            "json",
            path.to_str().unwrap(),
        ],
    )
    .await;
    let data: Value = serde_json::from_slice(&out.stdout).unwrap();
    data["packets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["data_hash"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn generation_reuses_audio_and_video_but_forced_repair_encodes() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source.mp4");
    make_source(&input, true).await;
    let info = crate::probe_video(&input).await.unwrap();
    let expected_video = frames(&input).await;
    let expected_audio = audio_packets(&input).await;
    assert!(!expected_audio.is_empty());
    for allow_reuse in [true, false] {
        let output = dir
            .path()
            .join(if allow_reuse { "reuse" } else { "repair" });
        tokio::fs::create_dir(&output).await.unwrap();
        let variants = crate::run_ffmpeg_hls(
            &input,
            &output,
            false,
            &info,
            allow_reuse,
            crate::MediaPolicy::AllowEncode,
        )
        .await
        .unwrap();
        assert_eq!(variants.variants.len(), 2);
        assert_eq!(
            variants.method,
            if allow_reuse {
                crate::HlsMethod::StreamCopy
            } else {
                crate::HlsMethod::Encode
            }
        );
        assert_eq!(
            variants.method.completion_counter(),
            if allow_reuse {
                "stream_copy_verified"
            } else {
                "encode_completed"
            }
        );
        crate::remux_ts_to_fmp4(&output, crate::MediaPolicy::AllowEncode)
            .await
            .unwrap();
        crate::require_progressive_outputs(&output).await.unwrap();
        for name in ["stream_720p.mp4", "stream_480p.mp4"] {
            let result = output.join(name);
            if allow_reuse {
                assert_eq!(frames(&result).await, expected_video);
                assert_eq!(audio_packets(&result).await, expected_audio);
                let p = probe(&result).await;
                let streams = p["streams"].as_array().unwrap();
                let v = streams.iter().find(|s| s["codec_type"] == "video").unwrap();
                let a = streams.iter().find(|s| s["codec_type"] == "audio").unwrap();
                assert!(
                    (number(&v["start_time"]).unwrap() - number(&a["start_time"]).unwrap()).abs()
                        < 0.05
                );
            } else {
                assert_ne!(
                    frames(&result).await,
                    expected_video,
                    "repair must run encoder"
                );
            }
        }
    }
}

#[test]
fn every_decoded_frame_must_match_the_compatible_video() {
    let video = json!({"width":320,"height":320});
    let frame = json!({"width":320,"height":320,"pix_fmt":"yuv420p","interlaced_frame":0,"sample_aspect_ratio":"1:1"});
    assert!(compatible_frames(
        &json!({"frames":[frame.clone(),frame.clone()]}),
        &video
    ));
    for (key, value) in [
        ("width", json!(640)),
        ("pix_fmt", json!("yuv444p")),
        ("interlaced_frame", json!(1)),
        ("sample_aspect_ratio", json!("4:3")),
    ] {
        let mut bad = frame.clone();
        bad[key] = value;
        assert!(!compatible_frames(
            &json!({"frames":[frame.clone(),bad]}),
            &video
        ));
    }
    assert!(!compatible_frames(&json!({"frames":[]}), &video));
    assert!(!compatible_frames(&json!({"frames":[{}]}), &video));
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn high_bitrate_source_falls_back_to_compression() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source.mp4");
    let output = dir.path().join("hls");
    media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=480x480:rate=25:duration=2",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=44100:duration=2",
            "-vf",
            "setsar=1,noise=alls=40:allf=t",
            "-c:v",
            "libx264",
            "-profile:v",
            "baseline",
            "-level:v",
            "3.0",
            "-pix_fmt",
            "yuv420p",
            "-bf",
            "0",
            "-crf",
            "16",
            "-preset",
            "fast",
            "-g",
            "25",
            "-c:a",
            "aac",
            "-b:a",
            "64k",
            "-movflags",
            "+faststart",
            input.to_str().unwrap(),
        ],
    )
    .await;
    tokio::fs::create_dir(&output).await.unwrap();
    let original = tokio::fs::read(&input).await.unwrap();
    let total_bps = original.len() as f64 * 8.0 / 2.0;
    assert!(
        total_bps > 1_500_000.0,
        "fixture must exceed 1.5 Mbps reuse budget, got {total_bps} bps"
    );
    assert!(
        !eligible(&probe(&input).await, original.len() as u64),
        "fixture must exceed reuse budget"
    );
    assert!(!try_reuse(&input, &output).await.unwrap());
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 0);
    let info = crate::probe_video(&input).await.unwrap();
    crate::run_ffmpeg_hls(
        &input,
        &output,
        false,
        &info,
        true,
        crate::MediaPolicy::AllowEncode,
    )
    .await
    .unwrap();
    crate::remux_ts_to_fmp4(&output, crate::MediaPolicy::AllowEncode)
        .await
        .unwrap();
    crate::require_progressive_outputs(&output).await.unwrap();
    for name in ["stream_720p.mp4", "stream_480p.mp4"] {
        assert!(std::fs::metadata(output.join(name)).unwrap().len() < original.len() as u64);
    }
    assert_eq!(tokio::fs::read(&input).await.unwrap(), original);
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn typical_480x480_1mbps_source_is_reused() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source.mp4");
    let output = dir.path().join("hls");
    media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc2=size=480x480:rate=30:duration=2",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=44100:duration=2",
            "-vf",
            "setsar=1",
            "-c:v",
            "libx264",
            "-profile:v",
            "baseline",
            "-level:v",
            "3.0",
            "-pix_fmt",
            "yuv420p",
            "-bf",
            "0",
            "-b:v",
            "950k",
            "-maxrate",
            "1100k",
            "-bufsize",
            "1100k",
            "-preset",
            "fast",
            "-g",
            "30",
            "-c:a",
            "aac",
            "-b:a",
            "96k",
            "-movflags",
            "+faststart",
            input.to_str().unwrap(),
        ],
    )
    .await;
    let original = tokio::fs::read(&input).await.unwrap();
    let total_bps = original.len() as f64 * 8.0 / 2.0;
    assert!(
        total_bps > 500_000.0 && total_bps <= 1_500_000.0,
        "fixture should exercise the 500k..=1500k band, got {total_bps} bps"
    );
    tokio::fs::create_dir(&output).await.unwrap();
    assert!(
        try_reuse(&input, &output).await.unwrap(),
        "compatible 480x480 ~1 Mbps source should be reused"
    );
    crate::remux_ts_to_fmp4(&output, crate::MediaPolicy::AllowEncode)
        .await
        .unwrap();
    crate::require_progressive_outputs(&output).await.unwrap();
    assert_eq!(
        frames(&output.join("stream_720p.mp4")).await,
        frames(&input).await
    );
    assert_eq!(
        tokio::fs::read(output.join("stream_720p.mp4"))
            .await
            .unwrap(),
        tokio::fs::read(output.join("stream_480p.mp4"))
            .await
            .unwrap(),
        "identical TS variants should mirror the remuxed MP4"
    );
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn container_only_color_metadata_survives_generation() {
    let dir = tempfile::tempdir().unwrap();
    let plain = dir.path().join("source.mp4");
    let tagged = dir.path().join("tagged.mp4");
    let output = dir.path().join("hls");
    make_source(&plain, true).await;
    media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-i",
            plain.to_str().unwrap(),
            "-c",
            "copy",
            "-color_primaries",
            "bt2020",
            "-color_trc",
            "smpte2084",
            "-colorspace",
            "bt2020nc",
            "-movflags",
            "+write_colr",
            tagged.to_str().unwrap(),
        ],
    )
    .await;
    let before = probe(&tagged).await;
    let video = &before["streams"][0];
    assert_eq!(video["color_primaries"], "bt2020");
    assert_eq!(video["color_transfer"], "smpte2084");
    assert!(eligible(&before, std::fs::metadata(&tagged).unwrap().len()));
    tokio::fs::create_dir(&output).await.unwrap();
    let info = crate::probe_video(&tagged).await.unwrap();
    crate::run_ffmpeg_hls(
        &tagged,
        &output,
        false,
        &info,
        true,
        crate::MediaPolicy::AllowEncode,
    )
    .await
    .unwrap();
    crate::remux_ts_to_fmp4(&output, crate::MediaPolicy::AllowEncode)
        .await
        .unwrap();
    crate::require_progressive_outputs(&output).await.unwrap();
    for variant in ["stream_720p", "stream_480p"] {
        for ext in ["m3u8", "mp4"] {
            let after = probe(&output.join(format!("{variant}.{ext}"))).await;
            for field in [
                "color_primaries",
                "color_transfer",
                "color_space",
                "color_range",
            ] {
                assert_eq!(
                    after["streams"][0][field], video[field],
                    "lost {field} in {variant}.{ext}"
                );
            }
        }
    }
}

async fn audible_frequency(path: &Path) -> f64 {
    let out = media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-i",
            path.to_str().unwrap(),
            "-ss",
            "0.1",
            "-t",
            "0.25",
            "-map",
            "0:a:0",
            "-ac",
            "1",
            "-ar",
            "44100",
            "-f",
            "s16le",
            "-",
        ],
    )
    .await;
    let samples: Vec<i16> = out
        .stdout
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect();
    assert!(samples.len() > 10000);
    let crossings = samples.windows(2).filter(|p| p[0] <= 0 && p[1] > 0).count();
    crossings as f64 * 44100.0 / samples.len() as f64
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn edited_aac_does_not_restore_trimmed_audio_or_delay_video() {
    let dir = tempfile::tempdir().unwrap();
    let video = dir.path().join("video.mp4");
    let audio = dir.path().join("audio.m4a");
    let input = dir.path().join("edited.mp4");
    let output = dir.path().join("hls");
    make_source(&video, false).await;
    media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=880:sample_rate=44100:duration=2",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:sample_rate=44100:duration=2",
            "-filter_complex",
            "[0:a][1:a]concat=n=2:v=0:a=1",
            "-c:a",
            "aac",
            "-b:a",
            "32k",
            audio.to_str().unwrap(),
        ],
    )
    .await;
    media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-i",
            video.to_str().unwrap(),
            "-itsoffset",
            "-2",
            "-i",
            audio.to_str().unwrap(),
            "-map",
            "0:v",
            "-map",
            "1:a",
            "-c",
            "copy",
            input.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        eligible(
            &probe(&input).await,
            std::fs::metadata(&input).unwrap().len()
        ),
        "metadata alone misses audio edits"
    );
    tokio::fs::create_dir(&output).await.unwrap();
    assert!(
        !try_reuse(&input, &output).await.unwrap(),
        "must not copy discarded audio preroll"
    );
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 0);
    let info = crate::probe_video(&input).await.unwrap();
    crate::run_ffmpeg_hls(
        &input,
        &output,
        false,
        &info,
        true,
        crate::MediaPolicy::AllowEncode,
    )
    .await
    .unwrap();
    crate::remux_ts_to_fmp4(&output, crate::MediaPolicy::AllowEncode)
        .await
        .unwrap();
    crate::require_progressive_outputs(&output).await.unwrap();
    let original_frequency = audible_frequency(&input).await;
    assert!((original_frequency - 440.0).abs() < 40.0);
    for name in ["stream_720p.mp4", "stream_480p.mp4"] {
        let result = output.join(name);
        let p = probe(&result).await;
        let streams = p["streams"].as_array().unwrap();
        let v = streams.iter().find(|s| s["codec_type"] == "video").unwrap();
        let a = streams.iter().find(|s| s["codec_type"] == "audio").unwrap();
        assert!(
            number(&v["start_time"]).unwrap() < 0.05,
            "black video preroll restored"
        );
        assert!(
            number(&a["duration"]).unwrap() < 2.1,
            "trimmed audio restored"
        );
        assert!(
            (audible_frequency(&result).await - original_frequency).abs() < 40.0,
            "wrong audible content"
        );
    }
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn changing_h264_configuration_is_not_copied() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("joined.mp4");
    let output = dir.path().join("hls");
    let a = dir.path().join("a.ts");
    let b = dir.path().join("b.ts");
    for (path, source, profile, pix_fmt) in [
        (
            &a,
            "color=red:size=160x160:rate=25:duration=1",
            "baseline",
            "yuv420p",
        ),
        (
            &b,
            "color=blue:size=640x640:rate=25:duration=1",
            "high444",
            "yuv444p",
        ),
    ] {
        media_tool(
            "ffmpeg",
            &[
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                source,
                "-c:v",
                "libx264",
                "-profile:v",
                profile,
                "-pix_fmt",
                pix_fmt,
                "-bf",
                "0",
                "-f",
                "mpegts",
                path.to_str().unwrap(),
            ],
        )
        .await;
    }
    let concat = format!("concat:{}|{}", a.display(), b.display());
    media_tool(
        "ffmpeg",
        &[
            "-v",
            "error",
            "-i",
            &concat,
            "-c",
            "copy",
            input.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        eligible(
            &probe(&input).await,
            std::fs::metadata(&input).unwrap().len()
        ),
        "first sequence alone looks compatible"
    );
    tokio::fs::create_dir(&output).await.unwrap();
    assert!(
        !try_reuse(&input, &output).await.unwrap(),
        "changed sequence must not be copied"
    );
    assert_eq!(std::fs::read_dir(&output).unwrap().count(), 0);
}

#[test]
fn avc_configuration_changes_and_invalid_packet_ranges_are_rejected() {
    let video = json!({"is_avc":"true","nal_length_size":"4"});
    let packet = json!({"packets":[{"pos":"0","size":"5"}]});
    assert!(stable_avc_packets(&packet, &[0, 0, 0, 1, 0x65], &video));
    for header in [0x67, 0x68, 0x6d, 0x6f, 0xe5, 0] {
        assert!(!stable_avc_packets(&packet, &[0, 0, 0, 1, header], &video));
    }
    assert!(!stable_avc_packets(&packet, &[0, 0, 0, 2, 0x65], &video));
    assert!(!stable_avc_packets(&packet, &[0, 0, 0, 0, 0x65], &video));
    assert!(!stable_avc_packets(&packet, &[0, 0, 0, 1], &video));
    assert!(!stable_avc_packets(
        &json!({"packets":[{"pos":"18446744073709551615","size":"5"}]}),
        &[0, 0, 0, 1, 0x65],
        &video
    ));
}

#[test]
fn changed_avc_sample_description_cannot_bypass_parameter_set_checks() {
    let video = json!({"is_avc":"true","nal_length_size":"4"});
    for side_data in [
        json!([{"side_data_type":"New Extradata"}]),
        json!([{"side_data_type":"unknown"}]),
        json!({}),
    ] {
        let packet = json!({"packets":[{"pos":"0","size":"5","side_data_list":side_data}]});
        assert!(!stable_avc_packets(&packet, &[0, 0, 0, 1, 0x65], &video));
    }
}

fn avcc_metadata(data: &[u8]) -> Value {
    use std::fmt::Write;
    let mut dump = String::new();
    for (i, bytes) in data.chunks(16).enumerate() {
        write!(dump, "\n{:08x}: {}  fixture", i * 16, hex::encode(bytes)).unwrap();
    }
    json!({"extradata":dump,"nal_length_size":"4","level":30})
}

#[test]
fn avcc_must_contain_exactly_one_initial_configuration() {
    // Synthetic avcC structure: one SPS and one PPS. SPS/PPS content is
    // decoded by ffprobe in production; this check constrains the container.
    let baseline = [
        1, 66, 0, 30, 255, 225, 0, 4, 0x67, 66, 0, 30, 1, 0, 2, 0x68, 0,
    ];
    assert!(single_avc_config(&avcc_metadata(&baseline)));
    let mut high = baseline;
    high[1] = 100;
    high[9] = 100;
    assert!(single_avc_config(&avcc_metadata(
        &[high.as_slice(), &[253, 248, 248, 0]].concat()
    )));
    for (index, value) in [(0, 0), (5, 226), (12, 2), (7, 255), (15, 0x67)] {
        let mut bad = baseline;
        bad[index] = value;
        assert!(
            !single_avc_config(&avcc_metadata(&bad)),
            "invalid avcC at {index}"
        );
    }
    assert!(!single_avc_config(&json!({})));
    assert!(!single_avc_config(&json!({"extradata":"not a hexdump"})));
    assert!(!single_avc_config(&avcc_metadata(&baseline[..16])));
    assert!(!single_avc_config(&avcc_metadata(
        &[baseline.as_slice(), &[0]].concat()
    )));
}

#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn single_main_and_high_profile_configurations_still_copy() {
    for profile in ["main", "high"] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("source.mp4");
        let output = dir.path().join("hls");
        media_tool(
            "ffmpeg",
            &[
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x320:rate=25:duration=2",
                "-c:v",
                "libx264",
                "-profile:v",
                profile,
                "-level:v",
                "3.0",
                "-pix_fmt",
                "yuv420p",
                "-bf",
                "0",
                "-crf",
                "36",
                input.to_str().unwrap(),
            ],
        )
        .await;
        let p = probe(&input).await;
        assert_eq!(
            p["streams"][0]["profile"],
            if profile == "main" { "Main" } else { "High" }
        );
        tokio::fs::create_dir(&output).await.unwrap();
        assert!(
            try_reuse(&input, &output).await.unwrap(),
            "compatible {profile} config rejected"
        );
        assert_eq!(
            frames(&output.join("stream_480p.m3u8")).await,
            frames(&input).await
        );
    }
}

#[tokio::test]
async fn impossible_file_sizes_skip_media_probing() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("not-media.mp4");
    for length in [0, 1_875_001] {
        tokio::fs::write(&input, vec![0; length]).await.unwrap();
        assert!(!try_reuse(&input, &dir.path().join("output"))
            .await
            .expect("size rejection must not invoke media tools"));
    }
}

#[tokio::test]
async fn archive_copy_only_rejection_is_terminal_without_encoding() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("incompatible.mp4");
    tokio::fs::write(&input, []).await.unwrap();
    let output = dir.path().join("hls");
    tokio::fs::create_dir(&output).await.unwrap();
    let info = crate::VideoInfo {
        width: 480,
        height: 480,
        display_width: 480,
        display_height: 480,
        rotation: 0,
        has_audio: false,
        preserve_source_timing: false,
    };
    for allow_reuse in [true, false] {
        let error = crate::run_ffmpeg_hls(
            &input,
            &output,
            false,
            &info,
            allow_reuse,
            crate::MediaPolicy::CopyOnly,
        )
        .await
        .err()
        .expect("incompatible archive must be rejected");
        assert!(
            error.is::<crate::TerminalTranscode>(),
            "archive must stop before encoding: {error:#}"
        );
        assert_eq!(error.to_string(), "archive_remux_incompatible");
    }
}

/// Runs tool interception in its own process so PATH/failure injection cannot
/// affect concurrent media tests. Fixtures and ffmpeg are real; only the
/// audio-copy failure is injected at the process boundary.
#[tokio::test]
#[ignore = "requires ffmpeg and ffprobe"]
async fn archive_policy_encoder_boundaries() {
    const CHILD: &str = "DIVINE_POLICY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let real = std::process::Command::new("which")
            .arg("ffmpeg")
            .output()
            .unwrap();
        assert!(real.status.success());
        let real = String::from_utf8(real.stdout).unwrap();
        let wrapper = dir.path().join("ffmpeg");
        std::fs::write(&wrapper, r#"#!/bin/sh
printf '%s\n' "$@" >> "$DIVINE_POLICY_TEST_CALLS"
previous=''
for arg in "$@"; do
    if [ "$previous" = '-c:a' ] && [ "$arg" = 'copy' ] && [ "$DIVINE_POLICY_TEST_FAIL_COPY" = '1' ]; then
        printf 'injected audio-copy failure\n' >&2
        exit 1
    fi
    previous="$arg"
done
exec "$DIVINE_POLICY_TEST_FFMPEG" "$@"
"#).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "media_reuse::tests::archive_policy_encoder_boundaries",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("DIVINE_POLICY_TEST_CALLS", dir.path().join("calls"))
            .env("DIVINE_POLICY_TEST_FFMPEG", real.trim())
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    dir.path().display(),
                    std::env::var("PATH").unwrap()
                ),
            )
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    use crate::MediaPolicy::{AllowEncode, CopyOnly};
    let calls = std::path::PathBuf::from(std::env::var_os("DIVINE_POLICY_TEST_CALLS").unwrap());
    let clear = || std::fs::write(&calls, []).unwrap();
    let assert_no_encoder = || {
        let args = std::fs::read_to_string(&calls).unwrap();
        assert!(
            !args
                .lines()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| (pair[0] == "-c"
                    || pair[0].starts_with("-c:")
                    || pair[0].starts_with("-codec"))
                    && pair[1] != "copy"),
            "encoder invoked: {args}"
        );
    };
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("source.mp4");
    make_source(&input, true).await;
    let original = tokio::fs::read(&input).await.unwrap();
    let info = crate::probe_video(&input).await.unwrap();
    let expected_frames = frames(&input).await;
    let expected_audio = audio_packets(&input).await;
    clear();
    for allow_reuse in [true, false] {
        let output = dir.path().join(format!("copy-{allow_reuse}"));
        tokio::fs::create_dir(&output).await.unwrap();
        let generation =
            crate::run_ffmpeg_hls(&input, &output, false, &info, allow_reuse, CopyOnly)
                .await
                .unwrap();
        assert_eq!(generation.method, crate::HlsMethod::StreamCopy);
        crate::remux_ts_to_fmp4(&output, CopyOnly).await.unwrap();
        for name in ["stream_720p.mp4", "stream_480p.mp4"] {
            assert_eq!(frames(&output.join(name)).await, expected_frames);
            assert_eq!(audio_packets(&output.join(name)).await, expected_audio);
        }
        assert_eq!(tokio::fs::read(&input).await.unwrap(), original);
    }
    assert_no_encoder();
    let incompatible = dir.path().join("non-square-pixels.mp4");
    make_source_with_sar(&incompatible, true, "36", "4/3").await;
    let incompatible_original = tokio::fs::read(&incompatible).await.unwrap();
    clear();
    for allow_reuse in [true, false] {
        let output = dir.path().join(format!("reject-{allow_reuse}"));
        tokio::fs::create_dir(&output).await.unwrap();
        let error =
            crate::run_ffmpeg_hls(&incompatible, &output, false, &info, allow_reuse, CopyOnly)
                .await
                .err()
                .unwrap();
        assert!(error.is::<crate::TerminalTranscode>());
        assert_eq!(std::fs::read_dir(output).unwrap().count(), 0);
        assert_eq!(
            tokio::fs::read(&incompatible).await.unwrap(),
            incompatible_original
        );
    }
    assert_no_encoder();
    // A real probe failure is retryable rather than archive incompatibility.
    tokio::fs::write(&incompatible, b"not media").await.unwrap();
    let error = crate::run_ffmpeg_hls(
        &incompatible,
        &dir.path().join("broken"),
        false,
        &info,
        false,
        CopyOnly,
    )
    .await
    .err()
    .unwrap();
    assert!(!error.is::<crate::TerminalTranscode>());
    assert_no_encoder();

    let source_hls = dir.path().join("copy-false");
    for name in ["stream_720p.mp4", "stream_480p.mp4"] {
        tokio::fs::remove_file(source_hls.join(name)).await.unwrap();
    }
    std::env::set_var("DIVINE_POLICY_TEST_FAIL_COPY", "1");
    clear();
    crate::remux_ts_to_fmp4(&source_hls, CopyOnly)
        .await
        .unwrap();
    assert!(source_hls.join("master.m3u8").is_file());
    assert!(!source_hls.join("stream_720p.mp4").exists());
    assert!(!source_hls.join("stream_480p.mp4").exists());
    assert_no_encoder();

    crate::hls_claim::tests::assert_copy_only_forced_repair_skips_optional_aliases(
        bytes::Bytes::from(original.clone()),
    )
    .await;
    assert_no_encoder();

    clear();
    crate::hls_claim::tests::assert_copy_only_backfill_never_encodes([
        bytes::Bytes::from(
            tokio::fs::read(source_hls.join("stream_720p.ts"))
                .await
                .unwrap(),
        ),
        bytes::Bytes::from(
            tokio::fs::read(source_hls.join("stream_480p.ts"))
                .await
                .unwrap(),
        ),
    ])
    .await;
    assert_no_encoder();
    // The same audio-copy failure may encode only after explicit permission.
    clear();
    crate::remux_variant(
        &source_hls.join("stream_720p.ts"),
        &dir.path().join("allowed.mp4"),
        "stream_720p",
        AllowEncode,
    )
    .await
    .unwrap();
    assert!(std::fs::read_to_string(&calls)
        .unwrap()
        .lines()
        .any(|arg| arg == "aac"));
    std::env::remove_var("DIVINE_POLICY_TEST_FAIL_COPY");
    clear();
    let output = dir.path().join("allowed-encode");
    tokio::fs::create_dir(&output).await.unwrap();
    let result = crate::run_ffmpeg_hls(&input, &output, false, &info, false, AllowEncode)
        .await
        .unwrap();
    assert_eq!(result.method, crate::HlsMethod::Encode);
    assert!(std::fs::read_to_string(&calls)
        .unwrap()
        .lines()
        .any(|arg| arg == "libx264"));
}

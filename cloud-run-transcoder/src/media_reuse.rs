// ABOUTME: Conservative admission for copying existing compressed media streams.
// ABOUTME: Unknown media properties keep the normal encoding path.
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::{path::Path, time::Duration};
use tokio::process::Command;

/// Repackage a qualifying original in private staging. No original writes and
/// no visible outputs until the complete HLS set can replace the empty output
/// directory. Dropping the future kills media children and drops staging.
pub async fn try_reuse(input: &Path, output: &Path) -> Result<bool> {
    let metadata = probe(input, None).await?;
    let bytes = tokio::fs::metadata(input).await?.len();
    if !eligible(&metadata, bytes) {
        return Ok(false);
    }
    let video = metadata["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["codec_type"] == "video")
        .unwrap();
    // Stream metadata describes the first sequence, not necessarily all frames.
    if !probe_compatible_frames(input, video).await? {
        return Ok(false);
    }
    let duration = number(&video["duration"]).unwrap();
    let packets = probe(input, Some("v:0")).await?;
    if !safe_packets(&packets, duration)
        || !stable_avc_packets(&packets, &tokio::fs::read(input).await?, video)
    {
        return Ok(false);
    }
    let audio = metadata["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["codec_type"] == "audio");
    if let Some(audio) = audio {
        if !safe_audio_packets(&probe(input, Some("a:0")).await?, audio) {
            return Ok(false);
        }
    }
    let audio = audio.is_some();
    let parent = output.parent().context("Output directory has no parent")?;
    let candidate = tempfile::Builder::new()
        .prefix(".media-reuse-")
        .tempdir_in(parent)?;
    let pattern = candidate.path().join("stream_%v.m3u8");
    let mut command = Command::new("ffmpeg");
    command
        .args(["-v", "error", "-nostdin", "-y", "-i"])
        .arg(input);
    for _ in 0..2 {
        command.args(["-map", "0:v:0"]);
        if audio {
            command.args(["-map", "0:a:0"]);
        }
    }
    command
        .args([
            "-map_metadata",
            "-1",
            "-c",
            "copy",
            "-f",
            "hls",
            "-hls_time",
            "10",
            "-hls_playlist_type",
            "vod",
            "-hls_flags",
            "single_file",
            "-master_pl_name",
            "master.m3u8",
            "-var_stream_map",
            if audio {
                "v:0,a:0,name:720p v:1,a:1,name:480p"
            } else {
                "v:0,name:720p v:1,name:480p"
            },
        ])
        .arg(pattern);
    let result = crate::media_command::output(&mut command, Duration::from_secs(120)).await?;
    ensure!(result.status.success(), "Stream-copy packaging failed");
    for name in [
        "master.m3u8",
        "stream_720p.m3u8",
        "stream_480p.m3u8",
        "stream_720p.ts",
        "stream_480p.ts",
    ] {
        ensure!(
            tokio::fs::metadata(candidate.path().join(name))
                .await?
                .len()
                > 0,
            "Empty stream-copy output"
        );
    }
    // MP4 colr metadata is not necessarily present in the H.264 bitstream.
    // Stream copying into TS can silently lose it while retaining identical
    // YUV samples, so a decode-only check cannot establish display fidelity.
    let copied = probe(&candidate.path().join("stream_720p.ts"), None).await?;
    if !preserves_color(video, &copied) {
        return Ok(false);
    }
    // Decode one identical copy before publication, so damaged source packets
    // cannot become a successfully completed derivative merely via -c copy.
    let result = crate::media_command::output(
        Command::new("ffmpeg")
            .args([
                "-v",
                "error",
                "-nostdin",
                "-xerror",
                "-err_detect",
                "explode",
                "-i",
            ])
            .arg(candidate.path().join("stream_720p.m3u8"))
            .args(["-map", "0:v:0", "-map", "0:a:0?", "-f", "null", "-"]),
        Duration::from_secs(120),
    )
    .await?;
    ensure!(
        result.status.success(),
        "Copied media did not decode cleanly"
    );
    // rename is atomic and refuses to replace a nonempty output directory.
    // Failed attempts therefore cannot leak candidate artifacts into fallback.
    tokio::fs::rename(candidate.path(), output)
        .await
        .context("Publish local stream-copy outputs")?;
    Ok(true)
}

async fn probe(input: &Path, packets: Option<&str>) -> Result<Value> {
    let mut command = Command::new("ffprobe");
    command.args(["-v", "error", "-of", "json"]);
    if let Some(selector) = packets {
        command.args(["-select_streams", selector, "-show_packets"]);
    } else {
        command.args(["-show_streams", "-show_format"]);
    }
    let result =
        crate::media_command::output(command.arg(input), crate::media_command::PROBE_TIMEOUT)
            .await?;
    ensure!(result.status.success(), "Reuse media probe failed");
    serde_json::from_slice(&result.stdout).context("Parse reuse media probe")
}

fn preserves_color(source: &Value, candidate: &Value) -> bool {
    let Some(video) = candidate["streams"]
        .as_array()
        .and_then(|streams| streams.iter().find(|s| s["codec_type"] == "video"))
    else {
        return false;
    };
    [
        "color_range",
        "color_space",
        "color_transfer",
        "color_primaries",
        "chroma_location",
    ]
    .iter()
    .all(|field| match source[field].as_str() {
        None | Some("unknown" | "unspecified") => true,
        Some(value) => video[field].as_str() == Some(value),
    })
}

async fn probe_compatible_frames(input: &Path, video: &Value) -> Result<bool> {
    let result = crate::media_command::output(
        Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_frames",
                "-show_entries",
                "frame=interlaced_frame,width,height,pix_fmt,sample_aspect_ratio",
                "-of",
                "json",
            ])
            .arg(input),
        crate::media_command::PROBE_TIMEOUT,
    )
    .await?;
    ensure!(result.status.success(), "Progressive frame probe failed");
    let value: Value = serde_json::from_slice(&result.stdout)?;
    Ok(compatible_frames(&value, video))
}

fn compatible_frames(value: &Value, video: &Value) -> bool {
    value["frames"].as_array().is_some_and(|frames| {
        !frames.is_empty()
            && frames.iter().all(|frame| {
                frame["interlaced_frame"].as_u64() == Some(0)
                    && frame["width"] == video["width"]
                    && frame["height"] == video["height"]
                    && frame["pix_fmt"] == "yuv420p"
                    && matches!(
                        frame["sample_aspect_ratio"].as_str(),
                        Some("1:1" | "0:1" | "N/A")
                    )
            })
    })
}

fn number(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|n| n.is_finite())
}

fn rate(value: &Value) -> Option<f64> {
    let (n, d) = value.as_str()?.split_once('/')?;
    let n: f64 = n.parse().ok()?;
    let d: f64 = d.parse().ok()?;
    (n.is_finite() && d.is_finite() && n > 0.0 && d > 0.0).then_some(n / d)
}

fn eligible(probe: &Value, file_bytes: u64) -> bool {
    let Some(streams) = probe["streams"].as_array() else {
        return false;
    };
    let videos: Vec<_> = streams
        .iter()
        .filter(|s| s["codec_type"] == "video")
        .collect();
    let audios: Vec<_> = streams
        .iter()
        .filter(|s| s["codec_type"] == "audio")
        .collect();
    if videos.len() != 1 || audios.len() > 1 || streams.len() != 1 + audios.len() {
        return false;
    }
    let v = videos[0];
    let Some(duration) = number(&v["duration"]).filter(|d| *d > 0.0 && *d <= 10.0) else {
        return false;
    };
    let Some(container_duration) = number(&probe["format"]["duration"]) else {
        return false;
    };
    if !probe["format"]["format_name"]
        .as_str()
        .is_some_and(|s| s.split(',').any(|f| f == "mp4"))
        || (container_duration - duration).abs() > 0.1
        || file_bytes == 0
        || file_bytes as f64 * 8.0 / duration > 500_000.0
    {
        return false;
    }
    if v["codec_name"] != "h264"
        || !matches!(
            v["profile"].as_str(),
            Some("Baseline" | "Constrained Baseline" | "Main" | "High")
        )
        || !v["level"].as_u64().is_some_and(|l| (10..=31).contains(&l))
        || v["pix_fmt"] != "yuv420p"
        || (!v["field_order"].is_null() && v["field_order"] != "progressive")
        || v["has_b_frames"].as_u64() != Some(0)
        || !rate(&v["avg_frame_rate"]).is_some_and(|fps| fps <= 30.0)
        || !number(&v["start_time"]).is_some_and(|n| n.abs() <= 0.001)
        || !["width", "height"].iter().all(|k| {
            v[k].as_u64()
                .is_some_and(|n| (2..=480).contains(&n) && n % 2 == 0)
        })
    {
        return false;
    }
    // Unspecified SAR defaults to square pixels. A display matrix can also
    // reflect/shear, so even a reported zero rotation is not sufficient.
    if (!v["sample_aspect_ratio"].is_null()
        && !matches!(
            v["sample_aspect_ratio"].as_str(),
            Some("1:1" | "0:1" | "N/A")
        ))
        || (!v["side_data_list"].is_null() && !v["side_data_list"].is_array())
        || (!v["tags"]["rotate"].is_null() && number(&v["tags"]["rotate"]) != Some(0.0))
        || v["side_data_list"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|s| s["side_data_type"] == "Display Matrix")
        })
    {
        return false;
    }
    audios.iter().all(|a| {
        a["codec_name"] == "aac"
            && a["profile"] == "LC"
            && a["channels"].as_u64().is_some_and(|c| (1..=2).contains(&c))
            && matches!(a["sample_rate"].as_str(), Some("44100" | "48000"))
            && number(&a["bit_rate"]).is_some_and(|n| n > 0.0 && n <= 96_000.0)
            && number(&a["start_time"]).is_some_and(|n| n.abs() <= 0.05)
            && number(&a["duration"]).is_some_and(|n| n > 0.0 && (n - duration).abs() <= 0.1)
    })
}

fn safe_packets(probe: &Value, duration: f64) -> bool {
    let Some(packets) = probe["packets"].as_array().filter(|p| !p.is_empty()) else {
        return false;
    };
    if !duration.is_finite()
        || duration <= 0.0
        || duration > 10.0
        || !packets[0]["flags"]
            .as_str()
            .is_some_and(|f| f.contains('K'))
    {
        return false;
    }
    let mut previous = -1.0;
    let mut end = 0.0;
    for (i, packet) in packets.iter().enumerate() {
        let (Some(pts), Some(dts), Some(length)) = (
            number(&packet["pts_time"]),
            number(&packet["dts_time"]),
            number(&packet["duration_time"]),
        ) else {
            return false;
        };
        if pts < 0.0
            || pts <= previous
            || (pts - dts).abs() > 0.001
            || length <= 0.0
            || pts + length > duration + 0.05
            || (pts - end).abs() > 0.001
            || (i == 0 && pts > 0.001)
        {
            return false;
        }
        previous = pts;
        end = pts + length;
    }
    (end - duration).abs() <= 0.05
}

#[cfg(test)]
#[path = "media_reuse_tests.rs"]
mod tests;

fn safe_audio_packets(probe: &Value, audio: &Value) -> bool {
    let Some(packets) = probe["packets"].as_array().filter(|p| !p.is_empty()) else {
        return false;
    };
    let (Some(rate), Some(duration)) = (number(&audio["sample_rate"]), number(&audio["duration"]))
    else {
        return false;
    };
    if ![44100.0, 48000.0].contains(&rate) {
        return false;
    }
    let frame = 1024.0 / rate;
    let mut previous_end = None;
    for (i, p) in packets.iter().enumerate() {
        let (Some(pts), Some(dts), Some(length)) = (
            number(&p["pts_time"]),
            number(&p["dts_time"]),
            number(&p["duration_time"]),
        ) else {
            return false;
        };
        if (pts - dts).abs() > 0.001
            || length <= 0.0
            || length > frame + 0.001
            || (i == 0 && (pts < -frame - 0.001 || pts > 0.05))
            || previous_end.is_some_and(|end: f64| (pts - end).abs() > 0.001)
            || pts + length > duration + 0.05
        {
            return false;
        }
        let Some(flags) = p["flags"].as_str() else {
            return false;
        };
        if flags.contains('C') || (flags.contains('D') && (i != 0 || pts >= 0.0)) {
            return false;
        }
        if !p["side_data_list"].is_null() {
            let Some(items) = p["side_data_list"].as_array() else {
                return false;
            };
            for data in items {
                if data["side_data_type"] != "Skip Samples" {
                    return false;
                }
                let (Some(skip), Some(discard)) = (
                    data["skip_samples"].as_u64(),
                    data["discard_padding"].as_u64(),
                ) else {
                    return false;
                };
                // Allow only ordinary AAC encoder priming, not edit-list preroll.
                // Permit only a final partial AAC frame; the shared MP4
                // loop-duration correction bounds its presentation.
                if discard > 1024
                    || (discard > 0
                        && (i + 1 != packets.len()
                            || (discard as f64 + length * rate - 1024.0).abs() > 2.0))
                    || skip > 1024
                    || (skip > 0
                        && (i != 0 || pts >= 0.0 || (skip as f64 + pts * rate).abs() > 2.0))
                {
                    return false;
                }
            }
        }
        previous_end = Some(pts + length);
    }
    previous_end.is_some_and(|end| (end - duration).abs() <= 0.05)
}

// MP4's stream profile/level describe its avcC configuration. Reject in-band
// parameter sets so later packets cannot silently replace that configuration.
fn stable_avc_packets(probe: &Value, bytes: &[u8], video: &Value) -> bool {
    fn integer(value: &Value) -> Option<usize> {
        value
            .as_u64()
            .and_then(|v| usize::try_from(v).ok())
            .or_else(|| value.as_str()?.parse().ok())
    }
    let Some(length_size) = integer(&video["nal_length_size"]).filter(|n| (1..=4).contains(n))
    else {
        return false;
    };
    if video["is_avc"] != "true" {
        return false;
    }
    let Some(packets) = probe["packets"].as_array().filter(|p| !p.is_empty()) else {
        return false;
    };
    for packet in packets {
        let (Some(pos), Some(size)) = (integer(&packet["pos"]), integer(&packet["size"])) else {
            return false;
        };
        let Some(end) = pos.checked_add(size) else {
            return false;
        };
        let Some(mut data) = bytes.get(pos..end) else {
            return false;
        };
        let mut picture = false;
        while !data.is_empty() {
            let Some(prefix) = data.get(..length_size) else {
                return false;
            };
            let len = prefix
                .iter()
                .fold(0usize, |n, b| (n << 8) | usize::from(*b));
            data = &data[length_size..];
            let Some(nal) = data.get(..len).filter(|n| !n.is_empty()) else {
                return false;
            };
            let kind = nal[0] & 31;
            if nal[0] & 0x80 != 0 || !matches!(kind, 1 | 5 | 6 | 9 | 12) {
                return false;
            }
            picture |= matches!(kind, 1 | 5);
            data = &data[len..];
        }
        if !picture {
            return false;
        }
    }
    true
}

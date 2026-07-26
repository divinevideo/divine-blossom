// ABOUTME: Builds and executes aspect-specific FFmpeg compilation renders
// ABOUTME: Normalizes clips, burns creator credits and branding, and falls back from NVENC

use crate::domain::{
    Aspect, AudioSettings, Credit, CreditSettings, FitMode, Watermark, WatermarkPosition,
};
use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;
use tokio::process::Command;

const FONT_PATH: &str = "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf";

#[derive(Debug, Clone)]
pub struct ClipInput {
    pub path: PathBuf,
    pub coordinate: String,
    pub duration_sec: f64,
    pub has_audio: bool,
    pub fit: FitMode,
    pub credit: Credit,
}

#[derive(Debug, Clone)]
pub struct AspectRenderJob {
    pub aspect: Aspect,
    pub clips: Vec<ClipInput>,
    pub logo_path: PathBuf,
    pub output_path: PathBuf,
    pub watermark: Watermark,
    pub credit: CreditSettings,
    pub audio: AudioSettings,
    pub use_gpu: bool,
}

pub fn build_ffmpeg_args(job: &AspectRenderJob) -> Result<Vec<String>> {
    if job.clips.is_empty() {
        bail!("cannot render an empty compilation");
    }
    if job
        .clips
        .iter()
        .any(|clip| !clip.duration_sec.is_finite() || clip.duration_sec <= 0.0)
    {
        bail!("all clips must have a positive finite duration");
    }

    let mut args = vec![
        "-y".into(),
        "-hide_banner".into(),
        "-loglevel".into(),
        "warning".into(),
    ];
    for clip in &job.clips {
        args.push("-i".into());
        args.push(clip.path.to_string_lossy().into_owned());
    }
    if job.watermark.enabled {
        args.push("-i".into());
        args.push(job.logo_path.to_string_lossy().into_owned());
    }

    args.push("-filter_complex".into());
    args.push(build_filter_graph(job));
    args.extend(["-map".into(), "[v_final]".into()]);
    args.extend(["-map".into(), "[a_final]".into()]);

    if job.use_gpu {
        args.extend(
            ["-c:v", "h264_nvenc", "-preset", "p5", "-rc:v", "vbr"]
                .into_iter()
                .map(String::from),
        );
    } else {
        args.extend(
            ["-c:v", "libx264", "-preset", "medium"]
                .into_iter()
                .map(String::from),
        );
    }
    args.extend(
        [
            "-b:v",
            "8000k",
            "-maxrate",
            "10000k",
            "-bufsize",
            "16000k",
            "-pix_fmt",
            "yuv420p",
            "-profile:v",
            "high",
            "-c:a",
            "aac",
            "-b:a",
            "192k",
            "-ar",
            "48000",
            "-movflags",
            "+faststart",
        ]
        .into_iter()
        .map(String::from),
    );
    args.push(job.output_path.to_string_lossy().into_owned());
    Ok(args)
}

fn build_filter_graph(job: &AspectRenderJob) -> String {
    let (width, height) = job.aspect.dimensions();
    let mut filters = Vec::new();
    let mut concat_inputs = String::new();

    for (index, clip) in job.clips.iter().enumerate() {
        let fit_output = format!("vfit{index}");
        filters.push(fit_filter(
            &format!("{index}:v:0"),
            &fit_output,
            clip.fit,
            width,
            height,
        ));
        filters.push(format!(
            "[{fit_output}]fps=30,format=yuv420p,setsar=1,setpts=PTS-STARTPTS[v{index}]"
        ));

        if clip.has_audio {
            filters.push(format!(
                "[{index}:a:0]aformat=sample_fmts=fltp:sample_rates=48000:\
                 channel_layouts=stereo,aresample=48000,asetpts=PTS-STARTPTS[a{index}]"
            ));
        } else {
            filters.push(format!(
                "anullsrc=channel_layout=stereo:sample_rate=48000:d={:.3}[a{index}]",
                clip.duration_sec
            ));
        }
        concat_inputs.push_str(&format!("[v{index}][a{index}]"));
    }
    filters.push(format!(
        "{concat_inputs}concat=n={}:v=1:a=1[vcat][acat]",
        job.clips.len()
    ));

    let mut current_video = "vcat".to_string();
    let mut start = 0.0;
    for (index, clip) in job.clips.iter().enumerate() {
        let next = format!("vcredit{index}");
        let text = format_credit(&clip.credit, &job.credit);
        filters.push(credit_filter(
            &current_video,
            &next,
            &text,
            start,
            height,
            job.credit.duration_ms,
        ));
        current_video = next;
        start += clip.duration_sec;
    }

    if job.watermark.enabled {
        let logo_index = job.clips.len();
        filters.push(watermark_filter(
            &current_video,
            &format!("{logo_index}:v:0"),
            "v_final",
            width,
            &job.watermark,
        ));
    } else {
        filters.push(format!("[{current_video}]null[v_final]"));
    }
    filters.push(format!(
        "[acat]loudnorm=I={:.1}:TP=-1.5:LRA=11[a_final]",
        job.audio.target_lufs
    ));
    filters.join(";")
}

fn fit_filter(input: &str, output: &str, fit: FitMode, width: u32, height: u32) -> String {
    match fit {
        FitMode::BlurPad => format!(
            "[{input}]split=2[bg{output}][fg{output}];\
             [bg{output}]scale={width}:{height}:force_original_aspect_ratio=increase,\
             crop={width}:{height},boxblur=20:5[blur{output}];\
             [fg{output}]scale={width}:{height}:force_original_aspect_ratio=decrease[front{output}];\
             [blur{output}][front{output}]overlay=(W-w)/2:(H-h)/2[{output}]"
        ),
        FitMode::CenterCrop => format!(
            "[{input}]scale={width}:{height}:force_original_aspect_ratio=increase,\
             crop={width}:{height}[{output}]"
        ),
        FitMode::Letterbox => format!(
            "[{input}]scale={width}:{height}:force_original_aspect_ratio=decrease,\
             pad={width}:{height}:(ow-iw)/2:(oh-ih)/2:color=black[{output}]"
        ),
    }
}

fn format_credit(credit: &Credit, settings: &CreditSettings) -> String {
    let display_name = settings
        .show_display_name
        .then_some(credit.display_name.as_deref())
        .flatten();
    let nip05 = settings
        .show_nip05
        .then_some(credit.nip05.as_deref())
        .flatten();
    match (display_name, nip05) {
        (Some(name), Some(nip05)) => format!("{name} • {nip05}"),
        (Some(name), None) => name.into(),
        (None, Some(nip05)) => nip05.into(),
        (None, None) => format!("pubkey: {}", credit.pubkey),
    }
}

fn credit_filter(
    input: &str,
    output: &str,
    text: &str,
    start: f64,
    height: u32,
    duration_ms: u32,
) -> String {
    if duration_ms == 0 {
        return format!("[{input}]null[{output}]");
    }
    let end = start + f64::from(duration_ms) / 1000.0;
    let fade_in_end = (start + 0.3).min(end);
    let fade_out_start = (end - 0.3).max(start);
    let y = (height as f32 * 0.78).round() as u32;
    format!(
        "[{input}]drawtext=fontfile={FONT_PATH}:text='{text}':\
         x=(w-text_w)/2:y={y}:fontsize=42:fontcolor=white:\
         box=1:boxcolor=black@0.55:boxborderw=12:\
         enable='between(t,{start:.3},{end:.3})':\
         alpha='if(lt(t,{fade_in_end:.3}),(t-{start:.3})/0.3,\
         if(gt(t,{fade_out_start:.3}),({end:.3}-t)/0.3,1))'[{output}]",
        text = escape_drawtext(text)
    )
}

fn watermark_filter(
    input: &str,
    logo: &str,
    output: &str,
    target_width: u32,
    watermark: &Watermark,
) -> String {
    let logo_width = (target_width as f32 * 0.12).round() as u32;
    let (x, y) = match watermark.position {
        WatermarkPosition::TopLeft => ("16", "16"),
        WatermarkPosition::TopRight => ("W-w-16", "16"),
        WatermarkPosition::BottomLeft => ("16", "H-h-16"),
        WatermarkPosition::BottomRight => ("W-w-16", "H-h-16"),
    };
    format!(
        "[{logo}]scale={logo_width}:-1,format=rgba,colorchannelmixer=aa={:.3}[logo];\
         [{input}][logo]overlay={x}:{y}[{output}]",
        watermark.opacity.clamp(0.0, 1.0)
    )
}

pub fn escape_drawtext(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace(',', "\\,")
        .replace(':', "\\:")
        .replace('%', "\\%")
        .replace('\'', "\\'")
}

pub async fn render_aspect(job: &AspectRenderJob) -> Result<PathBuf> {
    if job.use_gpu {
        let mut gpu = job.clone();
        gpu.use_gpu = true;
        if execute_ffmpeg(&gpu).await.is_ok() {
            return Ok(job.output_path.clone());
        }
    }

    let mut cpu = job.clone();
    cpu.use_gpu = false;
    execute_ffmpeg(&cpu).await?;
    Ok(job.output_path.clone())
}

async fn execute_ffmpeg(job: &AspectRenderJob) -> Result<()> {
    let args = build_ffmpeg_args(job)?;
    let output = Command::new("ffmpeg")
        .args(&args)
        .output()
        .await
        .context("start ffmpeg")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut lines: Vec<&str> = stderr.lines().rev().take(20).collect();
        lines.reverse();
        return Err(anyhow!(
            "ffmpeg failed with {}: {}",
            output.status,
            lines.join("\n")
        ));
    }
    if !job.output_path.is_file() {
        bail!("ffmpeg succeeded without producing an output file");
    }
    Ok(())
}

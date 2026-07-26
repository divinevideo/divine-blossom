use divine_compiler::{
    domain::{
        Aspect, AudioSettings, Credit, CreditSettings, FitMode, Watermark, WatermarkPosition,
    },
    render::{build_ffmpeg_args, escape_drawtext, AspectRenderJob, ClipInput},
};
use std::{
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn clip(name: &str, fit: FitMode, duration_sec: f64, has_audio: bool) -> ClipInput {
    ClipInput {
        path: PathBuf::from(format!("/tmp/{name}.mp4")),
        coordinate: format!(
            "34236:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:{name}"
        ),
        duration_sec,
        has_audio,
        fit,
        credit: Credit {
            coordinate: name.into(),
            pubkey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            nip05: Some(format!("{name}@divine.video")),
            display_name: Some(name.into()),
        },
    }
}

fn render_job(use_gpu: bool) -> AspectRenderJob {
    AspectRenderJob {
        aspect: Aspect::Portrait,
        clips: vec![
            clip("blur", FitMode::BlurPad, 6.0, true),
            clip("crop", FitMode::CenterCrop, 5.0, false),
        ],
        logo_path: PathBuf::from("/opt/divine/divine-logo.png"),
        output_path: PathBuf::from("/tmp/output.mp4"),
        watermark: Watermark {
            enabled: true,
            position: WatermarkPosition::BottomRight,
            opacity: 0.3,
        },
        credit: CreditSettings::default(),
        audio: AudioSettings::default(),
        use_gpu,
    }
}

#[test]
fn per_clip_fit_and_audio_normalization_are_in_filter_graph() {
    let args = build_ffmpeg_args(&render_job(true)).unwrap();
    let filter = &args[args
        .iter()
        .position(|arg| arg == "-filter_complex")
        .unwrap()
        + 1];

    assert!(filter.contains("boxblur="));
    assert!(filter.contains("crop=1080:1920"));
    assert!(filter.contains("anullsrc=channel_layout=stereo:sample_rate=48000"));
    assert!(filter.contains("fps=30"));
    assert!(filter.contains("loudnorm=I=-14.0"));
}

#[test]
fn gpu_and_cpu_commands_select_expected_h264_encoder() {
    let gpu = build_ffmpeg_args(&render_job(true)).unwrap();
    let cpu = build_ffmpeg_args(&render_job(false)).unwrap();

    assert!(gpu.windows(2).any(|pair| pair == ["-c:v", "h264_nvenc"]));
    assert!(cpu.windows(2).any(|pair| pair == ["-c:v", "libx264"]));
    assert!(gpu
        .windows(2)
        .any(|pair| pair == ["-movflags", "+faststart"]));
}

#[test]
fn credits_escape_ffmpeg_control_characters() {
    assert_eq!(
        escape_drawtext(r"Bob, 100% O'Brien: \wow"),
        r"Bob\, 100\% O\'Brien\: \\wow"
    );
}

#[tokio::test]
#[ignore = "requires system ffmpeg"]
async fn cpu_render_smoke_handles_clips_with_and_without_audio() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("divine-compiler-render-{suffix}"));
    std::fs::create_dir_all(&directory).unwrap();
    let with_audio = directory.join("with-audio.mp4");
    let silent = directory.join("silent.mp4");
    let output = directory.join("output.mp4");

    assert!(Command::new("ffmpeg")
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            "testsrc=size=320x240:rate=30:duration=0.5",
            "-f",
            "lavfi",
            "-i",
            "sine=frequency=440:duration=0.5",
            "-shortest",
            "-pix_fmt",
            "yuv420p",
            with_audio.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("ffmpeg")
        .args([
            "-y",
            "-f",
            "lavfi",
            "-i",
            "color=c=blue:size=320x240:rate=30:duration=0.5",
            "-pix_fmt",
            "yuv420p",
            silent.to_str().unwrap(),
        ])
        .status()
        .unwrap()
        .success());

    let job = AspectRenderJob {
        aspect: Aspect::Square,
        clips: vec![
            ClipInput {
                path: with_audio,
                ..clip("with-audio", FitMode::BlurPad, 0.5, true)
            },
            ClipInput {
                path: silent,
                ..clip("silent", FitMode::Letterbox, 0.5, false)
            },
        ],
        logo_path: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/divine-logo.png"),
        output_path: output.clone(),
        watermark: Watermark::default(),
        credit: CreditSettings {
            duration_ms: 0,
            ..CreditSettings::default()
        },
        audio: AudioSettings::default(),
        use_gpu: false,
    };

    divine_compiler::render::render_aspect(&job).await.unwrap();
    assert!(output.metadata().unwrap().len() > 0);
    std::fs::remove_dir_all(directory).unwrap();
}

use divine_compiler::{
    domain::{
        Aspect, AudioSettings, Credit, CreditSettings, FitMode, Watermark, WatermarkPosition,
    },
    render::{
        build_ffmpeg_args, escape_drawtext, nip05_handle, AspectRenderJob, ClipInput,
        DEFAULT_FONT_PATH,
    },
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
        font_path: PathBuf::from(DEFAULT_FONT_PATH),
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

fn filter_graph(job: &AspectRenderJob) -> String {
    let args = build_ffmpeg_args(job).unwrap();
    args[args.iter().position(|arg| arg == "-filter_complex").unwrap() + 1].clone()
}

#[test]
fn per_clip_fit_and_audio_normalization_are_in_filter_graph() {
    let filter = filter_graph(&render_job(true));

    assert!(filter.contains("boxblur="));
    assert!(filter.contains("crop=1080:1920"));
    // 480x480 sources are upscaled to 1080p, so the visible scale passes must
    // use lanczos rather than FFmpeg's default bicubic.
    assert!(filter.contains("force_original_aspect_ratio=decrease:flags=lanczos"));
    assert!(filter.contains("force_original_aspect_ratio=increase:flags=lanczos"));
    assert!(filter.contains("unsharp="));
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
fn credit_sits_below_the_clip_and_clear_of_the_watermark() {
    let filter = filter_graph(&render_job(false));

    // Anchored to the bottom of the frame, so it lands in the letterbox or
    // blur band instead of across the seam at the bottom of the clip.
    // 1080x1920 portrait: 4% edge margin is 77, the scaled logo needs 66.
    assert!(
        filter.contains("y=h-text_h-77"),
        "unexpected credit placement in {filter}"
    );

    let mut unmarked = render_job(false);
    unmarked.watermark.enabled = false;
    assert!(filter_graph(&unmarked).contains("y=h-text_h-77"));

    // Landscape's 43px edge margin would collide with the taller logo, so the
    // credit is pushed above it.
    let mut landscape = render_job(false);
    landscape.aspect = Aspect::Landscape;
    assert!(filter_graph(&landscape).contains("y=h-text_h-92"));
}

#[test]
fn nip05_renders_as_a_short_social_handle() {
    // Divine issues per-creator subdomains with the NIP-05 root identifier.
    assert_eq!(
        nip05_handle("_@ig-bricknooks.divine.video").as_deref(),
        Some("@ig-bricknooks")
    );
    assert_eq!(
        nip05_handle("alice@divine.video").as_deref(),
        Some("@alice")
    );
    assert_eq!(nip05_handle("bob@example.com").as_deref(), Some("@bob"));
    assert_eq!(nip05_handle("nonsense").as_deref(), None);
    assert_eq!(nip05_handle("@divine.video").as_deref(), None);
    assert_eq!(nip05_handle("_@").as_deref(), None);
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

    for (aspect, dimensions) in [
        (Aspect::Portrait, "1080x1920"),
        (Aspect::Square, "1080x1080"),
        (Aspect::Landscape, "1920x1080"),
    ] {
        let output = directory.join(format!("{aspect:?}.mp4"));
        let job = AspectRenderJob {
            aspect,
            clips: vec![
                ClipInput {
                    path: with_audio.clone(),
                    ..clip("with-audio", FitMode::BlurPad, 0.5, true)
                },
                ClipInput {
                    path: silent.clone(),
                    ..clip("silent", FitMode::Letterbox, 0.5, false)
                },
            ],
            logo_path: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/divine-logo.png"),
            font_path: PathBuf::from(font_path()),
            output_path: output.clone(),
            watermark: Watermark::default(),
            // Credits are burned in with drawtext, which needs an ffmpeg built
            // with libfreetype and a real font file. Exercise it here so a
            // toolchain that cannot render credits fails the smoke test rather
            // than every aspect of every production job.
            credit: CreditSettings::default(),
            audio: AudioSettings::default(),
            use_gpu: false,
        };

        divine_compiler::render::render_aspect(&job).await.unwrap();
        assert!(output.metadata().unwrap().len() > 0);
        let probe = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-select_streams",
                "v:0",
                "-show_entries",
                "stream=width,height",
                "-of",
                "csv=s=x:p=0",
                output.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(probe.status.success());
        assert_eq!(String::from_utf8_lossy(&probe.stdout).trim(), dimensions);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

fn font_path() -> String {
    std::env::var("CREDIT_FONT_PATH").unwrap_or_else(|_| DEFAULT_FONT_PATH.into())
}

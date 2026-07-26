use divine_compiler::domain::{
    Aspect, AspectFailure, ClipOverride, CompileRequest, FitMode, JobResult, JobStatus, NostrEvent,
    Output, RenderRequest, Source, ValidationError,
};

const LIST_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const VIDEO_PUBKEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VIDEO_PUBKEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn coordinate(kind: u32, pubkey: &str, identifier: &str) -> String {
    format!("{kind}:{pubkey}:{identifier}")
}

fn list_event(video_coordinates: &[String]) -> NostrEvent {
    let mut tags = vec![
        vec!["d".into(), "staff-picks".into()],
        vec!["title".into(), "Staff picks".into()],
    ];
    for coordinate in video_coordinates {
        tags.push(vec!["a".into(), coordinate.clone()]);
    }
    NostrEvent {
        id: "2222222222222222222222222222222222222222222222222222222222222222".into(),
        pubkey: LIST_PUBKEY.into(),
        created_at: 1_785_024_000,
        kind: 30_005,
        tags,
        content: String::new(),
        sig: "33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333".into(),
    }
}

fn request(coordinates: &[String]) -> CompileRequest {
    CompileRequest {
        source: Source {
            list_event: list_event(coordinates),
        },
        renders: vec![RenderRequest {
            aspect: Aspect::Portrait,
            default_fit: FitMode::BlurPad,
            clip_overrides: vec![],
        }],
        watermark: Default::default(),
        credit: Default::default(),
        audio: Default::default(),
        max_duration_sec: 600,
    }
}

#[test]
fn list_coordinates_keep_literal_tag_order() {
    let first = coordinate(34_236, VIDEO_PUBKEY_A, "first");
    let second = coordinate(34_235, VIDEO_PUBKEY_B, "second");
    let event = list_event(&[first.clone(), second.clone()]);

    assert_eq!(event.video_coordinates().unwrap(), vec![first, second]);
}

#[test]
fn rejects_unsupported_addressable_kinds() {
    let unsupported = coordinate(30_023, VIDEO_PUBKEY_A, "article");
    let error = request(&[unsupported]).validate().unwrap_err();

    assert_eq!(error, ValidationError::UnsupportedCoordinate);
}

#[test]
fn rejects_duplicate_aspects() {
    let clip = coordinate(34_236, VIDEO_PUBKEY_A, "first");
    let mut request = request(&[clip]);
    request.renders.push(request.renders[0].clone());

    assert_eq!(
        request.validate().unwrap_err(),
        ValidationError::DuplicateAspect
    );
}

#[test]
fn rejects_override_for_clip_outside_signed_list() {
    let listed = coordinate(34_236, VIDEO_PUBKEY_A, "listed");
    let absent = coordinate(34_236, VIDEO_PUBKEY_B, "absent");
    let mut request = request(&[listed]);
    request.renders[0].clip_overrides = vec![ClipOverride {
        coordinate: absent,
        fit: FitMode::CenterCrop,
    }];

    assert_eq!(
        request.validate().unwrap_err(),
        ValidationError::UnknownOverrideCoordinate
    );
}

#[test]
fn unknown_request_fields_are_rejected() {
    let clip = coordinate(34_236, VIDEO_PUBKEY_A, "first");
    let mut json = serde_json::to_value(request(&[clip])).unwrap();
    json.as_object_mut().unwrap().insert(
        "initiated_by".into(),
        serde_json::json!("forged@divine.video"),
    );

    assert!(serde_json::from_value::<CompileRequest>(json).is_err());
}

#[test]
fn one_output_and_one_failure_is_done() {
    let result = JobResult {
        outputs: vec![Output {
            aspect: Aspect::Portrait,
            url: "https://media.divine.video/4444444444444444444444444444444444444444444444444444444444444444".into(),
            sha256: "4444444444444444444444444444444444444444444444444444444444444444".into(),
            size: 12_345,
            dim: "1080x1920".into(),
        }],
        aspect_failures: vec![AspectFailure {
            aspect: Aspect::Square,
            code: "render_failed".into(),
            message: "The square version could not be rendered.".into(),
        }],
        ..Default::default()
    };

    assert_eq!(result.terminal_status(), JobStatus::Done);
}

#[test]
fn no_outputs_is_failed() {
    let result = JobResult {
        aspect_failures: vec![AspectFailure {
            aspect: Aspect::Square,
            code: "render_failed".into(),
            message: "The square version could not be rendered.".into(),
        }],
        ..Default::default()
    };

    assert_eq!(result.terminal_status(), JobStatus::Failed);
}

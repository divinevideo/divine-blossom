// ABOUTME: Strict API and persistence types for compilation jobs
// ABOUTME: Validates signed-list order, render aspects, and per-clip framing

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

const MAX_CLIPS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrEvent {
    pub fn d_tag(&self) -> Option<&str> {
        self.tags
            .iter()
            .find(|tag| tag.first().map(String::as_str) == Some("d"))
            .and_then(|tag| tag.get(1))
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }

    /// Ordered list slots, accepting both the addressable `a` coordinates
    /// written by the compiler editor and the `e` event ids written by the
    /// Divine mobile app.
    ///
    /// A tag that is neither shape is kept as an unsupported slot rather than
    /// failing the request. The editor's `videoReferences()` filters those tags
    /// out, so rejecting the whole list here would let a list open and save in
    /// the UI and then 400 at render time.
    pub fn list_slots(&self) -> Vec<ListSlot> {
        self.tags
            .iter()
            .filter_map(|tag| match (tag.first().map(String::as_str), tag.get(1)) {
                (Some("a"), Some(value)) => Some(match validate_video_coordinate(value) {
                    Ok(()) => ListSlot::Video(VideoReference::Coordinate(value.clone())),
                    Err(reason) => ListSlot::Unsupported {
                        value: value.clone(),
                        reason,
                    },
                }),
                (Some("e"), Some(value)) => Some(if is_hex_64(value) {
                    ListSlot::Video(VideoReference::Event(value.clone()))
                } else {
                    ListSlot::Unsupported {
                        value: value.clone(),
                        reason: "invalid-event-reference",
                    }
                }),
                _ => None,
            })
            .collect()
    }

    /// The renderable references only, in signed list order.
    pub fn video_references(&self) -> Vec<VideoReference> {
        self.list_slots()
            .into_iter()
            .filter_map(|slot| match slot {
                ListSlot::Video(reference) => Some(reference),
                ListSlot::Unsupported { .. } => None,
            })
            .collect()
    }
}

/// One ordered position in a signed list. Unsupported positions keep their
/// place so a dropped clip can be reported against the index the editor shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListSlot {
    Video(VideoReference),
    Unsupported {
        value: String,
        reason: &'static str,
    },
}

impl ListSlot {
    /// The tag value exactly as it appears in the signed list.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Video(reference) => reference.as_str(),
            Self::Unsupported { value, .. } => value,
        }
    }
}

/// A single ordered clip slot in a signed list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VideoReference {
    /// `a` tag holding a `34235:`/`34236:` addressable coordinate.
    Coordinate(String),
    /// `e` tag holding a video event id.
    Event(String),
}

impl VideoReference {
    /// The tag value exactly as it appears in the signed list.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Coordinate(value) | Self::Event(value) => value,
        }
    }
}

fn validate_video_coordinate(coordinate: &str) -> Result<(), &'static str> {
    let mut parts = coordinate.splitn(3, ':');
    let kind = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or("unsupported-coordinate")?;
    let pubkey = parts.next().ok_or("unsupported-coordinate")?;
    let identifier = parts.next().ok_or("unsupported-coordinate")?;

    if !matches!(kind, 34_235 | 34_236) || !is_hex_64(pubkey) || identifier.is_empty() {
        return Err("unsupported-coordinate");
    }

    Ok(())
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CompileRequest {
    pub source: Source,
    pub renders: Vec<RenderRequest>,
    #[serde(default)]
    pub watermark: Watermark,
    #[serde(default)]
    pub credit: CreditSettings,
    #[serde(default)]
    pub audio: AudioSettings,
    #[serde(default = "default_max_duration_sec")]
    pub max_duration_sec: u32,
}

impl CompileRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.source.list_event.kind != 30_005 {
            return Err(ValidationError::InvalidListKind);
        }
        if self.source.list_event.d_tag().is_none() {
            return Err(ValidationError::MissingDTag);
        }

        let references = self.source.list_event.video_references();
        if references.len() > MAX_CLIPS {
            return Err(ValidationError::TooManyClips);
        }
        if self.renders.is_empty() {
            return Err(ValidationError::EmptyRenders);
        }

        let coordinate_set: HashSet<&str> =
            references.iter().map(VideoReference::as_str).collect();
        let mut aspects = HashSet::new();
        for render in &self.renders {
            if !aspects.insert(render.aspect) {
                return Err(ValidationError::DuplicateAspect);
            }

            let mut overrides = HashSet::new();
            for clip_override in &render.clip_overrides {
                if !coordinate_set.contains(clip_override.coordinate.as_str()) {
                    return Err(ValidationError::UnknownOverrideCoordinate);
                }
                if !overrides.insert(clip_override.coordinate.as_str()) {
                    return Err(ValidationError::DuplicateOverrideCoordinate);
                }
            }
        }

        Ok(())
    }
}

fn default_max_duration_sec() -> u32 {
    600
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub list_event: NostrEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RenderRequest {
    pub aspect: Aspect,
    pub default_fit: FitMode,
    #[serde(default)]
    pub clip_overrides: Vec<ClipOverride>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClipOverride {
    pub coordinate: String,
    pub fit: FitMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Aspect {
    #[serde(rename = "9:16")]
    Portrait,
    #[serde(rename = "1:1")]
    Square,
    #[serde(rename = "16:9")]
    Landscape,
}

impl Aspect {
    pub fn dimensions(self) -> (u32, u32) {
        match self {
            Self::Portrait => (1080, 1920),
            Self::Square => (1080, 1080),
            Self::Landscape => (1920, 1080),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FitMode {
    BlurPad,
    CenterCrop,
    Letterbox,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    pub enabled: bool,
    pub position: WatermarkPosition,
    pub opacity: f32,
}

impl Default for Watermark {
    fn default() -> Self {
        Self {
            enabled: true,
            position: WatermarkPosition::BottomRight,
            opacity: 0.3,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WatermarkPosition {
    TopLeft,
    TopRight,
    BottomLeft,
    BottomRight,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreditSettings {
    pub duration_ms: u32,
    pub show_display_name: bool,
    pub show_nip05: bool,
}

impl Default for CreditSettings {
    fn default() -> Self {
        Self {
            duration_ms: 2500,
            show_display_name: true,
            show_nip05: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AudioSettings {
    pub target_lufs: f32,
}

impl Default for AudioSettings {
    fn default() -> Self {
        Self { target_lufs: -14.0 }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Job {
    pub id: String,
    pub status: JobStatus,
    pub progress: f32,
    pub request: CompileRequest,
    pub signer_pubkey: String,
    pub initiated_by: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// When the running worker's claim expires. A job whose lease has passed is
    /// reclaimable, so a crashed or replaced instance cannot strand it in
    /// `running` forever.
    #[serde(default)]
    pub lease_expires_at: Option<u64>,
    #[serde(default)]
    pub result: Option<JobResult>,
    #[serde(default)]
    pub error: Option<JobError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct JobResult {
    #[serde(default)]
    pub outputs: Vec<Output>,
    #[serde(default)]
    pub aspect_failures: Vec<AspectFailure>,
    #[serde(default)]
    pub duration_sec: f64,
    #[serde(default)]
    pub clips_used: usize,
    #[serde(default)]
    pub clips_dropped: Vec<ClipDrop>,
    #[serde(default)]
    pub credits: Vec<Credit>,
}

impl JobResult {
    pub fn terminal_status(&self) -> JobStatus {
        if self.outputs.is_empty() {
            JobStatus::Failed
        } else {
            JobStatus::Done
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Output {
    pub aspect: Aspect,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub dim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AspectFailure {
    pub aspect: Aspect,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClipDrop {
    pub source_index: usize,
    pub coordinate: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credit {
    pub coordinate: String,
    pub pubkey: String,
    pub nip05: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("list event must be kind 30005")]
    InvalidListKind,
    #[error("list event must contain a non-empty d tag")]
    MissingDTag,
    #[error("list contains more than 500 video coordinates")]
    TooManyClips,
    #[error("at least one render aspect is required")]
    EmptyRenders,
    #[error("render aspects must be unique")]
    DuplicateAspect,
    #[error("clip override coordinate is absent from the signed list")]
    UnknownOverrideCoordinate,
    #[error("clip override coordinate is duplicated for an aspect")]
    DuplicateOverrideCoordinate,
}

// ABOUTME: Video thumbnail extraction using ffmpeg CLI
// ABOUTME: Extracts a single frame from video at 1 second mark (or 0s for short videos)

use anyhow::{anyhow, Result};
use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;

pub struct ThumbnailResult {
    pub data: Vec<u8>,
    pub content_type: String,
}

/// Extract thumbnail from video bytes using ffmpeg
/// Returns JPEG image data on success
pub fn extract_thumbnail(video_data: &[u8]) -> Result<ThumbnailResult> {
    // Skip extraction for very large videos (>100MB) to avoid slowdowns
    if video_data.len() > 100 * 1024 * 1024 {
        return Err(anyhow!("Video too large for sync thumbnail extraction"));
    }

    // Write video to temp file
    let mut video_file = NamedTempFile::new()?;
    video_file.write_all(video_data)?;
    video_file.flush()?;

    // Create temp file for thumbnail output (with .jpg extension for ffmpeg)
    let thumb_file = NamedTempFile::with_suffix(".jpg")?;
    let thumb_path = thumb_file.path().to_str()
        .ok_or_else(|| anyhow!("Invalid temp file path"))?;
    let video_path = video_file.path().to_str()
        .ok_or_else(|| anyhow!("Invalid temp file path"))?;

    // Try extraction at 1 second mark first (good for most videos)
    let result = Command::new("ffmpeg")
        .args([
            "-y",                    // Overwrite output
            "-ss", "1",              // Seek to 1 second
            "-i", video_path,        // Input file
            "-vframes", "1",         // Extract 1 frame
            "-vf", "scale=640:360:force_original_aspect_ratio=decrease",  // Scale to max 640x360
            "-q:v", "2",             // High quality JPEG
            "-f", "image2",          // Force image2 format
            thumb_path,              // Output file
        ])
        .output()?;

    // Check if thumbnail was created (file has content)
    let data = std::fs::read(thumb_path).unwrap_or_default();

    // If first attempt failed or produced empty file, try at 0 seconds
    // This handles very short videos
    if data.is_empty() || !result.status.success() {
        let retry_result = Command::new("ffmpeg")
            .args([
                "-y",
                "-ss", "0",
                "-i", video_path,
                "-vframes", "1",
                "-vf", "scale=640:360:force_original_aspect_ratio=decrease",
                "-q:v", "2",
                "-f", "image2",
                thumb_path,
            ])
            .output()?;

        if !retry_result.status.success() {
            let stderr = String::from_utf8_lossy(&retry_result.stderr);
            return Err(anyhow!("ffmpeg failed: {}", stderr));
        }
    }

    // Read the final thumbnail
    let data = std::fs::read(thumb_path)?;
    if data.is_empty() {
        return Err(anyhow!("Empty thumbnail generated"));
    }

    Ok(ThumbnailResult {
        data,
        content_type: "image/jpeg".into(),
    })
}

/// Check if a content type is a video type that can have thumbnails extracted
pub fn is_video_type(content_type: &str) -> bool {
    matches!(
        content_type,
        "video/mp4"
            | "video/webm"
            | "video/quicktime"
            | "video/x-msvideo"
            | "video/x-matroska"
            | "video/ogg"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_video_type() {
        assert!(is_video_type("video/mp4"));
        assert!(is_video_type("video/webm"));
        assert!(is_video_type("video/quicktime"));
        assert!(!is_video_type("image/png"));
        assert!(!is_video_type("application/json"));
        assert!(!is_video_type("audio/mp3"));
    }
}

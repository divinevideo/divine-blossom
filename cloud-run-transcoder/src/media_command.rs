// ABOUTME: Bounded child-process execution for transcription media tools.
// ABOUTME: Cancelling an operation must not leave media decoders running.

use anyhow::{Context, Result};
use std::{process::Output, time::Duration};
use tokio::process::Command;

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
pub const AUDIO_TIMEOUT: Duration = Duration::from_secs(120);

/// The deadline bounds wall time, not media duration. Kill-on-drop also covers
/// caller cancellation; a timeout alone would leave the decoder running.
pub async fn output(command: &mut Command, limit: Duration) -> Result<Output> {
    tokio::time::timeout(limit, command.kill_on_drop(true).output())
        .await
        .context("Media command deadline exceeded")?
        .context("Media command failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hung_media_command_returns_before_request_deadline() {
        let mut command = Command::new("sleep");
        command.arg("2");
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            output(&mut command, Duration::from_millis(30)),
        )
        .await
        .expect("media command must enforce its own deadline");
        assert!(result.unwrap_err().to_string().contains("deadline"));
    }
    #[tokio::test]
    async fn successful_command_preserves_stdout_and_exit_status() {
        let result = output(
            Command::new("sh").args(["-c", "printf audio; exit 7"]),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(result.stdout, b"audio");
        assert_eq!(result.status.code(), Some(7));
    }

    #[tokio::test]
    async fn cancellation_kills_the_media_child() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let child_pid_file = pid_file.clone();
        let task = tokio::spawn(async move {
            output(
                Command::new("sh")
                    .arg("-c")
                    .arg("echo $$ > \"$1\"; exec sleep 10")
                    .arg("test-child")
                    .arg(child_pid_file),
                Duration::from_secs(20),
            )
            .await
        });
        let pid = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok(raw) = tokio::fs::read_to_string(&pid_file).await {
                    if let Ok(pid) = raw.trim().parse::<u32>() {
                        break pid;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("synthetic child must start");
        task.abort();
        let _ = task.await;
        let stopped = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let alive = Command::new("kill")
                    .args(["-0", &pid.to_string()])
                    .output()
                    .await
                    .unwrap()
                    .status
                    .success();
                if !alive {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        if stopped.is_err() {
            let _ = Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .output()
                .await;
        }
        assert!(
            stopped.is_ok(),
            "cancelled request left the media child running"
        );
    }
}

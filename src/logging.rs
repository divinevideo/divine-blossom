// ABOUTME: Persistent structured logging via Fastly log endpoints
// ABOUTME: Falls back to stderr when endpoint unavailable (local dev)

use fastly::log::Endpoint;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write;
use std::sync::OnceLock;

const ENDPOINT_NAME: &str = "app_logs";

static LOGGER: FastlyLogger = FastlyLogger;

/// Whether the logging endpoint is available (set once at init).
static ENDPOINT_AVAILABLE: OnceLock<bool> = OnceLock::new();

struct FastlyLogger;

impl Log for FastlyLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= LevelFilter::Info
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let msg = format!("{}", record.args());
        if *ENDPOINT_AVAILABLE.get().unwrap_or(&false) {
            if let Ok(mut ep) = Endpoint::try_from_name(ENDPOINT_NAME) {
                let _ = writeln!(ep, "{}", msg);
            }
        }
        // Always also write to stderr for real-time log-tail
        eprintln!("{}", msg);
    }

    fn flush(&self) {}
}

/// Initialize the logger. Call once at the start of main().
/// Probes the endpoint; if unavailable, logs only go to stderr.
pub fn init() {
    let available = Endpoint::try_from_name(ENDPOINT_NAME).is_ok();
    let _ = ENDPOINT_AVAILABLE.set(available);
    let _ = log::set_logger(&LOGGER);
    log::set_max_level(LevelFilter::Info);
}

/// Build a structured JSON log line for a completed request.
pub fn log_request(
    method: &str,
    path: &str,
    status: u16,
    duration_ms: u128,
    error: Option<&str>,
) {
    let mut line = format!(
        r#"{{"method":"{}","path":"{}","status":{},"duration_ms":{}"#,
        method,
        path.replace('"', ""),
        status,
        duration_ms,
    );
    if let Some(err) = error {
        line.push_str(&format!(r#","error":"{}""#, err.replace('"', r#"\""#)));
    }
    line.push('}');
    log::info!("{}", line);
}

/// Log a structured application event (non-request).
pub fn log_event(level: Level, tag: &str, message: &str) {
    let line = format!(
        r#"{{"tag":"{}","message":"{}"}}"#,
        tag,
        message.replace('"', r#"\""#),
    );
    match level {
        Level::Error => log::error!("{}", line),
        Level::Warn => log::warn!("{}", line),
        _ => log::info!("{}", line),
    }
}

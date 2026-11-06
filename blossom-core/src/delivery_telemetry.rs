//! Privacy-bounded Compute delivery telemetry wire contract.
use serde::Serialize;
use std::fmt::Write;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    B2,
    Gcs,
    None,
    #[default]
    Unknown,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cache {
    Hit,
    Miss,
    Bypass,
    #[default]
    Unknown,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    None,
    MissingReadiness,
    MissingVersion,
    Unavailable,
    Copying,
    Oversized,
    #[default]
    Unknown,
}

/// Actual request execution only; never populate from cached fill provenance.
#[derive(Clone, Copy, Debug, Default)]
pub struct DeliveryObservation {
    pub provider: Provider,
    pub storage_cache: Cache,
    pub fallback: Fallback,
    pub origin_attempted: Option<bool>,
}

pub fn is_uuid_v4(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            14 => b == b'4',
            19 => matches!(b, b'8' | b'9' | b'a' | b'b'),
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
}

pub fn eligible(
    flag: Option<&str>,
    direct_configured_host: bool,
    method: &str,
    load_id: Option<&str>,
) -> bool {
    flag == Some("true")
        && direct_configured_host
        && matches!(method, "GET" | "HEAD")
        && load_id.is_some_and(is_uuid_v4)
}

/// The adapter supplies fresh OS randomness; timestamps/caller IDs are not entropy.
pub fn uuid_v4(mut random: [u8; 16]) -> String {
    random[6] = (random[6] & 0x0f) | 0x40;
    random[8] = (random[8] & 0x3f) | 0x80;
    let mut hex = String::with_capacity(32);
    for byte in random {
        let _ = write!(hex, "{byte:02x}");
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[derive(Serialize)]
pub struct DeliveryEvent<'a> {
    schema: &'static str,
    event_id: &'a str,
    load_id: &'a str,
    request_id: &'a str,
    occurred_at_ms: u64,
    cohort: &'static str,
    stage: &'static str,
    method: &'a str,
    status: u16,
    range_request: bool,
    provider: Provider,
    storage_cache: Cache,
    outer_cache: Cache,
    fallback: Fallback,
    origin_attempted: Option<bool>,
    header_ready_ms: Option<u32>,
    transfer_ms: Option<u32>,
    bytes_sent: Option<u64>,
}

/// Only callers gated to the direct canary may construct this headers marker.
/// There is no send-complete observation here, including HEAD and 416 responses.
#[allow(clippy::too_many_arguments)]
pub fn compute_headers<'a>(
    event_id: &'a str,
    load_id: &'a str,
    request_id: &'a str,
    occurred_at_ms: u64,
    method: &'a str,
    status: u16,
    range_request: bool,
    elapsed_ms: u128,
    observation: DeliveryObservation,
) -> Option<DeliveryEvent<'a>> {
    if !is_uuid_v4(event_id)
        || !is_uuid_v4(load_id)
        || request_id.is_empty()
        || request_id.len() > 64
        || !request_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
        || !matches!(method, "GET" | "HEAD")
        || !(100..=599).contains(&status)
    {
        return None;
    }
    Some(DeliveryEvent {
        schema: "divine.media.delivery.v1",
        event_id,
        load_id,
        request_id,
        occurred_at_ms,
        cohort: "b2_canary",
        stage: "compute_headers",
        method,
        status,
        range_request,
        provider: observation.provider,
        storage_cache: observation.storage_cache,
        outer_cache: Cache::Bypass,
        fallback: observation.fallback,
        origin_attempted: observation.origin_attempted,
        header_ready_ms: (elapsed_ms <= 600000).then_some(elapsed_ms as u32),
        transfer_ms: None,
        bytes_sent: None,
    })
}

/// Guest logging outcomes do not acknowledge topic publication or storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryLogOutcome {
    HostAccepted,
    EndpointUnavailable,
    WriteFailed,
}
impl DeliveryLogOutcome {
    pub fn diagnostic(self) -> &'static str {
        match self {
            Self::HostAccepted => "playback_delivery_log outcome=host_accepted count=1",
            Self::EndpointUnavailable => {
                "playback_delivery_log outcome=endpoint_unavailable count=1"
            }
            Self::WriteFailed => "playback_delivery_log outcome=write_failed count=1",
        }
    }
}

/// Emit one raw JSON record in exactly one host write, without a newline.
/// Fastly treats each Write call as a separate record; retrying a short-write
/// suffix would create another malformed record. Report it as failure instead.
/// The platform may accept writes without publishing them; no durable ack exists.
pub fn write_delivery_log<W: std::io::Write>(
    endpoint: Option<W>,
    line: &str,
) -> DeliveryLogOutcome {
    let Some(mut endpoint) = endpoint else {
        return DeliveryLogOutcome::EndpointUnavailable;
    };
    match endpoint.write(line.as_bytes()) {
        Ok(written) if written == line.len() => DeliveryLogOutcome::HostAccepted,
        _ => DeliveryLogOutcome::WriteFailed,
    }
}

//! Request-boundary adapter: no correlation or observation lives in a cache object.
use blossom_core::delivery_telemetry::{self, Cache, DeliveryObservation, Fallback, Provider};
use fastly::{Request, Response};
use std::cell::RefCell;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const REQUEST_HEADER: &str = "X-Playback-Request-Id";
const LOAD_HEADER: &str = "X-Playback-Load-Id";
const LOG_ENDPOINT_NAME: &str = "cdn-view-logs";
thread_local! { static OBSERVATION: RefCell<Option<DeliveryObservation>> = const { RefCell::new(None) }; }

pub(crate) struct RequestContext {
    load_id: String,
    event_id: String,
    request_id: String,
    method: String,
    range_request: bool,
}
impl RequestContext {
    pub(crate) fn start(req: &Request) -> Option<Self> {
        OBSERVATION.with(|state| *state.borrow_mut() = None);
        let flag = crate::storage::get_config("b2_playback_telemetry_enabled").ok();
        let load_id = req.get_header_str(LOAD_HEADER);
        if !delivery_telemetry::eligible(
            flag.as_deref(),
            crate::canary::route(req) == blossom_core::canary::CanaryRoute::Canary,
            req.get_method_str(),
            load_id,
        ) {
            return None;
        }
        let mut random = [0; 32];
        // A missing random source disables this record; clocks are never an ID fallback.
        getrandom::getrandom(&mut random).ok()?;
        let context = Self {
            load_id: load_id?.to_owned(),
            event_id: delivery_telemetry::uuid_v4(random[..16].try_into().ok()?),
            request_id: delivery_telemetry::uuid_v4(random[16..].try_into().ok()?),
            method: req.get_method_str().to_owned(),
            range_request: req.contains_header("Range"),
        };
        OBSERVATION.with(|state| {
            *state.borrow_mut() = Some(DeliveryObservation {
                origin_attempted: Some(false),
                ..DeliveryObservation::default()
            })
        });
        Some(context)
    }
    pub(crate) fn finish(self, response: &mut Response, elapsed: Duration) -> Option<String> {
        let observation = OBSERVATION
            .with(|state| state.borrow_mut().take())
            .unwrap_or_default();
        let occurred_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis()
            .try_into()
            .ok()?;
        let event = delivery_telemetry::compute_headers(
            &self.event_id,
            &self.load_id,
            &self.request_id,
            occurred_at_ms,
            &self.method,
            response.get_status().as_u16(),
            self.range_request,
            elapsed.as_millis(),
            observation,
        )?;
        let line = serde_json::to_string(&event).ok()?;
        // This runs after every cache/policy handler has returned. Never put this in origin/cache headers.
        response.set_header(REQUEST_HEADER, &self.request_id);
        let outcome = delivery_telemetry::write_delivery_log(
            fastly::log::Endpoint::try_from_name(LOG_ENDPOINT_NAME).ok(),
            &line,
        );
        // Fixed aggregate labels only. Host acceptance is not Pub/Sub/storage acknowledgement.
        eprintln!("{}", outcome.diagnostic());
        Some(line)
    }
}
pub(crate) fn observe(provider: Provider, storage_cache: Cache) {
    OBSERVATION.with(|state| {
        if let Some(observation) = state.borrow_mut().as_mut() {
            observation.provider = provider;
            observation.storage_cache = storage_cache;
        }
    });
}
/// Record an actual media-send boundary; auth/policy I/O never calls this.
pub(crate) fn media_origin_attempt(provider: Provider) {
    OBSERVATION.with(|state| {
        if let Some(observation) = state.borrow_mut().as_mut() {
            observation.provider = provider;
            observation.storage_cache = Cache::Bypass;
            observation.origin_attempted = Some(true);
        }
    });
}

/// The final selected cache path may replace provider, but cannot erase an
/// earlier failed media attempt before fallback reaches a cache hit.
pub(crate) fn storage_cache(cache: Cache) {
    OBSERVATION.with(|state| {
        if let Some(observation) = state.borrow_mut().as_mut() {
            observation.storage_cache = cache;
            if cache == Cache::Hit {
                observation.provider = Provider::None;
            }
        }
    });
}

pub(crate) fn fallback(fallback: Fallback) {
    OBSERVATION.with(|state| {
        if let Some(observation) = state.borrow_mut().as_mut() {
            observation.fallback = fallback;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    const LOAD: &str = "12345678-1234-4234-9234-123456789abc";
    #[test]
    #[ignore = "requires explicit telemetry canary configuration; run-playback-telemetry-tests.py"]
    fn boundary_emits_failures_and_fresh_ids_without_mutating_body_or_cache_policy() {
        let mut seen = std::collections::HashSet::new();
        for method in ["GET", "HEAD"] {
            for status in [200, 206, 304, 400, 404, 416, 500, 503] {
                let mut req = Request::new(method, "https://media-b2.divine.video/synthetic");
                req.set_header(LOAD_HEADER, LOAD);
                req.set_header("X-Request-Id", "reused-caller-retry");
                req.set_header(REQUEST_HEADER, "spoofed");
                req.set_header("Range", "bytes=0-0");
                req.set_header("Authorization", "Bearer private-synthetic");
                let context = RequestContext::start(&req).expect("eligible");
                media_origin_attempt(Provider::Gcs);
                fallback(Fallback::MissingReadiness);
                let mut response = Response::from_status(status).with_body("body");
                response.set_header("Cache-Control", "private, no-store");
                response.set_header("Surrogate-Control", "no-store");
                response.set_header("Content-Length", "1048576");
                let line = context
                    .finish(&mut response, Duration::from_millis(9))
                    .unwrap();
                let value: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(value["status"], status);
                assert_eq!(value["method"], method);
                assert_eq!(value["provider"], "gcs");
                assert_eq!(value["origin_attempted"], true);
                assert_eq!(value["storage_cache"], "bypass");
                assert_eq!(value["fallback"], "missing_readiness");
                assert_eq!(value["transfer_ms"], serde_json::Value::Null);
                assert_eq!(value["bytes_sent"], serde_json::Value::Null);
                assert_eq!(value["load_id"], LOAD);
                let request = value["request_id"].as_str().unwrap();
                assert!(delivery_telemetry::is_uuid_v4(request));
                assert_eq!(response.get_header_str(REQUEST_HEADER), Some(request));
                assert!(seen.insert(request.to_owned()));
                assert!(seen.insert(value["event_id"].as_str().unwrap().to_owned()));
                assert!(!line.contains("synthetic"));
                assert!(!line.contains("reused-caller"));
                assert_eq!(
                    response.get_header_str("Cache-Control"),
                    Some("private, no-store")
                );
                assert_eq!(
                    response.get_header_str("Surrogate-Control"),
                    Some("no-store")
                );
                assert_eq!(response.take_body().into_string(), "body");
            }
        }
    }
    #[test]
    #[ignore = "requires synthetic origin fixtures; run-playback-origin-telemetry-tests.py"]
    fn canary_execution_observation_contract() {
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let method = config.get("test_method").unwrap_or_else(|| "GET".into());
        let mut request = Request::new(
            method,
            format!("https://media-b2.divine.video/{}", "a".repeat(64)),
        );
        request.set_header(LOAD_HEADER, LOAD);
        if let Some(range) = config.get("test_range") {
            request.set_header("Range", range);
        }
        let context = RequestContext::start(&request).unwrap();
        let mut response =
            crate::handle_request(request).unwrap_or_else(|error| crate::error_response(&error));
        let line = context.finish(&mut response, Duration::ZERO).unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        for (field, setting) in [
            ("provider", "test_telemetry_provider"),
            ("storage_cache", "test_telemetry_storage_cache"),
            ("fallback", "test_telemetry_fallback"),
        ] {
            assert_eq!(
                value[field].as_str(),
                config.get(setting).as_deref(),
                "{field}"
            );
        }
        assert_eq!(
            value["status"].as_u64(),
            Some(config.get("test_expected_status").unwrap().parse().unwrap())
        );
        assert!(value["transfer_ms"].is_null());
        assert!(value["bytes_sent"].is_null());
        assert_eq!(
            value["origin_attempted"].as_bool(),
            Some(config.get("test_telemetry_provider").as_deref() != Some("none"))
        );
    }
    #[test]
    #[ignore = "requires synthetic Core Cache/origin fixtures; run-playback-cache-telemetry-tests.py"]
    fn cache_delivery_observation_contract() {
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let scenario = config.get("test_cache_observation_scenario").unwrap();
        let hash = config.get("test_hash").unwrap();
        let body = config.get("test_body").unwrap();
        let read = |method: &str, load: &str| {
            crate::playback_cache::begin_request();
            let mut request = Request::new(method, format!("https://media-b2.divine.video/{hash}"));
            request.set_header(LOAD_HEADER, load);
            request.set_header(REQUEST_HEADER, "replayed-caller-id");
            request.set_header("X-Request-Id", "reused-retry-id");
            let context = RequestContext::start(&request).unwrap();
            let mut response = crate::handle_request(request)
                .unwrap_or_else(|error| crate::error_response(&error));
            let line = context.finish(&mut response, Duration::ZERO).unwrap();
            let event: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(event["load_id"], load);
            assert_eq!(
                response.get_header_str(REQUEST_HEADER),
                event["request_id"].as_str()
            );
            assert_eq!(
                response.get_header_str("Cache-Control"),
                Some("private, no-store")
            );
            assert_eq!(
                response.get_header_str("Surrogate-Control"),
                Some("no-store")
            );
            assert_eq!(event["transfer_ms"], serde_json::Value::Null);
            assert_eq!(event["bytes_sent"], serde_json::Value::Null);
            assert!(delivery_telemetry::is_uuid_v4(
                event["event_id"].as_str().unwrap()
            ));
            assert!(delivery_telemetry::is_uuid_v4(
                event["request_id"].as_str().unwrap()
            ));
            assert_eq!(
                response.take_body().into_string(),
                if method == "HEAD" { "" } else { body.as_str() }
            );
            event
        };
        let seed = if matches!(
            scenario.as_str(),
            "warm_hit" | "fallback_hit" | "failed_b2_fallback_hit"
        ) {
            let seed = read("GET", LOAD);
            if scenario == "failed_b2_fallback_hit" {
                // Warm the GCS path with missing readiness, then make B2 eligible
                // for the next request. Both KV and origins are local fixtures.
                crate::metadata::open_store()
                    .unwrap()
                    .insert(
                        &format!("b2-ready:{hash}"),
                        config.get("test_readiness").unwrap(),
                    )
                    .unwrap();
            }
            Some(seed)
        } else {
            None
        };
        let method = if scenario == "bypass" { "HEAD" } else { "GET" };
        let event = read(method, "44444444-4444-4444-8444-444444444444");
        for (field, setting) in [
            ("provider", "test_telemetry_provider"),
            ("storage_cache", "test_telemetry_storage_cache"),
            ("fallback", "test_telemetry_fallback"),
        ] {
            assert_eq!(
                event[field].as_str(),
                config.get(setting).as_deref(),
                "{scenario} {field}"
            );
        }
        assert_eq!(
            event["origin_attempted"].as_bool(),
            Some(config.get("test_origin_attempted").as_deref() == Some("true")),
            "{scenario} origin_attempted"
        );
        if let Some(seed) = seed {
            assert_ne!(event["event_id"], seed["event_id"]);
            assert_ne!(event["request_id"], seed["request_id"]);
        }
    }
    #[test]
    #[ignore = "requires explicit telemetry canary configuration; run-playback-telemetry-tests.py"]
    fn boundary_gates_and_resets_each_request() {
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let enabled = config.get("test_telemetry_enabled").as_deref() == Some("true");
        let mut req = Request::get("https://media-b2.divine.video/synthetic");
        req.set_header(LOAD_HEADER, LOAD);
        let context = RequestContext::start(&req);
        assert_eq!(context.is_some(), enabled);
        if let Some(context) = context {
            let mut response = Response::from_status(404);
            let line = context.finish(&mut response, Duration::ZERO).unwrap();
            let value: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(value["provider"], "unknown");
            assert_eq!(value["storage_cache"], "unknown");
            assert_eq!(value["origin_attempted"], false);
        }
        for url in [
            "https://media.divine.video/synthetic",
            "https://media-b2.divine.video:8443/synthetic",
        ] {
            let mut wrong = Request::get(url);
            wrong.set_header(LOAD_HEADER, LOAD);
            assert!(RequestContext::start(&wrong).is_none());
        }
        req.set_header(LOAD_HEADER, "private-not-a-uuid");
        assert!(RequestContext::start(&req).is_none());
    }
}

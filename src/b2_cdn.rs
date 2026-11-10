//! Configured outer-CDN delivery boundary; direct canary policy remains separate.
use blossom_core::b2_cdn::{self, Config, Route};
use fastly::{Request, Response};

pub(crate) fn route(req: &Request) -> Route {
    let authority = req.get_url().host_str().unwrap_or("");
    b2_cdn::route_with_configuration(
        authority,
        req.get_header_str("Host").unwrap_or(authority),
        req.get_header_str("X-Original-Host"),
        || configured_route(req),
    )
}

fn configured_route(req: &Request) -> Route {
    let enabled = crate::storage::get_config("b2_cdn_enabled").ok();
    let host = crate::storage::get_config("b2_cdn_host").ok();
    let origin_host = crate::storage::get_config("b2_cdn_origin_host").ok();
    let authority = req.get_url().host_str().unwrap_or("");
    let route = Config {
        enabled: enabled.as_deref(),
        host: host.as_deref(),
        origin_host: origin_host.as_deref(),
    }
    .route(
        authority,
        req.get_header_str("Host").unwrap_or(authority),
        req.get_header_str("X-Original-Host"),
    );
    if route != Route::Delivery {
        return route;
    }
    let purge_hosts = crate::storage::get_config("b2_cdn_purge_hosts").ok();
    let purge_configured = b2_cdn::purge_hosts(purge_hosts.as_deref(), host.as_deref()).is_some();
    let purge_credential = fastly::secret_store::SecretStore::open("blossom_secrets")
        .ok()
        .and_then(|store| store.get("fastly_api_token"))
        .is_some_and(|secret| !secret.plaintext().is_empty());
    if req.get_url().port().is_some() || !purge_configured || !purge_credential {
        Route::Denied
    } else {
        route
    }
}
fn original(req: &Request) -> Option<String> {
    b2_cdn::original(
        req.get_method_str(),
        req.get_path(),
        req.contains_header("Authorization"),
        req.contains_header("Cookie"),
    )
}
pub(crate) fn handle(req: Request) -> crate::error::Result<Response> {
    original(&req).ok_or_else(|| crate::error::BlossomError::NotFound("Not found".into()))?;
    crate::canary::handle_cdn(req)
}

/// Retained before dispatch; applied only after all routing and final policy
/// guards have returned. Warm outer hits use purge-based policy semantics.
pub(crate) struct FinalPolicy {
    route: Route,
    hash: Option<String>,
    head: bool,
}
impl FinalPolicy {
    pub(crate) fn for_request(req: &Request) -> Self {
        Self {
            route: route(req),
            hash: original(req),
            head: req.get_method_str() == "HEAD",
        }
    }
    pub(crate) fn apply(self, response: &mut Response) {
        let prepared_tag = response
            .get_header_str(crate::canary::VERIFIED_SEGMENT_HEADER)
            .map(str::to_owned);
        response.remove_header(crate::canary::VERIFIED_SEGMENT_HEADER);
        if self.route == Route::Unrelated {
            return;
        }
        response.remove_header("X-Divine-B2-CDN-Admission");
        crate::canary::no_store(response);
        if self.route == Route::Delivery {
            if let Some(hash) = self.hash {
                let ordinary = b2_cdn::admit(
                    response.get_status().as_u16(),
                    response.get_header_str("X-Divine-Source"),
                    response.contains_header("Content-Range"),
                ) && response.get_header_str("X-Sha256") == Some(hash.as_str())
                    && b2_cdn::outer_cacheable_length(response.get_header_str("Content-Length"))
                    && response.get_header_str("Content-Length")
                        == response.get_header_str("X-Content-Length")
                    && !response.contains_header("Set-Cookie");
                let size = response
                    .get_header_str("X-Content-Length")
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse::<u64>().ok());
                let segmented = prepared_tag.as_deref().is_some_and(|tag| {
                    let strong = tag
                        .strip_prefix("\"b2-")
                        .and_then(|v| v.strip_suffix('"'))
                        .is_some_and(|v| {
                            v.len() == 64
                                && v.bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        });
                    strong && response.get_header_str("ETag") == Some(tag)
                }) && response.get_header_str("X-Divine-Source") == Some("b2")
                    && response.get_header_str("X-Sha256") == Some(hash.as_str())
                    && !response.contains_header("Set-Cookie")
                    && response.get_header_all("Content-Length").count() == 1
                    && response.get_header_all("Content-Range").count() <= 1
                    && !response.contains_header("Transfer-Encoding")
                    && matches!(
                        response.get_header_str("Content-Encoding"),
                        None | Some("identity")
                    )
                    && size.is_some_and(|size| {
                        size > 0
                            && blossom_core::canary::origin_size_matches(
                                response.get_status().as_u16(),
                                response.get_header_str("Content-Length"),
                                response.get_header_str("Content-Range"),
                                size,
                            )
                    });
                if ordinary || segmented {
                    response.set_header(
                        "Surrogate-Control",
                        "max-age=31536000, stale-while-revalidate=0, stale-if-error=0",
                    );
                    response.set_header("Surrogate-Key", hash);
                    response.set_header(
                        "X-Divine-B2-CDN-Admission",
                        if ordinary {
                            "original-v1"
                        } else {
                            "original-segment-v1"
                        },
                    );
                }
            }
        }
        if self.head {
            response.take_body();
        }
    }
}

#[cfg(test)]
mod tests {
    use fastly::{http::StatusCode, Request};
    #[test]
    fn oversize_original_remains_successful_but_is_not_outer_cacheable() {
        let hash = "a".repeat(64);
        let policy = super::FinalPolicy {
            route: blossom_core::b2_cdn::Route::Delivery,
            hash: Some(hash.clone()),
            head: false,
        };
        // The boundary trusts the upstream verified origin contract. This test
        // exercises header admission only, not a synthetic large-body transfer.
        let mut response = fastly::Response::from_status(StatusCode::OK).with_body("stream");
        response.set_header("X-Divine-Source", "b2");
        response.set_header("X-Sha256", hash);
        response.set_header("Content-Length", "33554432");
        response.set_header("X-Content-Length", "33554432");
        policy.apply(&mut response);
        assert_eq!(response.get_status(), StatusCode::OK);
        assert_eq!(
            response.get_header_str("Surrogate-Control"),
            Some("no-store")
        );
        assert!(!response.contains_header("X-Divine-B2-CDN-Admission"));
        assert_eq!(response.take_body_str(), "stream");
    }
    #[test]
    fn disabled_production_host_never_falls_through_to_canonical_routes() {
        for (method, path) in [
            ("GET", "/version"),
            ("PUT", "/upload"),
            ("GET", "/admin"),
            (
                "GET",
                "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        ] {
            let response = crate::handle_main(Request::new(
                method,
                format!("https://media-b2-cdn.divine.video{path}"),
            ))
            .unwrap();
            assert_eq!(response.get_status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response.get_header_str("Surrogate-Control"),
                Some("no-store")
            );
            assert!(!response.contains_header("X-Divine-B2-CDN-Admission"));
        }
    }
    #[test]
    #[ignore = "requires enabled synthetic config; scripts/run-b2-cdn-tests.py"]
    fn final_hold_cannot_refill_b2_cdn_after_prepared_origin_response() {
        let hash = "a".repeat(64);
        let req = Request::get(format!("https://synthetic.edgecompute.app/{hash}"))
            .with_header("X-Original-Host", "media-b2-cdn.divine.video");
        let final_policy = super::FinalPolicy::for_request(&req);
        let result = crate::with_quarantine_response_guard(req, |req| {
            // Exercise the actual verified HTTP-origin handler before a hold
            // becomes visible to the final, uncached response guard.
            let response = crate::canary::handle_cdn(req)?;
            assert!(response.contains_header(crate::canary::VERIFIED_SEGMENT_HEADER));
            crate::metadata::open_store()
                .unwrap()
                .insert(
                    &format!("quarantine:v1:{hash}"),
                    r#"{"version":1,"holds":{"synthetic":{"version":1,"active":true}}}"#,
                )
                .unwrap();
            Ok(response)
        });
        let mut response = crate::error_response(&result.unwrap_err());
        final_policy.apply(&mut response);
        assert_eq!(response.get_status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.get_header_str("Surrogate-Control"),
            Some("no-store")
        );
        assert!(!response.contains_header("X-Divine-B2-CDN-Admission"));
        assert!(!response.contains_header(crate::canary::VERIFIED_SEGMENT_HEADER));
    }
    #[test]
    #[ignore = "requires synthetic private origin; scripts/run-b2-cdn-tests.py"]
    fn production_cdn_endpoint_contract() {
        let config = fastly::config_store::ConfigStore::open("blossom_config");
        let method = config.get("test_method").unwrap_or_else(|| "GET".into());
        let url = config
            .get("test_url")
            .unwrap_or_else(|| format!("https://synthetic.edgecompute.app/{}", "a".repeat(64)));
        let mut req = Request::new(method.clone(), url);
        if let Some(host) = config.get("test_host") {
            req.set_header("Host", host);
        }
        if let Some(host) = config.get("test_forwarded") {
            req.set_header("X-Original-Host", host);
        }
        if let Some(range) = config.get("test_range") {
            req.set_header("Range", range);
        }
        if let Some(value) = config.get("test_if_range") {
            req.set_header("If-Range", value);
        }
        if let Some(value) = config.get("test_if_range_second") {
            req.append_header("If-Range", value);
        }
        if let Some(value) = config.get("test_range_second") {
            req.append_header("Range", value);
        }
        if let Some(value) = config.get("test_untrusted_segment") {
            req.set_header("X-Divine-B2-Verified-Segment", value);
        }
        for (config_name, header) in [("test_auth", "Authorization"), ("test_cookie", "Cookie")] {
            if let Some(value) = config.get(config_name) {
                req.set_header(header, value);
            }
        }
        let mut response = crate::handle_main(req).unwrap();
        let status = config.get("test_status").unwrap().parse::<u16>().unwrap();
        assert_eq!(response.get_status().as_u16(), status);
        assert_eq!(
            response.get_header_str("Cache-Control"),
            Some("private, no-store")
        );
        if config.get("test_admitted").as_deref() == Some("true") {
            let expected_admission = config
                .get("test_admission")
                .unwrap_or_else(|| "original-v1".into());
            assert_eq!(
                response.get_header_str("X-Divine-B2-CDN-Admission"),
                Some(expected_admission.as_str())
            );
            assert_eq!(
                response.get_header_str("Surrogate-Control"),
                Some("max-age=31536000, stale-while-revalidate=0, stale-if-error=0")
            );
            assert_eq!(
                response.get_header_str("Surrogate-Key"),
                Some(
                    config
                        .get("test_hash")
                        .unwrap_or_else(|| "a".repeat(64))
                        .as_str()
                )
            );
        } else {
            assert!(!response.contains_header("X-Divine-B2-CDN-Admission"));
            assert_eq!(
                response.get_header_str("Surrogate-Control"),
                Some("no-store")
            );
        }
        if status == 200 || status == 206 {
            if let Some(expected_tag) = config.get("test_etag") {
                assert_eq!(response.get_header_str("ETag"), Some(expected_tag.as_str()));
            }
            assert!(!response.contains_header("X-Divine-B2-Verified-Segment"));
            assert_eq!(
                response.get_header_str("X-Divine-Source"),
                config.get("test_source").as_deref()
            );
            if method == "HEAD" {
                assert!(response.take_body().into_bytes().is_empty());
            } else if let Some(expected_sha) = config.get("test_body_sha256") {
                use sha2::{Digest, Sha256};
                use std::io::Read;
                let mut body = response.take_body();
                let mut digest = Sha256::new();
                let mut length = 0u64;
                let mut chunk = [0u8; 65536];
                loop {
                    let read = body.read(&mut chunk).unwrap();
                    if read == 0 {
                        break;
                    }
                    digest.update(&chunk[..read]);
                    length += read as u64;
                }
                assert_eq!(hex::encode(digest.finalize()), expected_sha);
                assert_eq!(length.to_string(), config.get("test_body_length").unwrap());
            } else {
                assert_eq!(
                    response.take_body().into_bytes(),
                    config.get("test_body").unwrap().into_bytes()
                );
            }
        }
    }
}

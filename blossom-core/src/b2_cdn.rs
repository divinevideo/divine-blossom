//! Default-off admission policy for purgeable outer-CDN B2 originals.

pub const HOST: &str = "media-b2-cdn.divine.video";
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    Unrelated,
    Delivery,
    Denied,
}
pub struct Config<'a> {
    pub enabled: Option<&'a str>,
    pub host: Option<&'a str>,
    pub origin_host: Option<&'a str>,
}
impl Config<'_> {
    pub fn route(&self, authority: &str, host: &str, original_host: Option<&str>) -> Route {
        let concerned = |value: &str| {
            let base = value.split(':').next().unwrap_or(value);
            base.eq_ignore_ascii_case(HOST)
                || self
                    .host
                    .is_some_and(|target| base.eq_ignore_ascii_case(target))
        };
        // The direct media-b2 endpoint keeps the strict canary contract, even
        // when that name is explicitly selected for forwarded CDN delivery.
        if host == crate::canary::RESERVED_HOST && original_host.is_none_or(|h| h == host) {
            return Route::Unrelated;
        }
        if !concerned(authority) && !concerned(host) && !original_host.is_some_and(concerned) {
            return Route::Unrelated;
        }
        let valid_host = matches!(self.host, Some(HOST | crate::canary::RESERVED_HOST));
        let valid_origin = self.origin_host.is_some_and(|origin| {
            origin != HOST
                && origin != crate::canary::RESERVED_HOST
                && origin.contains('.')
                && origin.len() <= 253
                && origin.split('.').all(|label| {
                    !label.is_empty()
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
        });
        if self.enabled != Some("true") || !valid_host || !valid_origin || authority != host {
            return Route::Denied;
        }
        let direct = Some(host) == self.host && original_host.is_none_or(|h| h == host);
        let forwarded = Some(host) == self.origin_host && original_host == self.host;
        if direct || forwarded {
            Route::Delivery
        } else {
            Route::Denied
        }
    }
}
pub fn original(method: &str, path: &str, authorization: bool, cookie: bool) -> Option<String> {
    if authorization || cookie {
        return None;
    }
    crate::canary::original_hash(method, path)
}
/// Called only for the verified demand handler's final response. Source is
/// selected by that handler after native auth, pinned version/size checks and
/// policy rechecks; it is never copied from an origin response or request.
pub fn admit(status: u16, source: Option<&str>, content_range: bool) -> bool {
    status == 200 && source == Some("b2") && !content_range
}

/// Hosts bound to the outer service and retained for targeted URL purges.
/// Only the delivery names managed by this VCL source are eligible.
pub fn purge_hosts<'a>(
    value: Option<&'a str>,
    delivery_host: Option<&str>,
) -> Option<Vec<&'a str>> {
    let delivery_host = delivery_host?;
    if !matches!(delivery_host, HOST | crate::canary::RESERVED_HOST) {
        return None;
    }
    let hosts: Vec<_> = value?.split(',').collect();
    if hosts.is_empty()
        || hosts.len() > 2
        || !hosts.contains(&delivery_host)
        || hosts
            .iter()
            .any(|host| !matches!(*host, HOST | crate::canary::RESERVED_HOST))
        || (hosts.len() == 2 && hosts[0] == hosts[1])
    {
        return None;
    }
    Some(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;
    const HOST: &str = "media-b2-cdn.divine.video";
    const ORIGIN: &str = "synthetic.edgecompute.app";
    fn configured() -> Config<'static> {
        Config {
            enabled: Some("true"),
            host: Some(HOST),
            origin_host: Some(ORIGIN),
        }
    }
    #[test]
    fn delivery_requires_explicit_configuration_and_exact_forwarding() {
        assert_eq!(configured().route(HOST, HOST, None), Route::Delivery);
        assert_eq!(
            configured().route(ORIGIN, ORIGIN, Some(HOST)),
            Route::Delivery
        );
        for enabled in [None, Some("false"), Some("TRUE")] {
            assert_eq!(
                Config {
                    enabled,
                    ..configured()
                }
                .route(HOST, HOST, None),
                Route::Denied
            );
        }
        for host in [
            None,
            Some(""),
            Some("other.example"),
            Some("MEDIA-B2-CDN.divine.video"),
        ] {
            assert_eq!(
                Config {
                    host,
                    ..configured()
                }
                .route(HOST, HOST, None),
                Route::Denied
            );
        }
        for origin_host in [
            None,
            Some(""),
            Some("https://synthetic.edgecompute.app"),
            Some(HOST),
        ] {
            assert_eq!(
                Config {
                    origin_host,
                    ..configured()
                }
                .route(HOST, HOST, None),
                Route::Denied
            );
        }
        for (authority, host, forwarded) in [
            (ORIGIN, ORIGIN, Some("MEDIA-B2-CDN.divine.video")),
            (ORIGIN, ORIGIN, Some("media-b2-cdn.divine.video:443")),
            ("other.edgecompute.app", "other.edgecompute.app", Some(HOST)),
            (HOST, HOST, Some("unknown.example")),
            (HOST, ORIGIN, Some(HOST)),
            (HOST, "media-b2-cdn.divine.video:443", None),
        ] {
            assert_eq!(
                configured().route(authority, host, forwarded),
                Route::Denied
            );
        }
    }
    #[test]
    fn purge_configuration_requires_bounded_declared_hosts_and_delivery_membership() {
        assert_eq!(purge_hosts(Some(HOST), Some(HOST)), Some(vec![HOST]));
        assert_eq!(
            purge_hosts(
                Some("media-b2-cdn.divine.video,media-b2.divine.video"),
                Some(HOST)
            ),
            Some(vec![HOST, "media-b2.divine.video"])
        );
        for value in [
            None,
            Some(""),
            Some("other.example"),
            Some("media-b2-cdn.divine.video,"),
            Some("media-b2-cdn.divine.video,media-b2-cdn.divine.video"),
            Some("media-b2-cdn.divine.video, unknown.example"),
            Some("https://media-b2-cdn.divine.video"),
            Some("media-b2-cdn.divine.video:443"),
            Some("media-b2-cdn.divine.video,other.example"),
            Some("MEDIA-B2-CDN.divine.video"),
        ] {
            assert_eq!(purge_hosts(value, Some(HOST)), None, "{value:?}");
        }
        assert_eq!(purge_hosts(Some(HOST), None), None);
        assert_eq!(purge_hosts(Some(HOST), Some("other.example")), None);
    }
    #[test]
    fn strict_canary_and_canonical_routes_are_unchanged() {
        for (host, forwarded) in [
            ("media-b2.divine.video", None),
            ("media.divine.video", None),
            (ORIGIN, Some("media.divine.video")),
            (ORIGIN, Some("media-b2.divine.video")),
        ] {
            assert_eq!(configured().route(host, host, forwarded), Route::Unrelated);
        }
        let migrated = Config {
            host: Some("media-b2.divine.video"),
            ..configured()
        };
        assert_eq!(
            migrated.route(ORIGIN, ORIGIN, Some("media-b2.divine.video")),
            Route::Delivery
        );
        // Even when configured for CDN migration, a direct canary remains fresh.
        assert_eq!(
            migrated.route("media-b2.divine.video", "media-b2.divine.video", None),
            Route::Unrelated
        );
    }
    #[test]
    fn only_anonymous_original_reads_can_be_admitted() {
        let hash = "a".repeat(64);
        for method in ["GET", "HEAD"] {
            for path in [format!("/{hash}"), format!("/{hash}.mp4")] {
                assert_eq!(original(method, &path, false, false), Some(hash.clone()));
                assert_eq!(original(method, &path, true, false), None);
                assert_eq!(original(method, &path, false, true), None);
            }
        }
        for path in [
            format!("/{hash}/720p"),
            format!("/{hash}.hls"),
            format!("/{hash}.jpg"),
            format!("/{hash}.vtt"),
            format!("/{}", hash.to_uppercase()),
            "/upload".into(),
            "/admin".into(),
        ] {
            assert_eq!(original("GET", &path, false, false), None);
        }
        assert_eq!(original("PUT", &format!("/{hash}"), false, false), None);
        for (status, source, content_range) in [
            (206, Some("b2"), false),
            (404, Some("b2"), false),
            (200, Some("gcs"), false),
            (200, None, false),
            (200, Some("b2"), true),
        ] {
            assert!(!admit(status, source, content_range));
        }
        assert!(admit(200, Some("b2"), false));
    }
}

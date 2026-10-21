use blossom_core::storage_origin::{MediaReadPolicy, StorageProvider};

#[test]
fn current_reads_remain_on_gcs_by_default() {
    let policy = MediaReadPolicy::parse(None, None).unwrap();
    assert_eq!(policy.primary, StorageProvider::Gcs);
    assert!(!policy.should_fallback(404));
}

#[test]
fn b2_falls_back_only_on_missing_or_transient_failures() {
    let policy = MediaReadPolicy::parse(Some("b2"), None).unwrap();
    assert!(policy.should_fallback(404));
    assert!(policy.should_fallback(503));
    for status in [200, 206, 304, 400, 401, 403, 416] {
        assert!(!policy.should_fallback(status));
    }
    assert!(!MediaReadPolicy::parse(Some("b2"), Some("false"))
        .unwrap()
        .should_fallback(404));
}

#[test]
fn invalid_rollout_configuration_is_rejected() {
    assert!(MediaReadPolicy::parse(Some("s3"), None).is_err());
    assert!(MediaReadPolicy::parse(Some("b2"), Some("yes")).is_err());
}

#[test]
fn b2_endpoint_is_derived_from_valid_region_only() {
    assert_eq!(
        StorageProvider::b2_host("us-west-004").unwrap(),
        "s3.us-west-004.backblazeb2.com"
    );
    for region in [
        "",
        "https://other.invalid",
        "us-west-004/other",
        "US-west",
        "-west",
        "west-",
        "a..b",
    ] {
        assert!(StorageProvider::b2_host(region).is_err(), "{region}");
    }
}

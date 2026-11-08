use blossom_core::b2_cdn::{SegmentedOriginal, SegmentedResponse};

const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn original(size: u64) -> SegmentedOriginal<'static> {
    SegmentedOriginal {
        sha256: HASH,
        destination_version_id: "verified-version-a",
        size,
    }
}

fn response<'a>(
    status: u16,
    length: &'a str,
    span: Option<&'a str>,
    etag: &'a str,
) -> SegmentedResponse<'a> {
    SegmentedResponse {
        method: "GET",
        source: Some("b2"),
        status,
        content_length: Some(length),
        content_range: span,
        entity_tag: Some(etag),
        content_encoding: None,
        transfer_encoding: None,
        set_cookie: false,
    }
}

#[test]
fn full_and_partial_contracts_cover_eight_sixteen_and_thirty_two_mib() {
    for size in [8, 16, 32].map(|mib| mib * 1024 * 1024) {
        let identity = original(size);
        let tag = identity.entity_tag().unwrap();
        assert!(identity.admits(&response(200, &size.to_string(), None, &tag), None));
        for (request, start, end) in [
            ("bytes=0-1023".to_owned(), 0, 1023),
            ("bytes=1048576-2097151".to_owned(), 1048576, 2097151),
            ("bytes=-1024".to_owned(), size - 1024, size - 1),
            (format!("bytes={}-", size - 1024), size - 1024, size - 1),
        ] {
            let span = format!("bytes {start}-{end}/{size}");
            assert!(identity.admits(
                &response(206, &(end - start + 1).to_string(), Some(&span), &tag),
                Some(&request)
            ));
        }
    }
}

#[test]
fn partial_admission_requires_the_exact_requested_span_total_and_length() {
    let identity = original(8388608);
    let tag = identity.entity_tag().unwrap();
    for (length, span) in [
        ("1023", "bytes 0-1023/8388608"),
        ("1024", "bytes 1-1024/8388608"),
        ("1024", "bytes 0-1023/16777216"),
        ("1024", "bytes 0-1024/8388608"),
        ("18446744073709551616", "bytes 0-1023/8388608"),
        (" 1024", "bytes 0-1023/8388608"),
    ] {
        assert!(!identity.admits(
            &response(206, length, Some(span), &tag),
            Some("bytes=0-1023")
        ));
    }
    assert!(!identity.admits(
        &response(206, "1024", Some("bytes 0-1023/8388608"), &tag),
        None
    ));
    assert!(!identity.admits(&response(206, "1024", None, &tag), Some("bytes=0-1023")));
}

#[test]
fn if_range_matches_only_the_strong_pinned_identity() {
    let identity = original(33554432);
    let tag = identity.entity_tag().unwrap();
    assert_eq!(
        identity.selected_range("GET", Some("bytes=0-1023"), None),
        Some("bytes=0-1023")
    );
    assert_eq!(
        identity.selected_range("GET", Some("bytes=0-1023"), Some(&tag)),
        Some("bytes=0-1023")
    );
    let other = SegmentedOriginal {
        destination_version_id: "verified-version-b",
        ..identity
    };
    assert_ne!(tag, other.entity_tag().unwrap());
    for validator in [
        format!("W/{tag}"),
        other.entity_tag().unwrap(),
        "Sun, 08 Nov 2026 00:00:00 GMT".into(),
        "*".into(),
        "".into(),
    ] {
        assert_eq!(
            identity.selected_range("GET", Some("bytes=0-1023"), Some(&validator)),
            None
        );
    }
    assert_eq!(
        identity.selected_range("HEAD", Some("bytes=0-1023"), Some(&tag)),
        None
    );
    for range in [
        "bytes=0-1,3-4",
        "bytes=3-1",
        "garbage",
        "bytes=18446744073709551616-",
    ] {
        assert_eq!(identity.selected_range("GET", Some(range), None), None);
    }
}

#[test]
fn changed_version_or_size_cannot_reuse_an_old_entity_tag() {
    let identity = original(16777216);
    let tag = identity.entity_tag().unwrap();
    for other in [
        SegmentedOriginal {
            destination_version_id: "verified-version-b",
            ..identity
        },
        SegmentedOriginal {
            size: 16777217,
            ..identity
        },
        SegmentedOriginal {
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ..identity
        },
    ] {
        assert_ne!(tag, other.entity_tag().unwrap());
        assert!(!other.admits(
            &response(206, "1024", Some("bytes 0-1023/16777216"), &tag),
            Some("bytes=0-1023")
        ));
    }
}

#[test]
fn fallback_errors_cookies_encoding_and_unsolicited_partial_responses_are_not_admitted() {
    let identity = original(8388608);
    let tag = identity.entity_tag().unwrap();
    for status in [202, 304, 404, 416, 500] {
        assert!(!identity.admits(&response(status, "8388608", None, &tag), None));
    }
    let mut candidate = response(200, "8388608", None, &tag);
    candidate.source = Some("gcs");
    assert!(!identity.admits(&candidate, None));
    candidate.source = Some("b2");
    candidate.set_cookie = true;
    assert!(!identity.admits(&candidate, None));
    candidate.set_cookie = false;
    candidate.content_encoding = Some("gzip");
    assert!(!identity.admits(&candidate, None));
    candidate.content_encoding = None;
    candidate.entity_tag = None;
    assert!(!identity.admits(&candidate, None));
    candidate.entity_tag = Some(&tag);
    candidate.transfer_encoding = Some("chunked");
    assert!(!identity.admits(&candidate, None));
    assert!(!identity.admits(
        &response(200, "8388608", Some("bytes 0-1023/8388608"), &tag),
        None
    ));
    assert!(!identity.admits(&response(200, "8388608", None, &tag), Some("bytes=0-1023")));
}

#[test]
fn invalid_identity_and_unproven_headers_fail_closed() {
    for identity in [
        original(0),
        SegmentedOriginal {
            sha256: "not-a-hash",
            ..original(8)
        },
        SegmentedOriginal {
            sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ..original(8)
        },
        SegmentedOriginal {
            destination_version_id: "",
            ..original(8)
        },
        SegmentedOriginal {
            destination_version_id: "version\r\nspoofed",
            ..original(8)
        },
    ] {
        assert_eq!(identity.entity_tag(), None);
        assert!(!identity.admits(&response(200, "8", None, "unverified"), None));
    }
    let identity = original(8);
    let tag = identity.entity_tag().unwrap();
    let mut candidate = response(200, "8", None, &tag);
    candidate.content_length = None;
    assert!(!identity.admits(&candidate, None));
    candidate.content_length = Some("8");
    candidate.method = "POST";
    assert!(!identity.admits(&candidate, None));
}

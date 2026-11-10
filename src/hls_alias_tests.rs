use super::*;

fn response(request: Request) -> Response {
    handle_request(request).unwrap_or_else(|error| error_response(&error))
}

fn metadata(hash: &str, status: &str, transcode: &str) {
    let value: BlobMetadata = serde_json::from_value(serde_json::json!({
        "sha256": hash, "size": 10, "type": "video/mp4",
        "uploaded": "2026-01-01T00:00:00Z", "owner": "b".repeat(64),
        "status": status, "transcode_status": transcode
    }))
    .unwrap();
    put_blob_metadata(&value).unwrap();
}

#[test]
#[ignore = "requires local synthetic metadata and HLS origin"]
fn hls_alias_relative_playlist_http_contract() {
    let hash = "a".repeat(64);
    metadata(&hash, "active", "complete");
    let alias = format!("https://media.example.test/{hash}.hls");
    let initial = response(Request::get(&alias));
    let status = initial.get_status();
    assert_eq!(
        initial.get_header_str("Access-Control-Allow-Origin"),
        Some("*")
    );
    assert!(initial
        .get_header_str("Cache-Control")
        .unwrap()
        .contains("public"));
    let (base, mut master) = if status == StatusCode::TEMPORARY_REDIRECT {
        let location = initial.get_header_str("Location").unwrap();
        assert_eq!(location, format!("/{hash}/hls/master.m3u8"));
        assert!(initial.get_header_str("ETag").is_none());
        let target = Request::get(&alias).get_url().join(location).unwrap();
        let base = target.clone();
        (base, response(Request::get(target.as_str())))
    } else {
        (Request::get(&alias).get_url().clone(), initial)
    };
    assert_eq!(master.get_status(), StatusCode::OK);
    let body = master.take_body_str();
    assert!(body.starts_with("#EXTM3U"));
    let variant = body
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty())
        .unwrap();
    // Exercise standard URL resolution against the actual handler response.
    let variant = base.join(variant).unwrap();
    assert!(
        variant.path().starts_with(&format!("/{hash}/hls/")),
        "playlist escaped its video directory: {variant}"
    );
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    let mut playlist = response(Request::get(variant.as_str()));
    assert_eq!(playlist.get_status(), StatusCode::OK);
    let body = playlist.take_body_str();
    let segment = body
        .lines()
        .find(|line| !line.starts_with('#') && !line.is_empty())
        .unwrap();
    let segment = variant.join(segment).unwrap();
    assert!(segment.path().starts_with(&format!("/{hash}/hls/")));
    let mut segment = response(Request::get(segment.as_str()));
    assert_eq!(segment.get_status(), StatusCode::OK);
    assert_eq!(segment.take_body_bytes(), b"segment-bytes");
    let mut request = Request::get(format!("https://media.example.test/{hash}/480p.mp4"));
    request.set_header("Range", "bytes=0-3");
    let mut segment = response(request);
    assert_eq!(segment.get_status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        segment.get_header_str("Content-Range"),
        Some("bytes 0-3/13")
    );
    assert_eq!(segment.take_body_bytes(), b"segm");

    // A redirect is not an access grant; denied requests never reach the origin.
    metadata(&hash, "banned", "complete");
    assert_eq!(
        response(Request::get(&alias)).get_status(),
        StatusCode::NOT_FOUND
    );
    let mut admin = Request::get(&alias);
    admin.set_header("Authorization", "Bearer synthetic-admin-token");
    let admin = response(admin);
    assert_eq!(admin.get_status(), StatusCode::TEMPORARY_REDIRECT);
    assert!(admin
        .get_header_str("Cache-Control")
        .unwrap()
        .contains("private"));

    let pending = "c".repeat(64);
    metadata(&pending, "active", "processing");
    let pending = response(Request::get(format!(
        "https://media.example.test/{pending}.hls"
    )));
    assert_eq!(pending.get_status(), StatusCode::ACCEPTED);
    assert!(pending.get_header_str("Location").is_none());
}

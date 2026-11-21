use super::*;
use sha2::Digest;

const ORIGINAL_HASH: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const OTHER_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn cohort_rejects_malformed_rollouts_and_missing_geography() {
    for percent in [
        None,
        Some("0"),
        Some("-1"),
        Some("+50"),
        Some("50.5"),
        Some("101"),
    ] {
        assert!(!cohort(ORIGINAL_HASH, percent, Some("US"), Some("US")));
    }
    for countries in [None, Some(""), Some("US,*"), Some("US,au"), Some("AU,NZ")] {
        assert!(!cohort(ORIGINAL_HASH, Some("100"), countries, Some("US")));
    }
    assert!(!cohort(ORIGINAL_HASH, Some("100"), Some("US"), None));
    let a = "0".repeat(64);
    assert!(cohort(&a, Some("1"), Some("US,NZ"), Some("NZ")));
    assert!(!cohort(ORIGINAL_HASH, Some("1"), Some("US"), Some("US")));
}
#[test]
#[ignore = "requires HLS loopback backends"]
fn bunny_hls_family_contract() {
    let fixture_parent = storage::get_config("fixture_parent").unwrap();
    let parent = fixture_parent.as_str();
    let base = "https://media.divine.video";
    let control = |name: &str, body: &str| {
        let res = Request::post(format!("http://fixture.invalid/fixture/{name}"))
            .with_body(body)
            .send("fixture_control")
            .unwrap();
        assert_eq!(res.get_status(), StatusCode::OK);
    };
    let call = |route: &str, body: Value| {
        let req = Request::post(format!("{base}/admin/api/bunny-pilot/{route}"))
            .with_header("Authorization", "Bearer fixture-admin")
            .with_body(body.to_string());
        crate::request_bindings::metered(req)
    };
    let inventory: Value =
        serde_json::from_str(&storage::get_config("fixture_inventory").unwrap()).unwrap();
    let rows = inventory.as_array().unwrap();
    let publish = |row: &Value, dependencies: Value| {
        call(
            "publish",
            json!({"path":row["path"],"sha256":row["source_sha256"],"dependencies":dependencies}),
        )
    };
    let finalize = |rows: &[Value]| {
        call(
            "finalize",
            json!({"version":1,"parent":parent,"assets":rows}),
        )
    };
    let child = |i: usize| json!({"path":rows[i]["path"],"sha256":rows[i]["delivery_sha256"]});
    let deps = |i| match i {
        2 => json!([child(0)]),
        3 => json!([child(1)]),
        4 => json!([child(2), child(3)]),
        _ => json!([]),
    };
    assert_eq!(
        publish(&rows[4], deps(4)).get_status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        publish(&rows[4], json!([])).get_status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(finalize(&rows[..1]).get_status(), StatusCode::BAD_REQUEST);
    for (i, row) in rows.iter().enumerate() {
        if i == 2 {
            assert_eq!(
                publish(row, json!([{"path":rows[0]["path"],"sha256":OTHER_HASH}])).get_status(),
                StatusCode::CONFLICT
            );
        }
        let mut response = publish(row, deps(i));
        assert_eq!(
            response.get_status(),
            StatusCode::OK,
            "{}",
            response.take_body_str()
        );
        if (2..=4).contains(&i) {
            let body: Value = serde_json::from_str(&response.take_body_str()).unwrap();
            assert_eq!(body["delivery_sha256"], row["delivery_sha256"]);
        }
    }
    let mut response = finalize(rows);
    assert_eq!(
        response.get_status(),
        StatusCode::OK,
        "{}",
        response.take_body_str()
    );
    let key = format!("bunny-ready:v1:{parent}");
    let record = metadata::open_store()
        .unwrap()
        .lookup(&key)
        .unwrap()
        .take_body()
        .into_string();
    control("ready", &record);
    let selection = Request::get(format!("{base}/api/bunny-playback/{parent}"))
        .with_header("Fastly-Client-Country", "US");
    let mut response = crate::request_bindings::metered(selection.clone_without_body());
    assert_eq!(
        response.get_header_str("Cache-Control"),
        Some("private, no-store")
    );
    assert_eq!(
        response.get_header_str("Access-Control-Allow-Origin"),
        Some("*")
    );
    let value: Value = serde_json::from_str(&response.take_body_str()).unwrap();
    assert_eq!(
        value["paths"],
        json!([]),
        "client-controlled country header admitted playback"
    );
    let selected =
        |request: &Request| super::selection(request, parent, Some("US")).unwrap()["paths"].clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let hop = |p: &str, country: &str, stamp: u64| {
        use hmac::{Hmac, Mac};
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(b"synthetic-test-key-with-32-or-more-bytes")
                .unwrap();
        mac.update(
            format!("bunny-playback-v1|GET|media.divine.video|/api/bunny-playback/{p}|{stamp}|US")
                .as_bytes(),
        );
        format!(
            "{stamp}:{country}:0x{}",
            hex::encode(mac.finalize().into_bytes())
        )
    };
    let forward = |token: &str, original: &str| {
        let req = Request::get(format!(
            "https://compute.fixture.example/api/bunny-playback/{parent}"
        ))
        .with_header("X-Original-Host", original)
        .with_header("X-Divine-Bunny-Market", token);
        let mut res = crate::request_bindings::metered(req);
        assert_eq!(res.get_status(), StatusCode::OK);
        serde_json::from_str::<Value>(&res.take_body_str()).unwrap()["paths"].clone()
    };
    assert_eq!(
        forward(&hop(parent, "US", now), "media.divine.video")
            .as_array()
            .unwrap()
            .len(),
        4
    );
    for token in [
        "spoof".into(),
        hop(OTHER_HASH, "US", now),
        hop(parent, "US", now - 60),
        hop(parent, "US", now + 60),
        hop(parent, "CA", now),
    ] {
        assert_eq!(forward(&token, "media.divine.video"), json!([]));
    }
    let paths = selected(&selection);
    let paths = paths.as_array().unwrap();
    assert_eq!(paths.len(), 4);
    assert!(paths.contains(&rows[4]["path"]));
    for row in &rows[5..] {
        assert!(paths.contains(&row["path"]));
    }
    // The producer replaced a canonical object, but neither queued callback has
    // reached metadata yet. Every new signed selection observes current versions.
    control("repair", "repair while callbacks are queued");
    assert_eq!(
        forward(&hop(parent, "US", now), "media.divine.video"),
        json!([rows[5]["path"]]),
        "stale derivative selected while producer callbacks lag"
    );
    // Even restoring matching bytes has a new immutable source version.
    control("repair", "restore-with-new-version");
    assert_eq!(
        forward(&hop(parent, "US", now), "media.divine.video"),
        json!([rows[5]["path"]])
    );
    assert_eq!(finalize(rows).get_status(), StatusCode::OK);
    let updated = metadata::open_store()
        .unwrap()
        .lookup(&key)
        .unwrap()
        .take_body()
        .into_string();
    control("ready", &updated);
    assert_eq!(
        forward(&hop(parent, "US", now), "media.divine.video")
            .as_array()
            .unwrap()
            .len(),
        4
    );
    control("repair", "restore-original");
    control("ready", &record);
    for fault in ["missing", "unreadable", "unversioned", "duplicate", "slow"] {
        control("head-fault", fault);
        assert_eq!(
            forward(&hop(parent, "US", now), "media.divine.video"),
            json!([rows[5]["path"]]),
            "{fault}"
        );
    }
    control("head-fault", "batch");
    assert_eq!(
        forward(&hop(parent, "US", now), "media.divine.video")
            .as_array()
            .unwrap()
            .len(),
        4
    );
    control("head-fault", "");
    // These snapshots are returned by the authoritative producer callback store.
    control(
        "transcode",
        r#"{"transcode_status":"complete","transcode_generation":18}"#,
    );
    let repaired_paths = forward(&hop(parent, "US", now), "media.divine.video");
    control(
        "transcode",
        r#"{"transcode_status":"processing","transcode_generation":17}"#,
    );
    let processing_paths = forward(&hop(parent, "US", now), "media.divine.video");
    control(
        "transcode",
        r#"{"transcode_status":"complete","transcode_generation":17}"#,
    );
    control("repair-during-finalize", "");
    let interleaved = finalize(rows).get_status();
    let mut legacy: Value = serde_json::from_str(&record).unwrap();
    legacy.as_object_mut().unwrap().remove("producer");
    control("ready", &legacy.to_string());
    let legacy_paths = forward(&hop(parent, "US", now), "media.divine.video");
    control("transcode", r#"{"transcode_status":"complete"}"#);
    let unversioned = finalize(rows).get_status();
    let original_only = finalize(&rows[5..6]).get_status();
    control(
        "transcode",
        r#"{"transcode_status":"complete","transcode_generation":17}"#,
    );
    control("ready", &record);
    control("policy-status", "pending");
    let mut pending = crate::request_bindings::metered(
        Request::get(format!(
            "https://compute.fixture.example/api/bunny-playback/{parent}"
        ))
        .with_header("X-Original-Host", "media.divine.video")
        .with_header("X-Divine-Bunny-Market", hop(parent, "US", now)),
    );
    assert_eq!(
        (
            repaired_paths,
            processing_paths,
            legacy_paths,
            interleaved,
            unversioned,
            original_only,
            pending.get_status()
        ),
        (
            json!([rows[5]["path"]]),
            json!([rows[5]["path"]]),
            json!([rows[5]["path"]]),
            StatusCode::CONFLICT,
            StatusCode::CONFLICT,
            StatusCode::OK,
            StatusCode::OK
        )
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&pending.take_body_bytes()).unwrap()["paths"],
        json!([])
    );
    for blocker in ["quarantine", "tombstone", "vanish"] {
        control("policy-blocker", blocker);
        assert_eq!(
            super::selection(&selection, parent, Some("US")).unwrap_err().status_code(),
            StatusCode::NOT_FOUND,
            "{blocker}"
        );
    }
    control("policy-blocker", "");
    control("policy-status", "active");
    let authenticated = selection
        .clone_without_body()
        .with_header("Authorization", "Bearer synthetic");
    assert_eq!(selected(&authenticated), json!([]));
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/prefix", json!("other/")),
        ("/assets/0/source/version", json!("null")),
        ("/assets/0/source/bucket", json!("unconfigured-bucket")),
        ("/assets/0/destination_version", json!("")),
        ("/assets/0/asset/delivery_sha256", json!("invalid")),
    ] {
        let mut broken: Value = serde_json::from_str(&record).unwrap();
        *broken.pointer_mut(pointer).unwrap() = value;
        control("ready", &broken.to_string());
        assert_eq!(selected(&selection), json!([]));
    }
    control("ready", "");
    assert_eq!(selected(&selection), json!([]));
    control("ready", &record);
    control("uploaders", "cde");
    // Accumulate independent regressions to report all outcomes in one run.
    let four = super::selection(&selection, parent, Some("US"))
        .map(|value| value["paths"].clone())
        .map_err(|e| e.status_code());
    control("ready", "");
    let four_missing = super::selection(&selection, parent, Some("US"))
        .map(|value| value["paths"].clone())
        .map_err(|e| e.status_code());
    control("policy-status", "age_restricted");
    let age_fallback = super::selection(&selection, parent, Some("US"))
        .map(|value| value["paths"].clone())
        .map_err(|e| e.status_code());
    control("uploaders", "cd");
    control("ready", &record);
    control("retire-during-read", "");
    let stale = selected(&selection);
    control("ready", &record);
    control("repair", "rebuilt rendition");
    let mut repaired = rows[6].clone();
    repaired["source_sha256"] = json!(hex::encode(sha2::Sha256::digest(b"rebuilt rendition")));
    let conflict = publish(&repaired, json!([])).get_status();
    let retired = matches!(
        metadata::open_store().unwrap().lookup(&key),
        Err(KVStoreError::ItemNotFound)
    );
    control("ready", if retired { "" } else { &record });
    let after_conflict = selected(&selection);
    assert_eq!(
        (
            four,
            four_missing,
            age_fallback,
            stale,
            conflict,
            retired,
            after_conflict
        ),
        (
            Ok(json!([])),
            Ok(json!([])),
            Ok(json!([])),
            json!([]),
            StatusCode::CONFLICT,
            true,
            json!([])
        )
    );
    control("repair", "restore-original");
    control("ready", &record);
    control("source-version", "null");
    assert_eq!(finalize(rows).get_status(), StatusCode::CONFLICT);
    control("source-version", "123");
    control("policy-status", "age_restricted");
    assert_eq!(finalize(rows).get_status(), StatusCode::NOT_FOUND);
    assert_eq!(selected(&selection), json!([]));
    control("policy-status", "restricted");
    assert_eq!(selected(&selection), json!([]));
    control("policy-status", "banned");
    assert_eq!(
        super::selection(&selection, parent, Some("US")).unwrap_err().status_code(),
        StatusCode::NOT_FOUND
    );
    control("policy-status", "active");
    control("source-version", "null");
    super::FAIL_NEXT_DELETE.set(true);
    assert_ne!(finalize(rows).get_status(), StatusCode::OK);
    let mut gate = metadata::open_store()
        .unwrap()
        .lookup(&format!("b2-sync:v1:{parent}"))
        .unwrap();
    assert_eq!(
        crate::parent_gate::parse(&gate.take_body().into_bytes()),
        Some(crate::parent_gate::Gate::Copying {
            attempt_id: format!("bunny-cleanup-{parent}")
        })
    );
}

#[test]
#[ignore = "requires synthetic four-uploader policy origin"]
fn bunny_disabled_four_uploaders() {
    let req = Request::get(format!(
        "https://media.divine.video/api/bunny-playback/{ORIGINAL_HASH}"
    ));
    let value = super::selection(&req, ORIGINAL_HASH, Some("US")).unwrap();
    assert_eq!(value["paths"], json!([]));
}

#[test]
#[ignore = "requires zero-rollout synthetic policy origin"]
fn pending_bunny_playback_falls_back() {
    let mut res = crate::request_bindings::metered(Request::get(format!(
        "https://media.divine.video/api/bunny-playback/{ORIGINAL_HASH}"
    )));
    assert_eq!(res.get_status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&res.take_body_str()).unwrap()["paths"],
        json!([])
    );
}

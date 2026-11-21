use super::*;

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
    let base = "https://media.divine.video";
    let control = |name: &str, body: &str| {
        let res = Request::post(format!("http://fixture.invalid/fixture/{name}"))
            .with_body(body)
            .send("fixture_control")
            .unwrap();
        assert_eq!(res.get_status(), StatusCode::OK);
    };
    let call = |route: &str, body: Value| {
        control("meter", route);
        let req = Request::post(format!("{base}/admin/api/bunny-pilot/{route}"))
            .with_header("Authorization", "Bearer fixture-admin")
            .with_body(body.to_string());
        crate::route_request(req).unwrap_or_else(|e| crate::error_response(&e))
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
            json!({"version":1,"parent":ORIGINAL_HASH,"assets":rows}),
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
    let key = format!("bunny-ready:v1:{ORIGINAL_HASH}");
    let record = metadata::open_store()
        .unwrap()
        .lookup(&key)
        .unwrap()
        .take_body()
        .into_string();
    control("meter", "selection");
    control("ready", &record);
    let selection = Request::get(format!("{base}/api/bunny-playback/{ORIGINAL_HASH}"))
        .with_header("Fastly-Client-Country", "US");
    let mut response = crate::route_request(selection.clone_without_body()).unwrap();
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
    let selected = |request: &Request| {
        super::selection(request, ORIGINAL_HASH, Some("US")).unwrap()["paths"].clone()
    };
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
            "https://compute.fixture.example/api/bunny-playback/{ORIGINAL_HASH}"
        ))
        .with_header("X-Original-Host", original)
        .with_header("X-Divine-Bunny-Market", token);
        let mut res = crate::route_request(req).unwrap();
        assert_eq!(res.get_status(), StatusCode::OK);
        serde_json::from_str::<Value>(&res.take_body_str()).unwrap()["paths"].clone()
    };
    assert_eq!(
        forward(&hop(ORIGINAL_HASH, "US", now), "media.divine.video")
            .as_array()
            .unwrap()
            .len(),
        4
    );
    for token in [
        "spoof".into(),
        hop(OTHER_HASH, "US", now),
        hop(ORIGINAL_HASH, "US", now - 60),
        hop(ORIGINAL_HASH, "US", now + 60),
        hop(ORIGINAL_HASH, "CA", now),
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
    let authenticated = selection
        .clone_without_body()
        .with_header("Authorization", "Bearer synthetic");
    assert_eq!(selected(&authenticated), json!([]));
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/prefix", json!("other/")),
        ("/assets/0/source/version", json!("null")),
        ("/assets/0/source/provider", json!("b2")),
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
    control("source-version", "null");
    assert_eq!(finalize(rows).get_status(), StatusCode::CONFLICT);
    control("source-version", "123");
    control("policy-status", "age_restricted");
    assert_eq!(finalize(rows).get_status(), StatusCode::NOT_FOUND);
    assert_eq!(
        crate::route_request(selection).unwrap().get_status(),
        StatusCode::NOT_FOUND
    );
}

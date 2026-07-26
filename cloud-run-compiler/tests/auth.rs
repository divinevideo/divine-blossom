use base64::{engine::general_purpose::STANDARD, Engine as _};
use divine_compiler::{
    auth::{verify_editor_request, AuthError},
    domain::{
        Aspect, AudioSettings, CompileRequest, CreditSettings, FitMode, RenderRequest, Source,
        Watermark,
    },
};
use nostr::{
    hashes::{sha256, Hash},
    nips::nip98::{HttpData, HttpMethod},
    EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp, UncheckedUrl,
};
use sha2::{Digest, Sha256};

const SECRET_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const OTHER_SECRET_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const VIDEO_PUBKEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const URL: &str = "https://compiler.divine.video/api/compile";

fn signed_request(list_keys: &Keys, auth_keys: &Keys) -> (CompileRequest, Vec<u8>, String, u64) {
    let coordinate = format!("34236:{VIDEO_PUBKEY}:first");
    let list_event = EventBuilder::new(
        Kind::Custom(30_005),
        "",
        vec![
            Tag::parse(&["d", "staff-picks"]).unwrap(),
            Tag::parse(&["a", coordinate.as_str(), "wss://relay.divine.video"]).unwrap(),
        ],
    )
    .to_event(list_keys)
    .unwrap();

    let request = CompileRequest {
        source: Source {
            list_event: serde_json::from_str(&list_event.as_json()).unwrap(),
        },
        renders: vec![RenderRequest {
            aspect: Aspect::Portrait,
            default_fit: FitMode::BlurPad,
            clip_overrides: vec![],
        }],
        watermark: Watermark::default(),
        credit: CreditSettings::default(),
        audio: AudioSettings::default(),
        max_duration_sec: 600,
    };
    let body = serde_json::to_vec(&request).unwrap();
    let body_hash = Sha256::digest(&body);
    let payload = sha256::Hash::from_slice(&body_hash).unwrap();
    let auth_event = EventBuilder::http_auth(
        HttpData::new(UncheckedUrl::from(URL), HttpMethod::POST).payload(payload),
    )
    .to_event(auth_keys)
    .unwrap();
    let header = format!("Nostr {}", STANDARD.encode(auth_event.as_json().as_bytes()));

    (request, body, header, Timestamp::now().as_u64())
}

#[test]
fn verifies_list_signature_and_matching_nip98_author() {
    let keys = Keys::parse(SECRET_KEY).unwrap();
    let (request, body, header, now) = signed_request(&keys, &keys);

    let identity = verify_editor_request(&header, "POST", URL, &body, &request, now).unwrap();

    assert_eq!(identity.pubkey, request.source.list_event.pubkey);
}

#[test]
fn rejects_nip98_author_that_does_not_match_list() {
    let list_keys = Keys::parse(SECRET_KEY).unwrap();
    let auth_keys = Keys::parse(OTHER_SECRET_KEY).unwrap();
    let (request, body, header, now) = signed_request(&list_keys, &auth_keys);

    let error = verify_editor_request(&header, "POST", URL, &body, &request, now).unwrap_err();

    assert_eq!(error, AuthError::AuthorMismatch);
}

#[test]
fn rejects_payload_hash_mismatch() {
    let keys = Keys::parse(SECRET_KEY).unwrap();
    let (request, mut body, header, now) = signed_request(&keys, &keys);
    body.push(b' ');

    let error = verify_editor_request(&header, "POST", URL, &body, &request, now).unwrap_err();

    assert_eq!(error, AuthError::PayloadMismatch);
}

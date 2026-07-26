use base64::{engine::general_purpose::STANDARD, Engine as _};
use divine_compiler::upload::{blossom_authorization, chunk_ranges, ResumableUploadInitRequest};
use nostr::{Event, JsonUtil, Keys};

const SECRET_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn init_request_explicitly_disables_derivatives() {
    let request = ResumableUploadInitRequest::compilation(SHA256, 17, "portrait.mp4");
    let json = serde_json::to_value(request).unwrap();

    assert_eq!(json["generateDerivatives"], false);
    assert_eq!(json["contentType"], "video/mp4");
}

#[test]
fn chunk_ranges_cover_file_without_overlap() {
    assert_eq!(chunk_ranges(17, 8), vec![(0, 7), (8, 15), (16, 16)]);
}

#[test]
fn blossom_authorization_binds_upload_action_and_hash() {
    let keys = Keys::parse(SECRET_KEY).unwrap();
    let header = blossom_authorization(&keys, SHA256, 1_000).unwrap();
    let json = STANDARD
        .decode(header.strip_prefix("Nostr ").unwrap())
        .unwrap();
    let event = Event::from_json(String::from_utf8(json).unwrap()).unwrap();

    event.verify().unwrap();
    assert_eq!(event.kind.as_u16(), 24_242);
    assert!(event.tags.iter().any(|tag| tag.as_vec() == ["t", "upload"]));
    assert!(event.tags.iter().any(|tag| tag.as_vec() == ["x", SHA256]));
    assert!(event
        .tags
        .iter()
        .any(|tag| tag.as_vec() == ["expiration", "1300"]));
}

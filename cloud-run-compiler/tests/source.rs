use anyhow::Result;
use async_trait::async_trait;
use divine_compiler::{
    domain::NostrEvent,
    source::{resolve_sources, CreatorProfile, SourceRepository},
};
use std::collections::HashMap;

const AUTHOR_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUTHOR_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn coordinate(author: &str, identifier: &str) -> String {
    format!("34236:{author}:{identifier}")
}

fn video_event(author: &str, identifier: &str, hash_byte: char) -> NostrEvent {
    let hash = hash_byte.to_string().repeat(64);
    NostrEvent {
        id: hash.clone(),
        pubkey: author.into(),
        created_at: 100,
        kind: 34_236,
        tags: vec![
            vec!["d".into(), identifier.into()],
            vec![
                "imeta".into(),
                format!("url https://media.divine.video/{hash}"),
                format!("x {hash}"),
                "m video/mp4".into(),
            ],
        ],
        content: String::new(),
        sig: "f".repeat(128),
    }
}

#[derive(Default)]
struct FakeRepository {
    events: Vec<NostrEvent>,
    profiles: HashMap<String, CreatorProfile>,
}

#[async_trait]
impl SourceRepository for FakeRepository {
    async fn addressable_events(&self, _coordinates: &[String]) -> Result<Vec<NostrEvent>> {
        Ok(self.events.clone())
    }

    async fn profiles(&self, _pubkeys: &[String]) -> Result<HashMap<String, CreatorProfile>> {
        Ok(self.profiles.clone())
    }
}

#[tokio::test]
async fn resolves_addressable_events_in_signed_list_order() {
    let repository = FakeRepository {
        events: vec![
            video_event(AUTHOR_B, "second", '2'),
            video_event(AUTHOR_A, "first", '1'),
        ],
        ..FakeRepository::default()
    };

    let result = resolve_sources(
        &repository,
        &[
            coordinate(AUTHOR_A, "first"),
            coordinate(AUTHOR_B, "second"),
        ],
    )
    .await
    .unwrap();

    assert_eq!(
        result
            .usable
            .iter()
            .map(|clip| clip.coordinate.as_str())
            .collect::<Vec<_>>(),
        vec![
            coordinate(AUTHOR_A, "first"),
            coordinate(AUTHOR_B, "second")
        ]
    );
}

#[tokio::test]
async fn records_missing_and_unusable_clips_without_reordering() {
    let mut unusable = video_event(AUTHOR_B, "bad-media", '2');
    unusable.tags = vec![vec!["d".into(), "bad-media".into()]];
    let repository = FakeRepository {
        events: vec![unusable, video_event(AUTHOR_A, "last", '3')],
        ..FakeRepository::default()
    };
    let missing = coordinate(AUTHOR_A, "missing");
    let bad = coordinate(AUTHOR_B, "bad-media");
    let last = coordinate(AUTHOR_A, "last");

    let result = resolve_sources(&repository, &[missing.clone(), bad.clone(), last.clone()])
        .await
        .unwrap();

    assert_eq!(result.usable[0].coordinate, last);
    assert_eq!(result.dropped[0].coordinate, missing);
    assert_eq!(result.dropped[0].reason, "event-not-found");
    assert_eq!(result.dropped[1].coordinate, bad);
    assert_eq!(result.dropped[1].reason, "missing-original-mp4");
}

#[tokio::test]
async fn attaches_full_creator_credit_metadata() {
    let repository = FakeRepository {
        events: vec![video_event(AUTHOR_A, "first", '1')],
        profiles: HashMap::from([(
            AUTHOR_A.into(),
            CreatorProfile {
                display_name: Some("Alice Example".into()),
                nip05: Some("alice@divine.video".into()),
            },
        )]),
    };

    let result = resolve_sources(&repository, &[coordinate(AUTHOR_A, "first")])
        .await
        .unwrap();

    assert_eq!(
        result.usable[0].credit.display_name.as_deref(),
        Some("Alice Example")
    );
    assert_eq!(
        result.usable[0].credit.nip05.as_deref(),
        Some("alice@divine.video")
    );
    assert_eq!(result.usable[0].credit.pubkey, AUTHOR_A);
}

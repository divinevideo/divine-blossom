use anyhow::Result;
use async_trait::async_trait;
use divine_compiler::{
    domain::{ListSlot, NostrEvent, VideoReference},
    source::{resolve_sources, CreatorProfile, SourceRepository},
};
use std::collections::HashMap;

const AUTHOR_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const AUTHOR_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn coordinate(author: &str, identifier: &str) -> String {
    format!("34236:{author}:{identifier}")
}

fn addressed(author: &str, identifier: &str) -> ListSlot {
    ListSlot::Video(VideoReference::Coordinate(coordinate(author, identifier)))
}

fn listed(hash_byte: char) -> ListSlot {
    ListSlot::Video(VideoReference::Event(hash_byte.to_string().repeat(64)))
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

    async fn events_by_id(&self, ids: &[String]) -> Result<Vec<NostrEvent>> {
        Ok(self
            .events
            .iter()
            .filter(|event| ids.contains(&event.id))
            .cloned()
            .collect())
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
        &[addressed(AUTHOR_A, "first"), addressed(AUTHOR_B, "second")],
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
    let missing = addressed(AUTHOR_A, "missing");
    let bad = addressed(AUTHOR_B, "bad-media");
    let last = addressed(AUTHOR_A, "last");

    let result = resolve_sources(&repository, &[missing.clone(), bad.clone(), last.clone()])
        .await
        .unwrap();

    assert_eq!(result.usable[0].coordinate, last.as_str());
    assert_eq!(result.dropped[0].coordinate, missing.as_str());
    assert_eq!(result.dropped[0].reason, "event-not-found");
    assert_eq!(result.dropped[1].coordinate, bad.as_str());
    assert_eq!(result.dropped[1].reason, "missing-original-mp4");
}

#[tokio::test]
async fn resolves_event_id_references_written_by_the_divine_app() {
    let repository = FakeRepository {
        events: vec![
            video_event(AUTHOR_B, "second", '2'),
            video_event(AUTHOR_A, "first", '1'),
        ],
        ..FakeRepository::default()
    };

    let result = resolve_sources(&repository, &[listed('1'), listed('2')])
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
    // The credit follows the resolved event, not the way the list referenced it.
    assert_eq!(result.usable[0].credit.pubkey, AUTHOR_A);
    assert_eq!(result.usable[0].reference, "1".repeat(64));
    assert_eq!(result.usable[0].event_id, "1".repeat(64));
}

#[tokio::test]
async fn keeps_signed_order_when_a_list_mixes_event_ids_and_coordinates() {
    let repository = FakeRepository {
        events: vec![
            video_event(AUTHOR_A, "first", '1'),
            video_event(AUTHOR_B, "second", '2'),
        ],
        ..FakeRepository::default()
    };

    let result = resolve_sources(&repository, &[listed('2'), addressed(AUTHOR_A, "first")])
        .await
        .unwrap();

    assert_eq!(
        result
            .usable
            .iter()
            .map(|clip| clip.coordinate.as_str())
            .collect::<Vec<_>>(),
        vec![
            coordinate(AUTHOR_B, "second"),
            coordinate(AUTHOR_A, "first")
        ]
    );
}

#[tokio::test]
async fn drops_event_references_that_are_not_video_events() {
    let mut note = video_event(AUTHOR_A, "not-a-video", '5');
    note.kind = 1;
    let repository = FakeRepository {
        events: vec![note],
        ..FakeRepository::default()
    };

    let result = resolve_sources(&repository, &[listed('5')]).await.unwrap();

    assert!(result.usable.is_empty());
    assert_eq!(result.dropped[0].reason, "event-not-found");
    assert_eq!(result.dropped[0].coordinate, "5".repeat(64));
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

    let result = resolve_sources(&repository, &[addressed(AUTHOR_A, "first")])
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

#[tokio::test]
async fn unsupported_list_tags_are_dropped_clips_rather_than_a_failed_render() {
    let repository = FakeRepository {
        events: vec![video_event(AUTHOR_A, "first", '1')],
        ..FakeRepository::default()
    };
    let unsupported = ListSlot::Unsupported {
        value: "30023:not-a-video:article".into(),
        reason: "unsupported-coordinate",
    };

    let result = resolve_sources(
        &repository,
        &[unsupported.clone(), addressed(AUTHOR_A, "first")],
    )
    .await
    .unwrap();

    assert_eq!(result.usable.len(), 1);
    assert_eq!(result.usable[0].source_index, 1);
    assert_eq!(result.dropped.len(), 1);
    assert_eq!(result.dropped[0].source_index, 0);
    assert_eq!(result.dropped[0].coordinate, unsupported.as_str());
    assert_eq!(result.dropped[0].reason, "unsupported-coordinate");
}

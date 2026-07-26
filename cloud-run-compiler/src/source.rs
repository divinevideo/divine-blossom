// ABOUTME: Resolves signed-list coordinates into ordered, renderable source clips
// ABOUTME: Parses NIP-71 media metadata and carries complete creator credit identity

use crate::domain::{ClipDrop, Credit, NostrEvent};
use anyhow::{Context, Result};
use async_trait::async_trait;
use nostr_sdk::{Client, EventSource, Filter, JsonUtil, Kind, PublicKey};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CreatorProfile {
    pub display_name: Option<String>,
    pub nip05: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedClip {
    pub source_index: usize,
    pub coordinate: String,
    pub event_id: String,
    pub media_url: String,
    pub sha256: String,
    pub credit: Credit,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Resolution {
    pub usable: Vec<ResolvedClip>,
    pub dropped: Vec<ClipDrop>,
}

#[async_trait]
pub trait SourceRepository: Send + Sync {
    async fn addressable_events(&self, coordinates: &[String]) -> Result<Vec<NostrEvent>>;
    async fn profiles(&self, pubkeys: &[String]) -> Result<HashMap<String, CreatorProfile>>;
}

#[derive(Clone)]
pub struct RelaySourceRepository {
    client: Client,
    timeout: Duration,
}

impl RelaySourceRepository {
    pub async fn connect(relays: &[String], timeout: Duration) -> Result<Self> {
        if relays.is_empty() {
            anyhow::bail!("at least one source relay is required");
        }
        let client = Client::default();
        for relay in relays {
            client
                .add_relay(relay)
                .await
                .with_context(|| format!("add source relay {relay}"))?;
        }
        client.connect().await;
        Ok(Self { client, timeout })
    }
}

#[async_trait]
impl SourceRepository for RelaySourceRepository {
    async fn addressable_events(&self, coordinates: &[String]) -> Result<Vec<NostrEvent>> {
        let filters: Vec<Filter> = coordinates
            .iter()
            .map(|coordinate| parse_coordinate(coordinate))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|(kind, author, identifier)| {
                Filter::new()
                    .kind(Kind::Custom(kind as u16))
                    .author(author)
                    .identifier(identifier)
                    .limit(1)
            })
            .collect();
        if filters.is_empty() {
            return Ok(Vec::new());
        }

        let events = self
            .client
            .get_events_of(filters, EventSource::relays(Some(self.timeout)))
            .await
            .context("query source video events")?;
        events
            .into_iter()
            .map(|event| {
                serde_json::from_str(&event.as_json()).context("decode source video event")
            })
            .collect()
    }

    async fn profiles(&self, pubkeys: &[String]) -> Result<HashMap<String, CreatorProfile>> {
        if pubkeys.is_empty() {
            return Ok(HashMap::new());
        }
        let authors: Vec<PublicKey> = pubkeys
            .iter()
            .map(|pubkey| PublicKey::from_hex(pubkey).context("parse profile pubkey"))
            .collect::<Result<_>>()?;
        let events = self
            .client
            .get_events_of(
                vec![Filter::new().kind(Kind::Metadata).authors(authors)],
                EventSource::relays(Some(self.timeout)),
            )
            .await
            .context("query creator profiles")?;

        let mut newest: HashMap<String, (u64, CreatorProfile)> = HashMap::new();
        for event in events {
            let profile: ProfileContent = match serde_json::from_str(&event.content) {
                Ok(profile) => profile,
                Err(_) => continue,
            };
            let pubkey = event.pubkey.to_string();
            let created_at = event.created_at.as_u64();
            let replace = newest
                .get(&pubkey)
                .map(|(current, _)| created_at > *current)
                .unwrap_or(true);
            if replace {
                newest.insert(
                    pubkey,
                    (
                        created_at,
                        CreatorProfile {
                            display_name: profile.display_name.or(profile.name),
                            nip05: profile.nip05,
                        },
                    ),
                );
            }
        }

        Ok(newest
            .into_iter()
            .map(|(pubkey, (_, profile))| (pubkey, profile))
            .collect())
    }
}

#[derive(Debug, Deserialize)]
struct ProfileContent {
    name: Option<String>,
    display_name: Option<String>,
    nip05: Option<String>,
}

pub async fn resolve_sources(
    repository: &dyn SourceRepository,
    coordinates: &[String],
) -> Result<Resolution> {
    let events = repository.addressable_events(coordinates).await?;
    let mut newest_by_coordinate: HashMap<String, NostrEvent> = HashMap::new();
    for event in events {
        let Some(coordinate) = event_coordinate(&event) else {
            continue;
        };
        if !coordinates.contains(&coordinate) {
            continue;
        }

        let replace = newest_by_coordinate
            .get(&coordinate)
            .map(|current| {
                event.created_at > current.created_at
                    || (event.created_at == current.created_at && event.id > current.id)
            })
            .unwrap_or(true);
        if replace {
            newest_by_coordinate.insert(coordinate, event);
        }
    }

    let author_pubkeys: Vec<String> = coordinates
        .iter()
        .filter_map(|coordinate| newest_by_coordinate.get(coordinate))
        .map(|event| event.pubkey.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let profiles = repository.profiles(&author_pubkeys).await?;

    let mut resolution = Resolution::default();
    for (source_index, coordinate) in coordinates.iter().enumerate() {
        let Some(event) = newest_by_coordinate.get(coordinate) else {
            resolution.dropped.push(ClipDrop {
                source_index,
                coordinate: coordinate.clone(),
                reason: "event-not-found".into(),
            });
            continue;
        };

        let Some((media_url, sha256)) = original_mp4(event) else {
            resolution.dropped.push(ClipDrop {
                source_index,
                coordinate: coordinate.clone(),
                reason: "missing-original-mp4".into(),
            });
            continue;
        };

        let profile = profiles.get(&event.pubkey).cloned().unwrap_or_default();
        resolution.usable.push(ResolvedClip {
            source_index,
            coordinate: coordinate.clone(),
            event_id: event.id.clone(),
            media_url,
            sha256,
            credit: Credit {
                coordinate: coordinate.clone(),
                pubkey: event.pubkey.clone(),
                nip05: profile.nip05,
                display_name: profile.display_name,
            },
        });
    }

    Ok(resolution)
}

fn event_coordinate(event: &NostrEvent) -> Option<String> {
    if !matches!(event.kind, 34_235 | 34_236) {
        return None;
    }
    let identifier = event.d_tag()?;
    Some(format!("{}:{}:{}", event.kind, event.pubkey, identifier))
}

fn parse_coordinate(coordinate: &str) -> Result<(u32, PublicKey, String)> {
    let mut parts = coordinate.splitn(3, ':');
    let kind = parts
        .next()
        .context("coordinate kind missing")?
        .parse::<u32>()
        .context("coordinate kind invalid")?;
    if !matches!(kind, 34_235 | 34_236) {
        anyhow::bail!("unsupported video coordinate kind");
    }
    let author = PublicKey::from_hex(parts.next().context("coordinate author missing")?)
        .context("coordinate author invalid")?;
    let identifier = parts.next().context("coordinate identifier missing")?;
    if identifier.is_empty() {
        anyhow::bail!("coordinate identifier empty");
    }
    Ok((kind, author, identifier.into()))
}

fn original_mp4(event: &NostrEvent) -> Option<(String, String)> {
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("imeta") {
            continue;
        }
        let mut url = None;
        let mut sha256 = None;
        let mut mime = None;
        for field in tag.iter().skip(1) {
            if let Some(value) = field.strip_prefix("url ") {
                url = Some(value);
            } else if let Some(value) = field.strip_prefix("x ") {
                sha256 = Some(value);
            } else if let Some(value) = field.strip_prefix("m ") {
                mime = Some(value);
            }
        }
        if mime != Some("video/mp4") {
            continue;
        }
        if let (Some(url), Some(sha256)) = (url, sha256) {
            if valid_media_url(url) && valid_sha256(sha256) {
                return Some((url.into(), sha256.into()));
            }
        }
    }

    let url = event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("url"))
        .and_then(|tag| tag.get(1));
    let sha256 = event
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("x"))
        .and_then(|tag| tag.get(1));
    match (url, sha256) {
        (Some(url), Some(sha256)) if valid_media_url(url) && valid_sha256(sha256) => {
            Some((url.clone(), sha256.clone()))
        }
        _ => None,
    }
}

fn valid_media_url(url: &str) -> bool {
    url.starts_with("https://")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

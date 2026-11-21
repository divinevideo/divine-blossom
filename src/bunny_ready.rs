//! Verified playback inventory. Only the finalizer writes a ready record.
use crate::bunny_publish::{invalid, reply, verified_bytes, with_gate};
use crate::error::{BlossomError, Result};
use crate::{metadata, storage};
use blossom_core::bunny_pilot::{
    digest, zone_hosts, Asset, DELIVERY_HOST, DELIVERY_PREFIX, HLS_PATHS,
};
use blossom_core::storage_origin::{ObjectRef, StorageProvider};
use fastly::http::{Method, StatusCode};
use fastly::kv_store::KVStoreError;
use fastly::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    path: String,
    source_sha256: String,
    delivery_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    version: u8,
    parent: String,
    assets: Vec<Pin>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Verified {
    asset: Pin,
    source: ObjectRef,
    destination_version: String,
    delivery_size: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    version: u8,
    parent: String,
    bucket: String,
    prefix: String,
    hosts: String,
    assets: Vec<Verified>,
}

fn complete<'a>(parent: &str, pins: impl Iterator<Item = &'a Pin>) -> bool {
    let mut suffixes = BTreeSet::new();
    for pin in pins {
        let Some(asset) = Asset::parse(&pin.path) else {
            return false;
        };
        if asset.hash() != parent
            || !digest(&pin.source_sha256)
            || !digest(&pin.delivery_sha256)
            || (asset.is_original() && pin.source_sha256 != parent)
            || (!asset.is_playlist() && pin.source_sha256 != pin.delivery_sha256)
            || !suffixes.insert(asset.suffix())
        {
            return false;
        }
    }
    !suffixes.is_empty()
        && suffixes.len() <= 8
        && (!suffixes.iter().any(|s| s.starts_with("hls/"))
            || HLS_PATHS.iter().all(|s| suffixes.contains(s)))
}

fn version_valid(provider: StorageProvider, value: &str) -> bool {
    match provider {
        StorageProvider::Gcs => crate::parent_gate::generation(value).is_some(),
        StorageProvider::B2 => {
            (1..=1024).contains(&value.len())
                && value != "null"
                && !value.contains("://")
                && value.bytes().all(|b| b.is_ascii_graphic())
        }
    }
}

fn key(parent: &str) -> String {
    format!("bunny-ready:v1:{parent}")
}

pub(crate) fn invalidate(parent: &str) -> Result<()> {
    match metadata::open_store()?.delete(&key(parent)) {
        Ok(()) | Err(KVStoreError::ItemNotFound) => Ok(()),
        Err(_) => Err(BlossomError::MetadataError(
            "Bunny readiness invalidation failed".into(),
        )),
    }
}

fn changed() -> BlossomError {
    BlossomError::Conflict("Bunny family changed or incomplete".into())
}

pub(crate) fn finalize(body: &[u8]) -> Result<Value> {
    let mut inventory: Inventory = serde_json::from_slice(body).map_err(|_| invalid())?;
    let parent = &inventory.parent;
    if inventory.version != 1 || !complete(parent, inventory.assets.iter()) {
        return Err(invalid());
    }
    // Segment sizes must be known before validating byte ranges in playlists.
    inventory
        .assets
        .sort_by_key(|pin| pin.path.ends_with(".m3u8"));
    with_gate(parent, |_, check_gate, _| {
        invalidate(parent)?;
        let hosts = storage::get_config("bunny_pilot_zone_hosts")?;
        if !storage::bunny_pilot_enrolled(parent)?
            || storage::origin_bunny_pilot_hosts()?.as_deref() != Some(&hosts)
        {
            return Err(changed());
        }
        let bucket = storage::get_config("b2_media_bucket")?;
        let mut assets = Vec::new();
        let mut sizes = BTreeMap::new();
        let mut original_size = None;
        for pin in inventory.assets {
            let asset = Asset::parse(&pin.path).ok_or_else(invalid)?;
            let source = storage::read_bunny_object(&asset, false)?.ok_or_else(changed)?;
            let copy = storage::read_bunny_object(&asset, true)?.ok_or_else(changed)?;
            let version = copy
                .identity
                .version
                .filter(|v| version_valid(StorageProvider::B2, v))
                .ok_or_else(changed)?;
            if !source
                .identity
                .version
                .as_ref()
                .is_some_and(|v| version_valid(source.identity.provider, v))
                || !verified_bytes(&source.bytes, &pin.source_sha256)
                || !verified_bytes(&copy.bytes, &pin.delivery_sha256)
            {
                return Err(changed());
            }
            if asset.is_playlist() {
                let size = match asset.child_names() {
                    [child] => *sizes
                        .get(&format!("/{parent}/hls/{child}"))
                        .ok_or_else(changed)?,
                    _ => 0,
                };
                let normalized = blossom_core::bunny_hls::normalize(&asset, &source.bytes, size)
                    .ok_or_else(changed)?;
                if normalized != copy.bytes {
                    return Err(changed());
                }
            }
            if asset.is_original() {
                original_size = Some(source.bytes.len() as u64);
            }
            sizes.insert(pin.path.clone(), copy.bytes.len());
            assets.push(Verified {
                asset: pin,
                source: source.identity,
                destination_version: version,
                delivery_size: copy.bytes.len(),
            });
        }
        check_gate()?;
        let policy = metadata::bunny_public_metadata(parent)?;
        if original_size.is_some_and(|n| policy.size != n || policy.mime_type != "video/mp4") {
            return Err(changed());
        }
        let ready = Ready {
            version: 1,
            parent: parent.to_owned(),
            bucket,
            hosts,
            prefix: DELIVERY_PREFIX.to_owned(),
            assets,
        };
        metadata::open_store()?
            .insert(
                &key(parent),
                serde_json::to_vec(&ready).map_err(|_| invalid())?,
            )
            .map_err(|_| BlossomError::MetadataError("Bunny readiness write failed".into()))?;
        Ok(json!({"result":"ready"}))
    })
}

fn cohort(
    parent: &str,
    percent: Option<&str>,
    countries: Option<&str>,
    country: Option<&str>,
) -> bool {
    let (Some(percent), Some(countries), Some(country)) = (percent, countries, country) else {
        return false;
    };
    let Ok(n) = percent.parse::<u8>() else {
        return false;
    };
    if n > 100 || n.to_string() != percent || !digest(parent) {
        return false;
    }
    let valid = |code: &str| code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase());
    valid(country)
        && countries.split(',').all(valid)
        && countries.split(',').any(|c| c == country)
        && u32::from_str_radix(&parent[..8], 16).is_ok_and(|bucket| bucket % 100 < n as u32)
}

fn read_paths(parent: &str) -> Result<Vec<(String, usize)>> {
    let read = crate::kv_origin::lookup(&key(parent))?
        .ok_or_else(|| BlossomError::MetadataError("Bunny readiness origin unavailable".into()))?;
    let Some(entry) = read else {
        return Ok(Vec::new());
    };
    // Eight assets with two bounded version IDs each fit comfortably in 32 KiB.
    if entry.body.len() > 32 * 1024 {
        return Ok(Vec::new());
    }
    let Ok(ready) = serde_json::from_slice::<Ready>(&entry.body) else {
        return Ok(Vec::new());
    };
    if ready.version != 1
        || ready.parent != parent
        || ready.prefix != DELIVERY_PREFIX
        || ready.bucket != storage::get_config("b2_media_bucket")?
        || zone_hosts(&ready.hosts).is_none()
        || ready.hosts != storage::get_config("bunny_pilot_zone_hosts")?
        || !complete(parent, ready.assets.iter().map(|v| &v.asset))
    {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for v in ready.assets {
        let asset = Asset::parse(&v.asset.path).ok_or_else(invalid)?;
        let (provider, bucket) = storage::bunny_source_location(&asset)?;
        if v.source.provider != provider
            || v.source.bucket != bucket
            || v.source.key != asset.source_key()
            || !v
                .source
                .version
                .as_ref()
                .is_some_and(|s| version_valid(provider, s))
            || !(1..=asset.max_size()).contains(&v.delivery_size)
            || !version_valid(StorageProvider::B2, &v.destination_version)
        {
            return Ok(Vec::new());
        }
        if asset.is_top_level() {
            paths.push((v.asset.path, v.delivery_size));
        }
    }
    if !crate::parent_gate::bunny_settled(parent)? {
        paths.clear();
    }
    Ok(paths)
}

fn selection(req: &Request, parent: &str, country: Option<&str>) -> Result<Value> {
    let selected = !req.contains_header("Authorization")
        && !req.contains_header("Cookie")
        && cohort(
            parent,
            storage::optional_config("bunny_playback_rollout_percent")?.as_deref(),
            storage::optional_config("bunny_playback_countries")?.as_deref(),
            country,
        );
    let paths = if selected {
        read_paths(parent)
    } else {
        Ok(Vec::new())
    };
    let policy = metadata::bunny_public_metadata(parent)?;
    let paths: Vec<String> = paths?
        .into_iter()
        .filter_map(|(path, size)| {
            let original = Asset::parse(&path)?.is_original();
            (!original || (policy.mime_type == "video/mp4" && policy.size == size as u64))
                .then_some(path)
        })
        .collect();
    Ok(json!({"version":1,"host":DELIVERY_HOST,"paths":paths}))
}

const CANONICAL: &str = "media.divine.video";

fn signed_country(req: &Request, now: u64) -> Option<&str> {
    use hmac::{Hmac, Mac};
    let proof = req.get_header_str("X-Divine-Bunny-Market")?;
    let (stamp, rest) = proof.split_once(':')?;
    let (country, signature) = rest.split_once(':')?;
    let timestamp = stamp.parse::<u64>().ok()?;
    if timestamp.to_string() != stamp
        || timestamp > now
        || now - timestamp > 30
        || country.len() != 2
        || !country.bytes().all(|b| b.is_ascii_uppercase())
    {
        return None;
    }
    let signature = signature.strip_prefix("0x")?;
    if !digest(signature) {
        return None;
    }
    let secret = storage::get_secret("bunny_playback_geo_key").ok()?;
    if secret.len() < 32 {
        return None;
    }
    let message = format!(
        "bunny-playback-v1|GET|{CANONICAL}|{}|{stamp}|{country}",
        req.get_path()
    );
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(message.as_bytes());
    mac.verify_slice(&hex::decode(signature).ok()?).ok()?;
    Some(country)
}

pub(crate) fn playback(req: Request, parent: &str) -> Response {
    let url = req.get_url();
    let authority = url.host_str().unwrap_or("");
    let forwarded_host = req.get_header_str("X-Original-Host");
    let direct = authority == CANONICAL && forwarded_host.is_none();
    // Before the operator binds the Compute authority, canonical traffic
    // forwarded by VCL still receives the disabled (empty) selection response.
    let chained = forwarded_host == Some(CANONICAL);
    let configured_hop = chained
        && (authority == CANONICAL
            || storage::get_config("bunny_playback_compute_host")
                .is_ok_and(|host| host == authority));
    let mut response = if !digest(parent)
        || !(direct || chained)
        || req.get_header_str("Host").is_some_and(|v| v != authority)
        || url.port().is_some()
        || url.query().is_some()
    {
        reply(StatusCode::NOT_FOUND, json!({"error":"Not found"}))
    } else if req.get_method() != Method::GET {
        reply(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error":"GET required"}),
        )
    } else {
        let country = if direct {
            req.get_client_ip_addr()
                .and_then(fastly::geo::geo_lookup)
                .map(|g| g.country_code().to_owned())
        } else if configured_hop {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| signed_country(&req, elapsed.as_secs()))
                .map(str::to_owned)
        } else {
            None
        };
        match selection(&req, parent, country.as_deref()) {
            Ok(body) => reply(StatusCode::OK, body),
            Err(error) => reply(error.status_code(), json!({"error":error.message()})),
        }
    };
    crate::add_cors_headers(&mut response);
    response
}

#[cfg(test)]
#[path = "bunny_ready_tests.rs"]
mod tests;

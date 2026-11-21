//! Verified playback inventory. Only the finalizer writes a ready record.
use crate::bunny_publish::{invalid, reply, with_gate};
use crate::error::{BlossomError, Result};
use crate::{metadata, storage};
use blossom_core::bunny_pilot::{digest, zone_hosts, Asset, DELIVERY_HOST, DELIVERY_PREFIX};
use blossom_core::bunny_worker::{complete, Inventory, Operation, Outcome, Verified};
use fastly::http::{Method, StatusCode};
use fastly::kv_store::KVStoreError;
use fastly::{Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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

fn key(parent: &str) -> String {
    format!("bunny-ready:v1:{parent}")
}

pub(crate) fn invalidate(parent: &str) -> Result<()> {
    let store = metadata::open_store()?;
    match metadata::retry_throttled_write(|| store.delete(&key(parent))) {
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
    let inventory: Inventory = serde_json::from_slice(body).map_err(|_| invalid())?;
    let parent = &inventory.parent;
    if inventory.version != 1 || !complete(parent, inventory.assets.iter()) {
        return Err(invalid());
    }
    with_gate(parent, |_, check_gate, may_release| {
        let verified = verify_family(&inventory, check_gate);
        let ready = match verified {
            Ok(ready) => ready,
            Err(error) => {
                *may_release = false;
                check_gate()?;
                invalidate(parent)?;
                *may_release = true;
                return Err(error);
            }
        };
        let store = metadata::open_store()?;
        let body = serde_json::to_vec(&ready).map_err(|_| invalid())?;
        // On an uncertain overwrite, keep exclusion until the operator verifies
        // which readiness is durable. Never expose an earlier inventory.
        *may_release = false;
        metadata::retry_throttled_write(|| store.insert(&key(parent), body.clone()))
            .map_err(|_| BlossomError::MetadataError("Bunny readiness write failed".into()))?;
        *may_release = true;
        Ok(json!({"result":"ready"}))
    })
}

fn verify_family(inventory: &Inventory, check_gate: &dyn Fn() -> Result<()>) -> Result<Ready> {
    let parent = &inventory.parent;
    metadata::bunny_public_metadata(parent)?;
    let hosts = storage::get_config("bunny_pilot_zone_hosts")?;
    if !storage::bunny_pilot_enrolled(parent)?
        || storage::origin_bunny_pilot_hosts()?.as_deref() != Some(&hosts)
    {
        return Err(changed());
    }
    let scope = storage::bunny_scope()?;
    let assets = match crate::bunny_publish::worker(
        &scope,
        Operation::Finalize {
            inventory: inventory.clone(),
        },
    )? {
        Outcome::Verified { assets } => assets,
        Outcome::SourceChanged | Outcome::SourceMissing | Outcome::DeliveryConflict => {
            return Err(changed())
        }
        _ => {
            return Err(BlossomError::StorageError(
                "Bunny verification unavailable".into(),
            ))
        }
    };
    if assets.len() != inventory.assets.len()
        || !complete(parent, assets.iter().map(|v| &v.asset))
        || !assets
            .iter()
            .all(|v| scope.matches(v) && inventory.assets.contains(&v.asset))
    {
        return Err(changed());
    }
    check_gate()?;
    let policy = metadata::bunny_public_metadata(parent)?;
    if assets.iter().any(|v| {
        Asset::parse(&v.asset.path).is_some_and(|a| a.is_original())
            && (policy.size != v.delivery_size as u64 || policy.mime_type != "video/mp4")
    }) {
        return Err(changed());
    }
    Ok(Ready {
        version: 1,
        parent: parent.clone(),
        bucket: scope.b2_bucket,
        hosts,
        prefix: DELIVERY_PREFIX.to_owned(),
        assets,
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
    let scope = storage::bunny_scope()?;
    let mut paths = Vec::new();
    for v in ready.assets {
        let asset = Asset::parse(&v.asset.path).ok_or_else(invalid)?;
        if !scope.matches(&v) {
            return Ok(Vec::new());
        }
        if asset.is_top_level() {
            paths.push((v.asset.path, v.delivery_size));
        }
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
    let before = if selected {
        crate::parent_gate::bunny_settled_generation(parent)?
    } else {
        None
    };
    let candidates = if before.is_some() {
        read_paths(parent)
    } else {
        Ok(Vec::new())
    };
    let policy = metadata::bunny_playback_policy(parent)?;
    let mut paths = Vec::new();
    if let (Some(policy), Some(before)) = (policy, before) {
        let candidates = candidates?;
        if !candidates.is_empty()
            && crate::parent_gate::bunny_settled_generation(parent)?.as_ref() == Some(&before)
        {
            paths.extend(candidates.into_iter().filter_map(|(path, size)| {
                let original = Asset::parse(&path)?.is_original();
                (!original || (policy.mime_type == "video/mp4" && policy.size == size as u64))
                    .then_some(path)
            }));
        }
    }
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

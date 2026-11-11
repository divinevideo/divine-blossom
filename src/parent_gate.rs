//! Shared no-TTL writer/erasure exclusion. Generations are equality fences.
use crate::error::{BlossomError, Result};
use fastly::http::{Method, StatusCode};
use fastly::kv_store::{InsertMode, KVStore, KVStoreError};
use fastly::{Request, Response};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Read;

const MAX_BODY: u64 = 8192;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Gate {
    Copying {
        attempt_id: String,
    },
    Erasing {},
    Released {
        version: u32,
        settled_attempt_id: String,
        released_from_generation: String,
    },
}

pub(crate) fn generation(value: &str) -> Option<u64> {
    let n = value.parse::<u64>().ok()?;
    (n > 0 && n.to_string() == value).then_some(n)
}

fn identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| (33..=126).contains(&b))
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn parse(body: &[u8]) -> Option<Gate> {
    if body.len() > MAX_BODY as usize {
        return None;
    }
    let gate: Gate = serde_json::from_slice(body).ok()?;
    let valid = match &gate {
        Gate::Copying { attempt_id } => identity(attempt_id),
        Gate::Erasing {} => true,
        Gate::Released {
            version,
            settled_attempt_id,
            released_from_generation,
        } => {
            *version == 1
                && identity(settled_attempt_id)
                && generation(released_from_generation).is_some()
        }
    };
    valid.then_some(gate)
}

#[derive(Serialize)]
struct Observed {
    gate: Gate,
    generation: String,
}

fn unavailable() -> BlossomError {
    BlossomError::MetadataError("Parent gate unavailable".into())
}
fn stale() -> BlossomError {
    BlossomError::StorageError("Parent gate changed or busy".into())
}
fn key(hash: &str) -> String {
    format!("b2-sync:v1:{hash}")
}

fn lookup(store: &KVStore, hash: &str) -> Result<Option<Observed>> {
    let mut entry = match store.lookup(&key(hash)) {
        Ok(entry) => entry,
        Err(KVStoreError::ItemNotFound) => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    let generation = entry.current_generation();
    if generation == 0 {
        return Err(unavailable());
    }
    let mut body = Vec::new();
    entry
        .take_body()
        .take(MAX_BODY + 1)
        .read_to_end(&mut body)
        .map_err(|_| unavailable())?;
    let gate = parse(&body).ok_or_else(unavailable)?;
    Ok(Some(Observed {
        gate,
        generation: generation.to_string(),
    }))
}

fn insert(store: &KVStore, hash: &str, gate: &Gate, expected: Option<u64>) -> Result<()> {
    let body = serde_json::to_string(gate).map_err(|_| unavailable())?;
    let builder = store.build_insert();
    let builder = match expected {
        Some(generation) => builder.if_generation_match(generation),
        None => builder.mode(InsertMode::Add),
    };
    builder.execute(&key(hash), body).map_err(|e| match e {
        KVStoreError::ItemPreconditionFailed => stale(),
        _ => unavailable(),
    })
}

/// Existing erasure callers must understand released before any emitter is enabled.
pub(crate) fn claim_erasure(store: &KVStore, hash: &str) -> Result<()> {
    if !hex(hash, 64) {
        return Err(unavailable());
    }
    match lookup(store, hash)? {
        None => insert(store, hash, &Gate::Erasing {}, None),
        Some(Observed {
            gate: Gate::Erasing {},
            ..
        }) => Ok(()),
        Some(Observed {
            gate: Gate::Released { .. },
            generation: g,
        }) => insert(store, hash, &Gate::Erasing {}, generation(&g)),
        Some(_) => Err(stale()),
    }
}

fn present(store: &KVStore, key: &str) -> Result<bool> {
    match store.lookup(key) {
        Ok(_) => Ok(true),
        Err(KVStoreError::ItemNotFound) => Ok(false),
        Err(_) => Err(unavailable()),
    }
}

/// Copy eligibility for an existing family; it does not grant viewer approval.
fn eligible(hash: &str) -> Result<()> {
    use crate::blossom::BlobStatus;
    let denied = || BlossomError::Forbidden("Parent policy denied".into());
    let meta = crate::metadata::get_blob_metadata_uncached(hash)?.ok_or_else(denied)?;
    if meta.sha256 != hash
        || !matches!(meta.status, BlobStatus::Active | BlobStatus::Pending)
        || !meta.mime_type.starts_with("video/")
        || meta.size == 0
        || !meta.quarantine_hold_ids.is_empty()
        || !hex(&meta.owner.to_lowercase(), 64)
        || crate::metadata::get_tombstone(hash)?.is_some()
    {
        return Err(denied());
    }
    let mut owners = crate::metadata::get_blob_refs(hash)?;
    if owners.len() > 1000 {
        return Err(denied());
    }
    owners.push(meta.owner);
    let store = crate::metadata::open_store()?;
    for owner in owners {
        if !hex(&owner.to_lowercase(), 64)
            || present(
                &store,
                &format!("vanish_in_progress:v1:{}", owner.to_lowercase()),
            )?
        {
            return Err(denied());
        }
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Expected {
    Missing {},
    Released {
        generation: String,
        settled_attempt_id: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    parent: String,
    attempt_id: String,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    expected: Option<Expected>,
    #[serde(default)]
    generation: Option<String>,
}

fn execute(store: &KVStore, op: &str, wire: &Wire) -> Result<serde_json::Value> {
    if wire.version != 1 || !hex(&wire.parent, 64) || !hex(&wire.attempt_id, 32) {
        return Err(BlossomError::BadRequest(
            "Invalid parent gate request".into(),
        ));
    }
    if wire.purpose.as_deref() == Some("original_write") {
        return Err(unavailable());
    }
    let observed = lookup(store, &wire.parent)?;
    match op {
        "inspect"
            if wire.expected.is_none() && wire.purpose.is_none() && wire.generation.is_none() =>
        {
            Ok(
                serde_json::json!({"version":1,"parent":wire.parent,"attempt_id":wire.attempt_id,"observed":observed}),
            )
        }
        "claim"
            if wire.purpose.as_deref() == Some("existing_family") && wire.generation.is_none() =>
        {
            // OriginalWrite intentionally has no admission hook or caller-selected bypass.
            eligible(&wire.parent)?;
            let expected = match (&wire.expected, &observed) {
                (Some(Expected::Missing {}), None) => None,
                (
                    Some(Expected::Released {
                        generation: g,
                        settled_attempt_id: a,
                    }),
                    Some(Observed {
                        gate:
                            Gate::Released {
                                settled_attempt_id, ..
                            },
                        generation: current,
                    }),
                ) if g == current && a == settled_attempt_id && a != &wire.attempt_id => {
                    Some(generation(g).ok_or_else(unavailable)?)
                }
                _ => return Err(stale()),
            };
            insert(
                store,
                &wire.parent,
                &Gate::Copying {
                    attempt_id: wire.attempt_id.clone(),
                },
                expected,
            )?;
            let current = lookup(store, &wire.parent)?.ok_or_else(unavailable)?;
            if current.gate
                != (Gate::Copying {
                    attempt_id: wire.attempt_id.clone(),
                })
            {
                return Err(stale());
            }
            // Repeat uncached policy after mutation; denial retains the owned gate.
            eligible(&wire.parent)?;
            Ok(
                serde_json::json!({"version":1,"parent":wire.parent,"attempt_id":wire.attempt_id,"observed":current}),
            )
        }
        "check" | "release" if wire.expected.is_none() && wire.purpose.is_none() => {
            let g = wire
                .generation
                .as_deref()
                .and_then(generation)
                .ok_or_else(stale)?;
            let current = observed.ok_or_else(stale)?;
            if current.generation != g.to_string()
                || current.gate
                    != (Gate::Copying {
                        attempt_id: wire.attempt_id.clone(),
                    })
            {
                return Err(stale());
            }
            if op == "check" {
                eligible(&wire.parent)?;
                return Ok(
                    serde_json::json!({"version":1,"parent":wire.parent,"attempt_id":wire.attempt_id,"observed":current}),
                );
            }
            // Only the PG authority holds this credential. It must settle/drain all
            // issued effects first; there is no worker-accessible release in PG.
            insert(
                store,
                &wire.parent,
                &Gate::Released {
                    version: 1,
                    settled_attempt_id: wire.attempt_id.clone(),
                    released_from_generation: g.to_string(),
                },
                Some(g),
            )?;
            Ok(
                serde_json::json!({"version":1,"parent":wire.parent,"attempt_id":wire.attempt_id,"released_from_generation":g.to_string()}),
            )
        }
        _ => Err(BlossomError::BadRequest(
            "Unavailable parent gate operation".into(),
        )),
    }
}

fn reply(status: StatusCode, body: serde_json::Value) -> Response {
    let mut response = Response::from_status(status);
    response.set_header("Content-Type", "application/json");
    crate::canary::no_store(&mut response);
    response.set_body(body.to_string());
    response
}

fn authenticated(req: &Request) -> Result<bool> {
    let store =
        fastly::secret_store::SecretStore::open("blossom_secrets").map_err(|_| unavailable())?;
    let secret = store
        .get("b2_storage_coordination_token")
        .ok_or_else(unavailable)?;
    let expected = secret.plaintext();
    if !(16..=1024).contains(&expected.len()) {
        return Err(unavailable());
    }
    let Some(provided) = req
        .get_header_str("Authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return Ok(false);
    };
    if provided.len() != expected.len() {
        return Ok(false);
    }
    let mut one = Hmac::<Sha256>::new_from_slice(&expected).map_err(|_| unavailable())?;
    let mut two = Hmac::<Sha256>::new_from_slice(provided.as_bytes()).map_err(|_| unavailable())?;
    one.update(b"divine-parent-gate-v1");
    two.update(b"divine-parent-gate-v1");
    Ok(one.verify_slice(&two.finalize().into_bytes()).is_ok())
}

pub(crate) fn handle(mut req: Request, op: &str) -> Response {
    let error = |status| {
        reply(
            status,
            serde_json::json!({"error":"parent gate unavailable"}),
        )
    };
    if !crate::storage::get_config("b2_parent_gate_enabled").is_ok_and(|v| v == "true") {
        return error(StatusCode::SERVICE_UNAVAILABLE);
    }
    match authenticated(&req) {
        Ok(true) => {}
        Ok(false) => return error(StatusCode::UNAUTHORIZED),
        Err(_) => return error(StatusCode::SERVICE_UNAVAILABLE),
    }
    if req.get_method() != Method::POST {
        return error(StatusCode::METHOD_NOT_ALLOWED);
    }
    let mut body = Vec::new();
    if req
        .take_body()
        .take(MAX_BODY + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return error(StatusCode::BAD_REQUEST);
    }
    if body.len() > MAX_BODY as usize {
        return error(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let Ok(wire) = serde_json::from_slice::<Wire>(&body) else {
        return error(StatusCode::BAD_REQUEST);
    };
    let result = crate::metadata::open_store().and_then(|store| execute(&store, op, &wire));
    match result {
        Ok(value) => reply(StatusCode::OK, value),
        Err(BlossomError::Forbidden(_)) | Err(BlossomError::NotFound(_)) => {
            error(StatusCode::FORBIDDEN)
        }
        Err(BlossomError::StorageError(_)) => error(StatusCode::CONFLICT),
        Err(BlossomError::BadRequest(_)) => error(StatusCode::BAD_REQUEST),
        Err(_) => error(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Trusted archive admission shares the same no-TTL exclusion as erasure.
/// Policy and provenance are checked by archive_import, never by caller-selected flags.
pub(crate) fn archive_claim(hash: &str, attempt: &str) -> Result<String> {
    let store = crate::metadata::open_store()?;
    let expected = match lookup(&store, hash)? {
        Some(Observed {gate: Gate::Copying {attempt_id}, generation}) if attempt_id == attempt => return Ok(generation),
        Some(Observed {gate: Gate::Released {..}, generation: g}) => Some(generation(&g).ok_or_else(unavailable)?),
        None => None,
        _ => return Err(stale()),
    };
    insert(&store, hash, &Gate::Copying {attempt_id: attempt.to_owned()}, expected)?;
    let current = lookup(&store, hash)?.ok_or_else(unavailable)?;
    archive_check(hash, attempt, &current.generation)?;
    Ok(current.generation)
}
pub(crate) fn archive_check(hash: &str, attempt: &str, expected: &str) -> Result<()> {
    match lookup(&crate::metadata::open_store()?, hash)? {
        Some(Observed {gate: Gate::Copying {attempt_id}, generation}) if attempt_id == attempt && generation == expected => Ok(()),
        _ => Err(stale()),
    }
}
pub(crate) fn archive_release(hash: &str, attempt: &str, expected: &str) -> Result<()> {
    let store = crate::metadata::open_store()?;
    if let Some(Observed {gate: Gate::Released {settled_attempt_id, released_from_generation, ..}, ..}) = lookup(&store,hash)? {
        if settled_attempt_id == attempt && released_from_generation == expected {return Ok(());}
    }
    archive_check(hash,attempt,expected)?;
    insert(&store,hash,&Gate::Released {version:1,settled_attempt_id:attempt.to_owned(),released_from_generation:expected.to_owned()},generation(expected))
}

pub(crate) fn archive_owned(hash:&str,attempt:&str)->Result<bool> {
    Ok(matches!(lookup(&crate::metadata::open_store()?,hash)?,Some(Observed{gate:Gate::Copying{attempt_id},..}) if attempt_id==attempt))
}

/// The PG authority first retires the attempt so a late admission cannot authorize bytes.
pub(crate) fn archive_settle_current(hash:&str,attempt:&str)->Result<()> {
    if let Some(Observed{gate:Gate::Copying{attempt_id},generation})=lookup(&crate::metadata::open_store()?,hash)? {
        if attempt_id==attempt {return archive_release(hash,attempt,&generation);}
    }
    Ok(())
}

/// A successful generic settlement is not evidence that this copy released its gate.
pub(crate) fn archive_copy_settlement_precheck(hash: &str, attempt: &str, expected: &str) -> Result<()> {
    generation(expected).ok_or_else(stale)?;
    match lookup(&crate::metadata::open_store()?, hash)? {
        Some(Observed {gate: Gate::Copying {attempt_id}, generation}) if attempt_id == attempt && generation == expected => Ok(()),
        Some(Observed {gate: Gate::Released {settled_attempt_id, released_from_generation, ..}, ..}) if settled_attempt_id == attempt && released_from_generation == expected => Ok(()),
        Some(Observed {gate: Gate::Erasing {}, ..}) => Err(BlossomError::Forbidden("Parent is erasing".into())),
        _ => Err(stale()),
    }
}

pub(crate) fn archive_copy_release_proof(hash: &str, attempt: &str, expected: &str) -> Result<serde_json::Value> {
    generation(expected).ok_or_else(stale)?;
    match lookup(&crate::metadata::open_store()?, hash)? {
        Some(Observed { gate: Gate::Released { version: 1, settled_attempt_id, released_from_generation }, generation })
            if settled_attempt_id == attempt && released_from_generation == expected =>
                Ok(serde_json::json!({"version":1,"sha256":hash,"attempt":attempt,
                    "state":"released","admission_generation":expected,
                    "released_from_generation":released_from_generation,"parent_generation":generation})),
        Some(Observed {gate: Gate::Erasing {}, ..}) => Err(BlossomError::Forbidden("Parent is erasing".into())),
        _ => Err(stale()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    fn wire(parent: &str, attempt: &str, fields: serde_json::Value) -> Wire {
        let mut value = serde_json::json!({"version":1,"parent":parent,"attempt_id":attempt});
        value
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        serde_json::from_value(value).unwrap()
    }
    fn seed(store: &KVStore, parent: &str) {
        store.insert(&format!("blob:{parent}"),serde_json::json!({"sha256":parent,"size":9,"type":"video/mp4","uploaded":"2026-01-01T00:00:00Z","owner":"e".repeat(64),"status":"pending"}).to_string()).unwrap();
    }
    #[test]
    fn gate_records_are_strict_and_generations_are_not_numbers_in_json() {
        for body in [
            "null",
            "{}",
            r#"{"state":"erasing","attempt_id":"x"}"#,
            r#"{"state":"released","version":2,"settled_attempt_id":"x","released_from_generation":"1"}"#,
            r#"{"state":"released","version":1,"settled_attempt_id":"x","released_from_generation":"01"}"#,
            r#"{"state":"copying","attempt_id":""}"#,
        ] {
            assert!(parse(body.as_bytes()).is_none(), "{body}");
        }
        assert!(parse(br#"{"state":"released","version":1,"settled_attempt_id":"legacy-attempt","released_from_generation":"18446744073709551615"}"#).is_some());
        assert!(generation("18446744073709551616").is_none());
        for expected in [
            serde_json::json!({"state":"missing","unexpected":true}),
            serde_json::json!({"state":"released","generation":"1","settled_attempt_id":A,"unexpected":true}),
        ] {
            assert!(serde_json::from_value::<Wire>(serde_json::json!({"version":1,"parent":"a".repeat(64),"attempt_id":A,"purpose":"existing_family","expected":expected})).is_err());
        }
    }
    #[test]
    #[ignore = "requires local KV fixture; scripts/run-parent-gate-tests.py"]
    fn parent_gate_cas_fences_reacquisition_release_and_erase() {
        let store = crate::metadata::open_store().unwrap();
        let parent = "c1".repeat(32);
        seed(&store, &parent);
        let first = wire(
            &parent,
            A,
            serde_json::json!({"purpose":"existing_family","expected":{"state":"missing"}}),
        );
        execute(&store, "claim", &first).unwrap();
        let copying = lookup(&store, &parent).unwrap().unwrap();
        assert!(execute(
            &store,
            "claim",
            &wire(
                &parent,
                B,
                serde_json::json!({"purpose":"existing_family","expected":{"state":"missing"}})
            )
        )
        .is_err());
        let release = wire(
            &parent,
            A,
            serde_json::json!({"generation":copying.generation}),
        );
        execute(&store, "check", &release).unwrap();
        execute(&store, "release", &release).unwrap();
        let released = lookup(&store, &parent).unwrap().unwrap();
        assert!(
            matches!(&released.gate,Gate::Released {settled_attempt_id,..} if settled_attempt_id==A)
        );
        assert!(!crate::canary::copy_in_progress(&parent).unwrap());
        let expected = serde_json::json!({"purpose":"existing_family","expected":{"state":"released","generation":released.generation,"settled_attempt_id":A}});
        assert!(execute(&store, "claim", &wire(&parent, A, expected.clone())).is_err());
        execute(&store, "claim", &wire(&parent, B, expected)).unwrap();
        assert!(execute(&store, "release", &release).is_err());
        assert!(insert(
            &store,
            &parent,
            &Gate::Erasing {},
            generation(&released.generation)
        )
        .is_err());
        let second = lookup(&store, &parent).unwrap().unwrap();
        execute(
            &store,
            "release",
            &wire(
                &parent,
                B,
                serde_json::json!({"generation":second.generation}),
            ),
        )
        .unwrap();
        let released = lookup(&store, &parent).unwrap().unwrap();
        claim_erasure(&store, &parent).unwrap();
        assert!(insert(
            &store,
            &parent,
            &Gate::Copying {
                attempt_id: A.into()
            },
            generation(&released.generation)
        )
        .is_err());
        assert_eq!(
            lookup(&store, &parent).unwrap().unwrap().gate,
            Gate::Erasing {}
        );
        assert!(execute(&store, "release", &release).is_err());
    }
    fn request(op: &str, token: &str, value: &[u8]) -> Request {
        let mut req = Request::post(format!(
            "https://synthetic.invalid/admin/api/b2-parent-gate/{op}"
        ));
        req.set_header("Authorization", format!("Bearer {token}"));
        req.set_body(value);
        req
    }
    #[test]
    #[ignore = "requires local KV/secret/config fixture; scripts/run-parent-gate-tests.py"]
    fn parent_gate_actual_routes_authenticate_before_body_and_fail_closed() {
        let store = crate::metadata::open_store().unwrap();
        let parent = "c2".repeat(32);
        seed(&store, &parent);
        let value = serde_json::json!({"version":1,"parent":parent,"attempt_id":A,"purpose":"existing_family","expected":{"state":"missing"}}).to_string();
        for token in [
            "fixture-admin-token",
            "fixture-worker-token",
            "fixture-drain-token",
        ] {
            let response =
                crate::route_request(request("claim", token, &vec![b'x'; 8193])).unwrap();
            assert_eq!(response.get_status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.get_header_str("Cache-Control"),
                Some("private, no-store")
            );
            assert!(lookup(&store, &parent).unwrap().is_none());
        }
        assert_eq!(
            handle(
                request("claim", "fixture-coordination-token", &vec![b'x'; 8193]),
                "claim"
            )
            .get_status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let original = value.replace("existing_family", "original_write");
        assert_eq!(
            handle(
                request("claim", "fixture-coordination-token", original.as_bytes()),
                "claim"
            )
            .get_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let response = crate::route_request(request(
            "claim",
            "fixture-coordination-token",
            value.as_bytes(),
        ))
        .unwrap();
        assert_eq!(response.get_status(), StatusCode::OK);
        store
            .insert(&format!("vanish_in_progress:v1:{}", "e".repeat(64)), "null")
            .unwrap();
        let current = lookup(&store, &parent).unwrap().unwrap();
        let check=serde_json::json!({"version":1,"parent":parent,"attempt_id":A,"generation":current.generation}).to_string();
        assert_eq!(
            handle(
                request("check", "fixture-coordination-token", check.as_bytes()),
                "check"
            )
            .get_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            lookup(&store, &parent).unwrap().unwrap().gate,
            Gate::Copying {
                attempt_id: A.into()
            }
        );
    }
    #[test]
    #[ignore = "requires disabled local config fixture; scripts/run-parent-gate-tests.py"]
    fn parent_gate_disabled_or_missing_secret_never_mutates() {
        let body=serde_json::json!({"version":1,"parent":"c3".repeat(32),"attempt_id":A,"purpose":"existing_family","expected":{"state":"missing"}}).to_string();
        assert_eq!(
            handle(
                request("claim", "fixture-coordination-token", body.as_bytes()),
                "claim"
            )
            .get_status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let store = crate::metadata::open_store().unwrap();
        assert!(lookup(&store, &"c3".repeat(32)).unwrap().is_none());
    }
}

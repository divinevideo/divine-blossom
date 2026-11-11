//! Private, default-off archive control plane. No media bytes or provider probes.
use crate::blossom::{ArchiveStorage, BlobMetadata, BlobStatus};
use crate::error::{BlossomError, Result};
use crate::archive_diagnostics::{self, observe_kv, with_stage, KvOperation, Stage};
use crate::{metadata, parent_gate};
use blossom_core::conditional_update::ConditionalJsonMutation as Mutation;
use fastly::http::{Method, StatusCode};
use fastly::kv_store::KVStoreError;
use fastly::{Request, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read};

const MAX_BODY: u64 = 65536;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Item {
    sha256: String,
    owner: String,
    attempt: String,
    source: String,
    provenance: String,
    size: u64,
    content_type: String,
    #[serde(default)]
    generation: Option<String>,
    #[serde(default)]
    file_id: Option<String>,
    #[serde(default)]
    bucket: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    version: u32,
    items: Vec<Item>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct Registration {
    version: u32,
    id: String,
    sha256: String,
    owner: String,
    size: u64,
    created: bool,
    content_type: String,
    file_id: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Record {
    #[serde(default)]
    settled: Vec<String>,
    #[serde(default)]
    created: bool,
    admission: Option<Item>,
    #[serde(default)]
    receipts: BTreeMap<String, Registration>,
    #[serde(default)]
    provenance: BTreeMap<String, String>,
}
fn unavailable() -> BlossomError {
    BlossomError::MetadataError("Archive import unavailable".into())
}
fn invalid() -> BlossomError {
    BlossomError::BadRequest("Invalid archive import".into())
}
fn denied() -> BlossomError {
    BlossomError::Forbidden("Archive policy denied".into())
}
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn key(hash: &str) -> String {
    format!("archive:v1:{hash}")
}
fn read(hash: &str) -> Result<Record> {
    match observe_kv(KvOperation::Lookup, metadata::open_store()?.lookup(&key(hash))) {
        Ok(mut r) => serde_json::from_str(&r.take_body().into_string()).map_err(|_| unavailable()),
        Err(KVStoreError::ItemNotFound) => Ok(Record::default()),
        Err(_) => Err(unavailable()),
    }
}
pub(crate) fn erase_record(hash: &str) -> Result<()> {
    // Clear identity/provenance while retaining a generation fence against delayed
    // add-only admission requests. Physical erasure permanently closes the parent gate.
    metadata::update_json_conditionally(
        &key(hash),
        5,
        "clear archive record",
        |_: Option<Record>| {
            Ok(Mutation::Write {
                value: Record::default(),
                result: (),
                time_to_live: None,
            })
        },
    )
}
fn validate(i: &Item) -> Result<()> {
    if !hex(&i.sha256, 64)
        || !hex(&i.owner, 64)
        || !hex(&i.attempt, 32)
        || i.size == 0
        || i.size > 5_000_000_000
        || i.source.is_empty()
        || i.source.len() > 2048
        || i.provenance.is_empty()
        || i.provenance.len() > 1024
        || !i.content_type.starts_with("video/")
        || i.content_type.len() > 100
    {
        return Err(invalid());
    }
    Ok(())
}
fn removed_owner_key(hash: &str, owner: &str) -> String {
    format!(
        "archive-owner-removed:v1:{}",
        hex::encode(Sha256::digest(format!("{hash}:{owner}")))
    )
}
pub(crate) fn unlink_owner(hash: &str, owner: &str) -> Result<()> {
    let store = metadata::open_store()?;
    // A non-identifying permanent fence also blocks delayed registrations after vanish clears.
    store
        .insert(&removed_owner_key(hash, owner), "true")
        .map_err(|_| unavailable())?;
    metadata::update_json_conditionally(&key(hash), 5, "archive owner removal", |current| {
        let mut record: Record = current.unwrap_or_default();
        record.receipts.remove(owner);
        record.provenance.remove(owner);
        if record.admission.as_ref().is_some_and(|a| a.owner == owner) {
            record.admission = None;
        }
        Ok(Mutation::Write {
            value: record,
            result: (),
            time_to_live: None,
        })
    })
}
fn removed_account_key(owner: &str) -> String {
    format!(
        "archive-account-removed:v1:{}",
        hex::encode(Sha256::digest(owner.to_lowercase()))
    )
}

/// Retire archive authority before the eraser enumerates the creator's list.
/// The same-key generation advance rejects additions prepared before this fence.
pub(crate) fn fence_account(owner: &str) -> Result<()> {
    metadata::open_store()?
        .insert(&removed_account_key(owner), "true")
        .map_err(|_| unavailable())?;
    metadata::update_json_conditionally(
        &format!("list:{}", owner.to_lowercase()),
        5,
        "archive account fence",
        |current: Option<Vec<String>>| {
            Ok(Mutation::Write {
                value: current.unwrap_or_default(),
                result: (),
                time_to_live: None,
            })
        },
    )
}

/// Called inside each ownership CAS mutation, after its generation was observed.
pub(crate) fn owner_allowed(hash: &str, owner: &str) -> Result<()> {
    let store = metadata::open_store()?;
    for key in [
        removed_owner_key(hash, owner),
        removed_account_key(owner),
        format!("vanish_in_progress:v1:{owner}"),
    ] {
        match observe_kv(KvOperation::Lookup, store.lookup(&key)) {
            Ok(_) => return Err(denied()),
            Err(KVStoreError::ItemNotFound) => {}
            Err(_) => return Err(unavailable()),
        }
    }
    Ok(())
}
fn policy(i: &Item) -> Result<()> {
    owner_allowed(&i.sha256, &i.owner)?;
    if metadata::get_tombstone(&i.sha256)?.is_some()
        || !metadata::get_quarantine_holds(&i.sha256)?
            .active_ids()
            .is_empty()
    {
        return Err(denied());
    }
    if let Some(meta) = metadata::get_blob_metadata_uncached(&i.sha256)? {
        if !matches!(meta.status, BlobStatus::Active | BlobStatus::Pending)
            || meta.size != i.size
            || meta.mime_type != i.content_type
        {
            return Err(denied());
        }
    }
    Ok(())
}
fn admit(i: &Item) -> Result<serde_json::Value> {
    admit_for(i, false)
}
fn admit_for(i: &Item, copy: bool) -> Result<serde_json::Value> {
    with_stage(Stage::Policy, || policy(i))?;
    let record = with_stage(Stage::ArchiveRead, || read(&i.sha256))?;
    if let Some(receipt) = record.receipts.get(&i.owner).filter(|_| !copy) {
        if let Some(a) = record
            .admission
            .as_ref()
            .filter(|a| a.owner == i.owner && a.attempt == i.attempt)
        {
            with_stage(Stage::ParentRelease, || parent_gate::archive_release(
                &i.sha256,
                &a.attempt,
                a.generation.as_deref().ok_or_else(invalid)?,
            ))?;
        }
        return Ok(serde_json::json!({"receipt":receipt}));
    }
    if record.settled.contains(&i.attempt) {
        return Err(denied());
    }
    // Register ownership before bytes are admitted so vanish can discover the in-flight hash.
    with_stage(Stage::OwnerList, || metadata::add_archive_user_hashes(&i.owner, std::slice::from_ref(&i.sha256)))?;
    let generation = with_stage(Stage::ParentClaim, || parent_gate::archive_claim(&i.sha256, &i.attempt))?;
    if with_stage(Stage::ArchiveRead, || read(&i.sha256))?.settled.contains(&i.attempt) {
        parent_gate::archive_settle_current(&i.sha256, &i.attempt)?;
        return Err(denied());
    }
    with_stage(Stage::Policy, || policy(i))?;
    let created = with_stage(Stage::BlobRead, || metadata::get_blob_metadata_uncached(&i.sha256))?.is_none();
    let mut admitted = i.clone();
    admitted.generation = Some(generation.clone());
    with_stage(Stage::ArchiveAdmissionCas, || metadata::update_json_conditionally(&key(&i.sha256), 5, "archive admission", |current| {
        owner_allowed(&i.sha256, &i.owner).map_err(|e| e.to_string())?;
        parent_gate::archive_check(&i.sha256, &i.attempt, &generation)
            .map_err(|e| e.to_string())?;
        let mut record: Record = current.unwrap_or_default();
        if record.admission.as_ref() == Some(&admitted) {
            return Ok(Mutation::Complete(()));
        }
        if record.settled.contains(&i.attempt) {
            return Err("Archive attempt settled".into());
        }
        if record
            .admission
            .as_ref()
            .is_some_and(|a| a.attempt == admitted.attempt && a.generation.is_some())
        {
            return Err("Admission identity changed".into());
        }
        record.created = record.created || created;
        record.admission = Some(admitted.clone());
        Ok(Mutation::Write {
            value: record,
            result: (),
            time_to_live: None,
        })
    }))?;
    let storage = with_stage(Stage::BlobRead, || metadata::get_blob_metadata_uncached(&i.sha256))?.and_then(|m| m.archive_storage);
    Ok(serde_json::json!({"generation":generation,"storage":storage}))
}
fn register(i: &Item) -> Result<serde_json::Value> {
    policy(i)?;
    let record = read(&i.sha256)?;
    if let Some(receipt) = record.receipts.get(&i.owner) {
        if i.file_id.as_deref() != Some(&receipt.file_id) {
            return Err(invalid());
        }
        if let Some(a) = record.admission.as_ref().filter(|a| a.attempt == i.attempt) {
            parent_gate::archive_release(
                &i.sha256,
                &i.attempt,
                a.generation.as_deref().ok_or_else(invalid)?,
            )?;
        }
        return Ok(serde_json::json!({"receipt":receipt}));
    }
    let a = record.admission.ok_or_else(invalid)?;
    let mut original = i.clone();
    original.file_id = None;
    original.bucket = None;
    if a != original {
        return Err(invalid());
    }
    let generation = i.generation.as_deref().ok_or_else(invalid)?;
    parent_gate::archive_check(&i.sha256, &i.attempt, generation)?;
    let file_id = i
        .file_id
        .as_ref()
        .filter(|s| !s.is_empty() && s.len() <= 1024)
        .ok_or_else(invalid)?;
    let bucket = i.bucket.as_ref().ok_or_else(invalid)?;
    if bucket != &crate::storage::get_config("b2_media_bucket")? {
        return Err(invalid());
    }
    let storage = ArchiveStorage {
        bucket: bucket.clone(),
        file_id: file_id.clone(),
    };
    let new_metadata:BlobMetadata=serde_json::from_value(serde_json::json!({
        "sha256":i.sha256,"size":i.size,"type":i.content_type,"uploaded":crate::current_timestamp(),
        "owner":i.owner,"status":"pending","transcode_status":"pending","transcript_status":"pending",
        "archive_storage":storage,
    })).map_err(|_|invalid())?;
    metadata::update_json_conditionally(
        &format!("blob:{}", i.sha256),
        5,
        "archive metadata",
        |current: Option<Option<BlobMetadata>>| {
            owner_allowed(&i.sha256, &i.owner).map_err(|e| e.to_string())?;
            parent_gate::archive_check(&i.sha256, &i.attempt, generation)
                .map_err(|e| e.to_string())?;
            let current = current.flatten();
            let is_new = current.is_none();
            let mut meta: BlobMetadata = current.unwrap_or_else(|| new_metadata.clone());
            if !matches!(meta.status, BlobStatus::Active | BlobStatus::Pending)
                || meta.size != i.size
                || meta.mime_type != i.content_type
            {
                return Err("Archive metadata conflict".into());
            }
            if !is_new && meta.archive_storage.is_some() {
                return Ok(Mutation::Complete(()));
            }
            meta.archive_storage = Some(storage.clone());
            Ok(Mutation::Write {
                value: Some(meta),
                result: (),
                time_to_live: None,
            })
        },
    )?;
    metadata::add_archive_user_hashes(&i.owner, std::slice::from_ref(&i.sha256))?;
    metadata::add_archive_blob_ref(&i.sha256, &i.owner)?;
    policy(i)?;
    let receipt = Registration {
        version: 1,
        created: read(&i.sha256)?.created,
        id: hex::encode(Sha256::digest(format!(
            "archive-registration-v1:{}:{}",
            i.sha256, i.owner
        ))),
        sha256: i.sha256.clone(),
        owner: i.owner.clone(),
        size: i.size,
        content_type: i.content_type.clone(),
        file_id: file_id.clone(),
    };
    metadata::update_json_conditionally(&key(&i.sha256), 5, "archive receipt", |current| {
        policy(i).map_err(|_| "Archive policy denied".to_string())?;
        let mut record: Record = current.ok_or_else(|| "Missing admission".to_string())?;
        if record.receipts.get(&i.owner) == Some(&receipt) {
            return Ok(Mutation::Complete(()));
        }
        record.receipts.insert(i.owner.clone(), receipt.clone());
        record
            .provenance
            .insert(i.owner.clone(), i.provenance.clone());
        Ok(Mutation::Write {
            value: record,
            result: (),
            time_to_live: None,
        })
    })?;
    metadata::invalidate_metadata_cache(&i.sha256);
    parent_gate::archive_release(&i.sha256, &i.attempt, generation)?;
    Ok(serde_json::json!({"receipt":receipt}))
}
fn process(i: &Item, phase: &str) -> Result<serde_json::Value> {
    policy(i)?;
    if !read(&i.sha256)?.receipts.contains_key(&i.owner) {
        return Err(denied());
    }
    match phase {
        "thumbnail" => {
            let response = crate::generate_thumbnail_on_demand(&i.sha256)?;
            if response.get_status() != StatusCode::OK {
                return Err(unavailable());
            }
        }
        "transcode" | "transcript" => {
            let path = if phase == "transcode" {
                "transcode"
            } else {
                "transcribe"
            };
            let host = crate::CLOUD_RUN_TRANSCODER_HOST;
            let mut req = Request::post(format!("https://{host}/{path}"));
            req.set_header("Host", host);
            req.set_header("Content-Type", "application/json");
            req.set_body(serde_json::json!({"hash":i.sha256,"owner":i.owner}).to_string());
            let response = req
                .send(crate::TRANSCODER_BACKEND)
                .map_err(|_| unavailable())?;
            if !response.get_status().is_success() {
                return Err(unavailable());
            }
        }
        "moderation" => {
            let secret = fastly::secret_store::SecretStore::open("blossom_secrets")
                .map_err(|_| unavailable())?
                .get("moderation_api_token")
                .ok_or_else(unavailable)?;
            let token =
                String::from_utf8(secret.plaintext().to_vec()).map_err(|_| unavailable())?;
            let mut req = Request::post("https://moderation-api.divine.video/api/v1/scan");
            req.set_header("Host", "moderation-api.divine.video");
            req.set_header("Content-Type", "application/json");
            req.set_header("Authorization", format!("Bearer {}", token.trim()));
            req.set_body(
                serde_json::json!({"sha256":i.sha256,"pubkey":i.owner,"source":"blossom"})
                    .to_string(),
            );
            let response = req
                .send(crate::MODERATION_API_BACKEND)
                .map_err(|_| unavailable())?;
            if !response.get_status().is_success() {
                return Err(unavailable());
            }
        }
        "index" => {
            metadata::add_to_recent_index(&i.sha256)?;
            metadata::add_to_user_index(&i.owner)?;
        }
        _ => return Err(invalid()),
    }
    Ok(serde_json::json!({"accepted":true}))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Aggregate {
    version: u32,
    previous: u64,
    next: u64,
    count: u64,
    bytes: u64,
    mime_counts: BTreeMap<String, u64>,
}
fn aggregate(a: Aggregate) -> Result<serde_json::Value> {
    if a.version != 1
        || a.next <= a.previous
        || a.count > 1000
        || a.bytes > 5_000_000_000_000
        || a.mime_counts.values().sum::<u64>() != a.count
    {
        return Err(invalid());
    }
    metadata::update_json_conditionally("stats:global", 5, "archive statistics", |current| {
        let mut stats: crate::blossom::GlobalStats = current.unwrap_or_default();
        if stats.archive_import_cursor >= a.next {
            return Ok(Mutation::Complete(()));
        }
        if stats.archive_import_cursor != a.previous {
            return Err("Archive aggregate cursor conflict".into());
        }
        stats.total_blobs += a.count;
        stats.total_size_bytes += a.bytes;
        *stats.status_counts.entry("pending".into()).or_default() += a.count;
        *stats.transcode_counts.entry("pending".into()).or_default() += a.count;
        for (mime, count) in &a.mime_counts {
            *stats.mime_type_counts.entry(mime.clone()).or_default() += count;
        }
        stats.archive_import_cursor = a.next;
        Ok(Mutation::Write {
            value: stats,
            result: (),
            time_to_live: None,
        })
    })?;
    Ok(serde_json::json!({"version":1,"checkpoint":a.next}))
}
fn reply(status: StatusCode, value: serde_json::Value) -> Response {
    let mut r = Response::from_status(status);
    r.set_header("Content-Type", "application/json");
    crate::canary::no_store(&mut r);
    r.set_body(value.to_string());
    r
}
pub(crate) fn handle(mut req: Request, op: &str) -> Response {
    let error = |s| reply(s, serde_json::json!({"error":"archive import unavailable"}));
    let Some(token) = crate::admin::extract_bearer_token(&req) else {
        return error(StatusCode::UNAUTHORIZED);
    };
    if crate::admin::validate_bearer_token_against_secret_keys(&token, &["archive_import_token"])
        .is_err()
    {
        return error(StatusCode::UNAUTHORIZED);
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
        || body.len() > MAX_BODY as usize
    {
        return error(StatusCode::BAD_REQUEST);
    }
    if op == "aggregate" {
        return match serde_json::from_slice::<Aggregate>(&body)
            .map_err(|_| invalid())
            .and_then(aggregate)
        {
            Ok(value) => reply(StatusCode::OK, value),
            Err(_) => error(StatusCode::SERVICE_UNAVAILABLE),
        };
    }
    let Ok(batch) = serde_json::from_slice::<Batch>(&body) else {
        return error(StatusCode::BAD_REQUEST);
    };
    if batch.version != 1 || batch.items.is_empty() || batch.items.len() > 16 {
        return error(StatusCode::BAD_REQUEST);
    }
    if op == "admit"
        && crate::storage::get_config("archive_import_enabled").is_ok_and(|v| v == "true")
    {
        let mut owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for i in &batch.items {
            if validate(i).and_then(|_| policy(i)).is_ok() {
                owners
                    .entry(i.owner.clone())
                    .or_default()
                    .push(i.sha256.clone());
            }
        }
        for (owner, hashes) in owners {
            let _ = metadata::add_archive_user_hashes(&owner, &hashes);
        }
    }
    let items:Vec<_>=batch.items.iter().map(|i| {
        let (result,diagnostic)=archive_diagnostics::item(|| validate(i).and_then(|_|{
            if matches!(op,"admit"|"admit-copy") && !crate::storage::get_config("archive_import_enabled").is_ok_and(|v|v=="true") {
                let existing_receipt=op=="admit" && read(&i.sha256)?.receipts.contains_key(&i.owner);
                if !existing_receipt && !parent_gate::archive_owned(&i.sha256,&i.attempt)? {
                    return with_stage(Stage::AdmissionPaused, || Err(BlossomError::StorageError("Archive admissions paused".into())));
                }
            }
            match op {
            "admit"=>admit(i),"admit-copy"=>admit_for(i,true),"register"=>register(i),
            "check"=>{policy(i)?;parent_gate::archive_check(&i.sha256,&i.attempt,i.generation.as_deref().ok_or_else(invalid)?)?;Ok(serde_json::json!({"checked":true}))},
            "settle"=>{
                metadata::update_json_conditionally(&key(&i.sha256),5,"archive attempt settlement",|current| {
                    let mut record:Record=current.unwrap_or_default();
                    if record.settled.contains(&i.attempt){return Ok(Mutation::Complete(()));}
                    record.settled.push(i.attempt.clone());
                    if record.admission.as_ref().is_some_and(|a|a.attempt==i.attempt){record.admission=None;}
                    Ok(Mutation::Write{value:record,result:(),time_to_live:None})
                })?;
                parent_gate::archive_settle_current(&i.sha256,&i.attempt)?;
                Ok(serde_json::json!({"settled":true}))
            },
            operation if operation.starts_with("process-") => process(i,operation.trim_start_matches("process-")),
            "reconcile"=>{policy(i)?;let r=read(&i.sha256)?;Ok(serde_json::json!({"receipt":r.receipts.get(&i.owner),"admission":r.admission}))},
            _=>Err(invalid()),
        }}));
        match result {Ok(value)=>serde_json::json!({"sha256":i.sha256,"owner":i.owner,"ok":true,"result":value}),Err(e)=>{
            let code=match e {BlossomError::Forbidden(_)=>"policy_denied",BlossomError::BadRequest(_)=>"invalid",_=>"retry"};
            let mut value=serde_json::json!({"sha256":i.sha256,"owner":i.owner,"ok":false,"error":code});
            if let Some(diagnostic)=diagnostic { value["diagnostic"]=serde_json::json!(diagnostic); }
            value
        }}
    }).collect();
    reply(
        StatusCode::OK,
        serde_json::json!({"version":1,"items":items}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(hash: &str, owner: &str, attempt: &str) -> Item {
        Item {
            sha256: hash.repeat(64),
            owner: owner.repeat(64),
            attempt: attempt.repeat(32),
            source: "gcs:fixture:1".into(),
            provenance: "fixture-manifest:1".into(),
            size: 9,
            content_type: "video/mp4".into(),
            generation: None,
            file_id: None,
            bucket: None,
        }
    }
    #[test]
    fn archive_input_rejects_unbounded_or_malformed_identities() {
        let mut i = sample("a", "b", "c");
        assert!(validate(&i).is_ok());
        i.owner = "invalid".into();
        assert!(validate(&i).is_err());
        i = sample("a", "b", "c");
        i.size = 0;
        assert!(validate(&i).is_err());
        assert!(serde_json::from_value::<Batch>(
            serde_json::json!({"version":1,"items":[],"extra":true})
        )
        .is_err());
    }
    #[test]
    #[ignore = "requires synthetic KV and origin fixtures; scripts/run-archive-import-tests.py"]
    fn archive_registration_retry_ownership_erasure_and_range() {
        let mut i = sample("a", "b", "c");
        assert!(metadata::get_blob_metadata(&i.sha256).unwrap().is_none());
        let admitted = admit(&i).unwrap();
        i.generation = Some(admitted["generation"].as_str().unwrap().into());
        assert!(parent_gate::archive_claim(&i.sha256, &"d".repeat(32)).is_err());
        i.file_id = Some("fixture-version".into());
        i.bucket = Some("b2".into());
        let registered = register(&i).unwrap();
        assert_eq!(registered, register(&i).unwrap());
        assert_eq!(registered["receipt"]["owner"], i.owner);
        let meta = metadata::get_blob_metadata(&i.sha256).unwrap().unwrap();
        assert!(meta.archive_storage.is_some());
        assert_eq!(meta.status, BlobStatus::Pending);
        let mut second = sample("a", "d", "e");
        let admitted = admit(&second).unwrap();
        second.generation = Some(admitted["generation"].as_str().unwrap().into());
        second.bucket = i.bucket.clone();
        second.file_id = i.file_id.clone();
        register(&second).unwrap();
        let refs = metadata::get_blob_refs(&i.sha256).unwrap();
        assert!(refs.contains(&i.owner) && refs.contains(&second.owner));
        assert_eq!(
            metadata::get_blob_metadata_uncached(&i.sha256)
                .unwrap()
                .unwrap()
                .owner,
            i.owner
        );
        let mut request = Request::get(format!("https://fixture.invalid/{}", i.sha256));
        request.set_header("Range", "bytes=1-3");
        let response = crate::storage::with_uncached_storage_for_test(|| {
            crate::handle_get_blob(request, &format!("/{}", i.sha256))
        })
        .unwrap();
        assert_eq!(response.get_status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.into_body().into_string(), "ynt");
        unlink_owner(&i.sha256, &second.owner).unwrap();
        assert!(!read(&i.sha256)
            .unwrap()
            .receipts
            .contains_key(&second.owner));
        assert!(admit(&second).is_err());
        metadata::mark_vanish_in_progress(&i.owner).unwrap();
        assert!(admit(&i).is_err());
        metadata::clear_vanish_in_progress(&i.owner).unwrap();
        parent_gate::claim_erasure(&metadata::open_store().unwrap(), &i.sha256).unwrap();
        let third = sample("a", "f", "f");
        assert!(admit(&third).is_err());
        erase_record(&i.sha256).unwrap();
        assert!(read(&i.sha256).unwrap().receipts.is_empty());
    }
    fn call(i: &Item, op: &str) -> serde_json::Value {
        let mut request =
            Request::post(format!("https://fixture.invalid/internal/archive/v1/{op}"));
        request.set_header("Authorization", "Bearer fixture-importer");
        request.set_body(serde_json::json!({"version":1,"items":[i]}).to_string());
        let response = handle(request, op);
        assert_eq!(response.get_status(), StatusCode::OK);
        serde_json::from_str(&response.into_body().into_string()).unwrap()
    }
    #[test]
    #[ignore = "requires synthetic KV; scripts/run-archive-import-tests.py"]
    fn archive_partial_admission_can_settle_without_record() {
        let i = sample("c", "d", "e");
        parent_gate::archive_claim(&i.sha256, &i.attempt).unwrap();
        assert!(read(&i.sha256).unwrap().admission.is_none());
        metadata::mark_vanish_in_progress(&i.owner).unwrap();
        assert!(admit(&i).is_err());
        assert_eq!(call(&i, "settle")["items"][0]["ok"], true);
        assert_eq!(call(&i, "settle")["items"][0]["ok"], true);
        metadata::clear_vanish_in_progress(&i.owner).unwrap();
        assert!(
            admit(&i).is_err(),
            "a late retry must not reopen a retired admission"
        );
        parent_gate::claim_erasure(&metadata::open_store().unwrap(), &i.sha256).unwrap();
    }
    #[test]
    #[ignore = "requires synthetic KV; scripts/run-archive-import-tests.py"]
    fn archive_ownership_cas_rejects_writes_prepared_before_unlink() {
        let mut original = sample("a", "b", "c");
        let admission = admit(&original).unwrap();
        original.generation = Some(admission["generation"].as_str().unwrap().into());
        original.file_id = Some("fixture-version".into());
        original.bucket = Some("b2".into());
        register(&original).unwrap();
        let mut delayed = sample("a", "d", "e");
        let admission = admit(&delayed).unwrap();
        delayed.generation = Some(admission["generation"].as_str().unwrap().into());
        delayed.file_id = original.file_id.clone();
        delayed.bucket = original.bucket.clone();
        let store = metadata::open_store().unwrap();
        let list_key = format!("list:{}", delayed.owner);
        let refs_key = format!("refs:{}", delayed.sha256);
        // Pause the writer after its CAS lookup and policy check, before insert.
        let record_key = key(&delayed.sha256);
        let mut record_snapshot = store.lookup(&record_key).unwrap();
        let record_generation = record_snapshot.current_generation();
        let stale_record = record_snapshot.take_body().into_string();
        let list_generation = store.lookup(&list_key).unwrap().current_generation();
        let refs_generation = store.lookup(&refs_key).unwrap().current_generation();
        owner_allowed(&delayed.sha256, &delayed.owner).unwrap();
        metadata::mark_vanish_in_progress(&delayed.owner).unwrap();
        metadata::remove_from_blob_refs(&delayed.sha256, &delayed.owner).unwrap();
        metadata::update_user_list_for_vanish(&delayed.owner, &[delayed.sha256.clone()], &[])
            .unwrap();
        metadata::clear_vanish_in_progress(&delayed.owner).unwrap();
        assert_eq!(call(&delayed, "settle")["items"][0]["ok"], true);
        // Resume the stale writes after erasure and settlement both returned.
        for (key, generation, value) in [
            (record_key, record_generation, stale_record),
            (
                list_key,
                list_generation,
                serde_json::json!([delayed.sha256]).to_string(),
            ),
            (
                refs_key,
                refs_generation,
                serde_json::json!([original.owner, delayed.owner]).to_string(),
            ),
        ] {
            assert!(matches!(
                store
                    .build_insert()
                    .if_generation_match(generation)
                    .execute(&key, value),
                Err(KVStoreError::ItemPreconditionFailed)
            ));
        }
        assert!(
            metadata::add_archive_user_hashes(&delayed.owner, &[delayed.sha256.clone()]).is_err()
        );
        assert!(metadata::add_archive_blob_ref(&delayed.sha256, &delayed.owner).is_err());
        assert!(register(&delayed).is_err());
        assert!(read(&delayed.sha256).unwrap().admission.is_none());
        assert!(metadata::get_user_blobs(&delayed.owner).unwrap().is_empty());
        assert_eq!(
            metadata::get_blob_refs(&delayed.sha256).unwrap(),
            vec![original.owner]
        );
        // A brand-new admission paused while the account list was absent is also fenced.
        let late = sample("f", "e", "f");
        let key = format!("list:{}", late.owner);
        assert!(matches!(
            store.lookup(&key),
            Err(KVStoreError::ItemNotFound)
        ));
        owner_allowed(&late.sha256, &late.owner).unwrap();
        metadata::mark_vanish_in_progress(&late.owner).unwrap();
        metadata::update_user_list_for_vanish(&late.owner, &[], &[]).unwrap();
        metadata::clear_vanish_in_progress(&late.owner).unwrap();
        assert!(matches!(
            store
                .build_insert()
                .mode(fastly::kv_store::InsertMode::Add)
                .execute(&key, serde_json::json!([late.sha256]).to_string()),
            Err(KVStoreError::ItemPreconditionFailed)
        ));
        assert!(admit(&late).is_err());
        unlink_owner(&late.sha256, &late.owner).unwrap();
        assert!(matches!(
            store
                .build_insert()
                .mode(fastly::kv_store::InsertMode::Add)
                .execute(&format!("archive:v1:{}", late.sha256), "{}"),
            Err(KVStoreError::ItemPreconditionFailed)
        ));
        erase_record(&late.sha256).unwrap();
        assert!(matches!(
            store
                .build_insert()
                .mode(fastly::kv_store::InsertMode::Add)
                .execute(&format!("archive:v1:{}", late.sha256), "{}"),
            Err(KVStoreError::ItemPreconditionFailed)
        ));
        assert!(metadata::get_user_blobs(&late.owner).unwrap().is_empty());
        let erased = sample("9", "8", "7");
        let admission = admit(&erased).unwrap();
        assert!(metadata::get_blob_metadata_uncached(&erased.sha256)
            .unwrap()
            .is_none());
        let meta_key = format!("blob:{}", erased.sha256);
        owner_allowed(&erased.sha256, &erased.owner).unwrap();
        parent_gate::archive_check(
            &erased.sha256,
            &erased.attempt,
            admission["generation"].as_str().unwrap(),
        )
        .unwrap();
        metadata::mark_vanish_in_progress(&erased.owner).unwrap();
        assert_eq!(call(&erased, "settle")["items"][0]["ok"], true);
        parent_gate::claim_erasure(&store, &erased.sha256).unwrap();
        metadata::delete_blob_metadata(&erased.sha256).unwrap();
        // Resume an absent-key insert prepared by the original registration request.
        assert!(matches!(
            store
                .build_insert()
                .mode(fastly::kv_store::InsertMode::Add)
                .execute(&meta_key, "{}"),
            Err(KVStoreError::ItemPreconditionFailed)
        ));
        assert_eq!(
            store.lookup(&meta_key).unwrap().take_body().into_string(),
            "null"
        );
        assert!(metadata::get_blob_metadata_uncached(&erased.sha256)
            .unwrap()
            .is_none());
        let mut request = Request::get(format!("https://fixture.invalid/{}", erased.sha256));
        request.set_header("Host", "media.divine.video");
        assert!(matches!(
            crate::handle_get_blob(request, &format!("/{}", erased.sha256)),
            Err(BlossomError::NotFound(_))
        ));
    }
    #[test]
    #[ignore = "requires admission-disabled synthetic KV; scripts/run-archive-import-tests.py"]
    fn archive_paused_routes_drain_existing_admissions() {
        let mut i = sample("e", "f", "a");
        let admitted = admit(&i).unwrap();
        let resumed = call(&i, "admit");
        assert_eq!(resumed["items"][0]["ok"], true);
        let paused = call(&sample("f", "e", "b"), "admit");
        assert_eq!(paused["items"][0]["ok"], false);
        assert_eq!(paused["items"][0]["error"], "retry");
        assert_eq!(paused["items"][0]["diagnostic"], serde_json::json!({"stage":"admission_paused"}));
        i.generation = Some(admitted["generation"].as_str().unwrap().into());
        i.file_id = Some("fixture-version".into());
        i.bucket = Some("b2".into());
        assert_eq!(call(&i, "register")["items"][0]["ok"], true);
        parent_gate::claim_erasure(&metadata::open_store().unwrap(), &i.sha256).unwrap();
    }
    #[test]
    #[ignore = "requires synthetic KV; scripts/run-archive-import-tests.py"]
    fn archive_routes_require_dedicated_auth_and_batch_results() {
        let mut req = Request::post("https://fixture.invalid/internal/archive/v1/admit");
        req.set_header("Authorization", "Bearer fixture-admin");
        req.set_body("invalid");
        assert_eq!(handle(req, "admit").get_status(), StatusCode::UNAUTHORIZED);
        let mut req = Request::post("https://fixture.invalid/internal/archive/v1/admit");
        req.set_header("Authorization", "Bearer fixture-importer");
        let mut bad = sample("c", "d", "e");
        bad.size = 0;
        req.set_body(
            serde_json::json!({"version":1,"items":[sample("b","c","d"),bad]}).to_string(),
        );
        let response = handle(req, "admit");
        assert_eq!(response.get_status(), StatusCode::OK);
        let value: serde_json::Value =
            serde_json::from_str(&response.into_body().into_string()).unwrap();
        assert_eq!(value["items"][0]["ok"], true);
        assert_eq!(value["items"][1]["ok"], false);
        let delta = || Aggregate {
            version: 1,
            previous: 0,
            next: 1,
            count: 2,
            bytes: 18,
            mime_counts: BTreeMap::from([("video/mp4".into(), 2)]),
        };
        aggregate(delta()).unwrap();
        aggregate(delta()).unwrap();
        let stats = metadata::get_global_stats().unwrap();
        assert_eq!(stats.total_blobs, 2);
        assert_eq!(stats.total_size_bytes, 18);
        assert_eq!(stats.archive_import_cursor, 1);
    }
    #[test]
    #[ignore = "requires synthetic KV; scripts/run-archive-import-tests.py"]
    fn archive_diagnostics_are_private_static_and_isolated_between_batch_items() {
        let mut unauthenticated = Request::post("https://fixture.invalid/internal/archive/v1/admit");
        unauthenticated.set_body("synthetic-private-body");
        let response = handle(unauthenticated, "admit");
        assert_eq!(response.get_status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.into_body().into_string(), r#"{"error":"archive import unavailable"}"#);
        let mut wrong_token = Request::post("https://fixture.invalid/internal/archive/v1/admit");
        wrong_token.set_header("Authorization", "Bearer fixture-admin");
        wrong_token.set_body("synthetic-private-body");
        let response = handle(wrong_token, "admit");
        assert_eq!(response.get_status(), StatusCode::UNAUTHORIZED);
        assert!(!response.into_body().into_string().contains("diagnostic"));

        let first = sample("1", "2", "3");
        let mut second = sample("4", "5", "6");
        second.size = 0;
        let store = metadata::open_store().unwrap();
        // A malformed synthetic owner list fails in the real conditional-read path.
        store.insert(&format!("list:{}", first.owner), "synthetic-private-source-token-generation").unwrap();
        let mut request = Request::post("https://fixture.invalid/internal/archive/v1/admit");
        request.set_header("Authorization", "Bearer fixture-importer");
        request.set_body(serde_json::json!({"version":1,"items":[first,second]}).to_string());
        let response = handle(request, "admit");
        assert_eq!(response.get_status(), StatusCode::OK);
        assert_eq!(response.get_header_str("Cache-Control"), Some("private, no-store"));
        let value:serde_json::Value=serde_json::from_str(&response.into_body().into_string()).unwrap();
        assert_eq!(value["items"][0]["error"], "retry");
        assert_eq!(value["items"][0]["diagnostic"], serde_json::json!({"stage":"owner_list"}));
        assert_eq!(value["items"][1]["error"], "invalid");
        assert_eq!(value["items"][1]["diagnostic"], serde_json::json!({"stage":"operation"}));
        let diagnostic=value["items"][0]["diagnostic"].to_string();
        for sensitive in [&first.sha256,&first.owner,&first.attempt,&first.source,&first.provenance,"synthetic-private-source-token-generation"] {
            assert!(!diagnostic.contains(sensitive));
        }
        assert!(read(&first.sha256).unwrap().admission.is_none());
        assert!(!parent_gate::archive_owned(&first.sha256,&first.attempt).unwrap());
        store.insert(&format!("list:{}", first.owner), "[]").unwrap();
        let success=call(&first,"reconcile");
        assert_eq!(success["items"][0]["ok"],true);
        assert!(success["items"][0].get("diagnostic").is_none());
        fence_account(&first.owner).unwrap();
        let denied=call(&first,"admit");
        assert_eq!(denied["items"][0]["error"],"policy_denied");
        assert_eq!(denied["items"][0]["diagnostic"],serde_json::json!({"stage":"policy"}));
    }

}

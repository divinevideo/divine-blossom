//! Transport-independent signing of an already-canonical S3 request.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// Sign canonical bytes supplied by the transport adapter, without rewriting
/// paths, queries, header values or signed-header ordering. Secrets are neither
/// formatted into errors nor retained in a debuggable configuration object.
pub fn authorization(
    access_key: &str,
    secret_key: &str,
    region: &str,
    date_stamp: &str,
    timestamp: &str,
    canonical_request: &str,
    signed_headers: &str,
) -> Result<String, &'static str> {
    let valid_access = !access_key.is_empty()
        && access_key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let valid_region = !region.is_empty()
        && region.len() <= 63
        && !region.starts_with('-')
        && !region.ends_with('-')
        && region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let valid_date = date_stamp.len() == 8 && date_stamp.bytes().all(|b| b.is_ascii_digit());
    let valid_time = timestamp.len() == 16
        && timestamp.starts_with(date_stamp)
        && timestamp.as_bytes()[8] == b'T'
        && timestamp.as_bytes()[15] == b'Z'
        && timestamp.as_bytes()[9..15].iter().all(u8::is_ascii_digit);
    let valid_headers = signed_headers.split(';').all(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    });
    if !valid_access
        || secret_key.is_empty()
        || secret_key.trim() != secret_key
        || secret_key.bytes().any(|b| b.is_ascii_control())
        || !valid_region
        || !valid_date
        || !valid_time
        || !valid_headers
    {
        return Err("invalid S3 signing configuration");
    }
    let scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{canonical_hash}");
    let date_key = hmac(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    )?;
    let region_key = hmac(&date_key, region.as_bytes())?;
    let service_key = hmac(&region_key, b"s3")?;
    let signing_key = hmac(&service_key, b"aws4_request")?;
    let signature = hex::encode(hmac(&signing_key, string_to_sign.as_bytes())?);
    Ok(format!("AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"))
}

fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid S3 signing key")?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_matches_frozen_pre_extraction_vectors() {
        let cases: serde_json::Value =
            serde_json::from_str(include_str!("../tests/s3_signing_golden.json")).unwrap();
        for case in cases.as_array().unwrap() {
            let actual = authorization(
                "synthetic-access",
                "synthetic-secret",
                "us-west-004",
                "20261107",
                "20261107T010203Z",
                case["canonical_request"].as_str().unwrap(),
                case["signed_headers"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(
                actual,
                case["authorization"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn empty_or_malformed_signing_configuration_is_rejected() {
        for (access, secret, region, date, timestamp, headers) in [
            (
                "",
                "secret",
                "region",
                "20261107",
                "20261107T010203Z",
                "host",
            ),
            (
                "access",
                "",
                "region",
                "20261107",
                "20261107T010203Z",
                "host",
            ),
            (
                "access",
                "secret",
                "",
                "20261107",
                "20261107T010203Z",
                "host",
            ),
            (
                "access\nheader",
                "secret",
                "region",
                "20261107",
                "20261107T010203Z",
                "host",
            ),
            (
                "access",
                "secret",
                "region/path",
                "20261107",
                "20261107T010203Z",
                "host",
            ),
            (
                "access",
                "secret",
                "region",
                "20261108",
                "20261107T010203Z",
                "host",
            ),
            (
                "access",
                "secret",
                "region",
                "20261107",
                "bad timestamp",
                "host",
            ),
            (
                "access",
                "secret",
                "region",
                "20261107",
                "20261107T010203Z",
                "Host\n",
            ),
        ] {
            assert!(authorization(
                access,
                secret,
                region,
                date,
                timestamp,
                "canonical",
                headers
            )
            .is_err());
        }
    }
}

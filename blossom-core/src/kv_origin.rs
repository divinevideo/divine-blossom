// ABOUTME: Builds requests for, and interprets responses from, the Fastly KV origin API.
// ABOUTME: Origin reads are authoritative where edge reads of recently written keys can be stale.

/// A KV entry as stored at the origin, with the generation conditional writes are checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginEntry {
    pub body: Vec<u8>,
    pub generation: u64,
}

/// Path of `key` in `store_id` on the KV API. Keys are percent-encoded except for unreserved
/// characters and `:`, which Blossom's key prefixes use.
pub fn key_path(store_id: &str, key: &str) -> String {
    let mut encoded = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    format!("/resources/stores/kv/{store_id}/keys/{encoded}")
}

/// Interpret a KV API read: `Ok(None)` when the key does not exist.
pub fn interpret(status: u16, generation: Option<&str>, body: Vec<u8>) -> Result<Option<OriginEntry>, String> {
    match status {
        200 => {
            let generation = generation
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| "KV origin response has no generation".to_string())?;
            Ok(Some(OriginEntry { body, generation }))
        }
        404 => Ok(None),
        other => Err(format!("KV origin read failed with status {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{interpret, key_path, OriginEntry};

    #[test]
    fn key_paths_keep_blossom_prefixes_and_encode_everything_else() {
        assert_eq!(
            key_path("store1", "b2-sync:v1:abc123"),
            "/resources/stores/kv/store1/keys/b2-sync:v1:abc123"
        );
        assert_eq!(key_path("s", "list:a/b c?"), "/resources/stores/kv/s/keys/list:a%2Fb%20c%3F");
    }

    #[test]
    fn found_entries_carry_their_generation() {
        assert_eq!(
            interpret(200, Some("1794521814756247"), b"[]".to_vec()),
            Ok(Some(OriginEntry { body: b"[]".to_vec(), generation: 1794521814756247 }))
        );
        assert_eq!(interpret(404, None, Vec::new()), Ok(None));
    }

    #[test]
    fn unusable_responses_are_errors_not_absent_keys() {
        assert!(interpret(200, None, b"[]".to_vec()).is_err());
        assert!(interpret(200, Some("0"), b"[]".to_vec()).is_err());
        assert!(interpret(200, Some("not-a-number"), b"[]".to_vec()).is_err());
        assert!(interpret(429, None, Vec::new()).is_err());
        assert!(interpret(401, None, Vec::new()).is_err());
    }
}

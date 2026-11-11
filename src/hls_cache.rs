//! POP Simple Cache entries for HLS playlists.
//!
//! An entry keeps the storage provenance headers with the playlist bytes, so a
//! cache hit answers with the same headers as the storage read that filled it.

use fastly::http::HeaderValue;

/// Storage headers a playlist response carries. Playlist handlers derive
/// `X-C2PA-Manifest-Id` and `X-Source-Sha256` from them. Changing this list
/// changes the entry format, so bump the namespace in [`key`] with it.
pub const PRESERVED_HEADERS: [&str; 2] =
    ["x-goog-meta-c2pa-manifest-id", "x-goog-meta-source-sha256"];

/// Simple Cache key for a playlist at `path`. Service versions share the POP
/// cache during a rollout or rollback, so bump the namespace whenever the entry
/// format or [`PRESERVED_HEADERS`] changes: otherwise each version would
/// reject and purge the other's entries. Body-only `hls:` entries from before
/// this format expire within the playlist cache TTL.
pub fn key(path: &str) -> String {
    format!("hls-v2:{path}")
}

/// Header lines, a blank line, then the playlist bytes unchanged. Header values
/// cannot contain line breaks, so the first blank line always ends the headers.
pub fn encode(headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut entry = Vec::new();
    for (name, value) in headers {
        entry.extend_from_slice(format!("{name}: {value}\n").as_bytes());
    }
    entry.push(b'\n');
    entry.extend_from_slice(body);
    entry
}

/// Preserved headers and the playlist body, borrowed from a cache entry.
pub type Decoded<'a> = (Vec<(&'static str, &'a str)>, &'a [u8]);

/// Returns `None` for an entry not in this format, so the caller can refill it
/// from storage instead of serving it.
pub fn decode(entry: &[u8]) -> Option<Decoded<'_>> {
    let mut headers = Vec::new();
    let mut rest = entry;
    loop {
        let end = rest.iter().position(|&byte| byte == b'\n')?;
        let line = &rest[..end];
        rest = &rest[end + 1..];
        if line.is_empty() {
            return Some((headers, rest));
        }
        let (name, value) = std::str::from_utf8(line).ok()?.split_once(": ")?;
        let name = PRESERVED_HEADERS.into_iter().find(|known| *known == name)?;
        HeaderValue::from_str(value).ok()?;
        headers.push((name, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "x-goog-meta-c2pa-manifest-id";
    const SOURCE: &str = "x-goog-meta-source-sha256";

    #[test]
    fn entry_round_trips_preserved_headers_and_body() {
        let body = b"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=100\nstream_480p.m3u8\n";
        let source = "e".repeat(64);
        let headers = [(MANIFEST, "urn:uuid:synthetic"), (SOURCE, source.as_str())];
        let entry = encode(&headers, body);
        let (decoded, decoded_body) = decode(&entry).unwrap();
        assert_eq!(decoded, headers);
        assert_eq!(decoded_body, body);
    }

    #[test]
    fn entry_without_headers_keeps_body() {
        let entry = encode(&[], b"#EXTM3U\n");
        let (decoded, body) = decode(&entry).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(body, b"#EXTM3U\n");
    }

    #[test]
    fn body_bytes_are_never_parsed_as_headers() {
        // Only the first blank line ends the header block.
        let body = b"\n\nx-goog-meta-source-sha256: forged\n\n\xff\x00";
        let entry = encode(&[(MANIFEST, "synthetic")], body);
        let (decoded, decoded_body) = decode(&entry).unwrap();
        assert_eq!(decoded, [(MANIFEST, "synthetic")]);
        assert_eq!(decoded_body, body);
    }

    #[test]
    fn empty_header_value_round_trips() {
        let entry = encode(&[(SOURCE, "")], b"#EXTM3U\n");
        assert_eq!(decode(&entry).unwrap().0, [(SOURCE, "")]);
    }

    #[test]
    fn unreadable_entries_are_rejected() {
        for entry in [
            // A pre-envelope body-only entry.
            &b"#EXTM3U\n#EXTINF:4,\nsegment_0.ts\n"[..],
            // No blank line terminating the header block.
            b"x-goog-meta-source-sha256: aaaa\n",
            // A header this version does not preserve.
            b"x-divine-unknown: value\n\n#EXTM3U\n",
            // A line without the name/value separator.
            b"x-goog-meta-source-sha256\n\n#EXTM3U\n",
            // A value that is not a valid HTTP header value.
            b"x-goog-meta-source-sha256: bad\rvalue\n\n#EXTM3U\n",
            // Non-UTF-8 header bytes.
            b"x-goog-meta-source-sha256: \xff\n\n#EXTM3U\n",
            b"",
        ] {
            assert!(
                decode(entry).is_none(),
                "{:?}",
                String::from_utf8_lossy(entry)
            );
        }
    }
}

use fastly::http::Url;

pub const MAX_MASTER_BYTES: u64 = 256 * 1024;

/// Keep the short master URL while resolving relative references at its canonical directory.
pub fn for_alias(manifest: &str, hash: &str) -> Result<String, &'static str> {
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Invalid HLS content hash");
    }
    let hash = hash.to_ascii_lowercase();
    let prefix = format!("/{hash}/hls/");
    let base = Url::parse(&format!("https://hls.invalid{prefix}master.m3u8"))
        .map_err(|_| "Invalid HLS base URL")?;
    let resolve = |uri: &str| -> Result<String, &'static str> {
        // Already base-independent references retain their existing meaning.
        if uri.starts_with('/') || Url::parse(uri).is_ok() {
            return Ok(uri.to_string());
        }
        let url = base.join(uri).map_err(|_| "Invalid relative HLS URI")?;
        if url.host_str() != base.host_str() || !url.path().starts_with(&prefix) {
            return Err("Relative HLS URI escaped its video directory");
        }
        let mut result = url.path().to_string();
        if let Some(query) = url.query() {
            result.push('?');
            result.push_str(query);
        }
        if let Some(fragment) = url.fragment() {
            result.push('#');
            result.push_str(fragment);
        }
        Ok(result)
    };
    let mut result = String::with_capacity(manifest.len());
    for line in manifest.lines() {
        if line.starts_with('#') {
            let mut rest = line;
            while let Some(start) = rest.find("URI=\"") {
                result.push_str(&rest[..start + 5]);
                rest = &rest[start + 5..];
                let end = rest.find('"').ok_or("Unclosed HLS URI attribute")?;
                result.push_str(&resolve(&rest[..end])?);
                result.push('"');
                rest = &rest[end + 1..];
            }
            result.push_str(rest);
        } else if !line.is_empty() {
            result.push_str(&resolve(line)?);
        }
        result.push('\n');
        if result.len() as u64 > MAX_MASTER_BYTES {
            return Err("Expanded HLS master exceeds size limit");
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_variant_and_quoted_rendition_references_without_redirecting() {
        let hash = "a".repeat(64);
        let input = "#EXTM3U\n#EXT-X-MEDIA:TYPE=AUDIO,URI=\"audio/main.m3u8\"\n#EXT-X-STREAM-INF:BANDWIDTH=100\nstream_480p.m3u8?mode=1\n";
        let output = for_alias(input, &hash).unwrap();
        assert!(output.contains(&format!("URI=\"/{hash}/hls/audio/main.m3u8\"")));
        let line = output.lines().find(|line| !line.starts_with('#')).unwrap();
        let alias = Url::parse(&format!("https://media.example.test/{hash}.hls")).unwrap();
        assert_eq!(
            alias.join(line).unwrap().path(),
            format!("/{hash}/hls/stream_480p.m3u8")
        );
        assert!(line.ends_with("?mode=1"));
    }

    #[test]
    fn preserves_existing_absolute_references() {
        let input = "#EXTM3U\n/other/playlist.m3u8\nhttps://cdn.example.test/rendition.m3u8\n";
        assert_eq!(for_alias(input, &"a".repeat(64)).unwrap(), input);
    }

    #[test]
    fn bounds_expanded_master_size() {
        let input = format!("#EXTM3U\n{}", "a\n".repeat(4096));
        assert!(input.len() < MAX_MASTER_BYTES as usize);
        assert!(for_alias(&input, &"a".repeat(64)).is_err());
    }

    #[test]
    fn refuses_relative_path_escape_and_unclosed_attributes() {
        for uri in ["../other.m3u8", "%2e%2e/other.m3u8"] {
            assert!(for_alias(&format!("#EXTM3U\n{uri}\n"), &"a".repeat(64)).is_err());
        }
        assert!(for_alias("#EXTM3U\n#EXT-X-MEDIA:URI=\"unclosed", &"a".repeat(64)).is_err());
        assert!(for_alias("#EXTM3U\nstream.m3u8\n", "../bad").is_err());
    }
}

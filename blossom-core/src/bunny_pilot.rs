//! Exact paths and hostnames in the approved-only Bunny delivery namespace.

pub const DELIVERY_PREFIX: &str = "bunny-delivery/";
pub const DELIVERY_HOST: &str = "media-bunny.divine.video";

pub struct Asset<'a> {
    hash: &'a str,
    rendition: bool,
}

impl<'a> Asset<'a> {
    pub fn parse(path: &'a str) -> Option<Self> {
        let path = path.strip_prefix('/')?;
        let (hash, rendition) = match path.strip_suffix("/720p.mp4") {
            Some(hash) => (hash, true),
            None => (path, false),
        };
        (hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .then_some(Self { hash, rendition })
    }

    pub fn hash(&self) -> &'a str {
        self.hash
    }

    pub fn is_original(&self) -> bool {
        !self.rendition
    }

    pub fn source_key(&self) -> String {
        if self.rendition {
            format!("{}/hls/stream_720p.mp4", self.hash)
        } else {
            self.hash.to_owned()
        }
    }

    pub fn delivery_key(&self) -> String {
        let suffix = if self.rendition { "/720p.mp4" } else { "" };
        format!("{DELIVERY_PREFIX}{}{suffix}", self.hash)
    }
}

pub fn zone_hosts(value: &str) -> Option<[&str; 2]> {
    let (custom, vendor) = value.split_once(',')?;
    let label = vendor.strip_suffix(".b-cdn.net")?;
    (custom == DELIVERY_HOST
        && (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'-')))
    .then_some([custom, vendor])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_only_exact_original_and_720p_paths() {
        let hash = "a".repeat(64);
        let original = format!("/{hash}");
        let rendition = format!("/{hash}/720p.mp4");
        assert_eq!(Asset::parse(&original).unwrap().source_key(), hash);
        assert_eq!(
            Asset::parse(&rendition).unwrap().source_key(),
            format!("{hash}/hls/stream_720p.mp4")
        );
        assert_eq!(
            Asset::parse(&rendition).unwrap().delivery_key(),
            format!("bunny-delivery{rendition}")
        );
        for path in [
            format!("/{hash}.mp4"),
            format!("/{hash}/480p.mp4"),
            format!("/{hash}?versionId=1"),
            format!("/{hash}/"),
            format!("/{}", hash.to_uppercase()),
        ] {
            assert!(Asset::parse(&path).is_none(), "unexpected asset {path}");
        }
    }

    #[test]
    fn purge_targets_require_one_owned_hostname_and_one_vendor_hostname() {
        let valid = "media-bunny.divine.video,divine-media-pilot.b-cdn.net";
        assert_eq!(
            zone_hosts(valid).unwrap(),
            ["media-bunny.divine.video", "divine-media-pilot.b-cdn.net"]
        );
        for raw in [
            "",
            "media-bunny.divine.video",
            "media-bunny.divine.video,evil.example",
            "media-bunny.divine.video,a.b.b-cdn.net",
            "media-bunny.divine.video,foo.b-cdn.net:443",
        ] {
            assert!(zone_hosts(raw).is_none(), "unexpected hosts {raw}");
        }
    }
}

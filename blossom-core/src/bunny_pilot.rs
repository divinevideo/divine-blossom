//! Exact paths and hostnames in the approved-only Bunny delivery namespace.

pub const DELIVERY_PREFIX: &str = "bunny-delivery/";
pub const DELIVERY_HOST: &str = "media-bunny.divine.video";

pub const MAX_PLAYLIST: usize = 64 * 1024;
pub const MAX_OBJECT: usize = 16 * 1024 * 1024;
pub const HLS_PATHS: [&str; 5] = [
    "hls/stream_720p.ts",
    "hls/stream_480p.ts",
    "hls/stream_720p.m3u8",
    "hls/stream_480p.m3u8",
    "hls/master.m3u8",
];

pub fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub struct Asset<'a> {
    path: &'a str,
    hash: &'a str,
    suffix: &'a str,
}

impl<'a> Asset<'a> {
    pub fn parse(path: &'a str) -> Option<Self> {
        let key = path.strip_prefix('/')?;
        let (hash, suffix) = match key.split_once('/') {
            Some((hash, suffix))
                if matches!(suffix, "720p.mp4" | "480p.mp4") || HLS_PATHS.contains(&suffix) =>
            {
                (hash, suffix)
            }
            Some(_) => return None,
            None => (key, ""),
        };
        digest(hash).then_some(Self { hash, suffix, path })
    }

    pub fn hash(&self) -> &'a str {
        self.hash
    }
    pub fn suffix(&self) -> &'a str {
        self.suffix
    }
    pub fn is_original(&self) -> bool {
        self.suffix.is_empty()
    }
    pub fn is_playlist(&self) -> bool {
        self.suffix.ends_with(".m3u8")
    }
    pub fn is_top_level(&self) -> bool {
        !self.suffix.starts_with("hls/") || self.suffix == "hls/master.m3u8"
    }
    pub fn mime(&self) -> &'static str {
        if self.is_playlist() {
            "application/vnd.apple.mpegurl"
        } else if self.suffix.ends_with(".ts") {
            "video/mp2t"
        } else {
            "video/mp4"
        }
    }
    pub fn max_size(&self) -> usize {
        if self.is_playlist() {
            MAX_PLAYLIST
        } else {
            MAX_OBJECT
        }
    }

    pub fn child_names(&self) -> &'static [&'static str] {
        match self.suffix {
            "hls/master.m3u8" => &["stream_720p.m3u8", "stream_480p.m3u8"],
            "hls/stream_720p.m3u8" => &["stream_720p.ts"],
            "hls/stream_480p.m3u8" => &["stream_480p.ts"],
            _ => &[],
        }
    }
    pub fn source_key(&self) -> String {
        if matches!(self.suffix, "720p.mp4" | "480p.mp4") {
            format!("{}/hls/stream_{}", self.hash, self.suffix)
        } else {
            self.path[1..].to_owned()
        }
    }
    pub fn delivery_key(&self) -> String {
        format!("{DELIVERY_PREFIX}{}", &self.path[1..])
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
    fn serves_only_exact_playback_paths() {
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
        for suffix in [
            "480p.mp4",
            "hls/master.m3u8",
            "hls/stream_720p.m3u8",
            "hls/stream_480p.m3u8",
            "hls/stream_720p.ts",
            "hls/stream_480p.ts",
        ] {
            let path = format!("/{hash}/{suffix}");
            assert_eq!(
                Asset::parse(&path)
                    .expect("supported playback path")
                    .delivery_key(),
                format!("bunny-delivery{path}")
            );
        }
        for path in [
            format!("/{hash}.mp4"),
            format!("/{hash}/1080p.mp4"),
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

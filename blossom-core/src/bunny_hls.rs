//! Validate the two-rendition, single-file MPEG-TS VOD format produced by the transcoder.
use crate::bunny_pilot::{Asset, MAX_PLAYLIST};
use std::collections::BTreeSet;

fn number(value: &str, max: usize) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok().filter(|n| *n <= max)
}

fn decimal(value: &str) -> Option<f64> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, "0"));
    number(whole, 99999)?;
    if fraction.len() > 9 || fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

// Parse quoted CODECS as one attribute, including its commas. Only values with
// a defined meaning for the current self-contained family are supported.
fn stream_attributes(mut text: &str) -> Option<()> {
    let mut seen = BTreeSet::new();
    loop {
        let (name, values) = text.split_once('=')?;
        if !seen.insert(name) {
            return None;
        }
        let (value, rest) = if let Some(quoted) = values.strip_prefix('"') {
            let (value, tail) = quoted.split_once('"')?;
            if name != "CODECS" {
                return None;
            }
            (value, tail)
        } else {
            if name == "CODECS" {
                return None;
            }
            values
                .find(',')
                .map_or((values, ""), |i| values.split_at(i))
        };
        let valid = match name {
            "BANDWIDTH" | "AVERAGE-BANDWIDTH" => number(value, usize::MAX)? > 0,
            "RESOLUTION" => {
                let (x, y) = value.split_once('x')?;
                number(x, 99999)? > 0 && number(y, 99999)? > 0
            }
            "FRAME-RATE" => decimal(value)? > 0.0,
            "CLOSED-CAPTIONS" => value == "NONE",
            "CODECS" => {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b".,_-".contains(&b))
            }
            _ => false,
        };
        if !valid {
            return None;
        }
        if rest.is_empty() {
            break;
        }
        text = rest.strip_prefix(',')?;
    }
    seen.contains("BANDWIDTH").then_some(())
}

fn master(lines: &[&str], children: &[&str]) -> Option<()> {
    let mut seen = BTreeSet::new();
    let mut tags = BTreeSet::new();
    let mut pending = false;
    for &line in lines {
        if pending {
            if !children.contains(&line) || !seen.insert(line) {
                return None;
            }
            pending = false;
        } else if let Some(attrs) = line.strip_prefix("#EXT-X-STREAM-INF:") {
            stream_attributes(attrs)?;
            pending = true;
        } else if let Some(v) = line.strip_prefix("#EXT-X-VERSION:") {
            if !tags.insert("version") || number(v, 7)? == 0 {
                return None;
            }
        } else if line != "#EXT-X-INDEPENDENT-SEGMENTS" || !tags.insert(line) {
            return None;
        }
    }
    (!pending && seen.len() == children.len()).then_some(())
}

fn variant(lines: &[&str], child: &str, size: usize) -> Option<()> {
    let mut tags = BTreeSet::new();
    let mut version = 0;
    let mut target = None;
    let mut previous_end = None;
    let mut segments = 0;
    let mut it = lines.iter().copied();
    while let Some(line) = it.next() {
        if line == "#EXT-X-ENDLIST" {
            return (segments > 0
                && it.next().is_none()
                && version >= 4
                && tags.contains("#EXT-X-PLAYLIST-TYPE"))
            .then_some(());
        }
        let (tag, value) = line.split_once(':')?;
        if tag == "#EXTINF" {
            let (duration, _title) = value.split_once(',')?;
            let duration = decimal(duration)?;
            if duration <= 0.0 || duration.round() > target? as f64 || segments >= 1024 {
                return None;
            }
            let range = it.next()?.strip_prefix("#EXT-X-BYTERANGE:")?;
            let (length, offset) = match range.split_once('@') {
                Some((len, start)) => (len, number(start, size)?),
                None => (range, previous_end?),
            };
            let length = number(length, size)?;
            let end = offset.checked_add(length)?;
            if length == 0
                || end > size
                || previous_end.is_some_and(|prev| offset < prev)
                || it.next()? != child
            {
                return None;
            }
            previous_end = Some(end);
            segments += 1;
        } else {
            if segments != 0 || !tags.insert(tag) {
                return None;
            }
            match tag {
                "#EXT-X-VERSION" => version = number(value, 7)?,
                "#EXT-X-TARGETDURATION" => target = number(value, 86400).filter(|n| *n > 0),
                "#EXT-X-MEDIA-SEQUENCE" if value == "0" => {}
                "#EXT-X-PLAYLIST-TYPE" if value == "VOD" => {}
                _ => return None,
            }
        }
    }
    None
}

pub fn normalize(asset: &Asset<'_>, bytes: &[u8], segment_size: usize) -> Option<Vec<u8>> {
    if !asset.is_playlist() || bytes.len() > MAX_PLAYLIST {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let prefix = format!("/{}/hls/", asset.hash());
    let mut lines = text.lines();
    if lines.next()? != "#EXTM3U" {
        return None;
    }
    let mut out = String::with_capacity(bytes.len());
    out.push_str("#EXTM3U\n");
    let mut normalized = Vec::new();
    for line in lines {
        if line.chars().any(char::is_control) {
            return None;
        }
        if line.is_empty() {
            continue;
        }
        let line = if line.starts_with('#') {
            line
        } else {
            let relative = line
                .strip_prefix(&prefix)
                .or_else(|| {
                    line.strip_prefix("https://media.divine.video")
                        .and_then(|path| path.strip_prefix(&prefix))
                })
                .unwrap_or(line);
            if !asset.child_names().contains(&relative) {
                return None;
            }
            relative
        };
        normalized.push(line);
        out.push_str(line);
        out.push('\n');
    }
    match asset.child_names() {
        [child] => variant(&normalized, child, segment_size)?,
        children => master(&normalized, children)?,
    }
    (out.len() <= MAX_PLAYLIST).then(|| out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const VARIANT: &str = "#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-TARGETDURATION:5\n#EXT-X-PLAYLIST-TYPE:VOD\n#EXTINF:5.0,\n#EXT-X-BYTERANGE:188@0\nstream_720p.ts\n#EXTINF:1.250,\n#EXT-X-BYTERANGE:188\nstream_720p.ts\n#EXT-X-ENDLIST\n";
    const MASTER: &str = "#EXTM3U\n#EXT-X-VERSION:4\n#EXT-X-STREAM-INF:BANDWIDTH=1234,CODECS=\"avc1.123456,mp4a.40.2\"\nstream_720p.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=1000\nstream_480p.m3u8\n";

    #[test]
    fn normalizes_only_the_supported_master_and_variant_closure() {
        for (file, body, child) in [
            ("master.m3u8", MASTER, "stream_480p.m3u8"),
            ("stream_720p.m3u8", VARIANT, "stream_720p.ts"),
        ] {
            let path = format!("/{HASH}/hls/{file}");
            let asset = Asset::parse(&path).expect("supported playlist");
            for prefix in [
                "",
                &format!("/{HASH}/hls/"),
                &format!("https://media.divine.video/{HASH}/hls/"),
            ] {
                let source = body.replace(child, &format!("{prefix}{child}"));
                assert_eq!(
                    normalize(&asset, source.as_bytes(), 376).as_deref(),
                    Some(body.as_bytes())
                );
            }
            for reference in [
                "../stream_720p.ts",
                "https://other.example/stream_720p.ts",
                "stream_480p.ts?key=1",
            ] {
                assert!(
                    normalize(&asset, body.replace(child, reference).as_bytes(), 376).is_none()
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_ranges_external_uri_attributes_and_incomplete_vod() {
        let path = format!("/{HASH}/hls/stream_720p.m3u8");
        let asset = Asset::parse(&path).unwrap();
        for invalid in [
            VARIANT.replace("188@0", "188"),
            VARIANT.replace("188@0", "188@1"),
            VARIANT.replace("VOD", "EVENT"),
            VARIANT.replace("ENDLIST", "DISCONTINUITY"),
            VARIANT.replace(
                "#EXTINF:5.0,",
                "#EXT-X-KEY:METHOD=AES-128,URI=\"outside\"\n#EXTINF:5.0,",
            ),
        ] {
            assert!(normalize(&asset, invalid.as_bytes(), 376).is_none());
        }
        let path = format!("/{HASH}/hls/master.m3u8");
        let asset = Asset::parse(&path).unwrap();
        for invalid in [
            MASTER.replace("BANDWIDTH=1000", "BANDWIDTH=1000,URI=\"outside\""),
            MASTER.replace("stream_480p", "stream_720p"),
            MASTER.replace("1234", "0"),
        ] {
            assert!(normalize(&asset, invalid.as_bytes(), 376).is_none());
        }
    }
}

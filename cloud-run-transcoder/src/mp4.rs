// ABOUTME: Minimal ISO-BMFF `moov` reader plus an in-place `mvhd.duration` patch
// ABOUTME: Used to keep the transcoded MP4 derivatives loopable without a seam

//! What this exists for
//!
//! A looping player restarts at `mvhd.duration`. ffmpeg writes that field as
//! the longest track's presentation end, and after an AAC re-encode the audio
//! track outlives the picture by a frame or two — so the movie keeps running
//! after the last video sample and the player holds the final frame across the
//! gap. Clamping the movie header to the video track's presentation end costs
//! no samples and removes the stall (issue #235).
//!
//! Everything here walks box headers only, so it never touches sample data and
//! runs in microseconds regardless of file size.

use anyhow::{anyhow, Result};

/// Header layout per ISO/IEC 14496-12: a 32-bit size, then a 4-byte type.
const BOX_HEADER_LEN: usize = 8;
/// `size == 1` means the real size follows the type as a 64-bit value.
const LARGE_SIZE_LEN: usize = 8;
/// Cap the walk so a malformed file cannot spin us through millions of boxes.
const MAX_BOXES_SCANNED: usize = 4096;
/// `AudioObjectType` 2 in an AudioSpecificConfig: AAC Low Complexity.
const AUDIO_OBJECT_TYPE_AAC_LC: u8 = 2;

/// The parts of a `moov` that decide how a clip loops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovieFacts {
    /// `mvhd.timescale` — the unit of every duration in this struct except
    /// the media ones, which we do not read.
    pub timescale: u32,
    /// `mvhd.duration`, the point a looping player restarts at.
    pub duration: u64,
    /// The longest video track's `tkhd.duration`, i.e. the end of the
    /// picture's presentation. `None` when the file carries no video track.
    pub video_duration: Option<u64>,
    /// Whether the file carries a sound track at all.
    pub has_audio_track: bool,
    /// The sound track's AudioSpecificConfig, as stored in `esds`. `None` when
    /// there is no audio track, or when its decoder config is missing.
    pub audio_specific_config: Option<Vec<u8>>,
}

impl MovieFacts {
    /// How far `mvhd.duration` runs past the last video sample, in the movie
    /// timescale. Zero when the movie ends with the picture, or when there is
    /// no video track to compare against.
    pub fn video_overhang(&self) -> u64 {
        match self.video_duration {
            Some(video) => self.duration.saturating_sub(video),
            None => 0,
        }
    }

    /// Whether the sound track carries a usable AAC-LC decoder config.
    ///
    /// A file with no audio at all counts as fine — there is nothing to be
    /// wrong. A sound track whose `esds` lost its DecoderSpecificInfo does
    /// not: no player can initialise a decoder from it.
    pub fn has_usable_audio_config(&self) -> bool {
        if !self.has_audio_track {
            return true;
        }
        match &self.audio_specific_config {
            Some(asc) => asc.len() >= 2 && (asc[0] >> 3) == AUDIO_OBJECT_TYPE_AAC_LC,
            None => false,
        }
    }
}

/// Read the movie header and track durations out of an ISO-BMFF file.
pub fn read_movie_facts(data: &[u8]) -> Result<MovieFacts> {
    let moov = find_box(data, 0, data.len(), b"moov")
        .ok_or_else(|| anyhow!("no moov box: not a readable MP4"))?;

    let mvhd = find_box(data, moov.start, moov.end, b"mvhd")
        .ok_or_else(|| anyhow!("moov has no mvhd box"))?;
    let (timescale, duration, _) = read_mvhd(data, &mvhd)?;

    let mut video_duration = None;
    let mut has_audio_track = false;
    let mut audio_specific_config = None;

    for trak in boxes_of_type(data, moov.start, moov.end, b"trak") {
        let Some(handler) = track_handler(data, &trak) else {
            continue;
        };
        match &handler {
            b"vide" => {
                let duration = track_duration(data, &trak)?;
                video_duration = Some(video_duration.map_or(duration, |v: u64| v.max(duration)));
            }
            b"soun" => {
                has_audio_track = true;
                if audio_specific_config.is_none() {
                    audio_specific_config = track_audio_specific_config(data, &trak);
                }
            }
            _ => {}
        }
    }

    Ok(MovieFacts {
        timescale,
        duration,
        video_duration,
        has_audio_track,
        audio_specific_config,
    })
}

/// Overwrite `mvhd.duration` in place and return the value it replaced.
///
/// The field keeps its declared width, so the file's length and every chunk
/// offset in it are untouched — a `+faststart` layout stays faststart.
pub fn write_movie_duration(data: &mut [u8], duration: u64) -> Result<u64> {
    let moov = find_box(data, 0, data.len(), b"moov")
        .ok_or_else(|| anyhow!("no moov box: not a readable MP4"))?;
    let mvhd = find_box(data, moov.start, moov.end, b"mvhd")
        .ok_or_else(|| anyhow!("moov has no mvhd box"))?;
    let (_, previous, offset) = read_mvhd(data, &mvhd)?;

    if version_of(data, &mvhd)? == 1 {
        data[offset..offset + 8].copy_from_slice(&duration.to_be_bytes());
    } else {
        let narrowed = u32::try_from(duration)
            .map_err(|_| anyhow!("duration {duration} does not fit a version 0 mvhd"))?;
        data[offset..offset + 4].copy_from_slice(&narrowed.to_be_bytes());
    }

    Ok(previous)
}

/// A box's payload span — the bytes after its header, exclusive of nothing.
#[derive(Debug, Clone, Copy)]
struct BoxSpan {
    start: usize,
    end: usize,
}

/// Walk the boxes laid out between `start` and `end`, stopping at the first
/// malformed header rather than guessing past it.
fn boxes(data: &[u8], start: usize, end: usize) -> impl Iterator<Item = ([u8; 4], BoxSpan)> + '_ {
    let mut offset = start;
    let mut seen = 0usize;

    std::iter::from_fn(move || {
        if seen >= MAX_BOXES_SCANNED || offset + BOX_HEADER_LEN > end {
            return None;
        }
        seen += 1;

        let declared = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&data[offset + 4..offset + BOX_HEADER_LEN]);

        let (size, header_len) = match declared {
            // `size == 0` means the box runs to the end of the enclosing span.
            0 => (end - offset, BOX_HEADER_LEN),
            1 => {
                if offset + BOX_HEADER_LEN + LARGE_SIZE_LEN > end {
                    return None;
                }
                let large = offset + BOX_HEADER_LEN;
                let size = u64::from_be_bytes(data[large..large + 8].try_into().ok()?);
                (usize::try_from(size).ok()?, BOX_HEADER_LEN + LARGE_SIZE_LEN)
            }
            n => (n, BOX_HEADER_LEN),
        };

        // A box must at least contain its own header, and must fit the span;
        // anything else would stall or rewind the walk.
        if size < header_len || offset + size > end {
            return None;
        }

        let span = BoxSpan {
            start: offset + header_len,
            end: offset + size,
        };
        offset += size;
        Some((kind, span))
    })
}

fn find_box(data: &[u8], start: usize, end: usize, kind: &[u8; 4]) -> Option<BoxSpan> {
    boxes(data, start, end)
        .find(|(found, _)| found == kind)
        .map(|(_, span)| span)
}

fn boxes_of_type<'a>(
    data: &'a [u8],
    start: usize,
    end: usize,
    kind: &'a [u8; 4],
) -> impl Iterator<Item = BoxSpan> + 'a {
    boxes(data, start, end)
        .filter(move |(found, _)| found == kind)
        .map(|(_, span)| span)
}

/// A FullBox opens with a one-byte version and three flag bytes.
fn version_of(data: &[u8], span: &BoxSpan) -> Result<u8> {
    data.get(span.start)
        .copied()
        .ok_or_else(|| anyhow!("truncated full box header"))
}

fn read_u32(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or_else(|| anyhow!("truncated 32-bit field at {at}"))
}

fn read_u64(data: &[u8], at: usize) -> Result<u64> {
    data.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or_else(|| anyhow!("truncated 64-bit field at {at}"))
}

/// Returns `(timescale, duration, byte offset of the duration field)`.
fn read_mvhd(data: &[u8], mvhd: &BoxSpan) -> Result<(u32, u64, usize)> {
    // version(1) + flags(3), then creation and modification times whose width
    // follows the version, then timescale and duration.
    let after_flags = mvhd.start + 4;
    match version_of(data, mvhd)? {
        1 => {
            let timescale_at = after_flags + 16;
            let duration_at = timescale_at + 4;
            Ok((
                read_u32(data, timescale_at)?,
                read_u64(data, duration_at)?,
                duration_at,
            ))
        }
        _ => {
            let timescale_at = after_flags + 8;
            let duration_at = timescale_at + 4;
            Ok((
                read_u32(data, timescale_at)?,
                u64::from(read_u32(data, duration_at)?),
                duration_at,
            ))
        }
    }
}

/// `tkhd.duration` — the sum of the track's edits, in the movie timescale, so
/// it already accounts for any empty edit at the head of the track.
fn track_duration(data: &[u8], trak: &BoxSpan) -> Result<u64> {
    let tkhd = find_box(data, trak.start, trak.end, b"tkhd")
        .ok_or_else(|| anyhow!("trak has no tkhd box"))?;
    // version(1) + flags(3), creation and modification times, track_id(4),
    // reserved(4), then duration.
    let after_flags = tkhd.start + 4;
    match version_of(data, &tkhd)? {
        1 => read_u64(data, after_flags + 16 + 8),
        _ => Ok(u64::from(read_u32(data, after_flags + 8 + 8)?)),
    }
}

/// The `hdlr.handler_type` that says what kind of media a track carries.
fn track_handler(data: &[u8], trak: &BoxSpan) -> Option<[u8; 4]> {
    let mdia = find_box(data, trak.start, trak.end, b"mdia")?;
    let hdlr = find_box(data, mdia.start, mdia.end, b"hdlr")?;
    // version(1) + flags(3) + pre_defined(4), then handler_type.
    let at = hdlr.start + 8;
    data.get(at..at + 4)?.try_into().ok()
}

/// Pull the AudioSpecificConfig out of a sound track's `esds` descriptor.
fn track_audio_specific_config(data: &[u8], trak: &BoxSpan) -> Option<Vec<u8>> {
    let mdia = find_box(data, trak.start, trak.end, b"mdia")?;
    let minf = find_box(data, mdia.start, mdia.end, b"minf")?;
    let stbl = find_box(data, minf.start, minf.end, b"stbl")?;
    let stsd = find_box(data, stbl.start, stbl.end, b"stsd")?;

    // stsd is a FullBox followed by an entry count, then sample entries laid
    // out as ordinary boxes.
    let entries_start = stsd.start + 8;
    for (_, entry) in boxes(data, entries_start, stsd.end) {
        // AudioSampleEntry: reserved(6) + data_reference_index(2), then a
        // version-dependent block of legacy QuickTime sound fields, then the
        // child boxes we are after.
        let version = u16::from_be_bytes(
            data.get(entry.start + 8..entry.start + 10)?
                .try_into()
                .ok()?,
        );
        // Version 0 carries version(2), revision(2), vendor(4), channels(2),
        // sample size(2), compression ID(2), packet size(2) and a 16.16 sample
        // rate(4). Versions 1 and 2 append further QuickTime-era fields.
        let sound_fields = match version {
            1 => 20 + 16,
            2 => 20 + 36,
            _ => 20,
        };
        let children = entry.start + 8 + sound_fields;
        if children >= entry.end {
            continue;
        }
        if let Some(esds) = find_box(data, children, entry.end, b"esds") {
            // esds is a FullBox wrapping an MPEG-4 descriptor tree.
            return audio_specific_config_from_descriptors(&data[esds.start + 4..esds.end]);
        }
    }
    None
}

/// Descriptor tags from ISO/IEC 14496-1 that we have to walk through to reach
/// the decoder config.
const TAG_ES_DESCRIPTOR: u8 = 0x03;
const TAG_DECODER_CONFIG_DESCRIPTOR: u8 = 0x04;
const TAG_DECODER_SPECIFIC_INFO: u8 = 0x05;

fn audio_specific_config_from_descriptors(data: &[u8]) -> Option<Vec<u8>> {
    if *data.first()? != TAG_ES_DESCRIPTOR {
        return None;
    }
    let mut at = read_descriptor_length(data, 1)?.1;
    // ES_ID(2), then a flags byte whose bits each add an optional field.
    let flags = *data.get(at + 2)?;
    at += 3;
    if flags & 0x80 != 0 {
        at += 2; // dependsOn_ES_ID
    }
    if flags & 0x40 != 0 {
        at += 1 + usize::from(*data.get(at)?); // URL length prefix, then URL
    }
    if flags & 0x20 != 0 {
        at += 2; // OCR_ES_Id
    }

    if *data.get(at)? != TAG_DECODER_CONFIG_DESCRIPTOR {
        return None;
    }
    at = read_descriptor_length(data, at + 1)?.1;
    // objectTypeIndication(1), streamType/upStream/reserved(1),
    // bufferSizeDB(3), maxBitrate(4), avgBitrate(4).
    at += 13;

    if *data.get(at)? != TAG_DECODER_SPECIFIC_INFO {
        return None;
    }
    let (length, at) = read_descriptor_length(data, at + 1)?;
    data.get(at..at + length).map(<[u8]>::to_vec)
}

/// MPEG-4 descriptor lengths are 7 bits per byte, high bit meaning "another
/// byte follows". Returns `(length, offset just past the length bytes)`.
fn read_descriptor_length(data: &[u8], mut at: usize) -> Option<(usize, usize)> {
    let mut length = 0usize;
    for _ in 0..4 {
        let byte = *data.get(at)?;
        at += 1;
        length = (length << 7) | usize::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some((length, at));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap `payload` in a box header of `kind`.
    fn boxed(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out
    }

    fn mvhd_v0(timescale: u32, duration: u32) -> Vec<u8> {
        let mut payload = vec![0u8; 4]; // version 0 + flags
        payload.extend_from_slice(&0u32.to_be_bytes()); // creation_time
        payload.extend_from_slice(&0u32.to_be_bytes()); // modification_time
        payload.extend_from_slice(&timescale.to_be_bytes());
        payload.extend_from_slice(&duration.to_be_bytes());
        payload.extend_from_slice(&[0u8; 80]); // rate, volume, matrix, next_track_ID
        boxed(b"mvhd", &payload)
    }

    fn mvhd_v1(timescale: u32, duration: u64) -> Vec<u8> {
        let mut payload = vec![1u8, 0, 0, 0]; // version 1 + flags
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&timescale.to_be_bytes());
        payload.extend_from_slice(&duration.to_be_bytes());
        payload.extend_from_slice(&[0u8; 80]);
        boxed(b"mvhd", &payload)
    }

    fn tkhd_v0(duration: u32) -> Vec<u8> {
        let mut payload = vec![0u8; 4];
        payload.extend_from_slice(&0u32.to_be_bytes()); // creation_time
        payload.extend_from_slice(&0u32.to_be_bytes()); // modification_time
        payload.extend_from_slice(&1u32.to_be_bytes()); // track_ID
        payload.extend_from_slice(&0u32.to_be_bytes()); // reserved
        payload.extend_from_slice(&duration.to_be_bytes());
        payload.extend_from_slice(&[0u8; 60]);
        boxed(b"tkhd", &payload)
    }

    fn tkhd_v1(duration: u64) -> Vec<u8> {
        let mut payload = vec![1u8, 0, 0, 0];
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&0u64.to_be_bytes());
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&duration.to_be_bytes());
        payload.extend_from_slice(&[0u8; 60]);
        boxed(b"tkhd", &payload)
    }

    fn hdlr(handler: &[u8; 4]) -> Vec<u8> {
        let mut payload = vec![0u8; 8]; // version + flags + pre_defined
        payload.extend_from_slice(handler);
        payload.extend_from_slice(&[0u8; 12]); // reserved
        payload.push(0); // empty name
        boxed(b"hdlr", &payload)
    }

    /// A one-byte-length descriptor: tag, length, body.
    fn descriptor(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    fn esds(asc: &[u8]) -> Vec<u8> {
        let dsi = descriptor(TAG_DECODER_SPECIFIC_INFO, asc);
        let mut decoder_config = vec![0x40, 0x15]; // AAC object type, audio stream
        decoder_config.extend_from_slice(&[0, 0, 0]); // bufferSizeDB
        decoder_config.extend_from_slice(&0u32.to_be_bytes()); // maxBitrate
        decoder_config.extend_from_slice(&0u32.to_be_bytes()); // avgBitrate
        decoder_config.extend_from_slice(&dsi);
        let dcd = descriptor(TAG_DECODER_CONFIG_DESCRIPTOR, &decoder_config);

        let mut es = vec![0x00, 0x01, 0x00]; // ES_ID(2), flags(1) with nothing optional
        es.extend_from_slice(&dcd);
        let esd = descriptor(TAG_ES_DESCRIPTOR, &es);

        let mut payload = vec![0u8; 4]; // FullBox version + flags
        payload.extend_from_slice(&esd);
        boxed(b"esds", &payload)
    }

    fn mp4a_stsd(asc_box: Option<Vec<u8>>) -> Vec<u8> {
        let mut entry = vec![0u8; 6]; // reserved
        entry.extend_from_slice(&1u16.to_be_bytes()); // data_reference_index
        entry.extend_from_slice(&[0u8; 20]); // version 0 sound fields
        if let Some(child) = asc_box {
            entry.extend_from_slice(&child);
        }
        let sample_entry = boxed(b"mp4a", &entry);

        let mut payload = vec![0u8; 4]; // FullBox version + flags
        payload.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        payload.extend_from_slice(&sample_entry);
        boxed(b"stsd", &payload)
    }

    fn trak(handler: &[u8; 4], tkhd: Vec<u8>, stsd: Option<Vec<u8>>) -> Vec<u8> {
        let mut stbl_payload = Vec::new();
        if let Some(stsd) = stsd {
            stbl_payload.extend_from_slice(&stsd);
        }
        let stbl = boxed(b"stbl", &stbl_payload);
        let minf = boxed(b"minf", &stbl);

        let mut mdia_payload = hdlr(handler);
        mdia_payload.extend_from_slice(&minf);
        let mdia = boxed(b"mdia", &mdia_payload);

        let mut payload = tkhd;
        payload.extend_from_slice(&mdia);
        boxed(b"trak", &payload)
    }

    /// A file shaped like the transcoder's own output: `ftyp`, then a `moov`
    /// whose sound track outlives the picture, then `mdat`.
    fn video_with_longer_audio() -> Vec<u8> {
        let mut moov = mvhd_v0(1000, 3135);
        moov.extend_from_slice(&trak(b"vide", tkhd_v0(3124), None));
        moov.extend_from_slice(&trak(
            b"soun",
            tkhd_v0(3135),
            Some(mp4a_stsd(Some(esds(&[0x12, 0x08])))),
        ));

        let mut file = boxed(b"ftyp", b"isom\0\0\x02\0isom");
        file.extend_from_slice(&boxed(b"moov", &moov));
        file.extend_from_slice(&boxed(b"mdat", &[0u8; 32]));
        file
    }

    #[test]
    fn reads_the_movie_and_track_durations() {
        let facts = read_movie_facts(&video_with_longer_audio()).unwrap();
        assert_eq!(facts.timescale, 1000);
        assert_eq!(facts.duration, 3135);
        assert_eq!(facts.video_duration, Some(3124));
        assert!(facts.has_audio_track);
    }

    #[test]
    fn overhang_is_how_far_the_movie_outlives_the_picture() {
        // The defect this module exists for: 11 ms of movie with no video
        // sample behind it, which a looping player spends holding a frame.
        let facts = read_movie_facts(&video_with_longer_audio()).unwrap();
        assert_eq!(facts.video_overhang(), 11);
    }

    #[test]
    fn clamping_the_movie_duration_removes_the_overhang() {
        let mut data = video_with_longer_audio();
        let before = data.len();
        let video = read_movie_facts(&data).unwrap().video_duration.unwrap();

        assert_eq!(write_movie_duration(&mut data, video).unwrap(), 3135);

        let facts = read_movie_facts(&data).unwrap();
        assert_eq!(facts.duration, 3124);
        assert_eq!(facts.video_overhang(), 0);
        // Nothing may move: a rewritten length would break every chunk offset
        // and undo the faststart layout.
        assert_eq!(data.len(), before);
        // The audio track keeps every sample it had; only the movie header
        // stopped claiming to run past the picture.
        assert!(facts.has_audio_track);
    }

    #[test]
    fn reads_and_writes_64_bit_movie_headers() {
        let mut moov = mvhd_v1(90_000, 5_000_000_000);
        moov.extend_from_slice(&trak(b"vide", tkhd_v1(4_000_000_000), None));
        let mut data = boxed(b"moov", &moov);

        let facts = read_movie_facts(&data).unwrap();
        assert_eq!(facts.duration, 5_000_000_000);
        assert_eq!(facts.video_duration, Some(4_000_000_000));

        write_movie_duration(&mut data, 4_000_000_000).unwrap();
        assert_eq!(read_movie_facts(&data).unwrap().duration, 4_000_000_000);
    }

    #[test]
    fn reads_the_audio_specific_config() {
        let facts = read_movie_facts(&video_with_longer_audio()).unwrap();
        assert_eq!(facts.audio_specific_config, Some(vec![0x12, 0x08]));
        assert!(facts.has_usable_audio_config());
    }

    #[test]
    fn accepts_the_five_byte_sbr_signalled_config() {
        // ffmpeg's native AAC encoder appends an explicit "SBR absent" marker.
        // It is the reason clips stall, but it is not a broken config, so the
        // usability check must not reject it.
        let mut moov = mvhd_v0(1000, 3135);
        moov.extend_from_slice(&trak(b"vide", tkhd_v0(3124), None));
        moov.extend_from_slice(&trak(
            b"soun",
            tkhd_v0(3135),
            Some(mp4a_stsd(Some(esds(&[0x12, 0x08, 0x56, 0xe5, 0x00])))),
        ));
        let data = boxed(b"moov", &moov);

        let facts = read_movie_facts(&data).unwrap();
        assert_eq!(
            facts.audio_specific_config,
            Some(vec![0x12, 0x08, 0x56, 0xe5, 0x00])
        );
        assert!(facts.has_usable_audio_config());
    }

    #[test]
    fn a_sound_track_without_a_decoder_config_is_not_usable() {
        let mut moov = mvhd_v0(1000, 3135);
        moov.extend_from_slice(&trak(b"soun", tkhd_v0(3135), Some(mp4a_stsd(None))));
        let data = boxed(b"moov", &moov);

        let facts = read_movie_facts(&data).unwrap();
        assert_eq!(facts.audio_specific_config, None);
        assert!(!facts.has_usable_audio_config());
    }

    #[test]
    fn a_file_with_no_audio_track_needs_no_decoder_config() {
        let mut moov = mvhd_v0(1000, 2000);
        moov.extend_from_slice(&trak(b"vide", tkhd_v0(2000), None));
        let data = boxed(b"moov", &moov);

        let facts = read_movie_facts(&data).unwrap();
        assert!(!facts.has_audio_track);
        assert!(facts.has_usable_audio_config());
        assert_eq!(facts.video_overhang(), 0);
    }

    #[test]
    fn a_movie_with_no_video_track_has_nothing_to_clamp_to() {
        let mut moov = mvhd_v0(1000, 3135);
        moov.extend_from_slice(&trak(
            b"soun",
            tkhd_v0(3135),
            Some(mp4a_stsd(Some(esds(&[0x12, 0x08])))),
        ));
        let data = boxed(b"moov", &moov);

        let facts = read_movie_facts(&data).unwrap();
        assert_eq!(facts.video_duration, None);
        assert_eq!(facts.video_overhang(), 0);
    }

    #[test]
    fn non_mp4_bytes_are_an_error_rather_than_a_guess() {
        assert!(read_movie_facts(b"not an mp4 at all").is_err());
        assert!(read_movie_facts(&[]).is_err());
    }

    #[test]
    fn a_box_that_overruns_its_parent_stops_the_walk() {
        // A `moov` whose child claims more bytes than the parent holds must
        // not be read as a valid header.
        let mut moov = mvhd_v0(1000, 1000);
        let overrun = u32::MAX.to_be_bytes();
        moov[0..4].copy_from_slice(&overrun);
        let data = boxed(b"moov", &moov);

        assert!(read_movie_facts(&data).is_err());
    }

    #[test]
    fn descriptor_lengths_spanning_multiple_bytes_are_decoded() {
        // 0x81 0x00 is the four-byte-capable form of the value 128.
        assert_eq!(read_descriptor_length(&[0x81, 0x00], 0), Some((128, 2)));
        assert_eq!(read_descriptor_length(&[0x05], 0), Some((5, 1)));
        // A run of continuation bytes with no terminator is malformed.
        assert_eq!(read_descriptor_length(&[0x80; 8], 0), None);
    }
}

// ABOUTME: Minimal ISO-BMFF top-level box scanner
// ABOUTME: Answers whether an MP4's moov box precedes its mdat box (faststart)

/// Header layout per ISO/IEC 14496-12: a 32-bit size, then a 4-byte type.
const BOX_HEADER_LEN: u64 = 8;
/// `size == 1` means the real size follows the type as a 64-bit value.
const LARGE_SIZE_LEN: u64 = 8;
/// Cap the scan so a malformed file cannot spin us through millions of boxes.
const MAX_BOXES_SCANNED: usize = 1024;

/// Whether the video is already laid out for progressive streaming.
///
/// Returns `Some(true)` when `moov` appears before `mdat`, `Some(false)` when
/// `mdat` comes first, and `None` when the bytes are not a recognisable
/// ISO-BMFF file — a non-MP4 container, or a structure we cannot walk. Callers
/// should treat `None` as "unknown", not as "not faststart".
///
/// This only walks top-level box headers, so it never reads sample data and
/// runs in microseconds regardless of video size.
pub fn is_faststart(data: &[u8]) -> Option<bool> {
    if !starts_with_iso_bmff_box(data) {
        return None;
    }

    let total = data.len() as u64;
    let mut offset: u64 = 0;

    for _ in 0..MAX_BOXES_SCANNED {
        if offset >= total {
            break;
        }
        if total - offset < BOX_HEADER_LEN {
            return None;
        }

        let start = offset as usize;
        let declared = u32::from_be_bytes(data[start..start + 4].try_into().ok()?) as u64;
        let box_type = &data[start + 4..start + 8];

        match box_type {
            b"moov" => return Some(true),
            b"mdat" => return Some(false),
            _ => {}
        }

        let (size, header_len) = match declared {
            // `size == 0` means the box runs to end of file, so nothing we care
            // about can follow it.
            0 => return None,
            1 => {
                if total - offset < BOX_HEADER_LEN + LARGE_SIZE_LEN {
                    return None;
                }
                let large = start + BOX_HEADER_LEN as usize;
                let size = u64::from_be_bytes(data[large..large + 8].try_into().ok()?);
                (size, BOX_HEADER_LEN + LARGE_SIZE_LEN)
            }
            n => (n, BOX_HEADER_LEN),
        };

        // A box must at least contain its own header — 16 bytes in the
        // large-size form; anything smaller would stall or rewind the scan.
        if size < header_len {
            return None;
        }

        offset = offset.checked_add(size)?;
    }

    None
}

/// Cheap sanity gate: the first box must have a plausible size and a type made
/// of printable ASCII, which rules out webm, raw streams and truncated files.
fn starts_with_iso_bmff_box(data: &[u8]) -> bool {
    if data.len() < BOX_HEADER_LEN as usize {
        return false;
    }
    let declared = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if declared != 1 && (declared as u64) < BOX_HEADER_LEN {
        return false;
    }
    data[4..8]
        .iter()
        .all(|b| b.is_ascii_graphic() || *b == b' ')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a top-level box with the given type and payload length.
    fn boxed(box_type: &[u8; 4], payload_len: usize) -> Vec<u8> {
        let size = BOX_HEADER_LEN as usize + payload_len;
        let mut out = (size as u32).to_be_bytes().to_vec();
        out.extend_from_slice(box_type);
        out.extend(std::iter::repeat_n(0u8, payload_len));
        out
    }

    fn ftyp() -> Vec<u8> {
        boxed(b"ftyp", 24)
    }

    #[test]
    fn reports_faststart_when_moov_precedes_mdat() {
        let mut data = ftyp();
        data.extend(boxed(b"moov", 64));
        data.extend(boxed(b"mdat", 512));

        assert_eq!(is_faststart(&data), Some(true));
    }

    #[test]
    fn reports_not_faststart_when_mdat_precedes_moov() {
        let mut data = ftyp();
        data.extend(boxed(b"mdat", 512));
        data.extend(boxed(b"moov", 64));

        assert_eq!(is_faststart(&data), Some(false));
    }

    #[test]
    fn skips_free_boxes_before_reaching_moov() {
        let mut data = ftyp();
        data.extend(boxed(b"free", 128));
        data.extend(boxed(b"moov", 64));
        data.extend(boxed(b"mdat", 512));

        assert_eq!(is_faststart(&data), Some(true));
    }

    #[test]
    fn handles_64_bit_large_size_boxes() {
        let mut data = ftyp();
        // A `size == 1` box carries its real length in the following 8 bytes.
        let payload = 40usize;
        let total = BOX_HEADER_LEN as usize + LARGE_SIZE_LEN as usize + payload;
        data.extend(1u32.to_be_bytes());
        data.extend(b"skip");
        data.extend((total as u64).to_be_bytes());
        data.extend(std::iter::repeat_n(0u8, payload));
        data.extend(boxed(b"moov", 32));

        assert_eq!(is_faststart(&data), Some(true));
    }

    #[test]
    fn returns_none_for_non_mp4_bytes() {
        // WebM starts with an EBML header, not an ISO-BMFF box.
        let webm = [0x1A, 0x45, 0xDF, 0xA3, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(is_faststart(&webm), None);
    }

    #[test]
    fn returns_none_for_truncated_input() {
        assert_eq!(is_faststart(&[]), None);
        assert_eq!(is_faststart(&[0, 0, 0, 24, b'f', b't']), None);
    }

    #[test]
    fn returns_none_when_neither_box_is_present() {
        let mut data = ftyp();
        data.extend(boxed(b"free", 32));

        assert_eq!(is_faststart(&data), None);
    }

    #[test]
    fn returns_none_on_zero_sized_box_rather_than_looping() {
        let mut data = ftyp();
        data.extend(0u32.to_be_bytes());
        data.extend(b"junk");
        data.extend(boxed(b"moov", 32));

        assert_eq!(is_faststart(&data), None);
    }

    #[test]
    fn returns_none_on_undersized_box_rather_than_stalling() {
        let mut data = ftyp();
        // A declared size below the 8-byte header would never advance.
        data.extend(4u32.to_be_bytes());
        data.extend(b"junk");

        assert_eq!(is_faststart(&data), None);
    }

    #[test]
    fn returns_none_on_undersized_large_size_box_rather_than_rewinding() {
        let mut data = ftyp();
        // The large-size form spends 16 bytes on its own header. A declared
        // size of 12 used to advance the scan only 12 bytes, landing it on
        // bytes the file controls — which here spell a fake `moov`.
        data.extend(1u32.to_be_bytes());
        data.extend(b"junk");
        data.extend(12u64.to_be_bytes());
        data.extend(b"moov");
        data.extend(boxed(b"mdat", 16));

        assert_eq!(is_faststart(&data), None);
    }
}

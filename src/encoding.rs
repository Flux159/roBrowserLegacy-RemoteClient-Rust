//! Encoding helpers for GRF filenames.
//!
//! GRF entry names are CP949 (Korean) bytes.  roBrowser asks for them as those
//! same bytes reinterpreted as ISO-8859-1 — "mojibake".  Everything in here
//! exists to move between the three spellings of one name:
//!
//! * raw bytes            `\xC0\xCE\xB0\xA3\xC1\xB7`
//! * Korean Unicode       `인간족`
//! * mojibake             `ÀÎ°£Á·`

use encoding_rs::EUC_KR;

/// Decode bytes as true ISO-8859-1: every byte maps to the codepoint of the
/// same value.  This is *not* windows-1252 — the 0x80..=0x9F range must stay
/// as C1 controls or the round trip through CP949 breaks.
pub fn latin1_decode(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

/// Encode a string as ISO-8859-1, substituting `?` for anything above U+00FF
/// (this is what iconv-lite does, and the reference relies on it).
pub fn latin1_encode(s: &str) -> Vec<u8> {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            if cp <= 0xFF {
                cp as u8
            } else {
                b'?'
            }
        })
        .collect()
}

/// Decode CP949/UHC.  `encoding_rs`' EUC-KR is the WHATWG variant, which
/// covers the full CP949 lead-byte range (0x81..=0xFE), not just EUC-KR.
pub fn cp949_decode(bytes: &[u8]) -> String {
    let (cow, _, _) = EUC_KR.decode(bytes);
    cow.into_owned()
}

/// Encode to CP949/UHC.
pub fn cp949_encode(s: &str) -> Vec<u8> {
    let (cow, _, _) = EUC_KR.encode(s);
    cow.into_owned()
}

/// Decode UTF-8 the way `TextDecoder('utf-8', {fatal:false})` does: invalid
/// sequences become U+FFFD rather than an error.
pub fn utf8_decode_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `ÀÎ°£Á·` -> `인간족`.  Reverses the client's mojibake spelling.
pub fn decode_mojibake(s: &str) -> String {
    cp949_decode(&latin1_encode(s))
}

/// `인간족` -> `ÀÎ°£Á·`.  Produces the spelling the client will ask for.
pub fn to_mojibake(s: &str) -> String {
    latin1_decode(&cp949_encode(s))
}

/// Count characters that signal a wrong decode: U+FFFD replacements and C1
/// controls (which is what a CP949 extended byte turns into under EUC-KR).
pub fn count_bad_chars(s: &str) -> usize {
    s.chars()
        .filter(|&c| c == '\u{FFFD}' || ('\u{80}'..='\u{9F}').contains(&c))
        .count()
}

/// Filename encodings the GRF loader can pick between.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilenameEncoding {
    Utf8,
    Cp949,
}

impl FilenameEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            FilenameEncoding::Utf8 => "utf-8",
            FilenameEncoding::Cp949 => "cp949",
        }
    }

    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            FilenameEncoding::Utf8 => utf8_decode_lossy(bytes),
            FilenameEncoding::Cp949 => cp949_decode(bytes),
        }
    }
}

/// Port of the reference loader's `detectBestKoreanEncoding`.
///
/// Samples names that actually contain high bytes, decodes them both ways and
/// keeps whichever produces fewer bad characters per byte.  Pure-ASCII archives
/// resolve to UTF-8, which decodes identically anyway.
pub fn detect_best_encoding(samples: &[&[u8]], threshold: f64) -> FilenameEncoding {
    if samples.is_empty() {
        return FilenameEncoding::Utf8;
    }

    let mut utf8_bad = 0usize;
    let mut cp949_bad = 0usize;
    let mut total_bytes = 0usize;
    let mut samples_with_high_bytes = 0usize;

    for bytes in samples {
        if !bytes.iter().any(|&b| b > 0x7F) {
            continue;
        }
        samples_with_high_bytes += 1;
        total_bytes += bytes.len();
        utf8_bad += count_bad_chars(&utf8_decode_lossy(bytes));
        cp949_bad += count_bad_chars(&cp949_decode(bytes));
    }

    if samples_with_high_bytes == 0 {
        return FilenameEncoding::Utf8;
    }

    let utf8_ratio = utf8_bad as f64 / total_bytes as f64;
    let cp949_ratio = cp949_bad as f64 / total_bytes as f64;

    if utf8_ratio < threshold {
        return FilenameEncoding::Utf8;
    }
    if cp949_ratio < utf8_ratio {
        return FilenameEncoding::Cp949;
    }
    FilenameEncoding::Utf8
}

/// Lowercase the way JavaScript's `String.prototype.toLowerCase` does.  Full
/// Unicode, not ASCII-only — mojibake names are full of Latin-1 letters whose
/// case folding the index and the request path must agree on.
pub fn js_lowercase(s: &str) -> String {
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        s.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin1_round_trips_every_byte() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(latin1_encode(&latin1_decode(&bytes)), bytes);
    }

    #[test]
    fn mojibake_round_trip() {
        let korean = "인간족";
        let moji = to_mojibake(korean);
        assert_eq!(moji, "ÀÎ°£Á·");
        assert_eq!(decode_mojibake(&moji), korean);
    }

    #[test]
    fn mojibake_of_user_interface_directory() {
        // The single most-requested Korean directory in the client.
        assert_eq!(to_mojibake("유저인터페이스"), "À¯ÀúÀÎÅÍÆäÀÌ½º");
        assert_eq!(decode_mojibake("À¯ÀúÀÎÅÍÆäÀÌ½º"), "유저인터페이스");
    }

    #[test]
    fn ascii_is_unchanged_by_mojibake() {
        assert_eq!(to_mojibake("data/sprite/test.spr"), "data/sprite/test.spr");
    }

    #[test]
    fn detects_cp949_over_utf8() {
        let korean = cp949_encode("data\\sprite\\인간족\\검사\\검사_남.act");
        let samples = [korean.as_slice()];
        assert_eq!(
            detect_best_encoding(&samples, 0.01),
            FilenameEncoding::Cp949
        );
    }

    #[test]
    fn detects_utf8_for_ascii_only() {
        let samples: [&[u8]; 1] = [b"data\\sprite\\test.spr"];
        assert_eq!(detect_best_encoding(&samples, 0.01), FilenameEncoding::Utf8);
    }
}

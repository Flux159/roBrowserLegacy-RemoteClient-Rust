//! Small helpers with no home of their own.

use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Join a request-supplied relative path onto a root, refusing anything that
/// could escape it.  Every path in this server originates from an HTTP request,
/// including the ones that get written back to disk when auto-extract is on.
pub fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.contains('\0') {
        return None;
    }

    let normalised = rel.replace('\\', "/");
    let mut out = root.to_path_buf();

    for part in normalised.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return None;
        }
        let candidate = Path::new(part);
        // A single path segment must be exactly one normal component; anything
        // else is a Windows drive prefix or a root marker sneaking through.
        let mut components = candidate.components();
        match (components.next(), components.next()) {
            (Some(Component::Normal(c)), None) => out.push(c),
            _ => return None,
        }
    }

    Some(out)
}

/// RFC 3339 timestamp in UTC, e.g. `2026-08-25T10:54:00.000Z` — the same shape
/// `Date.prototype.toISOString` produces, since the missing-files log is
/// consumed as JSON lines by whatever was reading the reference's output.
pub fn iso_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    iso_from_unix(now.as_secs() as i64, now.subsec_millis())
}

pub fn iso_from_unix(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        millis
    )
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding, as `Buffer.toString('base64')` produces.
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(BASE64_ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            BASE64_ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            BASE64_ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Lower-case extension without the dot, or `""`.
pub fn extension_of(path: &str) -> String {
    let tail = path.rsplit(['/', '\\']).next().unwrap_or(path);
    match tail.rfind('.') {
        Some(i) if i + 1 < tail.len() => tail[i + 1..].to_ascii_lowercase(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_accepts_ordinary_paths() {
        let root = Path::new("/srv");
        assert_eq!(
            safe_join(root, "data/sprite/foo.spr").unwrap(),
            Path::new("/srv/data/sprite/foo.spr")
        );
        assert_eq!(
            safe_join(root, "data\\sprite\\foo.spr").unwrap(),
            Path::new("/srv/data/sprite/foo.spr")
        );
    }

    #[test]
    fn safe_join_refuses_traversal() {
        let root = Path::new("/srv");
        assert!(safe_join(root, "../etc/passwd").is_none());
        assert!(safe_join(root, "data/../../etc/passwd").is_none());
        assert!(safe_join(root, "data\\..\\..\\etc").is_none());
        assert!(safe_join(root, "a\0b").is_none());
    }

    #[test]
    fn safe_join_ignores_leading_and_doubled_slashes() {
        let root = Path::new("/srv");
        assert_eq!(
            safe_join(root, "/data//sprite/./foo.spr").unwrap(),
            Path::new("/srv/data/sprite/foo.spr")
        );
    }

    #[test]
    fn iso_formats_the_epoch() {
        assert_eq!(iso_from_unix(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso_from_unix(1_756_119_240, 123),
            "2025-08-25T10:54:00.123Z"
        );
    }

    #[test]
    fn base64_matches_node() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    fn extensions() {
        assert_eq!(extension_of("data/sprite/a.SPR"), "spr");
        assert_eq!(extension_of("data\\a.act"), "act");
        assert_eq!(extension_of("noext"), "");
        assert_eq!(extension_of("trailing."), "");
        assert_eq!(extension_of("dir.with.dot/file"), "");
    }
}

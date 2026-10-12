//! Smaller pictures for players on a slow link.
//!
//! The map and window textures are 8-bit BMPs, and brotli takes only about
//! half off them: a remote player on a 10 Mbps link spends most of a map load
//! waiting for them.  No lossless format does much better, so a request that
//! carries [`HEADER`] gets a lossy WebP of a BMP or JPEG instead, made once
//! and kept with the cached file like the content codings.
//!
//! The header is opt-in and set by whatever sits in front of the server for
//! remote players (the app's sharing gateway).  A client on the same machine
//! never sends it and keeps the exact files.
//!
//! The client keys magenta out of BMPs after decoding them.  Lossy compression
//! smears that key into its neighbours, so it is applied here first, with the
//! client's own test (`Texture.removeMagenta`), and the WebP carries a lossless
//! alpha channel instead.

use axum::http::HeaderMap;

use crate::util::extension_of;

/// Request header asking for the compact form of pictures.
pub const HEADER: &str = "x-compact-images";

/// Pictures smaller than this are mostly header and stay as they are.
const MIN_BYTES: usize = 4096;

/// The largest picture worth decoding: 4096 x 4096 RGBA.
const MAX_PIXELS: u64 = 4096 * 4096;

/// True when this request asked for compact pictures and `path` is one.
pub fn wanted(headers: &HeaderMap, path: &str, len: usize, quality: u8) -> bool {
    quality > 0
        && len >= MIN_BYTES
        && matches!(extension_of(path).as_str(), "bmp" | "jpg" | "jpeg")
        && headers
            .get(HEADER)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == "1")
}

/// The ETag of the compact form, kept apart from the original's so that a
/// revalidation never matches the other one.
pub fn etag(etag: &str, quality: u8) -> String {
    format!("{etag}-w{quality}")
}

/// `data` as a lossy WebP at `quality` (1-100), or `None` when it does not
/// decode or does not come out smaller.  A few milliseconds for a 256x256
/// texture, so call it off the async workers.
pub fn transcode(path: &str, data: &[u8], quality: u8) -> Option<Vec<u8>> {
    let format = match extension_of(path).as_str() {
        "bmp" => image::ImageFormat::Bmp,
        "jpg" | "jpeg" => image::ImageFormat::Jpeg,
        _ => return None,
    };
    let mut reader = image::ImageReader::with_format(std::io::Cursor::new(data), format);
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(MAX_PIXELS * 4);
    reader.limits(limits);
    let decoded = reader.decode().ok()?;
    let (width, height) = (decoded.width(), decoded.height());
    if width == 0 || height == 0 || u64::from(width) * u64::from(height) > MAX_PIXELS {
        return None;
    }

    let mut rgba = decoded.into_rgba8().into_raw();
    let keyed = format == image::ImageFormat::Bmp && remove_magenta(&mut rgba);
    let quality = f32::from(quality.min(100));
    let out = if keyed {
        webp::Encoder::from_rgba(&rgba, width, height).encode_simple(false, quality)
    } else {
        let rgb: Vec<u8> = rgba
            .chunks_exact(4)
            .flat_map(|p| [p[0], p[1], p[2]])
            .collect();
        webp::Encoder::from_rgb(&rgb, width, height).encode_simple(false, quality)
    }
    .ok()?;
    (out.len() < data.len()).then(|| out.to_vec())
}

/// Clear every pixel the client would key out, exactly as
/// `Texture.removeMagenta` does; true when there was one.
fn remove_magenta(rgba: &mut [u8]) -> bool {
    let mut any = false;
    for p in rgba.chunks_exact_mut(4) {
        if p[0] > 230 && p[1] < 20 && p[2] > 230 {
            p.copy_from_slice(&[0, 0, 0, 0]);
            any = true;
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    /// A 64x64 24-bit BMP: a noisy gradient with a magenta square in it.
    fn bmp(magenta: bool) -> Vec<u8> {
        let (w, h) = (64u32, 64u32);
        let row = (w * 3).div_ceil(4) * 4;
        let size = 54 + row * h;
        let mut out = Vec::new();
        out.extend_from_slice(b"BM");
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&54u32.to_le_bytes());
        out.extend_from_slice(&40u32.to_le_bytes());
        out.extend_from_slice(&w.to_le_bytes());
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&24u16.to_le_bytes());
        out.extend_from_slice(&[0; 24]);
        for y in 0..h {
            for x in 0..w {
                let inside = magenta && (16..48).contains(&x) && (16..48).contains(&y);
                let px = if inside {
                    [255, 0, 255]
                } else {
                    let n = ((x * 7 + y * 13) % 17) as u8;
                    [(x * 4) as u8 ^ n, (y * 4) as u8, 128 + n]
                };
                out.extend_from_slice(&[px[2], px[1], px[0]]);
            }
            out.resize(out.len() + (row - w * 3) as usize, 0);
        }
        out
    }

    fn decode(webp: &[u8]) -> (u32, u32, Vec<u8>) {
        let image = webp::Decoder::new(webp).decode().expect("a WebP");
        (image.width(), image.height(), image.to_vec())
    }

    #[test]
    fn makes_a_smaller_webp_of_a_bmp() {
        let data = bmp(false);
        let out = transcode("data/texture/a.bmp", &data, 85).expect("transcoded");
        assert_eq!(&out[..4], b"RIFF");
        assert_eq!(&out[8..12], b"WEBP");
        assert!(out.len() < data.len());
        let (w, h, _) = decode(&out);
        assert_eq!((w, h), (64, 64));
    }

    #[test]
    fn keys_magenta_into_alpha_before_compressing() {
        let out = transcode("data/texture/a.bmp", &bmp(true), 85).expect("transcoded");
        let (w, _, px) = decode(&out);
        let at = |x: u32, y: u32| {
            let i = ((y * w + x) * 4) as usize;
            [px[i], px[i + 1], px[i + 2], px[i + 3]]
        };
        assert_eq!(at(32, 32)[3], 0, "inside the key is transparent");
        assert_eq!(at(16, 16)[3], 0, "its edge too");
        assert_eq!(at(4, 4)[3], 255, "the rest stays opaque");
        // Nothing the client would key out again is left behind.
        for p in px.chunks_exact(4).filter(|p| p[3] == 255) {
            assert!(!(p[0] > 230 && p[1] < 20 && p[2] > 230));
        }
    }

    #[test]
    fn leaves_what_it_cannot_read() {
        assert!(transcode("a.bmp", b"BM not really", 85).is_none());
        assert!(transcode("a.tga", &bmp(false), 85).is_none());
    }

    #[test]
    fn only_on_request_and_only_for_pictures() {
        let mut headers = HeaderMap::new();
        assert!(!wanted(&headers, "a.bmp", 10_000, 85));
        headers.insert(HEADER, HeaderValue::from_static("1"));
        assert!(wanted(&headers, "data/a.BMP", 10_000, 85));
        assert!(wanted(&headers, "a.jpg", 10_000, 85));
        assert!(!wanted(&headers, "a.png", 10_000, 85));
        assert!(!wanted(&headers, "a.spr", 10_000, 85));
        assert!(!wanted(&headers, "a.bmp", 100, 85), "too small to bother");
        assert!(!wanted(&headers, "a.bmp", 10_000, 0), "switched off");
        headers.insert(HEADER, HeaderValue::from_static("0"));
        assert!(!wanted(&headers, "a.bmp", 10_000, 85));
    }
}

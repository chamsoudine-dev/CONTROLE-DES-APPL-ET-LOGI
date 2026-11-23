//! Médias : conversion WebP (sans perte, pur Rust) + redimensionnement, et trait de stockage.
use async_trait::async_trait;
use cc_core::{CoreError, Result};
use image::{GenericImageView, ImageFormat};
use std::io::Cursor;

pub const MAX_INPUT: usize = 25 * 1024 * 1024;
pub const MAX_DIM: u32 = 2048;

/// Image convertie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebpImage {
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

/// Décode PNG/JPEG/GIF/BMP/WebP, redimensionne (côté max `max_dim`), encode en WebP.
pub fn to_webp(input: &[u8], max_dim: u32) -> Result<WebpImage> {
    if input.is_empty() || input.len() > MAX_INPUT {
        return Err(CoreError::Validation(
            "image vide ou trop volumineuse (25 Mio max)".into(),
        ));
    }
    let fmt = image::guess_format(input)
        .map_err(|_| CoreError::Validation("format d'image inconnu".into()))?;
    if !matches!(
        fmt,
        ImageFormat::Png
            | ImageFormat::Jpeg
            | ImageFormat::Gif
            | ImageFormat::Bmp
            | ImageFormat::WebP
    ) {
        return Err(CoreError::Validation(
            "format non pris en charge (PNG, JPEG, GIF, BMP, WebP)".into(),
        ));
    }
    let mut reader = image::ImageReader::with_format(Cursor::new(input), fmt);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(20_000);
    limits.max_image_height = Some(20_000);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    let img = reader
        .decode()
        .map_err(|_| CoreError::Validation("image illisible".into()))?;
    let img = if img.width() > max_dim || img.height() > max_dim {
        img.resize(max_dim, max_dim, image::imageops::FilterType::Lanczos3)
    } else {
        img
    };
    let (width, height) = img.dimensions();
    let mut out = Cursor::new(Vec::new());
    img.to_rgba8()
        .write_to(&mut out, ImageFormat::WebP)
        .map_err(|e| CoreError::Validation(format!("encodage WebP : {e}")))?;
    Ok(WebpImage {
        bytes: out.into_inner(),
        width,
        height,
    })
}

/// Nom de fichier sûr (`[a-z0-9-_]`, extension `.webp`).
pub fn safe_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = base.rsplit_once('.').map_or(base, |(s, _)| s);
    let mut s: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    s.truncate(80);
    let s = s.trim_matches('-');
    format!("{}.webp", if s.is_empty() { "image" } else { s })
}

/// Stockage de médias (Supabase Storage, Firebase Storage, Cloudinary).
#[async_trait]
pub trait MediaStore: Send + Sync {
    /// Envoie l'objet et renvoie son URL publique (ou signée).
    async fn upload(&self, path: &str, bytes: Vec<u8>, content_type: &str) -> Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbaImage::from_fn(w, h, |x, y| {
            image::Rgba([(x % 255) as u8, (y % 255) as u8, 128, 255])
        });
        let mut c = Cursor::new(Vec::new());
        img.write_to(&mut c, ImageFormat::Png).unwrap();
        c.into_inner()
    }

    #[test]
    fn converts_and_resizes() {
        let out = to_webp(&png(3000, 1500), 2048).unwrap();
        assert_eq!((out.width, out.height), (2048, 1024));
        assert_eq!(&out.bytes[..4], b"RIFF");
        assert_eq!(&out.bytes[8..12], b"WEBP");
        let small = to_webp(&png(10, 10), 2048).unwrap();
        assert_eq!((small.width, small.height), (10, 10));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(to_webp(b"", 10).is_err());
        assert!(to_webp(b"not an image at all", 10).is_err());
        assert!(to_webp(b"<svg xmlns='http://www.w3.org/2000/svg'/>", 10).is_err());
        let mut truncated = png(50, 50);
        truncated.truncate(60);
        assert!(to_webp(&truncated, 10).is_err());
    }

    #[test]
    fn filenames() {
        assert_eq!(safe_filename("Mon Logo.PNG"), "mon-logo.webp");
        assert_eq!(safe_filename("../../etc/passwd"), "passwd.webp");
        assert_eq!(safe_filename("C:\\x\\photo.jpg"), "photo.webp");
        assert_eq!(safe_filename("..."), "image.webp");
    }
}

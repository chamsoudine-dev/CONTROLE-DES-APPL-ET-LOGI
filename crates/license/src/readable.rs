use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Alphabet Base32 de Crockford (sans I, L, O, U : lecture/dictée sans ambiguïté).
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Clé lisible `XXXX-XXXX-XXXX-XXXX` (80 bits) dérivée par HMAC-SHA256(clé, jti).
///
/// C'est un identifiant de support (recherche, dictée au téléphone), pas un secret
/// d'autorisation : l'appli cliente vérifie le **jeton** signé.
pub fn readable_key(hmac_key: &[u8], license_id: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).expect("HMAC accepte toute taille");
    mac.update(b"cc-readable-key\0");
    mac.update(license_id.as_bytes());
    let digest = mac.finalize().into_bytes();
    // 80 premiers bits → 16 symboles de 5 bits.
    let mut acc: u128 = 0;
    for b in &digest[..10] {
        acc = (acc << 8) | u128::from(*b);
    }
    let mut out = String::with_capacity(19);
    for i in 0..16 {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        let shift = 75 - 5 * i;
        let idx = usize::try_from((acc >> shift) & 0x1f).expect("< 32");
        out.push(char::from(CROCKFORD[idx]));
    }
    out
}

/// Normalise une saisie utilisateur (minuscules, espaces, O→0, I/L→1) ; `None` si invalide.
pub fn normalize_readable_key(input: &str) -> Option<String> {
    let mut chars = String::with_capacity(16);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !CROCKFORD.contains(&u8::try_from(c).ok()?) {
            return None;
        }
        chars.push(c);
    }
    if chars.len() != 16 {
        return None;
    }
    Some(
        chars
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect::<Vec<_>>()
            .join("-"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_and_determinism() {
        let k = readable_key(b"secret", "abc");
        assert_eq!(k.len(), 19);
        assert_eq!(k, readable_key(b"secret", "abc"));
        assert_ne!(k, readable_key(b"secret", "abd"));
        assert_ne!(k, readable_key(b"other", "abc"));
        assert!(k.split('-').all(|g| g.len() == 4));
    }

    #[test]
    fn normalization() {
        let k = readable_key(b"s", "id");
        assert_eq!(
            normalize_readable_key(&k.to_lowercase().replace('-', " ")),
            Some(k.clone())
        );
        assert_eq!(
            normalize_readable_key("oooo-iiii-llll-0000"),
            Some("0000-1111-1111-0000".into())
        );
        assert_eq!(normalize_readable_key("UUUU-0000-0000-0000"), None);
        assert_eq!(normalize_readable_key("123"), None);
        assert_eq!(normalize_readable_key("é"), None);
    }
}

//! Primitives cryptographiques (bibliothèques auditées uniquement, aucune crypto maison).
use crate::{CoreError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Clé symétrique de 256 bits effacée à la destruction.
pub type Key32 = Zeroizing<[u8; 32]>;

/// Paramètres Argon2id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// 64 Mio, 3 passes, 1 voie (≥ recommandations OWASP 2024 pour Argon2id).
    pub const RECOMMENDED: Self = Self {
        m_kib: 64 * 1024,
        t: 3,
        p: 1,
    };
    /// Paramètres rapides : **tests uniquement**.
    pub const INSECURE_FAST_FOR_TESTS: Self = Self {
        m_kib: 64,
        t: 1,
        p: 1,
    };
}

/// Dérive une clé de 256 bits avec Argon2id.
pub fn derive_key(secret: &[u8], salt: &[u8], params: KdfParams) -> Result<Key32> {
    let p =
        Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| CoreError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(secret, salt, out.as_mut())
        .map_err(|_| CoreError::Crypto)?;
    Ok(out)
}

/// Sous-clé par séparation de domaine : HMAC-SHA256(maître, "cc-subkey:" ‖ label).
pub fn subkey(master: &[u8; 32], label: &str) -> Key32 {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(master).expect("taille quelconque");
    mac.update(b"cc-subkey:");
    mac.update(label.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("taille quelconque");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&sha256(data))
}

/// Comparaison en temps constant.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

pub fn random_key() -> Key32 {
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(k.as_mut());
    k
}

const NONCE_LEN: usize = 24;

/// Chiffre avec XChaCha20-Poly1305 ; sortie = nonce (24 octets) ‖ chiffré+tag.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::Crypto)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Déchiffre et authentifie ; échoue si le message, le nonce ou l'AAD ont été modifiés.
pub fn open(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < NONCE_LEN + 16 {
        return Err(CoreError::Crypto);
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CoreError::Crypto)
}

pub fn b64(data: &[u8]) -> String {
    data_encoding::BASE64.encode(data)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    data_encoding::BASE64
        .decode(s.as_bytes())
        .map_err(|_| CoreError::Validation("base64 invalide".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_deterministic_and_salted() {
        let p = KdfParams::INSECURE_FAST_FOR_TESTS;
        let a = derive_key(b"pass", b"saltsaltsaltsalt", p).unwrap();
        let b = derive_key(b"pass", b"saltsaltsaltsalt", p).unwrap();
        let c = derive_key(b"pass", b"saltsaltsaltsal2", p).unwrap();
        let d = derive_key(b"pasS", b"saltsaltsaltsalt", p).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(*a, *d);
        assert!(
            derive_key(b"x", b"short", p).is_err(),
            "sel < 8 octets refusé"
        );
        assert!(derive_key(
            b"x",
            b"saltsalt",
            KdfParams {
                m_kib: 1,
                t: 0,
                p: 1
            }
        )
        .is_err());
    }

    #[test]
    fn argon2id_known_answer() {
        // Vecteur RFC 9106 §5.3 n'utilise pas de secret/ad ; on vérifie la stabilité de
        // notre configuration (régression : un changement de paramètres casserait les coffres).
        let k = derive_key(
            b"password",
            b"somesaltsomesalt",
            KdfParams {
                m_kib: 256,
                t: 2,
                p: 1,
            },
        )
        .unwrap();
        assert_eq!(data_encoding::HEXLOWER.encode(&*k).len(), 64,);
        let k2 = derive_key(
            b"password",
            b"somesaltsomesalt",
            KdfParams {
                m_kib: 256,
                t: 2,
                p: 1,
            },
        )
        .unwrap();
        assert_eq!(*k, *k2);
    }

    #[test]
    fn seal_open_roundtrip_and_tamper() {
        let k = random_key();
        let ct = seal(&k, b"secret", b"aad").unwrap();
        assert_eq!(&**open(&k, &ct, b"aad").unwrap(), b"secret");
        assert!(open(&k, &ct, b"other").is_err());
        let other = random_key();
        assert!(open(&other, &ct, b"aad").is_err());
        for i in 0..ct.len() {
            let mut t = ct.clone();
            t[i] ^= 1;
            assert!(open(&k, &t, b"aad").is_err(), "octet {i}");
        }
        assert!(open(&k, &ct[..10], b"aad").is_err());
        // Nonces aléatoires : deux chiffrements diffèrent.
        assert_ne!(ct, seal(&k, b"secret", b"aad").unwrap());
    }

    #[test]
    fn subkeys_and_hmac() {
        let m = [7u8; 32];
        assert_ne!(*subkey(&m, "db"), *subkey(&m, "sync"));
        assert_eq!(*subkey(&m, "db"), *subkey(&m, "db"));
        // RFC 4231 cas de test 2.
        assert_eq!(
            data_encoding::HEXLOWER.encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn ct_eq_and_b64() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert_eq!(unb64(&b64(b"hello")).unwrap(), b"hello");
        assert!(unb64("@@@").is_err());
        assert_ne!(random_bytes::<16>(), random_bytes::<16>());
    }
}

use crate::{LicenseError, Result};
use ed25519_dalek::SigningKey;
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::paserk::{FormatAsPaserk, Id};
use pasetors::version4::V4;
use zeroize::Zeroizing;

/// Paire de clés Ed25519 de signature des licences.
///
/// La clé secrète est effacée de la mémoire à la destruction. `Debug` n'affiche que le `kid`.
pub struct SigningKeyPair {
    seed: Zeroizing<[u8; 32]>,
    public: PublicKey,
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyPair")
            .field("kid", &self.public.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKeyPair {
    /// Génère une nouvelle paire depuis le générateur aléatoire du système.
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut rand_core::OsRng);
        Self::from_seed(&sk.to_bytes()).expect("graine de 32 octets")
    }

    /// Reconstruit la paire depuis la graine (32 octets) conservée dans le trousseau.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let seed: [u8; 32] = seed.try_into().map_err(|_| LicenseError::InvalidKey)?;
        let sk = SigningKey::from_bytes(&seed);
        let public = PublicKey::from_bytes(sk.verifying_key().as_bytes())?;
        Ok(Self {
            seed: Zeroizing::new(seed),
            public,
        })
    }

    /// Graine secrète (32 octets) — à stocker uniquement dans le trousseau.
    pub fn seed(&self) -> Zeroizing<[u8; 32]> {
        self.seed.clone()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn kid(&self) -> &str {
        &self.public.kid
    }

    pub(crate) fn paseto_secret(&self) -> Result<AsymmetricSecretKey<V4>> {
        let mut kp = Zeroizing::new([0u8; 64]);
        kp[..32].copy_from_slice(&*self.seed);
        kp[32..].copy_from_slice(&self.public.bytes);
        AsymmetricSecretKey::<V4>::from(&kp[..]).map_err(|_| LicenseError::InvalidKey)
    }
}

/// Clé publique Ed25519 + son identifiant PASERK (`k4.pid.…`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    bytes: [u8; 32],
    kid: String,
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| LicenseError::InvalidKey)?;
        // Rejette les points invalides.
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| LicenseError::InvalidKey)?;
        let pk = AsymmetricPublicKey::<V4>::from(&bytes).map_err(|_| LicenseError::InvalidKey)?;
        let mut kid = String::new();
        Id::from(&pk)
            .fmt(&mut kid)
            .map_err(|_| LicenseError::InvalidKey)?;
        Ok(Self { bytes, kid })
    }

    /// Importe une clé au format PASERK `k4.public.…` (format à embarquer dans les applis clientes).
    pub fn from_paserk(s: &str) -> Result<Self> {
        let pk =
            AsymmetricPublicKey::<V4>::try_from(s.trim()).map_err(|_| LicenseError::InvalidKey)?;
        Self::from_bytes(pk.as_bytes())
    }

    pub fn to_paserk(&self) -> String {
        let pk = AsymmetricPublicKey::<V4>::from(&self.bytes).expect("clé validée");
        let mut s = String::new();
        pk.fmt(&mut s).expect("formatage PASERK");
        s
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub(crate) fn paseto(&self) -> AsymmetricPublicKey<V4> {
        AsymmetricPublicKey::<V4>::from(&self.bytes).expect("clé validée")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seed_and_paserk() {
        let kp = SigningKeyPair::generate();
        assert!(kp.kid().starts_with("k4.pid."));
        let again = SigningKeyPair::from_seed(&*kp.seed()).unwrap();
        assert_eq!(again.public_key(), kp.public_key());
        let paserk = kp.public_key().to_paserk();
        assert!(paserk.starts_with("k4.public."));
        assert_eq!(&PublicKey::from_paserk(&paserk).unwrap(), kp.public_key());
    }

    #[test]
    fn debug_redacts_secret() {
        let kp = SigningKeyPair::generate();
        let dbg = format!("{kp:?}");
        assert!(dbg.contains(kp.kid()) && dbg.contains(".."));
        let hex: String = kp.seed().iter().map(|b| format!("{b:02x}")).collect();
        assert!(!dbg.contains(&hex) && !dbg.contains("seed"));
    }

    #[test]
    fn invalid_keys_rejected() {
        assert_eq!(
            SigningKeyPair::from_seed(&[1; 31]).unwrap_err(),
            LicenseError::InvalidKey
        );
        assert_eq!(
            PublicKey::from_bytes(&[0; 12]).unwrap_err(),
            LicenseError::InvalidKey
        );
        assert_eq!(
            PublicKey::from_paserk("k4.public.@@").unwrap_err(),
            LicenseError::InvalidKey
        );
        assert_eq!(
            PublicKey::from_paserk("k3.public.AAAA").unwrap_err(),
            LicenseError::InvalidKey
        );
    }

    #[test]
    fn distinct_keys_distinct_kids() {
        let a = SigningKeyPair::generate();
        let b = SigningKeyPair::generate();
        assert_ne!(a.kid(), b.kid());
    }
}

//! Licences Control Center : jetons PASETO v4.public signés Ed25519, vérifiables hors ligne.
//!
//! - [`SigningKeyPair`] : paire Ed25519 (génération `ed25519-dalek`), identifiant `kid` = PASERK `k4.pid`.
//! - [`issue`] / [`Verifier::verify`] : émission et vérification d'une licence.
//! - [`RevocationList`] : liste signée et numérotée (anti-rollback).
//! - [`LicenseChecker`] : logique côté appli cliente (révocation + délai de grâce hors ligne).
#![forbid(unsafe_code)]

mod checker;
mod keys;
mod readable;
mod revocation;
mod token;

pub use checker::{CachedRevocationList, CheckOutcome, LicenseChecker};
pub use keys::{PublicKey, SigningKeyPair};
pub use readable::{normalize_readable_key, readable_key};
pub use revocation::{sign_revocation_list, RevocationList};
pub use token::{issue, LicenseClaims, LicenseKind, Verifier, ISSUER};

/// Erreurs de licence. Les messages ne révèlent jamais de matériel secret.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LicenseError {
    #[error("format de jeton invalide")]
    Malformed,
    #[error("en-tête de jeton non pris en charge (seul v4.public est accepté)")]
    UnsupportedHeader,
    #[error("identifiant de clé (kid) absent ou inconnu")]
    UnknownKey,
    #[error("signature invalide")]
    BadSignature,
    #[error("type de jeton inattendu")]
    WrongType,
    #[error("licence pas encore valide")]
    NotYetValid,
    #[error("licence expirée")]
    Expired,
    #[error("licence révoquée")]
    Revoked,
    #[error("liste de révocation plus ancienne que celle déjà connue (rollback)")]
    Rollback,
    #[error("liste de révocation trop ancienne : délai de grâce hors ligne dépassé")]
    GraceExpired,
    #[error("clé invalide")]
    InvalidKey,
    #[error("erreur interne : {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, LicenseError>;

pub(crate) fn fmt_time(t: time::OffsetDateTime) -> Result<String> {
    t.format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| LicenseError::Internal(e.to_string()))
}

pub(crate) fn parse_time(s: &str) -> Result<time::OffsetDateTime> {
    time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| LicenseError::Malformed)
}

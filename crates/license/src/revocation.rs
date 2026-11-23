use crate::token::footer_for;
use crate::{fmt_time, parse_time, LicenseError, Result, SigningKeyPair, Verifier, ISSUER};
use pasetors::claims::Claims;
use pasetors::public;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use time::OffsetDateTime;

const TYP_REVOCATION: &str = "cc.revocations.v1";

/// Liste de révocation signée, publiée dans un dépôt GitHub public.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    /// Numéro strictement croissant (anti-rollback).
    pub seq: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    /// Identifiants (jti) des licences révoquées.
    pub revoked: BTreeSet<String>,
}

impl RevocationList {
    pub fn is_revoked(&self, license_id: &str) -> bool {
        self.revoked.contains(license_id)
    }
}

fn internal<E: std::fmt::Display>(e: E) -> LicenseError {
    LicenseError::Internal(e.to_string())
}

/// Signe une liste de révocation (PASETO v4.public, même clé que les licences).
pub fn sign_revocation_list(kp: &SigningKeyPair, list: &RevocationList) -> Result<String> {
    let mut claims = Claims::new().map_err(internal)?;
    claims.issuer(ISSUER).map_err(internal)?;
    claims
        .issued_at(&fmt_time(list.issued_at)?)
        .map_err(internal)?;
    claims.non_expiring();
    claims
        .add_additional("typ", TYP_REVOCATION)
        .map_err(internal)?;
    claims.add_additional("seq", list.seq).map_err(internal)?;
    claims
        .add_additional(
            "revoked",
            serde_json::to_value(&list.revoked).map_err(internal)?,
        )
        .map_err(internal)?;
    public::sign(&kp.paseto_secret()?, &claims, Some(&footer_for(kp)?), None).map_err(internal)
}

impl Verifier {
    /// Vérifie et décode une liste de révocation signée.
    pub fn verify_revocation_list(&self, token: &str) -> Result<RevocationList> {
        let c = self.verify_raw(token, TYP_REVOCATION, 4 * 1024 * 1024)?;
        let seq = c
            .get_claim("seq")
            .and_then(serde_json::Value::as_u64)
            .ok_or(LicenseError::Malformed)?;
        let issued_at = parse_time(
            c.get_claim("iat")
                .and_then(serde_json::Value::as_str)
                .ok_or(LicenseError::Malformed)?,
        )?;
        let revoked: BTreeSet<String> = serde_json::from_value(
            c.get_claim("revoked")
                .cloned()
                .ok_or(LicenseError::Malformed)?,
        )
        .map_err(|_| LicenseError::Malformed)?;
        Ok(RevocationList {
            seq,
            issued_at,
            revoked,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{issue, LicenseClaims, LicenseKind};

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn sign_verify_list() {
        let kp = SigningKeyPair::generate();
        let list = RevocationList {
            seq: 3,
            issued_at: t0(),
            revoked: ["a".to_string(), "b".to_string()].into(),
        };
        let tok = sign_revocation_list(&kp, &list).unwrap();
        let v = Verifier::new([kp.public_key().clone()]);
        let got = v.verify_revocation_list(&tok).unwrap();
        assert_eq!(got, list);
        assert!(got.is_revoked("a") && !got.is_revoked("c"));
    }

    #[test]
    fn license_and_list_types_not_interchangeable() {
        let kp = SigningKeyPair::generate();
        let v = Verifier::new([kp.public_key().clone()]);
        let list = RevocationList {
            seq: 1,
            issued_at: t0(),
            revoked: BTreeSet::new(),
        };
        let tok = sign_revocation_list(&kp, &list).unwrap();
        assert_eq!(v.verify(&tok, t0()).unwrap_err(), LicenseError::WrongType);
        let lic = issue(
            &kp,
            &LicenseClaims::new("p", "P", "c", "C", LicenseKind::Perpetual, t0(), None),
        )
        .unwrap();
        assert_eq!(
            v.verify_revocation_list(&lic).unwrap_err(),
            LicenseError::WrongType
        );
    }

    #[test]
    fn large_list() {
        let kp = SigningKeyPair::generate();
        let revoked: BTreeSet<String> = (0..2000).map(|i| format!("{i:036}")).collect();
        let list = RevocationList {
            seq: 9,
            issued_at: t0(),
            revoked,
        };
        let tok = sign_revocation_list(&kp, &list).unwrap();
        assert!(tok.len() > 16 * 1024);
        let v = Verifier::new([kp.public_key().clone()]);
        assert_eq!(v.verify_revocation_list(&tok).unwrap().revoked.len(), 2000);
    }
}

//! SDK Rust de vérification **hors ligne** des licences Control Center.
//!
//! ```
//! use control_center_license::{LicenseChecker, Verifier, PublicKey};
//! # fn demo(token: &str, list: &str) -> Result<(), control_center_license::LicenseError> {
//! let verifier = Verifier::new([PublicKey::from_paserk("k4.public.…")?]);
//! let mut checker = LicenseChecker::new(verifier, 14);
//! checker.update_revocations(list, time::OffsetDateTime::now_utc())?; // liste téléchargée
//! let outcome = checker.check(token, time::OffsetDateTime::now_utc())?;
//! # let _ = outcome; Ok(()) }
//! ```
//!
//! Ce SDK n'expose que la **vérification** : la signature reste dans Control Center.
#![forbid(unsafe_code)]

pub use cc_license::{
    normalize_readable_key, CachedRevocationList, CheckOutcome, LicenseChecker, LicenseClaims,
    LicenseError, LicenseKind, PublicKey, RevocationList, Verifier, ISSUER,
};

#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;

    #[test]
    fn verifies_shared_fixtures() {
        let fx: serde_json::Value =
            serde_json::from_str(include_str!("../../fixtures.json")).unwrap();
        let s = |k: &str| fx[k].as_str().unwrap().to_owned();
        let t = |k: &str| OffsetDateTime::parse(&s(k), &Rfc3339).unwrap();
        let keys: Vec<PublicKey> = fx["public_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| PublicKey::from_paserk(k.as_str().unwrap()).unwrap())
            .collect();
        assert_eq!(keys[0].kid(), s("kid"));
        let mut c = LicenseChecker::new(Verifier::new(keys), 14);
        assert!(c.check(&s("valid"), t("t_valid")).is_ok());
        assert_eq!(
            c.check(&s("tampered"), t("t_valid")).unwrap_err(),
            LicenseError::BadSignature
        );
        c.update_revocations(&s("revocation_list_seq2_revokes_valid"), t("t_valid"))
            .unwrap();
        assert_eq!(
            c.check(&s("valid"), t("t_valid")).unwrap_err(),
            LicenseError::Revoked
        );
        assert_eq!(
            c.update_revocations(&s("revocation_list_seq1"), t("t_valid"))
                .unwrap_err(),
            LicenseError::Rollback
        );
    }
}

use crate::{fmt_time, parse_time, LicenseError, PublicKey, Result, SigningKeyPair};
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::footer::Footer;
use pasetors::paserk::Id;
use pasetors::token::UntrustedToken;
use pasetors::version4::V4;
use pasetors::{public, Public};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

/// Émetteur inscrit dans chaque jeton.
pub const ISSUER: &str = "control-center";
const TYP_LICENSE: &str = "cc.license.v1";
const MAX_LICENSE_LEN: usize = 16 * 1024;

/// Type de licence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseKind {
    Perpetual,
    Subscription,
    Trial,
}

/// Contenu d'une licence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Identifiant unique (jti) — sert à la révocation.
    pub id: String,
    pub product_id: String,
    pub product_name: String,
    pub customer_id: String,
    pub customer_name: String,
    pub kind: LicenseKind,
    #[serde(with = "time::serde::rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub not_before: Option<OffsetDateTime>,
    /// `None` = perpétuelle.
    #[serde(with = "time::serde::rfc3339::option")]
    pub expires_at: Option<OffsetDateTime>,
    pub features: Vec<String>,
    pub options: serde_json::Map<String, serde_json::Value>,
}

impl LicenseClaims {
    pub fn new(
        product_id: &str,
        product_name: &str,
        customer_id: &str,
        customer_name: &str,
        kind: LicenseKind,
        issued_at: OffsetDateTime,
        expires_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            product_id: product_id.to_owned(),
            product_name: product_name.to_owned(),
            customer_id: customer_id.to_owned(),
            customer_name: customer_name.to_owned(),
            kind,
            issued_at,
            not_before: None,
            expires_at,
            features: Vec::new(),
            options: serde_json::Map::new(),
        }
    }
}

fn internal<E: std::fmt::Display>(e: E) -> LicenseError {
    LicenseError::Internal(e.to_string())
}

pub(crate) fn footer_for(kp: &SigningKeyPair) -> Result<Footer> {
    let mut footer = Footer::new();
    let id = Id::try_from(kp.kid()).map_err(internal)?;
    footer.key_id(&id);
    Ok(footer)
}

/// Signe une licence (PASETO v4.public). Le `kid` est placé dans le pied de jeton.
pub fn issue(kp: &SigningKeyPair, c: &LicenseClaims) -> Result<String> {
    if let Some(exp) = c.expires_at {
        if exp <= c.issued_at {
            return Err(LicenseError::Internal(
                "expiration antérieure à l'émission".into(),
            ));
        }
    }
    let mut claims = Claims::new().map_err(internal)?;
    claims.issuer(ISSUER).map_err(internal)?;
    claims.subject(&c.customer_id).map_err(internal)?;
    claims.audience(&c.product_id).map_err(internal)?;
    claims.token_identifier(&c.id).map_err(internal)?;
    claims
        .issued_at(&fmt_time(c.issued_at)?)
        .map_err(internal)?;
    claims
        .not_before(&fmt_time(c.not_before.unwrap_or(c.issued_at))?)
        .map_err(internal)?;
    match c.expires_at {
        Some(exp) => claims.expiration(&fmt_time(exp)?).map_err(internal)?,
        None => claims.non_expiring(),
    }
    claims
        .add_additional("typ", TYP_LICENSE)
        .map_err(internal)?;
    claims
        .add_additional("pname", c.product_name.as_str())
        .map_err(internal)?;
    claims
        .add_additional("cname", c.customer_name.as_str())
        .map_err(internal)?;
    claims
        .add_additional("kind", serde_json::to_value(c.kind).map_err(internal)?)
        .map_err(internal)?;
    claims
        .add_additional(
            "features",
            serde_json::to_value(&c.features).map_err(internal)?,
        )
        .map_err(internal)?;
    claims
        .add_additional("opt", serde_json::Value::Object(c.options.clone()))
        .map_err(internal)?;
    let footer = footer_for(kp)?;
    public::sign(&kp.paseto_secret()?, &claims, Some(&footer), None).map_err(internal)
}

/// Vérificateur hors ligne : un ou plusieurs clés publiques (rotation), indexées par `kid`.
#[derive(Clone, Debug, Default)]
pub struct Verifier {
    keys: HashMap<String, PublicKey>,
}

impl Verifier {
    pub fn new(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            keys: keys.into_iter().map(|k| (k.kid().to_owned(), k)).collect(),
        }
    }

    /// Vérifie la signature et le type, renvoie les claims bruts (sans contrôle de dates).
    pub(crate) fn verify_raw(
        &self,
        token: &str,
        expected_typ: &str,
        max_len: usize,
    ) -> Result<Claims> {
        if token.len() > max_len {
            return Err(LicenseError::Malformed);
        }
        if !token.starts_with("v4.public.") {
            return Err(LicenseError::UnsupportedHeader);
        }
        let untrusted =
            UntrustedToken::<Public, V4>::try_from(token).map_err(|_| LicenseError::Malformed)?;
        let mut footer = Footer::new();
        footer
            .parse_bytes(untrusted.untrusted_footer())
            .map_err(|_| LicenseError::UnknownKey)?;
        let kid = footer
            .get_claim("kid")
            .and_then(serde_json::Value::as_str)
            .ok_or(LicenseError::UnknownKey)?;
        let key = self.keys.get(kid).ok_or(LicenseError::UnknownKey)?;
        let mut rules = ClaimsValidationRules::new();
        rules.disable_valid_at(); // les dates sont contrôlées avec l'horloge injectée
        rules.allow_non_expiring();
        rules.validate_issuer_with(ISSUER);
        let trusted = public::verify(&key.paseto(), &untrusted, &rules, Some(&footer), None)
            .map_err(|_| LicenseError::BadSignature)?;
        let claims = trusted
            .payload_claims()
            .ok_or(LicenseError::Malformed)?
            .clone();
        match claims.get_claim("typ").and_then(serde_json::Value::as_str) {
            Some(t) if t == expected_typ => Ok(claims),
            _ => Err(LicenseError::WrongType),
        }
    }

    /// Vérifie une licence : signature, type, `kid`, fenêtre de validité à l'instant `now`.
    pub fn verify(&self, token: &str, now: OffsetDateTime) -> Result<LicenseClaims> {
        let claims = self.verify_raw(token, TYP_LICENSE, MAX_LICENSE_LEN)?;
        let lic = claims_to_license(&claims)?;
        if let Some(nbf) = lic.not_before {
            if now < nbf {
                return Err(LicenseError::NotYetValid);
            }
        }
        if let Some(exp) = lic.expires_at {
            if now >= exp {
                return Err(LicenseError::Expired);
            }
        }
        Ok(lic)
    }
}

fn str_claim(c: &Claims, k: &str) -> Result<String> {
    c.get_claim(k)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or(LicenseError::Malformed)
}

fn claims_to_license(c: &Claims) -> Result<LicenseClaims> {
    let opt_time = |k: &str| -> Result<Option<OffsetDateTime>> {
        c.get_claim(k)
            .and_then(serde_json::Value::as_str)
            .map(parse_time)
            .transpose()
    };
    Ok(LicenseClaims {
        id: str_claim(c, "jti")?,
        product_id: str_claim(c, "aud")?,
        product_name: str_claim(c, "pname")?,
        customer_id: str_claim(c, "sub")?,
        customer_name: str_claim(c, "cname")?,
        kind: serde_json::from_value(
            c.get_claim("kind")
                .cloned()
                .ok_or(LicenseError::Malformed)?,
        )
        .map_err(|_| LicenseError::Malformed)?,
        issued_at: parse_time(&str_claim(c, "iat")?)?,
        not_before: opt_time("nbf")?,
        expires_at: opt_time("exp")?,
        features: serde_json::from_value(
            c.get_claim("features")
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![])),
        )
        .map_err(|_| LicenseError::Malformed)?,
        options: c
            .get_claim("opt")
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE64URL_NOPAD;
    use time::Duration;

    fn sample(now: OffsetDateTime) -> LicenseClaims {
        let mut c = LicenseClaims::new(
            "prod-1",
            "Pro",
            "cust-1",
            "Awa",
            LicenseKind::Subscription,
            now,
            Some(now + Duration::days(30)),
        );
        c.features = vec!["export".into()];
        c.options.insert("seats".into(), 3.into());
        c
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let kp = SigningKeyPair::generate();
        let c = sample(now());
        let t = issue(&kp, &c).unwrap();
        assert!(t.starts_with("v4.public."));
        let v = Verifier::new([kp.public_key().clone()]);
        let got = v.verify(&t, now() + Duration::days(1)).unwrap();
        assert_eq!(got.id, c.id);
        assert_eq!(got.product_name, "Pro");
        assert_eq!(got.features, vec!["export".to_string()]);
        assert_eq!(got.options.get("seats"), Some(&serde_json::json!(3)));
        assert_eq!(got.kind, LicenseKind::Subscription);
    }

    #[test]
    fn perpetual_never_expires() {
        let kp = SigningKeyPair::generate();
        let mut c = sample(now());
        c.expires_at = None;
        c.kind = LicenseKind::Perpetual;
        let t = issue(&kp, &c).unwrap();
        let v = Verifier::new([kp.public_key().clone()]);
        assert!(v.verify(&t, now() + Duration::days(36500)).is_ok());
    }

    #[test]
    fn expired_and_not_yet_valid() {
        let kp = SigningKeyPair::generate();
        let t = issue(&kp, &sample(now())).unwrap();
        let v = Verifier::new([kp.public_key().clone()]);
        assert_eq!(
            v.verify(&t, now() + Duration::days(31)).unwrap_err(),
            LicenseError::Expired
        );
        assert_eq!(
            v.verify(&t, now() - Duration::seconds(1)).unwrap_err(),
            LicenseError::NotYetValid
        );
    }

    #[test]
    fn tampered_rejected() {
        let kp = SigningKeyPair::generate();
        let t = issue(&kp, &sample(now())).unwrap();
        let v = Verifier::new([kp.public_key().clone()]);
        // Modifier le contenu signé (payload) : change "Pro" en "Max".
        let parts: Vec<&str> = t.split('.').collect();
        let mut body = BASE64URL_NOPAD.decode(parts[2].as_bytes()).unwrap();
        let s = String::from_utf8_lossy(&body).to_string();
        let pos = s.find("\"Pro\"").unwrap();
        body[pos + 1] = b'M';
        let forged = format!("v4.public.{}.{}", BASE64URL_NOPAD.encode(&body), parts[3]);
        assert_eq!(
            v.verify(&forged, now()).unwrap_err(),
            LicenseError::BadSignature
        );
        // Inverser chaque octet du jeton un par un : jamais accepté.
        for i in 10..t.len() {
            let mut b = t.clone().into_bytes();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            let s = String::from_utf8(b).unwrap();
            if s != t {
                assert!(v.verify(&s, now()).is_err(), "octet {i}");
            }
        }
    }

    #[test]
    fn wrong_key_and_unknown_kid() {
        let kp = SigningKeyPair::generate();
        let other = SigningKeyPair::generate();
        let t = issue(&kp, &sample(now())).unwrap();
        let v = Verifier::new([other.public_key().clone()]);
        assert_eq!(v.verify(&t, now()).unwrap_err(), LicenseError::UnknownKey);
    }

    #[test]
    fn swapped_kid_footer_rejected() {
        // Un attaquant remplace le kid par celui d'une autre clé connue : signature invalide.
        let kp = SigningKeyPair::generate();
        let other = SigningKeyPair::generate();
        let t = issue(&kp, &sample(now())).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        let f = footer_for(&other).unwrap().to_string().unwrap();
        let forged = format!(
            "v4.public.{}.{}",
            parts[2],
            BASE64URL_NOPAD.encode(f.as_bytes())
        );
        let v = Verifier::new([kp.public_key().clone(), other.public_key().clone()]);
        assert_eq!(
            v.verify(&forged, now()).unwrap_err(),
            LicenseError::BadSignature
        );
    }

    #[test]
    fn key_rotation_multiple_kids() {
        let old = SigningKeyPair::generate();
        let new = SigningKeyPair::generate();
        let v = Verifier::new([old.public_key().clone(), new.public_key().clone()]);
        assert!(v
            .verify(&issue(&old, &sample(now())).unwrap(), now())
            .is_ok());
        assert!(v
            .verify(&issue(&new, &sample(now())).unwrap(), now())
            .is_ok());
    }

    #[test]
    fn other_headers_rejected() {
        let v = Verifier::new([SigningKeyPair::generate().public_key().clone()]);
        for t in [
            "v2.public.AAAA",
            "v4.local.AAAA",
            "",
            "v4.public.",
            "v4.public.!!!.x",
        ] {
            assert!(v.verify(t, now()).is_err(), "{t}");
        }
        assert_eq!(
            v.verify("v3.public.x", now()).unwrap_err(),
            LicenseError::UnsupportedHeader
        );
        assert_eq!(
            v.verify(&"v4.public.".repeat(3000), now()).unwrap_err(),
            LicenseError::Malformed
        );
    }

    #[test]
    fn expiry_before_issue_refused() {
        let kp = SigningKeyPair::generate();
        let mut c = sample(now());
        c.expires_at = Some(now() - Duration::days(1));
        assert!(issue(&kp, &c).is_err());
    }

    proptest::proptest! {
        #[test]
        fn random_input_never_panics(s in ".{0,400}") {
            let v = Verifier::new([SigningKeyPair::generate().public_key().clone()]);
            let _ = v.verify(&s, now());
            let _ = v.verify(&format!("v4.public.{s}"), now());
        }
    }
}

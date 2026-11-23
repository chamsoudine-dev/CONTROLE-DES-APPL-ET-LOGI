//! Clé de signature des licences : génération, stockage dans le trousseau, sauvegarde chiffrée.
use crate::crypto::{self, KdfParams};
use crate::secrets::SecretValue;
use crate::vault::Session;
use crate::{profile, CoreError, Result};
use cc_license::SigningKeyPair;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

fn store_id(kid: &str) -> String {
    format!("license-signing-key:{kid}")
}

/// Génère une nouvelle paire, la stocke et la rend active (rotation : l'ancienne reste disponible).
pub fn generate(s: &Session) -> Result<String> {
    let kp = SigningKeyPair::generate();
    let seed = kp.seed();
    s.secrets
        .put(&store_id(kp.kid()), &SecretValue::new(crypto::b64(&*seed)))?;
    profile::set_field(&s.conn.lock(), &s.profile_id, "license_kid", Some(kp.kid()))?;
    let mut known = known_public_keys(s)?;
    known.push(kp.public_key().to_paserk());
    profile::set_setting(
        &s.conn.lock(),
        "license_public_keys",
        &serde_json::to_string(&known)?,
    )?;
    s.audit(
        "license.key.generate",
        kp.kid(),
        &serde_json::json!({}),
        "ok",
    )?;
    Ok(kp.kid().to_owned())
}

/// Clés publiques connues (PASERK `k4.public.…`), y compris les anciennes après rotation.
pub fn known_public_keys(s: &Session) -> Result<Vec<String>> {
    Ok(profile::get_setting(&s.conn.lock(), "license_public_keys")?
        .map(|v| serde_json::from_str(&v))
        .transpose()?
        .unwrap_or_default())
}

/// Paire active (lue depuis le trousseau).
pub fn active(s: &Session) -> Result<SigningKeyPair> {
    let kid = profile::get(&s.conn.lock(), &s.profile_id)?
        .license_kid
        .ok_or(CoreError::NotFound("clé de signature des licences".into()))?;
    load(s, &kid)
}

pub fn load(s: &Session, kid: &str) -> Result<SigningKeyPair> {
    let v = s.secrets.get(&store_id(kid))?.ok_or(CoreError::NotFound(
        "clé de signature dans le trousseau".into(),
    ))?;
    let seed = Zeroizing::new(crypto::unb64(v.expose())?);
    Ok(SigningKeyPair::from_seed(&seed)?)
}

/// Sauvegarde chiffrée de la clé de signature (fichier JSON à conserver hors ligne).
#[derive(Serialize, Deserialize)]
pub struct KeyBackup {
    pub format: String,
    pub kid: String,
    pub kdf: KdfParams,
    pub salt: String,
    pub blob: String,
}

pub fn export_backup(s: &Session, backup_passphrase: &str, kdf: KdfParams) -> Result<String> {
    crate::vault::check_passphrase_strength(backup_passphrase)?;
    s.ensure_recent_reauth()?;
    let kp = active(s)?;
    let salt = crypto::random_bytes::<16>();
    let k = crypto::derive_key(backup_passphrase.as_bytes(), &salt, kdf)?;
    let backup = KeyBackup {
        format: "cc-license-key-backup-v1".into(),
        kid: kp.kid().to_owned(),
        kdf,
        salt: crypto::b64(&salt),
        blob: crypto::b64(&crypto::seal(&k, &*kp.seed(), kp.kid().as_bytes())?),
    };
    s.audit("license.key.backup", kp.kid(), &serde_json::json!({}), "ok")?;
    Ok(serde_json::to_string_pretty(&backup)?)
}

pub fn import_backup(s: &Session, json: &str, backup_passphrase: &str) -> Result<String> {
    let b: KeyBackup = serde_json::from_str(json)?;
    if b.format != "cc-license-key-backup-v1" {
        return Err(CoreError::Validation("format de sauvegarde inconnu".into()));
    }
    let k = crypto::derive_key(
        backup_passphrase.as_bytes(),
        &crypto::unb64(&b.salt)?,
        b.kdf,
    )?;
    let seed = crypto::open(&k, &crypto::unb64(&b.blob)?, b.kid.as_bytes())
        .map_err(|_| CoreError::InvalidPassphrase)?;
    let kp = SigningKeyPair::from_seed(&seed)?;
    if kp.kid() != b.kid {
        return Err(CoreError::Integrity("kid incohérent".into()));
    }
    s.secrets.put(
        &store_id(kp.kid()),
        &SecretValue::new(crypto::b64(&*kp.seed())),
    )?;
    profile::set_field(&s.conn.lock(), &s.profile_id, "license_kid", Some(kp.kid()))?;
    let mut known = known_public_keys(s)?;
    let paserk = kp.public_key().to_paserk();
    if !known.contains(&paserk) {
        known.push(paserk);
    }
    profile::set_setting(
        &s.conn.lock(),
        "license_public_keys",
        &serde_json::to_string(&known)?,
    )?;
    s.audit(
        "license.key.restore",
        kp.kid(),
        &serde_json::json!({}),
        "ok",
    )?;
    Ok(kp.kid().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{new_vault, PASS};

    #[test]
    fn generate_rotate_backup_restore() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        assert!(active(v.session().unwrap()).is_err());
        let kid1 = generate(v.session().unwrap()).unwrap();
        assert_eq!(active(v.session().unwrap()).unwrap().kid(), kid1);
        let kid2 = generate(v.session().unwrap()).unwrap();
        assert_ne!(kid1, kid2);
        assert_eq!(known_public_keys(v.session().unwrap()).unwrap().len(), 2);
        assert!(load(v.session().unwrap(), &kid1).is_ok());

        let fast = KdfParams::INSECURE_FAST_FOR_TESTS;
        assert!(matches!(
            export_backup(v.session().unwrap(), "backup passphrase 1", fast),
            Err(CoreError::ReauthRequired)
        ));
        v.reauth(PASS, None).unwrap();
        let json = export_backup(v.session().unwrap(), "backup passphrase 1", fast).unwrap();
        assert!(!json.contains(&crypto::b64(&*active(v.session().unwrap()).unwrap().seed())));

        let d2 = tempfile::tempdir().unwrap();
        let v2 = new_vault(d2.path(), true);
        let s2 = v2.session().unwrap();
        assert!(matches!(
            import_backup(s2, &json, "wrong passphrase 1"),
            Err(CoreError::InvalidPassphrase)
        ));
        assert!(import_backup(s2, "{}", "x").is_err());
        assert_eq!(
            import_backup(s2, &json, "backup passphrase 1").unwrap(),
            kid2
        );
        assert_eq!(active(s2).unwrap().kid(), kid2);
    }
}

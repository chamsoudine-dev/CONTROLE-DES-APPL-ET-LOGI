//! Import/export chiffré du coffre (fichier `.ccvault`).
//!
//! Enveloppe JSON : `{format, version, kdf, salt, ciphertext}` ; le contenu est chiffré par
//! XChaCha20-Poly1305 avec une clé Argon2id dérivée d'une phrase d'export. L'authenticité est
//! vérifiée AVANT tout parsing du contenu (menace T14).
use crate::apps::{self, NewApp};
use crate::crypto::{self, KdfParams};
use crate::policy::Action;
use crate::secrets::SecretValue;
use crate::vault::Session;
use crate::{envvars, keys, CoreError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const FORMAT: &str = "ccvault";
pub const VERSION: u32 = 1;
pub const MAX_FILE: usize = 50 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: String,
    version: u32,
    kdf: KdfParams,
    salt: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Payload {
    exported_at: String,
    apps: Vec<AppExport>,
    global_secrets: Vec<SecretExport>,
}

#[derive(Serialize, Deserialize)]
struct AppExport {
    app: NewApp,
    matrix: BTreeMap<Action, bool>,
    secrets: Vec<SecretExport>,
    env_vars: Vec<(String, String, String, Option<String>)>, // env, key, value, secret name
    connectors: Vec<(String, String, serde_json::Value, Option<String>)>, // provider, category, config, secret name
}

#[derive(Serialize, Deserialize)]
struct SecretExport {
    environment: String,
    provider: String,
    name: String,
    value: String,
    expires_at: Option<String>,
}

impl Drop for SecretExport {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
    }
}

fn aad(version: u32, salt: &str) -> Vec<u8> {
    format!("{FORMAT}|{version}|{salt}").into_bytes()
}

/// Exporte tout le coffre (exige une ré-authentification récente).
pub fn export(s: &Session, passphrase: &str, kdf: KdfParams) -> Result<String> {
    s.ensure_recent_reauth()?;
    crate::vault::check_passphrase_strength(passphrase)?;
    let secret_export = |m: &keys::SecretMeta| -> Result<SecretExport> {
        Ok(SecretExport {
            environment: m.environment.clone(),
            provider: m.provider.clone(),
            name: m.name.clone(),
            value: s
                .secrets
                .get(&m.id)?
                .map(|v| v.expose().to_owned())
                .unwrap_or_default(),
            expires_at: m.expires_at.clone(),
        })
    };
    let mut payload = Payload {
        exported_at: crate::now_rfc3339(),
        ..Payload::default()
    };
    for m in keys::list(s, Some(""))? {
        payload.global_secrets.push(secret_export(&m)?);
    }
    for a in apps::list(s)? {
        let metas = keys::list(s, Some(&a.id))?;
        let name_of = |sid: &Option<String>| {
            sid.as_ref()
                .and_then(|id| metas.iter().find(|m| &m.id == id).map(|m| m.name.clone()))
        };
        let mut env_vars = Vec::new();
        for env in envvars::ENVS {
            let raw: Vec<(String, String, Option<String>)> = {
                let c = s.conn.lock();
                let mut st = c.prepare(
                    "SELECT key, value, secret_id FROM env_vars WHERE app_id=?1 AND environment=?2",
                )?;
                let v = st
                    .query_map(rusqlite::params![a.id, env], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })?
                    .collect::<std::result::Result<_, _>>()?;
                v
            };
            for (k, v, sid) in raw {
                env_vars.push((env.to_owned(), k, v, name_of(&sid)));
            }
        }
        let connectors = apps::connectors(s, &a.id)?
            .into_iter()
            .map(|c| (c.provider, c.category, c.config, name_of(&c.secret_id)))
            .collect();
        payload.apps.push(AppExport {
            matrix: apps::matrix(s, &a.id)?,
            secrets: metas.iter().map(secret_export).collect::<Result<_>>()?,
            env_vars,
            connectors,
            app: NewApp {
                name: a.name,
                description: a.description,
                icon: a.icon,
                urls: a.urls,
                repo: a.repo,
                access_mode: Some(a.access_mode),
                licensing_enabled: a.licensing_enabled,
            },
        });
    }
    let plain = Zeroizing::new(serde_json::to_vec(&payload)?);
    let salt = crypto::random_bytes::<16>();
    let salt_b64 = crypto::b64(&salt);
    let key = crypto::derive_key(passphrase.as_bytes(), &salt, kdf)?;
    let env = Envelope {
        format: FORMAT.into(),
        version: VERSION,
        kdf,
        ciphertext: crypto::b64(&crypto::seal(&key, &plain, &aad(VERSION, &salt_b64))?),
        salt: salt_b64,
    };
    s.audit(
        "vault.export",
        "",
        &serde_json::json!({"apps": payload.apps.len()}),
        "ok",
    )?;
    Ok(serde_json::to_string(&env)?)
}

/// Résumé d'un import.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct ImportReport {
    pub apps_created: usize,
    pub apps_skipped: Vec<String>,
    pub secrets: usize,
    pub env_vars: usize,
}

/// Déchiffre et vérifie un fichier (sans rien écrire) — utilisé aussi par le fuzzing.
fn decrypt(data: &[u8], passphrase: &str) -> Result<Payload> {
    if data.len() > MAX_FILE {
        return Err(CoreError::Validation("fichier trop volumineux".into()));
    }
    let env: Envelope = serde_json::from_slice(data)
        .map_err(|_| CoreError::Validation("fichier .ccvault invalide".into()))?;
    if env.format != FORMAT || env.version != VERSION {
        return Err(CoreError::Validation(
            "format .ccvault non pris en charge".into(),
        ));
    }
    // Paramètres bornés : un fichier piégé ne doit pas épuiser la mémoire.
    if env.kdf.m_kib > 1024 * 1024 || env.kdf.t > 20 || env.kdf.p > 8 {
        return Err(CoreError::Validation(
            "paramètres de dérivation hors limites".into(),
        ));
    }
    let salt = crypto::unb64(&env.salt)?;
    let key = crypto::derive_key(passphrase.as_bytes(), &salt, env.kdf)?;
    let plain = crypto::open(
        &key,
        &crypto::unb64(&env.ciphertext)?,
        &aad(env.version, &env.salt),
    )
    .map_err(|_| CoreError::InvalidPassphrase)?;
    serde_json::from_slice(&plain).map_err(|_| CoreError::Validation("contenu invalide".into()))
}

/// Vérifie qu'un fichier est lisible avec cette phrase (aucune écriture).
pub fn inspect(data: &[u8], passphrase: &str) -> Result<usize> {
    decrypt(data, passphrase).map(|p| p.apps.len())
}

/// Importe : les applis portant un nom existant sont ignorées (aucun écrasement silencieux).
pub fn import(s: &Session, data: &[u8], passphrase: &str) -> Result<ImportReport> {
    s.ensure_recent_reauth()?;
    let payload = decrypt(data, passphrase)?;
    let mut rep = ImportReport::default();
    let existing: Vec<String> = apps::list(s)?.into_iter().map(|a| a.name).collect();
    let existing_global: Vec<String> = keys::list(s, Some(""))?
        .into_iter()
        .map(|m| m.name)
        .collect();
    for g in &payload.global_secrets {
        if !existing_global.contains(&g.name) && !g.value.is_empty() {
            keys::add(
                s,
                None,
                &g.environment,
                &g.provider,
                &g.name,
                &SecretValue::new(g.value.clone()),
                g.expires_at.as_deref(),
            )?;
            rep.secrets += 1;
        }
    }
    for ae in &payload.apps {
        if existing.contains(&ae.app.name) {
            rep.apps_skipped.push(ae.app.name.clone());
            continue;
        }
        // Les droits élargis ne sont pas restaurés sans contrôle : lecture seule à l'import.
        let mut na = ae.app.clone();
        na.access_mode = Some(crate::policy::AccessMode::ReadOnly);
        let app = apps::create(s, &na)?;
        rep.apps_created += 1;
        for (a, allowed) in &ae.matrix {
            s.conn.lock().execute(
                "UPDATE permissions SET allowed=?3 WHERE app_id=?1 AND action=?2",
                rusqlite::params![app.id, a.as_str(), allowed],
            )?;
        }
        let mut ids: BTreeMap<String, String> = BTreeMap::new();
        for se in &ae.secrets {
            if se.value.is_empty() {
                continue;
            }
            let m = keys::add(
                s,
                Some(&app.id),
                &se.environment,
                &se.provider,
                &se.name,
                &SecretValue::new(se.value.clone()),
                se.expires_at.as_deref(),
            )?;
            ids.insert(se.name.clone(), m.id);
            rep.secrets += 1;
        }
        for (env, k, v, sname) in &ae.env_vars {
            match sname.as_ref().and_then(|n| ids.get(n)) {
                Some(sid) => envvars::set(s, &app.id, env, k, None, Some(sid))?,
                None => envvars::set(s, &app.id, env, k, Some(v), None)?,
            }
            rep.env_vars += 1;
        }
        for (p, cat, cfg, sname) in &ae.connectors {
            let sid = sname.as_ref().and_then(|n| ids.get(n)).map(String::as_str);
            apps::add_connector(s, &app.id, p, cat, cfg, sid)?;
        }
    }
    s.audit(
        "vault.import",
        "",
        &serde_json::json!({"apps": rep.apps_created, "secrets": rep.secrets}),
        "ok",
    )?;
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{new_vault, PASS};

    const EXPORT_PASS: &str = "export passphrase 42";

    #[test]
    fn export_import_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        {
            let s = v.session().unwrap();
            let app = apps::create(
                s,
                &NewApp {
                    name: "Boutique".into(),
                    ..Default::default()
                },
            )
            .unwrap();
            let m = keys::add(
                s,
                Some(&app.id),
                "production",
                "vercel",
                "VERCEL_TOKEN",
                &SecretValue::new("vercel-token-1234567"),
                None,
            )
            .unwrap();
            keys::add(
                s,
                None,
                "global",
                "custom",
                "GLOBAL_KEY",
                &SecretValue::new("global-secret-99999"),
                None,
            )
            .unwrap();
            envvars::set(s, &app.id, "production", "API", Some("https://x"), None).unwrap();
            envvars::set(s, &app.id, "production", "TOKEN", None, Some(&m.id)).unwrap();
            apps::add_connector(
                s,
                &app.id,
                "vercel",
                "hosting",
                &serde_json::json!({"project_id":"p"}),
                Some(&m.id),
            )
            .unwrap();
            assert!(matches!(
                export(s, EXPORT_PASS, KdfParams::INSECURE_FAST_FOR_TESTS),
                Err(CoreError::ReauthRequired)
            ));
        }
        v.reauth(PASS, None).unwrap();
        let file = export(
            v.session().unwrap(),
            EXPORT_PASS,
            KdfParams::INSECURE_FAST_FOR_TESTS,
        )
        .unwrap();
        assert!(
            !file.contains("vercel-token") && !file.contains("Boutique"),
            "contenu chiffré"
        );
        assert!(export(
            v.session().unwrap(),
            "weak",
            KdfParams::INSECURE_FAST_FOR_TESTS
        )
        .is_err());
        assert_eq!(inspect(file.as_bytes(), EXPORT_PASS).unwrap(), 1);

        let d2 = tempfile::tempdir().unwrap();
        let mut v2 = new_vault(d2.path(), true);
        v2.reauth(PASS, None).unwrap();
        let s2 = v2.session().unwrap();
        assert!(matches!(
            import(s2, file.as_bytes(), "wrong passphrase!!"),
            Err(CoreError::InvalidPassphrase)
        ));
        let rep = import(s2, file.as_bytes(), EXPORT_PASS).unwrap();
        assert_eq!(
            rep,
            ImportReport {
                apps_created: 1,
                apps_skipped: vec![],
                secrets: 2,
                env_vars: 2
            }
        );
        let app = &apps::list(s2).unwrap()[0];
        assert_eq!(app.access_mode, crate::policy::AccessMode::ReadOnly);
        let r = envvars::resolved(s2, &app.id, "production").unwrap();
        assert_eq!(r["TOKEN"].expose(), "vercel-token-1234567");
        assert!(apps::connectors(s2, &app.id).unwrap()[0]
            .secret_id
            .is_some());
        // Ré-import : appli ignorée (pas d'écrasement).
        let rep2 = import(s2, file.as_bytes(), EXPORT_PASS).unwrap();
        assert_eq!(rep2.apps_skipped, vec!["Boutique".to_string()]);
        assert_eq!(rep2.secrets, 0);
    }

    #[test]
    fn tampered_or_hostile_files_rejected() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        v.reauth(PASS, None).unwrap();
        let s = v.session().unwrap();
        let file = export(s, EXPORT_PASS, KdfParams::INSECURE_FAST_FOR_TESTS).unwrap();
        let mut env: serde_json::Value = serde_json::from_str(&file).unwrap();
        let ct = env["ciphertext"].as_str().unwrap().to_owned();
        let mut raw = crypto::unb64(&ct).unwrap();
        raw[30] ^= 1;
        env["ciphertext"] = crypto::b64(&raw).into();
        assert!(inspect(env.to_string().as_bytes(), EXPORT_PASS).is_err());
        let mut e2: serde_json::Value = serde_json::from_str(&file).unwrap();
        e2["kdf"]["m_kib"] = (8 * 1024 * 1024).into();
        assert!(inspect(e2.to_string().as_bytes(), EXPORT_PASS).is_err());
        let mut e3: serde_json::Value = serde_json::from_str(&file).unwrap();
        e3["version"] = 2.into();
        assert!(inspect(e3.to_string().as_bytes(), EXPORT_PASS).is_err());
        for junk in [&b""[..], b"{}", b"not json", b"{\"format\":\"ccvault\"}"] {
            assert!(inspect(junk, EXPORT_PASS).is_err());
        }
        assert!(inspect(&vec![b' '; MAX_FILE + 1], EXPORT_PASS).is_err());
    }
}

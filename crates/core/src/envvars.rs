//! Variables d'environnement par appli : édition locale, aperçu des différences, préparation de l'envoi.
use crate::apps;
use crate::policy::AccessMode;
use crate::secrets::SecretValue;
use crate::vault::Session;
use crate::{crypto, keys, new_id, now_rfc3339, CoreError, Result};
use rusqlite::{params, Row};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const ENVS: [&str; 3] = ["development", "preview", "production"];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvVar {
    pub id: String,
    pub app_id: String,
    pub environment: String,
    pub key: String,
    /// Valeur affichée : en clair si non secrète, masquée si liée à un secret.
    pub value: String,
    pub secret_id: Option<String>,
    pub updated_at: String,
    pub pushed: bool,
}

fn validate_key(k: &str) -> Result<()> {
    let ok = !k.is_empty()
        && k.len() <= 256
        && k.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(CoreError::Validation(format!(
            "clé de variable invalide : {k}"
        )))
    }
}

fn validate_env(e: &str) -> Result<()> {
    if ENVS.contains(&e) {
        Ok(())
    } else {
        Err(CoreError::Validation(format!(
            "environnement inconnu : {e}"
        )))
    }
}

fn value_hash(v: &str) -> String {
    crypto::sha256_hex(v.as_bytes())
}

fn row(r: &Row<'_>) -> rusqlite::Result<EnvVar> {
    let secret_id: Option<String> = r.get(5)?;
    let raw: String = r.get(4)?;
    let updated_at: String = r.get(6)?;
    let pushed_at: Option<String> = r.get(7)?;
    Ok(EnvVar {
        id: r.get(0)?,
        app_id: r.get(1)?,
        environment: r.get(2)?,
        key: r.get(3)?,
        value: if secret_id.is_some() {
            "••••".into()
        } else {
            raw.clone()
        },
        secret_id,
        pushed: pushed_at.is_some_and(|p| p >= updated_at),
        updated_at,
    })
}

pub fn list(s: &Session, app_id: &str, env: &str) -> Result<Vec<EnvVar>> {
    validate_env(env)?;
    let c = s.conn.lock();
    let mut st = c.prepare(
        "SELECT id, app_id, environment, key, value, secret_id, updated_at, pushed_at
         FROM env_vars WHERE app_id=?1 AND environment=?2 ORDER BY key",
    )?;
    let v = st
        .query_map(params![app_id, env], row)?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

/// Crée ou modifie une variable (valeur en clair OU référence à un secret du coffre).
pub fn set(
    s: &Session,
    app_id: &str,
    env: &str,
    key: &str,
    value: Option<&str>,
    secret_id: Option<&str>,
) -> Result<()> {
    validate_env(env)?;
    validate_key(key)?;
    let app = apps::get(s, app_id)?;
    if app.access_mode == AccessMode::Disabled {
        return Err(CoreError::Forbidden("application désactivée".into()));
    }
    let stored = match (value, secret_id) {
        (Some(v), None) => {
            if v.len() > 64 * 1024 {
                return Err(CoreError::Validation("valeur trop longue".into()));
            }
            v.to_owned()
        }
        (None, Some(sid)) => {
            let m = keys::get(s, sid)?;
            if m.app_id.as_deref().is_some_and(|a| a != app_id) {
                return Err(CoreError::Forbidden(
                    "secret d'une autre application".into(),
                ));
            }
            String::new()
        }
        _ => return Err(CoreError::Validation("valeur OU secret attendu".into())),
    };
    s.conn.lock().execute(
        "INSERT INTO env_vars(id, app_id, environment, key, value, secret_id, updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)
         ON CONFLICT(app_id, environment, key) DO UPDATE SET value=excluded.value,
            secret_id=excluded.secret_id, updated_at=excluded.updated_at",
        params![new_id(), app_id, env, key, stored, secret_id, now_rfc3339()],
    )?;
    s.audit(
        "env.set",
        app_id,
        &serde_json::json!({"env": env, "key": key, "secret": secret_id.is_some()}),
        "ok",
    )
}

pub fn remove(s: &Session, app_id: &str, env: &str, key: &str) -> Result<()> {
    let n = s.conn.lock().execute(
        "DELETE FROM env_vars WHERE app_id=?1 AND environment=?2 AND key=?3",
        params![app_id, env, key],
    )?;
    if n == 0 {
        return Err(CoreError::NotFound("variable".into()));
    }
    s.audit(
        "env.remove",
        app_id,
        &serde_json::json!({"env": env, "key": key}),
        "ok",
    )
}

/// Valeurs résolues (secrets inclus) pour l'envoi vers l'hébergeur. Usage interne uniquement.
pub fn resolved(s: &Session, app_id: &str, env: &str) -> Result<BTreeMap<String, SecretValue>> {
    validate_env(env)?;
    let rows: Vec<(String, String, Option<String>)> = {
        let c = s.conn.lock();
        let mut st = c.prepare(
            "SELECT key, value, secret_id FROM env_vars WHERE app_id=?1 AND environment=?2",
        )?;
        let v = st
            .query_map(params![app_id, env], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        v
    };
    let mut out = BTreeMap::new();
    for (k, v, sid) in rows {
        let val = match sid {
            Some(id) => keys::use_value(s, &id)?,
            None => SecretValue::new(v),
        };
        out.insert(k, val);
    }
    Ok(out)
}

/// Mémorise l'état envoyé (empreintes) pour les prochains aperçus.
pub fn mark_pushed(s: &Session, app_id: &str, env: &str) -> Result<()> {
    let vals = resolved(s, app_id, env)?;
    let c = s.conn.lock();
    for (k, v) in &vals {
        c.execute(
            "UPDATE env_vars SET remote_value_hash=?4, pushed_at=?5 WHERE app_id=?1 AND environment=?2 AND key=?3",
            params![app_id, env, k, value_hash(v.expose()), now_rfc3339()],
        )?;
    }
    Ok(())
}

/// Ligne de l'aperçu des différences.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiffLine {
    pub key: String,
    pub change: Change,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    Added,
    Changed,
    Removed,
    Unchanged,
}

/// Compare l'état local (clé → valeur) à l'état distant (clé → valeur si lisible).
/// Une valeur distante illisible (chiffrée chez l'hébergeur) est comparée à la dernière
/// empreinte envoyée.
pub fn diff(
    local: &BTreeMap<String, SecretValue>,
    remote: &BTreeMap<String, Option<String>>,
    last_pushed_hash: &BTreeMap<String, String>,
) -> Vec<DiffLine> {
    let mut out = Vec::new();
    for (k, v) in local {
        let change = match remote.get(k) {
            None => Change::Added,
            Some(Some(rv)) if rv == v.expose() => Change::Unchanged,
            Some(Some(_)) => Change::Changed,
            Some(None) => {
                if last_pushed_hash.get(k) == Some(&value_hash(v.expose())) {
                    Change::Unchanged
                } else {
                    Change::Changed
                }
            }
        };
        out.push(DiffLine {
            key: k.clone(),
            change,
        });
    }
    for k in remote.keys().filter(|k| !local.contains_key(*k)) {
        out.push(DiffLine {
            key: k.clone(),
            change: Change::Removed,
        });
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// Empreintes envoyées lors du dernier « push ».
pub fn last_pushed(s: &Session, app_id: &str, env: &str) -> Result<BTreeMap<String, String>> {
    let c = s.conn.lock();
    let mut st = c.prepare(
        "SELECT key, remote_value_hash FROM env_vars WHERE app_id=?1 AND environment=?2 AND remote_value_hash IS NOT NULL",
    )?;
    let v = st
        .query_map(params![app_id, env], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::{create, NewApp};
    use crate::vault::tests::new_vault;

    #[test]
    fn set_list_resolve_diff() {
        let d = tempfile::tempdir().unwrap();
        let v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        let app = create(
            s,
            &NewApp {
                name: "A".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let sec = keys::add(
            s,
            Some(&app.id),
            "production",
            "supabase",
            "SUPA",
            &SecretValue::new("supa-secret-value-123"),
            None,
        )
        .unwrap();
        set(
            s,
            &app.id,
            "production",
            "API_URL",
            Some("https://api.example.com"),
            None,
        )
        .unwrap();
        set(
            s,
            &app.id,
            "production",
            "SUPABASE_KEY",
            None,
            Some(&sec.id),
        )
        .unwrap();
        assert!(set(s, &app.id, "production", "1BAD", Some("x"), None).is_err());
        assert!(set(s, &app.id, "staging", "OK", Some("x"), None).is_err());
        assert!(set(s, &app.id, "production", "OK", None, None).is_err());
        assert!(set(s, &app.id, "production", "OK", Some("x"), Some(&sec.id)).is_err());
        let l = list(s, &app.id, "production").unwrap();
        assert_eq!(l.len(), 2);
        let sk = l.iter().find(|v| v.key == "SUPABASE_KEY").unwrap();
        assert_eq!(
            sk.value, "••••",
            "valeur secrète jamais renvoyée à l'interface"
        );
        let r = resolved(s, &app.id, "production").unwrap();
        assert_eq!(r["SUPABASE_KEY"].expose(), "supa-secret-value-123");

        let mut remote = BTreeMap::new();
        remote.insert(
            "API_URL".to_string(),
            Some("https://old.example.com".to_string()),
        );
        remote.insert("OLD".to_string(), Some("x".to_string()));
        let d1 = diff(&r, &remote, &last_pushed(s, &app.id, "production").unwrap());
        let get = |k: &str| d1.iter().find(|l| l.key == k).unwrap().change;
        assert_eq!(get("API_URL"), Change::Changed);
        assert_eq!(get("SUPABASE_KEY"), Change::Added);
        assert_eq!(get("OLD"), Change::Removed);

        mark_pushed(s, &app.id, "production").unwrap();
        assert!(list(s, &app.id, "production")
            .unwrap()
            .iter()
            .all(|v| v.pushed));
        let mut remote2 = BTreeMap::new();
        remote2.insert(
            "API_URL".to_string(),
            Some("https://api.example.com".to_string()),
        );
        remote2.insert("SUPABASE_KEY".to_string(), None); // chiffrée chez l'hébergeur
        let d2 = diff(
            &r,
            &remote2,
            &last_pushed(s, &app.id, "production").unwrap(),
        );
        assert!(d2.iter().all(|l| l.change == Change::Unchanged), "{d2:?}");

        remove(s, &app.id, "production", "API_URL").unwrap();
        assert!(remove(s, &app.id, "production", "API_URL").is_err());
        assert!(list(s, &app.id, "nope").is_err());
    }

    #[test]
    fn cross_app_secret_refused_and_disabled_app() {
        let d = tempfile::tempdir().unwrap();
        let v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        let a = create(
            s,
            &NewApp {
                name: "A".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let b = create(
            s,
            &NewApp {
                name: "B".into(),
                access_mode: Some(AccessMode::Disabled),
                ..Default::default()
            },
        )
        .unwrap();
        let sec = keys::add(
            s,
            Some(&a.id),
            "production",
            "x",
            "K",
            &SecretValue::new("secret-value-1234"),
            None,
        )
        .unwrap();
        let c = create(
            s,
            &NewApp {
                name: "C".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(matches!(
            set(s, &c.id, "production", "K", None, Some(&sec.id)),
            Err(CoreError::Forbidden(_))
        ));
        assert!(matches!(
            set(s, &b.id, "production", "K", Some("v"), None),
            Err(CoreError::Forbidden(_))
        ));
    }
}

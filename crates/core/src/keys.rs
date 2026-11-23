//! Coffre « Environnements & Clés » : métadonnées en base, valeur dans le trousseau.
use crate::secrets::{mask_last4, SecretValue};
use crate::vault::Session;
use crate::{crypto, new_id, now_rfc3339, CoreError, Result};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

pub const ENVIRONMENTS: [&str; 4] = ["development", "preview", "production", "global"];

/// Métadonnées d'un secret (jamais la valeur).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SecretMeta {
    pub id: String,
    pub app_id: Option<String>,
    pub environment: String,
    pub provider: String,
    pub name: String,
    pub masked: String,
    pub fingerprint: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub detected_permissions: serde_json::Value,
    pub too_powerful: bool,
}

const COLS: &str =
    "id, app_id, environment, provider, name, last4, fingerprint, created_at, updated_at,
                    last_used_at, expires_at, detected_permissions, too_powerful";

fn row(r: &Row<'_>) -> rusqlite::Result<SecretMeta> {
    let last4: String = r.get(5)?;
    let perms: String = r.get(11)?;
    Ok(SecretMeta {
        id: r.get(0)?,
        app_id: r.get(1)?,
        environment: r.get(2)?,
        provider: r.get(3)?,
        name: r.get(4)?,
        masked: mask_last4(&last4),
        fingerprint: r.get(6)?,
        created_at: r.get(7)?,
        updated_at: r.get(8)?,
        last_used_at: r.get(9)?,
        expires_at: r.get(10)?,
        detected_permissions: serde_json::from_str(&perms).unwrap_or(serde_json::Value::Null),
        too_powerful: r.get(12)?,
    })
}

pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        Err(CoreError::Validation(
            "nom : lettres, chiffres, « _ », « - », « . » (128 max)".into(),
        ))
    }
}

pub fn validate_env(env: &str) -> Result<()> {
    if ENVIRONMENTS.contains(&env) {
        Ok(())
    } else {
        Err(CoreError::Validation(format!(
            "environnement inconnu : {env}"
        )))
    }
}

fn validate_value(v: &SecretValue) -> Result<()> {
    if v.is_empty() || v.expose().len() > 16 * 1024 {
        return Err(CoreError::Validation(
            "valeur vide ou trop longue (16 Kio max)".into(),
        ));
    }
    Ok(())
}

fn validate_expiry(e: Option<&str>) -> Result<()> {
    if let Some(e) = e {
        time::OffsetDateTime::parse(e, &time::format_description::well_known::Rfc3339)
            .map_err(|_| CoreError::Validation("date d'expiration RFC 3339 attendue".into()))?;
    }
    Ok(())
}

/// Empreinte HMAC (détection de doublons sans révéler la valeur).
pub fn fingerprint(s: &Session, v: &SecretValue) -> String {
    let k = s.subkey("fingerprint");
    data_encoding::HEXLOWER.encode(&crypto::hmac_sha256(&*k, v.expose().as_bytes())[..8])
}

/// Unicité (appli, environnement, nom) — y compris pour les secrets globaux (app_id NULL,
/// que la contrainte SQL UNIQUE ne couvre pas).
fn ensure_unique(
    s: &Session,
    app_id: Option<&str>,
    env: &str,
    name: &str,
    except: Option<&str>,
) -> Result<()> {
    let exists: Option<String> = s
        .conn
        .lock()
        .query_row(
            "SELECT id FROM secrets_meta WHERE app_id IS ?1 AND environment=?2 AND name=?3
             AND id IS NOT ?4 LIMIT 1",
            params![app_id, env, name, except],
            |r| r.get(0),
        )
        .optional()?;
    match exists {
        Some(_) => Err(CoreError::Conflict(format!(
            "un secret « {name} » existe déjà"
        ))),
        None => Ok(()),
    }
}

/// Ajoute un secret. Renvoie ses métadonnées.
pub fn add(
    s: &Session,
    app_id: Option<&str>,
    environment: &str,
    provider: &str,
    name: &str,
    value: &SecretValue,
    expires_at: Option<&str>,
) -> Result<SecretMeta> {
    validate_env(environment)?;
    validate_name(name)?;
    validate_name(provider)?;
    validate_value(value)?;
    validate_expiry(expires_at)?;
    ensure_unique(s, app_id, environment, name, None)?;
    let id = new_id();
    let now = now_rfc3339();
    s.secrets.put(&id, value)?;
    let r = s.conn.lock().execute(
        "INSERT INTO secrets_meta(id, app_id, environment, provider, name, last4, fingerprint,
                                  created_at, updated_at, expires_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8,?9)",
        params![
            id,
            app_id,
            environment,
            provider,
            name,
            value.last4(),
            fingerprint(s, value),
            now,
            expires_at
        ],
    );
    if let Err(e) = r {
        let _ = s.secrets.delete(&id);
        return Err(e.into());
    }
    s.audit(
        "secret.add",
        &id,
        &serde_json::json!({"name": name, "env": environment, "provider": provider, "app": app_id}),
        "ok",
    )?;
    get(s, &id)
}

/// Enregistre (ou remplace) un secret global à identifiant fixe (ex. jeton GitHub).
pub fn register_global(
    s: &Session,
    id: &str,
    provider: &str,
    name: &str,
    value: &SecretValue,
    too_powerful: bool,
    detected_permissions_json: &str,
) -> Result<()> {
    s.secrets.put(id, value)?;
    let now = now_rfc3339();
    s.conn.lock().execute(
        "INSERT INTO secrets_meta(id, app_id, environment, provider, name, last4, fingerprint,
                                  created_at, updated_at, detected_permissions, too_powerful)
         VALUES (?1, NULL, 'global', ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?8)
         ON CONFLICT(id) DO UPDATE SET last4=excluded.last4, fingerprint=excluded.fingerprint,
           updated_at=excluded.updated_at, detected_permissions=excluded.detected_permissions,
           too_powerful=excluded.too_powerful",
        params![
            id,
            provider,
            name,
            value.last4(),
            fingerprint(s, value),
            now,
            detected_permissions_json,
            too_powerful
        ],
    )?;
    Ok(())
}

pub fn get(s: &Session, id: &str) -> Result<SecretMeta> {
    s.conn
        .lock()
        .query_row(
            &format!("SELECT {COLS} FROM secrets_meta WHERE id=?1"),
            [id],
            row,
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound("secret".into()))
}

/// Liste (filtrée par appli si fournie ; `Some("")` = secrets globaux).
pub fn list(s: &Session, app_id: Option<&str>) -> Result<Vec<SecretMeta>> {
    let c = s.conn.lock();
    let (sql, arg) = match app_id {
        None => (
            format!("SELECT {COLS} FROM secrets_meta ORDER BY app_id, environment, name"),
            None,
        ),
        Some("") => (
            format!("SELECT {COLS} FROM secrets_meta WHERE app_id IS NULL ORDER BY name"),
            None,
        ),
        Some(a) => (
            format!("SELECT {COLS} FROM secrets_meta WHERE app_id=?1 ORDER BY environment, name"),
            Some(a),
        ),
    };
    let mut st = c.prepare(&sql)?;
    let v = match arg {
        Some(a) => st
            .query_map([a], row)?
            .collect::<std::result::Result<_, _>>()?,
        None => st
            .query_map([], row)?
            .collect::<std::result::Result<_, _>>()?,
    };
    Ok(v)
}

/// Rotation : remplace la valeur (la précédente est écrasée dans le trousseau).
pub fn rotate(s: &Session, id: &str, value: &SecretValue) -> Result<SecretMeta> {
    validate_value(value)?;
    get(s, id)?;
    s.secrets.put(id, value)?;
    s.conn.lock().execute(
        "UPDATE secrets_meta SET last4=?2, fingerprint=?3, updated_at=?4,
                detected_permissions='[]', too_powerful=0 WHERE id=?1",
        params![id, value.last4(), fingerprint(s, value), now_rfc3339()],
    )?;
    s.audit("secret.rotate", id, &serde_json::json!({}), "ok")?;
    get(s, id)
}

/// Modifie les métadonnées (nom, expiration).
pub fn update_meta(
    s: &Session,
    id: &str,
    name: &str,
    expires_at: Option<&str>,
) -> Result<SecretMeta> {
    validate_name(name)?;
    validate_expiry(expires_at)?;
    let cur = get(s, id)?;
    ensure_unique(s, cur.app_id.as_deref(), &cur.environment, name, Some(id))?;
    let n = s.conn.lock().execute(
        "UPDATE secrets_meta SET name=?2, expires_at=?3, updated_at=?4 WHERE id=?1",
        params![id, name, expires_at, now_rfc3339()],
    )?;
    if n == 0 {
        return Err(CoreError::NotFound("secret".into()));
    }
    s.audit(
        "secret.update",
        id,
        &serde_json::json!({"name": name}),
        "ok",
    )?;
    get(s, id)
}

/// Révèle la valeur : ré-authentification récente obligatoire, action auditée.
pub fn reveal(s: &Session, id: &str) -> Result<SecretValue> {
    if let Err(e) = s.ensure_recent_reauth() {
        s.audit("secret.reveal", id, &serde_json::json!({}), "denied")?;
        return Err(e);
    }
    let v = s
        .secrets
        .get(id)?
        .ok_or_else(|| CoreError::NotFound("valeur du secret".into()))?;
    s.audit("secret.reveal", id, &serde_json::json!({}), "ok")?;
    Ok(v)
}

/// Valeur pour usage interne (appel fournisseur) ; met à jour « dernière utilisation ».
pub fn use_value(s: &Session, id: &str) -> Result<SecretValue> {
    let v = s
        .secrets
        .get(id)?
        .ok_or_else(|| CoreError::NotFound("valeur du secret".into()))?;
    s.conn.lock().execute(
        "UPDATE secrets_meta SET last_used_at=?2 WHERE id=?1",
        params![id, now_rfc3339()],
    )?;
    Ok(v)
}

pub fn set_detected(
    s: &Session,
    id: &str,
    perms: &serde_json::Value,
    too_powerful: bool,
) -> Result<()> {
    s.conn.lock().execute(
        "UPDATE secrets_meta SET detected_permissions=?2, too_powerful=?3 WHERE id=?1",
        params![id, perms.to_string(), too_powerful],
    )?;
    Ok(())
}

/// Suppression : ré-authentification récente obligatoire.
pub fn delete(s: &Session, id: &str) -> Result<()> {
    s.ensure_recent_reauth()?;
    get(s, id)?;
    s.conn
        .lock()
        .execute("DELETE FROM secrets_meta WHERE id=?1", [id])?;
    s.secrets.delete(id)?;
    s.audit("secret.delete", id, &serde_json::json!({}), "ok")
}

/// Secrets dont l'empreinte est identique (même valeur réutilisée).
pub fn duplicates(s: &Session) -> Result<Vec<Vec<String>>> {
    let c = s.conn.lock();
    let mut st = c.prepare(
        "SELECT group_concat(id) FROM secrets_meta GROUP BY fingerprint HAVING count(*) > 1",
    )?;
    let v = st
        .query_map([], |r| r.get::<_, String>(0))?
        .map(|r| r.map(|s| s.split(',').map(str::to_owned).collect()))
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{new_vault, PASS};

    #[test]
    fn crud_reveal_rotate_delete() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        let val = SecretValue::new("vercel_token_abcdefgh1234");
        assert!(add(s, None, "staging", "vercel", "X", &val, None).is_err());
        assert!(add(s, None, "production", "vercel", "bad name", &val, None).is_err());
        assert!(add(
            s,
            None,
            "production",
            "vercel",
            "X",
            &SecretValue::new(""),
            None
        )
        .is_err());
        assert!(add(s, None, "production", "vercel", "X", &val, Some("demain")).is_err());
        let m = add(
            s,
            None,
            "production",
            "vercel",
            "VERCEL_TOKEN",
            &val,
            Some("2030-01-01T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(m.masked, "••••1234");
        let json = serde_json::to_string(&m).unwrap();
        assert!(
            !json.contains("abcdefgh"),
            "la valeur ne quitte jamais le cœur"
        );
        assert!(matches!(
            add(s, None, "production", "vercel", "VERCEL_TOKEN", &val, None),
            Err(CoreError::Conflict(_))
        ));
        assert_eq!(list(s, None).unwrap().len(), 1);
        assert_eq!(list(s, Some("")).unwrap().len(), 1);
        assert_eq!(list(s, Some("app")).unwrap().len(), 0);
        assert!(matches!(reveal(s, &m.id), Err(CoreError::ReauthRequired)));
        assert_eq!(use_value(s, &m.id).unwrap().expose(), val.expose());
        assert!(get(s, &m.id).unwrap().last_used_at.is_some());
        let m2 = rotate(s, &m.id, &SecretValue::new("new_token_value_99999")).unwrap();
        assert_eq!(m2.masked, "••••9999");
        assert_ne!(m2.fingerprint, m.fingerprint);
        update_meta(s, &m.id, "VERCEL_TOKEN_2", None).unwrap();
        assert!(update_meta(s, "nope", "A", None).is_err());
        set_detected(s, &m.id, &serde_json::json!([{"scope":"x"}]), true).unwrap();
        assert!(get(s, &m.id).unwrap().too_powerful);
        assert!(matches!(delete(s, &m.id), Err(CoreError::ReauthRequired)));
        v.reauth(PASS, None).unwrap();
        let s = v.session().unwrap();
        assert_eq!(reveal(s, &m.id).unwrap().expose(), "new_token_value_99999");
        delete(s, &m.id).unwrap();
        assert!(get(s, &m.id).is_err());
        assert!(s.secrets.get(&m.id).unwrap().is_none());
        assert!(rotate(s, "nope", &val).is_err());
        assert!(use_value(s, "nope").is_err());
    }

    #[test]
    fn global_and_duplicates() {
        let d = tempfile::tempdir().unwrap();
        let v = new_vault(d.path(), true);
        let s = v.session().unwrap();
        let val = SecretValue::new("same_value_123456789");
        register_global(
            s,
            "github-token",
            "github",
            "GITHUB_TOKEN",
            &val,
            false,
            "[]",
        )
        .unwrap();
        register_global(
            s,
            "github-token",
            "github",
            "GITHUB_TOKEN",
            &val,
            true,
            "[]",
        )
        .unwrap();
        assert!(get(s, "github-token").unwrap().too_powerful);
        add(s, None, "production", "custom", "OTHER", &val, None).unwrap();
        assert_eq!(duplicates(s).unwrap().len(), 1);
        assert_eq!(
            s.secrets.get("github-token").unwrap().unwrap().expose(),
            val.expose()
        );
    }
}

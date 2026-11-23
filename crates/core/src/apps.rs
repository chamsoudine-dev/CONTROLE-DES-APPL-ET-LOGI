//! Applications suivies, leurs environnements, connecteurs et matrice de droits.
use crate::policy::{self, AccessMode, Action, Role};
use crate::vault::Session;
use crate::{new_id, now_rfc3339, CoreError, Result};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct App {
    pub id: String,
    pub name: String,
    pub description: String,
    pub icon: Option<String>,
    pub urls: Vec<String>,
    pub repo: Option<String>,
    pub access_mode: AccessMode,
    pub licensing_enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Données saisies dans l'assistant « Ajouter une application ».
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NewApp {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub access_mode: Option<AccessMode>,
    #[serde(default)]
    pub licensing_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectorRow {
    pub id: String,
    pub app_id: String,
    pub provider: String,
    pub category: String,
    pub config: serde_json::Value,
    pub secret_id: Option<String>,
    pub last_test_at: Option<String>,
    pub last_test_ok: Option<bool>,
    pub detected_permissions: serde_json::Value,
}

fn validate(a: &NewApp) -> Result<()> {
    let name = a.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(CoreError::Validation("nom : 1 à 80 caractères".into()));
    }
    if a.description.chars().count() > 2000 {
        return Err(CoreError::Validation("description trop longue".into()));
    }
    if a.urls.len() > 10 {
        return Err(CoreError::Validation("10 URL maximum".into()));
    }
    for u in &a.urls {
        let ok = (u.starts_with("https://")
            || u.starts_with("http://localhost")
            || u.starts_with("http://127.0.0.1"))
            && u.len() <= 2048
            && !u.chars().any(char::is_whitespace);
        if !ok {
            return Err(CoreError::Validation(format!(
                "URL invalide (HTTPS attendu) : {u}"
            )));
        }
    }
    if let Some(r) = &a.repo {
        let ok = r.split('/').count() == 2
            && r.split('/').all(|p| {
                !p.is_empty()
                    && p != ".."
                    && p.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
            });
        if !ok {
            return Err(CoreError::Validation("dépôt attendu : owner/nom".into()));
        }
    }
    if let Some(i) = &a.icon {
        let ok = i.len() <= 200_000
            && (i.starts_with("data:image/png;base64,")
                || i.starts_with("data:image/webp;base64,")
                || i.starts_with("data:image/jpeg;base64,")
                || (i.chars().count() <= 8 && !i.contains('<')));
        if !ok {
            return Err(CoreError::Validation(
                "icône : emoji ou image PNG/WebP/JPEG (data URL)".into(),
            ));
        }
    }
    Ok(())
}

fn row(r: &Row<'_>) -> rusqlite::Result<App> {
    let urls: String = r.get(4)?;
    let mode: String = r.get(6)?;
    Ok(App {
        id: r.get(0)?,
        name: r.get(1)?,
        description: r.get(2)?,
        icon: r.get(3)?,
        urls: serde_json::from_str(&urls).unwrap_or_default(),
        repo: r.get(5)?,
        access_mode: AccessMode::parse(&mode).unwrap_or(AccessMode::ReadOnly),
        licensing_enabled: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
    })
}

const COLS: &str =
    "id, name, description, icon, urls, repo, access_mode, licensing_enabled, created_at, updated_at";

/// Crée une application (mode par défaut : lecture seule), ses 3 environnements et sa matrice.
pub fn create(s: &Session, a: &NewApp) -> Result<App> {
    validate(a)?;
    let id = new_id();
    let now = now_rfc3339();
    let mode = a.access_mode.unwrap_or(AccessMode::ReadOnly);
    {
        let mut c = s.conn.lock();
        let tx = c.transaction()?;
        tx.execute(
            &format!("INSERT INTO apps({COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)"),
            params![
                id,
                a.name.trim(),
                a.description,
                a.icon,
                serde_json::to_string(&a.urls)?,
                a.repo,
                mode.as_str(),
                a.licensing_enabled,
                now
            ],
        )?;
        for env in ["development", "preview", "production"] {
            tx.execute(
                "INSERT INTO environments(id, app_id, kind) VALUES (?1, ?2, ?3)",
                params![new_id(), id, env],
            )?;
        }
        for (action, allowed) in policy::default_matrix() {
            tx.execute(
                "INSERT INTO permissions(app_id, action, allowed) VALUES (?1, ?2, ?3)",
                params![id, action.as_str(), allowed],
            )?;
        }
        tx.commit()?;
    }
    s.audit(
        "app.create",
        &id,
        &serde_json::json!({"name": a.name, "mode": mode}),
        "ok",
    )?;
    get(s, &id)
}

pub fn get(s: &Session, id: &str) -> Result<App> {
    s.conn
        .lock()
        .query_row(&format!("SELECT {COLS} FROM apps WHERE id=?1"), [id], row)
        .optional()?
        .ok_or_else(|| CoreError::NotFound("application".into()))
}

pub fn list(s: &Session) -> Result<Vec<App>> {
    let c = s.conn.lock();
    let mut st = c.prepare(&format!(
        "SELECT {COLS} FROM apps ORDER BY name COLLATE NOCASE"
    ))?;
    let v = st
        .query_map([], row)?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

pub fn update(s: &Session, id: &str, a: &NewApp) -> Result<App> {
    validate(a)?;
    let n = s.conn.lock().execute(
        "UPDATE apps SET name=?2, description=?3, icon=?4, urls=?5, repo=?6, licensing_enabled=?7, updated_at=?8
         WHERE id=?1",
        params![
            id,
            a.name.trim(),
            a.description,
            a.icon,
            serde_json::to_string(&a.urls)?,
            a.repo,
            a.licensing_enabled,
            now_rfc3339()
        ],
    )?;
    if n == 0 {
        return Err(CoreError::NotFound("application".into()));
    }
    s.audit("app.update", id, &serde_json::json!({"name": a.name}), "ok")?;
    get(s, id)
}

/// Change le mode d'accès (lecture seule / lecture-écriture / désactivé).
pub fn set_mode(s: &Session, id: &str, mode: AccessMode) -> Result<()> {
    get(s, id)?;
    // Passer en lecture-écriture élargit les droits : ré-authentification exigée.
    if mode == AccessMode::ReadWrite {
        s.ensure_recent_reauth()?;
    }
    s.conn.lock().execute(
        "UPDATE apps SET access_mode=?2, updated_at=?3 WHERE id=?1",
        params![id, mode.as_str(), now_rfc3339()],
    )?;
    s.audit("app.mode", id, &serde_json::json!({"mode": mode}), "ok")
}

pub fn matrix(s: &Session, id: &str) -> Result<BTreeMap<Action, bool>> {
    let c = s.conn.lock();
    let mut st = c.prepare("SELECT action, allowed FROM permissions WHERE app_id=?1")?;
    let mut m = BTreeMap::new();
    for r in st.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))? {
        let (a, allowed) = r?;
        if let Ok(a) = Action::parse(&a) {
            m.insert(a, allowed);
        }
    }
    Ok(m)
}

/// Modifie une case de la matrice (activer une action exige une ré-authentification).
pub fn set_permission(s: &Session, id: &str, action: Action, allowed: bool) -> Result<()> {
    get(s, id)?;
    if allowed {
        s.ensure_recent_reauth()?;
    }
    s.conn.lock().execute(
        "INSERT INTO permissions(app_id, action, allowed) VALUES (?1,?2,?3)
         ON CONFLICT(app_id, action) DO UPDATE SET allowed=excluded.allowed",
        params![id, action.as_str(), allowed],
    )?;
    s.audit(
        "app.permission",
        id,
        &serde_json::json!({"action": action, "allowed": allowed}),
        "ok",
    )
}

/// Décision d'autorisation pour une action sur une appli (auditée en cas de refus).
pub fn authorize(s: &Session, app_id: &str, action: Action, role: Role) -> Result<()> {
    let app = get(s, app_id)?;
    let m = matrix(s, app_id)?;
    let r = policy::authorize(app.access_mode, &m, role, action);
    if let Err(e) = &r {
        s.audit(
            "policy.denied",
            app_id,
            &serde_json::json!({"action": action, "reason": e.to_string()}),
            "denied",
        )?;
    }
    r
}

/// Suppression d'une application : action destructrice (matrice + ré-authentification).
pub fn delete(s: &Session, id: &str) -> Result<()> {
    authorize(s, id, Action::Delete, Role::Owner)?;
    s.ensure_recent_reauth()?;
    let secret_ids: Vec<String> = {
        let c = s.conn.lock();
        let mut st = c.prepare("SELECT id FROM secrets_meta WHERE app_id=?1")?;
        let v = st
            .query_map([id], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        v
    };
    for sid in &secret_ids {
        s.secrets.delete(sid)?;
    }
    {
        let mut c = s.conn.lock();
        let tx = c.transaction()?;
        // Licences/ventes conservées (historique comptable) : on détache les produits.
        tx.execute("UPDATE products SET app_id=NULL WHERE app_id=?1", [id])?;
        tx.execute("DELETE FROM apps WHERE id=?1", [id])?;
        tx.commit()?;
    }
    s.audit(
        "app.delete",
        id,
        &serde_json::json!({"secrets": secret_ids.len()}),
        "ok",
    )
}

// ---------- Connecteurs rattachés ----------

fn conn_row(r: &Row<'_>) -> rusqlite::Result<ConnectorRow> {
    let cfg: String = r.get(4)?;
    let perms: String = r.get(8)?;
    Ok(ConnectorRow {
        id: r.get(0)?,
        app_id: r.get(1)?,
        provider: r.get(2)?,
        category: r.get(3)?,
        config: serde_json::from_str(&cfg).unwrap_or_default(),
        secret_id: r.get(5)?,
        last_test_at: r.get(6)?,
        last_test_ok: r.get(7)?,
        detected_permissions: serde_json::from_str(&perms).unwrap_or_default(),
    })
}

const CCOLS: &str =
    "id, app_id, provider, category, config, secret_id, last_test_at, last_test_ok, detected_permissions";

pub fn add_connector(
    s: &Session,
    app_id: &str,
    provider: &str,
    category: &str,
    config: &serde_json::Value,
    secret_id: Option<&str>,
) -> Result<ConnectorRow> {
    get(s, app_id)?;
    if !config.is_object() || config.to_string().len() > 16 * 1024 {
        return Err(CoreError::Validation("configuration invalide".into()));
    }
    crate::keys::validate_name(provider)?;
    crate::keys::validate_name(category)?;
    let id = new_id();
    s.conn.lock().execute(
        &format!("INSERT INTO connectors({CCOLS}, created_at) VALUES (?1,?2,?3,?4,?5,?6,NULL,NULL,'[]',?7)"),
        params![id, app_id, provider, category, config.to_string(), secret_id, now_rfc3339()],
    )?;
    s.audit(
        "connector.add",
        app_id,
        &serde_json::json!({"provider": provider}),
        "ok",
    )?;
    get_connector(s, &id)
}

pub fn get_connector(s: &Session, id: &str) -> Result<ConnectorRow> {
    s.conn
        .lock()
        .query_row(
            &format!("SELECT {CCOLS} FROM connectors WHERE id=?1"),
            [id],
            conn_row,
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound("connecteur".into()))
}

pub fn connectors(s: &Session, app_id: &str) -> Result<Vec<ConnectorRow>> {
    let c = s.conn.lock();
    let mut st = c.prepare(&format!(
        "SELECT {CCOLS} FROM connectors WHERE app_id=?1 ORDER BY created_at"
    ))?;
    let v = st
        .query_map([app_id], conn_row)?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

pub fn record_test(
    s: &Session,
    connector_id: &str,
    ok: bool,
    perms: &serde_json::Value,
) -> Result<()> {
    s.conn.lock().execute(
        "UPDATE connectors SET last_test_at=?2, last_test_ok=?3, detected_permissions=?4 WHERE id=?1",
        params![connector_id, now_rfc3339(), ok, perms.to_string()],
    )?;
    Ok(())
}

pub fn remove_connector(s: &Session, connector_id: &str) -> Result<()> {
    let c = get_connector(s, connector_id)?;
    authorize(s, &c.app_id, Action::Delete, Role::Owner)?;
    s.ensure_recent_reauth()?;
    s.conn
        .lock()
        .execute("DELETE FROM connectors WHERE id=?1", [connector_id])?;
    s.audit(
        "connector.remove",
        &c.app_id,
        &serde_json::json!({"provider": c.provider}),
        "ok",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{new_vault, PASS};

    fn sample() -> NewApp {
        NewApp {
            name: "Boutique".into(),
            description: "Ma boutique".into(),
            icon: Some("🛒".into()),
            urls: vec!["https://boutique.example.com".into()],
            repo: Some("me/boutique".into()),
            access_mode: None,
            licensing_enabled: true,
        }
    }

    #[test]
    fn create_list_update() {
        let d = tempfile::tempdir().unwrap();
        let v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        let a = create(s, &sample()).unwrap();
        assert_eq!(
            a.access_mode,
            AccessMode::ReadOnly,
            "lecture seule par défaut"
        );
        assert_eq!(list(s).unwrap().len(), 1);
        assert!(matches!(create(s, &sample()), Err(CoreError::Conflict(_))));
        let mut u = sample();
        u.name = "Boutique 2".into();
        assert_eq!(update(s, &a.id, &u).unwrap().name, "Boutique 2");
        assert!(update(s, "nope", &u).is_err());
        assert_eq!(matrix(s, &a.id).unwrap().len(), Action::ALL.len());
        let envs: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT count(*) FROM environments WHERE app_id=?1",
                [&a.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(envs, 3);
    }

    #[test]
    fn validation() {
        let d = tempfile::tempdir().unwrap();
        let v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        for bad in [
            NewApp {
                name: " ".into(),
                ..sample()
            },
            NewApp {
                urls: vec!["http://example.com".into()],
                ..sample()
            },
            NewApp {
                urls: vec!["javascript:alert(1)".into()],
                ..sample()
            },
            NewApp {
                repo: Some("../etc".into()),
                ..sample()
            },
            NewApp {
                repo: Some("a/b/c".into()),
                ..sample()
            },
            NewApp {
                icon: Some("<svg onload=x>".into()),
                ..sample()
            },
            NewApp {
                icon: Some("data:image/svg+xml;base64,AAAA".into()),
                ..sample()
            },
            NewApp {
                description: "x".repeat(3000),
                ..sample()
            },
            NewApp {
                urls: vec!["https://a.b".into(); 11],
                ..sample()
            },
        ] {
            assert!(create(s, &bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn read_only_app_cannot_write() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        let id = create(v.session().unwrap(), &sample()).unwrap().id;
        let s = v.session().unwrap();
        for a in Action::ALL {
            let r = authorize(s, &id, a, Role::Owner);
            assert_eq!(r.is_ok(), a == Action::View, "{a:?}");
        }
        // Passer en lecture-écriture exige la ré-auth.
        assert!(matches!(
            set_mode(s, &id, AccessMode::ReadWrite),
            Err(CoreError::ReauthRequired)
        ));
        v.reauth(PASS, None).unwrap();
        let s = v.session().unwrap();
        set_mode(s, &id, AccessMode::ReadWrite).unwrap();
        assert!(authorize(s, &id, Action::Redeploy, Role::Owner).is_ok());
        set_permission(s, &id, Action::Redeploy, false).unwrap();
        assert!(authorize(s, &id, Action::Redeploy, Role::Owner).is_err());
        set_mode(s, &id, AccessMode::Disabled).unwrap();
        assert!(authorize(s, &id, Action::View, Role::Owner).is_err());
        // Les refus sont audités.
        let denied: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT count(*) FROM audit_logs WHERE outcome='denied'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(denied >= 8);
        assert!(authorize(s, "nope", Action::View, Role::Owner).is_err());
    }

    #[test]
    fn delete_requires_matrix_and_reauth() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        let id = create(
            v.session().unwrap(),
            &NewApp {
                access_mode: Some(AccessMode::ReadWrite),
                ..sample()
            },
        )
        .unwrap()
        .id;
        let s = v.session().unwrap();
        crate::keys::add(
            s,
            Some(&id),
            "production",
            "vercel",
            "TOKEN",
            &crate::secrets::SecretValue::new("abcdefghijkl"),
            None,
        )
        .unwrap();
        assert!(
            matches!(delete(s, &id), Err(CoreError::Forbidden(_))),
            "suppression désactivée par défaut"
        );
        assert!(
            set_permission(s, &id, Action::Delete, true).is_err(),
            "activer exige ré-auth"
        );
        v.reauth(PASS, None).unwrap();
        let s = v.session().unwrap();
        set_permission(s, &id, Action::Delete, true).unwrap();
        delete(s, &id).unwrap();
        assert!(get(s, &id).is_err());
        assert!(
            crate::keys::list(s, None).unwrap().is_empty(),
            "secrets supprimés en cascade"
        );
    }

    #[test]
    fn connectors_crud() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        let id = create(v.session().unwrap(), &sample()).unwrap().id;
        let s = v.session().unwrap();
        assert!(add_connector(s, &id, "vercel", "hosting", &serde_json::json!("x"), None).is_err());
        assert!(
            add_connector(s, "nope", "vercel", "hosting", &serde_json::json!({}), None).is_err()
        );
        let c = add_connector(
            s,
            &id,
            "vercel",
            "hosting",
            &serde_json::json!({"project_id":"prj_1"}),
            None,
        )
        .unwrap();
        record_test(
            s,
            &c.id,
            true,
            &serde_json::json!([{"scope":"deployments"}]),
        )
        .unwrap();
        let c2 = get_connector(s, &c.id).unwrap();
        assert_eq!(c2.last_test_ok, Some(true));
        assert_eq!(connectors(s, &id).unwrap().len(), 1);
        assert!(remove_connector(s, &c.id).is_err(), "lecture seule");
        v.reauth(PASS, None).unwrap();
        let s = v.session().unwrap();
        set_mode(s, &id, AccessMode::ReadWrite).unwrap();
        set_permission(s, &id, Action::Delete, true).unwrap();
        remove_connector(s, &c.id).unwrap();
        assert!(connectors(s, &id).unwrap().is_empty());
    }
}

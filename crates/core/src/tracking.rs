//! Suivi du code : événements de dépôt, ETag par URL interrogée, médias publiés, alertes.
use crate::vault::Session;
use crate::{keys, new_id, now_rfc3339, Result};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};

/// Événement de dépôt (commit, branche, PR, exécution d'Actions, release).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoEvent {
    pub id: String,
    pub repo: String,
    pub kind: String,
    pub title: String,
    pub author: Option<String>,
    pub ref_name: Option<String>,
    pub status: Option<String>,
    pub url: Option<String>,
    pub occurred_at: String,
}

/// Résultat d'un enregistrement : nouveaux événements et événements dont le statut a changé.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Upserted {
    pub new: Vec<RepoEvent>,
    pub status_changed: Vec<RepoEvent>,
    /// Vrai si l'appli n'avait encore aucun événement (premier passage : pas de notification).
    pub first_sync: bool,
}

pub fn upsert_events(s: &Session, app_id: &str, events: &[RepoEvent]) -> Result<Upserted> {
    let c = s.conn.lock();
    let existing: i64 = c.query_row(
        "SELECT count(*) FROM repo_events WHERE app_id=?1",
        [app_id],
        |r| r.get(0),
    )?;
    let mut out = Upserted {
        first_sync: existing == 0,
        ..Upserted::default()
    };
    for e in events {
        let prev: Option<Option<String>> = c
            .query_row("SELECT status FROM repo_events WHERE id=?1", [&e.id], |r| {
                r.get(0)
            })
            .optional()?;
        match prev {
            None => {
                c.execute(
                    "INSERT INTO repo_events(id, app_id, repo, kind, title, author, ref_name, status, url, occurred_at, notified)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![e.id, app_id, e.repo, e.kind, e.title, e.author, e.ref_name, e.status, e.url, e.occurred_at, out.first_sync],
                )?;
                out.new.push(e.clone());
            }
            Some(old) if old != e.status => {
                c.execute(
                    "UPDATE repo_events SET status=?2 WHERE id=?1",
                    params![e.id, e.status],
                )?;
                out.status_changed.push(e.clone());
            }
            Some(_) => {}
        }
    }
    Ok(out)
}

fn ev_row(r: &Row<'_>) -> rusqlite::Result<RepoEvent> {
    Ok(RepoEvent {
        id: r.get(0)?,
        repo: r.get(1)?,
        kind: r.get(2)?,
        title: r.get(3)?,
        author: r.get(4)?,
        ref_name: r.get(5)?,
        status: r.get(6)?,
        url: r.get(7)?,
        occurred_at: r.get(8)?,
    })
}

pub fn list_events(s: &Session, app_id: Option<&str>, limit: u32) -> Result<Vec<RepoEvent>> {
    let c = s.conn.lock();
    let sql =
        "SELECT id, repo, kind, title, author, ref_name, status, url, occurred_at FROM repo_events";
    let v = match app_id {
        Some(a) => {
            let mut st = c.prepare(&format!(
                "{sql} WHERE app_id=?1 ORDER BY occurred_at DESC LIMIT ?2"
            ))?;
            let v: Vec<RepoEvent> = st
                .query_map(params![a, limit.min(500)], ev_row)?
                .collect::<std::result::Result<_, _>>()?;
            v
        }
        None => {
            let mut st = c.prepare(&format!("{sql} ORDER BY occurred_at DESC LIMIT ?1"))?;
            let v: Vec<RepoEvent> = st
                .query_map(params![limit.min(500)], ev_row)?
                .collect::<std::result::Result<_, _>>()?;
            v
        }
    };
    Ok(v)
}

pub fn mark_notified(s: &Session, ids: &[String]) -> Result<()> {
    let c = s.conn.lock();
    for id in ids {
        c.execute("UPDATE repo_events SET notified=1 WHERE id=?1", [id])?;
    }
    Ok(())
}

pub fn etag(s: &Session, key: &str) -> Result<Option<String>> {
    Ok(s.conn
        .lock()
        .query_row("SELECT etag FROM poll_state WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?
        .flatten())
}

pub fn set_etag(s: &Session, key: &str, etag: Option<&str>) -> Result<()> {
    s.conn.lock().execute(
        "INSERT INTO poll_state(key, etag, last_polled_at) VALUES (?1,?2,?3)
         ON CONFLICT(key) DO UPDATE SET etag=COALESCE(excluded.etag, poll_state.etag), last_polled_at=excluded.last_polled_at",
        params![key, etag, now_rfc3339()],
    )?;
    Ok(())
}

// ---------- Médias ----------

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MediaAsset {
    pub id: String,
    pub app_id: String,
    pub provider: String,
    pub path: String,
    pub url: String,
    pub bytes: i64,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub created_at: String,
}

#[allow(clippy::too_many_arguments)]
pub fn add_media(
    s: &Session,
    app_id: &str,
    provider: &str,
    path: &str,
    url: &str,
    bytes: usize,
    width: u32,
    height: u32,
) -> Result<MediaAsset> {
    let id = new_id();
    s.conn.lock().execute(
        "INSERT INTO media_assets(id, app_id, provider, path, url, bytes, width, height, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![id, app_id, provider, path, url, i64::try_from(bytes).unwrap_or(i64::MAX), width, height, now_rfc3339()],
    )?;
    s.audit(
        "media.upload",
        app_id,
        &serde_json::json!({"provider": provider, "path": path, "bytes": bytes}),
        "ok",
    )?;
    Ok(list_media(s, app_id)?
        .into_iter()
        .find(|m| m.id == id)
        .expect("inséré"))
}

pub fn list_media(s: &Session, app_id: &str) -> Result<Vec<MediaAsset>> {
    let c = s.conn.lock();
    let mut st = c.prepare(
        "SELECT id, app_id, provider, path, url, bytes, width, height, created_at FROM media_assets
         WHERE app_id=?1 ORDER BY created_at DESC",
    )?;
    let v = st
        .query_map([app_id], |r| {
            Ok(MediaAsset {
                id: r.get(0)?,
                app_id: r.get(1)?,
                provider: r.get(2)?,
                path: r.get(3)?,
                url: r.get(4)?,
                bytes: r.get(5)?,
                width: r.get(6)?,
                height: r.get(7)?,
                created_at: r.get(8)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

// ---------- Alertes ----------

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Alert {
    pub level: &'static str,
    pub app_id: Option<String>,
    pub message: String,
}

/// Alertes locales : clés expirées / bientôt expirées, trop puissantes, CI en échec.
pub fn alerts(s: &Session, now: time::OffsetDateTime) -> Result<Vec<Alert>> {
    let mut out = Vec::new();
    for m in keys::list(s, None)? {
        if let Some(exp) = m.expires_at.as_deref().and_then(|e| {
            time::OffsetDateTime::parse(e, &time::format_description::well_known::Rfc3339).ok()
        }) {
            let days = (exp - now).whole_days();
            if days < 0 {
                out.push(Alert {
                    level: "error",
                    app_id: m.app_id.clone(),
                    message: format!("La clé {} a expiré.", m.name),
                });
            } else if days <= 14 {
                out.push(Alert {
                    level: "warning",
                    app_id: m.app_id.clone(),
                    message: format!("La clé {} expire dans {days} jour(s).", m.name),
                });
            }
        }
        if m.too_powerful {
            out.push(Alert {
                level: "warning",
                app_id: m.app_id.clone(),
                message: format!(
                    "La clé {} est trop puissante : réduisez ses droits.",
                    m.name
                ),
            });
        }
    }
    let failing: Vec<(Option<String>, String, String)> = {
        let c = s.conn.lock();
        let mut st = c.prepare(
            "SELECT e.app_id, e.repo, e.title FROM repo_events e
             WHERE e.kind='workflow_run' AND e.status IN ('failure','timed_out','startup_failure')
               AND e.occurred_at = (SELECT max(occurred_at) FROM repo_events x WHERE x.app_id=e.app_id AND x.kind='workflow_run')",
        )?;
        let v = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?;
        v
    };
    for (app_id, repo, title) in failing {
        out.push(Alert {
            level: "error",
            app_id,
            message: format!("GitHub Actions en échec sur {repo} : {title}"),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::{create, NewApp};
    use crate::secrets::SecretValue;
    use crate::vault::tests::new_vault;

    fn ev(id: &str, kind: &str, status: Option<&str>, at: &str) -> RepoEvent {
        RepoEvent {
            id: id.into(),
            repo: "me/app".into(),
            kind: kind.into(),
            title: format!("t-{id}"),
            author: Some("me".into()),
            ref_name: Some("main".into()),
            status: status.map(str::to_owned),
            url: None,
            occurred_at: at.into(),
        }
    }

    #[test]
    fn events_first_sync_new_and_status_change() {
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
        let u1 = upsert_events(
            s,
            &app.id,
            &[ev("commit:1", "commit", None, "2026-01-01T00:00:00Z")],
        )
        .unwrap();
        assert!(u1.first_sync && u1.new.len() == 1);
        let u2 = upsert_events(
            s,
            &app.id,
            &[
                ev("commit:1", "commit", None, "2026-01-01T00:00:00Z"),
                ev("commit:2", "commit", None, "2026-01-02T00:00:00Z"),
                ev(
                    "run:1",
                    "workflow_run",
                    Some("in_progress"),
                    "2026-01-02T00:01:00Z",
                ),
            ],
        )
        .unwrap();
        assert!(!u2.first_sync);
        assert_eq!(u2.new.len(), 2);
        let u3 = upsert_events(
            s,
            &app.id,
            &[ev(
                "run:1",
                "workflow_run",
                Some("failure"),
                "2026-01-02T00:01:00Z",
            )],
        )
        .unwrap();
        assert_eq!(u3.status_changed.len(), 1);
        assert!(u3.new.is_empty());
        let l = list_events(s, Some(&app.id), 10).unwrap();
        assert_eq!(l[0].id, "run:1");
        assert_eq!(list_events(s, None, 10).unwrap().len(), 3);
        mark_notified(s, &["commit:2".into()]).unwrap();
        let a = alerts(s, time::OffsetDateTime::now_utc()).unwrap();
        assert!(a
            .iter()
            .any(|x| x.message.contains("GitHub Actions en échec")));
    }

    #[test]
    fn etags_media_alerts() {
        let d = tempfile::tempdir().unwrap();
        let v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        assert_eq!(etag(s, "k").unwrap(), None);
        set_etag(s, "k", Some("\"v1\"")).unwrap();
        set_etag(s, "k", None).unwrap();
        assert_eq!(
            etag(s, "k").unwrap().as_deref(),
            Some("\"v1\""),
            "un 304 conserve l'ETag"
        );
        let app = create(
            s,
            &NewApp {
                name: "A".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let m = add_media(
            s,
            &app.id,
            "cloudinary",
            "app/logo.webp",
            "https://x/logo.webp",
            1234,
            10,
            20,
        )
        .unwrap();
        assert_eq!(list_media(s, &app.id).unwrap(), vec![m]);
        let now = time::OffsetDateTime::parse(
            "2026-01-01T00:00:00Z",
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap();
        keys::add(
            s,
            None,
            "global",
            "x",
            "SOON",
            &SecretValue::new("value-123456789"),
            Some("2026-01-05T00:00:00Z"),
        )
        .unwrap();
        keys::add(
            s,
            None,
            "global",
            "x",
            "OLD",
            &SecretValue::new("value-987654321"),
            Some("2025-12-01T00:00:00Z"),
        )
        .unwrap();
        let a = alerts(s, now).unwrap();
        assert!(a
            .iter()
            .any(|x| x.level == "warning" && x.message.contains("SOON")));
        assert!(a
            .iter()
            .any(|x| x.level == "error" && x.message.contains("OLD")));
    }
}

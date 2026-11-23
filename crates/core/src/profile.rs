//! Profil local et appareils.
use crate::{new_id, now_rfc3339, CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub display_name: String,
    #[serde(skip)]
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub autolock_secs: u32,
    pub github_login: Option<String>,
    pub sync_repo: Option<String>,
    pub revocation_repo: Option<String>,
    pub license_kid: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub is_current: bool,
    pub revoked_at: Option<String>,
    pub last_seen: Option<String>,
}

pub fn platform() -> &'static str {
    std::env::consts::OS
}

pub fn create(conn: &Connection, display_name: &str, device_id: &str) -> Result<String> {
    let id = new_id();
    let now = now_rfc3339();
    conn.execute(
        "INSERT INTO profiles(id, display_name, created_at, updated_at) VALUES (?1,?2,?3,?3)",
        params![id, display_name, now],
    )?;
    conn.execute(
        "INSERT INTO devices(id, name, platform, is_current, created_at, last_seen)
         VALUES (?1, ?2, ?3, 1, ?4, ?4)",
        params![
            device_id,
            format!("{} ({})", display_name, platform()),
            platform(),
            now
        ],
    )?;
    Ok(id)
}

pub fn current_id(conn: &Connection) -> Result<String> {
    conn.query_row(
        "SELECT id FROM profiles ORDER BY created_at LIMIT 1",
        [],
        |r| r.get(0),
    )
    .map_err(|_| CoreError::Integrity("profil manquant".into()))
}

pub fn get(conn: &Connection, id: &str) -> Result<Profile> {
    conn.query_row(
        "SELECT id, display_name, totp_secret, totp_enabled, autolock_secs, github_login,
                sync_repo, revocation_repo, license_kid FROM profiles WHERE id = ?1",
        [id],
        |r| {
            Ok(Profile {
                id: r.get(0)?,
                display_name: r.get(1)?,
                totp_secret: r.get(2)?,
                totp_enabled: r.get(3)?,
                autolock_secs: r.get(4)?,
                github_login: r.get(5)?,
                sync_repo: r.get(6)?,
                revocation_repo: r.get(7)?,
                license_kid: r.get(8)?,
            })
        },
    )
    .map_err(Into::into)
}

pub fn set_totp(conn: &Connection, id: &str, secret_b32: Option<&str>) -> Result<()> {
    conn.execute(
        "UPDATE profiles SET totp_secret=?2, totp_enabled=?3, updated_at=?4 WHERE id=?1",
        params![id, secret_b32, secret_b32.is_some(), now_rfc3339()],
    )?;
    Ok(())
}

/// Délai de verrouillage auto (0 = jamais ; maximum 24 h).
pub fn set_autolock(conn: &Connection, id: &str, secs: u32) -> Result<()> {
    if secs > 86_400 {
        return Err(CoreError::Validation(
            "verrouillage auto : 24 h maximum".into(),
        ));
    }
    conn.execute(
        "UPDATE profiles SET autolock_secs=?2, updated_at=?3 WHERE id=?1",
        params![id, secs, now_rfc3339()],
    )?;
    Ok(())
}

/// Champ texte optionnel du profil (liste blanche de colonnes).
pub fn set_field(conn: &Connection, id: &str, field: &str, value: Option<&str>) -> Result<()> {
    let col = match field {
        "github_login" | "sync_repo" | "revocation_repo" | "license_kid" | "display_name" => field,
        _ => return Err(CoreError::Validation(format!("champ inconnu : {field}"))),
    };
    if col == "display_name" && value.is_none_or(|v| v.trim().is_empty()) {
        return Err(CoreError::Validation("nom affiché requis".into()));
    }
    conn.execute(
        &format!("UPDATE profiles SET {col}=?2, updated_at=?3 WHERE id=?1"),
        params![id, value, now_rfc3339()],
    )?;
    Ok(())
}

pub fn list_devices(conn: &Connection) -> Result<Vec<Device>> {
    let mut st = conn.prepare(
        "SELECT id, name, platform, is_current, revoked_at, last_seen FROM devices ORDER BY created_at",
    )?;
    let v = st
        .query_map([], |r| {
            Ok(Device {
                id: r.get(0)?,
                name: r.get(1)?,
                platform: r.get(2)?,
                is_current: r.get(3)?,
                revoked_at: r.get(4)?,
                last_seen: r.get(5)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

pub fn upsert_device(conn: &Connection, id: &str, name: &str, platform: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO devices(id, name, platform, is_current, created_at, last_seen)
         VALUES (?1, ?2, ?3, 0, ?4, ?4)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, last_seen = excluded.last_seen",
        params![id, name, platform, now_rfc3339()],
    )?;
    Ok(())
}

pub fn revoke_device(conn: &Connection, id: &str) -> Result<()> {
    let current: Option<bool> = conn
        .query_row("SELECT is_current FROM devices WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .optional()?;
    match current {
        None => Err(CoreError::NotFound("appareil".into())),
        Some(true) => Err(CoreError::Validation(
            "impossible de révoquer l'appareil courant".into(),
        )),
        Some(false) => {
            conn.execute(
                "UPDATE devices SET revoked_at=?2 WHERE id=?1",
                params![id, now_rfc3339()],
            )?;
            Ok(())
        }
    }
}

pub fn is_device_revoked(conn: &Connection, id: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT revoked_at IS NOT NULL FROM devices WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false))
}

pub fn get_setting(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM settings WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        let mut c = crate::db::open_in_memory(&[1; 32]).unwrap();
        crate::db::migrate(&mut c).unwrap();
        c
    }

    #[test]
    fn profile_and_devices() {
        let c = conn();
        assert!(current_id(&c).is_err());
        let id = create(&c, "Awa", "dev-1").unwrap();
        assert_eq!(current_id(&c).unwrap(), id);
        set_field(&c, &id, "sync_repo", Some("me/control-center-sync")).unwrap();
        assert!(set_field(&c, &id, "totp_secret; DROP TABLE x", Some("x")).is_err());
        assert!(set_field(&c, &id, "display_name", Some(" ")).is_err());
        assert!(set_autolock(&c, &id, 100_000).is_err());
        let p = get(&c, &id).unwrap();
        assert_eq!(p.sync_repo.as_deref(), Some("me/control-center-sync"));
        assert!(!serde_json::to_string(&p).unwrap().contains("totp_secret"));
        upsert_device(&c, "dev-2", "Téléphone", "android").unwrap();
        assert_eq!(list_devices(&c).unwrap().len(), 2);
        assert!(revoke_device(&c, "dev-1").is_err());
        assert!(revoke_device(&c, "nope").is_err());
        revoke_device(&c, "dev-2").unwrap();
        assert!(is_device_revoked(&c, "dev-2").unwrap());
        assert!(!is_device_revoked(&c, "dev-1").unwrap());
        assert_eq!(get_setting(&c, "x").unwrap(), None);
        set_setting(&c, "x", "1").unwrap();
        set_setting(&c, "x", "2").unwrap();
        assert_eq!(get_setting(&c, "x").unwrap().as_deref(), Some("2"));
    }
}

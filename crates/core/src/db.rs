//! Base SQLCipher : ouverture avec clé brute, migrations versionnées.
use crate::{CoreError, Result};
use rusqlite::Connection;
use std::path::Path;

/// Migrations embarquées : (version, SQL). Ne jamais modifier une migration publiée.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_sync_meta.sql")),
];

/// Version de schéma la plus récente.
pub fn latest_version() -> u32 {
    MIGRATIONS.last().map_or(0, |m| m.0)
}

fn apply_key(conn: &Connection, key: &[u8; 32]) -> Result<()> {
    // Clé brute (pas de PBKDF2 SQLCipher : la dérivation est déjà faite par Argon2id).
    let hex = zeroize::Zeroizing::new(data_encoding::HEXLOWER.encode(key));
    conn.execute_batch(&format!("PRAGMA key = \"x'{}'\";", hex.as_str()))?;
    Ok(())
}

/// Ouvre (ou crée) la base chiffrée. Échoue avec `InvalidPassphrase` si la clé est fausse.
pub fn open(path: &Path, key: &[u8; 32]) -> Result<Connection> {
    let conn = Connection::open(path)?;
    apply_key(&conn, key)?;
    configure(&conn)?;
    Ok(conn)
}

/// Base en mémoire chiffrée (tests).
pub fn open_in_memory(key: &[u8; 32]) -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_key(&conn, key)?;
    configure(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<()> {
    // Lecture test : échoue si la clé est mauvaise ("file is not a database").
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|_| CoreError::InvalidPassphrase)?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA secure_delete = ON;
         PRAGMA journal_mode = DELETE;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(())
}

/// Change la clé de chiffrement (changement de phrase secrète).
pub fn rekey(conn: &Connection, new_key: &[u8; 32]) -> Result<()> {
    let hex = zeroize::Zeroizing::new(data_encoding::HEXLOWER.encode(new_key));
    conn.execute_batch(&format!("PRAGMA rekey = \"x'{}'\";", hex.as_str()))?;
    Ok(())
}

/// Applique les migrations manquantes, chacune dans une transaction.
pub fn migrate(conn: &mut Connection) -> Result<u32> {
    let current: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current > latest_version() {
        return Err(CoreError::Db(format!(
            "base créée par une version plus récente (schéma {current})"
        )));
    }
    for (v, sql) in MIGRATIONS.iter().filter(|(v, _)| *v > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {v};"))?;
        tx.commit()?;
    }
    Ok(latest_version())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_key_rejected_and_rekey() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.db");
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        {
            let mut c = open(&p, &k1).unwrap();
            migrate(&mut c).unwrap();
            c.execute("INSERT INTO settings(key,value) VALUES('a','b')", [])
                .unwrap();
        }
        assert!(matches!(open(&p, &k2), Err(CoreError::InvalidPassphrase)));
        {
            let c = open(&p, &k1).unwrap();
            rekey(&c, &k2).unwrap();
        }
        assert!(open(&p, &k1).is_err());
        let c = open(&p, &k2).unwrap();
        let v: String = c
            .query_row("SELECT value FROM settings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "b");
        // Fichier chiffré : pas d'en-tête SQLite en clair.
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.starts_with(b"SQLite format 3"));
    }

    #[test]
    fn migrations_idempotent_and_future_version_refused() {
        let mut c = open_in_memory(&[3u8; 32]).unwrap();
        assert_eq!(migrate(&mut c).unwrap(), latest_version());
        assert_eq!(migrate(&mut c).unwrap(), latest_version());
        c.execute_batch("PRAGMA user_version = 999;").unwrap();
        assert!(migrate(&mut c).is_err());
    }
}

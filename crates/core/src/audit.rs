//! Journal d'audit local append-only, chaîné par SHA-256.
//!
//! `hash_n = SHA-256(prev_hash ‖ champs de l'entrée n, préfixés par leur longueur)`.
//! Les triggers SQL refusent tout UPDATE/DELETE ; `verify_chain` détecte toute altération.
use crate::{crypto, now_rfc3339, CoreError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub seq: i64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: String,
    pub outcome: String,
    pub prev_hash: String,
    pub hash: String,
}

fn compute_hash(e: &AuditEntry) -> String {
    let mut buf = Vec::with_capacity(256);
    for field in [
        e.prev_hash.as_bytes(),
        e.seq.to_string().as_bytes(),
        e.ts.as_bytes(),
        e.actor.as_bytes(),
        e.action.as_bytes(),
        e.target.as_bytes(),
        e.details.as_bytes(),
        e.outcome.as_bytes(),
    ] {
        buf.extend_from_slice(&(field.len() as u64).to_be_bytes());
        buf.extend_from_slice(field);
    }
    crypto::sha256_hex(&buf)
}

/// Ajoute une entrée. `details` ne doit JAMAIS contenir de valeur secrète.
pub fn append(
    conn: &Connection,
    actor: &str,
    action: &str,
    target: &str,
    details: &serde_json::Value,
    outcome: &str,
) -> Result<AuditEntry> {
    let last: Option<(i64, String)> = conn
        .query_row(
            "SELECT seq, hash FROM audit_logs ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (seq, prev_hash) = last.map_or((1, GENESIS.to_string()), |(s, h)| (s + 1, h));
    let mut e = AuditEntry {
        seq,
        ts: now_rfc3339(),
        actor: actor.to_owned(),
        action: action.to_owned(),
        target: target.to_owned(),
        details: details.to_string(),
        outcome: outcome.to_owned(),
        prev_hash,
        hash: String::new(),
    };
    e.hash = compute_hash(&e);
    conn.execute(
        "INSERT INTO audit_logs(seq,ts,actor,action,target,details,outcome,prev_hash,hash)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            e.seq,
            e.ts,
            e.actor,
            e.action,
            e.target,
            e.details,
            e.outcome,
            e.prev_hash,
            e.hash
        ],
    )?;
    Ok(e)
}

/// Liste les entrées les plus récentes d'abord.
pub fn list(conn: &Connection, limit: u32, offset: u32) -> Result<Vec<AuditEntry>> {
    let mut st = conn.prepare(
        "SELECT seq,ts,actor,action,target,details,outcome,prev_hash,hash
         FROM audit_logs ORDER BY seq DESC LIMIT ?1 OFFSET ?2",
    )?;
    let rows = st.query_map(params![limit.min(1000), offset], row_to_entry)?;
    rows.collect::<std::result::Result<_, _>>()
        .map_err(Into::into)
}

fn row_to_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        seq: r.get(0)?,
        ts: r.get(1)?,
        actor: r.get(2)?,
        action: r.get(3)?,
        target: r.get(4)?,
        details: r.get(5)?,
        outcome: r.get(6)?,
        prev_hash: r.get(7)?,
        hash: r.get(8)?,
    })
}

/// Rapport de vérification.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ChainReport {
    pub entries: i64,
    pub head: String,
}

/// Vérifie toute la chaîne. Renvoie `Integrity` à la première entrée incohérente.
pub fn verify_chain(conn: &Connection) -> Result<ChainReport> {
    let mut st = conn.prepare(
        "SELECT seq,ts,actor,action,target,details,outcome,prev_hash,hash
         FROM audit_logs ORDER BY seq ASC",
    )?;
    let mut prev = GENESIS.to_string();
    let mut n = 0;
    for (expected_seq, e) in (1..).zip(st.query_map([], row_to_entry)?) {
        let e = e?;
        if e.seq != expected_seq {
            return Err(CoreError::Integrity(format!(
                "entrée {expected_seq} manquante"
            )));
        }
        if e.prev_hash != prev || compute_hash(&e) != e.hash {
            return Err(CoreError::Integrity(format!("entrée {} altérée", e.seq)));
        }
        prev = e.hash;
        n += 1;
    }
    Ok(ChainReport {
        entries: n,
        head: prev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use serde_json::json;

    fn conn() -> Connection {
        let mut c = db::open_in_memory(&[9u8; 32]).unwrap();
        db::migrate(&mut c).unwrap();
        c
    }

    #[test]
    fn chain_builds_and_verifies() {
        let c = conn();
        assert_eq!(verify_chain(&c).unwrap().entries, 0);
        let a = append(&c, "owner", "vault.create", "", &json!({}), "ok").unwrap();
        let b = append(
            &c,
            "owner",
            "app.create",
            "app-1",
            &json!({"name":"x"}),
            "ok",
        )
        .unwrap();
        assert_eq!(a.prev_hash, GENESIS);
        assert_eq!(b.prev_hash, a.hash);
        let r = verify_chain(&c).unwrap();
        assert_eq!(r.entries, 2);
        assert_eq!(r.head, b.hash);
        let l = list(&c, 10, 0).unwrap();
        assert_eq!(l[0].seq, 2);
    }

    #[test]
    fn append_only() {
        let c = conn();
        append(&c, "owner", "x", "", &json!({}), "ok").unwrap();
        assert!(c.execute("UPDATE audit_logs SET actor='evil'", []).is_err());
        assert!(c.execute("DELETE FROM audit_logs", []).is_err());
    }

    #[test]
    fn chain_detects_tamper() {
        let c = conn();
        for i in 0..5 {
            append(&c, "owner", "act", &i.to_string(), &json!({}), "ok").unwrap();
        }
        // Un attaquant qui a la clé contourne les triggers pour réécrire une entrée.
        c.execute_batch("DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;")
            .unwrap();
        c.execute("UPDATE audit_logs SET target='forged' WHERE seq=3", [])
            .unwrap();
        assert!(matches!(verify_chain(&c), Err(CoreError::Integrity(_))));
        // Suppression d'une entrée → trou détecté.
        let c2 = conn();
        for _ in 0..3 {
            append(&c2, "o", "a", "", &json!({}), "ok").unwrap();
        }
        c2.execute_batch("DROP TRIGGER audit_no_delete;").unwrap();
        c2.execute("DELETE FROM audit_logs WHERE seq=2", [])
            .unwrap();
        assert!(matches!(verify_chain(&c2), Err(CoreError::Integrity(_))));
    }
}

//! Synchronisation chiffrée entre appareils.
//!
//! - Journal : chaque changement local d'un enregistrement devient un événement horodaté par HLC.
//! - Transport (assuré par l'appelant) : fichiers `events/<appareil>/<hlc>_<lot>.ccev` dans le
//!   dépôt privé ; chaque lot est chiffré par XChaCha20-Poly1305 (données associées : version,
//!   époque, appareil, lot). GitHub ne voit que du chiffré.
//! - Fusion : dernier écrivain gagnant par enregistrement (ordre total HLC) → convergence ;
//!   les modifications concurrentes sont conservées dans `sync_conflicts` pour résolution manuelle.
use crate::crypto::{self, KdfParams, Key32};
use crate::hlc::Hlc;
use crate::secrets::{SecretStore, SecretValue};
use crate::vault::Session;
use crate::{new_id, now_rfc3339, profile, CoreError, Result};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};

/// Tables synchronisées, dans l'ordre d'application (parents avant enfants).
/// (table, clé primaire, colonnes propres à l'appareil non synchronisées)
pub const ENTITIES: &[(&str, &str, &[&str])] = &[
    ("devices", "id", &["is_current", "last_seen"]),
    ("apps", "id", &[]),
    ("secrets_meta", "id", &["last_used_at"]),
    ("connectors", "id", &["last_test_at", "last_test_ok"]),
    ("env_vars", "id", &[]),
    ("products", "id", &[]),
    ("customers", "id", &[]),
    ("sales", "id", &[]),
    ("licenses", "id", &[]),
    ("revocations", "license_id", &[]),
    ("revocation_lists", "seq", &[]),
];

const MAGIC: &str = "cc-sync";
const BATCH_MAX: usize = 500;

fn spec(entity: &str) -> Result<(&'static str, &'static str, &'static [&'static str])> {
    ENTITIES
        .iter()
        .find(|(t, _, _)| *t == entity)
        .copied()
        .ok_or_else(|| CoreError::Validation(format!("entité non synchronisée : {entity}")))
}

fn order(entity: &str) -> usize {
    ENTITIES
        .iter()
        .position(|(t, _, _)| *t == entity)
        .unwrap_or(usize::MAX)
}

fn now_ms() -> u64 {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000).unwrap_or(0)
}

// ---------- Clé et métadonnées du dépôt ----------

/// Métadonnées publiques du dépôt de synchronisation (`meta.json`, non secret).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncMeta {
    pub format: String,
    pub version: u32,
    pub epoch: u32,
    pub kdf: KdfParams,
    pub salt: String,
    /// Valeur témoin chiffrée : permet de vérifier la phrase secrète.
    pub check: String,
}

/// Clé de synchronisation d'une époque.
pub struct SyncKey {
    pub epoch: u32,
    key: Key32,
}

impl std::fmt::Debug for SyncKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncKey")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

fn check_aad(epoch: u32) -> Vec<u8> {
    format!("{MAGIC}|check|{epoch}").into_bytes()
}

/// Crée les métadonnées d'une nouvelle époque (premier appareil, ou rotation après révocation).
pub fn new_meta(passphrase: &str, epoch: u32, kdf: KdfParams) -> Result<(SyncMeta, SyncKey)> {
    let salt = crypto::random_bytes::<16>();
    let key = crypto::derive_key(passphrase.as_bytes(), &salt, kdf)?;
    let meta = SyncMeta {
        format: MAGIC.into(),
        version: 1,
        epoch,
        kdf,
        salt: crypto::b64(&salt),
        check: crypto::b64(&crypto::seal(&key, b"control-center", &check_aad(epoch))?),
    };
    Ok((meta, SyncKey { epoch, key }))
}

/// Dérive la clé depuis la phrase secrète et vérifie la valeur témoin.
pub fn unlock_meta(meta: &SyncMeta, passphrase: &str) -> Result<SyncKey> {
    if meta.format != MAGIC || meta.version != 1 {
        return Err(CoreError::Validation(
            "dépôt de synchronisation incompatible".into(),
        ));
    }
    if meta.kdf.m_kib > 1024 * 1024 || meta.kdf.t > 20 || meta.kdf.p > 8 {
        return Err(CoreError::Validation(
            "paramètres de dérivation hors limites".into(),
        ));
    }
    let key = crypto::derive_key(passphrase.as_bytes(), &crypto::unb64(&meta.salt)?, meta.kdf)?;
    crypto::open(&key, &crypto::unb64(&meta.check)?, &check_aad(meta.epoch))
        .map_err(|_| CoreError::InvalidPassphrase)?;
    Ok(SyncKey {
        epoch: meta.epoch,
        key,
    })
}

/// Mémorise la clé (trousseau / coffre) pour les synchronisations suivantes.
pub fn store_key(s: &Session, k: &SyncKey) -> Result<()> {
    s.secrets.put(
        "sync-key",
        &SecretValue::new(format!("{}:{}", k.epoch, crypto::b64(&*k.key))),
    )
}

pub fn stored_key(s: &Session) -> Result<Option<SyncKey>> {
    let Some(v) = s.secrets.get("sync-key")? else {
        return Ok(None);
    };
    let (e, k) = v
        .expose()
        .split_once(':')
        .ok_or_else(|| CoreError::Integrity("clé de sync".into()))?;
    let raw = crypto::unb64(k)?;
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    if raw.len() != 32 {
        return Err(CoreError::Integrity("clé de sync".into()));
    }
    key.copy_from_slice(&raw);
    Ok(Some(SyncKey {
        epoch: e
            .parse()
            .map_err(|_| CoreError::Integrity("époque".into()))?,
        key,
    }))
}

pub fn forget_key(s: &Session) -> Result<()> {
    s.secrets.delete("sync-key")
}

// ---------- Collecte des enregistrements ----------

fn sql_to_json(v: SqlValue) -> Value {
    match v {
        SqlValue::Null => Value::Null,
        SqlValue::Integer(i) => Value::from(i),
        SqlValue::Real(f) => Value::from(f),
        SqlValue::Text(t) => Value::from(t),
        SqlValue::Blob(b) => Value::from(crypto::b64(&b)),
    }
}

fn json_to_sql(v: &Value) -> SqlValue {
    match v {
        Value::Null => SqlValue::Null,
        Value::Bool(b) => SqlValue::Integer(i64::from(*b)),
        Value::Number(n) => n.as_i64().map_or_else(
            || SqlValue::Real(n.as_f64().unwrap_or(0.0)),
            SqlValue::Integer,
        ),
        Value::String(s) => SqlValue::Text(s.clone()),
        other => SqlValue::Text(other.to_string()),
    }
}

fn columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let mut st = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let v = st
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

/// Lit les lignes d'une table (sans valeurs secrètes). `id` = None → toutes.
fn rows(conn: &Connection, entity: &str, id: Option<&str>) -> Result<BTreeMap<String, Value>> {
    let (table, pk, excluded) = spec(entity)?;
    let cols: Vec<String> = columns(conn, table)?
        .into_iter()
        .filter(|c| !excluded.contains(&c.as_str()))
        .collect();
    let sql = match id {
        Some(_) => format!(
            "SELECT {} FROM {table} WHERE CAST({pk} AS TEXT)=?1",
            cols.join(",")
        ),
        None => format!("SELECT {} FROM {table}", cols.join(",")),
    };
    let mut st = conn.prepare(&sql)?;
    let map_row = |r: &rusqlite::Row<'_>| -> rusqlite::Result<(String, Value)> {
        let mut m = Map::new();
        for (i, c) in cols.iter().enumerate() {
            m.insert(c.clone(), sql_to_json(r.get::<_, SqlValue>(i)?));
        }
        let key = match m.get(pk) {
            Some(Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => String::new(),
        };
        Ok((key, Value::Object(m)))
    };
    let list: Vec<(String, Value)> = match id {
        Some(i) => st
            .query_map([i], map_row)?
            .collect::<std::result::Result<_, _>>()?,
        None => st
            .query_map([], map_row)?
            .collect::<std::result::Result<_, _>>()?,
    };
    let mut out: BTreeMap<String, Value> = list.into_iter().collect();
    if entity == "apps" {
        for (app_id, v) in &mut out {
            let mut st = conn.prepare(
                "SELECT action, allowed FROM permissions WHERE app_id=?1 ORDER BY action",
            )?;
            let perms: Map<String, Value> = st
                .query_map([app_id], |r| {
                    Ok((r.get::<_, String>(0)?, Value::from(r.get::<_, bool>(1)?)))
                })?
                .collect::<std::result::Result<_, _>>()?;
            v["_permissions"] = Value::Object(perms);
        }
    }
    Ok(out)
}

/// Ajoute la valeur (complète) ou son empreinte (forme expurgée) aux secrets.
fn attach_secret(store: &dyn SecretStore, id: &str, payload: &mut Value, full: bool) -> Result<()> {
    let v = store
        .get(id)?
        .map(|s| s.expose().to_owned())
        .unwrap_or_default();
    if full {
        payload["value"] = Value::from(v);
    } else {
        payload["value_hash"] = Value::from(crypto::sha256_hex(v.as_bytes()));
    }
    Ok(())
}

/// Forme expurgée (stockée localement) : la valeur d'un secret est remplacée par son empreinte.
fn redact(entity: &str, payload: &Value) -> Value {
    let mut p = payload.clone();
    if entity == "secrets_meta" {
        if let Some(v) = p.get("value").and_then(Value::as_str) {
            let h = crypto::sha256_hex(v.as_bytes());
            p["value_hash"] = Value::from(h);
        }
        if let Some(o) = p.as_object_mut() {
            o.remove("value");
        }
    }
    p
}

/// Tous les enregistrements locaux, forme expurgée.
fn collect_all(s: &Session) -> Result<BTreeMap<(String, String), Value>> {
    let mut out = BTreeMap::new();
    let snapshot: Vec<(String, BTreeMap<String, Value>)> = {
        let c = s.conn.lock();
        ENTITIES
            .iter()
            .map(|(e, _, _)| rows(&c, e, None).map(|r| ((*e).to_owned(), r)))
            .collect::<Result<_>>()?
    };
    for (entity, recs) in snapshot {
        for (id, mut p) in recs {
            if entity == "secrets_meta" {
                attach_secret(s.secrets.as_ref(), &id, &mut p, false)?;
            }
            out.insert((entity.clone(), id), p);
        }
    }
    Ok(out)
}

/// Un enregistrement local complet (avec valeur secrète), pour l'envoi.
fn collect_one_full(s: &Session, entity: &str, id: &str) -> Result<Option<Value>> {
    let p = {
        let c = s.conn.lock();
        rows(&c, entity, Some(id))?.remove(id)
    };
    match p {
        Some(mut p) => {
            if entity == "secrets_meta" {
                attach_secret(s.secrets.as_ref(), id, &mut p, true)?;
            }
            Ok(Some(p))
        }
        None => Ok(None),
    }
}

// ---------- Application d'un enregistrement ----------

enum StoreOp {
    Put(String, SecretValue),
    Delete(String),
}

fn apply(
    conn: &Connection,
    entity: &str,
    id: &str,
    payload: Option<&Value>,
    store_ops: &mut Vec<StoreOp>,
) -> Result<()> {
    let (table, pk, _) = spec(entity)?;
    let Some(p) = payload else {
        conn.execute(
            &format!("DELETE FROM {table} WHERE CAST({pk} AS TEXT)=?1"),
            [id],
        )?;
        if entity == "secrets_meta" {
            store_ops.push(StoreOp::Delete(id.to_owned()));
        }
        return Ok(());
    };
    let obj = p
        .as_object()
        .ok_or_else(|| CoreError::Validation("enregistrement invalide".into()))?;
    let allowed = columns(conn, table)?;
    let cols: Vec<&String> = obj.keys().filter(|k| allowed.contains(k)).collect();
    if !cols.iter().any(|c| c.as_str() == pk) {
        return Err(CoreError::Validation("clé primaire manquante".into()));
    }
    let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    let updates: Vec<String> = cols
        .iter()
        .filter(|c| c.as_str() != pk)
        .map(|c| format!("{c}=excluded.{c}"))
        .collect();
    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({}) ON CONFLICT({pk}) DO {}",
        cols.iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join(","),
        placeholders.join(","),
        if updates.is_empty() {
            "NOTHING".to_owned()
        } else {
            format!("UPDATE SET {}", updates.join(","))
        }
    );
    let values: Vec<SqlValue> = cols.iter().map(|c| json_to_sql(&obj[c.as_str()])).collect();
    conn.execute(&sql, rusqlite::params_from_iter(values))?;
    match entity {
        "apps" => {
            if let Some(perms) = obj.get("_permissions").and_then(Value::as_object) {
                conn.execute("DELETE FROM permissions WHERE app_id=?1", [id])?;
                for (a, allowed) in perms {
                    if crate::policy::Action::parse(a).is_ok() {
                        conn.execute(
                            "INSERT INTO permissions(app_id, action, allowed) VALUES (?1,?2,?3)",
                            params![id, a, allowed.as_bool().unwrap_or(false)],
                        )?;
                    }
                }
            }
            for env in ["development", "preview", "production"] {
                conn.execute(
                    "INSERT OR IGNORE INTO environments(id, app_id, kind) VALUES (?1,?2,?3)",
                    params![new_id(), id, env],
                )?;
            }
        }
        "secrets_meta" => {
            if let Some(v) = obj.get("value").and_then(Value::as_str) {
                store_ops.push(StoreOp::Put(id.to_owned(), SecretValue::new(v)));
            }
        }
        _ => {}
    }
    Ok(())
}

fn run_store_ops(store: &dyn SecretStore, ops: Vec<StoreOp>) -> Result<()> {
    for op in ops {
        match op {
            StoreOp::Put(id, v) => store.put(&id, &v)?,
            StoreOp::Delete(id) => store.delete(&id)?,
        }
    }
    Ok(())
}

// ---------- Journal local ----------

#[derive(Clone, Debug)]
struct Known {
    hlc: String,
    device: String,
    deleted: bool,
    payload: Value,
}

fn known(conn: &Connection) -> Result<HashMap<(String, String), Known>> {
    let mut st = conn
        .prepare("SELECT entity, entity_id, hlc, device_id, deleted, payload FROM sync_records")?;
    let v = st
        .query_map([], |r| {
            let p: String = r.get(5)?;
            Ok((
                (r.get(0)?, r.get(1)?),
                Known {
                    hlc: r.get(2)?,
                    device: r.get(3)?,
                    deleted: r.get(4)?,
                    payload: serde_json::from_str(&p).unwrap_or(Value::Null),
                },
            ))
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

fn known_one(conn: &Connection, entity: &str, id: &str) -> Result<Option<Known>> {
    Ok(conn
        .query_row(
            "SELECT hlc, device_id, deleted, payload FROM sync_records WHERE entity=?1 AND entity_id=?2",
            params![entity, id],
            |r| {
                let p: String = r.get(3)?;
                Ok(Known { hlc: r.get(0)?, device: r.get(1)?, deleted: r.get(2)?, payload: serde_json::from_str(&p).unwrap_or(Value::Null) })
            },
        )
        .optional()?)
}

fn set_record(
    conn: &Connection,
    entity: &str,
    id: &str,
    hlc: &str,
    device: &str,
    payload: Option<&Value>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_records(entity, entity_id, hlc, device_id, deleted, payload) VALUES (?1,?2,?3,?4,?5,?6)
         ON CONFLICT(entity, entity_id) DO UPDATE SET hlc=excluded.hlc, device_id=excluded.device_id,
            deleted=excluded.deleted, payload=excluded.payload",
        params![entity, id, hlc, device, payload.is_none(), payload.map_or_else(|| "null".to_owned(), Value::to_string)],
    )?;
    Ok(())
}

fn last_hlc(conn: &Connection) -> Result<Option<Hlc>> {
    conn.query_row("SELECT value FROM sync_state WHERE key='hlc'", [], |r| {
        r.get::<_, String>(0)
    })
    .optional()?
    .map(|s| Hlc::parse(&s))
    .transpose()
}

fn save_hlc(conn: &Connection, h: &Hlc) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_state(key, value) VALUES ('hlc', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [h.to_string()],
    )?;
    Ok(())
}

/// Transforme les changements locaux (depuis la dernière capture) en événements horodatés.
pub fn capture(s: &Session) -> Result<usize> {
    capture_at(s, now_ms())
}

pub fn capture_at(s: &Session, now: u64) -> Result<usize> {
    let local = collect_all(s)?;
    let c = s.conn.lock();
    let known = known(&c)?;
    let mut clock = last_hlc(&c)?;
    let mut changes: Vec<(String, String, Option<Value>, Option<String>)> = Vec::new();
    for ((e, id), p) in &local {
        match known.get(&(e.clone(), id.clone())) {
            Some(k) if !k.deleted && &k.payload == p => {}
            k => changes.push((
                e.clone(),
                id.clone(),
                Some(p.clone()),
                k.map(|k| k.hlc.clone()),
            )),
        }
    }
    for ((e, id), k) in &known {
        if !k.deleted && !local.contains_key(&(e.clone(), id.clone())) {
            changes.push((e.clone(), id.clone(), None, Some(k.hlc.clone())));
        }
    }
    changes.sort_by_key(|(e, _, p, _)| {
        if p.is_some() {
            order(e)
        } else {
            usize::MAX - order(e)
        }
    });
    for (e, id, p, base) in &changes {
        let h = Hlc::tick(clock.as_ref(), now, &s.device_id);
        c.execute(
            "INSERT INTO sync_events(id, device_id, hlc, entity, entity_id, op, payload, base_hlc, pushed, applied, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,0,1,?9)",
            params![new_id(), s.device_id, h.to_string(), e, id, if p.is_some() { "upsert" } else { "delete" },
                    p.as_ref().map_or_else(|| "null".into(), Value::to_string), base, now_rfc3339()],
        )?;
        set_record(&c, e, id, &h.to_string(), &s.device_id, p.as_ref())?;
        clock = Some(h);
    }
    if let Some(h) = &clock {
        save_hlc(&c, h)?;
    }
    Ok(changes.len())
}

// ---------- Lots chiffrés ----------

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct WireEvent {
    id: String,
    hlc: String,
    entity: String,
    entity_id: String,
    op: String,
    base_hlc: Option<String>,
    payload: Option<Value>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    epoch: u32,
    device: String,
    batch: String,
    ct: String,
}

fn batch_aad(epoch: u32, device: &str, batch: &str) -> Vec<u8> {
    format!("{MAGIC}|batch|1|{epoch}|{device}|{batch}").into_bytes()
}

/// Lot prêt à être poussé.
#[derive(Debug)]
pub struct Batch {
    pub file_name: String,
    pub bytes: Vec<u8>,
    pub event_ids: Vec<String>,
}

/// Construit le prochain lot chiffré des événements locaux non poussés.
pub fn build_batch(s: &Session, key: &SyncKey) -> Result<Option<Batch>> {
    let pending: Vec<(String, String, String, String, String, Option<String>)> = {
        let c = s.conn.lock();
        let mut st = c.prepare(
            "SELECT id, hlc, entity, entity_id, op, base_hlc FROM sync_events
             WHERE pushed=0 AND device_id=?1 ORDER BY hlc LIMIT ?2",
        )?;
        let v = st
            .query_map(params![s.device_id, BATCH_MAX], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })?
            .collect::<std::result::Result<_, _>>()?;
        v
    };
    if pending.is_empty() {
        return Ok(None);
    }
    let mut wire = Vec::new();
    let mut ids = Vec::new();
    for (id, hlc, entity, entity_id, op, base) in pending {
        ids.push(id.clone());
        // Événement remplacé depuis (par un plus récent, local ou distant) : rien à envoyer.
        let current = known_one(&s.conn.lock(), &entity, &entity_id)?;
        if current.as_ref().map(|k| k.hlc.as_str()) != Some(hlc.as_str()) {
            continue;
        }
        let payload = if op == "upsert" {
            match collect_one_full(s, &entity, &entity_id)? {
                Some(p) => Some(p),
                None => continue,
            }
        } else {
            None
        };
        wire.push(WireEvent {
            id,
            hlc,
            entity,
            entity_id,
            op,
            base_hlc: base,
            payload,
        });
    }
    let batch_id = new_id();
    let first = wire
        .first()
        .map_or_else(|| "0".repeat(13), |w| w.hlc.clone());
    let plain = zeroize::Zeroizing::new(serde_json::to_vec(&wire)?);
    let env = Envelope {
        v: 1,
        epoch: key.epoch,
        device: s.device_id.clone(),
        ct: crypto::b64(&crypto::seal(
            &key.key,
            &plain,
            &batch_aad(key.epoch, &s.device_id, &batch_id),
        )?),
        batch: batch_id.clone(),
    };
    Ok(Some(Batch {
        file_name: format!("{first}_{batch_id}.ccev"),
        bytes: serde_json::to_vec(&env)?,
        event_ids: ids,
    }))
}

/// Marque les événements du lot comme poussés (après succès du transport).
pub fn mark_pushed(s: &Session, batch: &Batch) -> Result<()> {
    let c = s.conn.lock();
    for id in &batch.event_ids {
        c.execute("UPDATE sync_events SET pushed=1 WHERE id=?1", [id])?;
    }
    Ok(())
}

/// Bilan d'une fusion.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct MergeReport {
    pub applied: usize,
    pub skipped: usize,
    pub conflicts: usize,
}

/// Déchiffre, authentifie et fusionne un lot reçu de `device_dir`.
pub fn ingest(s: &Session, key: &SyncKey, device_dir: &str, bytes: &[u8]) -> Result<MergeReport> {
    ingest_at(s, key, device_dir, bytes, now_ms())
}

pub fn ingest_at(
    s: &Session,
    key: &SyncKey,
    device_dir: &str,
    bytes: &[u8],
    now: u64,
) -> Result<MergeReport> {
    if bytes.len() > 20 * 1024 * 1024 {
        return Err(CoreError::Validation("lot trop volumineux".into()));
    }
    let env: Envelope =
        serde_json::from_slice(bytes).map_err(|_| CoreError::Integrity("lot illisible".into()))?;
    if env.v != 1 || env.epoch != key.epoch {
        return Err(CoreError::Integrity(
            "lot d'une autre époque ou version".into(),
        ));
    }
    if env.device != device_dir {
        return Err(CoreError::Integrity(
            "lot déplacé d'un appareil à un autre".into(),
        ));
    }
    let plain = crypto::open(
        &key.key,
        &crypto::unb64(&env.ct)?,
        &batch_aad(env.epoch, &env.device, &env.batch),
    )
    .map_err(|_| CoreError::Integrity("lot altéré ou mauvaise clé".into()))?;
    let mut events: Vec<WireEvent> = serde_json::from_slice(&plain)
        .map_err(|_| CoreError::Integrity("contenu invalide".into()))?;
    if env.device == s.device_id {
        return Ok(MergeReport {
            skipped: events.len(),
            ..MergeReport::default()
        });
    }
    if profile::is_device_revoked(&s.conn.lock(), &env.device)? {
        return Err(CoreError::Forbidden("appareil révoqué".into()));
    }
    events.sort_by(|a, b| (order(&a.entity), &a.hlc).cmp(&(order(&b.entity), &b.hlc)));
    // Valeurs secrètes locales lues AVANT de verrouiller la base (le stockage de repli l'utilise).
    let mut local_secret_values: HashMap<String, String> = HashMap::new();
    for e in events.iter().filter(|e| e.entity == "secrets_meta") {
        if let Some(v) = s.secrets.get(&e.entity_id)? {
            local_secret_values.insert(e.entity_id.clone(), v.expose().to_owned());
        }
    }
    let mut report = MergeReport::default();
    let mut store_ops = Vec::new();
    {
        let mut c = s.conn.lock();
        let tx = c.transaction()?;
        tx.execute_batch("PRAGMA defer_foreign_keys = ON;")?;
        let mut clock = last_hlc(&tx)?;
        for ev in &events {
            spec(&ev.entity)?;
            let seen: bool = tx.query_row(
                "SELECT count(*) FROM sync_events WHERE id=?1",
                [&ev.id],
                |r| r.get::<_, i64>(0),
            )? > 0;
            if seen {
                report.skipped += 1;
                continue;
            }
            let h = Hlc::parse(&ev.hlc)?;
            if h.device != env.device {
                return Err(CoreError::Integrity("HLC d'un autre appareil".into()));
            }
            clock = Some(Hlc::observe(clock.as_ref(), &h, now, &s.device_id));
            let cur = known_one(&tx, &ev.entity, &ev.entity_id)?;
            let concurrent = cur
                .as_ref()
                .is_some_and(|k| Some(&k.hlc) != ev.base_hlc.as_ref() && k.device != env.device);
            let incoming_newer = cur.as_ref().is_none_or(|k| ev.hlc > k.hlc);
            let payload = if ev.op == "upsert" {
                ev.payload.as_ref()
            } else {
                None
            };
            if incoming_newer {
                if concurrent {
                    // Perdant = version locale actuelle (complète, pour pouvoir la restaurer).
                    let mut loser =
                        rows(&tx, &ev.entity, Some(&ev.entity_id))?.remove(&ev.entity_id);
                    if let (Some(l), Some(v)) =
                        (loser.as_mut(), local_secret_values.get(&ev.entity_id))
                    {
                        l["value"] = Value::from(v.clone());
                    }
                    record_conflict(
                        &tx,
                        ev,
                        cur.as_ref().map(|k| k.hlc.as_str()).unwrap_or_default(),
                        loser.as_ref(),
                    )?;
                    report.conflicts += 1;
                }
                apply(&tx, &ev.entity, &ev.entity_id, payload, &mut store_ops)?;
                set_record(
                    &tx,
                    &ev.entity,
                    &ev.entity_id,
                    &ev.hlc,
                    &env.device,
                    payload.map(|p| redact(&ev.entity, p)).as_ref(),
                )?;
                report.applied += 1;
            } else {
                if concurrent {
                    record_conflict(&tx, ev, &ev.hlc, payload)?;
                    report.conflicts += 1;
                }
                report.skipped += 1;
            }
            tx.execute(
                "INSERT INTO sync_events(id, device_id, hlc, entity, entity_id, op, payload, base_hlc, pushed, applied, created_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,1,1,?9)",
                params![ev.id, env.device, ev.hlc, ev.entity, ev.entity_id, ev.op,
                        payload.map_or_else(|| "null".into(), |p| redact(&ev.entity, p).to_string()), ev.base_hlc, now_rfc3339()],
            )?;
        }
        if let Some(h) = &clock {
            save_hlc(&tx, h)?;
        }
        tx.commit()?;
    }
    run_store_ops(s.secrets.as_ref(), store_ops)?;
    Ok(report)
}

fn record_conflict(
    conn: &Connection,
    ev: &WireEvent,
    loser_ref: &str,
    loser_payload: Option<&Value>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_conflicts(id, entity, entity_id, winner_event, loser_event, loser_payload, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![new_id(), ev.entity, ev.entity_id, ev.id, loser_ref,
                loser_payload.map_or_else(|| "null".into(), Value::to_string), now_rfc3339()],
    )?;
    Ok(())
}

// ---------- Conflits ----------

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Conflict {
    pub id: String,
    pub entity: String,
    pub entity_id: String,
    /// Version retenue automatiquement (actuelle), valeurs secrètes masquées.
    pub current: Value,
    /// Version écartée, valeurs secrètes masquées.
    pub discarded: Value,
    pub created_at: String,
}

fn mask(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        if o.contains_key("value") {
            o.insert("value".into(), Value::from("••••"));
        }
        o.remove("value_hash");
    }
    v
}

pub fn conflicts(s: &Session) -> Result<Vec<Conflict>> {
    let raw: Vec<(String, String, String, String, String)> = {
        let c = s.conn.lock();
        let mut st = c.prepare(
            "SELECT id, entity, entity_id, loser_payload, created_at FROM sync_conflicts WHERE resolved=0 ORDER BY created_at",
        )?;
        let v = st
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<std::result::Result<_, _>>()?;
        v
    };
    raw.into_iter()
        .map(|(id, entity, entity_id, loser, created_at)| {
            let current = collect_one_full(s, &entity, &entity_id)?.unwrap_or(Value::Null);
            Ok(Conflict {
                id,
                current: mask(current),
                discarded: mask(serde_json::from_str(&loser).unwrap_or(Value::Null)),
                entity,
                entity_id,
                created_at,
            })
        })
        .collect()
}

/// Résolution manuelle : garder la version actuelle, ou restaurer la version écartée
/// (qui devient une nouvelle modification locale, propagée à tous les appareils).
pub fn resolve(s: &Session, conflict_id: &str, restore_discarded: bool) -> Result<()> {
    let (entity, entity_id, loser): (String, String, String) = s
        .conn
        .lock()
        .query_row(
            "SELECT entity, entity_id, loser_payload FROM sync_conflicts WHERE id=?1 AND resolved=0",
            [conflict_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound("conflit".into()))?;
    if restore_discarded {
        let payload: Value = serde_json::from_str(&loser)?;
        let mut ops = Vec::new();
        {
            let mut c = s.conn.lock();
            let tx = c.transaction()?;
            tx.execute_batch("PRAGMA defer_foreign_keys = ON;")?;
            apply(
                &tx,
                &entity,
                &entity_id,
                if payload.is_null() {
                    None
                } else {
                    Some(&payload)
                },
                &mut ops,
            )?;
            tx.commit()?;
        }
        run_store_ops(s.secrets.as_ref(), ops)?;
        capture(s)?;
    }
    s.conn.lock().execute(
        "UPDATE sync_conflicts SET resolved=1, loser_payload='null' WHERE id=?1",
        [conflict_id],
    )?;
    s.audit(
        "sync.conflict.resolve",
        &entity_id,
        &serde_json::json!({"entity": entity, "restored": restore_discarded}),
        "ok",
    )
}

// ---------- Curseurs de lecture ----------

pub fn cursor(s: &Session, device: &str) -> Result<Option<String>> {
    Ok(s.conn
        .lock()
        .query_row(
            "SELECT value FROM sync_state WHERE key=?1",
            [format!("cursor:{device}")],
            |r| r.get(0),
        )
        .optional()?)
}

pub fn set_cursor(s: &Session, device: &str, file: &str) -> Result<()> {
    s.conn.lock().execute(
        "INSERT INTO sync_state(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![format!("cursor:{device}"), file],
    )?;
    Ok(())
}

/// Réinitialise les curseurs (nouvelle époque).
pub fn reset_cursors(s: &Session) -> Result<()> {
    s.conn
        .lock()
        .execute("DELETE FROM sync_state WHERE key LIKE 'cursor:%'", [])?;
    Ok(())
}

/// Nouvelle époque : tous les enregistrements sont ré-émis (ré-chiffrés avec la nouvelle clé).
pub fn reemit_all(s: &Session) -> Result<usize> {
    {
        let c = s.conn.lock();
        c.execute("DELETE FROM sync_records", [])?;
        c.execute("UPDATE sync_events SET pushed=1 WHERE pushed=0", [])?;
    }
    capture(s)
}

/// Charge utile du QR code d'appairage (aucun secret : la phrase secrète est saisie à part).
pub fn pairing_payload(s: &Session, repo: &str, epoch: u32) -> Result<String> {
    Ok(serde_json::json!({"cc": "pair", "v": 1, "repo": repo, "epoch": epoch, "from": s.device_id}).to_string())
}

pub fn pairing_qr_png_base64(payload: &str) -> Result<String> {
    qrcodegen_image::draw_base64(payload).map_err(CoreError::Validation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::{self, NewApp};
    use crate::keys;
    use crate::vault::tests::new_vault;
    use crate::vault::Vault;
    use std::collections::BTreeMap as Repo;

    const KDF: KdfParams = KdfParams::INSECURE_FAST_FOR_TESTS;

    /// Dépôt simulé : chemin → contenu (ce que GitHub verrait).
    fn sync(v: &Vault, key: &SyncKey, repo: &mut Repo<String, Vec<u8>>, now: u64) -> MergeReport {
        let s = v.session().unwrap();
        capture_at(s, now).unwrap();
        let mut total = MergeReport::default();
        let devices: Vec<String> = repo
            .keys()
            .filter_map(|k| k.split('/').nth(1).map(str::to_owned))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        for d in devices {
            let cur = cursor(s, &d).unwrap();
            let files: Vec<(String, Vec<u8>)> = repo
                .iter()
                .filter(|(k, _)| k.starts_with(&format!("events/{d}/")))
                .map(|(k, v)| (k.rsplit('/').next().unwrap().to_owned(), v.clone()))
                .filter(|(f, _)| cur.as_deref().is_none_or(|c| f.as_str() > c))
                .collect();
            for (f, bytes) in files {
                let r = ingest_at(s, key, &d, &bytes, now).unwrap();
                total.applied += r.applied;
                total.conflicts += r.conflicts;
                set_cursor(s, &d, &f).unwrap();
            }
        }
        while let Some(b) = build_batch(s, key).unwrap() {
            repo.insert(
                format!("events/{}/{}", s.device_id, b.file_name),
                b.bytes.clone(),
            );
            mark_pushed(s, &b).unwrap();
        }
        total
    }

    fn state(v: &Vault) -> BTreeMap<(String, String), Value> {
        let s = v.session().unwrap();
        // is_current / last_seen (propres à l'appareil) sont exclus de la synchronisation.
        collect_all(s).unwrap()
    }

    fn pair() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        Vault,
        Vault,
        SyncKey,
        SyncKey,
    ) {
        let (da, db) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (new_vault(da.path(), false), new_vault(db.path(), true));
        let (meta, ka) = new_meta("sync passphrase 123", 1, KDF).unwrap();
        let kb = unlock_meta(&meta, "sync passphrase 123").unwrap();
        (da, db, a, b, ka, kb)
    }

    #[test]
    fn two_instances_converge_after_cross_modifications() {
        let (_da, _db, a, b, ka, kb) = pair();
        let mut repo = Repo::new();
        // A crée une appli et un secret.
        let app = apps::create(
            a.session().unwrap(),
            &NewApp {
                name: "Boutique".into(),
                ..Default::default()
            },
        )
        .unwrap();
        keys::add(
            a.session().unwrap(),
            Some(&app.id),
            "production",
            "vercel",
            "TOKEN",
            &SecretValue::new("secret-from-A-123"),
            None,
        )
        .unwrap();
        sync(&a, &ka, &mut repo, 1_000);
        sync(&b, &kb, &mut repo, 2_000);
        assert_eq!(apps::list(b.session().unwrap()).unwrap().len(), 1);
        let sb = keys::list(b.session().unwrap(), Some(&app.id)).unwrap();
        assert_eq!(
            b.session()
                .unwrap()
                .secrets
                .get(&sb[0].id)
                .unwrap()
                .unwrap()
                .expose(),
            "secret-from-A-123"
        );
        // Modifications croisées sur des enregistrements différents.
        apps::create(
            b.session().unwrap(),
            &NewApp {
                name: "Blog".into(),
                ..Default::default()
            },
        )
        .unwrap();
        apps::update(
            a.session().unwrap(),
            &app.id,
            &NewApp {
                name: "Boutique".into(),
                description: "v2 par A".into(),
                ..Default::default()
            },
        )
        .unwrap();
        keys::rotate(
            b.session().unwrap(),
            &sb[0].id,
            &SecretValue::new("rotated-by-B-456"),
        )
        .unwrap();
        sync(&a, &ka, &mut repo, 3_000);
        sync(&b, &kb, &mut repo, 4_000);
        sync(&a, &ka, &mut repo, 5_000);
        assert_eq!(state(&a), state(&b), "les deux instances ont convergé");
        assert_eq!(apps::list(a.session().unwrap()).unwrap().len(), 2);
        assert_eq!(
            a.session()
                .unwrap()
                .secrets
                .get(&sb[0].id)
                .unwrap()
                .unwrap()
                .expose(),
            "rotated-by-B-456"
        );
        assert_eq!(
            apps::get(b.session().unwrap(), &app.id)
                .unwrap()
                .description,
            "v2 par A"
        );
        // Suppression propagée.
        let blog = apps::list(a.session().unwrap())
            .unwrap()
            .into_iter()
            .find(|x| x.name == "Blog")
            .unwrap();
        a.session()
            .unwrap()
            .conn
            .lock()
            .execute("DELETE FROM apps WHERE id=?1", [&blog.id])
            .unwrap();
        sync(&a, &ka, &mut repo, 6_000);
        sync(&b, &kb, &mut repo, 7_000);
        assert_eq!(apps::list(b.session().unwrap()).unwrap().len(), 1);
        assert_eq!(state(&a), state(&b));
    }

    #[test]
    fn concurrent_edit_conflict_is_detected_and_resolvable() {
        let (_da, _db, a, b, ka, kb) = pair();
        let mut repo = Repo::new();
        let app = apps::create(
            a.session().unwrap(),
            &NewApp {
                name: "X".into(),
                ..Default::default()
            },
        )
        .unwrap();
        sync(&a, &ka, &mut repo, 1_000);
        sync(&b, &kb, &mut repo, 2_000);
        // Même enregistrement modifié des deux côtés sans synchronisation intermédiaire.
        apps::update(
            a.session().unwrap(),
            &app.id,
            &NewApp {
                name: "X".into(),
                description: "par A".into(),
                ..Default::default()
            },
        )
        .unwrap();
        apps::update(
            b.session().unwrap(),
            &app.id,
            &NewApp {
                name: "X".into(),
                description: "par B".into(),
                ..Default::default()
            },
        )
        .unwrap();
        sync(&a, &ka, &mut repo, 3_000);
        let rb = sync(&b, &kb, &mut repo, 4_000);
        let ra = sync(&a, &ka, &mut repo, 5_000);
        assert_eq!(state(&a), state(&b), "convergence malgré le conflit");
        assert_eq!(
            apps::get(a.session().unwrap(), &app.id)
                .unwrap()
                .description,
            "par B",
            "HLC le plus récent gagne"
        );
        assert!(ra.conflicts + rb.conflicts >= 1);
        // Résolution manuelle sur A : restaurer la version écartée.
        let cs = conflicts(a.session().unwrap()).unwrap();
        let c = cs
            .iter()
            .find(|c| c.entity == "apps")
            .expect("conflit listé");
        assert_eq!(c.discarded["description"], "par A");
        resolve(a.session().unwrap(), &c.id, true).unwrap();
        assert!(
            resolve(a.session().unwrap(), &c.id, true).is_err(),
            "déjà résolu"
        );
        sync(&a, &ka, &mut repo, 6_000);
        sync(&b, &kb, &mut repo, 7_000);
        assert_eq!(
            apps::get(b.session().unwrap(), &app.id)
                .unwrap()
                .description,
            "par A"
        );
        assert_eq!(state(&a), state(&b));
        for c in conflicts(b.session().unwrap()).unwrap() {
            resolve(b.session().unwrap(), &c.id, false).unwrap();
        }
        assert!(conflicts(b.session().unwrap()).unwrap().is_empty());
    }

    #[test]
    fn ciphertext_unreadable_and_tamper_detected() {
        let (_da, _db, a, b, ka, kb) = pair();
        let mut repo = Repo::new();
        let app = apps::create(
            a.session().unwrap(),
            &NewApp {
                name: "TopSecretShop".into(),
                ..Default::default()
            },
        )
        .unwrap();
        keys::add(
            a.session().unwrap(),
            Some(&app.id),
            "production",
            "stripe",
            "STRIPE",
            &SecretValue::new("sk_live_SHOULD_NOT_LEAK"),
            None,
        )
        .unwrap();
        sync(&a, &ka, &mut repo, 1_000);
        for bytes in repo.values() {
            let s = String::from_utf8_lossy(bytes);
            assert!(
                !s.contains("TopSecretShop") && !s.contains("sk_live") && !s.contains("STRIPE"),
                "contenu lisible : {s}"
            );
        }
        let (path, bytes) = repo
            .iter()
            .next()
            .map(|(k, v)| (k.clone(), v.clone()))
            .unwrap();
        let dev = path.split('/').nth(1).unwrap().to_owned();
        let sb = b.session().unwrap();
        // Mauvaise phrase secrète → impossible de dériver la clé.
        let meta = new_meta("sync passphrase 123", 1, KDF).unwrap().0;
        assert!(matches!(
            unlock_meta(&meta, "wrong passphrase!!"),
            Err(CoreError::InvalidPassphrase)
        ));
        let other = new_meta("another passphrase 9", 1, KDF).unwrap().1;
        assert!(
            ingest_at(sb, &other, &dev, &bytes, 2_000).is_err(),
            "illisible sans la phrase secrète"
        );
        // Altération du chiffré.
        let mut env: Value = serde_json::from_slice(&bytes).unwrap();
        let mut ct = crypto::unb64(env["ct"].as_str().unwrap()).unwrap();
        ct[40] ^= 1;
        env["ct"] = Value::from(crypto::b64(&ct));
        assert!(ingest_at(sb, &kb, &dev, env.to_string().as_bytes(), 2_000).is_err());
        // Lot déplacé vers le dossier d'un autre appareil.
        assert!(ingest_at(sb, &kb, "intrus", &bytes, 2_000).is_err());
        // Rejeu : idempotent.
        let r1 = ingest_at(sb, &kb, &dev, &bytes, 2_000).unwrap();
        let r2 = ingest_at(sb, &kb, &dev, &bytes, 2_000).unwrap();
        assert!(r1.applied > 0 && r2.applied == 0);
        assert!(ingest_at(sb, &kb, &dev, b"garbage", 2_000).is_err());
    }

    #[test]
    fn revoked_device_ignored_and_key_storage() {
        let (_da, _db, a, b, ka, kb) = pair();
        let mut repo = Repo::new();
        sync(&b, &kb, &mut repo, 500);
        sync(&a, &ka, &mut repo, 1_000);
        let bdev = b.session().unwrap().device_id.clone();
        profile::revoke_device(&a.session().unwrap().conn.lock(), &bdev).unwrap();
        apps::create(
            b.session().unwrap(),
            &NewApp {
                name: "FromLostPhone".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let s = b.session().unwrap();
        capture_at(s, 2_000).unwrap();
        let batch = build_batch(s, &kb).unwrap().unwrap();
        assert!(matches!(
            ingest_at(a.session().unwrap(), &ka, &bdev, &batch.bytes, 3_000),
            Err(CoreError::Forbidden(_))
        ));
        // Stockage de la clé.
        let sa = a.session().unwrap();
        assert!(stored_key(sa).unwrap().is_none());
        store_key(sa, &ka).unwrap();
        assert_eq!(stored_key(sa).unwrap().unwrap().epoch, 1);
        forget_key(sa).unwrap();
        assert!(stored_key(sa).unwrap().is_none());
        assert!(format!("{ka:?}").contains("epoch"));
        let p = pairing_payload(sa, "me/control-center-sync", 1).unwrap();
        assert!(
            p.contains("control-center-sync") && !pairing_qr_png_base64(&p).unwrap().is_empty()
        );
        reset_cursors(sa).unwrap();
        assert!(reemit_all(sa).unwrap() > 0);
    }

    #[test]
    fn epoch_rotation_rejects_old_batches() {
        let (_da, _db, a, _b, ka, _kb) = pair();
        let (_, k2) = new_meta("new passphrase after loss", 2, KDF).unwrap();
        let s = a.session().unwrap();
        apps::create(
            s,
            &NewApp {
                name: "Z".into(),
                ..Default::default()
            },
        )
        .unwrap();
        capture_at(s, 1).unwrap();
        let old = build_batch(s, &ka).unwrap().unwrap();
        assert!(ingest_at(s, &k2, &s.device_id, &old.bytes, 2).is_err());
        assert!(unlock_meta(
            &SyncMeta {
                format: "x".into(),
                ..new_meta("p a s s w o r d", 1, KDF).unwrap().0
            },
            "p a s s w o r d"
        )
        .is_err());
    }
}

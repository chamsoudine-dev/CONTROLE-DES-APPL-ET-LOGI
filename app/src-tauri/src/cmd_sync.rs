//! Commandes : synchronisation chiffrée via le dépôt privé GitHub, appairage, révocation.
use crate::state::{AppState, CmdResult};
use cc_connectors::github::GitHub;
use cc_core::crypto::KdfParams;
use cc_core::profile;
use cc_core::sync::{self, Conflict, MergeReport, SyncMeta};
use cc_core::CoreError;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};

const META: &str = "meta.json";

fn repo_and_client(state: &AppState) -> CmdResult<(String, GitHub)> {
    let repo = {
        let v = state.vault.lock();
        let s = v.session()?;
        let p = profile::get(&s.conn.lock(), &s.profile_id)?;
        p.sync_repo.ok_or_else(|| {
            CoreError::NotFound("dépôt de synchronisation (Paramètres → GitHub)".into())
        })?
    };
    Ok((repo.clone(), crate::cmd_github::client(state, Some(repo))?))
}

async fn read_meta(gh: &GitHub, repo: &str) -> CmdResult<Option<(SyncMeta, String)>> {
    match gh.get_file(repo, META).await? {
        Some(f) => Ok(Some((
            serde_json::from_slice(&f.bytes)
                .map_err(|_| CoreError::Integrity("meta.json invalide".into()))?,
            f.sha,
        ))),
        None => Ok(None),
    }
}

#[derive(Serialize)]
pub struct SyncStatus {
    pub repo: Option<String>,
    pub configured: bool,
    pub epoch: Option<u32>,
    pub conflicts: usize,
    pub last_sync: Option<String>,
    pub devices: Vec<profile::Device>,
}

#[tauri::command]
pub fn sync_status(state: State<'_, AppState>) -> CmdResult<SyncStatus> {
    let v = state.vault.lock();
    let s = v.session()?;
    let key = sync::stored_key(s)?;
    let c = s.conn.lock();
    let repo = profile::get(&c, &s.profile_id)?.sync_repo;
    let devices = profile::list_devices(&c)?;
    let last_sync = profile::get_setting(&c, "last_sync")?;
    drop(c);
    Ok(SyncStatus {
        repo,
        configured: key.is_some(),
        epoch: key.map(|k| k.epoch),
        conflicts: sync::conflicts(s)?.len(),
        last_sync,
        devices,
    })
}

/// Active la synchronisation : crée `meta.json` (premier appareil) ou vérifie la phrase secrète.
#[tauri::command]
pub async fn sync_setup(state: State<'_, AppState>, passphrase: String) -> CmdResult<u32> {
    if passphrase.len() > 1024 {
        return Err(CoreError::Validation("phrase trop longue".into()));
    }
    let (repo, gh) = repo_and_client(&state)?;
    let key = match read_meta(&gh, &repo).await? {
        Some((meta, _)) => sync::unlock_meta(&meta, &passphrase)?,
        None => {
            cc_core::vault::check_passphrase_strength(&passphrase)?;
            let (meta, key) = sync::new_meta(&passphrase, 1, KdfParams::RECOMMENDED)?;
            gh.put_file(
                &repo,
                META,
                &serde_json::to_vec_pretty(&meta)?,
                "control-center: initialisation de la synchronisation chiffrée",
                None,
            )
            .await?;
            key
        }
    };
    let v = state.vault.lock();
    let s = v.session()?;
    sync::store_key(s, &key)?;
    s.audit(
        "sync.setup",
        &repo,
        &serde_json::json!({"epoch": key.epoch}),
        "ok",
    )?;
    Ok(key.epoch)
}

#[derive(Debug, Default, Serialize)]
pub struct SyncReport {
    pub captured: usize,
    pub pulled: MergeReport,
    pub pushed_batches: usize,
}

/// Une synchronisation complète : capture → récupération + fusion → envoi.
pub async fn sync_once(app: &AppHandle) -> CmdResult<SyncReport> {
    let state = app.state::<AppState>();
    let (repo, gh) = repo_and_client(&state)?;
    let (key, me, captured) = {
        let v = state.vault.lock();
        let s = v.session()?;
        let key = sync::stored_key(s)?
            .ok_or_else(|| CoreError::Validation("synchronisation non activée".into()))?;
        (key, s.device_id.clone(), sync::capture(s)?)
    };
    if let Some((meta, _)) = read_meta(&gh, &repo).await? {
        if meta.epoch != key.epoch {
            return Err(CoreError::Validation(format!(
                "la synchronisation est passée à l'époque {} : saisissez la nouvelle phrase secrète",
                meta.epoch
            )));
        }
    }
    let mut rep = SyncReport {
        captured,
        ..SyncReport::default()
    };
    let root = format!("epochs/{}/events", key.epoch);
    for dev in gh.list_dir(&repo, &root).await? {
        if dev == me {
            continue;
        }
        let cursor = {
            let v = state.vault.lock();
            sync::cursor(v.session()?, &dev)?
        };
        let mut files: Vec<String> = gh
            .list_dir(&repo, &format!("{root}/{dev}"))
            .await?
            .into_iter()
            .filter(|f| f.ends_with(".ccev") && cursor.as_deref().is_none_or(|c| f.as_str() > c))
            .collect();
        files.sort();
        for f in files {
            let Some(content) = gh.get_file(&repo, &format!("{root}/{dev}/{f}")).await? else {
                continue;
            };
            let v = state.vault.lock();
            let s = v.session()?;
            match sync::ingest(s, &key, &dev, &content.bytes) {
                Ok(r) => {
                    rep.pulled.applied += r.applied;
                    rep.pulled.skipped += r.skipped;
                    rep.pulled.conflicts += r.conflicts;
                }
                Err(CoreError::Forbidden(_)) => {} // appareil révoqué : ignoré
                Err(e) => return Err(e),
            }
            sync::set_cursor(s, &dev, &f)?;
        }
    }
    loop {
        let batch = {
            let v = state.vault.lock();
            sync::build_batch(v.session()?, &key)?
        };
        let Some(batch) = batch else { break };
        gh.put_file(
            &repo,
            &format!("{root}/{me}/{}", batch.file_name),
            &batch.bytes,
            "control-center: sync (chiffré)",
            None,
        )
        .await?;
        let v = state.vault.lock();
        sync::mark_pushed(v.session()?, &batch)?;
        rep.pushed_batches += 1;
    }
    let v = state.vault.lock();
    let s = v.session()?;
    profile::set_setting(&s.conn.lock(), "last_sync", &cc_core::now_rfc3339())?;
    s.audit("sync.run", &repo, &serde_json::json!({"applied": rep.pulled.applied, "conflicts": rep.pulled.conflicts, "pushed": rep.pushed_batches}), "ok")?;
    Ok(rep)
}

#[tauri::command]
pub async fn sync_now(app: AppHandle) -> CmdResult<SyncReport> {
    sync_once(&app).await
}

#[tauri::command]
pub fn sync_conflicts(state: State<'_, AppState>) -> CmdResult<Vec<Conflict>> {
    let v = state.vault.lock();
    sync::conflicts(v.session()?)
}

#[tauri::command]
pub fn sync_resolve(
    state: State<'_, AppState>,
    id: String,
    restore_discarded: bool,
) -> CmdResult<()> {
    let v = state.vault.lock();
    sync::resolve(v.session()?, &id, restore_discarded)
}

#[derive(Serialize)]
pub struct Pairing {
    pub payload: String,
    pub qr_png_base64: String,
}

/// QR code d'ajout d'un appareil (contient le dépôt, jamais la phrase secrète).
#[tauri::command]
pub fn sync_pairing(state: State<'_, AppState>) -> CmdResult<Pairing> {
    let v = state.vault.lock();
    let s = v.session()?;
    let p = profile::get(&s.conn.lock(), &s.profile_id)?;
    let repo = p
        .sync_repo
        .ok_or_else(|| CoreError::NotFound("dépôt de synchronisation".into()))?;
    let epoch = sync::stored_key(s)?.map_or(1, |k| k.epoch);
    let payload = sync::pairing_payload(s, &repo, epoch)?;
    Ok(Pairing {
        qr_png_base64: sync::pairing_qr_png_base64(&payload)?,
        payload,
    })
}

/// Révoque un appareil perdu (ré-authentification). Étape suivante conseillée : rotation de l'époque.
#[tauri::command]
pub fn device_revoke(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let v = state.vault.lock();
    let s = v.session()?;
    s.ensure_recent_reauth()?;
    profile::revoke_device(&s.conn.lock(), &id)?;
    s.audit("device.revoke", &id, &serde_json::json!({}), "ok")
}

/// Nouvelle époque avec une NOUVELLE phrase : l'appareil révoqué ne peut plus rien déchiffrer.
#[tauri::command]
pub async fn sync_rotate_epoch(
    state: State<'_, AppState>,
    new_passphrase: String,
) -> CmdResult<u32> {
    cc_core::vault::check_passphrase_strength(&new_passphrase)?;
    {
        let v = state.vault.lock();
        v.session()?.ensure_recent_reauth()?;
    }
    let (repo, gh) = repo_and_client(&state)?;
    let (old, sha) = read_meta(&gh, &repo)
        .await?
        .ok_or_else(|| CoreError::NotFound("meta.json".into()))?;
    let (meta, key) = sync::new_meta(&new_passphrase, old.epoch + 1, KdfParams::RECOMMENDED)?;
    gh.put_file(
        &repo,
        META,
        &serde_json::to_vec_pretty(&meta)?,
        "control-center: rotation de la clé de synchronisation",
        Some(&sha),
    )
    .await?;
    {
        let v = state.vault.lock();
        let s = v.session()?;
        sync::store_key(s, &key)?;
        sync::reset_cursors(s)?;
        sync::reemit_all(s)?;
        s.audit(
            "sync.rotate",
            &repo,
            &serde_json::json!({"epoch": key.epoch}),
            "ok",
        )?;
    }
    Ok(key.epoch)
}

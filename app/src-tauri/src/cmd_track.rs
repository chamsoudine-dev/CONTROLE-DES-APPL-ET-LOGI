//! Commandes : suivi GitHub (ETag, quota, notifications), santé, alertes, médias.
use crate::state::{AppState, CmdResult};
use cc_connectors::github::{GitHub, RateState};
use cc_connectors::media::{safe_filename, to_webp, MAX_DIM};
use cc_connectors::registry;
use cc_connectors::{app_health, tracker, Health, Provider, Resource};
use cc_core::policy::{Action, Role};
use cc_core::tracking::{self, Alert, MediaAsset, RepoEvent};
use cc_core::{apps, keys, CoreError};
use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_notification::NotificationExt;

#[derive(Clone, Debug, Default, Serialize)]
pub struct PollSummary {
    pub repos: u32,
    pub requests: u32,
    pub not_modified: u32,
    pub new_events: u32,
    pub notifications: u32,
    pub rate: Option<RateState>,
    pub next_interval_secs: u64,
    pub errors: Vec<String>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Une passe de suivi sur toutes les applis liées à un dépôt.
pub async fn poll_once(app: &AppHandle) -> CmdResult<PollSummary> {
    let state = app.state::<AppState>();
    let (token, targets) = {
        let v = state.vault.lock();
        let s = v.session()?;
        let token = s
            .secrets
            .get(crate::cmd_github::GITHUB_TOKEN_ID)?
            .ok_or_else(|| CoreError::NotFound("connexion GitHub".into()))?;
        let targets: Vec<(String, String, String)> = apps::list(s)?
            .into_iter()
            .filter(|a| a.access_mode != cc_core::policy::AccessMode::Disabled)
            .filter_map(|a| a.repo.clone().map(|r| (a.id, a.name, r)))
            .collect();
        (token, targets)
    };
    let gh = GitHub::new(token, None)?;
    let mut sum = PollSummary {
        repos: u32::try_from(targets.len()).unwrap_or(u32::MAX),
        ..PollSummary::default()
    };
    for (app_id, name, repo) in targets {
        let etags: HashMap<String, String> = {
            let v = state.vault.lock();
            let s = v.session()?;
            GitHub::watch_paths(&repo)?
                .into_iter()
                .filter_map(|(_, p)| tracking::etag(s, &p).ok().flatten().map(|e| (p, e)))
                .collect()
        };
        let outcome = match tracker::poll_repo(&gh, &repo, |p| etags.get(p).cloned()).await {
            Ok(o) => o,
            Err(e) => {
                sum.errors.push(format!("{repo} : {e}"));
                continue;
            }
        };
        sum.requests += outcome.requests;
        sum.not_modified += outcome.not_modified;
        let notices = {
            let v = state.vault.lock();
            let s = v.session()?;
            for (p, e) in &outcome.etags {
                tracking::set_etag(s, p, e.as_deref())?;
            }
            let up = tracking::upsert_events(s, &app_id, &outcome.events)?;
            sum.new_events += u32::try_from(up.new.len()).unwrap_or(u32::MAX);
            let n = tracker::notices(&name, &up);
            tracking::mark_notified(s, &n.iter().map(|x| x.event_id.clone()).collect::<Vec<_>>())?;
            n
        };
        for n in notices {
            let _ = app
                .notification()
                .builder()
                .title(&n.title)
                .body(&n.body)
                .show();
            sum.notifications += 1;
        }
    }
    let rate = gh.rate();
    sum.next_interval_secs = rate.recommended_interval_secs(now_unix(), 5 * sum.repos.max(1));
    sum.rate = Some(rate);
    *state.rate.lock() = Some(rate);
    Ok(sum)
}

/// Tâche de fond : suivi périodique adapté au quota (uniquement coffre déverrouillé).
pub fn spawn_poller(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut wait = Duration::from_secs(30);
        loop {
            tokio::time::sleep(wait).await;
            let unlocked = app.state::<AppState>().vault.lock().is_unlocked();
            wait = if unlocked {
                match poll_once(&app).await {
                    Ok(s) => Duration::from_secs(s.next_interval_secs.max(60)),
                    Err(_) => Duration::from_secs(300),
                }
            } else {
                Duration::from_secs(30)
            };
        }
    });
}

#[tauri::command]
pub async fn tracking_poll_now(app: AppHandle) -> CmdResult<PollSummary> {
    poll_once(&app).await
}

#[tauri::command]
pub fn repo_events(
    state: State<'_, AppState>,
    app_id: Option<String>,
    limit: u32,
) -> CmdResult<Vec<RepoEvent>> {
    let v = state.vault.lock();
    tracking::list_events(v.session()?, app_id.as_deref(), limit)
}

#[tauri::command]
pub fn github_rate(state: State<'_, AppState>) -> Option<RateState> {
    *state.rate.lock()
}

#[tauri::command]
pub fn alerts_list(state: State<'_, AppState>) -> CmdResult<Vec<Alert>> {
    let v = state.vault.lock();
    tracking::alerts(v.session()?, time::OffsetDateTime::now_utc())
}

#[derive(Serialize)]
pub struct AppStatus {
    pub urls: Vec<(String, Health)>,
    pub online: Option<bool>,
    pub latest_deployment: Option<(String, Resource)>,
}

/// En ligne / hors ligne (URL) + dernier déploiement (premier hébergeur configuré).
#[tauri::command]
pub async fn app_status(state: State<'_, AppState>, app_id: String) -> CmdResult<AppStatus> {
    let (urls, hosting) = {
        let v = state.vault.lock();
        let s = v.session()?;
        apps::authorize(s, &app_id, Action::View, Role::Owner)?;
        let app = apps::get(s, &app_id)?;
        let hosting = apps::connectors(s, &app_id)?
            .into_iter()
            .find(|c| matches!(c.provider.as_str(), "vercel" | "netlify" | "cloudflare"));
        let hosting = match hosting {
            Some(c) => {
                let secret = c
                    .secret_id
                    .as_ref()
                    .map(|id| keys::use_value(s, id))
                    .transpose()?;
                Some((c, secret))
            }
            None => None,
        };
        (app.urls, hosting)
    };
    let mut out = AppStatus {
        urls: vec![],
        online: None,
        latest_deployment: None,
    };
    for u in urls.iter().take(5) {
        out.urls.push((u.clone(), app_health::check(u).await?));
    }
    if !out.urls.is_empty() {
        out.online = Some(out.urls.iter().all(|(_, h)| h.online));
    }
    if let Some((c, Some(secret))) = hosting {
        if let Ok(conn) = registry::build(Provider::parse(&c.provider)?, &c.config, secret).await {
            if let Ok(list) = conn.list_resources().await {
                out.latest_deployment = list.into_iter().next().map(|r| (c.provider.clone(), r));
            }
        }
    }
    Ok(out)
}

// ---------- Médias ----------

#[tauri::command]
pub fn media_list(state: State<'_, AppState>, app_id: String) -> CmdResult<Vec<MediaAsset>> {
    let v = state.vault.lock();
    tracking::list_media(v.session()?, &app_id)
}

/// Aperçu de l'envoi d'un média (droit « Médias » requis) → jeton de confirmation.
#[tauri::command]
pub fn media_prepare(
    state: State<'_, AppState>,
    app_id: String,
    connector_id: String,
    file_name: String,
    size: u64,
) -> CmdResult<cc_connectors::exec::Prepared> {
    let v = state.vault.lock();
    let s = v.session()?;
    let c = apps::get_connector(s, &connector_id)?;
    if c.app_id != app_id {
        return Err(CoreError::Forbidden(
            "connecteur d'une autre application".into(),
        ));
    }
    apps::authorize(s, &app_id, Action::Media, Role::Owner)?;
    let target = safe_filename(&file_name);
    let preview = format!(
        "Envoyer « {target} » (converti en WebP, ≤ {MAX_DIM} px, source {size} octets) vers {}",
        c.provider
    );
    let token = state.confirmations.issue(
        &app_id,
        Action::Media,
        &format!("media:{connector_id}"),
        serde_json::json!({"file": target}),
        preview.clone(),
    );
    Ok(cc_connectors::exec::Prepared {
        token,
        preview,
        policy_action: Action::Media,
        destructive: false,
    })
}

/// Envoi confirmé : conversion WebP puis upload vers le stockage choisi.
#[tauri::command]
pub async fn media_upload(
    state: State<'_, AppState>,
    token: String,
    data_base64: String,
) -> CmdResult<MediaAsset> {
    if data_base64.len() > 36 * 1024 * 1024 {
        return Err(CoreError::Validation("fichier trop volumineux".into()));
    }
    let (pending, provider, config, secret, app_name) = {
        let v = state.vault.lock();
        let s = v.session()?;
        let p = cc_connectors::exec::authorize_execution(s, &state.confirmations, &token)?;
        let connector_id =
            p.op.strip_prefix("media:")
                .ok_or_else(|| CoreError::Validation("jeton non destiné aux médias".into()))?
                .to_owned();
        let c = apps::get_connector(s, &connector_id)?;
        let secret = c
            .secret_id
            .as_ref()
            .map(|id| keys::use_value(s, id))
            .transpose()?
            .ok_or_else(|| CoreError::NotFound("clé du stockage".into()))?;
        let app_name = apps::get(s, &p.app_id)?.name;
        (p, c.provider, c.config, secret, app_name)
    };
    let raw = data_encoding::BASE64
        .decode(data_base64.as_bytes())
        .map_err(|_| CoreError::Validation("données invalides".into()))?;
    let img = to_webp(&raw, MAX_DIM)?;
    let folder: String = app_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let path = format!(
        "{}/{}",
        folder.trim_matches('-'),
        pending.params["file"].as_str().unwrap_or("image.webp")
    );
    let store = registry::build_media(Provider::parse(&provider)?, &config, secret)?;
    let (w, h, n) = (img.width, img.height, img.bytes.len());
    let result = store.upload(&path, img.bytes, "image/webp").await;
    let v = state.vault.lock();
    let s = v.session()?;
    cc_connectors::exec::record(
        s,
        &pending,
        &result
            .as_ref()
            .map(|u| serde_json::json!({"url": u}))
            .map_err(|e| CoreError::External(e.to_string())),
    )?;
    let url = result?;
    tracking::add_media(s, &pending.app_id, &provider, &path, &url, n, w, h)
}

//! Commandes : connexion GitHub (obligatoire en premier), dépôt de sync, clé de licences.
use crate::state::{AppState, CmdResult};
use cc_connectors::github::{DeviceCode, DeviceFlow, DevicePoll, GitHub, RateState, Repo};
use cc_connectors::{Connector, PermissionSpec, TestReport};
use cc_core::secrets::SecretValue;
use cc_core::{license_keys, profile, CoreError};
use serde::Serialize;
use tauri::State;

pub const GITHUB_TOKEN_ID: &str = "github-token";
/// Portées demandées en Device Flow (OAuth App : pas de portée plus fine possible).
pub const DEVICE_SCOPES: &str = "repo workflow";

/// Client GitHub construit depuis le jeton stocké (le verrou du coffre est relâché avant tout appel réseau).
pub fn client(state: &AppState, repo: Option<String>) -> CmdResult<GitHub> {
    let token = {
        let v = state.vault.lock();
        let s = v.session()?;
        s.secrets
            .get(GITHUB_TOKEN_ID)?
            .ok_or_else(|| CoreError::NotFound("connexion GitHub".into()))?
    };
    GitHub::new(token, repo)
}

#[tauri::command]
pub fn github_permissions() -> Vec<PermissionSpec> {
    GitHub::new(SecretValue::new("x"), None)
        .map(|g| g.required_permissions())
        .unwrap_or_default()
}

fn store_token(state: &AppState, token: &SecretValue, report: &TestReport) -> CmdResult<()> {
    let v = state.vault.lock();
    let s = v.session()?;
    s.secrets.put(GITHUB_TOKEN_ID, token)?;
    profile::set_field(
        &s.conn.lock(),
        &s.profile_id,
        "github_login",
        report.identity.as_deref(),
    )?;
    cc_core::keys::register_global(
        s,
        GITHUB_TOKEN_ID,
        "github",
        "GITHUB_TOKEN",
        token,
        report.too_powerful,
        &serde_json::to_string(&report.permissions)?,
    )?;
    s.audit(
        "github.connect",
        report.identity.as_deref().unwrap_or_default(),
        &serde_json::json!({"too_powerful": report.too_powerful}),
        "ok",
    )
}

/// Connexion par jeton fine-grained : le jeton est testé AVANT d'être stocké.
#[tauri::command]
pub async fn github_connect_token(
    state: State<'_, AppState>,
    token: String,
) -> CmdResult<TestReport> {
    if token.len() > 512 || token.trim().is_empty() {
        return Err(CoreError::Validation("jeton invalide".into()));
    }
    state.vault.lock().session()?;
    let token = SecretValue::new(token.trim());
    let report = GitHub::new(token.clone(), None)?.test().await?;
    if report.ok {
        store_token(&state, &token, &report)?;
    }
    Ok(report)
}

#[tauri::command]
pub async fn github_device_start(
    state: State<'_, AppState>,
    client_id: String,
) -> CmdResult<DeviceCode> {
    state.vault.lock().session()?;
    DeviceFlow::new(&client_id)?.start(DEVICE_SCOPES).await
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DevicePollResult {
    Pending,
    SlowDown,
    Connected { report: TestReport },
}

#[tauri::command]
pub async fn github_device_poll(
    state: State<'_, AppState>,
    client_id: String,
    device_code: String,
) -> CmdResult<DevicePollResult> {
    state.vault.lock().session()?;
    if device_code.len() > 256 {
        return Err(CoreError::Validation("code invalide".into()));
    }
    match DeviceFlow::new(&client_id)?.poll(&device_code).await? {
        DevicePoll::Pending => Ok(DevicePollResult::Pending),
        DevicePoll::SlowDown => Ok(DevicePollResult::SlowDown),
        DevicePoll::Token(token) => {
            let report = GitHub::new(token.clone(), None)?.test().await?;
            if report.ok {
                store_token(&state, &token, &report)?;
            }
            Ok(DevicePollResult::Connected { report })
        }
    }
}

#[tauri::command]
pub async fn github_repos(state: State<'_, AppState>) -> CmdResult<Vec<Repo>> {
    client(&state, None)?.list_repos().await
}

#[derive(Serialize)]
pub struct GithubStatus {
    pub connected: bool,
    pub login: Option<String>,
    pub sync_repo: Option<String>,
    pub rate: Option<RateState>,
}

#[tauri::command]
pub fn github_status(state: State<'_, AppState>) -> CmdResult<GithubStatus> {
    let v = state.vault.lock();
    let s = v.session()?;
    let p = profile::get(&s.conn.lock(), &s.profile_id)?;
    Ok(GithubStatus {
        connected: s.secrets.get(GITHUB_TOKEN_ID)?.is_some(),
        login: p.github_login,
        sync_repo: p.sync_repo,
        rate: None,
    })
}

/// Crée (privé) ou sélectionne le dépôt de synchronisation. Refuse un dépôt public.
#[tauri::command]
pub async fn github_setup_sync_repo(
    state: State<'_, AppState>,
    existing: Option<String>,
    name: Option<String>,
) -> CmdResult<Repo> {
    let gh = client(&state, None)?;
    let repo = if let Some(full) = existing {
        gh.get_repo(&full)
            .await?
            .ok_or_else(|| CoreError::NotFound(format!("dépôt {full}")))?
    } else {
        let n = name.unwrap_or_else(|| "control-center-sync".into());
        gh.create_repo(
            &n,
            true,
            "Control Center — synchronisation chiffrée (illisible sans phrase secrète)",
        )
        .await?
    };
    if !repo.private {
        return Err(CoreError::Forbidden(
            "le dépôt de synchronisation doit être privé".into(),
        ));
    }
    let v = state.vault.lock();
    let s = v.session()?;
    profile::set_field(
        &s.conn.lock(),
        &s.profile_id,
        "sync_repo",
        Some(&repo.full_name),
    )?;
    s.audit(
        "sync.repo.set",
        &repo.full_name,
        &serde_json::json!({}),
        "ok",
    )?;
    Ok(repo)
}

#[derive(Serialize)]
pub struct LicenseKeyStatus {
    pub kid: Option<String>,
    pub public_keys: Vec<String>,
}

#[tauri::command]
pub fn license_key_status(state: State<'_, AppState>) -> CmdResult<LicenseKeyStatus> {
    let v = state.vault.lock();
    let s = v.session()?;
    let kid = profile::get(&s.conn.lock(), &s.profile_id)?.license_kid;
    let public_keys = license_keys::known_public_keys(s)?;
    Ok(LicenseKeyStatus { kid, public_keys })
}

#[tauri::command]
pub fn license_key_generate(state: State<'_, AppState>) -> CmdResult<String> {
    let v = state.vault.lock();
    let s = v.session()?;
    // Rotation d'une clé existante = action sensible.
    if profile::get(&s.conn.lock(), &s.profile_id)?
        .license_kid
        .is_some()
    {
        s.ensure_recent_reauth()?;
    }
    license_keys::generate(s)
}

/// Sauvegarde chiffrée de la clé de signature (exige une ré-authentification récente).
#[tauri::command]
pub fn license_key_backup(
    state: State<'_, AppState>,
    backup_passphrase: String,
) -> CmdResult<String> {
    let v = state.vault.lock();
    license_keys::export_backup(
        v.session()?,
        &backup_passphrase,
        cc_core::crypto::KdfParams::RECOMMENDED,
    )
}

#[tauri::command]
pub fn license_key_restore(
    state: State<'_, AppState>,
    backup: String,
    backup_passphrase: String,
) -> CmdResult<String> {
    if backup.len() > 64 * 1024 {
        return Err(CoreError::Validation("sauvegarde trop volumineuse".into()));
    }
    let v = state.vault.lock();
    let s = v.session()?;
    s.ensure_recent_reauth()?;
    license_keys::import_backup(s, &backup, &backup_passphrase)
}

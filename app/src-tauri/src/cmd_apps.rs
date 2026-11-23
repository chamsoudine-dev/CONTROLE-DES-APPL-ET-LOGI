//! Commandes : applications, droits, coffre « Environnements & Clés », connecteurs, actions.
use crate::state::{AppState, CmdResult};
use cc_connectors::exec::{self, Prepared};
use cc_connectors::registry::{self, ProviderInfo};
use cc_connectors::{ActionSpec, Connector, Provider, Resource, TestReport};
use cc_core::apps::{self, App, ConnectorRow, NewApp};
use cc_core::ccvault::{self, ImportReport};
use cc_core::envvars::{self, DiffLine, EnvVar};
use cc_core::keys::{self, SecretMeta};
use cc_core::policy::{AccessMode, Action};
use cc_core::secrets::SecretValue;
use cc_core::CoreError;
use serde::Serialize;
use std::collections::BTreeMap;
use tauri::State;

fn limit(s: &str, max: usize) -> CmdResult<()> {
    if s.len() > max {
        Err(CoreError::Validation("valeur trop longue".into()))
    } else {
        Ok(())
    }
}

/// Charge un connecteur enregistré (le verrou est relâché avant tout appel réseau).
pub async fn load_connector(
    state: &AppState,
    connector_id: &str,
) -> CmdResult<(ConnectorRow, Box<dyn Connector>)> {
    let (row, secret) = {
        let v = state.vault.lock();
        let s = v.session()?;
        let row = apps::get_connector(s, connector_id)?;
        let secret = match &row.secret_id {
            Some(id) => keys::use_value(s, id)?,
            None if row.provider == "github" => s
                .secrets
                .get(crate::cmd_github::GITHUB_TOKEN_ID)?
                .ok_or_else(|| CoreError::NotFound("connexion GitHub".into()))?,
            None => SecretValue::new(""),
        };
        (row, secret)
    };
    let conn = registry::build(Provider::parse(&row.provider)?, &row.config, secret).await?;
    Ok((row, conn))
}

#[tauri::command]
pub async fn providers_catalog() -> Vec<ProviderInfo> {
    registry::catalog().await
}

#[tauri::command]
pub fn apps_list(state: State<'_, AppState>) -> CmdResult<Vec<App>> {
    let v = state.vault.lock();
    apps::list(v.session()?)
}

#[derive(Serialize)]
pub struct AppDetail {
    pub app: App,
    pub matrix: BTreeMap<Action, bool>,
    pub connectors: Vec<ConnectorRow>,
    pub secrets: Vec<SecretMeta>,
}

#[tauri::command]
pub fn app_get(state: State<'_, AppState>, id: String) -> CmdResult<AppDetail> {
    let v = state.vault.lock();
    let s = v.session()?;
    apps::authorize(s, &id, Action::View, cc_core::policy::Role::Owner)?;
    Ok(AppDetail {
        app: apps::get(s, &id)?,
        matrix: apps::matrix(s, &id)?,
        connectors: apps::connectors(s, &id)?,
        secrets: keys::list(s, Some(&id))?,
    })
}

#[tauri::command]
pub fn app_create(state: State<'_, AppState>, app: NewApp) -> CmdResult<App> {
    let v = state.vault.lock();
    let s = v.session()?;
    // Créer directement en lecture-écriture élargit les droits : ré-authentification.
    if app.access_mode == Some(AccessMode::ReadWrite) {
        s.ensure_recent_reauth()?;
    }
    apps::create(s, &app)
}

#[tauri::command]
pub fn app_update(state: State<'_, AppState>, id: String, app: NewApp) -> CmdResult<App> {
    let v = state.vault.lock();
    apps::update(v.session()?, &id, &app)
}

#[tauri::command]
pub fn app_set_mode(state: State<'_, AppState>, id: String, mode: AccessMode) -> CmdResult<()> {
    let v = state.vault.lock();
    apps::set_mode(v.session()?, &id, mode)
}

#[tauri::command]
pub fn app_set_permission(
    state: State<'_, AppState>,
    id: String,
    action: Action,
    allowed: bool,
) -> CmdResult<()> {
    let v = state.vault.lock();
    apps::set_permission(v.session()?, &id, action, allowed)
}

#[tauri::command]
pub fn app_delete(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let v = state.vault.lock();
    apps::delete(v.session()?, &id)
}

// ---------- Connecteurs ----------

/// « Tester » avant enregistrement : vérifie la clé ET ses permissions réelles.
#[tauri::command]
pub async fn connector_test_draft(
    state: State<'_, AppState>,
    provider: Provider,
    config: serde_json::Value,
    secret: Option<String>,
) -> CmdResult<TestReport> {
    state.vault.lock().session()?;
    let secret = match (provider, secret) {
        (Provider::Github, None) => {
            let v = state.vault.lock();
            v.session()?
                .secrets
                .get(crate::cmd_github::GITHUB_TOKEN_ID)?
                .ok_or_else(|| CoreError::NotFound("connexion GitHub".into()))?
        }
        (_, Some(s)) => {
            limit(&s, 64 * 1024)?;
            SecretValue::new(s)
        }
        (_, None) => SecretValue::new(""),
    };
    registry::build(provider, &config, secret)
        .await?
        .test()
        .await
}

#[derive(Serialize)]
pub struct ConnectorAdded {
    pub connector: ConnectorRow,
    pub report: TestReport,
}

/// Ajoute un service à une appli : secret dans le trousseau + connecteur + test.
#[tauri::command]
pub async fn connector_add(
    state: State<'_, AppState>,
    app_id: String,
    provider: Provider,
    config: serde_json::Value,
    secret: Option<String>,
    environment: Option<String>,
) -> CmdResult<ConnectorAdded> {
    let row = {
        let v = state.vault.lock();
        let s = v.session()?;
        let secret_id = match &secret {
            Some(val) if !val.is_empty() => {
                limit(val, 64 * 1024)?;
                let name = format!("{}_KEY", provider.as_str().to_uppercase());
                let env = environment.as_deref().unwrap_or("production");
                Some(
                    keys::add(
                        s,
                        Some(&app_id),
                        env,
                        provider.as_str(),
                        &name,
                        &SecretValue::new(val.clone()),
                        None,
                    )?
                    .id,
                )
            }
            _ => None,
        };
        apps::add_connector(
            s,
            &app_id,
            provider.as_str(),
            provider.category(),
            &config,
            secret_id.as_deref(),
        )?
    };
    let report = connector_test(state, row.id.clone()).await?;
    Ok(ConnectorAdded {
        connector: row,
        report,
    })
}

#[tauri::command]
pub async fn connector_test(
    state: State<'_, AppState>,
    connector_id: String,
) -> CmdResult<TestReport> {
    let (row, conn) = load_connector(&state, &connector_id).await?;
    let report = conn.test().await?;
    let v = state.vault.lock();
    let s = v.session()?;
    let perms = serde_json::to_value(&report.permissions)?;
    apps::record_test(s, &row.id, report.ok, &perms)?;
    if let Some(sid) = &row.secret_id {
        keys::set_detected(s, sid, &perms, report.too_powerful)?;
    }
    s.audit(
        "connector.test",
        &row.app_id,
        &serde_json::json!({"provider": row.provider, "ok": report.ok}),
        "ok",
    )?;
    Ok(report)
}

#[tauri::command]
pub fn connector_remove(state: State<'_, AppState>, connector_id: String) -> CmdResult<()> {
    let v = state.vault.lock();
    apps::remove_connector(v.session()?, &connector_id)
}

#[tauri::command]
pub async fn connector_resources(
    state: State<'_, AppState>,
    connector_id: String,
) -> CmdResult<Vec<Resource>> {
    let (row, conn) = load_connector(&state, &connector_id).await?;
    {
        let v = state.vault.lock();
        apps::authorize(
            v.session()?,
            &row.app_id,
            Action::View,
            cc_core::policy::Role::Owner,
        )?;
    }
    conn.list_resources().await
}

#[tauri::command]
pub async fn connector_actions(
    state: State<'_, AppState>,
    connector_id: String,
) -> CmdResult<Vec<ActionSpec>> {
    let (_, conn) = load_connector(&state, &connector_id).await?;
    Ok(conn.actions())
}

/// Aperçu d'une écriture : renvoie un jeton de confirmation à usage unique.
#[tauri::command]
pub async fn action_prepare(
    state: State<'_, AppState>,
    connector_id: String,
    action: String,
    params: serde_json::Value,
) -> CmdResult<Prepared> {
    if params.to_string().len() > 64 * 1024 {
        return Err(CoreError::Validation("paramètres trop volumineux".into()));
    }
    let (row, conn) = load_connector(&state, &connector_id).await?;
    let v = state.vault.lock();
    exec::prepare(
        v.session()?,
        &state.confirmations,
        &row.app_id,
        &row.id,
        conn.as_ref(),
        &action,
        &params,
    )
}

/// Exécute une écriture confirmée (ré-authentification exigée si destructive).
#[tauri::command]
pub async fn action_execute(
    state: State<'_, AppState>,
    token: String,
) -> CmdResult<serde_json::Value> {
    let pending = {
        let v = state.vault.lock();
        exec::authorize_execution(v.session()?, &state.confirmations, &token)?
    };
    let (connector_id, action) = exec::split_op(&pending)?;
    let (row, conn) = load_connector(&state, connector_id).await?;
    // Envoi des variables : les valeurs (secrets compris) ne sont résolues qu'ici, jamais
    // transmises à l'interface ni conservées dans l'aperçu.
    let params = if action == "env_push" {
        let env = pending.params["environment"]
            .as_str()
            .unwrap_or("production")
            .to_owned();
        let vals = {
            let v = state.vault.lock();
            envvars::resolved(v.session()?, &row.app_id, &env)?
        };
        let vars: serde_json::Map<String, serde_json::Value> = vals
            .iter()
            .map(|(k, v)| (k.clone(), v.expose().into()))
            .collect();
        serde_json::json!({"environment": env, "vars": vars})
    } else {
        pending.params.clone()
    };
    let result = conn.execute(action, &params).await;
    let v = state.vault.lock();
    let s = v.session()?;
    if action == "env_push" && result.is_ok() {
        envvars::mark_pushed(
            s,
            &row.app_id,
            params["environment"].as_str().unwrap_or("production"),
        )?;
    }
    exec::record(s, &pending, &result)?;
    result
}

// ---------- Secrets ----------

#[tauri::command]
pub fn secrets_list(
    state: State<'_, AppState>,
    app_id: Option<String>,
) -> CmdResult<Vec<SecretMeta>> {
    let v = state.vault.lock();
    keys::list(v.session()?, app_id.as_deref())
}

#[tauri::command]
pub fn secret_add(
    state: State<'_, AppState>,
    app_id: Option<String>,
    environment: String,
    provider: String,
    name: String,
    value: String,
    expires_at: Option<String>,
) -> CmdResult<SecretMeta> {
    limit(&value, 16 * 1024)?;
    let v = state.vault.lock();
    keys::add(
        v.session()?,
        app_id.as_deref(),
        &environment,
        &provider,
        &name,
        &SecretValue::new(value),
        expires_at.as_deref(),
    )
}

#[tauri::command]
pub fn secret_update(
    state: State<'_, AppState>,
    id: String,
    name: String,
    expires_at: Option<String>,
) -> CmdResult<SecretMeta> {
    let v = state.vault.lock();
    keys::update_meta(v.session()?, &id, &name, expires_at.as_deref())
}

#[tauri::command]
pub fn secret_rotate(
    state: State<'_, AppState>,
    id: String,
    value: String,
) -> CmdResult<SecretMeta> {
    limit(&value, 16 * 1024)?;
    let v = state.vault.lock();
    keys::rotate(v.session()?, &id, &SecretValue::new(value))
}

/// Révèle une valeur (ré-authentification récente exigée, auditée). L'interface l'efface après 30 s.
#[tauri::command]
pub fn secret_reveal(state: State<'_, AppState>, id: String) -> CmdResult<String> {
    let v = state.vault.lock();
    keys::reveal(v.session()?, &id).map(|s| s.expose().to_owned())
}

#[tauri::command]
pub fn secret_delete(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let v = state.vault.lock();
    keys::delete(v.session()?, &id)
}

/// Teste le secret via le connecteur qui l'utilise.
#[tauri::command]
pub async fn secret_test(state: State<'_, AppState>, id: String) -> CmdResult<TestReport> {
    let connector_id = {
        let v = state.vault.lock();
        let s = v.session()?;
        let m = keys::get(s, &id)?;
        let app_id = m.app_id.ok_or_else(|| {
            CoreError::Validation("secret global : testez-le depuis Paramètres".into())
        })?;
        apps::connectors(s, &app_id)?
            .into_iter()
            .find(|c| c.secret_id.as_deref() == Some(id.as_str()))
            .ok_or_else(|| CoreError::NotFound("aucun connecteur n'utilise ce secret".into()))?
            .id
    };
    connector_test(state, connector_id).await
}

// ---------- Variables d'environnement ----------

#[tauri::command]
pub fn env_list(
    state: State<'_, AppState>,
    app_id: String,
    environment: String,
) -> CmdResult<Vec<EnvVar>> {
    let v = state.vault.lock();
    envvars::list(v.session()?, &app_id, &environment)
}

#[tauri::command]
pub fn env_set(
    state: State<'_, AppState>,
    app_id: String,
    environment: String,
    key: String,
    value: Option<String>,
    secret_id: Option<String>,
) -> CmdResult<()> {
    let v = state.vault.lock();
    envvars::set(
        v.session()?,
        &app_id,
        &environment,
        &key,
        value.as_deref(),
        secret_id.as_deref(),
    )
}

#[tauri::command]
pub fn env_remove(
    state: State<'_, AppState>,
    app_id: String,
    environment: String,
    key: String,
) -> CmdResult<()> {
    let v = state.vault.lock();
    envvars::remove(v.session()?, &app_id, &environment, &key)
}

/// Aperçu des différences avec l'hébergeur (lecture distante pour Vercel).
#[tauri::command]
pub async fn env_diff(
    state: State<'_, AppState>,
    app_id: String,
    environment: String,
    connector_id: String,
) -> CmdResult<Vec<DiffLine>> {
    let (row, secret) = {
        let v = state.vault.lock();
        let s = v.session()?;
        let row = apps::get_connector(s, &connector_id)?;
        let secret = row
            .secret_id
            .as_ref()
            .map(|id| keys::use_value(s, id))
            .transpose()?;
        (row, secret)
    };
    let mut remote: BTreeMap<String, Option<String>> = BTreeMap::new();
    if row.provider == "vercel" {
        let c = cc_connectors::vercel::Vercel::new(
            &row.config,
            secret.unwrap_or_else(|| SecretValue::new("")),
        )?;
        for (k, _, val, targets) in c.remote_env().await? {
            if targets.iter().any(|t| t == &environment) {
                remote.insert(k, val);
            }
        }
    }
    let v = state.vault.lock();
    let s = v.session()?;
    let local = envvars::resolved(s, &app_id, &environment)?;
    Ok(envvars::diff(
        &local,
        &remote,
        &envvars::last_pushed(s, &app_id, &environment)?,
    ))
}

/// Prépare l'envoi des variables (aperçu : noms des clés uniquement).
#[tauri::command]
pub async fn env_push_prepare(
    state: State<'_, AppState>,
    app_id: String,
    environment: String,
    connector_id: String,
) -> CmdResult<Prepared> {
    let keys_list: Vec<String> = {
        let v = state.vault.lock();
        envvars::list(v.session()?, &app_id, &environment)?
            .into_iter()
            .map(|e| e.key)
            .collect()
    };
    let (row, conn) = load_connector(&state, &connector_id).await?;
    if row.app_id != app_id {
        return Err(CoreError::Forbidden(
            "connecteur d'une autre application".into(),
        ));
    }
    let params = serde_json::json!({"environment": environment, "keys": keys_list});
    let v = state.vault.lock();
    exec::prepare(
        v.session()?,
        &state.confirmations,
        &app_id,
        &row.id,
        conn.as_ref(),
        "env_push",
        &params,
    )
}

// ---------- Export / import ----------

#[tauri::command]
pub fn vault_export(state: State<'_, AppState>, passphrase: String) -> CmdResult<String> {
    limit(&passphrase, 1024)?;
    let v = state.vault.lock();
    ccvault::export(
        v.session()?,
        &passphrase,
        cc_core::crypto::KdfParams::RECOMMENDED,
    )
}

#[tauri::command]
pub fn vault_import(
    state: State<'_, AppState>,
    content: String,
    passphrase: String,
) -> CmdResult<ImportReport> {
    limit(&passphrase, 1024)?;
    let v = state.vault.lock();
    ccvault::import(v.session()?, content.as_bytes(), &passphrase)
}

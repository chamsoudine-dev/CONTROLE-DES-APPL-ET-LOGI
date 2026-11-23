//! Commandes : produits, clients, ventes, licences, publication des révocations.
use crate::state::{AppState, CmdResult};
use cc_core::licensing::{self, Customer, License, NewProduct, Product, RevocationStatus, Sale};
use cc_core::{license_keys, profile, CoreError};
use serde::Serialize;
use tauri::State;

pub const REVOCATION_FILE: &str = "revocations.paseto";
pub const KEYS_FILE: &str = "public-keys.json";

#[tauri::command]
pub fn products_list(state: State<'_, AppState>) -> CmdResult<Vec<Product>> {
    let v = state.vault.lock();
    licensing::list_products(v.session()?)
}

#[tauri::command]
pub fn product_create(state: State<'_, AppState>, product: NewProduct) -> CmdResult<Product> {
    let v = state.vault.lock();
    licensing::create_product(v.session()?, &product)
}

#[tauri::command]
pub fn customers_list(state: State<'_, AppState>) -> CmdResult<Vec<Customer>> {
    let v = state.vault.lock();
    licensing::list_customers(v.session()?)
}

#[tauri::command]
pub fn customer_create(
    state: State<'_, AppState>,
    name: String,
    email: Option<String>,
    phone: Option<String>,
    notes: Option<String>,
) -> CmdResult<Customer> {
    let v = state.vault.lock();
    licensing::create_customer(
        v.session()?,
        &name,
        email.as_deref().filter(|s| !s.is_empty()),
        phone.as_deref().filter(|s| !s.is_empty()),
        notes.as_deref().unwrap_or(""),
    )
}

#[derive(Serialize)]
pub struct ProviderItem {
    pub id: &'static str,
    pub label: &'static str,
}

#[tauri::command]
pub fn payment_providers() -> Vec<ProviderItem> {
    licensing::payment_providers()
        .iter()
        .map(|p| ProviderItem {
            id: p.id(),
            label: p.label(),
        })
        .collect()
}

#[tauri::command]
pub fn sales_list(state: State<'_, AppState>) -> CmdResult<Vec<Sale>> {
    let v = state.vault.lock();
    licensing::list_sales(v.session()?)
}

#[tauri::command]
pub fn sale_record(
    state: State<'_, AppState>,
    product_id: String,
    customer_id: String,
    provider: String,
    reference: Option<String>,
) -> CmdResult<Sale> {
    let v = state.vault.lock();
    licensing::record_sale(
        v.session()?,
        &product_id,
        &customer_id,
        &provider,
        reference.as_deref().filter(|s| !s.is_empty()),
    )
}

#[tauri::command]
pub fn licenses_list(state: State<'_, AppState>) -> CmdResult<Vec<License>> {
    let v = state.vault.lock();
    licensing::list_licenses(v.session()?)
}

#[tauri::command]
pub fn license_create(
    state: State<'_, AppState>,
    product_id: String,
    customer_id: String,
    sale_id: Option<String>,
    options: Option<serde_json::Map<String, serde_json::Value>>,
) -> CmdResult<License> {
    let v = state.vault.lock();
    licensing::create_license(
        v.session()?,
        &product_id,
        &customer_id,
        sale_id.as_deref(),
        options.unwrap_or_default(),
        time::OffsetDateTime::now_utc(),
    )
}

#[tauri::command]
pub fn license_extend(state: State<'_, AppState>, id: String, days: i64) -> CmdResult<License> {
    let v = state.vault.lock();
    licensing::extend_license(v.session()?, &id, days, time::OffsetDateTime::now_utc())
}

#[tauri::command]
pub fn license_revoke(state: State<'_, AppState>, id: String, reason: String) -> CmdResult<()> {
    if reason.len() > 500 {
        return Err(CoreError::Validation("motif trop long".into()));
    }
    let v = state.vault.lock();
    licensing::revoke_license(v.session()?, &id, &reason)
}

#[tauri::command]
pub fn license_find(state: State<'_, AppState>, readable_key: String) -> CmdResult<License> {
    let v = state.vault.lock();
    licensing::find_by_readable_key(v.session()?, &readable_key)
}

#[tauri::command]
pub fn licenses_export_csv(state: State<'_, AppState>) -> CmdResult<String> {
    let v = state.vault.lock();
    licensing::export_csv(v.session()?)
}

#[derive(Serialize)]
pub struct RevocationInfo {
    pub status: RevocationStatus,
    pub repo: Option<String>,
    /// URL brute à configurer dans les applis clientes.
    pub list_url: Option<String>,
    pub public_keys: Vec<String>,
}

#[tauri::command]
pub fn revocations_info(state: State<'_, AppState>) -> CmdResult<RevocationInfo> {
    let v = state.vault.lock();
    let s = v.session()?;
    let repo = profile::get(&s.conn.lock(), &s.profile_id)?.revocation_repo;
    Ok(RevocationInfo {
        status: licensing::revocation_status(s)?,
        list_url: repo
            .as_ref()
            .map(|r| format!("https://raw.githubusercontent.com/{r}/HEAD/{REVOCATION_FILE}")),
        repo,
        public_keys: license_keys::known_public_keys(s)?,
    })
}

/// Crée (public) ou sélectionne le dépôt des révocations.
#[tauri::command]
pub async fn revocations_setup_repo(
    state: State<'_, AppState>,
    existing: Option<String>,
    name: Option<String>,
) -> CmdResult<String> {
    let gh = crate::cmd_github::client(&state, None)?;
    let repo = match existing {
        Some(full) => gh.get_repo(&full).await?.ok_or_else(|| CoreError::NotFound(format!("dépôt {full}")))?,
        None => {
            gh.create_repo(
                name.as_deref().unwrap_or("control-center-revocations"),
                false,
                "Liste de révocation signée (Ed25519 / PASETO v4.public) des licences Control Center",
            )
            .await?
        }
    };
    if repo.private {
        return Err(CoreError::Validation(
            "le dépôt des révocations doit être public (lu par les applis clientes)".into(),
        ));
    }
    let v = state.vault.lock();
    let s = v.session()?;
    profile::set_field(
        &s.conn.lock(),
        &s.profile_id,
        "revocation_repo",
        Some(&repo.full_name),
    )?;
    s.audit(
        "license.revocations.repo",
        &repo.full_name,
        &serde_json::json!({}),
        "ok",
    )?;
    Ok(repo.full_name)
}

/// Signe une nouvelle liste et la publie automatiquement dans le dépôt public.
#[tauri::command]
pub async fn revocations_publish(state: State<'_, AppState>) -> CmdResult<u64> {
    let (repo, seq, token, keys) = {
        let v = state.vault.lock();
        let s = v.session()?;
        let repo = profile::get(&s.conn.lock(), &s.profile_id)?
            .revocation_repo
            .ok_or_else(|| CoreError::NotFound("dépôt des révocations".into()))?;
        let (seq, token) = licensing::build_revocation_list(s, time::OffsetDateTime::now_utc())?;
        (repo, seq, token, license_keys::known_public_keys(s)?)
    };
    let gh = crate::cmd_github::client(&state, Some(repo.clone()))?;
    let sha = gh.get_file(&repo, REVOCATION_FILE).await?.map(|f| f.sha);
    gh.put_file(
        &repo,
        REVOCATION_FILE,
        token.as_bytes(),
        &format!("révocations : liste n° {seq}"),
        sha.as_deref(),
    )
    .await?;
    let keys_json = serde_json::to_vec_pretty(
        &serde_json::json!({"issuer": cc_license::ISSUER, "keys": keys}),
    )?;
    let ksha = gh.get_file(&repo, KEYS_FILE).await?.map(|f| f.sha);
    gh.put_file(
        &repo,
        KEYS_FILE,
        &keys_json,
        "clés publiques de vérification",
        ksha.as_deref(),
    )
    .await?;
    let v = state.vault.lock();
    licensing::mark_list_published(v.session()?, seq)?;
    Ok(seq)
}

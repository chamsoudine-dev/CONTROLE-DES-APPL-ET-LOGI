//! Commandes : coffre, authentification, profil, audit.
use crate::state::{AppState, CmdResult};
use cc_core::audit::{self, AuditEntry, ChainReport};
use cc_core::profile::{self, Device, Profile};
use cc_core::vault::{TotpSetup, UnlockStep, VaultStatus};
use cc_core::CoreError;
use std::time::Instant;
use tauri::State;

fn bounded(s: &str, max: usize, what: &str) -> CmdResult<()> {
    if s.len() > max {
        return Err(CoreError::Validation(format!("{what} trop long")));
    }
    Ok(())
}

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> VaultStatus {
    state.vault.lock().status()
}

#[tauri::command]
pub fn vault_setup(
    state: State<'_, AppState>,
    display_name: String,
    passphrase: String,
) -> CmdResult<()> {
    bounded(&passphrase, 1024, "phrase secrète")?;
    state.vault.lock().setup(&display_name, &passphrase)
}

#[tauri::command]
pub fn vault_unlock(state: State<'_, AppState>, passphrase: String) -> CmdResult<UnlockStep> {
    bounded(&passphrase, 1024, "phrase secrète")?;
    state.vault.lock().unlock(&passphrase)
}

#[tauri::command]
pub fn vault_complete_totp(state: State<'_, AppState>, code: String) -> CmdResult<()> {
    bounded(&code, 16, "code")?;
    state.vault.lock().complete_totp(&code)
}

#[tauri::command]
pub fn vault_unlock_pin(state: State<'_, AppState>, pin: String) -> CmdResult<()> {
    bounded(&pin, 16, "PIN")?;
    state.vault.lock().unlock_with_pin(&pin)
}

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) {
    state.vault.lock().lock();
}

#[tauri::command]
pub fn vault_touch(state: State<'_, AppState>) {
    state.vault.lock().touch_at(Instant::now());
}

#[tauri::command]
pub fn vault_reauth(
    state: State<'_, AppState>,
    passphrase: String,
    totp: Option<String>,
) -> CmdResult<()> {
    bounded(&passphrase, 1024, "phrase secrète")?;
    state.vault.lock().reauth(&passphrase, totp.as_deref())
}

#[tauri::command]
pub fn totp_begin(state: State<'_, AppState>) -> CmdResult<TotpSetup> {
    state.vault.lock().totp_begin()
}

#[tauri::command]
pub fn totp_confirm(state: State<'_, AppState>, code: String) -> CmdResult<()> {
    bounded(&code, 16, "code")?;
    state.vault.lock().totp_confirm(&code)
}

#[tauri::command]
pub fn totp_disable(state: State<'_, AppState>) -> CmdResult<()> {
    state.vault.lock().totp_disable()
}

#[tauri::command]
pub fn pin_set(state: State<'_, AppState>, pin: String) -> CmdResult<()> {
    bounded(&pin, 16, "PIN")?;
    state.vault.lock().set_pin(&pin)
}

#[tauri::command]
pub fn pin_remove(state: State<'_, AppState>) -> CmdResult<()> {
    state.vault.lock().remove_pin()
}

#[tauri::command]
pub fn passphrase_change(state: State<'_, AppState>, old: String, new: String) -> CmdResult<()> {
    bounded(&old, 1024, "phrase secrète")?;
    bounded(&new, 1024, "phrase secrète")?;
    state.vault.lock().change_passphrase(&old, &new)
}

#[tauri::command]
pub fn autolock_set(state: State<'_, AppState>, secs: u32) -> CmdResult<()> {
    let v = state.vault.lock();
    let s = v.session()?;
    profile::set_autolock(&s.conn.lock(), &s.profile_id, secs)?;
    s.audit(
        "settings.autolock",
        "",
        &serde_json::json!({"secs": secs}),
        "ok",
    )
}

#[tauri::command]
pub fn profile_get(state: State<'_, AppState>) -> CmdResult<Profile> {
    let v = state.vault.lock();
    let s = v.session()?;
    let p = profile::get(&s.conn.lock(), &s.profile_id)?;
    Ok(p)
}

#[tauri::command]
pub fn audit_list(
    state: State<'_, AppState>,
    limit: u32,
    offset: u32,
) -> CmdResult<Vec<AuditEntry>> {
    let v = state.vault.lock();
    let s = v.session()?;
    let l = audit::list(&s.conn.lock(), limit, offset)?;
    Ok(l)
}

#[tauri::command]
pub fn audit_verify(state: State<'_, AppState>) -> CmdResult<ChainReport> {
    let v = state.vault.lock();
    let s = v.session()?;
    let r = audit::verify_chain(&s.conn.lock())?;
    Ok(r)
}

#[tauri::command]
pub fn devices_list(state: State<'_, AppState>) -> CmdResult<Vec<Device>> {
    let v = state.vault.lock();
    let s = v.session()?;
    let d = profile::list_devices(&s.conn.lock())?;
    Ok(d)
}

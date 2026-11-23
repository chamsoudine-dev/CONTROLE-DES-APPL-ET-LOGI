//! Application Tauri Control Center : la WebView n'a accès qu'aux commandes listées dans
//! `commands.txt` et autorisées par `capabilities/default.json`.
#![forbid(unsafe_code)]

mod cmd_github;
mod cmd_vault;
mod state;

use cc_core::crypto::KdfParams;
use cc_core::vault::{Vault, VaultConfig};
use state::AppState;
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager};

/// Service du trousseau OS.
pub const KEYRING_SERVICE: &str = "dev.chamsoudine.controlcenter";

fn open_vault(dir: std::path::PathBuf) -> Result<Vault, cc_core::CoreError> {
    Vault::open(VaultConfig {
        dir,
        kdf: KdfParams::RECOMMENDED,
        os_store: cc_core::secrets::os_keyring(KEYRING_SERVICE),
    })
}

/// Tâche de fond : verrouillage automatique après inactivité.
fn spawn_autolock(app: tauri::AppHandle) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let state = app.state::<AppState>();
        let locked = state.vault.lock().autolock_if_idle_at(Instant::now());
        if locked {
            let _ = app.emit("vault-locked", ());
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let vault = open_vault(dir).map_err(|e| e.to_string())?;
            app.manage(AppState::new(vault));
            spawn_autolock(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            cmd_vault::vault_status,
            cmd_vault::vault_setup,
            cmd_vault::vault_unlock,
            cmd_vault::vault_complete_totp,
            cmd_vault::vault_unlock_pin,
            cmd_vault::vault_lock,
            cmd_vault::vault_touch,
            cmd_vault::vault_reauth,
            cmd_vault::totp_begin,
            cmd_vault::totp_confirm,
            cmd_vault::totp_disable,
            cmd_vault::pin_set,
            cmd_vault::pin_remove,
            cmd_vault::passphrase_change,
            cmd_vault::autolock_set,
            cmd_vault::profile_get,
            cmd_vault::audit_list,
            cmd_vault::audit_verify,
            cmd_vault::devices_list,
            cmd_github::github_permissions,
            cmd_github::github_connect_token,
            cmd_github::github_device_start,
            cmd_github::github_device_poll,
            cmd_github::github_repos,
            cmd_github::github_setup_sync_repo,
            cmd_github::github_status,
            cmd_github::license_key_generate,
            cmd_github::license_key_status,
            cmd_github::license_key_backup,
            cmd_github::license_key_restore,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de Control Center");
}

#[cfg(test)]
mod tests {
    /// Chaque commande listée doit avoir sa permission dans la capability, et inversement.
    #[test]
    fn capabilities_match_commands() {
        let cmds: std::collections::BTreeSet<String> = include_str!("../commands.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|c| format!("allow-{}", c.replace('_', "-")))
            .collect();
        let cap: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let perms: std::collections::BTreeSet<String> = cap["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p.as_str())
            .filter(|p| p.starts_with("allow-"))
            .map(str::to_owned)
            .collect();
        assert_eq!(cmds, perms);
        // Aucune permission dangereuse (shell, fs, http libre).
        let raw = include_str!("../capabilities/default.json");
        for forbidden in ["shell:", "fs:", "http:", "process:allow-exit"] {
            assert!(!raw.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn csp_is_strict() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let csp = &conf["app"]["security"]["csp"];
        assert_eq!(csp["default-src"], "'self'");
        assert_eq!(csp["script-src"], "'self'");
        assert_eq!(csp["object-src"], "'none'");
        let all = csp.to_string();
        assert!(!all.contains("unsafe-eval"));
        assert_eq!(conf["app"]["withGlobalTauri"], false);
    }
}

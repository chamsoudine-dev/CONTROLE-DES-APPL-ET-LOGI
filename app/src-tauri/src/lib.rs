//! Application Tauri Control Center : la WebView n'a accès qu'aux commandes listées dans
//! `commands.txt` et autorisées par `capabilities/default.json`.
#![forbid(unsafe_code)]

mod cmd_apps;
mod cmd_github;
mod cmd_licenses;
mod cmd_sync;
mod cmd_track;
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
    let builder = tauri::Builder::default().plugin(tauri_plugin_notification::init());
    // Mises à jour signées (minisign) : toute mise à jour non signée par la clé embarquée est refusée.
    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init());
    builder
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let vault = open_vault(dir).map_err(|e| e.to_string())?;
            app.manage(AppState::new(vault));
            spawn_autolock(app.handle().clone());
            cmd_track::spawn_poller(app.handle().clone());
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
            cmd_apps::providers_catalog,
            cmd_apps::apps_list,
            cmd_apps::app_get,
            cmd_apps::app_create,
            cmd_apps::app_update,
            cmd_apps::app_set_mode,
            cmd_apps::app_set_permission,
            cmd_apps::app_delete,
            cmd_apps::connector_test_draft,
            cmd_apps::connector_add,
            cmd_apps::connector_test,
            cmd_apps::connector_remove,
            cmd_apps::connector_resources,
            cmd_apps::connector_actions,
            cmd_apps::action_prepare,
            cmd_apps::action_execute,
            cmd_apps::secrets_list,
            cmd_apps::secret_add,
            cmd_apps::secret_update,
            cmd_apps::secret_rotate,
            cmd_apps::secret_reveal,
            cmd_apps::secret_delete,
            cmd_apps::secret_test,
            cmd_apps::env_list,
            cmd_apps::env_set,
            cmd_apps::env_remove,
            cmd_apps::env_diff,
            cmd_apps::env_push_prepare,
            cmd_apps::vault_export,
            cmd_apps::vault_import,
            cmd_track::tracking_poll_now,
            cmd_track::repo_events,
            cmd_track::github_rate,
            cmd_track::alerts_list,
            cmd_track::app_status,
            cmd_track::media_list,
            cmd_track::media_prepare,
            cmd_track::media_upload,
            cmd_sync::sync_status,
            cmd_sync::sync_setup,
            cmd_sync::sync_now,
            cmd_sync::sync_conflicts,
            cmd_sync::sync_resolve,
            cmd_sync::sync_pairing,
            cmd_sync::device_revoke,
            cmd_sync::sync_rotate_epoch,
            cmd_licenses::products_list,
            cmd_licenses::product_create,
            cmd_licenses::customers_list,
            cmd_licenses::customer_create,
            cmd_licenses::payment_providers,
            cmd_licenses::sales_list,
            cmd_licenses::sale_record,
            cmd_licenses::licenses_list,
            cmd_licenses::license_create,
            cmd_licenses::license_extend,
            cmd_licenses::license_revoke,
            cmd_licenses::license_find,
            cmd_licenses::licenses_export_csv,
            cmd_licenses::revocations_info,
            cmd_licenses::revocations_setup_repo,
            cmd_licenses::revocations_publish,
            cmd_vault::device_integrity,
            cmd_vault::app_version,
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
    fn updater_is_safe() {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let u = &conf["plugins"]["updater"];
        assert_eq!(u["requireSignedVersion"], true, "anti-rétrogradation");
        for flag in [
            "dangerousInsecureTransportProtocol",
            "dangerousAcceptInvalidCerts",
            "dangerousAcceptInvalidHostnames",
        ] {
            assert!(u.get(flag).is_none_or(|v| v == false), "{flag}");
        }
        for e in u["endpoints"].as_array().unwrap() {
            assert!(e.as_str().unwrap().starts_with("https://"));
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

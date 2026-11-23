//! État partagé de l'application.

use cc_core::vault::Vault;
use parking_lot::Mutex;

pub struct AppState {
    pub vault: Mutex<Vault>,
}

impl AppState {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Mutex::new(vault),
        }
    }
}

/// Résultat des commandes : `CoreError` est sérialisé en `{code, message}` pour l'interface.
pub type CmdResult<T> = Result<T, cc_core::CoreError>;

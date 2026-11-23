//! État partagé de l'application.
use cc_core::policy::Confirmations;
use cc_core::vault::Vault;
use parking_lot::Mutex;

pub struct AppState {
    pub vault: Mutex<Vault>,
    /// Jetons de confirmation des écritures (aperçu → confirmation, usage unique).
    pub confirmations: Confirmations,
    /// Dernier état connu du quota GitHub.
    pub rate: Mutex<Option<cc_connectors::github::RateState>>,
}

impl AppState {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Mutex::new(vault),
            confirmations: Confirmations::default(),
            rate: Mutex::new(None),
        }
    }
}

/// Résultat des commandes : `CoreError` est sérialisé en `{code, message}` pour l'interface.
pub type CmdResult<T> = Result<T, cc_core::CoreError>;

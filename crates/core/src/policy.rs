//! Politique d'accès : mode par appli ∧ matrice d'actions ∧ rôle, confirmation et ré-authentification.
use crate::{crypto, CoreError, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// Mode d'accès d'une application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    ReadOnly,
    ReadWrite,
    Disabled,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "read_only" => Ok(Self::ReadOnly),
            "read_write" => Ok(Self::ReadWrite),
            "disabled" => Ok(Self::Disabled),
            _ => Err(CoreError::Validation(format!("mode inconnu : {s}"))),
        }
    }
}

/// Actions soumises à la matrice de droits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    View,
    Redeploy,
    Rollback,
    Release,
    EditEnv,
    Media,
    Licenses,
    Delete,
}

impl Action {
    pub const ALL: [Action; 8] = [
        Self::View,
        Self::Redeploy,
        Self::Rollback,
        Self::Release,
        Self::EditEnv,
        Self::Media,
        Self::Licenses,
        Self::Delete,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Redeploy => "redeploy",
            Self::Rollback => "rollback",
            Self::Release => "release",
            Self::EditEnv => "edit_env",
            Self::Media => "media",
            Self::Licenses => "licenses",
            Self::Delete => "delete",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str() == s)
            .ok_or_else(|| CoreError::Validation(format!("action inconnue : {s}")))
    }

    /// Toute action autre que la lecture est une écriture.
    pub fn is_write(self) -> bool {
        self != Self::View
    }

    /// Actions destructrices : ré-authentification obligatoire.
    pub fn is_destructive(self) -> bool {
        matches!(self, Self::Delete | Self::Rollback)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::View => "Voir",
            Self::Redeploy => "Redéployer",
            Self::Rollback => "Rollback",
            Self::Release => "Tag / release / workflow",
            Self::EditEnv => "Modifier les variables",
            Self::Media => "Médias",
            Self::Licenses => "Licences",
            Self::Delete => "Supprimer",
        }
    }
}

/// Rôles (prêts pour l'invitation de collaborateurs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
    Viewer,
}

impl Role {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "owner" => Ok(Self::Owner),
            "admin" => Ok(Self::Admin),
            "viewer" => Ok(Self::Viewer),
            _ => Err(CoreError::Validation(format!("rôle inconnu : {s}"))),
        }
    }

    pub fn allows(self, a: Action) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => a != Action::Delete,
            Self::Viewer => a == Action::View,
        }
    }
}

/// Matrice par défaut : tout sauf la suppression.
pub fn default_matrix() -> BTreeMap<Action, bool> {
    Action::ALL
        .into_iter()
        .map(|a| (a, a != Action::Delete))
        .collect()
}

/// Décision d'autorisation (sans confirmation ni ré-auth).
pub fn authorize(
    mode: AccessMode,
    matrix: &BTreeMap<Action, bool>,
    role: Role,
    action: Action,
) -> Result<()> {
    if mode == AccessMode::Disabled {
        return Err(CoreError::Forbidden("application désactivée".into()));
    }
    if !role.allows(action) {
        return Err(CoreError::Forbidden(format!(
            "rôle insuffisant pour « {} »",
            action.label()
        )));
    }
    if mode == AccessMode::ReadOnly && action.is_write() {
        return Err(CoreError::Forbidden(format!(
            "application en lecture seule : « {} » refusé",
            action.label()
        )));
    }
    if !matrix.get(&action).copied().unwrap_or(false) {
        return Err(CoreError::Forbidden(format!(
            "« {} » désactivé dans la matrice",
            action.label()
        )));
    }
    Ok(())
}

/// Demande d'écriture en attente de confirmation (issue de l'aperçu).
#[derive(Clone, Debug)]
pub struct PendingAction {
    pub app_id: String,
    pub action: Action,
    pub op: String,
    pub params: serde_json::Value,
    pub preview: String,
    created: Instant,
}

/// Jetons de confirmation à usage unique (TTL 2 min).
#[derive(Default)]
pub struct Confirmations {
    pending: Mutex<HashMap<String, PendingAction>>,
}

pub const CONFIRMATION_TTL: Duration = Duration::from_secs(120);

impl Confirmations {
    pub fn issue(
        &self,
        app_id: &str,
        action: Action,
        op: &str,
        params: serde_json::Value,
        preview: String,
    ) -> String {
        self.issue_at(app_id, action, op, params, preview, Instant::now())
    }

    pub fn issue_at(
        &self,
        app_id: &str,
        action: Action,
        op: &str,
        params: serde_json::Value,
        preview: String,
        now: Instant,
    ) -> String {
        let token = data_encoding::BASE32_NOPAD.encode(&crypto::random_bytes::<20>());
        let mut map = self.pending.lock();
        map.retain(|_, p| now.saturating_duration_since(p.created) < CONFIRMATION_TTL);
        map.insert(
            token.clone(),
            PendingAction {
                app_id: app_id.to_owned(),
                action,
                op: op.to_owned(),
                params,
                preview,
                created: now,
            },
        );
        token
    }

    /// Consomme le jeton (usage unique). Échoue s'il est inconnu, expiré ou déjà utilisé.
    pub fn consume_at(&self, token: &str, now: Instant) -> Result<PendingAction> {
        let p = self
            .pending
            .lock()
            .remove(token)
            .ok_or(CoreError::ConfirmationRequired)?;
        if now.saturating_duration_since(p.created) >= CONFIRMATION_TTL {
            return Err(CoreError::ConfirmationRequired);
        }
        Ok(p)
    }

    /// Action associée à un jeton encore valide, sans le consommer.
    pub fn peek(&self, token: &str) -> Option<Action> {
        self.pending.lock().get(token).map(|p| p.action)
    }

    pub fn consume(&self, token: &str) -> Result<PendingAction> {
        self.consume_at(token, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_blocks_writes() {
        let m = default_matrix();
        for a in Action::ALL {
            let r = authorize(AccessMode::ReadOnly, &m, Role::Owner, a);
            assert_eq!(r.is_ok(), a == Action::View, "{a:?}");
        }
    }

    #[test]
    fn disabled_blocks_everything() {
        let m: BTreeMap<_, _> = Action::ALL.into_iter().map(|a| (a, true)).collect();
        for a in Action::ALL {
            assert!(authorize(AccessMode::Disabled, &m, Role::Owner, a).is_err());
        }
    }

    #[test]
    fn matrix_and_roles() {
        let mut m = default_matrix();
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Owner, Action::Redeploy).is_ok());
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Owner, Action::Delete).is_err());
        m.insert(Action::Delete, true);
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Owner, Action::Delete).is_ok());
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Admin, Action::Delete).is_err());
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Admin, Action::Redeploy).is_ok());
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Viewer, Action::Redeploy).is_err());
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Viewer, Action::View).is_ok());
        m.insert(Action::Redeploy, false);
        assert!(authorize(AccessMode::ReadWrite, &m, Role::Owner, Action::Redeploy).is_err());
        assert!(authorize(
            AccessMode::ReadWrite,
            &BTreeMap::new(),
            Role::Owner,
            Action::View
        )
        .is_err());
    }

    #[test]
    fn parsing_and_flags() {
        for a in Action::ALL {
            assert_eq!(Action::parse(a.as_str()).unwrap(), a);
            assert!(!a.label().is_empty());
        }
        assert!(Action::parse("x").is_err());
        for m in [
            AccessMode::ReadOnly,
            AccessMode::ReadWrite,
            AccessMode::Disabled,
        ] {
            assert_eq!(AccessMode::parse(m.as_str()).unwrap(), m);
        }
        assert!(AccessMode::parse("x").is_err());
        assert_eq!(Role::parse("admin").unwrap(), Role::Admin);
        assert_eq!(Role::parse("owner").unwrap(), Role::Owner);
        assert_eq!(Role::parse("viewer").unwrap(), Role::Viewer);
        assert!(Role::parse("root").is_err());
        assert!(Action::Delete.is_destructive() && Action::Rollback.is_destructive());
        assert!(!Action::Redeploy.is_destructive() && Action::Redeploy.is_write());
    }

    #[test]
    fn confirmation_single_use_and_ttl() {
        let c = Confirmations::default();
        let t0 = Instant::now();
        let tok = c.issue_at(
            "app",
            Action::Redeploy,
            "redeploy",
            serde_json::json!({}),
            "x".into(),
            t0,
        );
        let p = c.consume_at(&tok, t0 + Duration::from_secs(5)).unwrap();
        assert_eq!(p.action, Action::Redeploy);
        assert!(matches!(
            c.consume_at(&tok, t0),
            Err(CoreError::ConfirmationRequired)
        ));
        let tok2 = c.issue(
            "app",
            Action::Redeploy,
            "redeploy",
            serde_json::json!({}),
            "x".into(),
        );
        assert!(c
            .consume_at(&tok2, Instant::now() + CONFIRMATION_TTL)
            .is_err());
        assert!(c.consume("unknown").is_err());
    }
}

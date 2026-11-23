use serde::Serialize;

/// Erreurs du cœur. Les messages sont destinés à l'utilisateur : jamais de secret dedans.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("le coffre n'est pas encore initialisé")]
    NotInitialized,
    #[error("le coffre est déjà initialisé")]
    AlreadyInitialized,
    #[error("le coffre est verrouillé")]
    Locked,
    #[error("phrase secrète incorrecte")]
    InvalidPassphrase,
    #[error("phrase secrète trop faible : {0}")]
    WeakPassphrase(String),
    #[error("code de double authentification requis")]
    TotpRequired,
    #[error("code de double authentification invalide")]
    InvalidTotp,
    #[error("PIN incorrect ({0} essai(s) restant(s))")]
    InvalidPin(u32),
    #[error("PIN désactivé après trop d'échecs : utilisez la phrase secrète")]
    PinLocked,
    #[error("PIN non configuré sur cet appareil")]
    PinUnavailable,
    #[error("ré-authentification requise pour cette action")]
    ReauthRequired,
    #[error("confirmation requise pour cette action")]
    ConfirmationRequired,
    #[error("action interdite : {0}")]
    Forbidden(String),
    #[error("introuvable : {0}")]
    NotFound(String),
    #[error("donnée invalide : {0}")]
    Validation(String),
    #[error("conflit : {0}")]
    Conflict(String),
    #[error("intégrité compromise : {0}")]
    Integrity(String),
    #[error("échec cryptographique")]
    Crypto,
    #[error("trousseau du système : {0}")]
    SecretStore(String),
    #[error("base de données : {0}")]
    Db(String),
    #[error("entrée/sortie : {0}")]
    Io(String),
    #[error("service externe : {0}")]
    External(String),
}

impl CoreError {
    /// Code stable transmis à l'interface.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotInitialized => "not_initialized",
            Self::AlreadyInitialized => "already_initialized",
            Self::Locked => "locked",
            Self::InvalidPassphrase => "invalid_passphrase",
            Self::WeakPassphrase(_) => "weak_passphrase",
            Self::TotpRequired => "totp_required",
            Self::InvalidTotp => "invalid_totp",
            Self::InvalidPin(_) => "invalid_pin",
            Self::PinLocked => "pin_locked",
            Self::PinUnavailable => "pin_unavailable",
            Self::ReauthRequired => "reauth_required",
            Self::ConfirmationRequired => "confirmation_required",
            Self::Forbidden(_) => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::Validation(_) => "validation",
            Self::Conflict(_) => "conflict",
            Self::Integrity(_) => "integrity",
            Self::Crypto => "crypto",
            Self::SecretStore(_) => "secret_store",
            Self::Db(_) => "db",
            Self::Io(_) => "io",
            Self::External(_) => "external",
        }
    }
}

impl Serialize for CoreError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("CoreError", 2)?;
        st.serialize_field("code", self.code())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}

impl From<rusqlite::Error> for CoreError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => Self::NotFound("enregistrement".into()),
            rusqlite::Error::SqliteFailure(f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Self::Conflict("contrainte d'unicité ou d'intégrité".into())
            }
            other => Self::Db(other.to_string()),
        }
    }
}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind().to_string())
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Validation(format!("JSON : {e}"))
    }
}

impl From<cc_license::LicenseError> for CoreError {
    fn from(e: cc_license::LicenseError) -> Self {
        Self::Validation(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_code_and_message() {
        let v = serde_json::to_value(CoreError::InvalidPin(3)).unwrap();
        assert_eq!(v["code"], "invalid_pin");
        assert!(v["message"].as_str().unwrap().contains('3'));
        let all = [
            CoreError::NotInitialized,
            CoreError::AlreadyInitialized,
            CoreError::Locked,
            CoreError::InvalidPassphrase,
            CoreError::WeakPassphrase(String::new()),
            CoreError::TotpRequired,
            CoreError::InvalidTotp,
            CoreError::PinLocked,
            CoreError::PinUnavailable,
            CoreError::ReauthRequired,
            CoreError::ConfirmationRequired,
            CoreError::Forbidden(String::new()),
            CoreError::NotFound(String::new()),
            CoreError::Validation(String::new()),
            CoreError::Conflict(String::new()),
            CoreError::Integrity(String::new()),
            CoreError::Crypto,
            CoreError::SecretStore(String::new()),
            CoreError::Db(String::new()),
            CoreError::Io(String::new()),
            CoreError::External(String::new()),
        ];
        let codes: std::collections::HashSet<_> = all.iter().map(CoreError::code).collect();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn conversions() {
        assert_eq!(
            CoreError::from(rusqlite::Error::QueryReturnedNoRows).code(),
            "not_found"
        );
        assert_eq!(CoreError::from(std::io::Error::other("x")).code(), "io");
        assert_eq!(
            CoreError::from(serde_json::from_str::<u8>("x").unwrap_err()).code(),
            "validation"
        );
        assert_eq!(
            CoreError::from(cc_license::LicenseError::Expired).code(),
            "validation"
        );
    }
}

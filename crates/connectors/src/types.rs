//! Types communs aux connecteurs.
use async_trait::async_trait;
use cc_core::policy::Action;
use cc_core::Result;
use serde::{Deserialize, Serialize};

/// Accès requis par une permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
}

/// Permission déclarée par un connecteur (affichée avant connexion, avec sa raison).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PermissionSpec {
    pub scope: String,
    pub access: Access,
    pub reason: String,
    /// Faut-il cette permission pour le mode lecture seule ?
    pub required_for_read_only: bool,
}

impl PermissionSpec {
    pub fn read(scope: &str, reason: &str) -> Self {
        Self {
            scope: scope.into(),
            access: Access::Read,
            reason: reason.into(),
            required_for_read_only: true,
        }
    }
    pub fn write(scope: &str, reason: &str) -> Self {
        Self {
            scope: scope.into(),
            access: Access::Write,
            reason: reason.into(),
            required_for_read_only: false,
        }
    }
}

/// Permission constatée lors du test de la clé.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedPermission {
    pub scope: String,
    pub access: Access,
    pub granted: bool,
}

/// Résultat du bouton « Tester ».
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TestReport {
    pub ok: bool,
    pub identity: Option<String>,
    pub permissions: Vec<DetectedPermission>,
    pub warnings: Vec<String>,
    pub too_powerful: bool,
    pub expires_at: Option<String>,
    pub can_read: bool,
    pub can_write: bool,
}

/// État de santé.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Health {
    pub online: bool,
    pub latency_ms: u64,
    pub detail: String,
}

/// Ressource listée chez le fournisseur (projet, déploiement, bucket…).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub url: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

/// Action proposée par un connecteur.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActionSpec {
    pub id: String,
    pub label: String,
    pub policy_action: Action,
    pub description: String,
}

impl ActionSpec {
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        policy_action: Action,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            policy_action,
            description: description.into(),
        }
    }
}

/// Fournisseurs pris en charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Github,
    Vercel,
    Supabase,
    Firebase,
    Netlify,
    Cloudflare,
    Cloudinary,
    Custom,
}

impl Provider {
    pub const ALL: [Provider; 8] = [
        Self::Github,
        Self::Vercel,
        Self::Supabase,
        Self::Firebase,
        Self::Netlify,
        Self::Cloudflare,
        Self::Cloudinary,
        Self::Custom,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Vercel => "vercel",
            Self::Supabase => "supabase",
            Self::Firebase => "firebase",
            Self::Netlify => "netlify",
            Self::Cloudflare => "cloudflare",
            Self::Cloudinary => "cloudinary",
            Self::Custom => "custom",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| cc_core::CoreError::Validation(format!("fournisseur inconnu : {s}")))
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Github => "GitHub",
            Self::Vercel => "Vercel",
            Self::Supabase => "Supabase",
            Self::Firebase => "Firebase",
            Self::Netlify => "Netlify",
            Self::Cloudflare => "Cloudflare Pages",
            Self::Cloudinary => "Cloudinary",
            Self::Custom => "API personnalisée",
        }
    }

    /// Catégorie par défaut (hébergement, base, stockage…).
    pub fn category(self) -> &'static str {
        match self {
            Self::Github => "source",
            Self::Vercel | Self::Netlify | Self::Cloudflare => "hosting",
            Self::Supabase | Self::Firebase => "database",
            Self::Cloudinary => "storage",
            Self::Custom => "custom",
        }
    }
}

/// Contrat de tout connecteur.
#[async_trait]
pub trait Connector: Send + Sync {
    fn provider(&self) -> Provider;
    /// Permissions nécessaires, séparées lecture / écriture, avec la raison.
    fn required_permissions(&self) -> Vec<PermissionSpec>;
    /// Vérifie la clé ET ses permissions réelles.
    async fn test(&self) -> Result<TestReport>;
    async fn health(&self) -> Result<Health>;
    async fn list_resources(&self) -> Result<Vec<Resource>>;
    fn actions(&self) -> Vec<ActionSpec>;
    /// Texte décrivant l'effet de l'action (aperçu avant confirmation).
    fn preview(&self, action: &str, params: &serde_json::Value) -> Result<String> {
        let spec = self
            .actions()
            .into_iter()
            .find(|a| a.id == action)
            .ok_or_else(|| cc_core::CoreError::Validation(format!("action inconnue : {action}")))?;
        Ok(format!(
            "{} — {} ({})",
            self.provider().label(),
            spec.label,
            compact(params)
        ))
    }
    /// Exécute une action. N'est appelée qu'après autorisation, confirmation et ré-auth.
    async fn execute(&self, action: &str, params: &serde_json::Value) -> Result<serde_json::Value>;
}

fn compact(v: &serde_json::Value) -> String {
    let s = v.to_string();
    if s.chars().count() > 160 {
        format!("{}…", s.chars().take(160).collect::<String>())
    } else {
        s
    }
}

/// Paramètre texte obligatoire.
pub fn param<'a>(params: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    params
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| cc_core::CoreError::Validation(format!("paramètre « {key} » requis")))
}

/// Segment d'URL sûr (identifiant fournisseur) : pas de `/`, `?`, `#`, `..`.
pub fn safe_segment(s: &str) -> Result<&str> {
    let ok = !s.is_empty()
        && s.len() <= 200
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'));
    if ok {
        Ok(s)
    } else {
        Err(cc_core::CoreError::Validation(format!(
            "identifiant invalide : {s}"
        )))
    }
}

/// `owner/name` GitHub validé.
pub fn safe_repo(s: &str) -> Result<(&str, &str)> {
    let (o, n) = s
        .split_once('/')
        .ok_or_else(|| cc_core::CoreError::Validation("dépôt attendu : owner/nom".into()))?;
    Ok((safe_segment(o)?, safe_segment(n)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_roundtrip() {
        for p in Provider::ALL {
            assert_eq!(Provider::parse(p.as_str()).unwrap(), p);
            assert!(!p.label().is_empty() && !p.category().is_empty());
        }
        assert!(Provider::parse("aws").is_err());
    }

    #[test]
    fn segments() {
        assert!(safe_segment("prj_123-abc.def").is_ok());
        for bad in ["", "..", "a/b", "a?b", "a#b", "a b", "é"] {
            assert!(safe_segment(bad).is_err(), "{bad}");
        }
        assert_eq!(safe_repo("me/app").unwrap(), ("me", "app"));
        assert!(safe_repo("me").is_err());
        assert!(safe_repo("me/../x").is_err());
        assert!(param(&serde_json::json!({"a": "x"}), "a").is_ok());
        assert!(param(&serde_json::json!({"a": ""}), "a").is_err());
        assert!(param(&serde_json::json!({}), "a").is_err());
        assert_eq!(
            compact(&serde_json::json!("x".repeat(300))).chars().count(),
            161
        );
        assert!(PermissionSpec::read("a", "b").required_for_read_only);
        assert!(!PermissionSpec::write("a", "b").required_for_read_only);
    }
}

//! Catalogue des fournisseurs (formulaires dédiés) et construction des connecteurs.
use crate::media::MediaStore;
use crate::types::{Connector, PermissionSpec, Provider};
use crate::{cloudflare, cloudinary, custom, firebase, github, netlify, supabase, vercel};
use cc_core::secrets::SecretValue;
use cc_core::{CoreError, Result};
use serde::Serialize;

/// Champ du formulaire dédié à un service.
#[derive(Clone, Debug, Serialize)]
pub struct FieldSpec {
    pub key: &'static str,
    pub label: &'static str,
    pub required: bool,
    pub help: &'static str,
    /// Valeurs possibles (liste déroulante) si renseigné.
    pub options: &'static [&'static str],
}

const fn f(
    key: &'static str,
    label: &'static str,
    required: bool,
    help: &'static str,
) -> FieldSpec {
    FieldSpec {
        key,
        label,
        required,
        help,
        options: &[],
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderInfo {
    pub provider: Provider,
    pub label: &'static str,
    pub category: &'static str,
    pub fields: Vec<FieldSpec>,
    pub secret_label: &'static str,
    pub secret_help: &'static str,
    pub permissions: Vec<PermissionSpec>,
    pub media: bool,
}

fn info(p: Provider) -> (Vec<FieldSpec>, &'static str, &'static str, bool) {
    match p {
        Provider::Github => (vec![f("repo", "Dépôt (owner/nom)", true, "Dépôt suivi")], "Jeton GitHub", "Fine-grained, limité aux dépôts nécessaires", false),
        Provider::Vercel => (
            vec![f("project_id", "ID du projet", true, "Settings → General → Project ID"), f("team_id", "ID de l'équipe", false, "Pour un projet d'équipe")],
            "Jeton Vercel",
            "Account Settings → Tokens ; limitez la portée à l'équipe et définissez une expiration",
            false,
        ),
        Provider::Supabase => (
            vec![
                f("project_ref", "Référence du projet", true, "Ex. abcdefghijklmnop"),
                FieldSpec { key: "mode", label: "Mode", required: true, help: "management = suivi ; service_role = Storage (médias)", options: &["management", "service_role"] },
                f("bucket", "Bucket des médias", false, "Requis pour l'envoi de médias"),
            ],
            "Jeton d'accès / clé service_role",
            "management : Account → Access Tokens ; service_role : Project Settings → API",
            true,
        ),
        Provider::Firebase => (
            vec![f("project_id", "ID du projet", false, "Déduit du compte de service si vide"), f("bucket", "Bucket Storage", false, "ex. mon-projet.appspot.com"), f("site_id", "Site Hosting", false, "Par défaut : ID du projet")],
            "Compte de service (JSON)",
            "IAM → Comptes de service → clé JSON ; rôles : Firebase Viewer + Storage Object Creator",
            true,
        ),
        Provider::Netlify => (vec![f("site_id", "ID du site", true, "Site configuration → Site ID")], "Jeton personnel Netlify", "User settings → Applications → Personal access tokens", false),
        Provider::Cloudflare => (
            vec![f("account_id", "ID du compte", true, "Tableau de bord → barre latérale"), f("project_name", "Projet Pages", true, "Nom du projet")],
            "Jeton API Cloudflare",
            "Jeton personnalisé : Account · Cloudflare Pages : Edit, limité au compte",
            false,
        ),
        Provider::Cloudinary => (
            vec![f("cloud_name", "Cloud name", true, "Dashboard"), f("folder", "Dossier", false, "Dossier de destination")],
            "api_key:api_secret",
            "Settings → API Keys ; créez une clé dédiée",
            true,
        ),
        Provider::Custom => (
            vec![
                f("base_url", "URL de base (HTTPS)", true, "Les identifiants ne sont envoyés qu'à cet hôte"),
                FieldSpec { key: "auth_type", label: "Authentification", required: true, help: "", options: &["bearer", "header", "basic", "oauth2", "none"] },
                f("header_name", "Nom de l'en-tête", false, "Pour « header »"),
                f("username", "Utilisateur", false, "Pour « basic »"),
                f("token_url", "URL du jeton OAuth2", false, "Pour « oauth2 » (client credentials)"),
                f("client_id", "Client ID OAuth2", false, ""),
                f("scope", "Scope OAuth2", false, ""),
                f("health_path", "Endpoint de santé", false, "ex. /health"),
            ],
            "Jeton / mot de passe / client_secret",
            "Selon l'API",
            false,
        ),
    }
}

/// Catalogue complet pour l'assistant « Ajouter une application ».
pub async fn catalog() -> Vec<ProviderInfo> {
    let mut out = Vec::new();
    for p in Provider::ALL {
        let (fields, secret_label, secret_help, media) = info(p);
        let permissions = match placeholder(p).await {
            Ok(c) => c.required_permissions(),
            Err(_) => vec![],
        };
        out.push(ProviderInfo {
            provider: p,
            label: p.label(),
            category: p.category(),
            fields,
            secret_label,
            secret_help,
            permissions,
            media,
        });
    }
    out
}

async fn placeholder(p: Provider) -> Result<Box<dyn Connector>> {
    let cfg = serde_json::json!({
        "project_id": "example", "repo": "owner/example", "project_ref": "example", "site_id": "example",
        "account_id": "example", "project_name": "example", "cloud_name": "example",
        "base_url": "https://api.example.com", "auth_type": "none"
    });
    let secret = match p {
        Provider::Firebase => {
            SecretValue::new(r#"{"client_email":"x","private_key":"x","project_id":"example"}"#)
        }
        Provider::Cloudinary => SecretValue::new("k:s"),
        _ => SecretValue::new("placeholder"),
    };
    build(p, &cfg, secret).await
}

/// Construit un connecteur à partir de sa configuration (non secrète) et de son secret.
pub async fn build(
    p: Provider,
    config: &serde_json::Value,
    secret: SecretValue,
) -> Result<Box<dyn Connector>> {
    Ok(match p {
        Provider::Github => {
            let repo = config
                .get("repo")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            Box::new(github::GitHub::new(secret, repo)?)
        }
        Provider::Vercel => Box::new(vercel::Vercel::new(config, secret)?),
        Provider::Supabase => Box::new(supabase::Supabase::new(config, secret)?),
        Provider::Firebase => Box::new(firebase::Firebase::new(config, secret)?),
        Provider::Netlify => Box::new(netlify::Netlify::new(config, secret)?),
        Provider::Cloudflare => Box::new(cloudflare::Cloudflare::new(config, secret)?),
        Provider::Cloudinary => Box::new(cloudinary::Cloudinary::new(config, secret)?),
        Provider::Custom => Box::new(custom::Custom::new(config, secret).await?),
    })
}

/// Construit un stockage de médias (Supabase, Firebase, Cloudinary).
pub fn build_media(
    p: Provider,
    config: &serde_json::Value,
    secret: SecretValue,
) -> Result<Box<dyn MediaStore>> {
    Ok(match p {
        Provider::Supabase => Box::new(supabase::Supabase::new(config, secret)?),
        Provider::Firebase => Box::new(firebase::Firebase::new(config, secret)?),
        Provider::Cloudinary => Box::new(cloudinary::Cloudinary::new(config, secret)?),
        _ => {
            return Err(CoreError::Validation(format!(
                "{} ne stocke pas de médias",
                p.label()
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn catalog_complete() {
        let c = catalog().await;
        assert_eq!(c.len(), Provider::ALL.len());
        for p in &c {
            assert!(
                !p.permissions.is_empty(),
                "{:?} sans permissions déclarées",
                p.provider
            );
            assert!(!p.fields.is_empty());
        }
        assert_eq!(c.iter().filter(|p| p.media).count(), 3);
    }

    #[tokio::test]
    async fn build_media_only_for_storage() {
        assert!(build_media(
            Provider::Vercel,
            &serde_json::json!({"project_id":"x"}),
            SecretValue::new("t")
        )
        .is_err());
        assert!(build_media(
            Provider::Cloudinary,
            &serde_json::json!({"cloud_name":"x"}),
            SecretValue::new("a:b")
        )
        .is_ok());
        assert!(build(
            Provider::Vercel,
            &serde_json::json!({}),
            SecretValue::new("t")
        )
        .await
        .is_err());
    }
}

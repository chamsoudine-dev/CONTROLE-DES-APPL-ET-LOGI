//! Outils partagés par les connecteurs.
use crate::http::validate_base_url;
use cc_core::{CoreError, Result};
use std::time::Instant;

/// URL de base : la valeur officielle, ou une surcharge **uniquement** vers la boucle locale
/// (tests, émulateurs). Empêche d'envoyer une clé à un hôte arbitraire via la configuration.
pub fn base_url(config: &serde_json::Value, official: &str) -> Result<String> {
    match config.get("api_base").and_then(serde_json::Value::as_str) {
        None | Some("") => Ok(official.to_owned()),
        Some(b) => {
            let u = validate_base_url(b)?;
            if matches!(u.host_str(), Some("localhost" | "127.0.0.1")) {
                Ok(b.trim_end_matches('/').to_owned())
            } else {
                Err(CoreError::Forbidden(
                    "surcharge d'URL autorisée uniquement vers localhost (utilisez le connecteur personnalisé)".into(),
                ))
            }
        }
    }
}

/// Champ de configuration obligatoire.
pub fn cfg<'a>(config: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    config
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CoreError::Validation(format!("configuration : « {key} » requis")))
}

pub fn cfg_opt<'a>(config: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

pub fn elapsed_ms(t: Instant) -> u64 {
    u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Encode une composante de requête (query string).
pub fn q(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Horodatage Unix (ms) → RFC 3339.
pub fn ms_to_rfc3339(ms: i64) -> Option<String> {
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000).ok()?;
    t.format(&time::format_description::well_known::Rfc3339)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_override_only_loopback() {
        let off = "https://api.vercel.com";
        assert_eq!(base_url(&serde_json::json!({}), off).unwrap(), off);
        assert_eq!(
            base_url(&serde_json::json!({"api_base":"http://127.0.0.1:9/"}), off).unwrap(),
            "http://127.0.0.1:9"
        );
        assert!(base_url(&serde_json::json!({"api_base":"https://evil.example"}), off).is_err());
        assert!(base_url(&serde_json::json!({"api_base":"http://evil.example"}), off).is_err());
        assert!(cfg(&serde_json::json!({"a":" "}), "a").is_err());
        assert_eq!(cfg_opt(&serde_json::json!({"a":"x"}), "a"), Some("x"));
        assert_eq!(q("a b&c"), "a+b%26c");
        assert_eq!(ms_to_rfc3339(0).as_deref(), Some("1970-01-01T00:00:00Z"));
    }
}

//! Connecteur Cloudinary : vérification (Admin API), liste des médias, envoi signé.
//!
//! Secret attendu : `api_key:api_secret`.
use crate::common::{base_url, cfg, elapsed_ms};
use crate::http::{Auth, Body, HttpClient};
use crate::media::MediaStore;
use crate::types::{
    safe_segment, Access, ActionSpec, Connector, DetectedPermission, Health, PermissionSpec,
    Provider, Resource, TestReport,
};
use async_trait::async_trait;
use cc_core::secrets::SecretValue;
use cc_core::{CoreError, Result};
use reqwest::Method;
use sha1::{Digest, Sha1};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const API: &str = "https://api.cloudinary.com";

pub struct Cloudinary {
    http: HttpClient,
    cloud: String,
    api_key: String,
    api_secret: SecretValue,
    folder: Option<String>,
}

impl Cloudinary {
    pub fn new(config: &serde_json::Value, secret: SecretValue) -> Result<Self> {
        let (k, s) = secret
            .expose()
            .split_once(':')
            .ok_or_else(|| CoreError::Validation("secret attendu : api_key:api_secret".into()))?;
        let api_key = k.trim().to_owned();
        let api_secret = SecretValue::new(s.trim());
        let cloud = safe_segment(cfg(config, "cloud_name")?)?.to_owned();
        let folder = crate::common::cfg_opt(config, "folder")
            .map(|f| safe_segment(f).map(str::to_owned))
            .transpose()?;
        Ok(Self {
            http: HttpClient::new(
                &base_url(config, API)?,
                Auth::Basic {
                    user: api_key.clone(),
                    pass: api_secret.clone(),
                },
            )?,
            cloud,
            api_key,
            api_secret,
            folder,
        })
    }

    /// Signature Cloudinary : SHA-1(paramètres triés « k=v&… » + api_secret).
    pub fn sign(params: &[(&str, String)], api_secret: &str) -> String {
        let mut p: Vec<&(&str, String)> = params.iter().collect();
        p.sort_by(|a, b| a.0.cmp(b.0));
        let joined = p
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let mut h = Sha1::new();
        h.update(joined.as_bytes());
        h.update(api_secret.as_bytes());
        data_encoding::HEXLOWER.encode(&h.finalize())
    }
}

#[async_trait]
impl Connector for Cloudinary {
    fn provider(&self) -> Provider {
        Provider::Cloudinary
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        vec![
            PermissionSpec::read("admin:resources", "Lister les médias existants"),
            PermissionSpec::write("upload", "Envoyer les médias (WebP)"),
        ]
    }

    async fn test(&self) -> Result<TestReport> {
        let mut rep = TestReport::default();
        match self
            .http
            .get_json::<serde_json::Value>(&format!("/v1_1/{}/usage", self.cloud))
            .await
        {
            Ok(v) => {
                rep.ok = true;
                rep.can_read = true;
                rep.can_write = true;
                rep.identity = Some(format!(
                    "{} ({})",
                    self.cloud,
                    v["plan"].as_str().unwrap_or("?")
                ));
                rep.permissions.push(DetectedPermission {
                    scope: "admin".into(),
                    access: Access::Read,
                    granted: true,
                });
                rep.permissions.push(DetectedPermission {
                    scope: "upload".into(),
                    access: Access::Write,
                    granted: true,
                });
                rep.too_powerful = true;
                rep.warnings.push(
                    "La clé API principale Cloudinary a tous les droits : créez une clé dédiée (Settings → API Keys) et révoquez-la si besoin."
                        .into(),
                );
            }
            Err(e) => rep.warnings.push(e.to_string()),
        }
        Ok(rep)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        Ok(
            match self
                .http
                .get(&format!("/v1_1/{}/usage", self.cloud))
                .await
                .and_then(crate::http::Response::ok)
            {
                Ok(_) => Health {
                    online: true,
                    latency_ms: elapsed_ms(t),
                    detail: "API joignable".into(),
                },
                Err(e) => Health {
                    online: false,
                    latency_ms: elapsed_ms(t),
                    detail: e.to_string(),
                },
            },
        )
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        let v: serde_json::Value = self
            .http
            .get_json(&format!(
                "/v1_1/{}/resources/image?max_results=30",
                self.cloud
            ))
            .await?;
        Ok(v["resources"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|r| Resource {
                        id: r["public_id"].as_str().unwrap_or_default().into(),
                        kind: "image".into(),
                        name: r["public_id"].as_str().unwrap_or_default().into(),
                        url: r["secure_url"].as_str().map(str::to_owned),
                        status: r["format"].as_str().map(str::to_owned),
                        created_at: r["created_at"].as_str().map(str::to_owned),
                        extra: serde_json::json!({"bytes": r["bytes"]}),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![]
    }

    async fn execute(&self, action: &str, _p: &serde_json::Value) -> Result<serde_json::Value> {
        Err(CoreError::Validation(format!("action inconnue : {action}")))
    }
}

#[async_trait]
impl MediaStore for Cloudinary {
    async fn upload(&self, path: &str, bytes: Vec<u8>, content_type: &str) -> Result<String> {
        let stem = path.rsplit_once('.').map_or(path, |(s, _)| s);
        if stem.split('/').any(|s| s.is_empty() || s == "..") {
            return Err(CoreError::Validation("chemin invalide".into()));
        }
        let public_id = match &self.folder {
            Some(f) => format!("{f}/{stem}"),
            None => stem.to_owned(),
        };
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            .to_string();
        let params = [("public_id", public_id.clone()), ("timestamp", ts.clone())];
        let signature = Self::sign(&params, self.api_secret.expose());
        let file = format!(
            "data:{content_type};base64,{}",
            data_encoding::BASE64.encode(&bytes)
        );
        let url = self
            .http
            .url(&format!("/v1_1/{}/image/upload", self.cloud))?;
        let v: serde_json::Value = self
            .http
            .send_url(
                Method::POST,
                url,
                Some(Body::Form(vec![
                    ("file".into(), file),
                    ("public_id".into(), public_id),
                    ("timestamp".into(), ts),
                    ("api_key".into(), self.api_key.clone()),
                    ("signature".into(), signature),
                ])),
                &[],
            )
            .await?
            .ok()?
            .json()?;
        v["secure_url"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| CoreError::External("URL absente".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn signature_matches_cloudinary_docs() {
        // Exemple de la documentation Cloudinary (Authentication signatures).
        let sig = Cloudinary::sign(
            &[
                ("timestamp", "1315060510".into()),
                ("public_id", "sample_image".into()),
                ("eager", "w_400,h_300,c_pad|w_260,h_200,c_crop".into()),
            ],
            "abcd",
        );
        assert_eq!(sig, "bfd09f95f331f558cbd1320e67aa8d488770583e");
    }

    #[tokio::test]
    async fn cloudinary_flow() {
        let s = MockServer::start().await;
        Mock::given(path("/v1_1/demo/usage"))
            .and(header("authorization", "Basic a2V5OnNlY3JldA=="))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"plan":"Free"})),
            )
            .mount(&s)
            .await;
        Mock::given(path("/v1_1/demo/resources/image")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"resources":[{"public_id":"logo","secure_url":"https://res/logo.webp","format":"webp"}]}))).mount(&s).await;
        Mock::given(method("POST")).and(path("/v1_1/demo/image/upload")).and(body_string_contains("signature=")).and(body_string_contains("public_id=app%2Flogo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"secure_url":"https://res.cloudinary.com/demo/image/upload/app/logo.webp"}))).mount(&s).await;
        let c = Cloudinary::new(
            &serde_json::json!({"cloud_name":"demo","folder":"app","api_base": s.uri()}),
            SecretValue::new("key:secret"),
        )
        .unwrap();
        let r = c.test().await.unwrap();
        assert!(r.ok && r.can_write && r.too_powerful);
        assert!(c.health().await.unwrap().online);
        assert_eq!(c.list_resources().await.unwrap()[0].id, "logo");
        assert!(c
            .upload("logo.webp", vec![1, 2], "image/webp")
            .await
            .unwrap()
            .ends_with("logo.webp"));
        assert!(c.upload("../x.webp", vec![1], "image/webp").await.is_err());
        assert!(c.actions().is_empty() && c.execute("x", &serde_json::json!({})).await.is_err());
        assert_eq!(c.required_permissions().len(), 2);
    }

    #[test]
    fn config_validation() {
        assert!(Cloudinary::new(
            &serde_json::json!({"cloud_name":"d"}),
            SecretValue::new("nocolon")
        )
        .is_err());
        assert!(Cloudinary::new(&serde_json::json!({}), SecretValue::new("a:b")).is_err());
    }
}

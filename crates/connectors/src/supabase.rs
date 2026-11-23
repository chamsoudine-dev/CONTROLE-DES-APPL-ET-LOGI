//! Connecteur Supabase.
//!
//! Deux modes : `management` (jeton personnel → API de gestion : santé, fonctions) et
//! `service_role` (clé du projet → Storage : buckets, envoi de médias).
use crate::common::{cfg, cfg_opt, elapsed_ms};
use crate::http::{validate_base_url, Auth, Body, HttpClient};
use crate::media::MediaStore;
use crate::types::{
    safe_segment, Access, ActionSpec, Connector, DetectedPermission, Health, PermissionSpec,
    Provider, Resource, TestReport,
};
use async_trait::async_trait;
use cc_core::secrets::SecretValue;
use cc_core::{CoreError, Result};
use reqwest::Method;
use std::time::Instant;

pub const MGMT_API: &str = "https://api.supabase.com";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Management,
    ServiceRole,
}

pub struct Supabase {
    http: HttpClient,
    mode: Mode,
    project_ref: String,
    project_url: String,
    bucket: Option<String>,
}

impl Supabase {
    pub fn new(config: &serde_json::Value, key: SecretValue) -> Result<Self> {
        let project_ref = safe_segment(cfg(config, "project_ref")?)?.to_owned();
        let mode = match cfg_opt(config, "mode").unwrap_or("management") {
            "management" => Mode::Management,
            "service_role" => Mode::ServiceRole,
            m => {
                return Err(CoreError::Validation(format!(
                    "mode Supabase inconnu : {m}"
                )))
            }
        };
        let official_project = format!("https://{project_ref}.supabase.co");
        let override_base = cfg_opt(config, "api_base");
        if let Some(b) = override_base {
            let u = validate_base_url(b)?;
            if !matches!(u.host_str(), Some("localhost" | "127.0.0.1")) {
                return Err(CoreError::Forbidden(
                    "surcharge d'URL autorisée uniquement vers localhost".into(),
                ));
            }
        }
        let project_url = override_base
            .unwrap_or(&official_project)
            .trim_end_matches('/')
            .to_owned();
        let (base, auth) = match mode {
            Mode::Management => (
                override_base.unwrap_or(MGMT_API).to_owned(),
                Auth::Bearer(key),
            ),
            Mode::ServiceRole => (
                project_url.clone(),
                Auth::Header {
                    name: "apikey".into(),
                    value: key,
                },
            ),
        };
        let bucket = cfg_opt(config, "bucket")
            .map(|b| safe_segment(b).map(str::to_owned))
            .transpose()?;
        Ok(Self {
            http: HttpClient::new(&base, auth)?,
            mode,
            project_ref,
            project_url,
            bucket,
        })
    }

    async fn get(&self, path: &str) -> Result<serde_json::Value> {
        self.http.get_json(path).await
    }
}

#[async_trait]
impl Connector for Supabase {
    fn provider(&self) -> Provider {
        Provider::Supabase
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        match self.mode {
            Mode::Management => vec![
                PermissionSpec::read("projects", "Lire l'état de santé du projet"),
                PermissionSpec::read("functions", "Lister les Edge Functions"),
            ],
            Mode::ServiceRole => vec![
                PermissionSpec::read("storage", "Lister les buckets et fichiers"),
                PermissionSpec::write("storage", "Envoyer les médias (WebP)"),
            ],
        }
    }

    async fn test(&self) -> Result<TestReport> {
        let mut rep = TestReport::default();
        let r = match self.mode {
            Mode::Management => {
                self.get(&format!("/v1/projects/{}", self.project_ref))
                    .await
            }
            Mode::ServiceRole => self.get("/storage/v1/bucket").await,
        };
        match r {
            Ok(v) => {
                rep.ok = true;
                rep.can_read = true;
                match self.mode {
                    Mode::Management => {
                        rep.identity = v["name"].as_str().map(str::to_owned);
                        rep.too_powerful = true;
                        rep.warnings.push(
                            "Les jetons personnels Supabase ont accès à toute l'organisation : réservez-les au suivi."
                                .into(),
                        );
                        rep.permissions.push(DetectedPermission {
                            scope: "projects".into(),
                            access: Access::Read,
                            granted: true,
                        });
                    }
                    Mode::ServiceRole => {
                        rep.can_write = true;
                        rep.too_powerful = true;
                        rep.identity = Some(self.project_ref.clone());
                        rep.warnings.push(
                            "La clé service_role contourne la sécurité RLS : ne l'utilisez que pour le Storage, jamais côté client."
                                .into(),
                        );
                        rep.permissions.push(DetectedPermission {
                            scope: "storage".into(),
                            access: Access::Read,
                            granted: true,
                        });
                        rep.permissions.push(DetectedPermission {
                            scope: "storage".into(),
                            access: Access::Write,
                            granted: true,
                        });
                    }
                }
            }
            Err(e) => rep.warnings.push(e.to_string()),
        }
        Ok(rep)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        let r = match self.mode {
            Mode::Management => self
                .get(&format!("/v1/projects/{}/health?services=db&services=auth&services=storage&services=rest", self.project_ref))
                .await
                .map(|v| {
                    let all = v.as_array().is_some_and(|a| a.iter().all(|s| s["healthy"].as_bool() == Some(true)));
                    (all, if all { "tous les services sont sains".to_owned() } else { "service dégradé".to_owned() })
                }),
            Mode::ServiceRole => self.get("/storage/v1/bucket").await.map(|_| (true, "Storage joignable".to_owned())),
        };
        Ok(match r {
            Ok((online, detail)) => Health {
                online,
                latency_ms: elapsed_ms(t),
                detail,
            },
            Err(e) => Health {
                online: false,
                latency_ms: elapsed_ms(t),
                detail: e.to_string(),
            },
        })
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        let (path, kind) = match self.mode {
            Mode::Management => (
                format!("/v1/projects/{}/functions", self.project_ref),
                "function",
            ),
            Mode::ServiceRole => ("/storage/v1/bucket".to_owned(), "bucket"),
        };
        let v = self.get(&path).await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .map(|x| Resource {
                        id: x["id"].as_str().unwrap_or_default().into(),
                        kind: kind.into(),
                        name: x["name"]
                            .as_str()
                            .or(x["slug"].as_str())
                            .unwrap_or_default()
                            .into(),
                        url: None,
                        status: x["status"].as_str().map(str::to_owned).or_else(|| {
                            x["public"].as_bool().map(|p| {
                                if p {
                                    "public".into()
                                } else {
                                    "privé".into()
                                }
                            })
                        }),
                        created_at: x["created_at"].as_str().map(str::to_owned),
                        extra: serde_json::Value::Null,
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
impl MediaStore for Supabase {
    async fn upload(&self, path: &str, bytes: Vec<u8>, content_type: &str) -> Result<String> {
        if self.mode != Mode::ServiceRole {
            return Err(CoreError::Validation(
                "l'envoi de médias nécessite le mode service_role".into(),
            ));
        }
        let bucket = self
            .bucket
            .as_deref()
            .ok_or_else(|| CoreError::Validation("bucket non configuré".into()))?;
        if path.split('/').any(|s| s.is_empty() || s == "..") {
            return Err(CoreError::Validation("chemin invalide".into()));
        }
        let url = self
            .http
            .url(&format!("/storage/v1/object/{bucket}/{path}"))?;
        self.http
            .send_url(
                Method::POST,
                url,
                Some(Body::Bytes(bytes, content_type.into())),
                &[("x-upsert", "true")],
            )
            .await?
            .ok()?;
        Ok(format!(
            "{}/storage/v1/object/public/{bucket}/{path}",
            self.project_url
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn management_mode() {
        let s = MockServer::start().await;
        Mock::given(path("/v1/projects/abc"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"name":"prod"})),
            )
            .mount(&s)
            .await;
        Mock::given(path("/v1/projects/abc/health"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"name":"db","healthy":true}])),
            )
            .mount(&s)
            .await;
        Mock::given(path("/v1/projects/abc/functions"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!([{"id":"f1","slug":"hello","status":"ACTIVE"}]),
                ),
            )
            .mount(&s)
            .await;
        let c = Supabase::new(
            &serde_json::json!({"project_ref":"abc","api_base": s.uri()}),
            SecretValue::new("sbp_x"),
        )
        .unwrap();
        let r = c.test().await.unwrap();
        assert!(r.ok && r.too_powerful && !r.can_write);
        assert!(c.health().await.unwrap().online);
        assert_eq!(c.list_resources().await.unwrap()[0].name, "hello");
        assert!(c.upload("a.webp", vec![1], "image/webp").await.is_err());
        assert!(c.actions().is_empty() && c.execute("x", &serde_json::json!({})).await.is_err());
        assert_eq!(c.required_permissions().len(), 2);
    }

    #[tokio::test]
    async fn service_role_storage_upload() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/storage/v1/bucket"))
            .and(header("apikey", "srk"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!([{"id":"media","name":"media","public":true}]),
                ),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/storage/v1/object/media/app/logo.webp"))
            .and(header("content-type", "image/webp"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"Key":"media/app/logo.webp"})),
            )
            .mount(&s)
            .await;
        let c = Supabase::new(&serde_json::json!({"project_ref":"abc","mode":"service_role","bucket":"media","api_base": s.uri()}), SecretValue::new("srk")).unwrap();
        let r = c.test().await.unwrap();
        assert!(r.ok && r.can_write && r.too_powerful);
        assert_eq!(
            c.list_resources().await.unwrap()[0].status.as_deref(),
            Some("public")
        );
        let url = c
            .upload("app/logo.webp", vec![1, 2], "image/webp")
            .await
            .unwrap();
        assert!(url.ends_with("/storage/v1/object/public/media/app/logo.webp"));
        assert!(c.upload("../x.webp", vec![1], "image/webp").await.is_err());
        assert!(c.health().await.unwrap().online);
    }

    #[test]
    fn config_validation() {
        assert!(Supabase::new(&serde_json::json!({}), SecretValue::new("x")).is_err());
        assert!(Supabase::new(
            &serde_json::json!({"project_ref":"a","mode":"x"}),
            SecretValue::new("x")
        )
        .is_err());
        assert!(Supabase::new(
            &serde_json::json!({"project_ref":"a","api_base":"https://evil.example"}),
            SecretValue::new("x")
        )
        .is_err());
        let ok = Supabase::new(
            &serde_json::json!({"project_ref":"abc"}),
            SecretValue::new("x"),
        )
        .unwrap();
        assert_eq!(ok.project_url, "https://abc.supabase.co");
    }
}

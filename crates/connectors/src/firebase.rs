//! Connecteur Firebase (compte de service) : jeton OAuth2 (JWT RS256), permissions IAM réelles,
//! Hosting (versions publiées), Storage (envoi de médias).
use crate::common::{cfg_opt, elapsed_ms, q};
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
use serde::Deserialize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const SCOPES: &str =
    "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/firebase";

#[derive(Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    #[serde(default)]
    token_uri: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
}

impl Drop for ServiceAccount {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}

pub struct Firebase {
    sa: ServiceAccount,
    project: String,
    bucket: Option<String>,
    site: Option<String>,
    base_override: Option<String>,
    token: tokio::sync::Mutex<Option<(SecretValue, Instant)>>,
}

/// Permissions IAM vérifiées (lecture / écriture / dangereuses).
const IAM_READ: &[&str] = &[
    "firebase.projects.get",
    "firebasehosting.sites.get",
    "storage.objects.list",
];
const IAM_WRITE: &[&str] = &["storage.objects.create", "firebasehosting.sites.update"];
const IAM_DANGEROUS: &[&str] = &[
    "resourcemanager.projects.delete",
    "iam.serviceAccountKeys.create",
    "resourcemanager.projects.setIamPolicy",
];

impl Firebase {
    pub fn new(config: &serde_json::Value, service_account_json: SecretValue) -> Result<Self> {
        let sa: ServiceAccount = serde_json::from_str(service_account_json.expose())
            .map_err(|_| CoreError::Validation("JSON de compte de service invalide".into()))?;
        let base_override = cfg_opt(config, "api_base").map(str::to_owned);
        if let Some(b) = &base_override {
            let u = validate_base_url(b)?;
            if !matches!(u.host_str(), Some("localhost" | "127.0.0.1")) {
                return Err(CoreError::Forbidden(
                    "surcharge d'URL autorisée uniquement vers localhost".into(),
                ));
            }
        } else if sa.token_uri.as_deref().is_some_and(|t| t != TOKEN_URI) {
            return Err(CoreError::Forbidden(
                "token_uri inattendu dans le compte de service".into(),
            ));
        }
        let project = cfg_opt(config, "project_id")
            .map(str::to_owned)
            .or_else(|| sa.project_id.clone())
            .ok_or_else(|| CoreError::Validation("configuration : « project_id » requis".into()))?;
        safe_segment(&project)?;
        let bucket = cfg_opt(config, "bucket")
            .map(|b| safe_segment(b).map(str::to_owned))
            .transpose()?;
        let site = cfg_opt(config, "site_id")
            .map(|b| safe_segment(b).map(str::to_owned))
            .transpose()?;
        Ok(Self {
            sa,
            project,
            bucket,
            site,
            base_override,
            token: tokio::sync::Mutex::new(None),
        })
    }

    fn base(&self, official: &str) -> String {
        self.base_override
            .clone()
            .unwrap_or_else(|| official.to_owned())
    }

    /// Jeton d'accès OAuth2 (mis en cache 50 min).
    async fn access_token(&self) -> Result<SecretValue> {
        let mut guard = self.token.lock().await;
        if let Some((t, at)) = guard.as_ref() {
            if at.elapsed() < Duration::from_secs(50 * 60) {
                return Ok(t.clone());
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let token_url = format!("{}/token", self.base("https://oauth2.googleapis.com"));
        let claims = serde_json::json!({
            "iss": self.sa.client_email, "scope": SCOPES, "aud": TOKEN_URI, "iat": now, "exp": now + 3600
        });
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(self.sa.private_key.as_bytes()).map_err(
            |_| CoreError::Validation("clé privée du compte de service invalide".into()),
        )?;
        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &key,
        )
        .map_err(|_| CoreError::Crypto)?;
        let http = HttpClient::new(&token_url, Auth::None)?;
        let v: serde_json::Value = http
            .send_url(
                Method::POST,
                http.base().clone(),
                Some(Body::Form(vec![
                    (
                        "grant_type".into(),
                        "urn:ietf:params:oauth:grant-type:jwt-bearer".into(),
                    ),
                    ("assertion".into(), jwt),
                ])),
                &[],
            )
            .await?
            .ok()?
            .json()?;
        let t = SecretValue::new(
            v["access_token"]
                .as_str()
                .ok_or_else(|| CoreError::External("jeton Google absent".into()))?,
        );
        *guard = Some((t.clone(), Instant::now()));
        Ok(t)
    }

    async fn client(&self, official: &str) -> Result<HttpClient> {
        HttpClient::new(
            &self.base(official),
            Auth::Bearer(self.access_token().await?),
        )
    }

    async fn iam_check(&self) -> Result<Vec<String>> {
        let c = self
            .client("https://cloudresourcemanager.googleapis.com")
            .await?;
        let all: Vec<&str> = IAM_READ
            .iter()
            .chain(IAM_WRITE)
            .chain(IAM_DANGEROUS)
            .copied()
            .collect();
        let v: serde_json::Value = c
            .send(
                Method::POST,
                &format!("/v1/projects/{}:testIamPermissions", self.project),
                Some(&serde_json::json!({"permissions": all})),
                &[],
            )
            .await?
            .ok()?
            .json()?;
        Ok(v["permissions"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[async_trait]
impl Connector for Firebase {
    fn provider(&self) -> Provider {
        Provider::Firebase
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        vec![
            PermissionSpec::read("Firebase Viewer", "Lire le projet, Hosting et Storage"),
            PermissionSpec::write("Storage Object Creator", "Envoyer les médias"),
            PermissionSpec::write(
                "Firebase Hosting Admin",
                "Publier une version Hosting (optionnel)",
            ),
        ]
    }

    async fn test(&self) -> Result<TestReport> {
        let mut rep = TestReport::default();
        let granted = match self.iam_check().await {
            Ok(g) => g,
            Err(e) => {
                rep.warnings.push(e.to_string());
                return Ok(rep);
            }
        };
        rep.identity = Some(self.sa.client_email.clone());
        rep.ok = true;
        for p in IAM_READ.iter().chain(IAM_WRITE) {
            rep.permissions.push(DetectedPermission {
                scope: (*p).to_owned(),
                access: if IAM_WRITE.contains(p) {
                    Access::Write
                } else {
                    Access::Read
                },
                granted: granted.iter().any(|g| g == p),
            });
        }
        rep.can_read = IAM_READ.iter().any(|p| granted.iter().any(|g| g == p));
        rep.can_write = IAM_WRITE.iter().any(|p| granted.iter().any(|g| g == p));
        let dangerous: Vec<&str> = IAM_DANGEROUS
            .iter()
            .copied()
            .filter(|p| granted.iter().any(|g| g == p))
            .collect();
        if !dangerous.is_empty() {
            rep.too_powerful = true;
            rep.warnings.push(format!(
                "Compte de service trop puissant ({dangerous:?}) : attribuez seulement « Firebase Viewer » + « Storage Object Creator »."
            ));
        }
        Ok(rep)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        let r = async {
            let c = self.client("https://firebase.googleapis.com").await?;
            c.get_json::<serde_json::Value>(&format!("/v1beta1/projects/{}", self.project))
                .await
        }
        .await;
        Ok(match r {
            Ok(v) => Health {
                online: v["state"].as_str().unwrap_or("ACTIVE") == "ACTIVE",
                latency_ms: elapsed_ms(t),
                detail: format!(
                    "projet {}",
                    v["displayName"].as_str().unwrap_or(&self.project)
                ),
            },
            Err(e) => Health {
                online: false,
                latency_ms: elapsed_ms(t),
                detail: e.to_string(),
            },
        })
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        let site = self.site.clone().unwrap_or_else(|| self.project.clone());
        let c = self
            .client("https://firebasehosting.googleapis.com")
            .await?;
        let v: serde_json::Value = c
            .get_json(&format!("/v1beta1/sites/{site}/releases?pageSize=20"))
            .await?;
        Ok(v["releases"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|r| Resource {
                        id: r["name"].as_str().unwrap_or_default().into(),
                        kind: "release".into(),
                        name: r["message"].as_str().unwrap_or_default().into(),
                        url: Some(format!("https://{site}.web.app")),
                        status: r["type"].as_str().map(str::to_owned),
                        created_at: r["releaseTime"].as_str().map(str::to_owned),
                        extra: serde_json::json!({"version": r["version"]["name"]}),
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
impl MediaStore for Firebase {
    async fn upload(&self, path: &str, bytes: Vec<u8>, content_type: &str) -> Result<String> {
        let bucket = self
            .bucket
            .as_deref()
            .ok_or_else(|| CoreError::Validation("bucket non configuré".into()))?;
        if path.split('/').any(|s| s.is_empty() || s == "..") {
            return Err(CoreError::Validation("chemin invalide".into()));
        }
        let c = self.client("https://storage.googleapis.com").await?;
        let url = c.url(&format!(
            "/upload/storage/v1/b/{bucket}/o?uploadType=media&name={}",
            q(path)
        ))?;
        c.send_url(
            Method::POST,
            url,
            Some(Body::Bytes(bytes, content_type.into())),
            &[],
        )
        .await?
        .ok()?;
        Ok(format!(
            "https://firebasestorage.googleapis.com/v0/b/{bucket}/o/{}?alt=media",
            q(path)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sa_json(token_uri: &str) -> SecretValue {
        let key = include_str!("../tests/fixtures/test-only-rsa.pem");
        SecretValue::new(
            serde_json::json!({
                "type": "service_account", "project_id": "demo-proj",
                "client_email": "cc@demo-proj.iam.gserviceaccount.com",
                "private_key": key, "token_uri": token_uri
            })
            .to_string(),
        )
    }

    async fn mount(s: &MockServer, perms: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("jwt-bearer"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"access_token":"ya29.test","expires_in":3600}),
                ),
            )
            .expect(1..)
            .mount(s)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/projects/demo-proj:testIamPermissions"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"permissions": perms})),
            )
            .mount(s)
            .await;
        Mock::given(path("/v1beta1/projects/demo-proj"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"displayName":"Demo","state":"ACTIVE"})),
            )
            .mount(s)
            .await;
        Mock::given(path("/v1beta1/sites/demo-proj/releases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"releases":[{"name":"r1","type":"DEPLOY","message":"v2"}]}),
            ))
            .mount(s)
            .await;
        Mock::given(method("POST"))
            .and(path("/upload/storage/v1/b/demo-bucket/o"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"name":"a/b.webp"})),
            )
            .mount(s)
            .await;
    }

    #[tokio::test]
    async fn least_privilege_service_account() {
        let s = MockServer::start().await;
        mount(
            &s,
            serde_json::json!(["firebase.projects.get", "storage.objects.create"]),
        )
        .await;
        let c = Firebase::new(
            &serde_json::json!({"api_base": s.uri(), "bucket": "demo-bucket"}),
            sa_json(TOKEN_URI),
        )
        .unwrap();
        let r = c.test().await.unwrap();
        assert!(
            r.ok && r.can_read && r.can_write && !r.too_powerful,
            "{r:?}"
        );
        assert!(c.health().await.unwrap().online);
        assert_eq!(c.list_resources().await.unwrap()[0].name, "v2");
        let url = c
            .upload("a/b.webp", vec![1, 2, 3], "image/webp")
            .await
            .unwrap();
        assert!(url.contains("demo-bucket") && url.contains("a%2Fb.webp"));
        assert!(c.upload("../b.webp", vec![1], "image/webp").await.is_err());
        assert!(c.actions().is_empty() && c.execute("x", &serde_json::json!({})).await.is_err());
        assert_eq!(c.required_permissions().len(), 3);
    }

    #[tokio::test]
    async fn owner_service_account_flagged() {
        let s = MockServer::start().await;
        mount(
            &s,
            serde_json::json!(["firebase.projects.get", "resourcemanager.projects.delete"]),
        )
        .await;
        let c = Firebase::new(
            &serde_json::json!({"api_base": s.uri()}),
            sa_json(TOKEN_URI),
        )
        .unwrap();
        let r = c.test().await.unwrap();
        assert!(r.too_powerful && !r.can_write);
        assert!(
            c.upload("a.webp", vec![], "image/webp").await.is_err(),
            "bucket manquant"
        );
    }

    #[test]
    fn config_validation() {
        assert!(Firebase::new(&serde_json::json!({}), SecretValue::new("{}")).is_err());
        assert!(Firebase::new(
            &serde_json::json!({}),
            sa_json("https://evil.example/token")
        )
        .is_err());
        assert!(Firebase::new(
            &serde_json::json!({"api_base":"https://evil.example"}),
            sa_json(TOKEN_URI)
        )
        .is_err());
        assert!(Firebase::new(
            &serde_json::json!({"project_id":"../x"}),
            sa_json(TOKEN_URI)
        )
        .is_err());
        assert!(Firebase::new(&serde_json::json!({}), sa_json(TOKEN_URI)).is_ok());
    }

    #[tokio::test]
    async fn token_failure_reported() {
        let s = MockServer::start().await;
        Mock::given(path("/token"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&s)
            .await;
        let c = Firebase::new(
            &serde_json::json!({"api_base": s.uri()}),
            sa_json(TOKEN_URI),
        )
        .unwrap();
        assert!(!c.test().await.unwrap().ok);
        assert!(!c.health().await.unwrap().online);
    }
}

//! Connecteur Netlify : déploiements, nouveau build, restauration (rollback), variables.
use crate::common::{base_url, cfg, elapsed_ms};
use crate::http::{Auth, HttpClient};
use crate::types::{
    param, safe_segment, Access, ActionSpec, Connector, DetectedPermission, Health, PermissionSpec,
    Provider, Resource, TestReport,
};
use async_trait::async_trait;
use cc_core::policy::Action;
use cc_core::secrets::SecretValue;
use cc_core::{CoreError, Result};
use reqwest::Method;
use std::time::Instant;

pub const API: &str = "https://api.netlify.com/api/v1";

pub struct Netlify {
    http: HttpClient,
    site: String,
}

impl Netlify {
    pub fn new(config: &serde_json::Value, token: SecretValue) -> Result<Self> {
        Ok(Self {
            http: HttpClient::new(&base_url(config, API)?, Auth::Bearer(token))?,
            site: safe_segment(cfg(config, "site_id")?)?.to_owned(),
        })
    }

    async fn req(
        &self,
        m: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let r = self.http.send(m, path, body, &[]).await?.ok()?;
        if r.body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        r.json()
    }
}

#[async_trait]
impl Connector for Netlify {
    fn provider(&self) -> Provider {
        Provider::Netlify
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        vec![
            PermissionSpec::read("sites", "Lire le site et ses déploiements"),
            PermissionSpec::write("builds", "Déclencher un nouveau build"),
            PermissionSpec::write("deploys", "Restaurer un déploiement précédent (rollback)"),
            PermissionSpec::write("env", "Envoyer les variables d'environnement"),
        ]
    }

    async fn test(&self) -> Result<TestReport> {
        let mut rep = TestReport::default();
        match self.req(Method::GET, "/user", None).await {
            Ok(u) => {
                rep.identity = u["email"]
                    .as_str()
                    .or(u["full_name"].as_str())
                    .map(str::to_owned)
            }
            Err(e) => {
                rep.warnings.push(e.to_string());
                return Ok(rep);
            }
        }
        match self
            .req(Method::GET, &format!("/sites/{}", self.site), None)
            .await
        {
            Ok(_) => {
                rep.ok = true;
                rep.can_read = true;
                rep.can_write = true;
                rep.too_powerful = true;
                for (scope, access) in [
                    ("sites", Access::Read),
                    ("builds", Access::Write),
                    ("deploys", Access::Write),
                    ("env", Access::Write),
                ] {
                    rep.permissions.push(DetectedPermission {
                        scope: scope.into(),
                        access,
                        granted: true,
                    });
                }
                rep.warnings.push(
                    "Les jetons personnels Netlify donnent accès à tout le compte (pas de portée possible). Gardez l'appli en lecture seule sauf besoin."
                        .into(),
                );
            }
            Err(e) => rep.warnings.push(format!("Site inaccessible : {e}")),
        }
        Ok(rep)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        Ok(
            match self
                .req(Method::GET, &format!("/sites/{}", self.site), None)
                .await
            {
                Ok(v) => {
                    let state = v["published_deploy"]["state"]
                        .as_str()
                        .unwrap_or("inconnu")
                        .to_owned();
                    Health {
                        online: state == "ready",
                        latency_ms: elapsed_ms(t),
                        detail: format!("publié : {state}"),
                    }
                }
                Err(e) => Health {
                    online: false,
                    latency_ms: elapsed_ms(t),
                    detail: e.to_string(),
                },
            },
        )
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        let v = self
            .req(
                Method::GET,
                &format!("/sites/{}/deploys?per_page=20", self.site),
                None,
            )
            .await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .map(|d| Resource {
                        id: d["id"].as_str().unwrap_or_default().into(),
                        kind: "deployment".into(),
                        name: d["title"].as_str().or(d["branch"].as_str()).unwrap_or_default().into(),
                        url: d["deploy_ssl_url"].as_str().map(str::to_owned),
                        status: d["state"].as_str().map(str::to_owned),
                        created_at: d["created_at"].as_str().map(str::to_owned),
                        extra: serde_json::json!({"context": d["context"], "commit": d["commit_ref"]}),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "redeploy",
                "Nouveau build",
                Action::Redeploy,
                "Déclenche un build du site",
            ),
            ActionSpec::new(
                "rollback",
                "Restaurer un déploiement",
                Action::Rollback,
                "Publie à nouveau un déploiement précédent (deployment_id)",
            ),
            ActionSpec::new(
                "env_push",
                "Envoyer les variables",
                Action::EditEnv,
                "Met à jour les variables du site (vars)",
            ),
        ]
    }

    async fn execute(&self, action: &str, p: &serde_json::Value) -> Result<serde_json::Value> {
        match action {
            "redeploy" => {
                let v = self
                    .req(
                        Method::POST,
                        &format!("/sites/{}/builds", self.site),
                        Some(&serde_json::json!({})),
                    )
                    .await?;
                Ok(serde_json::json!({"build_id": v["id"]}))
            }
            "rollback" => {
                let dep = safe_segment(param(p, "deployment_id")?)?;
                self.req(
                    Method::POST,
                    &format!("/sites/{}/deploys/{dep}/restore", self.site),
                    None,
                )
                .await?;
                Ok(serde_json::json!({"restored": dep}))
            }
            "env_push" => {
                let vars = p
                    .get("vars")
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| CoreError::Validation("vars requis".into()))?;
                let site = self
                    .req(Method::GET, &format!("/sites/{}", self.site), None)
                    .await?;
                let account =
                    safe_segment(site["account_id"].as_str().unwrap_or_default())?.to_owned();
                let ctx = match p
                    .get("environment")
                    .and_then(|v| v.as_str())
                    .unwrap_or("production")
                {
                    "production" => "production",
                    "preview" => "deploy-preview",
                    "development" => "dev",
                    other => {
                        return Err(CoreError::Validation(format!(
                            "environnement inconnu : {other}"
                        )))
                    }
                };
                let body: Vec<serde_json::Value> = vars
                    .iter()
                    .map(|(k, v)| serde_json::json!({"key": k, "values": [{"value": v, "context": ctx}], "is_secret": true}))
                    .collect();
                self.req(
                    Method::POST,
                    &format!("/accounts/{account}/env?site_id={}", self.site),
                    Some(&serde_json::Value::Array(body)),
                )
                .await?;
                Ok(serde_json::json!({"pushed": vars.len()}))
            }
            _ => Err(CoreError::Validation(format!("action inconnue : {action}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn netlify_flow() {
        let s = MockServer::start().await;
        Mock::given(path("/user"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"email":"me@x"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/sites/site1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"account_id":"acc1","published_deploy":{"state":"ready"}}),
            ))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/sites/site1/deploys"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!([{"id":"d1","state":"ready","branch":"main"}]),
                ),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/sites/site1/builds"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"b1"})))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/sites/site1/deploys/d1/restore"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/accounts/acc1/env"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!([])))
            .mount(&s)
            .await;
        let c = Netlify::new(
            &serde_json::json!({"site_id":"site1","api_base": s.uri()}),
            SecretValue::new("t"),
        )
        .unwrap();
        let r = c.test().await.unwrap();
        assert!(r.ok && r.too_powerful);
        assert!(c.health().await.unwrap().online);
        assert_eq!(c.list_resources().await.unwrap()[0].id, "d1");
        assert_eq!(
            c.execute("redeploy", &serde_json::json!({})).await.unwrap()["build_id"],
            "b1"
        );
        c.execute("rollback", &serde_json::json!({"deployment_id":"d1"}))
            .await
            .unwrap();
        c.execute(
            "env_push",
            &serde_json::json!({"vars":{"A":"1"},"environment":"preview"}),
        )
        .await
        .unwrap();
        assert!(c
            .execute(
                "env_push",
                &serde_json::json!({"vars":{"A":"1"},"environment":"x"})
            )
            .await
            .is_err());
        assert!(c.execute("nope", &serde_json::json!({})).await.is_err());
        assert_eq!(c.actions().len(), 3);
        assert_eq!(c.required_permissions().len(), 4);
        let bad = Netlify::new(
            &serde_json::json!({"site_id":"zz","api_base": s.uri()}),
            SecretValue::new("t"),
        )
        .unwrap();
        assert!(!bad.test().await.unwrap().ok);
        assert!(!bad.health().await.unwrap().online);
    }
}

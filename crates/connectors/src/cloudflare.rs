//! Connecteur Cloudflare Pages : déploiements, relance, rollback, variables.
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

pub const API: &str = "https://api.cloudflare.com/client/v4";

pub struct Cloudflare {
    http: HttpClient,
    account: String,
    project: String,
}

impl Cloudflare {
    pub fn new(config: &serde_json::Value, token: SecretValue) -> Result<Self> {
        Ok(Self {
            http: HttpClient::new(&base_url(config, API)?, Auth::Bearer(token))?,
            account: safe_segment(cfg(config, "account_id")?)?.to_owned(),
            project: safe_segment(cfg(config, "project_name")?)?.to_owned(),
        })
    }

    fn base(&self) -> String {
        format!("/accounts/{}/pages/projects/{}", self.account, self.project)
    }

    async fn req(
        &self,
        m: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let v: serde_json::Value = self.http.send(m, path, body, &[]).await?.ok()?.json()?;
        if v["success"].as_bool() == Some(false) {
            let msg = v["errors"][0]["message"]
                .as_str()
                .unwrap_or("erreur Cloudflare");
            return Err(CoreError::External(msg.to_owned()));
        }
        Ok(v["result"].clone())
    }
}

#[async_trait]
impl Connector for Cloudflare {
    fn provider(&self) -> Provider {
        Provider::Cloudflare
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        vec![
            PermissionSpec::read(
                "Account · Cloudflare Pages : Read",
                "Lire le projet et ses déploiements",
            ),
            PermissionSpec::write(
                "Account · Cloudflare Pages : Edit",
                "Relancer, rollback, variables d'environnement",
            ),
        ]
    }

    async fn test(&self) -> Result<TestReport> {
        let mut rep = TestReport::default();
        match self.req(Method::GET, "/user/tokens/verify", None).await {
            Ok(v) => {
                if v["status"] != "active" {
                    rep.warnings.push("Jeton inactif.".into());
                    return Ok(rep);
                }
                rep.expires_at = v["expires_on"].as_str().map(str::to_owned);
            }
            Err(e) => {
                rep.warnings.push(e.to_string());
                return Ok(rep);
            }
        }
        match self.req(Method::GET, &self.base(), None).await {
            Ok(p) => {
                rep.ok = true;
                rep.can_read = true;
                rep.identity = p["subdomain"].as_str().map(str::to_owned);
                rep.permissions.push(DetectedPermission {
                    scope: "pages".into(),
                    access: Access::Read,
                    granted: true,
                });
                // L'écriture ne peut être vérifiée sans effet de bord : signalée comme non confirmée.
                rep.warnings.push("Droit d'écriture non vérifiable sans action : il sera confirmé au premier redéploiement.".into());
            }
            Err(e) => rep.warnings.push(format!("Projet inaccessible : {e}")),
        }
        Ok(rep)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        Ok(match self.req(Method::GET, &self.base(), None).await {
            Ok(p) => {
                let st = p["latest_deployment"]["latest_stage"]["status"]
                    .as_str()
                    .unwrap_or("inconnu")
                    .to_owned();
                Health {
                    online: st == "success",
                    latency_ms: elapsed_ms(t),
                    detail: format!("dernier déploiement : {st}"),
                }
            }
            Err(e) => Health {
                online: false,
                latency_ms: elapsed_ms(t),
                detail: e.to_string(),
            },
        })
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        let v = self
            .req(Method::GET, &format!("{}/deployments", self.base()), None)
            .await?;
        Ok(v.as_array()
            .map(|a| {
                a.iter()
                    .map(|d| Resource {
                        id: d["id"].as_str().unwrap_or_default().into(),
                        kind: "deployment".into(),
                        name: d["deployment_trigger"]["metadata"]["commit_message"]
                            .as_str()
                            .unwrap_or_default()
                            .into(),
                        url: d["url"].as_str().map(str::to_owned),
                        status: d["latest_stage"]["status"].as_str().map(str::to_owned),
                        created_at: d["created_on"].as_str().map(str::to_owned),
                        extra: serde_json::json!({"environment": d["environment"]}),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "redeploy",
                "Relancer un déploiement",
                Action::Redeploy,
                "Relance un déploiement (deployment_id)",
            ),
            ActionSpec::new(
                "rollback",
                "Rollback production",
                Action::Rollback,
                "Revient à un déploiement précédent (deployment_id)",
            ),
            ActionSpec::new(
                "env_push",
                "Envoyer les variables",
                Action::EditEnv,
                "Met à jour les variables (environment, vars)",
            ),
        ]
    }

    async fn execute(&self, action: &str, p: &serde_json::Value) -> Result<serde_json::Value> {
        match action {
            "redeploy" => {
                let d = safe_segment(param(p, "deployment_id")?)?;
                let v = self
                    .req(
                        Method::POST,
                        &format!("{}/deployments/{d}/retry", self.base()),
                        None,
                    )
                    .await?;
                Ok(serde_json::json!({"id": v["id"]}))
            }
            "rollback" => {
                let d = safe_segment(param(p, "deployment_id")?)?;
                self.req(
                    Method::POST,
                    &format!("{}/deployments/{d}/rollback", self.base()),
                    None,
                )
                .await?;
                Ok(serde_json::json!({"rolled_back_to": d}))
            }
            "env_push" => {
                let env = match param(p, "environment")? {
                    "production" => "production",
                    "preview" | "development" => "preview",
                    other => {
                        return Err(CoreError::Validation(format!(
                            "environnement inconnu : {other}"
                        )))
                    }
                };
                let vars = p
                    .get("vars")
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| CoreError::Validation("vars requis".into()))?;
                let mut ev = serde_json::Map::new();
                for (k, v) in vars {
                    ev.insert(
                        k.clone(),
                        serde_json::json!({"type": "secret_text", "value": v}),
                    );
                }
                let body = serde_json::json!({"deployment_configs": {env: {"env_vars": ev}}});
                self.req(Method::PATCH, &self.base(), Some(&body)).await?;
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

    fn ok(v: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({"success": true, "result": v}))
    }

    #[tokio::test]
    async fn cloudflare_flow() {
        let s = MockServer::start().await;
        let base = "/accounts/acc/pages/projects/site";
        Mock::given(path("/user/tokens/verify"))
            .respond_with(ok(serde_json::json!({"status":"active"})))
            .mount(&s)
            .await;
        Mock::given(method("GET")).and(path(base)).respond_with(ok(serde_json::json!({"subdomain":"site.pages.dev","latest_deployment":{"latest_stage":{"status":"success"}}}))).mount(&s).await;
        Mock::given(method("GET")).and(path(format!("{base}/deployments"))).respond_with(ok(serde_json::json!([{"id":"d1","url":"https://d1.site.pages.dev","latest_stage":{"status":"success"}}]))).mount(&s).await;
        Mock::given(method("POST"))
            .and(path(format!("{base}/deployments/d1/retry")))
            .respond_with(ok(serde_json::json!({"id":"d2"})))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{base}/deployments/d1/rollback")))
            .respond_with(ok(serde_json::json!({})))
            .mount(&s)
            .await;
        Mock::given(method("PATCH"))
            .and(path(base))
            .respond_with(ok(serde_json::json!({})))
            .mount(&s)
            .await;
        let c = Cloudflare::new(
            &serde_json::json!({"account_id":"acc","project_name":"site","api_base": s.uri()}),
            SecretValue::new("t"),
        )
        .unwrap();
        let r = c.test().await.unwrap();
        assert!(r.ok && r.can_read && !r.can_write);
        assert!(c.health().await.unwrap().online);
        assert_eq!(c.list_resources().await.unwrap().len(), 1);
        assert_eq!(
            c.execute("redeploy", &serde_json::json!({"deployment_id":"d1"}))
                .await
                .unwrap()["id"],
            "d2"
        );
        c.execute("rollback", &serde_json::json!({"deployment_id":"d1"}))
            .await
            .unwrap();
        c.execute(
            "env_push",
            &serde_json::json!({"environment":"production","vars":{"A":"b"}}),
        )
        .await
        .unwrap();
        assert!(c
            .execute(
                "env_push",
                &serde_json::json!({"environment":"x","vars":{}})
            )
            .await
            .is_err());
        assert!(c.execute("nope", &serde_json::json!({})).await.is_err());
        assert_eq!(c.required_permissions().len(), 2);
        assert_eq!(c.actions().len(), 3);
    }

    #[tokio::test]
    async fn cloudflare_errors() {
        let s = MockServer::start().await;
        Mock::given(path("/user/tokens/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"success": false, "errors":[{"message":"Invalid API Token"}]}),
            ))
            .mount(&s)
            .await;
        let c = Cloudflare::new(
            &serde_json::json!({"account_id":"acc","project_name":"site","api_base": s.uri()}),
            SecretValue::new("t"),
        )
        .unwrap();
        let r = c.test().await.unwrap();
        assert!(!r.ok && r.warnings[0].contains("Invalid"));
        assert!(!c.health().await.unwrap().online);
        let s2 = MockServer::start().await;
        Mock::given(path("/user/tokens/verify"))
            .respond_with(ok(serde_json::json!({"status":"disabled"})))
            .mount(&s2)
            .await;
        let c2 = Cloudflare::new(
            &serde_json::json!({"account_id":"acc","project_name":"site","api_base": s2.uri()}),
            SecretValue::new("t"),
        )
        .unwrap();
        assert!(!c2.test().await.unwrap().ok);
    }
}

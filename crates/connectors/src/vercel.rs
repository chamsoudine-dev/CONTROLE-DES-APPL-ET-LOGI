//! Connecteur Vercel : déploiements, redéploiement, rollback, variables d'environnement.
use crate::common::{base_url, cfg, cfg_opt, elapsed_ms, ms_to_rfc3339, q};
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

pub const API: &str = "https://api.vercel.com";

pub struct Vercel {
    http: HttpClient,
    project: String,
    team: Option<String>,
}

impl Vercel {
    pub fn new(config: &serde_json::Value, token: SecretValue) -> Result<Self> {
        let project = safe_segment(cfg(config, "project_id")?)?.to_owned();
        let team = cfg_opt(config, "team_id")
            .map(|t| safe_segment(t).map(str::to_owned))
            .transpose()?;
        Ok(Self {
            http: HttpClient::new(&base_url(config, API)?, Auth::Bearer(token))?,
            project,
            team,
        })
    }

    fn with_team(&self, path: &str) -> String {
        match &self.team {
            Some(t) => format!(
                "{path}{}teamId={}",
                if path.contains('?') { '&' } else { '?' },
                q(t)
            ),
            None => path.to_owned(),
        }
    }

    async fn req(
        &self,
        m: Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let r = self
            .http
            .send(m, &self.with_team(path), body, &[])
            .await?
            .ok()?;
        if r.body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        r.json()
    }

    /// Variables distantes : clé → (id, valeur si lisible, cibles).
    pub async fn remote_env(&self) -> Result<Vec<(String, String, Option<String>, Vec<String>)>> {
        let v = self
            .req(
                Method::GET,
                &format!("/v9/projects/{}/env?decrypt=false", self.project),
                None,
            )
            .await?;
        Ok(v["envs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| {
                        let readable = e["type"].as_str() == Some("plain");
                        (
                            e["key"].as_str().unwrap_or_default().to_owned(),
                            e["id"].as_str().unwrap_or_default().to_owned(),
                            if readable {
                                e["value"].as_str().map(str::to_owned)
                            } else {
                                None
                            },
                            e["target"]
                                .as_array()
                                .map(|t| {
                                    t.iter()
                                        .filter_map(|x| x.as_str().map(str::to_owned))
                                        .collect()
                                })
                                .unwrap_or_default(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

fn target_for(env: &str) -> Result<&'static str> {
    match env {
        "production" => Ok("production"),
        "preview" => Ok("preview"),
        "development" => Ok("development"),
        _ => Err(CoreError::Validation(format!(
            "environnement inconnu : {env}"
        ))),
    }
}

#[async_trait]
impl Connector for Vercel {
    fn provider(&self) -> Provider {
        Provider::Vercel
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        vec![
            PermissionSpec::read("deployments", "Afficher les déploiements et leur statut"),
            PermissionSpec::read("projects", "Lire le projet et ses variables (noms)"),
            PermissionSpec::write("deployments", "Redéployer et faire un rollback"),
            PermissionSpec::write("env", "Envoyer les variables d'environnement"),
        ]
    }

    async fn test(&self) -> Result<TestReport> {
        let mut rep = TestReport::default();
        let user = match self.req(Method::GET, "/v2/user", None).await {
            Ok(u) => u,
            Err(e) => {
                rep.warnings.push(e.to_string());
                return Ok(rep);
            }
        };
        rep.identity = user["user"]["username"].as_str().map(str::to_owned);
        if let Ok(tok) = self.req(Method::GET, "/v5/user/tokens/current", None).await {
            let t = &tok["token"];
            rep.expires_at = t["expiresAt"].as_i64().and_then(ms_to_rfc3339);
            let scopes = t["scopes"].as_array().cloned().unwrap_or_default();
            let full_account = scopes.iter().any(|s| s["type"] == "user");
            if full_account && self.team.is_some() {
                rep.too_powerful = true;
                rep.warnings.push(
                    "Jeton à portée « compte entier » : créez un jeton limité à l'équipe du projet.".into(),
                );
            }
        }
        match self
            .req(Method::GET, &format!("/v9/projects/{}", self.project), None)
            .await
        {
            Ok(_) => {
                rep.ok = true;
                rep.can_read = true;
                // Vercel n'a pas de jeton en lecture seule : un jeton valide sur le projet peut écrire.
                rep.can_write = true;
                for (scope, access) in [
                    ("projects", Access::Read),
                    ("deployments", Access::Read),
                    ("deployments", Access::Write),
                    ("env", Access::Write),
                ] {
                    rep.permissions.push(DetectedPermission {
                        scope: scope.into(),
                        access,
                        granted: true,
                    });
                }
                rep.warnings.push(
                    "Vercel ne propose pas de jeton en lecture seule : utilisez le mode « Lecture seule » de l'appli pour bloquer les écritures."
                        .into(),
                );
            }
            Err(e) => rep.warnings.push(format!("Projet inaccessible : {e}")),
        }
        if rep.expires_at.is_none() && rep.ok {
            rep.warnings
                .push("Le jeton n'expire pas : définissez une expiration.".into());
        }
        Ok(rep)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        let r = self
            .req(
                Method::GET,
                &format!(
                    "/v6/deployments?projectId={}&limit=1&target=production",
                    q(&self.project)
                ),
                None,
            )
            .await;
        Ok(match r {
            Ok(v) => {
                let state = v["deployments"][0]["state"]
                    .as_str()
                    .unwrap_or("aucun")
                    .to_owned();
                Health {
                    online: state == "READY",
                    latency_ms: elapsed_ms(t),
                    detail: format!("production : {state}"),
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
            .req(
                Method::GET,
                &format!("/v6/deployments?projectId={}&limit=20", q(&self.project)),
                None,
            )
            .await?;
        Ok(v["deployments"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|d| Resource {
                        id: d["uid"].as_str().unwrap_or_default().into(),
                        kind: "deployment".into(),
                        name: d["name"].as_str().unwrap_or_default().into(),
                        url: d["url"].as_str().map(|u| format!("https://{u}")),
                        status: d["state"].as_str().map(str::to_owned),
                        created_at: d["created"].as_i64().and_then(ms_to_rfc3339),
                        extra: serde_json::json!({
                            "target": d["target"],
                            "commit": d["meta"]["githubCommitSha"],
                            "message": d["meta"]["githubCommitMessage"],
                        }),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "redeploy",
                "Redéployer",
                Action::Redeploy,
                "Relance un déploiement existant (deployment_id, target)",
            ),
            ActionSpec::new(
                "rollback",
                "Rollback production",
                Action::Rollback,
                "Remet en production un déploiement précédent (deployment_id)",
            ),
            ActionSpec::new(
                "env_push",
                "Envoyer les variables",
                Action::EditEnv,
                "Crée/met à jour les variables (environment, vars{clé: valeur})",
            ),
            ActionSpec::new(
                "env_delete",
                "Supprimer une variable",
                Action::EditEnv,
                "Supprime une variable distante (key)",
            ),
        ]
    }

    async fn execute(&self, action: &str, p: &serde_json::Value) -> Result<serde_json::Value> {
        match action {
            "redeploy" => {
                let dep = safe_segment(param(p, "deployment_id")?)?;
                let target = p
                    .get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("production");
                let v = self
                    .req(Method::POST, "/v13/deployments?forceNew=1", Some(&serde_json::json!({
                        "name": self.project, "deploymentId": dep, "target": target_for(target)?, "project": self.project
                    })))
                    .await?;
                Ok(serde_json::json!({"id": v["id"], "url": v["url"]}))
            }
            "rollback" => {
                let dep = safe_segment(param(p, "deployment_id")?)?;
                self.req(
                    Method::POST,
                    &format!("/v9/projects/{}/rollback/{dep}", self.project),
                    None,
                )
                .await?;
                Ok(serde_json::json!({"rolled_back_to": dep}))
            }
            "env_push" => {
                let target = target_for(param(p, "environment")?)?;
                let vars = p
                    .get("vars")
                    .and_then(|v| v.as_object())
                    .ok_or_else(|| CoreError::Validation("vars requis".into()))?;
                let body: Vec<serde_json::Value> = vars
                    .iter()
                    .map(|(k, v)| serde_json::json!({"key": k, "value": v, "type": "encrypted", "target": [target]}))
                    .collect();
                self.req(
                    Method::POST,
                    &format!("/v10/projects/{}/env?upsert=true", self.project),
                    Some(&serde_json::Value::Array(body)),
                )
                .await?;
                Ok(serde_json::json!({"pushed": vars.len()}))
            }
            "env_delete" => {
                let key = param(p, "key")?;
                let remote = self.remote_env().await?;
                let id = remote
                    .iter()
                    .find(|e| e.0 == key)
                    .map(|e| e.1.clone())
                    .ok_or_else(|| CoreError::NotFound(format!("variable {key}")))?;
                self.req(
                    Method::DELETE,
                    &format!("/v9/projects/{}/env/{}", self.project, safe_segment(&id)?),
                    None,
                )
                .await?;
                Ok(serde_json::json!({"deleted": key}))
            }
            _ => Err(CoreError::Validation(format!("action inconnue : {action}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn v(s: &MockServer, team: bool) -> Vercel {
        let mut c = serde_json::json!({"project_id":"prj_1","api_base": s.uri()});
        if team {
            c["team_id"] = "team_1".into();
        }
        Vercel::new(&c, SecretValue::new("vtok")).unwrap()
    }

    async fn mount(s: &MockServer) {
        Mock::given(path("/v2/user"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"user":{"username":"me"}})),
            )
            .mount(s)
            .await;
        Mock::given(path("/v5/user/tokens/current")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"token":{"scopes":[{"type":"user"}],"expiresAt":1_900_000_000_000_i64}}))).mount(s).await;
        Mock::given(method("GET"))
            .and(path("/v9/projects/prj_1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"prj_1"})),
            )
            .mount(s)
            .await;
        Mock::given(method("GET")).and(path("/v6/deployments")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"deployments":[
            {"uid":"dpl_2","name":"shop","url":"shop-2.vercel.app","state":"READY","created":1_800_000_000_000_i64,"target":"production","meta":{"githubCommitSha":"abc"}},
            {"uid":"dpl_1","name":"shop","url":"shop-1.vercel.app","state":"READY","created":1_700_000_000_000_i64}
        ]}))).mount(s).await;
        Mock::given(method("POST"))
            .and(path("/v13/deployments"))
            .and(body_string_contains("dpl_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"id":"dpl_3","url":"x"})),
            )
            .mount(s)
            .await;
        Mock::given(method("POST"))
            .and(path("/v9/projects/prj_1/rollback/dpl_1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(s)
            .await;
        Mock::given(method("POST"))
            .and(path("/v10/projects/prj_1/env"))
            .and(query_param("upsert", "true"))
            .and(body_string_contains("\"API\""))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(s)
            .await;
        Mock::given(method("GET")).and(path("/v9/projects/prj_1/env")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"envs":[
            {"id":"env_1","key":"API","type":"plain","value":"https://x","target":["production"]},
            {"id":"env_2","key":"SECRET","type":"encrypted","value":"enc","target":["production"]}
        ]}))).mount(s).await;
        Mock::given(method("DELETE"))
            .and(path("/v9/projects/prj_1/env/env_1"))
            .respond_with(ResponseTemplate::new(200))
            .mount(s)
            .await;
    }

    #[tokio::test]
    async fn test_and_permissions() {
        let s = MockServer::start().await;
        mount(&s).await;
        let r = v(&s, true).test().await.unwrap();
        assert!(r.ok && r.can_read && r.can_write && r.too_powerful);
        assert_eq!(r.identity.as_deref(), Some("me"));
        assert!(r.expires_at.is_some());
        let r2 = v(&s, false).test().await.unwrap();
        assert!(!r2.too_powerful);
        assert_eq!(v(&s, false).required_permissions().len(), 4);
    }

    #[tokio::test]
    async fn deployments_redeploy_rollback_env() {
        let s = MockServer::start().await;
        mount(&s).await;
        let c = v(&s, false);
        let deps = c.list_resources().await.unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].url.as_deref(), Some("https://shop-2.vercel.app"));
        assert!(c.health().await.unwrap().online);
        assert_eq!(
            c.execute("redeploy", &serde_json::json!({"deployment_id":"dpl_1"}))
                .await
                .unwrap()["id"],
            "dpl_3"
        );
        c.execute("rollback", &serde_json::json!({"deployment_id":"dpl_1"}))
            .await
            .unwrap();
        c.execute(
            "env_push",
            &serde_json::json!({"environment":"production","vars":{"API":"https://x"}}),
        )
        .await
        .unwrap();
        let remote = c.remote_env().await.unwrap();
        assert_eq!(remote[0].2.as_deref(), Some("https://x"));
        assert_eq!(remote[1].2, None, "valeur chiffrée illisible");
        c.execute("env_delete", &serde_json::json!({"key":"API"}))
            .await
            .unwrap();
        assert!(c
            .execute("env_delete", &serde_json::json!({"key":"NOPE"}))
            .await
            .is_err());
        assert!(c
            .execute(
                "env_push",
                &serde_json::json!({"environment":"staging","vars":{}})
            )
            .await
            .is_err());
        assert!(c
            .execute("rollback", &serde_json::json!({"deployment_id":"../x"}))
            .await
            .is_err());
        assert!(c.execute("x", &serde_json::json!({})).await.is_err());
    }

    #[tokio::test]
    async fn invalid_token() {
        let s = MockServer::start().await;
        Mock::given(path("/v2/user"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&s)
            .await;
        let r = v(&s, false).test().await.unwrap();
        assert!(!r.ok);
        assert!(Vercel::new(&serde_json::json!({}), SecretValue::new("x")).is_err());
    }
}

//! Connecteur personnalisé : n'importe quelle API HTTPS (Bearer, en-tête, Basic, OAuth2
//! client credentials), endpoint de santé et actions déclarées.
use crate::common::{cfg, cfg_opt, elapsed_ms};
use crate::http::{validate_base_url, Auth, Body, HttpClient};
use crate::types::{ActionSpec, Connector, Health, PermissionSpec, Provider, Resource, TestReport};
use async_trait::async_trait;
use cc_core::policy::Action;
use cc_core::secrets::SecretValue;
use cc_core::{CoreError, Result};
use reqwest::Method;
use serde::Deserialize;
use std::time::Instant;

#[derive(Clone, Debug, Deserialize)]
pub struct CustomAction {
    pub id: String,
    pub label: String,
    pub method: String,
    pub path: String,
    /// Action de la matrice de droits (par défaut : `view` pour GET, `redeploy` sinon).
    #[serde(default)]
    pub policy: Option<String>,
}

pub struct Custom {
    http: HttpClient,
    health_path: String,
    actions: Vec<(CustomAction, Method, Action)>,
}

fn method(m: &str) -> Result<Method> {
    match m.to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        _ => Err(CoreError::Validation(format!(
            "méthode non prise en charge : {m}"
        ))),
    }
}

fn check_path(p: &str) -> Result<()> {
    if !p.starts_with('/') || p.contains("://") || p.contains("..") || p.len() > 512 {
        return Err(CoreError::Validation(format!(
            "chemin relatif attendu : {p}"
        )));
    }
    Ok(())
}

impl Custom {
    /// `config` : `{base_url, auth_type, header_name?, username?, token_url?, client_id?, scope?,
    /// health_path?, actions?: [{id, label, method, path, policy?}]}`.
    pub async fn new(config: &serde_json::Value, secret: SecretValue) -> Result<Self> {
        let base = cfg(config, "base_url")?;
        validate_base_url(base)?;
        let auth = match cfg_opt(config, "auth_type").unwrap_or("bearer") {
            "bearer" => Auth::Bearer(secret),
            "header" => {
                let name = cfg(config, "header_name")?.to_owned();
                if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("cookie") {
                    return Err(CoreError::Validation("en-tête interdit".into()));
                }
                Auth::Header {
                    name,
                    value: secret,
                }
            }
            "basic" => Auth::Basic {
                user: cfg(config, "username")?.to_owned(),
                pass: secret,
            },
            "oauth2" => Auth::Bearer(Self::client_credentials(config, &secret).await?),
            "none" => Auth::None,
            other => {
                return Err(CoreError::Validation(format!(
                    "authentification inconnue : {other}"
                )))
            }
        };
        let health_path = cfg_opt(config, "health_path").unwrap_or("/").to_owned();
        check_path(&health_path)?;
        let mut actions = Vec::new();
        if let Some(list) = config.get("actions") {
            let list: Vec<CustomAction> = serde_json::from_value(list.clone())?;
            if list.len() > 20 {
                return Err(CoreError::Validation("20 actions maximum".into()));
            }
            for a in list {
                crate::types::safe_segment(&a.id)?;
                check_path(&a.path)?;
                let m = method(&a.method)?;
                let pa = match &a.policy {
                    Some(p) => Action::parse(p)?,
                    None if m == Method::GET => Action::View,
                    None if m == Method::DELETE => Action::Delete,
                    None => Action::Redeploy,
                };
                actions.push((a, m, pa));
            }
        }
        Ok(Self {
            http: HttpClient::new(base, auth)?,
            health_path,
            actions,
        })
    }

    /// OAuth2 « client credentials » : le secret est le client_secret.
    async fn client_credentials(
        config: &serde_json::Value,
        secret: &SecretValue,
    ) -> Result<SecretValue> {
        let token_url = cfg(config, "token_url")?;
        let client_id = cfg(config, "client_id")?;
        let http = HttpClient::new(
            token_url,
            Auth::Basic {
                user: client_id.to_owned(),
                pass: secret.clone(),
            },
        )?;
        let mut form = vec![("grant_type".to_owned(), "client_credentials".to_owned())];
        if let Some(s) = cfg_opt(config, "scope") {
            form.push(("scope".into(), s.into()));
        }
        let v: serde_json::Value = http
            .send_url(
                Method::POST,
                http.base().clone(),
                Some(Body::Form(form)),
                &[],
            )
            .await?
            .ok()?
            .json()?;
        v["access_token"]
            .as_str()
            .map(SecretValue::new)
            .ok_or_else(|| CoreError::External("access_token absent de la réponse OAuth2".into()))
    }
}

#[async_trait]
impl Connector for Custom {
    fn provider(&self) -> Provider {
        Provider::Custom
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        let mut v = vec![PermissionSpec::read(
            "health",
            "Vérifier la disponibilité de l'API",
        )];
        for (a, m, _) in &self.actions {
            v.push(if *m == Method::GET {
                PermissionSpec::read(&a.path, &a.label)
            } else {
                PermissionSpec::write(&a.path, &a.label)
            });
        }
        v
    }

    async fn test(&self) -> Result<TestReport> {
        let mut rep = TestReport::default();
        match self.http.get(&self.health_path).await {
            Ok(r) if r.status.is_success() => {
                rep.ok = true;
                rep.can_read = true;
                rep.can_write = self.actions.iter().any(|(_, m, _)| *m != Method::GET);
                rep.identity = self.http.base().host_str().map(str::to_owned);
                rep.warnings.push("Les droits réels d'une API personnalisée ne peuvent pas être détectés automatiquement.".into());
            }
            Ok(r) => rep
                .warnings
                .push(format!("Endpoint de santé : HTTP {}", r.status)),
            Err(e) => rep.warnings.push(e.to_string()),
        }
        Ok(rep)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        Ok(match self.http.get(&self.health_path).await {
            Ok(r) => Health {
                online: r.status.is_success(),
                latency_ms: elapsed_ms(t),
                detail: format!("HTTP {}", r.status.as_u16()),
            },
            Err(e) => Health {
                online: false,
                latency_ms: elapsed_ms(t),
                detail: e.to_string(),
            },
        })
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        Ok(vec![])
    }

    fn actions(&self) -> Vec<ActionSpec> {
        self.actions
            .iter()
            .map(|(a, _, pa)| {
                ActionSpec::new(a.id.clone(), a.label.clone(), *pa, "Action personnalisée")
            })
            .collect()
    }

    async fn execute(&self, action: &str, p: &serde_json::Value) -> Result<serde_json::Value> {
        let (a, m, _) = self
            .actions
            .iter()
            .find(|(a, _, _)| a.id == action)
            .ok_or_else(|| CoreError::Validation(format!("action inconnue : {action}")))?;
        let body = p.get("body");
        let r = self.http.send(m.clone(), &a.path, body, &[]).await?.ok()?;
        Ok(if r.body.is_empty() {
            serde_json::json!({"status": r.status.as_u16()})
        } else {
            r.json()
                .unwrap_or_else(|_| serde_json::json!({"status": r.status.as_u16()}))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn bearer_and_actions() {
        let s = MockServer::start().await;
        Mock::given(path("/health"))
            .and(header("authorization", "Bearer t"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/deploy"))
            .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({"ok":true})))
            .mount(&s)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/cache"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&s)
            .await;
        let cfg = serde_json::json!({"base_url": s.uri(), "health_path": "/health", "actions": [
            {"id":"deploy","label":"Déployer","method":"POST","path":"/deploy"},
            {"id":"purge","label":"Purger le cache","method":"DELETE","path":"/cache"},
            {"id":"stats","label":"Stats","method":"GET","path":"/stats"}
        ]});
        let c = Custom::new(&cfg, SecretValue::new("t")).await.unwrap();
        let r = c.test().await.unwrap();
        assert!(r.ok && r.can_write);
        assert!(c.health().await.unwrap().online);
        let acts = c.actions();
        assert_eq!(acts.len(), 3);
        assert_eq!(acts[0].policy_action, Action::Redeploy);
        assert_eq!(acts[1].policy_action, Action::Delete);
        assert_eq!(acts[2].policy_action, Action::View);
        assert_eq!(
            c.execute("deploy", &serde_json::json!({})).await.unwrap()["ok"],
            true
        );
        assert_eq!(
            c.execute("purge", &serde_json::json!({})).await.unwrap()["status"],
            204
        );
        assert!(c.execute("nope", &serde_json::json!({})).await.is_err());
        assert_eq!(c.required_permissions().len(), 4);
        assert!(c.list_resources().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn header_basic_oauth2() {
        let s = MockServer::start().await;
        Mock::given(path("/"))
            .and(header("x-api-key", "k"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        Mock::given(path("/b"))
            .and(header("authorization", "Basic dTpw"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/oauth/token"))
            .and(body_string_contains("grant_type=client_credentials"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"access_token":"at"})),
            )
            .mount(&s)
            .await;
        Mock::given(path("/o"))
            .and(header("authorization", "Bearer at"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        let h = Custom::new(&serde_json::json!({"base_url": s.uri(), "auth_type":"header","header_name":"x-api-key"}), SecretValue::new("k")).await.unwrap();
        assert!(h.test().await.unwrap().ok);
        let b = Custom::new(&serde_json::json!({"base_url": s.uri(), "auth_type":"basic","username":"u","health_path":"/b"}), SecretValue::new("p")).await.unwrap();
        assert!(b.test().await.unwrap().ok);
        let o = Custom::new(&serde_json::json!({"base_url": s.uri(), "auth_type":"oauth2","token_url": format!("{}/oauth/token", s.uri()),"client_id":"cid","scope":"read","health_path":"/o"}), SecretValue::new("cs")).await.unwrap();
        assert!(o.test().await.unwrap().ok);
        let down = Custom::new(
            &serde_json::json!({"base_url": s.uri(), "health_path":"/missing"}),
            SecretValue::new("x"),
        )
        .await
        .unwrap();
        assert!(!down.test().await.unwrap().ok);
        assert!(!down.health().await.unwrap().online);
    }

    #[tokio::test]
    async fn rejects_http_and_bad_config() {
        let x = SecretValue::new("x");
        assert!(Custom::new(
            &serde_json::json!({"base_url":"http://api.example.com"}),
            x.clone()
        )
        .await
        .is_err());
        assert!(Custom::new(&serde_json::json!({"base_url":"https://a.example","auth_type":"header","header_name":"Host"}), x.clone()).await.is_err());
        assert!(Custom::new(
            &serde_json::json!({"base_url":"https://a.example","auth_type":"magic"}),
            x.clone()
        )
        .await
        .is_err());
        assert!(Custom::new(
            &serde_json::json!({"base_url":"https://a.example","health_path":"https://evil/x"}),
            x.clone()
        )
        .await
        .is_err());
        assert!(Custom::new(&serde_json::json!({"base_url":"https://a.example","actions":[{"id":"a","label":"A","method":"TRACE","path":"/x"}]}), x.clone()).await.is_err());
        assert!(Custom::new(&serde_json::json!({"base_url":"https://a.example","actions":[{"id":"a","label":"A","method":"GET","path":"/../x"}]}), x.clone()).await.is_err());
        assert!(Custom::new(&serde_json::json!({"base_url":"https://a.example","actions":[{"id":"a","label":"A","method":"GET","path":"/x","policy":"root"}]}), x).await.is_err());
    }
}

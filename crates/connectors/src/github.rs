//! Connecteur GitHub : identité et permissions, dépôts, Device Flow, contenus (sync,
//! révocations), suivi par requêtes conditionnelles (ETag) avec respect du quota, actions.
use crate::http::{Auth, Body, HttpClient, Response};
use crate::types::{
    param, safe_repo, safe_segment, Access, ActionSpec, Connector, DetectedPermission, Health,
    PermissionSpec, Provider, Resource, TestReport,
};
use async_trait::async_trait;
use cc_core::policy::Action;
use cc_core::secrets::SecretValue;
use cc_core::{CoreError, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const API: &str = "https://api.github.com";
pub const WEB: &str = "https://github.com";
/// Réserve de requêtes conservée pour les actions manuelles de l'utilisateur.
pub const QUOTA_RESERVE: u32 = 100;

/// État du quota (en-têtes `X-RateLimit-*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RateState {
    pub limit: u32,
    pub remaining: u32,
    /// Epoch (s) de réinitialisation.
    pub reset: u64,
}

impl RateState {
    fn update(&mut self, r: &Response) {
        let num = |h: &str| r.header(h).and_then(|v| v.parse::<u64>().ok());
        if let Some(l) = num("x-ratelimit-limit") {
            self.limit = u32::try_from(l).unwrap_or(u32::MAX);
        }
        if let Some(rem) = num("x-ratelimit-remaining") {
            self.remaining = u32::try_from(rem).unwrap_or(u32::MAX);
        }
        if let Some(reset) = num("x-ratelimit-reset") {
            self.reset = reset;
        }
    }

    /// Le polling automatique doit-il s'abstenir (quota sous la réserve) ?
    pub fn should_back_off(&self, now_unix: u64) -> bool {
        self.limit > 0 && self.remaining < QUOTA_RESERVE && now_unix < self.reset
    }

    /// Intervalle de polling adapté : répartit le quota restant jusqu'à la réinitialisation.
    pub fn recommended_interval_secs(&self, now_unix: u64, requests_per_cycle: u32) -> u64 {
        const MIN: u64 = 60;
        if self.limit == 0 {
            return MIN;
        }
        let until_reset = self.reset.saturating_sub(now_unix).max(1);
        let budget = u64::from(self.remaining.saturating_sub(QUOTA_RESERVE));
        if budget == 0 {
            return until_reset.max(MIN);
        }
        let cycles = (budget / u64::from(requests_per_cycle.max(1))).max(1);
        (until_reset / cycles).max(MIN)
    }
}

/// Résultat d'une requête conditionnelle.
#[derive(Clone, Debug, PartialEq)]
pub enum Polled {
    NotModified,
    Modified {
        etag: Option<String>,
        body: serde_json::Value,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Repo {
    pub full_name: String,
    pub private: bool,
    pub html_url: String,
    pub default_branch: Option<String>,
    pub pushed_at: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Réponse du Device Flow (étape 1).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Résultat d'un sondage du Device Flow.
#[derive(Debug, PartialEq, Eq)]
pub enum DevicePoll {
    Pending,
    SlowDown,
    Token(SecretValue),
}

/// Contenu d'un fichier (API contents).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileContent {
    pub sha: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct GitHub {
    http: HttpClient,
    repo: Option<String>,
    rate: Arc<Mutex<RateState>>,
}

/// Portées « classic » jugées trop puissantes pour l'usage de Control Center.
const DANGEROUS_SCOPES: &[&str] = &[
    "delete_repo",
    "admin:org",
    "admin:enterprise",
    "admin:public_key",
    "admin:gpg_key",
    "admin:repo_hook",
    "admin:org_hook",
    "site_admin",
    "write:packages",
    "delete:packages",
    "user",
];

impl GitHub {
    pub fn new(token: SecretValue, repo: Option<String>) -> Result<Self> {
        Self::with_base(API, token, repo)
    }

    pub fn with_base(base: &str, token: SecretValue, repo: Option<String>) -> Result<Self> {
        if let Some(r) = &repo {
            safe_repo(r)?;
        }
        Ok(Self {
            http: HttpClient::new(base, Auth::Bearer(token))?,
            repo,
            rate: Arc::new(Mutex::new(RateState::default())),
        })
    }

    pub fn rate(&self) -> RateState {
        *self.rate.lock().expect("verrou quota")
    }

    fn repo(&self) -> Result<&str> {
        self.repo
            .as_deref()
            .ok_or_else(|| CoreError::Validation("aucun dépôt associé".into()))
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
        extra: &[(&str, &str)],
    ) -> Result<Response> {
        let mut headers = vec![
            ("accept", "application/vnd.github+json"),
            ("x-github-api-version", "2022-11-28"),
        ];
        headers.extend_from_slice(extra);
        let r = self.http.send(method, path, body, &headers).await?;
        self.rate.lock().expect("verrou quota").update(&r);
        Ok(r)
    }

    /// Identité et portées du jeton.
    pub async fn whoami(&self) -> Result<(String, Option<Vec<String>>, Option<String>)> {
        let r = self.call(Method::GET, "/user", None, &[]).await?.ok()?;
        let login = r.json::<serde_json::Value>()?["login"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let scopes = r.header("x-oauth-scopes").map(|s| {
            s.split(',')
                .map(|x| x.trim().to_owned())
                .filter(|x| !x.is_empty())
                .collect()
        });
        let exp = r
            .header("github-authentication-token-expiration")
            .map(str::to_owned);
        Ok((login, scopes, exp))
    }

    pub async fn list_repos(&self) -> Result<Vec<Repo>> {
        self.call(
            Method::GET,
            "/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member",
            None,
            &[],
        )
        .await?
        .ok()?
        .json()
    }

    pub async fn get_repo(&self, full_name: &str) -> Result<Option<Repo>> {
        let (o, n) = safe_repo(full_name)?;
        let r = self
            .call(Method::GET, &format!("/repos/{o}/{n}"), None, &[])
            .await?;
        if r.status.as_u16() == 404 {
            return Ok(None);
        }
        r.ok()?.json().map(Some)
    }

    /// Crée un dépôt pour l'utilisateur (privé par défaut).
    pub async fn create_repo(&self, name: &str, private: bool, description: &str) -> Result<Repo> {
        safe_segment(name)?;
        self.call(
            Method::POST,
            "/user/repos",
            Some(&serde_json::json!({
                "name": name, "private": private, "auto_init": true, "description": description
            })),
            &[],
        )
        .await?
        .ok()?
        .json()
    }

    // ---------- Contenus (sync chiffrée, liste de révocation) ----------

    fn contents_path(&self, repo: &str, path: &str) -> Result<String> {
        let (o, n) = safe_repo(repo)?;
        if path.split('/').any(|s| s.is_empty() || s == "..") {
            return Err(CoreError::Validation("chemin invalide".into()));
        }
        Ok(format!("/repos/{o}/{n}/contents/{path}"))
    }

    pub async fn get_file(&self, repo: &str, path: &str) -> Result<Option<FileContent>> {
        let r = self
            .call(Method::GET, &self.contents_path(repo, path)?, None, &[])
            .await?;
        if r.status.as_u16() == 404 {
            return Ok(None);
        }
        let v: serde_json::Value = r.ok()?.json()?;
        let b64: String = v["content"]
            .as_str()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        Ok(Some(FileContent {
            sha: v["sha"].as_str().unwrap_or_default().to_owned(),
            bytes: data_encoding::BASE64
                .decode(b64.as_bytes())
                .map_err(|_| CoreError::External("contenu base64 invalide".into()))?,
        }))
    }

    /// Crée ou met à jour un fichier (`sha` requis pour une mise à jour).
    pub async fn put_file(
        &self,
        repo: &str,
        path: &str,
        bytes: &[u8],
        message: &str,
        sha: Option<&str>,
    ) -> Result<String> {
        let mut body = serde_json::json!({
            "message": message,
            "content": data_encoding::BASE64.encode(bytes),
        });
        if let Some(s) = sha {
            body["sha"] = s.into();
        }
        let v: serde_json::Value = self
            .call(
                Method::PUT,
                &self.contents_path(repo, path)?,
                Some(&body),
                &[],
            )
            .await?
            .ok()?
            .json()?;
        Ok(v["content"]["sha"].as_str().unwrap_or_default().to_owned())
    }

    /// Liste un répertoire (noms de fichiers). Répertoire absent → vide.
    pub async fn list_dir(&self, repo: &str, path: &str) -> Result<Vec<String>> {
        let r = self
            .call(Method::GET, &self.contents_path(repo, path)?, None, &[])
            .await?;
        if r.status.as_u16() == 404 {
            return Ok(vec![]);
        }
        let v: Vec<serde_json::Value> = r.ok()?.json()?;
        Ok(v.iter()
            .filter_map(|e| e["name"].as_str().map(str::to_owned))
            .collect())
    }

    // ---------- Suivi (ETag) ----------

    /// Requête conditionnelle : un 304 ne consomme pas de quota.
    pub async fn poll(&self, path: &str, etag: Option<&str>) -> Result<Polled> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if self.rate().should_back_off(now) {
            return Err(CoreError::External(
                "quota GitHub presque épuisé : suivi suspendu".into(),
            ));
        }
        let extra: Vec<(&str, &str)> = etag.map(|e| vec![("if-none-match", e)]).unwrap_or_default();
        let r = self.call(Method::GET, path, None, &extra).await?;
        if r.status.as_u16() == 304 {
            return Ok(Polled::NotModified);
        }
        let etag = r.header("etag").map(str::to_owned);
        let body = r.ok()?.json()?;
        Ok(Polled::Modified { etag, body })
    }

    /// Chemins suivis pour un dépôt.
    pub fn watch_paths(repo: &str) -> Result<Vec<(&'static str, String)>> {
        let (o, n) = safe_repo(repo)?;
        Ok(vec![
            ("commit", format!("/repos/{o}/{n}/commits?per_page=10")),
            ("branch", format!("/repos/{o}/{n}/branches?per_page=30")),
            (
                "pull_request",
                format!("/repos/{o}/{n}/pulls?state=open&per_page=20"),
            ),
            (
                "workflow_run",
                format!("/repos/{o}/{n}/actions/runs?per_page=10"),
            ),
            ("release", format!("/repos/{o}/{n}/releases?per_page=5")),
        ])
    }
}

// ---------- Device Flow (sur github.com, sans jeton) ----------

/// Client OAuth Device Flow. Le *Client ID* (non secret) est fourni par l'utilisateur.
pub struct DeviceFlow {
    http: HttpClient,
    client_id: String,
}

impl DeviceFlow {
    pub fn new(client_id: &str) -> Result<Self> {
        Self::with_base(WEB, client_id)
    }

    pub fn with_base(base: &str, client_id: &str) -> Result<Self> {
        let ok = !client_id.is_empty()
            && client_id.len() <= 64
            && client_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_');
        if !ok {
            return Err(CoreError::Validation("Client ID invalide".into()));
        }
        Ok(Self {
            http: HttpClient::new(base, Auth::None)?,
            client_id: client_id.to_owned(),
        })
    }

    pub async fn start(&self, scopes: &str) -> Result<DeviceCode> {
        let url = self.http.url("/login/device/code")?;
        self.http
            .send_url(
                Method::POST,
                url,
                Some(Body::Form(vec![
                    ("client_id".into(), self.client_id.clone()),
                    ("scope".into(), scopes.to_owned()),
                ])),
                &[("accept", "application/json")],
            )
            .await?
            .ok()?
            .json()
    }

    pub async fn poll(&self, device_code: &str) -> Result<DevicePoll> {
        let url = self.http.url("/login/oauth/access_token")?;
        let v: serde_json::Value = self
            .http
            .send_url(
                Method::POST,
                url,
                Some(Body::Form(vec![
                    ("client_id".into(), self.client_id.clone()),
                    ("device_code".into(), device_code.to_owned()),
                    (
                        "grant_type".into(),
                        "urn:ietf:params:oauth:grant-type:device_code".into(),
                    ),
                ])),
                &[("accept", "application/json")],
            )
            .await?
            .ok()?
            .json()?;
        if let Some(t) = v["access_token"].as_str() {
            return Ok(DevicePoll::Token(SecretValue::new(t)));
        }
        match v["error"].as_str() {
            Some("authorization_pending") => Ok(DevicePoll::Pending),
            Some("slow_down") => Ok(DevicePoll::SlowDown),
            Some("expired_token") => Err(CoreError::External("code expiré, recommencez".into())),
            Some("access_denied") => Err(CoreError::External("autorisation refusée".into())),
            _ => Err(CoreError::External("réponse Device Flow inattendue".into())),
        }
    }
}

#[async_trait]
impl Connector for GitHub {
    fn provider(&self) -> Provider {
        Provider::Github
    }

    fn required_permissions(&self) -> Vec<PermissionSpec> {
        vec![
            PermissionSpec::read("metadata", "Lister vos dépôts et identifier votre compte"),
            PermissionSpec::read("contents", "Lire commits, branches et releases des dépôts suivis"),
            PermissionSpec::read("actions", "Afficher le statut des GitHub Actions"),
            PermissionSpec::read("pull_requests", "Afficher les pull requests ouvertes"),
            PermissionSpec::write(
                "contents",
                "Synchronisation chiffrée (dépôt control-center-sync), tags/releases, liste de révocation",
            ),
            PermissionSpec::write("actions", "Déclencher un workflow (optionnel)"),
            PermissionSpec::write("administration", "Créer le dépôt privé de synchronisation (une seule fois)"),
        ]
    }

    async fn test(&self) -> Result<TestReport> {
        let started = self.whoami().await;
        let (login, scopes, exp) = match started {
            Ok(v) => v,
            Err(e) => {
                return Ok(TestReport {
                    ok: false,
                    warnings: vec![e.to_string()],
                    ..TestReport::default()
                })
            }
        };
        let mut report = TestReport {
            ok: true,
            identity: Some(login),
            expires_at: exp,
            can_read: true,
            ..TestReport::default()
        };
        match scopes {
            Some(scopes) => {
                report.warnings.push(
                    "Jeton « classic » : préférez un jeton fine-grained limité aux dépôts choisis."
                        .into(),
                );
                let has = |s: &str| scopes.iter().any(|x| x == s);
                report.can_write = has("repo") || has("public_repo");
                for s in &scopes {
                    report.permissions.push(DetectedPermission {
                        scope: s.clone(),
                        access: if s.starts_with("read:") {
                            Access::Read
                        } else {
                            Access::Write
                        },
                        granted: true,
                    });
                }
                let dangerous: Vec<&String> = scopes
                    .iter()
                    .filter(|s| DANGEROUS_SCOPES.contains(&s.as_str()))
                    .collect();
                if !dangerous.is_empty() {
                    report.too_powerful = true;
                    report.warnings.push(format!(
                        "Clé trop puissante : portées inutiles {dangerous:?}. Recommandé : fine-grained, \
                         Contents R/W + Metadata R + Actions R sur les seuls dépôts suivis."
                    ));
                }
            }
            None => {
                // Fine-grained : pas d'en-tête de portées ; on sonde l'accès réel au dépôt.
                if let Some(repo) = &self.repo {
                    let (o, n) = safe_repo(repo)?;
                    let r = self
                        .call(Method::GET, &format!("/repos/{o}/{n}"), None, &[])
                        .await?;
                    if r.status.is_success() {
                        let v: serde_json::Value = r.json()?;
                        let perms = &v["permissions"];
                        report.can_write = perms["push"].as_bool().unwrap_or(false);
                        report.permissions.push(DetectedPermission {
                            scope: format!("{repo}:contents"),
                            access: Access::Read,
                            granted: perms["pull"].as_bool().unwrap_or(true),
                        });
                        report.permissions.push(DetectedPermission {
                            scope: format!("{repo}:contents"),
                            access: Access::Write,
                            granted: report.can_write,
                        });
                        if perms["admin"].as_bool().unwrap_or(false) {
                            report.warnings.push(
                                "Le jeton a les droits d'administration sur ce dépôt : non nécessaire.".into(),
                            );
                            report.too_powerful = true;
                        }
                    } else {
                        report.can_read = false;
                        report
                            .warnings
                            .push(format!("Pas d'accès au dépôt {repo}."));
                    }
                }
            }
        }
        if report.expires_at.is_none() {
            report
                .warnings
                .push("Le jeton n'expire jamais : définissez une expiration.".into());
        }
        Ok(report)
    }

    async fn health(&self) -> Result<Health> {
        let t = Instant::now();
        let r = self.call(Method::GET, "/rate_limit", None, &[]).await;
        let latency_ms = u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX);
        Ok(match r {
            Ok(r) if r.status.is_success() => Health {
                online: true,
                latency_ms,
                detail: format!("quota {}/{}", self.rate().remaining, self.rate().limit),
            },
            Ok(r) => Health {
                online: false,
                latency_ms,
                detail: format!("HTTP {}", r.status),
            },
            Err(e) => Health {
                online: false,
                latency_ms,
                detail: e.to_string(),
            },
        })
    }

    async fn list_resources(&self) -> Result<Vec<Resource>> {
        let repo = self.repo()?;
        let (o, n) = safe_repo(repo)?;
        let runs: serde_json::Value = self
            .call(
                Method::GET,
                &format!("/repos/{o}/{n}/actions/runs?per_page=10"),
                None,
                &[],
            )
            .await?
            .ok()?
            .json()?;
        Ok(runs["workflow_runs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|r| Resource {
                        id: r["id"].to_string(),
                        kind: "workflow_run".into(),
                        name: r["name"].as_str().unwrap_or_default().into(),
                        url: r["html_url"].as_str().map(str::to_owned),
                        status: r["conclusion"]
                            .as_str()
                            .or_else(|| r["status"].as_str())
                            .map(str::to_owned),
                        created_at: r["created_at"].as_str().map(str::to_owned),
                        extra: serde_json::json!({"branch": r["head_branch"], "sha": r["head_sha"]}),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "workflow_dispatch",
                "Déclencher un workflow",
                Action::Release,
                "Lance un workflow GitHub Actions (workflow, ref)",
            ),
            ActionSpec::new(
                "create_release",
                "Créer un tag et une release",
                Action::Release,
                "Crée le tag et la release (tag, target, name, body)",
            ),
            ActionSpec::new(
                "rerun_workflow",
                "Relancer une exécution",
                Action::Redeploy,
                "Relance une exécution GitHub Actions (run_id)",
            ),
        ]
    }

    async fn execute(&self, action: &str, params: &serde_json::Value) -> Result<serde_json::Value> {
        let repo = self.repo()?;
        let (o, n) = safe_repo(repo)?;
        match action {
            "workflow_dispatch" => {
                let wf = safe_segment(param(params, "workflow")?)?;
                let git_ref = param(params, "ref")?;
                self.call(
                    Method::POST,
                    &format!("/repos/{o}/{n}/actions/workflows/{wf}/dispatches"),
                    Some(&serde_json::json!({"ref": git_ref})),
                    &[],
                )
                .await?
                .ok()?;
                Ok(serde_json::json!({"dispatched": true}))
            }
            "create_release" => {
                let tag = param(params, "tag")?;
                let body = serde_json::json!({
                    "tag_name": tag,
                    "target_commitish": params.get("target").and_then(|v| v.as_str()).unwrap_or("main"),
                    "name": params.get("name").and_then(|v| v.as_str()).unwrap_or(tag),
                    "body": params.get("body").and_then(|v| v.as_str()).unwrap_or(""),
                    "draft": false, "prerelease": false
                });
                let v: serde_json::Value = self
                    .call(
                        Method::POST,
                        &format!("/repos/{o}/{n}/releases"),
                        Some(&body),
                        &[],
                    )
                    .await?
                    .ok()?
                    .json()?;
                Ok(serde_json::json!({"url": v["html_url"], "id": v["id"]}))
            }
            "rerun_workflow" => {
                let run = safe_segment(param(params, "run_id")?)?;
                self.call(
                    Method::POST,
                    &format!("/repos/{o}/{n}/actions/runs/{run}/rerun"),
                    None,
                    &[],
                )
                .await?
                .ok()?;
                Ok(serde_json::json!({"rerun": true}))
            }
            _ => Err(CoreError::Validation(format!("action inconnue : {action}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn gh(s: &MockServer, repo: Option<&str>) -> GitHub {
        GitHub::with_base(
            &s.uri(),
            SecretValue::new("ghp_test"),
            repo.map(str::to_owned),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn classic_token_too_powerful() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .and(header("authorization", "Bearer ghp_test"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"login": "chamsoudine"}))
                    .insert_header("x-oauth-scopes", "repo, delete_repo, read:org")
                    .insert_header("x-ratelimit-limit", "5000")
                    .insert_header("x-ratelimit-remaining", "4999")
                    .insert_header("x-ratelimit-reset", "1900000000"),
            )
            .mount(&s)
            .await;
        let g = gh(&s, None);
        let r = g.test().await.unwrap();
        assert!(r.ok && r.too_powerful && r.can_write && r.can_read);
        assert_eq!(r.identity.as_deref(), Some("chamsoudine"));
        assert_eq!(r.permissions.len(), 3);
        assert!(r
            .permissions
            .iter()
            .any(|p| p.scope == "read:org" && p.access == Access::Read));
        assert_eq!(g.rate().remaining, 4999);
        assert_eq!(g.provider(), Provider::Github);
        assert!(!g.required_permissions().is_empty());
    }

    #[tokio::test]
    async fn fine_grained_token_repo_probe() {
        let s = MockServer::start().await;
        Mock::given(path("/user"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"login": "me"}))
                    .insert_header(
                        "github-authentication-token-expiration",
                        "2027-01-01 00:00:00 UTC",
                    ),
            )
            .mount(&s)
            .await;
        Mock::given(path("/repos/me/app"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "full_name":"me/app","private":true,"html_url":"https://github.com/me/app",
                "permissions":{"pull":true,"push":true,"admin":false}
            })))
            .mount(&s)
            .await;
        let r = gh(&s, Some("me/app")).test().await.unwrap();
        assert!(r.ok && r.can_write && !r.too_powerful);
        assert!(r.expires_at.is_some());
        assert_eq!(r.permissions.len(), 2);
    }

    #[tokio::test]
    async fn invalid_token_reports_failure() {
        let s = MockServer::start().await;
        Mock::given(path("/user"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&s)
            .await;
        let r = gh(&s, None).test().await.unwrap();
        assert!(!r.ok);
        assert!(r.warnings[0].contains("authentification"));
    }

    #[tokio::test]
    async fn repos_and_contents() {
        let s = MockServer::start().await;
        let repo = serde_json::json!({"full_name":"me/control-center-sync","private":true,"html_url":"u","default_branch":"main","pushed_at":null});
        Mock::given(method("GET"))
            .and(path("/user/repos"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([repo])))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/user/repos"))
            .and(body_string_contains("\"private\":true"))
            .respond_with(ResponseTemplate::new(201).set_body_json(repo.clone()))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/me/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/me/control-center-sync/contents/a/b.bin"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"sha":"abc","content":"aGVs\nbG8="})),
            )
            .mount(&s)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/me/control-center-sync/contents/a/c.bin"))
            .and(body_string_contains("aGVsbG8="))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"content":{"sha":"def"}})),
            )
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/me/control-center-sync/contents/a"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"name":"b.bin"},{"name":"c.bin"}])),
            )
            .mount(&s)
            .await;
        let g = gh(&s, None);
        assert_eq!(g.list_repos().await.unwrap().len(), 1);
        assert!(
            g.create_repo("control-center-sync", true, "sync")
                .await
                .unwrap()
                .private
        );
        assert!(g.create_repo("bad/name", true, "").await.is_err());
        assert!(g.get_repo("me/missing").await.unwrap().is_none());
        let f = g
            .get_file("me/control-center-sync", "a/b.bin")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(f.bytes, b"hello");
        assert_eq!(f.sha, "abc");
        assert!(g
            .get_file("me/control-center-sync", "a/zz")
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            g.put_file("me/control-center-sync", "a/c.bin", b"hello", "m", None)
                .await
                .unwrap(),
            "def"
        );
        assert_eq!(
            g.list_dir("me/control-center-sync", "a").await.unwrap(),
            vec!["b.bin", "c.bin"]
        );
        assert!(g
            .list_dir("me/control-center-sync", "none")
            .await
            .unwrap()
            .is_empty());
        assert!(g.get_file("me/control-center-sync", "../x").await.is_err());
    }

    #[tokio::test]
    async fn etag_304() {
        let s = MockServer::start().await;
        Mock::given(path("/repos/me/app/commits"))
            .and(header("if-none-match", "\"v1\""))
            .respond_with(ResponseTemplate::new(304))
            .mount(&s)
            .await;
        Mock::given(path("/repos/me/app/commits"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"sha":"1"}]))
                    .insert_header("etag", "\"v1\""),
            )
            .mount(&s)
            .await;
        let g = gh(&s, Some("me/app"));
        let Polled::Modified { etag, body } = g.poll("/repos/me/app/commits", None).await.unwrap()
        else {
            panic!("attendu Modified")
        };
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        assert_eq!(body[0]["sha"], "1");
        assert_eq!(
            g.poll("/repos/me/app/commits", etag.as_deref())
                .await
                .unwrap(),
            Polled::NotModified
        );
        assert_eq!(GitHub::watch_paths("me/app").unwrap().len(), 5);
        assert!(GitHub::watch_paths("bad").is_err());
    }

    #[tokio::test]
    async fn rate_limit_backoff() {
        let s = MockServer::start().await;
        Mock::given(path("/user"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"login":"me"}))
                    .insert_header("x-ratelimit-limit", "5000")
                    .insert_header("x-ratelimit-remaining", "10")
                    .insert_header("x-ratelimit-reset", "99999999999"),
            )
            .mount(&s)
            .await;
        let g = gh(&s, Some("me/app"));
        g.whoami().await.unwrap();
        assert!(g.rate().should_back_off(1_900_000_000));
        assert!(
            g.poll("/repos/me/app/commits", None).await.is_err(),
            "polling suspendu"
        );

        let st = RateState {
            limit: 5000,
            remaining: 4100,
            reset: 1000 + 3600,
        };
        // 4000 requêtes de budget, 5 par cycle → 800 cycles sur 3600 s → max(4.5, 60) = 60 s
        assert_eq!(st.recommended_interval_secs(1000, 5), 60);
        let low = RateState {
            limit: 5000,
            remaining: 130,
            reset: 1000 + 3600,
        };
        // 30 de budget, 5 par cycle → 6 cycles → 600 s
        assert_eq!(low.recommended_interval_secs(1000, 5), 600);
        let none = RateState {
            limit: 5000,
            remaining: 50,
            reset: 1000 + 3600,
        };
        assert_eq!(none.recommended_interval_secs(1000, 5), 3600);
        assert_eq!(RateState::default().recommended_interval_secs(0, 5), 60);
        assert!(!RateState::default().should_back_off(0));
    }

    #[tokio::test]
    async fn actions_and_resources() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/me/app/actions/workflows/ci.yml/dispatches"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/me/app/releases"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"id":1,"html_url":"u"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/me/app/actions/runs/42/rerun"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/me/app/actions/runs"))
            .and(query_param("per_page", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"workflow_runs":[
                {"id":42,"name":"CI","status":"completed","conclusion":"success","html_url":"u","created_at":"t","head_branch":"main","head_sha":"abc"}
            ]})))
            .mount(&s)
            .await;
        Mock::given(path("/rate_limit"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        let g = gh(&s, Some("me/app"));
        assert_eq!(g.actions().len(), 3);
        g.execute(
            "workflow_dispatch",
            &serde_json::json!({"workflow":"ci.yml","ref":"main"}),
        )
        .await
        .unwrap();
        g.execute("create_release", &serde_json::json!({"tag":"v1.0.0"}))
            .await
            .unwrap();
        g.execute("rerun_workflow", &serde_json::json!({"run_id":"42"}))
            .await
            .unwrap();
        assert!(g.execute("nope", &serde_json::json!({})).await.is_err());
        assert!(g
            .execute(
                "workflow_dispatch",
                &serde_json::json!({"workflow":"../x","ref":"m"})
            )
            .await
            .is_err());
        let res = g.list_resources().await.unwrap();
        assert_eq!(res[0].status.as_deref(), Some("success"));
        assert!(g.health().await.unwrap().online);
        assert!(g
            .preview("create_release", &serde_json::json!({"tag":"v1"}))
            .unwrap()
            .contains("release"));
        assert!(g.preview("nope", &serde_json::json!({})).is_err());
        let no_repo = gh(&s, None);
        assert!(no_repo.list_resources().await.is_err());
        assert!(GitHub::with_base(&s.uri(), SecretValue::new("x"), Some("bad".into())).is_err());
    }

    #[tokio::test]
    async fn device_flow() {
        let s = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/login/device/code"))
            .and(body_string_contains("client_id=Iv1.abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "device_code":"dc","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5
            })))
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("device_code=pending"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"error":"authorization_pending"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("device_code=slow"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"error":"slow_down"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("device_code=ok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"access_token":"gho_x"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("device_code=denied"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"error":"access_denied"})),
            )
            .mount(&s)
            .await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(body_string_contains("device_code=exp"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"error":"expired_token"})),
            )
            .mount(&s)
            .await;
        assert!(DeviceFlow::with_base(&s.uri(), "bad id!").is_err());
        assert!(DeviceFlow::new("Iv1.abc").is_ok());
        let f = DeviceFlow::with_base(&s.uri(), "Iv1.abc").unwrap();
        assert_eq!(f.start("repo").await.unwrap().user_code, "ABCD-1234");
        assert_eq!(f.poll("pending").await.unwrap(), DevicePoll::Pending);
        assert_eq!(f.poll("slow").await.unwrap(), DevicePoll::SlowDown);
        assert!(
            matches!(f.poll("ok").await.unwrap(), DevicePoll::Token(t) if t.expose() == "gho_x")
        );
        assert!(f.poll("denied").await.is_err());
        assert!(f.poll("exp").await.is_err());
        assert!(f.poll("other").await.is_err());
    }
}

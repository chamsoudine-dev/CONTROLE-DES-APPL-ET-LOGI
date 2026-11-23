//! Suivi périodique d'un dépôt GitHub : requêtes conditionnelles, conversion en événements,
//! détection des « push depuis ailleurs » et du statut de déploiement associé.
use crate::github::{GitHub, Polled};
use cc_core::tracking::{RepoEvent, Upserted};
use cc_core::Result;

/// Convertit une réponse GitHub en événements.
pub fn parse(kind: &str, repo: &str, body: &serde_json::Value) -> Vec<RepoEvent> {
    let s = |v: &serde_json::Value| v.as_str().map(str::to_owned);
    let arr = match kind {
        "workflow_run" => body["workflow_runs"].as_array(),
        _ => body.as_array(),
    };
    let Some(arr) = arr else { return vec![] };
    arr.iter()
        .filter_map(|x| {
            Some(match kind {
                "commit" => RepoEvent {
                    id: format!("commit:{}", x["sha"].as_str()?),
                    repo: repo.into(),
                    kind: kind.into(),
                    title: x["commit"]["message"]
                        .as_str()
                        .unwrap_or_default()
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .into(),
                    author: s(&x["author"]["login"]).or_else(|| s(&x["commit"]["author"]["name"])),
                    ref_name: Some(x["sha"].as_str()?.chars().take(7).collect()),
                    status: None,
                    url: s(&x["html_url"]),
                    occurred_at: s(&x["commit"]["author"]["date"]).unwrap_or_default(),
                },
                "branch" => RepoEvent {
                    id: format!(
                        "branch:{}:{}",
                        x["name"].as_str()?,
                        x["commit"]["sha"].as_str().unwrap_or_default()
                    ),
                    repo: repo.into(),
                    kind: kind.into(),
                    title: x["name"].as_str()?.into(),
                    author: None,
                    ref_name: s(&x["name"]),
                    status: None,
                    url: None,
                    occurred_at: cc_core::now_rfc3339(),
                },
                "pull_request" => RepoEvent {
                    id: format!("pr:{}", x["number"].as_i64()?),
                    repo: repo.into(),
                    kind: kind.into(),
                    title: format!(
                        "#{} {}",
                        x["number"],
                        x["title"].as_str().unwrap_or_default()
                    ),
                    author: s(&x["user"]["login"]),
                    ref_name: s(&x["head"]["ref"]),
                    status: s(&x["state"]),
                    url: s(&x["html_url"]),
                    occurred_at: s(&x["updated_at"]).unwrap_or_default(),
                },
                "workflow_run" => RepoEvent {
                    id: format!("run:{}", x["id"].as_i64()?),
                    repo: repo.into(),
                    kind: kind.into(),
                    title: format!(
                        "{} ({})",
                        x["name"].as_str().unwrap_or_default(),
                        x["head_sha"]
                            .as_str()
                            .unwrap_or_default()
                            .chars()
                            .take(7)
                            .collect::<String>()
                    ),
                    author: s(&x["actor"]["login"]),
                    ref_name: s(&x["head_branch"]),
                    status: s(&x["conclusion"]).or_else(|| s(&x["status"])),
                    url: s(&x["html_url"]),
                    occurred_at: s(&x["created_at"]).unwrap_or_default(),
                },
                "release" => RepoEvent {
                    id: format!("release:{}", x["id"].as_i64()?),
                    repo: repo.into(),
                    kind: kind.into(),
                    title: x["name"]
                        .as_str()
                        .filter(|n| !n.is_empty())
                        .or(x["tag_name"].as_str())
                        .unwrap_or_default()
                        .into(),
                    author: s(&x["author"]["login"]),
                    ref_name: s(&x["tag_name"]),
                    status: Some(if x["draft"].as_bool() == Some(true) {
                        "draft".into()
                    } else {
                        "published".into()
                    }),
                    url: s(&x["html_url"]),
                    occurred_at: s(&x["published_at"])
                        .or_else(|| s(&x["created_at"]))
                        .unwrap_or_default(),
                },
                _ => return None,
            })
        })
        .collect()
}

/// Résultat d'une interrogation : événements + ETag à mémoriser par chemin.
pub struct PollOutcome {
    pub events: Vec<RepoEvent>,
    pub etags: Vec<(String, Option<String>)>,
    pub requests: u32,
    pub not_modified: u32,
}

/// Interroge tous les chemins suivis d'un dépôt. `etag_of` donne l'ETag connu de chaque URL.
pub async fn poll_repo(
    gh: &GitHub,
    repo: &str,
    etag_of: impl Fn(&str) -> Option<String>,
) -> Result<PollOutcome> {
    let mut out = PollOutcome {
        events: vec![],
        etags: vec![],
        requests: 0,
        not_modified: 0,
    };
    for (kind, path) in GitHub::watch_paths(repo)? {
        out.requests += 1;
        match gh.poll(&path, etag_of(&path).as_deref()).await? {
            Polled::NotModified => out.not_modified += 1,
            Polled::Modified { etag, body } => {
                out.events.extend(parse(kind, repo, &body));
                out.etags.push((path, etag));
            }
        }
    }
    Ok(out)
}

/// Notification à afficher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    pub title: String,
    pub body: String,
    pub event_id: String,
}

/// Notifications : nouveaux commits (push depuis ailleurs) et fin d'exécution CI/déploiement.
pub fn notices(app_name: &str, u: &Upserted) -> Vec<Notice> {
    if u.first_sync {
        return vec![];
    }
    let mut v = Vec::new();
    for e in u.new.iter().filter(|e| e.kind == "commit") {
        v.push(Notice {
            title: format!("{app_name} : nouveau push"),
            body: format!(
                "{} — {} ({})",
                e.ref_name.clone().unwrap_or_default(),
                e.title,
                e.author.clone().unwrap_or_else(|| "?".into())
            ),
            event_id: e.id.clone(),
        });
    }
    for e in u
        .new
        .iter()
        .chain(&u.status_changed)
        .filter(|e| e.kind == "workflow_run")
    {
        let st = e.status.as_deref().unwrap_or("");
        let icon = match st {
            "success" => "✓",
            "failure" | "timed_out" | "startup_failure" => "✗",
            "cancelled" => "⊘",
            _ => continue, // en cours : pas de notification
        };
        v.push(Notice {
            title: format!("{app_name} : déploiement / CI {icon}"),
            body: format!("{} — {st}", e.title),
            event_id: e.id.clone(),
        });
    }
    for e in u.new.iter().filter(|e| e.kind == "release") {
        v.push(Notice {
            title: format!("{app_name} : release"),
            body: e.title.clone(),
            event_id: e.id.clone(),
        });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_core::secrets::SecretValue;
    use wiremock::matchers::{header, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn commits() -> serde_json::Value {
        serde_json::json!([{"sha":"abcdef123","html_url":"u","author":{"login":"me"},"commit":{"message":"fix: bug\n\ndétails","author":{"name":"Me","date":"2026-01-02T10:00:00Z"}}}])
    }

    #[test]
    fn parse_all_kinds() {
        assert_eq!(parse("commit", "me/app", &commits())[0].title, "fix: bug");
        assert_eq!(
            parse(
                "branch",
                "me/app",
                &serde_json::json!([{"name":"main","commit":{"sha":"1"}}])
            )[0]
            .id,
            "branch:main:1"
        );
        assert_eq!(parse("pull_request", "me/app", &serde_json::json!([{"number":3,"title":"T","state":"open","user":{"login":"x"},"head":{"ref":"f"},"updated_at":"t"}]))[0].title, "#3 T");
        let runs = parse(
            "workflow_run",
            "me/app",
            &serde_json::json!({"workflow_runs":[{"id":9,"name":"CI","head_sha":"abcdef1234","status":"completed","conclusion":"success","created_at":"t"}]}),
        );
        assert_eq!(runs[0].status.as_deref(), Some("success"));
        assert_eq!(
            parse(
                "release",
                "me/app",
                &serde_json::json!([{"id":1,"tag_name":"v1","name":"","draft":false}])
            )[0]
            .title,
            "v1"
        );
        assert!(parse("unknown", "me/app", &serde_json::json!([{}])).is_empty());
        assert!(parse("commit", "me/app", &serde_json::json!({})).is_empty());
    }

    #[test]
    fn notices_for_push_and_ci() {
        let commit = parse("commit", "me/app", &commits()).remove(0);
        let mut run = parse("workflow_run", "me/app", &serde_json::json!({"workflow_runs":[{"id":9,"name":"Deploy","head_sha":"abcdef1","status":"in_progress","created_at":"t"}]})).remove(0);
        let u = Upserted {
            new: vec![commit.clone(), run.clone()],
            status_changed: vec![],
            first_sync: false,
        };
        let n = notices("Boutique", &u);
        assert_eq!(n.len(), 1, "CI en cours : pas encore de notification");
        assert!(n[0].title.contains("nouveau push") && n[0].body.contains("fix: bug"));
        run.status = Some("failure".into());
        let n2 = notices(
            "Boutique",
            &Upserted {
                new: vec![],
                status_changed: vec![run],
                first_sync: false,
            },
        );
        assert!(n2[0].title.contains('✗'));
        assert!(notices(
            "B",
            &Upserted {
                new: vec![commit],
                status_changed: vec![],
                first_sync: true
            }
        )
        .is_empty());
    }

    #[tokio::test]
    async fn push_appears_and_quota_respected_with_etags() {
        let s = MockServer::start().await;
        let rl = |t: ResponseTemplate| {
            t.insert_header("x-ratelimit-limit", "5000")
                .insert_header("x-ratelimit-remaining", "4990")
                .insert_header("x-ratelimit-reset", "99999999999")
        };
        for p in ["branches", "pulls", "releases"] {
            Mock::given(path(format!("/repos/me/app/{p}")))
                .respond_with(rl(ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([]))
                    .insert_header("etag", format!("\"{p}\""))))
                .mount(&s)
                .await;
        }
        Mock::given(path("/repos/me/app/actions/runs"))
            .respond_with(rl(ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"workflow_runs":[]}))
                .insert_header("etag", "\"runs\"")))
            .mount(&s)
            .await;
        Mock::given(path("/repos/me/app/commits"))
            .and(header("if-none-match", "\"c1\""))
            .respond_with(rl(ResponseTemplate::new(304)))
            .mount(&s)
            .await;
        Mock::given(path("/repos/me/app/commits"))
            .respond_with(rl(ResponseTemplate::new(200)
                .set_body_json(commits())
                .insert_header("etag", "\"c1\"")))
            .mount(&s)
            .await;
        let gh = GitHub::with_base(&s.uri(), SecretValue::new("t"), Some("me/app".into())).unwrap();
        let first = poll_repo(&gh, "me/app", |_| None).await.unwrap();
        assert_eq!(first.requests, 5);
        assert!(
            first.events.iter().any(|e| e.id == "commit:abcdef123"),
            "le push apparaît"
        );
        let known: std::collections::HashMap<String, String> = first
            .etags
            .iter()
            .filter_map(|(k, v)| v.clone().map(|v| (k.clone(), v)))
            .collect();
        let second = poll_repo(&gh, "me/app", |p| known.get(p).cloned())
            .await
            .unwrap();
        assert_eq!(
            second.not_modified, 1,
            "commits : 304 (ne consomme pas de quota)"
        );
        assert!(!gh.rate().should_back_off(1_900_000_000));
    }
}

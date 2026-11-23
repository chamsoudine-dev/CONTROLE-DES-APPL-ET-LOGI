//! Critère Phase 2 : ajout d'une appli complète de bout en bout (avec fournisseur simulé).
use cc_connectors::exec;
use cc_connectors::registry;
use cc_connectors::Provider;
use cc_core::apps::{self, NewApp};
use cc_core::crypto::KdfParams;
use cc_core::policy::{AccessMode, Confirmations};
use cc_core::secrets::{MemorySecretStore, SecretStore, SecretValue};
use cc_core::vault::{Vault, VaultConfig};
use cc_core::{envvars, keys};
use std::sync::Arc;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PASS: &str = "correct horse battery staple";

#[tokio::test]
async fn add_complete_app_then_push_env_and_redeploy() {
    // Fournisseur simulé.
    let s = MockServer::start().await;
    Mock::given(path("/v2/user"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"user":{"username":"me"}})),
        )
        .mount(&s)
        .await;
    Mock::given(path("/v5/user/tokens/current")).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"token":{"scopes":[{"type":"team"}],"expiresAt": 1_900_000_000_000_i64}}))).mount(&s).await;
    Mock::given(method("GET"))
        .and(path("/v9/projects/prj_shop"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"prj_shop"})),
        )
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/v6/deployments"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"deployments":[{"uid":"dpl_1","state":"READY"}]}),
            ),
        )
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/v10/projects/prj_shop/env"))
        .and(body_string_contains("SUPER_SECRET_DB_URL"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
        .expect(1)
        .mount(&s)
        .await;
    Mock::given(method("POST"))
        .and(path("/v13/deployments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id":"dpl_2"})))
        .expect(1)
        .mount(&s)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let mut vault = Vault::open(VaultConfig {
        dir: dir.path().to_path_buf(),
        kdf: KdfParams::INSECURE_FAST_FOR_TESTS,
        os_store: Some(Arc::new(MemorySecretStore::default()) as Arc<dyn SecretStore>),
    })
    .unwrap();
    vault.setup("Chamsoudine", PASS).unwrap();
    vault.reauth(PASS, None).unwrap();
    let conf = Confirmations::default();

    // 1. Assistant : identité + droits.
    let s_ = vault.session().unwrap();
    let app = apps::create(
        s_,
        &NewApp {
            name: "Boutique".into(),
            description: "Boutique en ligne".into(),
            icon: Some("🛒".into()),
            urls: vec!["https://boutique.example.com".into()],
            repo: Some("me/boutique".into()),
            access_mode: Some(AccessMode::ReadWrite),
            licensing_enabled: true,
        },
    )
    .unwrap();

    // 2. Service d'hébergement : test AVANT enregistrement.
    let config =
        serde_json::json!({"project_id":"prj_shop","team_id":"team_1","api_base": s.uri()});
    let report = registry::build(
        Provider::Vercel,
        &config,
        SecretValue::new("vercel-token-xyz"),
    )
    .await
    .unwrap()
    .test()
    .await
    .unwrap();
    assert!(
        report.ok && report.can_write && !report.too_powerful,
        "{report:?}"
    );

    // 3. Enregistrement : secret dans le trousseau, connecteur, permissions détectées.
    let secret = keys::add(
        s_,
        Some(&app.id),
        "production",
        "vercel",
        "VERCEL_KEY",
        &SecretValue::new("vercel-token-xyz"),
        None,
    )
    .unwrap();
    let row =
        apps::add_connector(s_, &app.id, "vercel", "hosting", &config, Some(&secret.id)).unwrap();
    apps::record_test(
        s_,
        &row.id,
        report.ok,
        &serde_json::to_value(&report.permissions).unwrap(),
    )
    .unwrap();

    // 4. Variables : une en clair, une liée à un secret.
    let db = keys::add(
        s_,
        Some(&app.id),
        "production",
        "custom",
        "DB_URL",
        &SecretValue::new("SUPER_SECRET_DB_URL"),
        None,
    )
    .unwrap();
    envvars::set(
        s_,
        &app.id,
        "production",
        "PUBLIC_URL",
        Some("https://boutique.example.com"),
        None,
    )
    .unwrap();
    envvars::set(
        s_,
        &app.id,
        "production",
        "DATABASE_URL",
        None,
        Some(&db.id),
    )
    .unwrap();

    // 5. Envoi des variables : aperçu sans valeurs → confirmation → exécution.
    let conn = registry::build(
        Provider::Vercel,
        &row.config,
        keys::use_value(s_, &secret.id).unwrap(),
    )
    .await
    .unwrap();
    let prep = exec::prepare(
        s_,
        &conf,
        &app.id,
        &row.id,
        conn.as_ref(),
        "env_push",
        &serde_json::json!({"environment":"production","keys":["DATABASE_URL","PUBLIC_URL"]}),
    )
    .unwrap();
    assert!(
        !prep.preview.contains("SUPER_SECRET"),
        "l'aperçu ne révèle aucune valeur"
    );
    let pending = exec::authorize_execution(s_, &conf, &prep.token).unwrap();
    let vars: serde_json::Map<String, serde_json::Value> =
        envvars::resolved(s_, &app.id, "production")
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.expose().into()))
            .collect();
    let r = conn
        .execute(
            "env_push",
            &serde_json::json!({"environment":"production","vars": vars}),
        )
        .await;
    exec::record(s_, &pending, &r).unwrap();
    r.unwrap();
    envvars::mark_pushed(s_, &app.id, "production").unwrap();
    assert!(envvars::list(s_, &app.id, "production")
        .unwrap()
        .iter()
        .all(|v| v.pushed));

    // 6. Redéploiement.
    let prep = exec::prepare(
        s_,
        &conf,
        &app.id,
        &row.id,
        conn.as_ref(),
        "redeploy",
        &serde_json::json!({"deployment_id":"dpl_1"}),
    )
    .unwrap();
    let pending = exec::authorize_execution(s_, &conf, &prep.token).unwrap();
    let r = conn.execute("redeploy", &pending.params).await;
    exec::record(s_, &pending, &r).unwrap();
    assert_eq!(r.unwrap()["id"], "dpl_2");

    // 7. Audit complet et intègre.
    let c = s_.conn.lock();
    let chain = cc_core::audit::verify_chain(&c).unwrap();
    assert!(chain.entries >= 8);
    let execs: i64 = c
        .query_row(
            "SELECT count(*) FROM audit_logs WHERE action='action.execute' AND outcome='ok'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(execs, 2);
}

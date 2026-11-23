//! Exécution des actions d'écriture : politique (mode ∧ matrice ∧ rôle) → aperçu + jeton de
//! confirmation à usage unique → ré-authentification si destructif → exécution → audit.
use crate::types::Connector;
use cc_core::apps;
use cc_core::policy::{Action, Confirmations, PendingAction, Role};
use cc_core::vault::Session;
use cc_core::{CoreError, Result};
use serde::Serialize;

/// Aperçu renvoyé à l'interface avant confirmation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Prepared {
    pub token: String,
    pub preview: String,
    pub policy_action: Action,
    pub destructive: bool,
}

/// Étape 1 : vérifie les droits et prépare l'aperçu. Aucune écriture n'a lieu.
pub fn prepare(
    s: &Session,
    conf: &Confirmations,
    app_id: &str,
    connector_id: &str,
    conn: &dyn Connector,
    action: &str,
    params: &serde_json::Value,
) -> Result<Prepared> {
    let spec = conn
        .actions()
        .into_iter()
        .find(|a| a.id == action)
        .ok_or_else(|| CoreError::Validation(format!("action inconnue : {action}")))?;
    apps::authorize(s, app_id, spec.policy_action, Role::Owner)?;
    let preview = conn.preview(action, params)?;
    let token = conf.issue(
        app_id,
        spec.policy_action,
        &format!("{connector_id}:{action}"),
        params.clone(),
        preview.clone(),
    );
    s.audit(
        "action.prepare",
        app_id,
        &serde_json::json!({"op": format!("{connector_id}:{action}")}),
        "ok",
    )?;
    Ok(Prepared {
        token,
        preview,
        policy_action: spec.policy_action,
        destructive: spec.policy_action.is_destructive(),
    })
}

/// Étape 2 : consomme le jeton après re-vérification des droits (et de la ré-auth si destructif).
/// Renvoie `(connector_id, action, params)` à exécuter.
pub fn authorize_execution(
    s: &Session,
    conf: &Confirmations,
    token: &str,
) -> Result<PendingAction> {
    // Vérifier la ré-auth AVANT de consommer le jeton (pour pouvoir réessayer).
    if conf.peek(token).is_some_and(Action::is_destructive) {
        s.ensure_recent_reauth()?;
    }
    let p = conf.consume(token)?;
    // Les droits ont pu changer entre l'aperçu et la confirmation.
    apps::authorize(s, &p.app_id, p.action, Role::Owner)?;
    Ok(p)
}

/// Découpe `PendingAction::op` en (connector_id, action).
pub fn split_op(p: &PendingAction) -> Result<(&str, &str)> {
    p.op.split_once(':')
        .ok_or_else(|| CoreError::Integrity("opération invalide".into()))
}

/// Étape 3 : inscrit le résultat au journal.
pub fn record(s: &Session, p: &PendingAction, result: &Result<serde_json::Value>) -> Result<()> {
    match result {
        Ok(_) => s.audit(
            "action.execute",
            &p.app_id,
            &serde_json::json!({"op": p.op, "preview": p.preview}),
            "ok",
        ),
        Err(e) => s.audit(
            "action.execute",
            &p.app_id,
            &serde_json::json!({"op": p.op, "error": e.to_string()}),
            "error",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ActionSpec, Health, PermissionSpec, Provider, Resource, TestReport};
    use async_trait::async_trait;
    use cc_core::apps::NewApp;
    use cc_core::crypto::KdfParams;
    use cc_core::policy::AccessMode;
    use cc_core::secrets::{MemorySecretStore, SecretStore};
    use cc_core::vault::{Vault, VaultConfig};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const PASS: &str = "correct horse battery staple";

    #[derive(Default)]
    struct Mock {
        writes: AtomicUsize,
    }

    #[async_trait]
    impl Connector for Mock {
        fn provider(&self) -> Provider {
            Provider::Custom
        }
        fn required_permissions(&self) -> Vec<PermissionSpec> {
            vec![]
        }
        async fn test(&self) -> Result<TestReport> {
            Ok(TestReport::default())
        }
        async fn health(&self) -> Result<Health> {
            Ok(Health {
                online: true,
                latency_ms: 0,
                detail: String::new(),
            })
        }
        async fn list_resources(&self) -> Result<Vec<Resource>> {
            Ok(vec![])
        }
        fn actions(&self) -> Vec<ActionSpec> {
            vec![
                ActionSpec::new("redeploy", "Redéployer", Action::Redeploy, ""),
                ActionSpec::new("rollback", "Rollback", Action::Rollback, ""),
            ]
        }
        async fn execute(&self, _a: &str, _p: &serde_json::Value) -> Result<serde_json::Value> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::json!({}))
        }
    }

    fn vault(dir: &std::path::Path) -> Vault {
        let mut v = Vault::open(VaultConfig {
            dir: dir.to_path_buf(),
            kdf: KdfParams::INSECURE_FAST_FOR_TESTS,
            os_store: Some(Arc::new(MemorySecretStore::default()) as Arc<dyn SecretStore>),
        })
        .unwrap();
        v.setup("Test", PASS).unwrap();
        v
    }

    async fn run(
        s: &Session,
        conf: &Confirmations,
        conn: &Mock,
        token: &str,
    ) -> Result<serde_json::Value> {
        let p = authorize_execution(s, conf, token)?;
        let (_, action) = split_op(&p)?;
        let r = conn.execute(action, &p.params).await;
        record(s, &p, &r)?;
        r
    }

    #[tokio::test]
    async fn read_only_app_cannot_execute_any_write() {
        let d = tempfile::tempdir().unwrap();
        let v = vault(d.path());
        let s = v.session().unwrap();
        let conf = Confirmations::default();
        let m = Mock::default();
        let app = apps::create(
            s,
            &NewApp {
                name: "RO".into(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(app.access_mode, AccessMode::ReadOnly);
        for a in ["redeploy", "rollback"] {
            assert!(matches!(
                prepare(s, &conf, &app.id, "c1", &m, a, &serde_json::json!({})),
                Err(CoreError::Forbidden(_))
            ));
        }
        assert!(run(s, &conf, &m, "forged-token").await.is_err());
        assert_eq!(
            m.writes.load(Ordering::SeqCst),
            0,
            "aucune écriture exécutée"
        );
    }

    #[tokio::test]
    async fn write_flow_confirmation_and_reauth() {
        let d = tempfile::tempdir().unwrap();
        let mut v = vault(d.path());
        let conf = Confirmations::default();
        let m = Mock::default();
        let app = apps::create(
            v.session().unwrap(),
            &NewApp {
                name: "RW".into(),
                access_mode: Some(AccessMode::ReadWrite),
                ..Default::default()
            },
        )
        .unwrap();
        let s = v.session().unwrap();
        // Écriture simple : aperçu → confirmation → exécution, jeton à usage unique.
        let p = prepare(
            s,
            &conf,
            &app.id,
            "c1",
            &m,
            "redeploy",
            &serde_json::json!({"x":1}),
        )
        .unwrap();
        assert!(!p.destructive && p.preview.contains("Redéployer"));
        run(s, &conf, &m, &p.token).await.unwrap();
        assert!(
            run(s, &conf, &m, &p.token).await.is_err(),
            "jeton déjà utilisé"
        );
        assert_eq!(m.writes.load(Ordering::SeqCst), 1);
        // Destructif : ré-auth requise, le jeton n'est pas brûlé.
        let p2 = prepare(
            s,
            &conf,
            &app.id,
            "c1",
            &m,
            "rollback",
            &serde_json::json!({}),
        )
        .unwrap();
        assert!(p2.destructive);
        assert!(matches!(
            run(s, &conf, &m, &p2.token).await,
            Err(CoreError::ReauthRequired)
        ));
        v.reauth(PASS, None).unwrap();
        let s = v.session().unwrap();
        run(s, &conf, &m, &p2.token).await.unwrap();
        assert_eq!(m.writes.load(Ordering::SeqCst), 2);
        // Droits retirés entre l'aperçu et la confirmation → refus.
        let p3 = prepare(
            s,
            &conf,
            &app.id,
            "c1",
            &m,
            "redeploy",
            &serde_json::json!({}),
        )
        .unwrap();
        apps::set_mode(s, &app.id, AccessMode::ReadOnly).unwrap();
        assert!(matches!(
            run(s, &conf, &m, &p3.token).await,
            Err(CoreError::Forbidden(_))
        ));
        assert_eq!(m.writes.load(Ordering::SeqCst), 2);
        assert!(prepare(
            s,
            &conf,
            &app.id,
            "c1",
            &m,
            "unknown",
            &serde_json::json!({})
        )
        .is_err());
        let audited: i64 = s
            .conn
            .lock()
            .query_row(
                "SELECT count(*) FROM audit_logs WHERE action='action.execute'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(audited, 2);
    }
}

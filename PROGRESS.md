# PROGRESS

| Phase | État | Détail |
|-------|------|--------|
| 0 — Conception | ✅ fait | docs/threat-model.md, architecture.md, schema.md, wireframes.md ; monorepo compilé ; CI |
| 1 — Socle sécurisé | ✅ fait | assistant 5 étapes, vault Argon2id+SQLCipher, TOTP, PIN (5 essais), auto-lock, ré-auth, audit chaîné append-only, capabilities minimales + CSP stricte, test no_plaintext_on_disk, e2e premier lancement (scripts/e2e-first-launch.sh) |
| 2 — Coffre & connecteurs | ✅ fait | trait Connector + 8 connecteurs (GitHub, Vercel, Supabase, Firebase, Netlify, Cloudflare Pages, Cloudinary, personnalisé) testés avec mocks ; coffre Environnements & Clés (révéler/tester/rotation/supprimer), variables + diff + envoi, .ccvault ; assistant Ajouter une appli ; mode + matrice + rôles ; exécuteur aperçu→confirmation→ré-auth→audit ; tests `read_only_app_cannot_execute_any_write`, `add_complete_app_then_push_env_and_redeploy` |
| 3 — Suivi code & médias | ✅ fait | poller GitHub ETag (304 sans quota) + intervalle adaptatif au quota + réserve ; événements commits/branches/PR/Actions/releases ; notifications natives (push depuis ailleurs, fin de CI/déploiement) ; actions redéployer/rollback/workflow/tag+release/variables ; tableau de bord (santé URL, dernier déploiement, alertes, quota) ; fiche appli (dépôt, déploiements, médias, droits) ; médias WebP vers Supabase/Firebase/Cloudinary ; tests `push_appears_and_quota_respected_with_etags`, `rate_limit_backoff`, redeploy/rollback mockés |
| 4 — Sync chiffrée | ✅ fait | HLC, capture par enregistrement, lots XChaCha20-Poly1305 (AAD époque/appareil/lot) dans `epochs/<n>/events/<appareil>/`, fusion LWW + conflits concurrents + écran de résolution, appairage par QR + phrase, révocation + rotation d'époque ; sync auto (boucle de fond) ; tests `two_instances_converge_after_cross_modifications`, `ciphertext_unreadable_and_tamper_detected`, `concurrent_edit_conflict_is_detected_and_resolvable` ; LAN : conçu, non activé (docs/sync.md) |
| 5 — Licences | ⏳ à faire | |
| 6 — Distribution & mobile | ⏳ à faire | |
| 7 — Qualité & livraison | ⏳ à faire | |

## Reprise
Reprendre à la première phase non « fait ». Commandes de vérification : `cargo test --workspace`, `cd app && npm run lint && npm run typecheck && npm test && npm run build`.

# PROGRESS

| Phase | État | Détail |
|-------|------|--------|
| 0 — Conception | ✅ fait | docs/threat-model.md, architecture.md, schema.md, wireframes.md ; monorepo compilé ; CI |
| 1 — Socle sécurisé | ✅ fait | assistant 5 étapes, vault Argon2id+SQLCipher, TOTP, PIN (5 essais), auto-lock, ré-auth, audit chaîné append-only, capabilities minimales + CSP stricte, test no_plaintext_on_disk, e2e premier lancement (scripts/e2e-first-launch.sh) |
| 2 — Coffre & connecteurs | ✅ fait | trait Connector + 8 connecteurs (GitHub, Vercel, Supabase, Firebase, Netlify, Cloudflare Pages, Cloudinary, personnalisé) testés avec mocks ; coffre Environnements & Clés (révéler/tester/rotation/supprimer), variables + diff + envoi, .ccvault ; assistant Ajouter une appli ; mode + matrice + rôles ; exécuteur aperçu→confirmation→ré-auth→audit ; tests `read_only_app_cannot_execute_any_write`, `add_complete_app_then_push_env_and_redeploy` |
| 3 — Suivi code & médias | ⏳ à faire | |
| 4 — Sync chiffrée | ⏳ à faire | |
| 5 — Licences | ⏳ à faire | |
| 6 — Distribution & mobile | ⏳ à faire | |
| 7 — Qualité & livraison | ⏳ à faire | |

## Reprise
Reprendre à la première phase non « fait ». Commandes de vérification : `cargo test --workspace`, `cd app && npm run lint && npm run typecheck && npm test && npm run build`.

# PROGRESS

| Phase | État | Détail |
|-------|------|--------|
| 0 — Conception | ✅ fait | docs/threat-model.md, architecture.md, schema.md, wireframes.md ; monorepo compilé ; CI |
| 1 — Socle sécurisé | ✅ fait | assistant 5 étapes, vault Argon2id+SQLCipher, TOTP, PIN (5 essais), auto-lock, ré-auth, audit chaîné append-only, capabilities minimales + CSP stricte, test no_plaintext_on_disk, e2e premier lancement (scripts/e2e-first-launch.sh) |
| 2 — Coffre & connecteurs | ⏳ à faire | |
| 3 — Suivi code & médias | ⏳ à faire | |
| 4 — Sync chiffrée | ⏳ à faire | |
| 5 — Licences | ⏳ à faire | |
| 6 — Distribution & mobile | ⏳ à faire | |
| 7 — Qualité & livraison | ⏳ à faire | |

## Reprise
Reprendre à la première phase non « fait ». Commandes de vérification : `cargo test --workspace`, `cd app && npm run lint && npm run typecheck && npm test && npm run build`.

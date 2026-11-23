# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versionnage [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Phase 1 — Socle sécurisé
- Coffre : phrase secrète Argon2id (64 Mio, t=3) → clé SQLCipher ; vérificateur HMAC ; changement de phrase (rekey).
- 2FA TOTP (QR code), PIN enveloppant la clé maîtresse dans le trousseau (5 essais), verrouillage auto, ré-authentification (2 min).
- Trousseau OS (`keyring`) avec repli chiffré XChaCha20-Poly1305 en base.
- Journal d'audit append-only chaîné SHA-256 (triggers SQL + vérification).
- Connexion GitHub (jeton fine-grained ou Device Flow), création/sélection du dépôt privé de sync.
- Paire Ed25519 de signature des licences (kid PASERK), sauvegarde chiffrée.
- Tauri : commandes en liste blanche (`commands.txt` ↔ capability), CSP stricte, `withGlobalTauri=false`.
- Tests : crypto, audit, vault, absence de secret en clair sur disque, e2e premier lancement.

### Phase 0 — Conception
- Modèle de menaces STRIDE, architecture (Mermaid), schéma SQLite, maquettes.
- Monorepo Cargo + application Tauri 2 / React / TypeScript strict / Tailwind.
- CI minimale (fmt, clippy, tests, lint/typecheck/build de l'interface).

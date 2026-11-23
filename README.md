# Control Center

Application **native** (Windows, macOS, Linux, Android ; iOS préparé) pour piloter vos
applications, leurs clés API, leurs déploiements et leurs licences — **local-first** : votre appareil
est le serveur, tout est chiffré localement, et GitHub est le seul service externe obligatoire
(distribution, mises à jour, synchronisation chiffrée, suivi des dépôts).

> Aucune clé n'est nécessaire pour compiler : tout se configure **dans l'application** après installation.

## Fonctionnalités

- **Coffre chiffré** : SQLCipher + Argon2id, trousseau du système, 2FA TOTP, PIN, verrouillage auto,
  ré-authentification pour les actions sensibles, journal d'audit chaîné.
- **Environnements & Clés** : secrets par appli/environnement (masqués, révéler/tester/rotation),
  variables d'environnement avec aperçu des différences et envoi vers l'hébergeur, export `.ccvault`.
- **Connecteurs** : GitHub, Vercel, Supabase, Firebase, Netlify, Cloudflare Pages, Cloudinary,
  API personnalisée ; test réel des permissions, alerte « clé trop puissante ».
- **Droits** : lecture seule / lecture-écriture / désactivé + matrice par action, aperçu et
  confirmation de toute écriture.
- **Suivi** : commits, PR, GitHub Actions, releases (ETag, quota), notifications de push,
  redéploiement, rollback, workflows, tags/releases, santé des applis, médias WebP.
- **Synchronisation** multi-appareils chiffrée de bout en bout via un dépôt privé.
- **Licences** hors ligne (PASETO v4.public / Ed25519), révocation signée publiée, SDK TS/Rust/Go.
- **Mises à jour signées** (refus de toute mise à jour non signée).

## Structure

| Dossier | Contenu |
|---------|---------|
| `app/` | Application Tauri 2 (`src-tauri` = cœur Rust, `src` = interface React/TS/Tailwind) |
| `crates/core` | Stockage SQLCipher, crypto, coffre, droits, audit, sync, licences |
| `crates/connectors` | Trait `Connector`, fournisseurs, client HTTP durci, suivi GitHub, médias |
| `crates/license` | Licences PASETO v4.public, listes de révocation, vérificateur client |
| `sdk/ts`, `sdk/rust`, `sdk/go` | SDK de vérification de licence hors ligne |
| `fuzz/` | Cibles `cargo-fuzz` |
| `docs/` | Menaces, architecture, schéma, maquettes, guides, distribution, incidents, revue de sécurité |

## Démarrage rapide (développeurs)

```bash
# Linux : sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev libdbus-1-dev patchelf
cd app && npm ci && npm run tauri dev
cargo test --workspace
```

Documentation : [guide utilisateur](docs/user-guide.md) · [guide développeur](docs/developer-guide.md) ·
[distribution](docs/distribution.md) · [modèle de menaces](docs/threat-model.md) ·
[revue de sécurité](docs/security-review.md) · [incidents](docs/incident-response.md) ·
[synchronisation](docs/sync.md) · [rapport final](docs/final-report.md).

## Sécurité

Signalement de vulnérabilité : voir `SECURITY.md`.

## Licence

MIT OR Apache-2.0.

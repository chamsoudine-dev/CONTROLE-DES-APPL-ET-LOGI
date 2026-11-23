# Control Center

Application **native** (Windows, macOS, Linux, Android ; iOS en préparation) pour piloter
vos applications, leurs clés API, leurs déploiements et leurs licences — **local-first** :
votre appareil est le serveur, tout est chiffré localement, et GitHub est le seul service
externe obligatoire (distribution, mises à jour, synchronisation chiffrée, suivi des dépôts).

> Aucune clé n'est nécessaire pour compiler : tout se configure **dans l'application** après installation.

## Structure

| Dossier | Contenu |
|---------|---------|
| `app/` | Application Tauri 2 (`src-tauri` = cœur Rust, `src` = interface React/TS/Tailwind) |
| `crates/core` | Stockage SQLCipher, crypto, vault, politique d'accès, audit, sync |
| `crates/connectors` | Trait `Connector` + GitHub, Vercel, Supabase, Firebase, Netlify, Cloudflare Pages, Cloudinary, personnalisé |
| `crates/license` | Licences PASETO v4.public / Ed25519, listes de révocation signées |
| `sdk/ts`, `sdk/rust`, `sdk/go` | SDK de vérification de licence hors ligne |
| `docs/` | Modèle de menaces, architecture, schéma, guides |

## Démarrage rapide (développeurs)

```bash
# Prérequis Linux : libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev patchelf
cd app && npm ci && npm run tauri dev
cargo test --workspace         # tests Rust
```

Voir `docs/developer-guide.md` et `docs/user-guide.md`.

## Sécurité

Modèle de menaces : `docs/threat-model.md`. Signalement de vulnérabilité : `SECURITY.md`.

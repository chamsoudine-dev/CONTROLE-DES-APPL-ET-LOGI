# PLAN — Control Center

## Plan global

| Phase | Objet | Branche | Tag |
|-------|-------|---------|-----|
| 0 | Conception : menaces, architecture, schéma, maquettes, monorepo, CI | `phase-0` | `phase-0` |
| 1 | Socle sécurisé : assistant, SQLCipher, vault, auto-lock, audit chaîné, durcissement Tauri | `phase-1` | `phase-1` |
| 2 | Coffre Environnements & Clés, connecteurs, ajout d'applis, droits | `phase-2` | `phase-2` |
| 3 | Suivi GitHub (ETag/quota), notifications, actions de déploiement, tableau de bord, médias | `phase-3` | `phase-3` |
| 4 | Synchronisation chiffrée multi-appareils (HLC, conflits, appairage) | `phase-4` | `phase-4` |
| 5 | Licences hors ligne (PASETO), révocation signée, SDK TS/Rust/Go | `phase-5` | `phase-5` |
| 6 | Distribution, mises à jour signées, Android/iOS | `phase-6` | `phase-6` |
| 7 | Qualité finale, fuzzing, CI bloquante, docs, v1.0.0 | `phase-7` | `phase-7`, `v1.0.0` |

## Décisions d'architecture (et justification)

### D1 — Tauri 2 stable (2.x), pas Tauri 3 alpha
Tauri 3 n'existe qu'en alpha au moment du développement ; la cible demandée est Tauri 2, stable et supportée (mobile inclus).

### D2 — SQLCipher via `rusqlite` + `bundled-sqlcipher-vendored-openssl`
Compile SQLCipher et OpenSSL statiquement : même comportement sur Windows/macOS/Linux/Android, aucune dépendance système. Clé brute de 256 bits (`PRAGMA key = "x'…'"`) dérivée par Argon2id → pas de second KDF PBKDF2 inutile côté SQLCipher.

### D3 — Dérivation de clés
- Argon2id (m = 64 Mio, t = 3, p = 1 ; paramètres réduits *uniquement* sous `cfg(test)`).
- Sel aléatoire 16 octets stocké dans `vault.json` (non secret) avec un **vérificateur** = HMAC-SHA256(clé, "cc-verifier") pour distinguer « mauvaise phrase » de « base corrompue ».
- Sous-clés par HMAC-SHA256 (séparation de domaines) : `db`, `secrets-fallback`, `fingerprint`. La clé de **synchronisation** utilise son propre sel (stocké dans le dépôt) pour que tous les appareils dérivent la même clé à partir de la même phrase secrète, indépendamment de leur sel local.

### D4 — Secrets : trait `SecretStore`
- Desktop : trousseau OS via la crate `keyring` (Credential Manager / Keychain / Secret Service).
- Mobile (Android/iOS) et environnements sans trousseau : `EncryptedDbSecretStore` — valeur chiffrée XChaCha20-Poly1305 (sous-clé dérivée de la phrase secrète) **dans** la base SQLCipher (double chiffrement). Un plugin natif Android Keystore / iOS Keychain est prévu (voir limites) ; le trait permet de le brancher sans toucher au reste.
- Tests : `MemorySecretStore`.
- Le type `SecretValue` (zeroize à la destruction) n'implémente ni `Debug` en clair ni `Serialize`.

### D5 — PIN et biométrie
PIN : la clé de base est enveloppée (XChaCha20-Poly1305) par Argon2id(PIN, sel) et stockée dans le trousseau ; 5 échecs → l'enveloppe est détruite, la phrase secrète redevient obligatoire. Biométrie : via `tauri-plugin-biometric` sur mobile (déverrouille l'enveloppe) ; sur desktop, non proposée en v1 (documenté).

### D6 — 2FA TOTP
`totp-rs` (RFC 6238, SHA-1, 6 chiffres, 30 s, tolérance ±1 pas). Exigée au déverrouillage par phrase secrète et pour la ré-authentification (révéler, supprimer). Limite documentée dans le modèle de menaces.

### D7 — GitHub d'abord
Deux méthodes : jeton fine-grained (recommandé, aucune configuration) ou OAuth Device Flow (nécessite un *Client ID* d'OAuth App, non secret, saisi dans l'app). Aucun identifiant n'est codé en dur.

### D8 — Connecteurs compilés, HTTP durci
`reqwest` + rustls (TLS 1.2 minimum, 1.3 privilégié), délai 20 s, aucune redirection suivie hors de l'hôte d'origine, réponses limitées à 10 Mio, URL de base injectable (tests avec `wiremock`). Pas de plugins dynamiques (menace T4).

### D9 — Politique d'accès
Mode par appli (`read_only` / `read_write` / `disabled`) ∧ matrice par action ∧ rôle (owner/admin/viewer). Écriture = jeton de confirmation à usage unique issu de l'aperçu ; destructif = ré-authentification récente (< 2 min). Toute décision (autorisée ou refusée) est auditée.

### D10 — Audit
Table `audit_logs` append-only (triggers `RAISE(ABORT)`), `hash = SHA-256(prev_hash ‖ JSON canonique de l'entrée)`, vérification complète disponible dans Paramètres.

### D11 — Synchronisation
Événements par enregistrement, HLC (`<ms 13 chiffres>-<compteur 4>-<device>`), fusion LWW par enregistrement (ordre total HLC puis id appareil) → convergence garantie. Conflit = modification concurrente (le `base_hlc` de l'événement entrant ≠ version locale issue d'un autre appareil) : le gagnant LWW est appliqué automatiquement et le perdant est conservé dans `sync_conflicts` pour résolution manuelle. Fichiers chiffrés `events/<device>/<hlc>_<id>.ccev` (un fichier par événement → pas de conflit Git). AEAD avec données associées (version, époque, appareil, id). Révocation d'appareil = nouvelle époque (nouveau sel, nouvelle phrase secrète recommandée). La synchronisation LAN directe est **reportée** (option) — documentée.

### D12 — Licences
PASETO v4.public via `pasetors` (implémentation de référence listée par paseto.io) ; clés Ed25519 générées avec `ed25519-dalek` ; `kid` = PASERK `k4.pid` en pied de jeton. Clé lisible `XXXX-XXXX-XXXX-XXXX` = Base32 Crockford de HMAC-SHA256(clé dérivée, jti) tronqué — identifiant de support, ne remplace pas le jeton. Révocation : PASETO v4.public signé contenant `{seq, issued_at, revoked:[jti]}` publié dans un dépôt public ; SDK : anti-rollback (`seq` croissant), délai de grâce hors ligne (14 j par défaut).

### D13 — SDK TypeScript
`@noble/ed25519` + `@noble/hashes` (audités) ; seule la PAE PASETO (encodage, pas de crypto) est implémentée. Testé contre des jetons produits par la crate Rust.

### D14 — Mises à jour
`tauri-plugin-updater` : signature minisign obligatoire (comportement natif : refus si absente/invalide). La clé publique est injectée dans `tauri.conf.json` par la CI depuis la variable `TAURI_UPDATER_PUBKEY` ; la clé privée vit dans les GitHub Secrets (`TAURI_SIGNING_PRIVATE_KEY`). Aucune clé n'est dans le dépôt.

### D15 — Branches, tags et dépôt
Une branche par phase, fusionnée (merge `--no-ff`) dans `main`, tag `phase-N`. La branche de travail imposée par l'environnement (`claude/control-center-app-9anzfw`) suit `main`.

### D16 — Médias
Conversion WebP **sans perte** via la crate `image` (pur Rust, pas de libwebp C), redimensionnement max 2048 px ; choix « sans perte » pour éviter une dépendance C supplémentaire (compression avec perte = amélioration future).

### D17 — Monnaie par défaut
`XOF` (Mobile Money visé) ; modifiable par produit.

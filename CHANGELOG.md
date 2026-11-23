# Changelog

Format : [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versionnage [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Phase 5 — Licences sans serveur permanent
- Produits (perpétuelle, abonnement, essai), clients, ventes ; couche `PaymentProvider` (saisie manuelle ; Mobile Money et fournisseur international prévus).
- Licence = jeton PASETO v4.public signé Ed25519 (produit, client, dates, options, `kid`) + clé lisible `XXXX-XXXX-XXXX-XXXX`.
- Révocation : liste signée numérotée publiée automatiquement dans un dépôt GitHub public ; anti-rollback et délai de grâce hors ligne côté client.
- Prolongation, export CSV (protégé contre l'injection de formules).
- SDK TypeScript, Rust et Go + exemple d'intégration ; jeux de test partagés générés par la crate Rust.
- Fuzzing (cargo-fuzz) : licences, listes de révocation, import `.ccvault`, réponses d'API.
- Corrigé : la vérification des dates utilisait l'horloge système de `pasetors` au lieu de l'horloge injectée.

### Phase 4 — Synchronisation chiffrée
- Journal d'événements par enregistrement horodaté par HLC ; lots chiffrés XChaCha20-Poly1305 (clé Argon2id de la phrase secrète) poussés dans le dépôt privé.
- Fusion automatique (dernier écrivain gagnant) avec convergence garantie ; conflits concurrents conservés et résolubles manuellement.
- Ajout d'un appareil par QR code + phrase secrète ; révocation d'un appareil perdu et rotation de l'époque.
- Synchronisation automatique au déverrouillage et périodiquement.

### Phase 3 — Suivi du code, déploiements et médias
- Suivi GitHub périodique par requêtes conditionnelles (ETag), lecture des en-têtes de quota, réserve de 100 requêtes, intervalle adaptatif.
- Notifications natives : nouveau push (VS Code, autre machine…), fin de CI/déploiement, release.
- Actions : redéployer, rollback, déclencher un workflow, créer tag + release, relancer une exécution, envoyer les variables.
- Tableau de bord : santé des URL, dernier déploiement, alertes (clés expirées/trop puissantes, CI en échec), quota GitHub.
- Fiche appli : dépôt, déploiements, services, médias, droits.
- Médias : conversion WebP (redimensionnement ≤ 2048 px) puis envoi vers Supabase Storage, Firebase Storage ou Cloudinary ; URL copiable.

### Phase 2 — Coffre, applications et droits
- Trait `Connector` (test, permissions lecture/écriture, santé, ressources, actions) et connecteurs GitHub, Vercel, Supabase (gestion / service_role), Firebase (compte de service, IAM réel), Netlify, Cloudflare Pages, Cloudinary (upload signé), personnalisé (Bearer, en-tête, Basic, OAuth2 client credentials).
- Détection des clés trop puissantes et recommandations de portées minimales.
- Onglet Environnements & Clés : secrets par appli/environnement, révéler (ré-auth, masquage 30 s), tester, rotation guidée, suppression ; variables d'environnement, aperçu des différences, envoi vers l'hébergeur (valeurs résolues uniquement côté Rust).
- Import/export chiffré `.ccvault` (Argon2id + XChaCha20-Poly1305, AEAD vérifié avant parsing).
- Assistant « Ajouter une application », fiche appli, matrice de droits, rôles owner/admin/viewer.
- Exécuteur d'actions : politique → aperçu + jeton à usage unique → ré-auth si destructif → audit.

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

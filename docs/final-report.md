# Rapport final — Control Center v1.0.0

## Ce qui est fait

| Phase | Livré | Preuves |
|-------|-------|---------|
| 0 Conception | Modèle de menaces STRIDE (16 menaces), architecture Mermaid, schéma SQLite, maquettes, monorepo, CI | `docs/threat-model.md`, `docs/architecture.md`, `docs/schema.md`, `docs/wireframes.md` |
| 1 Socle sécurisé | Assistant 5 étapes, coffre Argon2id + SQLCipher, 2FA TOTP, PIN (5 essais), verrouillage auto, ré-authentification, trousseau OS + repli chiffré, audit chaîné append-only, connexion GitHub (jeton fine-grained / Device Flow), dépôt de sync privé, clé Ed25519 + sauvegarde chiffrée, capabilities minimales + CSP stricte | `no_plaintext_on_disk`, tests `vault`/`audit`/`crypto`, e2e réel `scripts/e2e-first-launch.sh` |
| 2 Coffre & droits | 8 connecteurs (GitHub, Vercel, Supabase, Firebase, Netlify, Cloudflare Pages, Cloudinary, personnalisé), permissions lecture/écriture, alerte « trop puissante », onglet Environnements & Clés, variables + diff + envoi, `.ccvault`, assistant d'ajout, mode + matrice + rôles, aperçu/confirmation/ré-auth/audit | `read_only_app_cannot_execute_any_write`, `add_complete_app_then_push_env_and_redeploy`, tests mockés par fournisseur |
| 3 Suivi & médias | Poller GitHub ETag + quota adaptatif, notifications de push et de fin de CI, redéploiement/rollback/workflow/release, tableau de bord santé/alertes/quota, fiche appli, médias WebP | `push_appears_and_quota_respected_with_etags`, `rate_limit_backoff`, `etag_304` |
| 4 Sync chiffrée | HLC, lots XChaCha20-Poly1305 (AAD), fusion LWW, conflits + écran de résolution, QR d'appairage, révocation + rotation d'époque, sync automatique | `two_instances_converge_after_cross_modifications`, `ciphertext_unreadable_and_tamper_detected`, `concurrent_edit_conflict_is_detected_and_resolvable` |
| 5 Licences | Produits/clients/ventes, PaymentProvider, PASETO v4.public + kid + clé lisible, prolongation, révocation publiée (dépôt public), CSV, SDK TS/Rust/Go + exemple, fuzzing | tests `license`, `licensing`, SDK TS (6) et Go, `cargo-fuzz` 4 cibles sans plantage |
| 6 Distribution & mobile | `release.yml` multi-OS + APK + archive source + `latest.json`, updater signé anti-rétrogradation, écran Mises à jour, docs certificats/coûts, projet Android, détection root/jailbreak, iOS préparé | `updater_is_safe`, `security::tests`, compilation Rust `aarch64-linux-android` réussie |
| 7 Qualité | 136 tests Rust + 8 tests UI + 6 tests SDK TS + tests Go ; couverture `/crates` **96,7 % des lignes** (93,1 % des régions) ; CI bloquante (fmt, clippy pedantic `-D warnings`, tests, e2e, cargo-audit, cargo-deny, npm audit, CodeQL, fuzzing, couverture ≥ 80 %), Dependabot ; revue de sécurité ; guides utilisateur/développeur ; plan d'incident | `docs/security-review.md`, `.github/workflows/*.yml` |

Corrections de sécurité issues de la revue : vérification des dates de licence avec l'horloge
injectée (bug `pasetors`), unicité des secrets globaux, **mise à jour de SQLite/SQLCipher**
(RUSTSEC-2026-0459 ; `cargo audit` : 0 vulnérabilité).

## Ce qui n'a pas pu être vérifié dans cet environnement (et pourquoi)

| Élément | État | Raison | Comment finaliser |
|---------|------|--------|-------------------|
| Push des branches/tags, release v1.0.0 publiée sur GitHub | ❌ non fait | L'App Claude GitHub n'a pas accès au dépôt (HTTP 403 à chaque push) | Installer l'App Claude sur `chamsoudine-dev/Logiciel-` (ou pousser soi-même `main`, `phase-*`, les tags), puis `git push origin v1.0.0` → `release.yml` produit la release |
| Installateurs Windows/macOS, AppImage | ⏳ CI uniquement | Nécessitent les runners Windows/macOS ; AppImage télécharge ses outils depuis github.com (bloqué ici) | Automatique au tag |
| APK Android | ⚠ partiel | La bibliothèque native Rust compile pour Android ; l'empaquetage Gradle échoue ici (Maven Central renvoie 429 via le proxy) | Job `android` de `release.yml` sur runner GitHub |
| Mise à jour v1.0.0 → v1.0.1 de bout en bout | ⏳ procédure documentée | Requiert deux releases réelles et la clé de signature (secret GitHub) | `docs/distribution.md` § « Tester la mise à jour » |
| Signature de code des installateurs | ⏳ documentée | Certificats payants à acquérir | `docs/distribution.md` (comptes et coûts) |
| CI GitHub verte | ⏳ | Non exécutée faute d'accès au dépôt ; toutes les étapes ont été exécutées localement avec succès (sauf CodeQL) | Premier push |

## Limites connues

- **Mobile** : Android Keystore / iOS Keychain et biométrie non branchés (secrets chiffrés en base,
  double chiffrement) ; interface mobile = mise en page adaptée, sans scanner de QR intégré.
- **Synchronisation** : fusion par enregistrement (pas par champ) ; pas de compaction (la rotation
  d'époque en tient lieu) ; métadonnées visibles par GitHub (nombre d'appareils, horodatages) ;
  synchronisation LAN non activée (conçue, `docs/sync.md`).
- **PIN** indisponible sans trousseau du système (Linux sans Secret Service, mobile).
- **Licences** : pas de limitation stricte des activations (option en ligne documentée).
- **Paiements** : saisie manuelle uniquement ; Mobile Money / fournisseur international prévus
  (trait `PaymentProvider`).
- **Connecteurs** : Cloudflare ne permet pas de vérifier le droit d'écriture sans effet de bord ;
  Netlify/Supabase (jeton personnel) ne proposent pas de portée réduite → toujours signalés
  « trop puissants ».
- **Médias** : WebP sans perte (pas de compression avec perte, pour éviter une dépendance C).
- **Rôles** : modélisés et appliqués, mais l'invitation d'un collaborateur n'est pas encore
  implémentée (un seul profil local).
- Avertissements `cargo audit` non bloquants : crates « unmaintained » transitives de Tauri/GTK
  (`glib` 0.18, `zvariant`…), sans correctif amont.

## Prochaines améliorations

1. Plugins natifs Android Keystore / iOS Keychain + biométrie (enveloppe de la clé maîtresse).
2. Invitations de collaborateurs (rôles admin/lecteur) avec clés par appareil et partage chiffré.
3. Synchronisation LAN (mDNS + TLS épinglé) et compaction des journaux.
4. Intégrations Mobile Money (Orange Money, Wave, MTN MoMo) et Stripe avec webhooks signés.
5. Service d'activation en ligne optionnel (`docs/licensing-online-option.md`).
6. Fusion au niveau du champ pour réduire les conflits.
7. WebP avec perte / AVIF, galerie de médias avec suppression.
8. Tests E2E multiplateformes via WebDriver (tauri-driver) dans la CI.

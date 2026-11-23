# Revue de sécurité finale (selon le modèle de menaces de la Phase 0)

Chaque menace de `docs/threat-model.md` → mesure appliquée → test automatisé qui la vérifie.
Tous les tests cités passent en CI (`cargo test --workspace`, SDK, e2e).

| # | Menace | Mesure appliquée (code) | Test(s) |
|---|--------|-------------------------|---------|
| T1 | Vol de l'appareil | Base SQLCipher, clé = sous-clé HMAC d'Argon2id(phrase, sel) (`vault.rs`, `db.rs`) ; secrets dans le trousseau OS ou chiffrés XChaCha20 en base (`secrets.rs`) ; verrouillage auto ; clé effacée (`Zeroizing`) | `no_plaintext_tests::no_plaintext_on_disk`, `db::tests::wrong_key_rejected_and_rekey`, `vault::tests::lock_wipes_session`, `vault::tests::autolock`, `scripts/e2e-first-launch.sh` |
| T2 | Force brute phrase / PIN | Argon2id 64 Mio/t=3 ; robustesse minimale (`check_passphrase_strength`) ; PIN : 5 essais puis destruction de l'enveloppe ; TOTP au déverrouillage et à la ré-auth | `vault::tests::pin_unlock_and_lockout`, `vault::tests::totp_required`, `vault::tests::passphrase_strength` |
| T3 | Fuite d'une clé API | Valeurs jamais renvoyées à l'UI (masque), révéler = ré-auth + audit + masquage 30 s ; `SecretValue` sans `Debug`/`Serialize` en clair ; envoi des variables résolu côté Rust uniquement ; alertes « trop puissante » | `secrets::tests::mask`, `secrets::tests::debug_redacted`, `keys::tests::crud_reveal_rotate_delete`, `add_app_end_to_end` (aperçu sans valeur), `envvars::tests::set_list_resolve_diff` |
| T4 | Faux connecteur | Connecteurs compilés ; HTTPS obligatoire (loopback toléré) ; aucune redirection inter-hôte ; surcharge d'URL limitée à localhost ; identifiants validés (`safe_segment`) ; réponses ≤ 10 Mio | `http::tests::rejects_http_and_credentials_in_url`, `http::tests::no_cross_host_redirect_and_errors`, `common::tests::base_override_only_loopback`, `custom::tests::rejects_http_and_bad_config`, `firebase::tests::config_validation` (token_uri épinglé) |
| T5 | Mise à jour piégée | Plugin updater (minisign) + `requireSignedVersion` ; pas de drapeau `dangerous*` ; clé publique injectée par la CI, clé privée en secret | `tests::updater_is_safe` (app) ; procédure manuelle `docs/distribution.md` |
| T6 | Falsification de licence | PASETO v4.public (Ed25519), en-tête unique accepté, `kid` PASERK, type de jeton vérifié, taille bornée ; fuzzing | `token::tests::tampered_rejected`, `swapped_kid_footer_rejected`, `other_headers_rejected`, `random_input_never_panics` ; SDK TS/Go (octet par octet) ; `fuzz/verify_license` |
| T7 | Contournement de la révocation | Liste signée numérotée (anti-rollback), délai de grâce borné, cache re-vérifié ; dates contrôlées avec l'horloge injectée | `checker::tests::*`, `licensing::tests::full_license_lifecycle`, SDK TS/Go `revocation`, `token::tests::dates_use_injected_clock_not_system_clock` |
| T8 | Attaque de la synchronisation | Lots XChaCha20-Poly1305 avec AAD (époque, appareil, lot) ; HLC émis par l'appareil vérifié ; rejeu idempotent ; appareil révoqué refusé ; rotation d'époque | `sync::tests::ciphertext_unreadable_and_tamper_detected`, `revoked_device_ignored_and_key_storage`, `epoch_rotation_rejects_old_batches`, `two_instances_converge_after_cross_modifications` |
| T9 | Injection dans l'interface | CSP stricte (`script-src 'self'`, pas d'`unsafe-eval`, `object-src 'none'`), `withGlobalTauri=false`, `freezePrototype`, ESLint `react/no-danger`, commandes en liste blanche + capability générée, entrées bornées côté Rust | `tests::csp_is_strict`, `tests::capabilities_match_commands`, `npm run lint` |
| T10 | Répudiation | Journal append-only (triggers), chaîne SHA-256 à champs préfixés, refus d'accès audités | `audit::tests::append_only`, `chain_detects_tamper`, `apps::tests::read_only_app_cannot_write` (refus audités) |
| T11 | Écriture non voulue | Mode ∧ matrice ∧ rôle ; jeton de confirmation à usage unique (TTL 2 min) ; ré-auth pour destructif ; re-vérification des droits à l'exécution | `exec::tests::read_only_app_cannot_execute_any_write`, `write_flow_confirmation_and_reauth`, `policy::tests::*` |
| T12 | Jeton GitHub volé | Dépôt de sync illisible sans phrase ; recommandation fine-grained + détection des portées dangereuses | `github::tests::classic_token_too_powerful`, `sync::tests::ciphertext_unreadable_and_tamper_detected` |
| T13 | DoS par quota | ETag (304 sans quota), réserve de 100 requêtes, intervalle adaptatif | `github::tests::etag_304`, `rate_limit_backoff`, `tracker::tests::push_appears_and_quota_respected_with_etags` |
| T14 | `.ccvault` malveillant | Taille max, paramètres KDF bornés, AEAD avant parsing, import en lecture seule sans écrasement | `ccvault::tests::tampered_or_hostile_files_rejected`, `export_import_roundtrip`, `fuzz/ccvault_import` |
| T15 | Appareil rooté / jailbreaké | Détection heuristique + bannière | `security::tests::*` |
| T16 | Chaîne d'approvisionnement | Lockfiles, cargo-audit, cargo-deny, npm audit, CodeQL, Dependabot | workflow `security.yml` |

## Constats de la revue et corrections

| Constat | Gravité | Correction |
|---------|---------|------------|
| `pasetors` contrôlait l'expiration avec l'horloge système même si désactivée : une licence expirée renvoyait « signature invalide », et la vérification à date injectée était impossible | Moyenne (fonctionnelle + diagnostic) | Vérification bas niveau de la signature puis contrôle des dates par le code (`token.rs`) + test de non-régression |
| Unicité des secrets globaux non garantie (NULL distincts dans la contrainte SQL) | Faible | Contrôle applicatif `ensure_unique` + test |
| `cargo audit` : SQLite embarqué vulnérable (RUSTSEC-2026-0459, `libsqlite3-sys` 0.30) | Élevée | Corrigé : `rusqlite` 0.43 → `libsqlite3-sys` 0.40 (SQLCipher 4.20 / SQLite 3.54.1) ; `cargo audit` : 0 vulnérabilité |
| Avertissements « unmaintained » (`glib` 0.18, `zvariant`, `proc-macro-error`) | Info | Dépendances transitives de Tauri/GTK/keyring ; suivies par Dependabot, sans correctif disponible en amont |

## Risques résiduels

Voir `docs/threat-model.md` §4, plus :
- Mobile : le trousseau natif (Android Keystore / iOS Keychain) n'est pas encore branché ;
  les secrets mobiles sont chiffrés en base (double chiffrement), la biométrie n'est pas proposée.
- Synchronisation : métadonnées visibles par GitHub (nombre d'appareils, horodatages, tailles).
- Les tests de bout en bout des mises à jour signées et des installateurs signés nécessitent des
  releases réelles (secrets de signature) : procédure décrite, non automatisable ici.

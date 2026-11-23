# Modèle de menaces (STRIDE) — Control Center

Version : 1.0 · Méthode : STRIDE par actif et par frontière de confiance.

## 1. Actifs à protéger

| ID | Actif | Où il vit | Sensibilité |
|----|-------|-----------|-------------|
| A1 | Clés API des fournisseurs (Vercel, Supabase, …) | Trousseau OS (desktop) / table chiffrée (mobile) | Critique |
| A2 | Jeton GitHub | Trousseau OS | Critique |
| A3 | Clé privée Ed25519 de signature des licences | Trousseau OS | Critique |
| A4 | Phrase secrète maîtresse | Mémoire uniquement (jamais stockée) | Critique |
| A5 | Base locale (applis, clients, ventes, licences, journaux) | SQLite chiffrée SQLCipher | Élevée |
| A6 | Journal d'audit | Table `audit_logs` (dans A5), chaînée par hash | Élevée |
| A7 | Événements de synchronisation | Dépôt GitHub privé, chiffrés XChaCha20-Poly1305 | Élevée |
| A8 | Liste de révocation des licences | Dépôt GitHub public, signée | Intégrité |
| A9 | Binaire de l'application et ses mises à jour | GitHub Releases | Intégrité |

## 2. Frontières de confiance

1. **Interface WebView ↔ cœur Rust** : l'interface est considérée comme *non fiable* (risque XSS). Elle n'a accès qu'à des commandes Tauri listées, validées, et ne reçoit jamais de secret en clair (sauf « Révéler » après ré-authentification, valeur effacée de l'écran après 30 s).
2. **Cœur Rust ↔ disque** : tout ce qui est persistant est chiffré (SQLCipher, trousseau).
3. **Cœur Rust ↔ Internet** (GitHub, fournisseurs) : TLS 1.2+ (rustls, TLS 1.3 privilégié), aucune redirection vers un autre hôte avec les en-têtes d'authentification.
4. **Appareil ↔ dépôt de synchronisation** : GitHub ne voit que du chiffré authentifié.
5. **Applis clientes ↔ liste de révocation / jetons de licence** : vérification de signature Ed25519 hors ligne.

## 3. Analyse STRIDE

Légende : **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege.

| # | Menace | STRIDE | Mesures | Vérification (test) |
|---|--------|--------|---------|---------------------|
| T1 | **Vol de l'appareil** : lecture de la base, des secrets | I | Base SQLCipher (clé = Argon2id(phrase secrète, sel), 64 Mio / 3 passes) ; secrets dans le trousseau OS ; verrouillage auto après inactivité ; la clé de base est effacée de la mémoire (`zeroize`) au verrouillage | `core::tests::no_plaintext_on_disk`, `vault::tests::lock_wipes_key`, `vault::tests::autolock` |
| T2 | **Force brute de la phrase secrète / du PIN** | S/E | Argon2id ; PIN : 5 essais puis effacement de la clé enveloppée par PIN (retour à la phrase secrète) ; TOTP obligatoire si activé | `vault::tests::pin_lockout`, `vault::tests::totp_required` |
| T3 | **Fuite d'une clé API** (copie, capture d'écran, logs) | I | Valeurs jamais envoyées à l'interface (masque `••••1234`) ; « Révéler » exige ré-authentification ; aucune journalisation des valeurs (`Secret` n'implémente pas `Debug`/`Serialize` en clair) ; alerte « clé trop puissante » ; rotation guidée | `secrets::tests::mask`, `secrets::tests::debug_redacted`, `policy::tests::reveal_requires_reauth` |
| T4 | **Faux connecteur / connecteur malveillant** | S/E | Connecteurs compilés dans le binaire (pas de plugins dynamiques) ; connecteur personnalisé : HTTPS obligatoire, les identifiants ne sont envoyés qu'à l'hôte déclaré, pas de suivi de redirection inter-hôte ; aucune commande shell | `custom::tests::rejects_http`, `http::tests::no_cross_host_redirect` |
| T5 | **Mise à jour piégée** | T/E | Plugin updater Tauri : signature minisign vérifiée avec la clé publique embarquée, mise à jour non signée refusée ; installateurs signés (Authenticode / notarisation Apple) ; CI de release depuis tags uniquement | Vérification intégrée à `tauri-plugin-updater` ; workflow `release.yml` |
| T6 | **Falsification de licence** | T/S | PASETO v4.public (Ed25519) ; `kid` (PASERK k4.pid) ; refus de tout autre en-tête ; fuzzing du parseur | `license::tests::tampered_rejected`, `fuzz/fuzz_targets/verify_license.rs` |
| T7 | **Contournement de la révocation** (rester hors ligne) | T/R | Liste de révocation signée et numérotée (anti-rollback : `seq` monotone) ; délai de grâce hors ligne borné (par défaut 14 jours) puis refus | `license::tests::revoked_rejected`, `revocation_rollback_rejected`, SDK TS idem |
| T8 | **Attaque sur la synchronisation** (lecture, rejeu, modification, suppression dans le dépôt) | I/T/D | XChaCha20-Poly1305 avec données associées (id appareil, HLC, époque) ; clé de sync = Argon2id(phrase secrète, sel de l'époque) ; rejeu idempotent (id d'événement unique) ; appareil révoqué → rotation de l'époque | `sync::tests::ciphertext_unreadable`, `tamper_detected`, `converge` |
| T9 | **Injection dans l'interface (XSS)** | E/I | CSP stricte (`default-src 'self'`, pas d'`unsafe-eval`, pas de script distant) ; React échappe par défaut, interdiction de `dangerouslySetInnerHTML` (règle ESLint) ; capabilities Tauri minimales ; validation de chaque argument côté Rust | `app/src-tauri/capabilities/*.json`, `tauri.conf.json`, ESLint |
| T10 | **Répudiation d'une action** (« ce n'est pas moi qui ai supprimé ») | R | Journal d'audit append-only (triggers SQL empêchant UPDATE/DELETE) chaîné SHA-256 ; vérification de la chaîne | `audit::tests::chain_detects_tamper`, `append_only` |
| T11 | **Écriture non voulue chez un fournisseur** | E | Mode par appli (lecture seule / lecture-écriture / désactivé) ; matrice par action ; confirmation + aperçu pour toute écriture ; ré-authentification pour toute action destructrice | `policy::tests::read_only_blocks_writes` |
| T12 | **Jeton GitHub volé utilisé pour lire la sync** | I | Contenu chiffré, inutile sans phrase secrète ; recommandation de jeton fine-grained limité au seul dépôt | `sync::tests::ciphertext_unreadable` |
| T13 | **Déni de service par quota GitHub** | D | Requêtes conditionnelles (ETag → 304 ne compte pas), lecture de `X-RateLimit-*`, intervalle adaptatif | `github::tests::etag_304`, `rate_limit_backoff` |
| T14 | **Import d'un fichier .ccvault malveillant** | T/D | Format versionné, taille max, AEAD vérifié avant tout parsing JSON, fuzzing | `ccvault::tests::*`, `fuzz_targets/ccvault_import.rs` |
| T15 | **Appareil rooté / jailbreaké** | E | Détection heuristique et avertissement (pas de blocage dur, documenté) | `security::tests` (desktop : toujours `false`) |
| T16 | **Chaîne d'approvisionnement (dépendance compromise)** | T | `Cargo.lock`/`package-lock.json` versionnés, cargo-audit, cargo-deny (licences, sources), npm audit, Dependabot, CodeQL | CI `security.yml` |

## 4. Risques résiduels acceptés (documentés)

- Un malware tournant avec les droits de l'utilisateur *pendant que l'app est déverrouillée* peut lire la mémoire du processus. Hors périmètre (aucune app desktop ne s'en protège totalement).
- Le TOTP local protège contre l'usage d'une phrase secrète volée seule, mais pas contre un attaquant qui possède à la fois la base et la phrase secrète (le secret TOTP est dans la base chiffrée).
- Les licences hors ligne ne peuvent pas limiter *strictement* le nombre d'activations (voir `docs/licensing-online-option.md`).

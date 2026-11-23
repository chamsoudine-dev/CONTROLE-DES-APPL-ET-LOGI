# Guide développeur

## Environnement

```bash
# Linux : sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libsoup-3.0-dev libdbus-1-dev patchelf
cd app && npm ci && npm run tauri dev       # application en développement
cargo test --workspace                       # tests Rust
cd app && npm run lint && npm run typecheck && npm test
bash scripts/e2e-first-launch.sh             # e2e premier lancement (Xvfb + xdotool)
cargo llvm-cov -p cc-core -p cc-license -p cc-connectors --summary-only   # couverture
cd fuzz && cargo +nightly fuzz run verify_license                          # fuzzing
```

Règles : `#![forbid(unsafe_code)]`, clippy pedantic sans avertissement, `cargo fmt`, aucune
crypto maison, aucun secret dans le dépôt, toute commande exposée listée dans
`app/src-tauri/commands.txt` (puis `python3 scripts/gen-capability.py`).

## Architecture du code

| Chemin | Rôle |
|--------|------|
| `crates/core/src/vault.rs` | coffre : Argon2id → SQLCipher, TOTP, PIN, verrouillage, ré-auth |
| `crates/core/src/{keys,envvars,apps,policy}.rs` | secrets, variables, applis, droits |
| `crates/core/src/{audit,sync,hlc,ccvault,licensing,tracking}.rs` | audit chaîné, sync, export, licences, suivi |
| `crates/connectors/src/*.rs` | un module par fournisseur, `http.rs` (client durci), `exec.rs` (écritures) |
| `crates/license` | PASETO v4.public, révocations, vérificateur client |
| `app/src-tauri/src/cmd_*.rs` | commandes Tauri (validation + appel du cœur) |
| `app/src/pages`, `app/src/components` | interface (aucune logique sensible) |

## Ajouter un connecteur

1. Créer `crates/connectors/src/monfournisseur.rs` :
   ```rust
   pub struct MonFournisseur { http: HttpClient, projet: String }
   impl MonFournisseur {
       pub fn new(config: &serde_json::Value, secret: SecretValue) -> Result<Self> {
           Ok(Self {
               http: HttpClient::new(&base_url(config, "https://api.exemple.com")?, Auth::Bearer(secret))?,
               projet: safe_segment(cfg(config, "project_id")?)?.to_owned(),
           })
       }
   }
   #[async_trait]
   impl Connector for MonFournisseur {
       fn provider(&self) -> Provider { Provider::Custom /* ou nouvelle variante */ }
       fn required_permissions(&self) -> Vec<PermissionSpec> {
           vec![PermissionSpec::read("deployments", "Afficher les déploiements"),
                PermissionSpec::write("deployments", "Redéployer")]
       }
       async fn test(&self) -> Result<TestReport> { /* appel réel + permissions détectées + too_powerful */ }
       async fn health(&self) -> Result<Health> { /* … */ }
       async fn list_resources(&self) -> Result<Vec<Resource>> { /* … */ }
       fn actions(&self) -> Vec<ActionSpec> {
           vec![ActionSpec::new("redeploy", "Redéployer", Action::Redeploy, "…")]
       }
       async fn execute(&self, action: &str, p: &serde_json::Value) -> Result<serde_json::Value> { /* … */ }
   }
   ```
2. Ajouter la variante dans `Provider` (`types.rs`), le formulaire dans `registry.rs`
   (`info()` + `build()`), et éventuellement `MediaStore` pour un stockage.
3. Tests avec `wiremock` : succès, clé invalide, chaque action, validation des identifiants
   (`safe_segment`), surcharge d'URL limitée à localhost (`base_url`).
4. Règles : jamais d'URL construite avec une entrée non validée ; jamais de secret dans un message
   d'erreur ; toute écriture déclarée avec la bonne `Action` (la politique s'applique via `exec`).

## Intégrer le SDK de licence

**TypeScript** (`sdk/ts`) :
```ts
import { LicenseChecker, LicenseVerifier } from "@control-center/license";
const checker = new LicenseChecker(new LicenseVerifier(["k4.public.…"]), {
  revocationUrl: "https://raw.githubusercontent.com/<owner>/control-center-revocations/HEAD/revocations.paseto",
  graceDays: 14,
  store: { get: (k) => localStorage.getItem(k), set: (k, v) => localStorage.setItem(k, v) },
});
await checker.restore();
await checker.refresh();
const { claims } = await checker.check(token);   // LicenseError.code sinon
```
Exemple exécutable : `cd sdk/ts && npm run example`.

**Rust** (`sdk/rust`, crate `control-center-license`) :
```rust
let verifier = Verifier::new([PublicKey::from_paserk("k4.public.…")?]);
let mut checker = LicenseChecker::new(verifier, 14);
checker.update_revocations(&list_token, OffsetDateTime::now_utc())?;
let outcome = checker.check(&token, OffsetDateTime::now_utc())?;
```

**Go** (`sdk/go/ccl`) :
```go
v, _ := ccl.NewVerifier("k4.public.…")
c := ccl.NewChecker(v, 14)
c.UpdateRevocations(listToken, time.Now())
claims, err := c.Check(token, time.Now())
```

Les trois SDK sont testés contre les mêmes jeux (`sdk/fixtures.json`, régénérés par
`cargo run -p cc-license --example gen_fixtures > sdk/fixtures.json`).

Bonnes pratiques côté appli cliente : embarquer **toutes** les clés publiques actives (rotation),
persister le cache de la liste, rafraîchir au démarrage puis quotidiennement, ne jamais faire
confiance à l'horloge seule pour prolonger le délai de grâce (stocker la date de dernière liste).

## Publier une release

Voir `docs/distribution.md` : `git tag vX.Y.Z && git push origin vX.Y.Z` déclenche
`.github/workflows/release.yml` (installateurs, APK, archive source, `latest.json` signé).

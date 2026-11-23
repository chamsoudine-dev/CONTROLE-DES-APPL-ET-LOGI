# Distribution, signature et mises à jour

## Publier une version

```bash
# 1. Mettre à jour la version (app/package.json, app/src-tauri/tauri.conf.json, Cargo.toml) et CHANGELOG.md
# 2. Taguer et pousser
git tag v1.0.1 && git push origin v1.0.1
```

Le workflow `.github/workflows/release.yml` :

| Job | Runner | Produit |
|-----|--------|---------|
| create-release | ubuntu | brouillon de release + `control-center-vX.Y.Z-source.zip` |
| desktop / Linux | ubuntu-22.04 | `.AppImage`, `.deb` |
| desktop / Windows | windows-latest | `.msi`, `-setup.exe` (NSIS) |
| desktop / macOS | macos-latest | `.dmg` universel (Intel + Apple Silicon) |
| android | ubuntu-22.04 | `.apk` signé |
| ios | macos-latest | activé si la variable `IOS_ENABLED=true` |
| publish | ubuntu | passe la release en « publiée » |

`latest.json` (manifeste du plugin updater) est joint automatiquement par `tauri-action`.

## Mises à jour signées (obligatoire)

1. Générer la paire de clés **une fois**, hors du dépôt :
   ```bash
   cd app && npx tauri signer generate -w ~/.tauri/control-center.key
   ```
2. GitHub → Settings → Secrets and variables → Actions :
   - secret `TAURI_SIGNING_PRIVATE_KEY` = contenu de `control-center.key`
   - secret `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` = son mot de passe
   - **variable** `TAURI_UPDATER_PUBKEY` = contenu de `control-center.key.pub`
3. La CI injecte la clé publique dans `tauri.conf.json` au moment du build : elle n'est jamais
   éditée à la main et la clé privée ne quitte jamais les secrets GitHub.

Garanties (plugin `tauri-plugin-updater`) :
- l'artefact téléchargé doit porter une signature minisign valide pour la clé embarquée, sinon
  l'installation est refusée ;
- `requireSignedVersion: true` : la version annoncée doit être celle signée (anti-rétrogradation) ;
- aucun drapeau `dangerous*` (transport HTTP, certificat invalide) n'est activé — vérifié par le
  test `updater_is_safe`.

Sans clé configurée, la CI produit quand même les installateurs, mais aucune mise à jour ne pourra
être installée (comportement sûr par défaut : `pubkey` vide ⇒ refus).

### Tester la mise à jour v1.0.0 → v1.0.1
1. Publier `v1.0.0` avec les secrets ci-dessus, installer l'application.
2. Publier `v1.0.1`.
3. Dans l'app : Paramètres → Mises à jour → Vérifier → « Mettre à jour » → redémarrage sur 1.0.1.
4. Contre-test : remplacer un artefact de la release par un fichier modifié → l'installation est refusée.

## Signature de code des installateurs (comptes et coûts indicatifs, 2026)

| Plateforme | Ce qu'il faut | Coût | Secrets CI |
|------------|---------------|------|------------|
| macOS | Apple Developer Program (certificat « Developer ID Application » + notarisation) | 99 USD / an | `APPLE_CERTIFICATE` (p12 base64), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`, `APPLE_PASSWORD` (mot de passe d'app), `APPLE_TEAM_ID` |
| Windows | Certificat Authenticode OV/EV (DigiCert, Sectigo, SSL.com…) **ou** Azure Trusted Signing | OV ≈ 200–400 USD/an, EV ≈ 300–600 USD/an ; Azure Trusted Signing ≈ 10 USD/mois | selon fournisseur (voir doc Tauri « Windows code signing ») |
| Linux | Aucun obligatoire (signature GPG optionnelle des paquets) | 0 | — |
| Android | Keystore de publication (gratuit) ; Google Play Console si publication sur le Store | 0 (Play : 25 USD une fois) | `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` |
| iOS | Apple Developer Program (même compte que macOS) + profil de provisionnement | inclus dans les 99 USD | `APPLE_API_ISSUER`, `APPLE_API_KEY`, `APPLE_API_KEY_PATH`, `APPLE_TEAM_ID` |

Sans certificats, les installateurs fonctionnent mais Windows SmartScreen et macOS Gatekeeper
afficheront un avertissement (macOS : clic droit → Ouvrir).

## Android

- Projet généré : `app/src-tauri/gen/android` (commité).
- Build local : `ANDROID_HOME=… NDK_HOME=… npx tauri android build --apk`.
- Stockage des secrets : le trousseau desktop n'existe pas sur Android ; les secrets sont chiffrés
  (XChaCha20-Poly1305, sous-clé de la phrase secrète) dans la base SQLCipher. Un plugin natif
  Android Keystore (enveloppe de la clé maîtresse, biométrie) est la prochaine étape.
- Détection root : `cc_core::security` (su, Magisk…) → bannière d'avertissement.

## iOS (préparé)

- Activer `IOS_ENABLED=true` (variable du dépôt) et fournir les secrets Apple.
- Détection jailbreak : `cc_core::security` (Cydia, Sileo, `/var/jb`…).
- Keychain : même approche que pour Android (plugin natif à brancher sur le trait `SecretStore`).

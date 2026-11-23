# Guide utilisateur — Control Center

## 1. Installation

Téléchargez l'installateur de votre système sur la page **Releases** du dépôt :

| Système | Fichier | Remarque |
|---------|---------|----------|
| Windows 10/11 | `Control Center_x.y.z_x64-setup.exe` ou `.msi` | Si SmartScreen s'affiche sans certificat : « Informations complémentaires → Exécuter quand même » |
| macOS 11+ | `Control Center_x.y.z_universal.dmg` | Glissez l'app dans Applications. Sans notarisation : clic droit → Ouvrir |
| Linux | `.AppImage` (rendre exécutable) ou `.deb` (`sudo apt install ./fichier.deb`) | Le trousseau utilise Secret Service (GNOME Keyring / KWallet) |
| Android 8+ | `Control-Center_x.y.z_android.apk` | Autoriser l'installation depuis cette source |

Les mises à jour se font ensuite **dans l'application** (Paramètres → Mises à jour) ; chaque mise à
jour est signée et vérifiée avant installation.

## 2. Premier lancement (5 étapes)

1. **Profil** : nom affiché + **phrase secrète maîtresse** (12 caractères minimum ; une phrase de
   4 à 6 mots est idéale). Elle chiffre toute la base ; elle n'est stockée nulle part.
   **Si vous l'oubliez, vos données sont irrécupérables** (sauf depuis un autre appareil synchronisé).
2. **Sécurité** : activez la **2FA TOTP** (scannez le QR code avec Google Authenticator, Aegis,
   1Password…), puis un **PIN** optionnel (6–12 chiffres) pour déverrouiller rapidement.
   Après 5 erreurs de PIN, la phrase secrète devient obligatoire.
3. **GitHub** (obligatoire) : collez un **jeton fine-grained** (recommandé) limité aux dépôts suivis
   et au dépôt de synchronisation — permissions *Contents* lecture/écriture, *Metadata* lecture,
   *Actions* lecture — avec une expiration. Le tableau affiche chaque permission et sa raison.
4. **Dépôt de synchronisation** : créez `control-center-sync` (privé) ou choisissez un dépôt privé.
5. **Clé de licences** : générez la paire Ed25519 (clé privée dans le trousseau). Exportez ensuite
   une **sauvegarde chiffrée** (Paramètres → Clé de signature des licences).

## 3. Verrouillage

- Verrouillage automatique après inactivité (5 min par défaut, Paramètres → Sécurité).
- Bouton **Verrouiller** dans la barre latérale.
- Déverrouillage : phrase secrète (+ code 2FA) ou PIN.

## 4. Ajouter une application

Tableau de bord → **＋ Ajouter une appli** :
1. Identité (nom, description, icône, URL HTTPS pour la surveillance en ligne/hors ligne).
2. Dépôt GitHub (liste de vos dépôts, recherche).
3. Services : hébergement (Vercel, Netlify, Cloudflare Pages), base (Supabase, Firebase),
   stockage (Cloudinary, Supabase Storage, Firebase Storage), paiement / personnalisé (toute API HTTPS).
   Chaque service a son formulaire ; **Tester** vérifie la clé **et ses permissions réelles**
   et signale une clé **trop puissante** avec les droits minimaux recommandés.
4. Droits : mode **Lecture seule** (recommandé au début), **Lecture-écriture** ou **Désactivé**.
5. Récapitulatif → Créer.

## 5. Environnements & Clés

- Secrets groupés par appli et par environnement (développement / preview / production) ;
  colonnes : nom, fournisseur, valeur masquée `••••1234`, ajout, dernière utilisation, expiration,
  permissions détectées.
- **Révéler** : demande votre phrase secrète (et le code 2FA) ; la valeur se masque après 30 s.
- **Tester**, **Rotation** (procédure guidée), **Modifier** (nom, expiration), **Supprimer**
  (confirmation + phrase secrète).
- **Variables d'environnement** : édition locale (valeur en clair ou lien vers un secret),
  **Aperçu des différences** avec l'hébergeur, **Envoyer** (confirmation).
- **Export / import `.ccvault`** : fichier chiffré par une phrase distincte. Les applis importées
  arrivent en lecture seule.

## 6. Droits

Fiche appli → **Droits** :
- Mode par appli ; matrice par action : voir, redéployer, rollback, tag/release/workflow,
  modifier les variables, médias, licences, supprimer.
- Toute écriture affiche un **aperçu** et demande une **confirmation** ; rollback et suppression
  demandent aussi la **phrase secrète**. Tout est inscrit au **journal d'audit** (Journal).
- Rôles propriétaire / administrateur / lecteur (prévus pour inviter un collaborateur).

## 7. Suivi, déploiements, médias

- Le tableau de bord indique pour chaque appli : en ligne/hors ligne, dernier déploiement, alertes
  (clé expirée, clé trop puissante, CI en échec) et le quota GitHub.
- Notifications système lors d'un **push** fait ailleurs (VS Code, autre machine) et à la fin de
  la CI / du déploiement.
- Fiche appli : redéployer, rollback, déclencher un workflow, créer tag + release.
- **Médias** : déposez une image ; elle est convertie en WebP (≤ 2048 px) puis envoyée vers le
  stockage choisi ; URL copiable.

## 8. Synchronisation entre appareils

- Synchronisation → saisir la **phrase secrète de synchronisation** (la même sur tous les
  appareils). GitHub ne reçoit que des données chiffrées.
- Ajouter un appareil : **QR code** → sur le nouvel appareil : profil → GitHub → même dépôt →
  phrase secrète.
- Conflits (même élément modifié sur deux appareils) : choisissez la version à garder.
- **Appareil perdu** : Révoquer, puis **Rotation de la clé** avec une nouvelle phrase.

## 9. Sauvegarde et restauration

| Quoi | Comment |
|------|---------|
| Tout le coffre | Environnements & Clés → Export `.ccvault` (à garder hors ligne) |
| Clé de signature des licences | Paramètres → Exporter une sauvegarde chiffrée |
| Multi-appareils | La synchronisation chiffrée est aussi une sauvegarde |

Restauration : installer l'app → créer un profil → Importer le `.ccvault` (ou activer la
synchronisation) → Restaurer la clé de licences.

## 10. Licences

Licences → Produits (perpétuelle, abonnement, essai) → Clients → Ventes (saisie manuelle :
espèces, virement, Mobile Money vérifié) → **Nouvelle licence** : un jeton signé (à remettre au
client) + une clé lisible `XXXX-XXXX-XXXX-XXXX` (support).
- **Prolonger** : nouveau jeton, même identifiant.
- **Révoquer** puis **Signer et publier la liste** (onglet Révocations) : les applis clientes
  la téléchargent et refusent la licence ; hors ligne, elles tolèrent 14 jours sans liste fraîche.
- **Exporter CSV**.

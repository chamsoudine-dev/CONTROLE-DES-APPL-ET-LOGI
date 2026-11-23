# Maquettes textuelles

## 1. Premier lancement (assistant, 5 étapes)

```
┌─────────────────────────────── Control Center ───────────────────────────────┐
│  ● Profil  ○ Sécurité  ○ GitHub  ○ Dépôt de sync  ○ Clé de licences          │
│──────────────────────────────────────────────────────────────────────────────│
│  Étape 1 — Votre profil local                                                │
│  Nom affiché      [ Chamsoudine            ]                                 │
│  Phrase secrète   [ •••••••••••••••••••••  ]  Force : ████████░░ forte       │
│  Confirmer        [ •••••••••••••••••••••  ]                                 │
│  ⓘ Elle chiffre toute la base. Elle n'est stockée nulle part :              │
│    si vous l'oubliez, les données sont irrécupérables.                       │
│                                                        [ Continuer → ]       │
└──────────────────────────────────────────────────────────────────────────────┘
Étape 2 : 2FA TOTP (QR code + saisie d'un code de vérification) · PIN optionnel (6+ chiffres)
Étape 3 : GitHub — [Jeton fine-grained] | [Device Flow]
          Tableau « Permission demandée | Lecture/Écriture | Pourquoi »
Étape 4 : Dépôt de sync — ( ) créer « control-center-sync » (privé)  ( ) choisir existant ▾
Étape 5 : Clé de licences — Générer la paire Ed25519 · [Exporter une sauvegarde chiffrée]
```

## 2. Tableau de bord

```
┌ Sidebar ─────────┐┌─────────────────────────────────────────────────────────┐
│ ▣ Tableau de bord││  4 applis · 3 en ligne · 1 hors ligne · 2 alertes        │
│ ⚿ Environnements ││ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐  │
│ ＋ Ajouter appli  ││ │ ● Boutique    │ │ ● Blog        │ │ ○ API Paie    │  │
│ ⎘ Licences       ││ │ Vercel · prod │ │ Netlify       │ │ hors ligne 5m │  │
│ ⇅ Synchronisation││ │ ✓ déployé 3m  │ │ ✓ 2h          │ │ ✗ build échoué│  │
│ ☰ Journal        ││ └───────────────┘ └───────────────┘ └───────────────┘  │
│ ⚙ Paramètres     ││  Activité récente : push main par vous (VS Code) · ✓    │
│ 🔒 Verrouiller   ││  Quota GitHub : 4 812 / 5 000                           │
└──────────────────┘└─────────────────────────────────────────────────────────┘
```

## 3. Environnements & Clés

```
 Appli : [ Boutique ▾ ]   Env : (dev) (preview) (●production)   [＋ Ajouter un secret]
 ┌──────────────────┬──────────┬────────────┬───────────┬───────────┬──────────────────┐
 │ Nom              │ Fourn.   │ Valeur     │ Ajouté    │ Utilisé   │ Actions          │
 ├──────────────────┼──────────┼────────────┼───────────┼───────────┼──────────────────┤
 │ VERCEL_TOKEN ⚠   │ vercel   │ ••••a91F   │ 12/10     │ il y a 3m │ 👁 ✓ ⟳ ✎ 🗑     │
 │ SUPABASE_KEY     │ supabase │ ••••77xQ   │ 01/11     │ hier      │ 👁 ✓ ⟳ ✎ 🗑     │
 └──────────────────┴──────────┴────────────┴───────────┴───────────┴──────────────────┘
 ⚠ = clé trop puissante (ex. accès à toute l'équipe) → suggestion de scopes minimaux
 Variables d'environnement : éditeur clé=valeur · [Aperçu des différences] · [Envoyer vers Vercel]
 [Exporter le coffre (.ccvault)]  [Importer]
```

## 4. Ajouter une application (assistant)

```
 1 Identité : nom, description, icône, URL(s)
 2 Dépôt GitHub : liste déroulante de vos dépôts (recherche)
 3 Services : [✓] Hébergement (Vercel▾) [✓] Base (Supabase▾) [ ] Stockage [ ] Paiement [ ] Personnalisé
 4 Formulaire par service : champs dédiés + secret → [Tester] → ✓ connecté · permissions : lecture ✓ écriture ✓
 5 Droits : mode (Lecture seule | Lecture-écriture | Désactivé) + matrice d'actions · licences (on/off)
 6 Récapitulatif → [Créer]
```

## 5. Fiche appli

```
 Boutique  ● en ligne  [Lecture-écriture]                       [Redéployer] [Rollback ▾]
 ┌ Dépôt ─────────────────┐ ┌ Déploiements ────────────┐ ┌ Base ─────────────┐
 │ main · a1b2c3 « fix »  │ │ ✓ prod 3m  ✓ preview 1h  │ │ Supabase · sain   │
 │ PR #12 ouverte         │ │ ✗ prod hier (rollback)   │ │ 3 tables          │
 │ Actions : ✓ CI         │ │                          │ │                   │
 └────────────────────────┘ └──────────────────────────┘ └───────────────────┘
 ┌ Médias ──────────────── [Déposer une image] ┐ ┌ Licences ────────────────┐
 │ logo.webp  48 Ko  [Copier l'URL]            │ │ 12 actives · 1 révoquée  │
 └─────────────────────────────────────────────┘ └──────────────────────────┘
```

## 6. Licences

```
 Produits  |  Clients  |  Ventes  |  Licences  |  Révocations
 [＋ Nouvelle licence]  [Exporter CSV]   Liste de révocation : seq 7 · publiée il y a 2h ✓
 Clé lisible           Client        Produit        Expire     Statut   Actions
 K7QD-M2XA-9FZP-T4WC   Awa Diallo    Pro (abonn.)   2027-01-01 active   Prolonger · Révoquer · Copier jeton
```

## 7. Paramètres

```
 Sécurité : verrouillage auto [5 min ▾] · PIN [Définir] · 2FA [activée] · Changer la phrase secrète
 GitHub : connecté en tant que @… · permissions · [Reconnecter]
 Synchronisation : dépôt · appareils (révoquer) · [Ajouter un appareil (QR)]
 Licences : kid actif · [Rotation de clé] · [Sauvegarde chiffrée]
 Mises à jour : version · [Vérifier]
 Journal d'audit : intégrité ✓ (chaîne vérifiée)
```

# Plan de réponse aux incidents

Principe : **contenir → révoquer → remplacer → vérifier → consigner**. Chaque étape faite dans
Control Center est inscrite au journal d'audit (Journal → Vérifier la chaîne).

## A. Clé API compromise (Vercel, Supabase, Firebase, Cloudinary, …)

1. **Contenir** : passer l'appli concernée en **Lecture seule** (ou Désactivé) — Fiche appli → Droits.
2. **Révoquer** la clé chez le fournisseur (console du fournisseur).
3. **Remplacer** : créer une nouvelle clé **aux droits minimaux** (voir « Permissions recommandées »)
   → Environnements & Clés → **Rotation** → **Tester**.
4. **Vérifier** l'activité chez le fournisseur (journaux de déploiement, d'accès au stockage).
5. **Propager** : Envoyer les variables d'environnement si la clé y figure ; synchroniser.
6. **Consigner** : date, portée, cause probable.

## B. Jeton GitHub compromis

1. GitHub → Settings → Developer settings → révoquer le jeton (ou Applications autorisées).
2. Le dépôt de synchronisation ne contient que du chiffré : sans la phrase secrète, rien n'est lisible.
   Par précaution, faites une **rotation de la clé de synchronisation** (nouvelle phrase).
3. Vérifier le journal de sécurité GitHub (Settings → Security log), les branches/tags/releases
   inattendus, et les secrets Actions (`TAURI_SIGNING_PRIVATE_KEY`…).
4. Nouveau jeton fine-grained → Paramètres → GitHub → Reconnecter.

## C. Appareil perdu ou volé

1. Depuis un autre appareil : Synchronisation → **Révoquer** l'appareil.
2. **Rotation de la clé** avec une **nouvelle** phrase secrète de synchronisation ; ressaisir
   cette phrase sur les autres appareils.
3. Révoquer le jeton GitHub de cet appareil, faire tourner les clés API les plus sensibles
   (procédure A) — la base locale est chiffrée (SQLCipher + Argon2id), mais la prudence s'impose
   si la phrase secrète a pu être observée.
4. Si la **clé de signature des licences** était sur cet appareil : voir D.

## D. Clé de signature des licences compromise

1. Paramètres → **Rotation de clé** (nouveau `kid`).
2. Publier une mise à jour des applis clientes embarquant la **nouvelle** clé publique et
   **retirant** l'ancienne.
3. Réémettre les licences légitimes avec la nouvelle clé (Licences → Prolonger produit un nouveau
   jeton) et les envoyer aux clients.
4. Tant que l'ancienne clé reste embarquée dans des versions clientes, des licences forgées
   peuvent être acceptées : prioriser la mise à jour des clients.

## E. Licence piratée (partagée publiquement)

1. Licences → rechercher la clé lisible → **Révoquer** (motif) → **Signer et publier la liste**.
2. Les applis clientes la refusent dès la prochaine récupération de la liste, et au plus tard à
   l'expiration du délai de grâce hors ligne (14 jours par défaut).
3. Réémettre une licence au client légitime si nécessaire ; envisager l'option d'activation en
   ligne (`docs/licensing-online-option.md`) pour les produits fortement piratés.

## F. Mise à jour piégée suspectée

1. Les mises à jour non signées sont refusées automatiquement. Si une release suspecte apparaît :
   la supprimer, révoquer le secret `TAURI_SIGNING_PRIVATE_KEY`, générer une nouvelle paire,
   publier une version signée avec la nouvelle clé (installation manuelle requise pour les clients,
   puisque la clé publique embarquée change).
2. Auditer les workflows et les accès au dépôt (protection de branche, tags protégés).

## G. Phrase secrète oubliée

Aucune récupération possible (par conception). Options : restaurer depuis un autre appareil
synchronisé (la phrase de synchronisation suffit) ou depuis un export `.ccvault` (sa propre phrase).

# Synchronisation chiffrée — conception

## Format du dépôt privé

```
meta.json                              # public : époque, paramètres Argon2id, sel, valeur témoin chiffrée
epochs/<n>/events/<appareil>/<hlc>_<lot>.ccev
```

`meta.json` ne contient aucun secret. Chaque `.ccev` est une enveloppe JSON :

```json
{ "v": 1, "epoch": 1, "device": "<uuid>", "batch": "<uuid>", "ct": "<base64>" }
```

`ct` = nonce (24 o) ‖ XChaCha20-Poly1305(clé, événements JSON), avec pour données associées
`cc-sync|batch|1|<epoch>|<device>|<batch>` : déplacer un lot vers un autre dossier, changer d'époque
ou modifier un octet fait échouer l'authentification.

Clé = Argon2id(phrase secrète de synchronisation, sel de l'époque). Elle est mémorisée dans le
trousseau de chaque appareil après la première saisie.

**Métadonnées visibles par GitHub** : nombre d'appareils (noms de dossiers = UUID), horodatages
HLC des lots et leur taille. Aucun nom d'appli, de client ou de clé.

## Journal et fusion

1. **Capture** : l'état local de chaque enregistrement synchronisé (applis + droits, secrets, connecteurs,
   variables, produits, clients, ventes, licences, révocations, appareils) est comparé au dernier
   état connu (`sync_records`) ; chaque différence devient un événement horodaté par HLC
   (`<ms>-<compteur>-<appareil>`), avec l'HLC de la version sur laquelle il s'appuie (`base_hlc`).
2. **Récupération** : les lots des autres appareils postérieurs au curseur sont téléchargés,
   authentifiés puis appliqués dans une transaction (clés étrangères différées).
3. **Fusion** : dernier écrivain gagnant par enregistrement (HLC, puis identifiant d'appareil) →
   tous les appareils convergent vers le même état, quel que soit l'ordre de réception.
   Si l'événement entrant ne s'appuie pas sur la version locale et vient d'un autre appareil,
   la modification est **concurrente** : la version perdante est conservée dans `sync_conflicts`
   et l'écran « Synchronisation » permet de la restaurer (elle devient alors une nouvelle
   modification, propagée partout).
4. **Envoi** : les événements locaux non encore poussés sont relus depuis l'état courant
   (les valeurs secrètes ne sont jamais conservées en clair dans le journal local : seule leur
   empreinte l'est) et envoyés en un lot chiffré.

Rejeu : chaque événement a un identifiant unique ; un lot déjà appliqué est ignoré.

## Ajout d'un appareil

QR code (Synchronisation → Ajouter un appareil) contenant le dépôt et l'époque — jamais la phrase.
Sur le nouvel appareil : profil local → GitHub → choisir le dépôt → saisir la phrase secrète de
synchronisation → récupération complète.

## Appareil perdu

1. Révoquer l'appareil (ré-authentification) : ses lots futurs sont refusés par les autres appareils.
2. **Rotation de l'époque avec une nouvelle phrase secrète** : nouvelle clé, toutes les données
   sont ré-émises sous `epochs/<n+1>/`. L'appareil perdu connaît l'ancienne phrase mais pas la
   nouvelle : il ne peut plus rien déchiffrer de nouveau.
3. Révoquer aussi son jeton GitHub (Settings → Applications / tokens) et faire tourner les clés
   API sensibles (voir `docs/incident-response.md`).

## Option : synchronisation directe en réseau local (non activée)

Conception retenue pour une version future : découverte mDNS, canal TLS 1.3 avec épinglage de
la clé publique de l'appareil échangée par QR code, même format de lots chiffrés (le transport
change, pas la cryptographie). Non livrée en v1 pour limiter la surface d'attaque réseau
(ouverture d'un port en écoute).

## Limites connues

- Fusion au niveau de l'enregistrement (pas du champ) : deux modifications concurrentes de champs
  différents d'un même enregistrement produisent un conflit (résolu manuellement).
- Pas encore de compaction : un nouvel appareil relit tout l'historique de l'époque courante
  (une rotation d'époque sert de compaction).
- L'API Contents de GitHub impose une requête par fichier : un lot regroupe jusqu'à 500 événements.

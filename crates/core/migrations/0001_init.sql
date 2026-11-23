-- Control Center — schéma initial (SQLCipher)
-- Toutes les dates : texte RFC 3339 UTC. Tous les identifiants : UUID v4 texte.
-- Les VALEURS des secrets ne sont JAMAIS ici : seulement leurs métadonnées.

CREATE TABLE profiles (
  id            TEXT PRIMARY KEY,
  display_name  TEXT NOT NULL,
  totp_secret   TEXT,                -- base32, NULL si 2FA désactivée
  totp_enabled  INTEGER NOT NULL DEFAULT 0,
  autolock_secs INTEGER NOT NULL DEFAULT 300,
  github_login  TEXT,
  sync_repo     TEXT,                -- owner/name du dépôt privé
  revocation_repo TEXT,              -- owner/name du dépôt public des révocations
  license_kid   TEXT,                -- kid de la clé de signature active
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);

CREATE TABLE devices (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  platform    TEXT NOT NULL,
  is_current  INTEGER NOT NULL DEFAULT 0,
  revoked_at  TEXT,
  last_seen   TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE roles (
  id    TEXT PRIMARY KEY,           -- owner | admin | viewer
  label TEXT NOT NULL
);
INSERT INTO roles(id,label) VALUES ('owner','Propriétaire'),('admin','Administrateur'),('viewer','Lecteur');

CREATE TABLE apps (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  description  TEXT NOT NULL DEFAULT '',
  icon         TEXT,                -- data URL ou nom d'icône
  urls         TEXT NOT NULL DEFAULT '[]', -- JSON array
  repo         TEXT,                -- owner/name
  access_mode  TEXT NOT NULL DEFAULT 'read_only' CHECK (access_mode IN ('read_only','read_write','disabled')),
  licensing_enabled INTEGER NOT NULL DEFAULT 0,
  hlc          TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE TABLE environments (
  id      TEXT PRIMARY KEY,
  app_id  TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  kind    TEXT NOT NULL CHECK (kind IN ('development','preview','production')),
  UNIQUE(app_id, kind)
);

CREATE TABLE connectors (
  id          TEXT PRIMARY KEY,
  app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  provider    TEXT NOT NULL,        -- github | vercel | supabase | firebase | netlify | cloudflare | cloudinary | custom
  category    TEXT NOT NULL,        -- hosting | database | storage | payment | custom | source
  config      TEXT NOT NULL DEFAULT '{}', -- JSON non secret (project id, base url, …)
  secret_id   TEXT,                 -- référence secrets_meta.id
  last_test_at TEXT,
  last_test_ok INTEGER,
  detected_permissions TEXT NOT NULL DEFAULT '[]',
  created_at  TEXT NOT NULL
);

CREATE TABLE secrets_meta (
  id          TEXT PRIMARY KEY,     -- aussi l'identifiant dans le trousseau : "cc:<id>"
  app_id      TEXT REFERENCES apps(id) ON DELETE CASCADE,
  environment TEXT NOT NULL CHECK (environment IN ('development','preview','production','global')),
  provider    TEXT NOT NULL,
  name        TEXT NOT NULL,
  last4       TEXT NOT NULL,        -- 4 derniers caractères pour le masque
  fingerprint TEXT NOT NULL,        -- HMAC-SHA256 tronqué (détection de doublons sans révéler)
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL,
  last_used_at TEXT,
  expires_at  TEXT,
  detected_permissions TEXT NOT NULL DEFAULT '[]',
  too_powerful INTEGER NOT NULL DEFAULT 0,
  UNIQUE(app_id, environment, name)
);

CREATE TABLE env_vars (
  id          TEXT PRIMARY KEY,
  app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  environment TEXT NOT NULL CHECK (environment IN ('development','preview','production')),
  key         TEXT NOT NULL,
  value       TEXT NOT NULL,        -- valeur non secrète (sinon : lien vers un secret)
  secret_id   TEXT REFERENCES secrets_meta(id) ON DELETE SET NULL,
  remote_value_hash TEXT,           -- empreinte de la valeur envoyée à l'hébergeur
  pushed_at   TEXT,
  updated_at  TEXT NOT NULL,
  UNIQUE(app_id, environment, key)
);

CREATE TABLE permissions (
  app_id  TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  action  TEXT NOT NULL,            -- view | redeploy | rollback | edit_env | media | licenses | delete
  allowed INTEGER NOT NULL,
  PRIMARY KEY(app_id, action)
);

CREATE TABLE products (
  id          TEXT PRIMARY KEY,
  app_id      TEXT REFERENCES apps(id) ON DELETE SET NULL,
  name        TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('perpetual','subscription','trial')),
  duration_days INTEGER,            -- abonnement/essai
  price_cents INTEGER NOT NULL DEFAULT 0,
  currency    TEXT NOT NULL DEFAULT 'XOF',
  features    TEXT NOT NULL DEFAULT '[]',
  created_at  TEXT NOT NULL
);

CREATE TABLE customers (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  email       TEXT,
  phone       TEXT,
  notes       TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL
);

CREATE TABLE sales (
  id          TEXT PRIMARY KEY,
  product_id  TEXT NOT NULL REFERENCES products(id),
  customer_id TEXT NOT NULL REFERENCES customers(id),
  amount_cents INTEGER NOT NULL,
  currency    TEXT NOT NULL,
  provider    TEXT NOT NULL DEFAULT 'manual', -- manual | mobile_money | stripe | …
  reference   TEXT,
  status      TEXT NOT NULL DEFAULT 'paid' CHECK (status IN ('pending','paid','refunded')),
  created_at  TEXT NOT NULL
);

CREATE TABLE licenses (
  id          TEXT PRIMARY KEY,     -- = jti du jeton
  product_id  TEXT NOT NULL REFERENCES products(id),
  customer_id TEXT NOT NULL REFERENCES customers(id),
  sale_id     TEXT REFERENCES sales(id),
  readable_key TEXT NOT NULL UNIQUE,
  token       TEXT NOT NULL,        -- PASETO v4.public (public par nature, signé)
  kid         TEXT NOT NULL,
  issued_at   TEXT NOT NULL,
  expires_at  TEXT,
  options     TEXT NOT NULL DEFAULT '{}',
  status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired'))
);

CREATE TABLE revocations (
  license_id  TEXT PRIMARY KEY REFERENCES licenses(id),
  reason      TEXT NOT NULL DEFAULT '',
  revoked_at  TEXT NOT NULL,
  published_seq INTEGER           -- numéro de la liste publiée qui l'inclut
);

CREATE TABLE revocation_lists (
  seq         INTEGER PRIMARY KEY,
  token       TEXT NOT NULL,
  published_at TEXT
);

CREATE TABLE media_assets (
  id          TEXT PRIMARY KEY,
  app_id      TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  provider    TEXT NOT NULL,
  path        TEXT NOT NULL,
  url         TEXT NOT NULL,
  bytes       INTEGER NOT NULL,
  width       INTEGER,
  height      INTEGER,
  created_at  TEXT NOT NULL
);

CREATE TABLE repo_events (
  id          TEXT PRIMARY KEY,     -- type:sha / type:id
  app_id      TEXT REFERENCES apps(id) ON DELETE CASCADE,
  repo        TEXT NOT NULL,
  kind        TEXT NOT NULL,        -- commit | branch | pull_request | workflow_run | release
  title       TEXT NOT NULL,
  author      TEXT,
  ref_name    TEXT,
  status      TEXT,
  url         TEXT,
  occurred_at TEXT NOT NULL,
  notified    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX repo_events_app ON repo_events(app_id, occurred_at DESC);

CREATE TABLE poll_state (
  key   TEXT PRIMARY KEY,           -- URL interrogée
  etag  TEXT,
  last_polled_at TEXT
);

CREATE TABLE sync_events (
  id          TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL,
  hlc         TEXT NOT NULL,
  entity      TEXT NOT NULL,        -- table
  entity_id   TEXT NOT NULL,
  op          TEXT NOT NULL CHECK (op IN ('upsert','delete')),
  payload     TEXT NOT NULL,        -- JSON (en clair DANS la base chiffrée)
  base_hlc    TEXT,
  pushed      INTEGER NOT NULL DEFAULT 0,
  applied     INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL
);
CREATE INDEX sync_events_entity ON sync_events(entity, entity_id, hlc);

CREATE TABLE sync_records (
  entity      TEXT NOT NULL,
  entity_id   TEXT NOT NULL,
  hlc         TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  deleted     INTEGER NOT NULL DEFAULT 0,
  payload     TEXT NOT NULL,
  PRIMARY KEY(entity, entity_id)
);

CREATE TABLE sync_conflicts (
  id          TEXT PRIMARY KEY,
  entity      TEXT NOT NULL,
  entity_id   TEXT NOT NULL,
  winner_event TEXT NOT NULL,
  loser_event TEXT NOT NULL,
  loser_payload TEXT NOT NULL,
  resolved    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);

CREATE TABLE audit_logs (
  seq         INTEGER PRIMARY KEY,  -- strictement croissant
  ts          TEXT NOT NULL,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  details     TEXT NOT NULL DEFAULT '{}',
  outcome     TEXT NOT NULL DEFAULT 'ok',
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_logs
BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_logs
BEGIN SELECT RAISE(ABORT, 'audit_logs is append-only'); END;

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Fallback (mobile / pas de trousseau) : valeur chiffrée XChaCha20-Poly1305
-- avec une sous-clé dérivée de la phrase secrète, DANS la base SQLCipher (double chiffrement).
CREATE TABLE secret_blobs (
  id    TEXT PRIMARY KEY,
  blob  BLOB NOT NULL
);

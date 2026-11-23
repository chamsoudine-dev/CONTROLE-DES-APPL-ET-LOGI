//! Coffre local : phrase secrète (Argon2id) → clé SQLCipher, 2FA TOTP, PIN, verrouillage auto,
//! ré-authentification pour les actions sensibles.
use crate::crypto::{self, KdfParams, Key32};
use crate::secrets::{EncryptedDbSecretStore, SecretStore, SecretValue};
use crate::{audit, db, now_rfc3339, profile, CoreError, Result};
use parking_lot::Mutex;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

const HEADER_FILE: &str = "vault.json";
const DB_FILE: &str = "control-center.db";
const VERIFIER_LABEL: &[u8] = b"cc-verifier-v1";
pub const PIN_MAX_ATTEMPTS: u32 = 5;
/// Durée de validité d'une ré-authentification.
pub const REAUTH_WINDOW: Duration = Duration::from_secs(120);
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// En-tête non secret du coffre (sel, paramètres, vérificateur).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultHeader {
    pub version: u32,
    pub vault_id: String,
    pub device_id: String,
    pub kdf: KdfParams,
    pub salt: String,
    pub verifier: String,
    pub created_at: String,
}

/// Configuration du coffre.
pub struct VaultConfig {
    pub dir: PathBuf,
    pub kdf: KdfParams,
    /// Trousseau OS (None = indisponible → secrets chiffrés en base, PIN indisponible).
    pub os_store: Option<Arc<dyn SecretStore>>,
}

/// Session déverrouillée.
pub struct Session {
    pub conn: Arc<Mutex<Connection>>,
    master: Key32,
    pub secrets: Arc<dyn SecretStore>,
    pub vault_id: String,
    pub device_id: String,
    pub profile_id: String,
    pub actor: String,
    last_activity: Instant,
    last_reauth: Option<Instant>,
    pending_totp_secret: Option<Zeroizing<Vec<u8>>>,
}

impl Session {
    /// Sous-clé dérivée de la clé maîtresse (séparation de domaines).
    pub fn subkey(&self, label: &str) -> Key32 {
        crypto::subkey(&self.master, label)
    }

    /// Inscrit une action au journal d'audit.
    pub fn audit(
        &self,
        action: &str,
        target: &str,
        details: &serde_json::Value,
        outcome: &str,
    ) -> Result<()> {
        audit::append(
            &self.conn.lock(),
            &self.actor,
            action,
            target,
            details,
            outcome,
        )
        .map(|_| ())
    }

    pub fn has_recent_reauth_at(&self, now: Instant) -> bool {
        self.last_reauth
            .is_some_and(|t| now.saturating_duration_since(t) <= REAUTH_WINDOW)
    }

    pub fn ensure_recent_reauth(&self) -> Result<()> {
        if self.has_recent_reauth_at(Instant::now()) {
            Ok(())
        } else {
            Err(CoreError::ReauthRequired)
        }
    }
}

enum State {
    Uninitialized,
    Locked,
    PendingTotp(Box<Session>),
    Unlocked(Box<Session>),
}

/// Étape renvoyée par le déverrouillage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnlockStep {
    Unlocked,
    TotpRequired,
}

/// État visible par l'interface.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VaultStatus {
    pub state: &'static str,
    pub pin_available: bool,
    pub secret_backend: &'static str,
    pub autolock_secs: Option<u32>,
}

/// Matériel d'enrôlement TOTP (affiché une seule fois).
#[derive(Clone, Serialize)]
pub struct TotpSetup {
    pub secret_base32: String,
    pub otpauth_url: String,
    pub qr_png_base64: String,
}

impl std::fmt::Debug for TotpSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpSetup(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
struct PinWrap {
    salt: String,
    blob: String,
    attempts_left: u32,
}

pub struct Vault {
    cfg: VaultConfig,
    header: Option<VaultHeader>,
    state: State,
}

/// Valide la robustesse de la phrase secrète.
pub fn check_passphrase_strength(p: &str) -> Result<()> {
    let n = p.chars().count();
    if n < MIN_PASSPHRASE_CHARS {
        return Err(CoreError::WeakPassphrase(format!(
            "au moins {MIN_PASSPHRASE_CHARS} caractères"
        )));
    }
    let distinct: std::collections::HashSet<char> = p.chars().collect();
    if distinct.len() < 5 {
        return Err(CoreError::WeakPassphrase("trop répétitive".into()));
    }
    let lower = p.to_lowercase();
    for common in [
        "password",
        "motdepasse",
        "123456789",
        "azertyuiop",
        "qwertyuiop",
    ] {
        if lower.contains(common) {
            return Err(CoreError::WeakPassphrase(
                "contient une suite trop courante".into(),
            ));
        }
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn totp_for(secret: &[u8], account: &str) -> Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret.to_vec(),
        Some("Control Center".to_string()),
        account.to_string(),
    )
    .map_err(|e| CoreError::Validation(e.to_string()))
}

impl Vault {
    pub fn open(cfg: VaultConfig) -> Result<Self> {
        std::fs::create_dir_all(&cfg.dir)?;
        let hp = cfg.dir.join(HEADER_FILE);
        let header = if hp.exists() {
            let raw = std::fs::read(&hp)?;
            Some(
                serde_json::from_slice::<VaultHeader>(&raw)
                    .map_err(|_| CoreError::Integrity("vault.json illisible".into()))?,
            )
        } else {
            None
        };
        let state = if header.is_some() {
            State::Locked
        } else {
            State::Uninitialized
        };
        Ok(Self { cfg, header, state })
    }

    pub fn dir(&self) -> &Path {
        &self.cfg.dir
    }

    pub fn db_path(&self) -> PathBuf {
        self.cfg.dir.join(DB_FILE)
    }

    pub fn header(&self) -> Option<&VaultHeader> {
        self.header.as_ref()
    }

    pub fn status(&self) -> VaultStatus {
        let state = match self.state {
            State::Uninitialized => "uninitialized",
            State::Locked => "locked",
            State::PendingTotp(_) => "totp_required",
            State::Unlocked(_) => "unlocked",
        };
        let autolock_secs = self
            .session()
            .ok()
            .and_then(|s| profile::get(&s.conn.lock(), &s.profile_id).ok())
            .map(|p| p.autolock_secs);
        VaultStatus {
            state,
            pin_available: self.pin_configured(),
            secret_backend: self
                .cfg
                .os_store
                .as_ref()
                .map_or("base chiffrée (fallback)", |s| s.backend_name()),
            autolock_secs,
        }
    }

    fn os_key(&self, name: &str) -> String {
        let id = self.header.as_ref().map_or("none", |h| h.vault_id.as_str());
        format!("{id}:{name}")
    }

    fn pin_configured(&self) -> bool {
        self.cfg
            .os_store
            .as_ref()
            .and_then(|s| s.get(&self.os_key("pin-wrap")).ok().flatten())
            .is_some()
    }

    /// Crée le coffre : en-tête, base chiffrée, profil, appareil courant. Laisse le coffre déverrouillé.
    pub fn setup(&mut self, display_name: &str, passphrase: &str) -> Result<()> {
        if !matches!(self.state, State::Uninitialized) {
            return Err(CoreError::AlreadyInitialized);
        }
        let display_name = display_name.trim();
        if display_name.is_empty() || display_name.chars().count() > 80 {
            return Err(CoreError::Validation(
                "nom affiché : 1 à 80 caractères".into(),
            ));
        }
        check_passphrase_strength(passphrase)?;
        let salt = crypto::random_bytes::<16>();
        let master = crypto::derive_key(passphrase.as_bytes(), &salt, self.cfg.kdf)?;
        let header = VaultHeader {
            version: 1,
            vault_id: uuid::Uuid::new_v4().to_string(),
            device_id: uuid::Uuid::new_v4().to_string(),
            kdf: self.cfg.kdf,
            salt: crypto::b64(&salt),
            verifier: crypto::b64(&crypto::hmac_sha256(&*master, VERIFIER_LABEL)),
            created_at: now_rfc3339(),
        };
        let dbp = self.db_path();
        if dbp.exists() {
            return Err(CoreError::AlreadyInitialized);
        }
        let mut conn = db::open(&dbp, &crypto::subkey(&master, "db"))?;
        db::migrate(&mut conn)?;
        let profile_id = profile::create(&conn, display_name, &header.device_id)?;
        write_atomic(
            &self.cfg.dir.join(HEADER_FILE),
            &serde_json::to_vec_pretty(&header)?,
        )?;
        self.header = Some(header);
        let session = self.make_session(conn, master, profile_id)?;
        session.audit("vault.create", "", &serde_json::json!({}), "ok")?;
        self.state = State::Unlocked(Box::new(session));
        Ok(())
    }

    fn make_session(&self, conn: Connection, master: Key32, profile_id: String) -> Result<Session> {
        let h = self.header.as_ref().ok_or(CoreError::NotInitialized)?;
        let conn = Arc::new(Mutex::new(conn));
        let secrets: Arc<dyn SecretStore> = match &self.cfg.os_store {
            Some(os) => Arc::new(NamespacedStore {
                inner: os.clone(),
                prefix: format!("{}:secret:", h.vault_id),
            }),
            None => Arc::new(EncryptedDbSecretStore::new(
                conn.clone(),
                crypto::subkey(&master, "secrets-fallback"),
            )),
        };
        Ok(Session {
            conn,
            master,
            secrets,
            vault_id: h.vault_id.clone(),
            device_id: h.device_id.clone(),
            profile_id,
            actor: "owner".into(),
            last_activity: Instant::now(),
            last_reauth: None,
            pending_totp_secret: None,
        })
    }

    fn derive_and_check(&self, passphrase: &str) -> Result<Key32> {
        let h = self.header.as_ref().ok_or(CoreError::NotInitialized)?;
        let salt = crypto::unb64(&h.salt)?;
        let master = crypto::derive_key(passphrase.as_bytes(), &salt, h.kdf)?;
        let expected = crypto::unb64(&h.verifier)?;
        if !crypto::ct_eq(&crypto::hmac_sha256(&*master, VERIFIER_LABEL), &expected) {
            return Err(CoreError::InvalidPassphrase);
        }
        Ok(master)
    }

    fn open_session(&self, master: Key32) -> Result<Session> {
        let mut conn = db::open(&self.db_path(), &crypto::subkey(&master, "db"))?;
        db::migrate(&mut conn)?;
        let profile_id = profile::current_id(&conn)?;
        self.make_session(conn, master, profile_id)
    }

    /// Déverrouillage par phrase secrète. Si la 2FA est active, passe en attente du code.
    pub fn unlock(&mut self, passphrase: &str) -> Result<UnlockStep> {
        match self.state {
            State::Uninitialized => return Err(CoreError::NotInitialized),
            State::Unlocked(_) => return Ok(UnlockStep::Unlocked),
            _ => {}
        }
        let master = self.derive_and_check(passphrase)?;
        let session = self.open_session(master)?;
        let totp_enabled = profile::get(&session.conn.lock(), &session.profile_id)?.totp_enabled;
        if totp_enabled {
            self.state = State::PendingTotp(Box::new(session));
            Ok(UnlockStep::TotpRequired)
        } else {
            session.audit(
                "vault.unlock",
                "",
                &serde_json::json!({"method":"passphrase"}),
                "ok",
            )?;
            self.state = State::Unlocked(Box::new(session));
            Ok(UnlockStep::Unlocked)
        }
    }

    /// Termine le déverrouillage avec le code TOTP.
    pub fn complete_totp(&mut self, code: &str) -> Result<()> {
        self.complete_totp_at(code, unix_now())
    }

    pub fn complete_totp_at(&mut self, code: &str, unix: u64) -> Result<()> {
        let State::PendingTotp(session) = &self.state else {
            return Err(CoreError::Locked);
        };
        if !Self::check_totp(session, code, unix)? {
            session.audit(
                "vault.unlock",
                "",
                &serde_json::json!({"method":"totp"}),
                "denied",
            )?;
            return Err(CoreError::InvalidTotp);
        }
        let State::PendingTotp(session) = std::mem::replace(&mut self.state, State::Locked) else {
            unreachable!()
        };
        session.audit(
            "vault.unlock",
            "",
            &serde_json::json!({"method":"passphrase+totp"}),
            "ok",
        )?;
        self.state = State::Unlocked(session);
        Ok(())
    }

    fn check_totp(session: &Session, code: &str, unix: u64) -> Result<bool> {
        let p = profile::get(&session.conn.lock(), &session.profile_id)?;
        let Some(secret) = p.totp_secret else {
            return Ok(true);
        };
        let bytes = Secret::Encoded(secret)
            .to_bytes()
            .map_err(|_| CoreError::Integrity("secret TOTP".into()))?;
        let code = code.trim();
        if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }
        Ok(totp_for(&bytes, &p.display_name)?.check(code, unix))
    }

    pub fn lock(&mut self) {
        if let State::Unlocked(s) | State::PendingTotp(s) = &self.state {
            let _ = s.audit("vault.lock", "", &serde_json::json!({}), "ok");
        }
        if !matches!(self.state, State::Uninitialized) {
            // La session (clé maîtresse Zeroizing, connexion) est détruite ici.
            self.state = State::Locked;
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, State::Unlocked(_))
    }

    pub fn session(&self) -> Result<&Session> {
        match &self.state {
            State::Unlocked(s) => Ok(s),
            State::Uninitialized => Err(CoreError::NotInitialized),
            _ => Err(CoreError::Locked),
        }
    }

    pub fn session_mut(&mut self) -> Result<&mut Session> {
        match &mut self.state {
            State::Unlocked(s) => Ok(s),
            State::Uninitialized => Err(CoreError::NotInitialized),
            _ => Err(CoreError::Locked),
        }
    }

    /// Enregistre une activité de l'utilisateur.
    pub fn touch_at(&mut self, now: Instant) {
        if let Ok(s) = self.session_mut() {
            s.last_activity = now;
        }
    }

    /// Verrouille si l'inactivité dépasse le délai du profil. Renvoie `true` si verrouillé.
    pub fn autolock_if_idle_at(&mut self, now: Instant) -> bool {
        let Ok(s) = self.session() else {
            return false;
        };
        let secs = profile::get(&s.conn.lock(), &s.profile_id).map_or(300, |p| p.autolock_secs);
        if secs > 0
            && now.saturating_duration_since(s.last_activity) >= Duration::from_secs(secs.into())
        {
            self.lock();
            return true;
        }
        false
    }

    /// Ré-authentification (phrase secrète + TOTP si actif) pour les actions sensibles.
    pub fn reauth(&mut self, passphrase: &str, totp: Option<&str>) -> Result<()> {
        self.reauth_at(passphrase, totp, unix_now(), Instant::now())
    }

    pub fn reauth_at(
        &mut self,
        passphrase: &str,
        totp: Option<&str>,
        unix: u64,
        now: Instant,
    ) -> Result<()> {
        self.session()?;
        let result = (|| {
            self.derive_and_check(passphrase)?;
            let s = self.session()?;
            let enabled = profile::get(&s.conn.lock(), &s.profile_id)?.totp_enabled;
            if enabled {
                let code = totp.ok_or(CoreError::TotpRequired)?;
                if !Self::check_totp(s, code, unix)? {
                    return Err(CoreError::InvalidTotp);
                }
            }
            Ok(())
        })();
        let s = self.session_mut()?;
        match &result {
            Ok(()) => {
                s.last_reauth = Some(now);
                s.audit("auth.reauth", "", &serde_json::json!({}), "ok")?;
            }
            Err(e) => s.audit(
                "auth.reauth",
                "",
                &serde_json::json!({"error": e.code()}),
                "denied",
            )?,
        }
        result
    }

    // ---------- TOTP ----------

    /// Commence l'enrôlement TOTP : renvoie le QR code (le secret n'est enregistré qu'après confirmation).
    pub fn totp_begin(&mut self) -> Result<TotpSetup> {
        let s = self.session_mut()?;
        let name = profile::get(&s.conn.lock(), &s.profile_id)?.display_name;
        let Secret::Raw(raw) = Secret::generate_secret()
            .to_raw()
            .map_err(|_| CoreError::Crypto)?
        else {
            return Err(CoreError::Crypto);
        };
        let totp = totp_for(&raw, &name)?;
        let setup = TotpSetup {
            secret_base32: totp.get_secret_base32(),
            otpauth_url: totp.get_url(),
            qr_png_base64: totp.get_qr_base64().map_err(CoreError::Validation)?,
        };
        s.pending_totp_secret = Some(Zeroizing::new(raw));
        Ok(setup)
    }

    pub fn totp_confirm(&mut self, code: &str) -> Result<()> {
        self.totp_confirm_at(code, unix_now())
    }

    pub fn totp_confirm_at(&mut self, code: &str, unix: u64) -> Result<()> {
        let s = self.session_mut()?;
        let raw = s.pending_totp_secret.clone().ok_or(CoreError::Validation(
            "aucun enrôlement TOTP en cours".into(),
        ))?;
        let name = profile::get(&s.conn.lock(), &s.profile_id)?.display_name;
        if !totp_for(&raw, &name)?.check(code.trim(), unix) {
            return Err(CoreError::InvalidTotp);
        }
        let b32 = Secret::Raw(raw.to_vec()).to_encoded().to_string();
        profile::set_totp(&s.conn.lock(), &s.profile_id, Some(&b32))?;
        s.pending_totp_secret = None;
        s.audit("auth.totp.enable", "", &serde_json::json!({}), "ok")
    }

    /// Désactive la 2FA (exige une ré-authentification récente).
    pub fn totp_disable(&mut self) -> Result<()> {
        let s = self.session()?;
        s.ensure_recent_reauth()?;
        profile::set_totp(&s.conn.lock(), &s.profile_id, None)?;
        s.audit("auth.totp.disable", "", &serde_json::json!({}), "ok")
    }

    // ---------- PIN ----------

    /// Définit un PIN (6 à 12 chiffres) qui enveloppe la clé maîtresse dans le trousseau OS.
    pub fn set_pin(&mut self, pin: &str) -> Result<()> {
        if !(6..=12).contains(&pin.len()) || !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err(CoreError::Validation(
                "le PIN doit contenir 6 à 12 chiffres".into(),
            ));
        }
        let os = self.cfg.os_store.clone().ok_or(CoreError::PinUnavailable)?;
        let kdf = self.header.as_ref().ok_or(CoreError::NotInitialized)?.kdf;
        let s = self.session()?;
        let salt = crypto::random_bytes::<16>();
        let pin_key = crypto::derive_key(pin.as_bytes(), &salt, kdf)?;
        let wrap = PinWrap {
            salt: crypto::b64(&salt),
            blob: crypto::b64(&crypto::seal(&pin_key, &*s.master, b"cc-pin-wrap")?),
            attempts_left: PIN_MAX_ATTEMPTS,
        };
        let json = Zeroizing::new(serde_json::to_string(&wrap)?);
        os.put(&self.os_key("pin-wrap"), &SecretValue::new(json.as_str()))?;
        s.audit("auth.pin.set", "", &serde_json::json!({}), "ok")
    }

    pub fn remove_pin(&mut self) -> Result<()> {
        let s = self.session()?;
        if let Some(os) = &self.cfg.os_store {
            os.delete(&self.os_key("pin-wrap"))?;
        }
        s.audit("auth.pin.remove", "", &serde_json::json!({}), "ok")
    }

    /// Déverrouillage par PIN. Après `PIN_MAX_ATTEMPTS` échecs, l'enveloppe est détruite.
    pub fn unlock_with_pin(&mut self, pin: &str) -> Result<()> {
        if matches!(self.state, State::Uninitialized) {
            return Err(CoreError::NotInitialized);
        }
        let os = self.cfg.os_store.clone().ok_or(CoreError::PinUnavailable)?;
        let key = self.os_key("pin-wrap");
        let stored = os.get(&key)?.ok_or(CoreError::PinLocked)?;
        let mut wrap: PinWrap = serde_json::from_str(stored.expose())
            .map_err(|_| CoreError::Integrity("enveloppe PIN".into()))?;
        let kdf = self.header.as_ref().ok_or(CoreError::NotInitialized)?.kdf;
        let pin_key = crypto::derive_key(pin.as_bytes(), &crypto::unb64(&wrap.salt)?, kdf)?;
        match crypto::open(&pin_key, &crypto::unb64(&wrap.blob)?, b"cc-pin-wrap") {
            Ok(pt) if pt.len() == 32 => {
                let mut master = Zeroizing::new([0u8; 32]);
                master.copy_from_slice(&pt);
                let session = self.open_session(master)?;
                if wrap.attempts_left != PIN_MAX_ATTEMPTS {
                    wrap.attempts_left = PIN_MAX_ATTEMPTS;
                    os.put(&key, &SecretValue::new(serde_json::to_string(&wrap)?))?;
                }
                session.audit(
                    "vault.unlock",
                    "",
                    &serde_json::json!({"method":"pin"}),
                    "ok",
                )?;
                self.state = State::Unlocked(Box::new(session));
                Ok(())
            }
            _ => {
                wrap.attempts_left = wrap.attempts_left.saturating_sub(1);
                if wrap.attempts_left == 0 {
                    os.delete(&key)?;
                    return Err(CoreError::PinLocked);
                }
                os.put(&key, &SecretValue::new(serde_json::to_string(&wrap)?))?;
                Err(CoreError::InvalidPin(wrap.attempts_left))
            }
        }
    }

    // ---------- Phrase secrète ----------

    /// Change la phrase secrète : nouveau sel, re-chiffrement SQLCipher (`rekey`), secrets de
    /// secours re-chiffrés, PIN supprimé (à redéfinir).
    pub fn change_passphrase(&mut self, old: &str, new: &str) -> Result<()> {
        self.session()?;
        let old_master = self.derive_and_check(old)?;
        check_passphrase_strength(new)?;
        let kdf = self.cfg.kdf;
        let salt = crypto::random_bytes::<16>();
        let new_master = crypto::derive_key(new.as_bytes(), &salt, kdf)?;
        {
            let s = self.session()?;
            // Re-chiffre les secrets du fallback avec la nouvelle sous-clé.
            if self.cfg.os_store.is_none() {
                let old_store = EncryptedDbSecretStore::new(
                    s.conn.clone(),
                    crypto::subkey(&old_master, "secrets-fallback"),
                );
                let new_store = EncryptedDbSecretStore::new(
                    s.conn.clone(),
                    crypto::subkey(&new_master, "secrets-fallback"),
                );
                let ids: Vec<String> = {
                    let c = s.conn.lock();
                    let mut st = c.prepare("SELECT id FROM secret_blobs")?;
                    let v = st
                        .query_map([], |r| r.get(0))?
                        .collect::<std::result::Result<_, _>>()?;
                    v
                };
                for id in ids {
                    if let Some(v) = old_store.get(&id)? {
                        new_store.put(&id, &v)?;
                    }
                }
            }
            db::rekey(&s.conn.lock(), &crypto::subkey(&new_master, "db"))?;
        }
        let h = self.header.as_mut().ok_or(CoreError::NotInitialized)?;
        h.salt = crypto::b64(&salt);
        h.kdf = kdf;
        h.verifier = crypto::b64(&crypto::hmac_sha256(&*new_master, VERIFIER_LABEL));
        let bytes = serde_json::to_vec_pretty(h)?;
        write_atomic(&self.cfg.dir.join(HEADER_FILE), &bytes)?;
        if let Some(os) = &self.cfg.os_store {
            os.delete(&self.os_key("pin-wrap"))?;
        }
        let os_store = self.cfg.os_store.clone();
        let s = self.session_mut()?;
        s.master = new_master;
        if os_store.is_none() {
            s.secrets = Arc::new(EncryptedDbSecretStore::new(
                s.conn.clone(),
                crypto::subkey(&s.master, "secrets-fallback"),
            ));
        }
        s.audit("auth.passphrase.change", "", &serde_json::json!({}), "ok")
    }

    /// Vérifie une phrase secrète sans changer l'état (utilisé pour la sync et les sauvegardes).
    pub fn verify_passphrase(&self, passphrase: &str) -> Result<()> {
        self.derive_and_check(passphrase).map(|_| ())
    }
}

/// Préfixe les identifiants dans le trousseau OS pour isoler chaque coffre.
struct NamespacedStore {
    inner: Arc<dyn SecretStore>,
    prefix: String,
}

impl SecretStore for NamespacedStore {
    fn put(&self, id: &str, value: &SecretValue) -> Result<()> {
        self.inner.put(&format!("{}{id}", self.prefix), value)
    }
    fn get(&self, id: &str) -> Result<Option<SecretValue>> {
        self.inner.get(&format!("{}{id}", self.prefix))
    }
    fn delete(&self, id: &str) -> Result<()> {
        self.inner.delete(&format!("{}{id}", self.prefix))
    }
    fn backend_name(&self) -> &'static str {
        self.inner.backend_name()
    }
}

/// Écriture atomique (fichier temporaire + renommage).
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::secrets::MemorySecretStore;

    pub const PASS: &str = "correct horse battery staple";

    pub fn cfg(dir: &Path, os: bool) -> VaultConfig {
        VaultConfig {
            dir: dir.to_path_buf(),
            kdf: KdfParams::INSECURE_FAST_FOR_TESTS,
            os_store: os.then(|| Arc::new(MemorySecretStore::default()) as Arc<dyn SecretStore>),
        }
    }

    pub fn new_vault(dir: &Path, os: bool) -> Vault {
        let mut v = Vault::open(cfg(dir, os)).unwrap();
        v.setup("Chamsoudine", PASS).unwrap();
        v
    }

    #[test]
    fn passphrase_strength() {
        assert!(check_passphrase_strength("short").is_err());
        assert!(check_passphrase_strength("aaaaaaaaaaaaaaaa").is_err());
        assert!(check_passphrase_strength("myPassword-2024!").is_err());
        assert!(check_passphrase_strength(PASS).is_ok());
    }

    #[test]
    fn setup_lock_unlock() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        assert_eq!(v.status().state, "unlocked");
        assert!(matches!(
            v.setup("x", PASS),
            Err(CoreError::AlreadyInitialized)
        ));
        v.lock();
        assert_eq!(v.status().state, "locked");
        assert!(matches!(v.session(), Err(CoreError::Locked)));
        assert!(matches!(
            v.unlock("wrong passphrase!!"),
            Err(CoreError::InvalidPassphrase)
        ));
        assert_eq!(v.unlock(PASS).unwrap(), UnlockStep::Unlocked);
        // Réouverture depuis le disque.
        drop(v);
        let mut v2 = Vault::open(cfg(d.path(), false)).unwrap();
        assert_eq!(v2.status().state, "locked");
        v2.unlock(PASS).unwrap();
        let s = v2.session().unwrap();
        let p = profile::get(&s.conn.lock(), &s.profile_id).unwrap();
        assert_eq!(p.display_name, "Chamsoudine");
        assert!(crate::audit::verify_chain(&s.conn.lock()).unwrap().entries >= 3);
    }

    #[test]
    fn uninitialized_errors_and_validation() {
        let d = tempfile::tempdir().unwrap();
        let mut v = Vault::open(cfg(d.path(), false)).unwrap();
        assert_eq!(v.status().state, "uninitialized");
        assert!(matches!(v.unlock(PASS), Err(CoreError::NotInitialized)));
        assert!(matches!(
            v.unlock_with_pin("123456"),
            Err(CoreError::NotInitialized)
        ));
        assert!(matches!(v.session(), Err(CoreError::NotInitialized)));
        assert!(v.setup("  ", PASS).is_err());
        assert!(v.setup("ok", "weak").is_err());
        v.lock();
        assert_eq!(v.status().state, "uninitialized");
    }

    #[test]
    fn lock_wipes_session() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        let weak = Arc::downgrade(&v.session().unwrap().conn);
        v.lock();
        assert!(
            weak.upgrade().is_none(),
            "connexion et clé détruites au verrouillage"
        );
    }

    #[test]
    fn autolock() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        let t0 = Instant::now();
        v.touch_at(t0);
        assert!(!v.autolock_if_idle_at(t0 + Duration::from_secs(299)));
        assert!(v.autolock_if_idle_at(t0 + Duration::from_secs(300)));
        assert!(!v.is_unlocked());
        assert!(!v.autolock_if_idle_at(t0 + Duration::from_secs(900)));
        v.unlock(PASS).unwrap();
        {
            let s = v.session().unwrap();
            profile::set_autolock(&s.conn.lock(), &s.profile_id, 0).unwrap();
        }
        assert!(!v.autolock_if_idle_at(Instant::now() + Duration::from_secs(100_000)));
        assert_eq!(v.status().autolock_secs, Some(0));
    }

    fn totp_code(v: &Vault, setup: &TotpSetup, unix: u64) -> String {
        let _ = v;
        let raw = Secret::Encoded(setup.secret_base32.clone())
            .to_bytes()
            .unwrap();
        totp_for(&raw, "Chamsoudine").unwrap().generate(unix)
    }

    #[test]
    fn totp_required() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        assert!(
            v.totp_confirm_at("000000", 0).is_err(),
            "pas d'enrôlement en cours"
        );
        let setup = v.totp_begin().unwrap();
        assert!(setup.otpauth_url.starts_with("otpauth://totp/"));
        assert!(!setup.qr_png_base64.is_empty());
        assert!(!format!("{setup:?}").contains(&setup.secret_base32));
        let t = 1_800_000_000;
        let good = totp_code(&v, &setup, t);
        let wrong = if good == "123456" { "654321" } else { "123456" };
        assert!(matches!(
            v.totp_confirm_at(wrong, t),
            Err(CoreError::InvalidTotp)
        ));
        v.totp_confirm_at(&good, t).unwrap();
        v.lock();
        assert_eq!(v.unlock(PASS).unwrap(), UnlockStep::TotpRequired);
        assert_eq!(v.status().state, "totp_required");
        assert!(matches!(v.session(), Err(CoreError::Locked)));
        assert!(matches!(
            v.complete_totp_at("abc", t),
            Err(CoreError::InvalidTotp)
        ));
        assert!(matches!(
            v.complete_totp_at(wrong, t),
            Err(CoreError::InvalidTotp)
        ));
        v.complete_totp_at(&totp_code(&v, &setup, t), t).unwrap();
        assert!(v.is_unlocked());
        // Ré-auth : TOTP exigé.
        let now = Instant::now();
        assert!(matches!(
            v.reauth_at(PASS, None, t, now),
            Err(CoreError::TotpRequired)
        ));
        assert!(matches!(
            v.reauth_at(PASS, Some(wrong), t, now),
            Err(CoreError::InvalidTotp)
        ));
        v.reauth_at(PASS, Some(&totp_code(&v, &setup, t)), t, now)
            .unwrap();
        v.totp_disable().unwrap();
        v.lock();
        assert_eq!(v.unlock(PASS).unwrap(), UnlockStep::Unlocked);
    }

    #[test]
    fn reauth_window() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        assert!(matches!(
            v.session().unwrap().ensure_recent_reauth(),
            Err(CoreError::ReauthRequired)
        ));
        assert!(matches!(
            v.reauth("bad bad bad bad", None),
            Err(CoreError::InvalidPassphrase)
        ));
        let t0 = Instant::now();
        v.reauth_at(PASS, None, 0, t0).unwrap();
        let s = v.session().unwrap();
        assert!(s.has_recent_reauth_at(t0 + Duration::from_secs(119)));
        assert!(!s.has_recent_reauth_at(t0 + Duration::from_secs(121)));
        s.ensure_recent_reauth().unwrap();
    }

    #[test]
    fn pin_unlock_and_lockout() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), true);
        assert!(v.set_pin("12ab").is_err());
        v.set_pin("246810").unwrap();
        assert!(v.status().pin_available);
        v.lock();
        assert!(matches!(
            v.unlock_with_pin("000000"),
            Err(CoreError::InvalidPin(4))
        ));
        v.unlock_with_pin("246810").unwrap();
        assert!(v.is_unlocked());
        v.lock();
        for left in (1..PIN_MAX_ATTEMPTS).rev() {
            assert!(
                matches!(v.unlock_with_pin("111111"), Err(CoreError::InvalidPin(n)) if n == left)
            );
        }
        assert!(matches!(
            v.unlock_with_pin("111111"),
            Err(CoreError::PinLocked)
        ));
        // Même le bon PIN ne marche plus : phrase secrète obligatoire.
        assert!(matches!(
            v.unlock_with_pin("246810"),
            Err(CoreError::PinLocked)
        ));
        assert!(!v.status().pin_available);
        v.unlock(PASS).unwrap();
        v.set_pin("135790").unwrap();
        v.remove_pin().unwrap();
        assert!(!v.status().pin_available);
    }

    #[test]
    fn pin_unavailable_without_os_store() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        assert!(matches!(
            v.set_pin("123456"),
            Err(CoreError::PinUnavailable)
        ));
        v.lock();
        assert!(matches!(
            v.unlock_with_pin("123456"),
            Err(CoreError::PinUnavailable)
        ));
    }

    #[test]
    fn change_passphrase_keeps_data() {
        for os in [false, true] {
            let d = tempfile::tempdir().unwrap();
            let mut v = new_vault(d.path(), os);
            v.session()
                .unwrap()
                .secrets
                .put("k", &SecretValue::new("value-123456789"))
                .unwrap();
            if os {
                v.set_pin("123456").unwrap();
            }
            assert!(v
                .change_passphrase("wrong wrong wrong", "new passphrase here!")
                .is_err());
            assert!(v.change_passphrase(PASS, "weak").is_err());
            v.change_passphrase(PASS, "new passphrase here!").unwrap();
            assert_eq!(
                v.session()
                    .unwrap()
                    .secrets
                    .get("k")
                    .unwrap()
                    .unwrap()
                    .expose(),
                "value-123456789"
            );
            assert!(!v.status().pin_available, "PIN invalidé");
            v.lock();
            assert!(v.unlock(PASS).is_err());
            v.unlock("new passphrase here!").unwrap();
            assert_eq!(
                v.session()
                    .unwrap()
                    .secrets
                    .get("k")
                    .unwrap()
                    .unwrap()
                    .expose(),
                "value-123456789"
            );
            v.verify_passphrase("new passphrase here!").unwrap();
        }
    }

    #[test]
    fn corrupted_header_detected() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(HEADER_FILE), b"{not json").unwrap();
        assert!(matches!(
            Vault::open(cfg(d.path(), false)),
            Err(CoreError::Integrity(_))
        ));
    }
}

//! Valeurs secrètes et stockage (trousseau OS ou fallback chiffré).
use crate::{crypto, CoreError, Result};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Valeur secrète : effacée de la mémoire à la destruction, jamais affichée ni sérialisée.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Accès explicite à la valeur (à n'utiliser que pour l'envoyer au fournisseur).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Masque `••••1234` (4 derniers caractères, ou moins si la valeur est courte).
    pub fn masked(&self) -> String {
        mask_last4(&self.last4())
    }

    pub fn last4(&self) -> String {
        let n = self.0.chars().count();
        if n <= 8 {
            // Valeur courte : ne rien révéler.
            return String::new();
        }
        self.0.chars().skip(n - 4).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub fn mask_last4(last4: &str) -> String {
    format!("••••{last4}")
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// Stockage des valeurs secrètes (le reste — métadonnées — est en base).
pub trait SecretStore: Send + Sync {
    fn put(&self, id: &str, value: &SecretValue) -> Result<()>;
    fn get(&self, id: &str) -> Result<Option<SecretValue>>;
    fn delete(&self, id: &str) -> Result<()>;
    /// Nom affiché dans les paramètres.
    fn backend_name(&self) -> &'static str;
}

/// Stockage en mémoire (tests).
#[derive(Default)]
pub struct MemorySecretStore {
    map: Mutex<HashMap<String, SecretValue>>,
}

impl SecretStore for MemorySecretStore {
    fn put(&self, id: &str, value: &SecretValue) -> Result<()> {
        self.map.lock().insert(id.to_owned(), value.clone());
        Ok(())
    }
    fn get(&self, id: &str) -> Result<Option<SecretValue>> {
        Ok(self.map.lock().get(id).cloned())
    }
    fn delete(&self, id: &str) -> Result<()> {
        self.map.lock().remove(id);
        Ok(())
    }
    fn backend_name(&self) -> &'static str {
        "mémoire (tests)"
    }
}

/// Fallback : valeur chiffrée XChaCha20-Poly1305 dans la base SQLCipher (double chiffrement).
pub struct EncryptedDbSecretStore {
    conn: Arc<Mutex<Connection>>,
    key: crypto::Key32,
}

impl EncryptedDbSecretStore {
    pub fn new(conn: Arc<Mutex<Connection>>, key: crypto::Key32) -> Self {
        Self { conn, key }
    }
}

impl SecretStore for EncryptedDbSecretStore {
    fn put(&self, id: &str, value: &SecretValue) -> Result<()> {
        let blob = crypto::seal(&self.key, value.expose().as_bytes(), id.as_bytes())?;
        self.conn.lock().execute(
            "INSERT INTO secret_blobs(id, blob) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET blob = excluded.blob",
            params![id, blob],
        )?;
        Ok(())
    }
    fn get(&self, id: &str) -> Result<Option<SecretValue>> {
        let blob: Option<Vec<u8>> = self
            .conn
            .lock()
            .query_row("SELECT blob FROM secret_blobs WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        blob.map(|b| {
            let pt = crypto::open(&self.key, &b, id.as_bytes())?;
            let s = std::str::from_utf8(&pt).map_err(|_| CoreError::Crypto)?;
            Ok(SecretValue::new(s))
        })
        .transpose()
    }
    fn delete(&self, id: &str) -> Result<()> {
        self.conn
            .lock()
            .execute("DELETE FROM secret_blobs WHERE id = ?1", [id])?;
        Ok(())
    }
    fn backend_name(&self) -> &'static str {
        "base chiffrée (fallback)"
    }
}

/// Trousseau du système (Windows Credential Manager, macOS Keychain, Secret Service).
#[cfg(all(
    feature = "os-keyring",
    any(target_os = "windows", target_os = "macos", target_os = "linux")
))]
pub struct KeyringSecretStore {
    service: String,
}

#[cfg(all(
    feature = "os-keyring",
    any(target_os = "windows", target_os = "macos", target_os = "linux")
))]
impl KeyringSecretStore {
    /// Crée le store si le trousseau est réellement utilisable (écriture/lecture/suppression d'essai).
    pub fn probe(service: &str) -> Option<Self> {
        let s = Self {
            service: service.to_owned(),
        };
        let probe_id = format!("probe-{}", uuid::Uuid::new_v4());
        let ok = s.put(&probe_id, &SecretValue::new("probe")).is_ok()
            && matches!(s.get(&probe_id), Ok(Some(v)) if v.expose() == "probe");
        let _ = s.delete(&probe_id);
        ok.then_some(s)
    }

    fn entry(&self, id: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, id).map_err(|e| CoreError::SecretStore(e.to_string()))
    }
}

#[cfg(all(
    feature = "os-keyring",
    any(target_os = "windows", target_os = "macos", target_os = "linux")
))]
impl SecretStore for KeyringSecretStore {
    fn put(&self, id: &str, value: &SecretValue) -> Result<()> {
        self.entry(id)?
            .set_password(value.expose())
            .map_err(|e| CoreError::SecretStore(e.to_string()))
    }
    fn get(&self, id: &str) -> Result<Option<SecretValue>> {
        match self.entry(id)?.get_password() {
            Ok(v) => Ok(Some(SecretValue::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CoreError::SecretStore(e.to_string())),
        }
    }
    fn delete(&self, id: &str) -> Result<()> {
        match self.entry(id)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CoreError::SecretStore(e.to_string())),
        }
    }
    fn backend_name(&self) -> &'static str {
        "trousseau du système"
    }
}

/// Trousseau OS si disponible sur cette plateforme.
pub fn os_keyring(service: &str) -> Option<Arc<dyn SecretStore>> {
    #[cfg(all(
        feature = "os-keyring",
        any(target_os = "windows", target_os = "macos", target_os = "linux")
    ))]
    {
        KeyringSecretStore::probe(service).map(|s| Arc::new(s) as Arc<dyn SecretStore>)
    }
    #[cfg(not(all(
        feature = "os-keyring",
        any(target_os = "windows", target_os = "macos", target_os = "linux")
    )))]
    {
        let _ = service;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask() {
        assert_eq!(
            SecretValue::new("sk_live_abcdefgh1234").masked(),
            "••••1234"
        );
        assert_eq!(SecretValue::new("short").masked(), "••••");
        assert_eq!(SecretValue::new("ééééééééé1€34").last4(), "1€34");
        assert!(SecretValue::new("").is_empty());
    }

    #[test]
    fn debug_redacted() {
        let s = SecretValue::new("supersecretvalue");
        assert!(!format!("{s:?}").contains("supersecret"));
    }

    #[test]
    fn memory_store() {
        let m = MemorySecretStore::default();
        m.put("a", &SecretValue::new("v")).unwrap();
        assert_eq!(m.get("a").unwrap().unwrap().expose(), "v");
        m.delete("a").unwrap();
        assert!(m.get("a").unwrap().is_none());
        assert!(!m.backend_name().is_empty());
    }

    #[test]
    fn encrypted_db_store_roundtrip_and_binding() {
        let mut c = crate::db::open_in_memory(&[5u8; 32]).unwrap();
        crate::db::migrate(&mut c).unwrap();
        let conn = Arc::new(Mutex::new(c));
        let s = EncryptedDbSecretStore::new(conn.clone(), crypto::random_key());
        s.put("id1", &SecretValue::new("value-1")).unwrap();
        s.put("id1", &SecretValue::new("value-2")).unwrap();
        assert_eq!(s.get("id1").unwrap().unwrap().expose(), "value-2");
        assert!(s.get("nope").unwrap().is_none());
        // Le blob est lié à son id (AAD) : déplacer un blob vers un autre id échoue.
        conn.lock()
            .execute("INSERT INTO secret_blobs(id, blob) SELECT 'id2', blob FROM secret_blobs WHERE id='id1'", [])
            .unwrap();
        assert!(s.get("id2").is_err());
        let raw: Vec<u8> = conn
            .lock()
            .query_row("SELECT blob FROM secret_blobs WHERE id='id1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(!raw.windows(7).any(|w| w == b"value-2"));
        s.delete("id1").unwrap();
        assert!(s.get("id1").unwrap().is_none());
        assert!(!s.backend_name().is_empty());
    }

    #[test]
    fn os_keyring_probe_does_not_panic() {
        // Dans un conteneur sans Secret Service, renvoie None ; sur desktop, Some.
        let _ = os_keyring("dev.chamsoudine.controlcenter.test");
    }
}

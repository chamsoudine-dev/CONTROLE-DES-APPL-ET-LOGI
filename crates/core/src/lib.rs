//! Cœur métier de Control Center : stockage chiffré (SQLCipher), crypto, coffre, audit,
//! politique d'accès, applications, secrets, synchronisation, licences.
#![forbid(unsafe_code)]

pub mod audit;
pub mod crypto;
pub mod db;
mod error;
pub mod keys;
pub mod license_keys;
pub mod policy;
pub mod profile;
pub mod secrets;
pub mod vault;

pub use error::{CoreError, Result};

/// Horodatage RFC 3339 UTC courant.
pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("formatage RFC 3339")
}

/// Nouvel identifiant UUID v4.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod no_plaintext_tests {
    //! Critère d'acceptation Phase 1 : aucun secret lisible sur disque.
    use crate::secrets::SecretValue;
    use crate::vault::tests::{new_vault, PASS};

    fn scan(dir: &std::path::Path, needles: &[&str]) {
        for entry in walk(dir) {
            let bytes = std::fs::read(&entry).unwrap();
            assert!(
                !bytes.starts_with(b"SQLite format 3"),
                "{entry:?} non chiffré"
            );
            for n in needles {
                assert!(
                    !bytes.windows(n.len()).any(|w| w == n.as_bytes()),
                    "« {n} » trouvé en clair dans {entry:?}"
                );
            }
        }
    }

    fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut out = vec![];
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }

    #[test]
    fn no_plaintext_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let api_key = "vercel_tok_SUPERSECRET_0123456789";
        {
            let mut v = new_vault(d.path(), false);
            let s = v.session().unwrap();
            s.secrets.put("s1", &SecretValue::new(api_key)).unwrap();
            crate::license_keys::generate(s).unwrap();
            crate::profile::set_setting(&s.conn.lock(), "marker", "UNIQUE_MARKER_VALUE").unwrap();
            v.lock();
        }
        let files = walk(d.path());
        assert!(files.iter().any(|f| f.ends_with("control-center.db")));
        scan(
            d.path(),
            &[
                api_key,
                PASS,
                "UNIQUE_MARKER_VALUE",
                "Chamsoudine",
                "CREATE TABLE",
            ],
        );
    }
}

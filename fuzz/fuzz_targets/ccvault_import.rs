#![no_main]
//! Fichier .ccvault arbitraire : rejet propre (AEAD vérifié avant tout parsing du contenu).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Évite les paramètres Argon2 coûteux qu'un fichier piégé pourrait demander :
    // ils sont bornés par `inspect`, mais le fuzzing doit rester rapide.
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        if v["kdf"]["m_kib"].as_u64().unwrap_or(0) > 1024 || v["kdf"]["t"].as_u64().unwrap_or(0) > 2 {
            return;
        }
    }
    let _ = cc_core::ccvault::inspect(data, "fuzz passphrase 123");
});

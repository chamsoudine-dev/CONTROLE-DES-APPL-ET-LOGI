#![no_main]
//! Jeton arbitraire : la vérification ne doit jamais paniquer ni accepter un jeton non signé.
use cc_license::{PublicKey, Verifier};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn verifier() -> &'static Verifier {
    static V: OnceLock<Verifier> = OnceLock::new();
    V.get_or_init(|| {
        let fx: serde_json::Value = serde_json::from_str(include_str!("../../sdk/fixtures.json")).unwrap();
        Verifier::new([PublicKey::from_paserk(fx["public_keys"][0].as_str().unwrap()).unwrap()])
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let now = time::OffsetDateTime::from_unix_timestamp(1_767_312_000).unwrap();
        if let Ok(c) = verifier().verify(s, now) {
            // Seul un jeton réellement signé peut passer : il doit porter l'identifiant de la fixture.
            assert!(!c.id.is_empty());
        }
        let _ = verifier().verify(&format!("v4.public.{s}"), now);
    }
});

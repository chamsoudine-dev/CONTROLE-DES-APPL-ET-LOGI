#![no_main]
use cc_license::{LicenseChecker, PublicKey, Verifier};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let fx: serde_json::Value = serde_json::from_str(include_str!("../../sdk/fixtures.json")).unwrap();
    let v = Verifier::new([PublicKey::from_paserk(fx["public_keys"][0].as_str().unwrap()).unwrap()]);
    if let Ok(s) = std::str::from_utf8(data) {
        let mut c = LicenseChecker::new(v, 14);
        let _ = c.update_revocations(s, time::OffsetDateTime::UNIX_EPOCH);
    }
});

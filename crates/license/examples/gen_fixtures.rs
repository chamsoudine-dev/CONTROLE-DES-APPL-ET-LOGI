//! Génère les jeux de test des SDK (TypeScript, Go) à partir de l'implémentation de référence.
//! Usage : cargo run -p cc-license --example gen_fixtures > sdk/fixtures.json
use cc_license::{
    issue, sign_revocation_list, LicenseClaims, LicenseKind, RevocationList, SigningKeyPair,
};
use time::{Duration, OffsetDateTime};

fn rfc(t: OffsetDateTime) -> String {
    t.format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn main() {
    let kp = SigningKeyPair::generate();
    let attacker = SigningKeyPair::generate();
    let t0 = OffsetDateTime::parse(
        "2026-01-01T00:00:00Z",
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let mut c = LicenseClaims::new(
        "prod-pro",
        "Pro",
        "cust-awa",
        "Awa Diallo",
        LicenseKind::Subscription,
        t0,
        Some(t0 + Duration::days(30)),
    );
    c.features = vec!["export".into(), "multi-postes".into()];
    c.options.insert("seats".into(), 3.into());
    let valid = issue(&kp, &c).unwrap();
    let mut perpetual = LicenseClaims::new(
        "prod-pro",
        "Pro",
        "cust-ali",
        "Ali",
        LicenseKind::Perpetual,
        t0,
        None,
    );
    perpetual.features = vec![];
    let perpetual_tok = issue(&kp, &perpetual).unwrap();
    let parts: Vec<&str> = valid.split('.').collect();
    let mut body = data_encoding::BASE64URL_NOPAD
        .decode(parts[2].as_bytes())
        .unwrap();
    let pos = String::from_utf8_lossy(&body).find("\"Pro\"").unwrap();
    body[pos + 1] = b'M';
    let tampered = format!(
        "v4.public.{}.{}",
        data_encoding::BASE64URL_NOPAD.encode(&body),
        parts[3]
    );
    let forged = issue(&attacker, &c).unwrap();
    let list1 = sign_revocation_list(
        &kp,
        &RevocationList {
            seq: 1,
            issued_at: t0,
            revoked: std::collections::BTreeSet::default(),
        },
    )
    .unwrap();
    let list2 = sign_revocation_list(
        &kp,
        &RevocationList {
            seq: 2,
            issued_at: t0 + Duration::days(2),
            revoked: [c.id.clone()].into(),
        },
    )
    .unwrap();
    let forged_list = sign_revocation_list(
        &attacker,
        &RevocationList {
            seq: 99,
            issued_at: t0,
            revoked: std::collections::BTreeSet::default(),
        },
    )
    .unwrap();
    let out = serde_json::json!({
        "comment": "Généré par `cargo run -p cc-license --example gen_fixtures`. Clés de test jetables.",
        "public_keys": [kp.public_key().to_paserk()],
        "kid": kp.kid(),
        "license_id": c.id,
        "t_valid": rfc(t0 + Duration::days(1)),
        "t_after_expiry": rfc(t0 + Duration::days(31)),
        "t_before_issue": rfc(t0 - Duration::days(1)),
        "t_grace_exceeded": rfc(t0 + Duration::days(20)),
        "valid": valid,
        "perpetual": perpetual_tok,
        "tampered": tampered,
        "forged_other_key": forged,
        "revocation_list_seq1": list1,
        "revocation_list_seq2_revokes_valid": list2,
        "revocation_list_forged": forged_list,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

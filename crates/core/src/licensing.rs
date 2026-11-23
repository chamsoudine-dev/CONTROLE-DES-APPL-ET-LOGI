//! Produits, clients, ventes, licences (émission, prolongation, révocation, export CSV) et
//! couche de paiement.
use crate::vault::Session;
use crate::{license_keys, new_id, now_rfc3339, CoreError, Result};
use cc_license::{
    issue, readable_key, sign_revocation_list, LicenseClaims, LicenseKind, RevocationList,
};
use rusqlite::{params, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

fn parse_t(s: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|_| CoreError::Validation("date RFC 3339 attendue".into()))
}

fn fmt_t(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).expect("RFC 3339")
}

fn text(s: &str, max: usize, what: &str) -> Result<()> {
    if s.trim().is_empty() || s.chars().count() > max {
        return Err(CoreError::Validation(format!(
            "{what} : 1 à {max} caractères"
        )));
    }
    Ok(())
}

// ---------- Produits ----------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Product {
    pub id: String,
    pub app_id: Option<String>,
    pub name: String,
    pub kind: LicenseKind,
    pub duration_days: Option<i64>,
    pub price_cents: i64,
    pub currency: String,
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct NewProduct {
    pub app_id: Option<String>,
    pub name: String,
    pub kind: LicenseKind,
    pub duration_days: Option<i64>,
    #[serde(default)]
    pub price_cents: i64,
    #[serde(default = "default_currency")]
    pub currency: String,
    #[serde(default)]
    pub features: Vec<String>,
}

fn default_currency() -> String {
    "XOF".into()
}

fn kind_str(k: LicenseKind) -> &'static str {
    match k {
        LicenseKind::Perpetual => "perpetual",
        LicenseKind::Subscription => "subscription",
        LicenseKind::Trial => "trial",
    }
}

fn kind_parse(s: &str) -> LicenseKind {
    match s {
        "subscription" => LicenseKind::Subscription,
        "trial" => LicenseKind::Trial,
        _ => LicenseKind::Perpetual,
    }
}

pub fn create_product(s: &Session, p: &NewProduct) -> Result<Product> {
    text(&p.name, 120, "nom du produit")?;
    match (p.kind, p.duration_days) {
        (LicenseKind::Perpetual, _) => {}
        (_, Some(d)) if (1..=3650).contains(&d) => {}
        _ => {
            return Err(CoreError::Validation(
                "abonnement/essai : durée de 1 à 3650 jours".into(),
            ))
        }
    }
    if p.price_cents < 0
        || p.currency.len() != 3
        || !p.currency.chars().all(|c| c.is_ascii_uppercase())
    {
        return Err(CoreError::Validation(
            "prix ≥ 0 et devise ISO 4217 (ex. XOF, EUR)".into(),
        ));
    }
    if p.features.len() > 50 || p.features.iter().any(|f| f.is_empty() || f.len() > 64) {
        return Err(CoreError::Validation(
            "options : 50 max, 64 caractères chacune".into(),
        ));
    }
    let id = new_id();
    s.conn.lock().execute(
        "INSERT INTO products(id, app_id, name, kind, duration_days, price_cents, currency, features, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![id, p.app_id, p.name.trim(), kind_str(p.kind), p.duration_days.filter(|_| p.kind != LicenseKind::Perpetual),
                p.price_cents, p.currency, serde_json::to_string(&p.features)?, now_rfc3339()],
    )?;
    s.audit(
        "product.create",
        &id,
        &serde_json::json!({"name": p.name}),
        "ok",
    )?;
    get_product(s, &id)
}

fn product_row(r: &Row<'_>) -> rusqlite::Result<Product> {
    let kind: String = r.get(3)?;
    let f: String = r.get(7)?;
    Ok(Product {
        id: r.get(0)?,
        app_id: r.get(1)?,
        name: r.get(2)?,
        kind: kind_parse(&kind),
        duration_days: r.get(4)?,
        price_cents: r.get(5)?,
        currency: r.get(6)?,
        features: serde_json::from_str(&f).unwrap_or_default(),
    })
}

const PCOLS: &str = "id, app_id, name, kind, duration_days, price_cents, currency, features";

pub fn get_product(s: &Session, id: &str) -> Result<Product> {
    s.conn
        .lock()
        .query_row(
            &format!("SELECT {PCOLS} FROM products WHERE id=?1"),
            [id],
            product_row,
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound("produit".into()))
}

pub fn list_products(s: &Session) -> Result<Vec<Product>> {
    let c = s.conn.lock();
    let mut st = c.prepare(&format!("SELECT {PCOLS} FROM products ORDER BY name"))?;
    let v = st
        .query_map([], product_row)?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

// ---------- Clients ----------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Customer {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub notes: String,
}

pub fn create_customer(
    s: &Session,
    name: &str,
    email: Option<&str>,
    phone: Option<&str>,
    notes: &str,
) -> Result<Customer> {
    text(name, 120, "nom du client")?;
    if let Some(e) = email {
        if e.len() > 254 || !e.contains('@') || e.chars().any(char::is_whitespace) {
            return Err(CoreError::Validation("e-mail invalide".into()));
        }
    }
    if let Some(p) = phone {
        if p.len() > 32
            || !p
                .chars()
                .all(|c| c.is_ascii_digit() || " +-().".contains(c))
        {
            return Err(CoreError::Validation("téléphone invalide".into()));
        }
    }
    let id = new_id();
    s.conn.lock().execute(
        "INSERT INTO customers(id, name, email, phone, notes, created_at) VALUES (?1,?2,?3,?4,?5,?6)",
        params![id, name.trim(), email, phone, notes, now_rfc3339()],
    )?;
    s.audit("customer.create", &id, &serde_json::json!({}), "ok")?;
    get_customer(s, &id)
}

pub fn get_customer(s: &Session, id: &str) -> Result<Customer> {
    s.conn
        .lock()
        .query_row(
            "SELECT id, name, email, phone, notes FROM customers WHERE id=?1",
            [id],
            |r| {
                Ok(Customer {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    email: r.get(2)?,
                    phone: r.get(3)?,
                    notes: r.get(4)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound("client".into()))
}

pub fn list_customers(s: &Session) -> Result<Vec<Customer>> {
    let c = s.conn.lock();
    let mut st = c.prepare("SELECT id, name, email, phone, notes FROM customers ORDER BY name")?;
    let v = st
        .query_map([], |r| {
            Ok(Customer {
                id: r.get(0)?,
                name: r.get(1)?,
                email: r.get(2)?,
                phone: r.get(3)?,
                notes: r.get(4)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

// ---------- Paiements ----------

/// Résultat d'un encaissement.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Payment {
    pub provider: String,
    pub reference: Option<String>,
    pub status: String,
}

/// Couche d'abstraction des moyens de paiement (Mobile Money, fournisseur international…).
pub trait PaymentProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn label(&self) -> &'static str;
    /// Enregistre / vérifie un paiement. Les fournisseurs en ligne vérifieront la transaction
    /// auprès de leur API (webhook signé ou requête), jamais sur la seule parole du client.
    fn record(&self, amount_cents: i64, currency: &str, reference: Option<&str>)
        -> Result<Payment>;
}

/// Saisie manuelle (espèces, virement, Mobile Money vérifié à la main).
pub struct ManualPayment;

impl PaymentProvider for ManualPayment {
    fn id(&self) -> &'static str {
        "manual"
    }
    fn label(&self) -> &'static str {
        "Saisie manuelle"
    }
    fn record(
        &self,
        amount_cents: i64,
        _currency: &str,
        reference: Option<&str>,
    ) -> Result<Payment> {
        if amount_cents < 0 {
            return Err(CoreError::Validation("montant négatif".into()));
        }
        Ok(Payment {
            provider: "manual".into(),
            reference: reference.map(str::to_owned),
            status: "paid".into(),
        })
    }
}

/// Emplacements prévus (non actifs) : renvoient une erreur explicite.
pub struct PlannedProvider {
    pub id: &'static str,
    pub label: &'static str,
}

impl PaymentProvider for PlannedProvider {
    fn id(&self) -> &'static str {
        self.id
    }
    fn label(&self) -> &'static str {
        self.label
    }
    fn record(&self, _a: i64, _c: &str, _r: Option<&str>) -> Result<Payment> {
        Err(CoreError::Validation(format!(
            "{} : intégration prévue, pas encore disponible",
            self.label
        )))
    }
}

pub fn payment_providers() -> Vec<Box<dyn PaymentProvider>> {
    vec![
        Box::new(ManualPayment),
        Box::new(PlannedProvider {
            id: "mobile_money",
            label: "Mobile Money (Orange Money, Wave, MTN MoMo…)",
        }),
        Box::new(PlannedProvider {
            id: "international",
            label: "Fournisseur international (Stripe, PayPal…)",
        }),
    ]
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Sale {
    pub id: String,
    pub product_id: String,
    pub customer_id: String,
    pub amount_cents: i64,
    pub currency: String,
    pub provider: String,
    pub reference: Option<String>,
    pub status: String,
    pub created_at: String,
}

pub fn record_sale(
    s: &Session,
    product_id: &str,
    customer_id: &str,
    provider: &str,
    reference: Option<&str>,
) -> Result<Sale> {
    let p = get_product(s, product_id)?;
    get_customer(s, customer_id)?;
    let prov = payment_providers()
        .into_iter()
        .find(|x| x.id() == provider)
        .ok_or_else(|| CoreError::Validation(format!("moyen de paiement inconnu : {provider}")))?;
    let pay = prov.record(p.price_cents, &p.currency, reference)?;
    let id = new_id();
    s.conn.lock().execute(
        "INSERT INTO sales(id, product_id, customer_id, amount_cents, currency, provider, reference, status, created_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![id, product_id, customer_id, p.price_cents, p.currency, pay.provider, pay.reference, pay.status, now_rfc3339()],
    )?;
    s.audit(
        "sale.record",
        &id,
        &serde_json::json!({"amount": p.price_cents, "currency": p.currency}),
        "ok",
    )?;
    Ok(list_sales(s)?
        .into_iter()
        .find(|x| x.id == id)
        .expect("insérée"))
}

pub fn list_sales(s: &Session) -> Result<Vec<Sale>> {
    let c = s.conn.lock();
    let mut st = c.prepare(
        "SELECT id, product_id, customer_id, amount_cents, currency, provider, reference, status, created_at
         FROM sales ORDER BY created_at DESC",
    )?;
    let v = st
        .query_map([], |r| {
            Ok(Sale {
                id: r.get(0)?,
                product_id: r.get(1)?,
                customer_id: r.get(2)?,
                amount_cents: r.get(3)?,
                currency: r.get(4)?,
                provider: r.get(5)?,
                reference: r.get(6)?,
                status: r.get(7)?,
                created_at: r.get(8)?,
            })
        })?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

// ---------- Licences ----------

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct License {
    pub id: String,
    pub product_id: String,
    pub product_name: String,
    pub customer_id: String,
    pub customer_name: String,
    pub sale_id: Option<String>,
    pub readable_key: String,
    pub token: String,
    pub kid: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub status: String,
}

fn readable_secret(s: &Session) -> Result<Vec<u8>> {
    // Secret HMAC des clés lisibles : stocké (et synchronisé) via le trousseau.
    if let Some(v) = s.secrets.get("license-readable-hmac")? {
        return crate::crypto::unb64(v.expose());
    }
    let k = crate::crypto::random_bytes::<32>();
    s.secrets.put(
        "license-readable-hmac",
        &crate::secrets::SecretValue::new(crate::crypto::b64(&k)),
    )?;
    Ok(k.to_vec())
}

/// Crée une licence signée. Exige le droit « Licences » si le produit est lié à une appli.
pub fn create_license(
    s: &Session,
    product_id: &str,
    customer_id: &str,
    sale_id: Option<&str>,
    options: serde_json::Map<String, serde_json::Value>,
    now: OffsetDateTime,
) -> Result<License> {
    let p = get_product(s, product_id)?;
    if let Some(app) = &p.app_id {
        crate::apps::authorize(
            s,
            app,
            crate::policy::Action::Licenses,
            crate::policy::Role::Owner,
        )?;
    }
    let c = get_customer(s, customer_id)?;
    if options.len() > 32 || serde_json::Value::Object(options.clone()).to_string().len() > 4096 {
        return Err(CoreError::Validation("options trop volumineuses".into()));
    }
    let kp = license_keys::active(s)?;
    let expires = p.duration_days.map(|d| now + Duration::days(d));
    let mut claims = LicenseClaims::new(&p.id, &p.name, &c.id, &c.name, p.kind, now, expires);
    claims.features.clone_from(&p.features);
    claims.options.clone_from(&options);
    let token = issue(&kp, &claims)?;
    let rk = readable_key(&readable_secret(s)?, &claims.id);
    s.conn.lock().execute(
        "INSERT INTO licenses(id, product_id, customer_id, sale_id, readable_key, token, kid, issued_at, expires_at, options, status)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'active')",
        params![claims.id, p.id, c.id, sale_id, rk, token, kp.kid(), fmt_t(now), expires.map(fmt_t),
                serde_json::Value::Object(options).to_string()],
    )?;
    s.audit(
        "license.create",
        &claims.id,
        &serde_json::json!({"product": p.name, "readable_key": rk}),
        "ok",
    )?;
    get_license(s, &claims.id)
}

const LCOLS: &str =
    "l.id, l.product_id, p.name, l.customer_id, c.name, l.sale_id, l.readable_key, l.token, l.kid,
                     l.issued_at, l.expires_at, l.status";

fn license_row(r: &Row<'_>) -> rusqlite::Result<License> {
    Ok(License {
        id: r.get(0)?,
        product_id: r.get(1)?,
        product_name: r.get(2)?,
        customer_id: r.get(3)?,
        customer_name: r.get(4)?,
        sale_id: r.get(5)?,
        readable_key: r.get(6)?,
        token: r.get(7)?,
        kid: r.get(8)?,
        issued_at: r.get(9)?,
        expires_at: r.get(10)?,
        status: r.get(11)?,
    })
}

pub fn get_license(s: &Session, id: &str) -> Result<License> {
    s.conn
        .lock()
        .query_row(
            &format!("SELECT {LCOLS} FROM licenses l JOIN products p ON p.id=l.product_id JOIN customers c ON c.id=l.customer_id WHERE l.id=?1"),
            [id],
            license_row,
        )
        .optional()?
        .ok_or_else(|| CoreError::NotFound("licence".into()))
}

/// Recherche par clé lisible (saisie tolérante : minuscules, espaces, O/0, I/L/1).
pub fn find_by_readable_key(s: &Session, input: &str) -> Result<License> {
    let k = cc_license::normalize_readable_key(input)
        .ok_or_else(|| CoreError::Validation("clé lisible invalide".into()))?;
    let id: String = s
        .conn
        .lock()
        .query_row("SELECT id FROM licenses WHERE readable_key=?1", [k], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or_else(|| CoreError::NotFound("licence".into()))?;
    get_license(s, &id)
}

pub fn list_licenses(s: &Session) -> Result<Vec<License>> {
    let c = s.conn.lock();
    let mut st = c.prepare(&format!(
        "SELECT {LCOLS} FROM licenses l JOIN products p ON p.id=l.product_id JOIN customers c ON c.id=l.customer_id ORDER BY l.issued_at DESC"
    ))?;
    let v = st
        .query_map([], license_row)?
        .collect::<std::result::Result<_, _>>()?;
    Ok(v)
}

/// Prolonge une licence : nouveau jeton (même identifiant) avec une nouvelle échéance.
pub fn extend_license(
    s: &Session,
    id: &str,
    extra_days: i64,
    now: OffsetDateTime,
) -> Result<License> {
    if !(1..=3650).contains(&extra_days) {
        return Err(CoreError::Validation(
            "prolongation : 1 à 3650 jours".into(),
        ));
    }
    let l = get_license(s, id)?;
    if l.status == "revoked" {
        return Err(CoreError::Validation("licence révoquée".into()));
    }
    let p = get_product(s, &l.product_id)?;
    let c = get_customer(s, &l.customer_id)?;
    let base = l
        .expires_at
        .as_deref()
        .map(parse_t)
        .transpose()?
        .map_or(now, |e| e.max(now));
    let kp = license_keys::active(s)?;
    let options: serde_json::Map<String, serde_json::Value> = {
        let raw: String =
            s.conn
                .lock()
                .query_row("SELECT options FROM licenses WHERE id=?1", [id], |r| {
                    r.get(0)
                })?;
        serde_json::from_str(&raw).unwrap_or_default()
    };
    let mut claims = LicenseClaims::new(
        &p.id,
        &p.name,
        &c.id,
        &c.name,
        p.kind,
        now,
        Some(base + Duration::days(extra_days)),
    );
    claims.id.clone_from(&l.id);
    claims.features.clone_from(&p.features);
    claims.options = options;
    let token = issue(&kp, &claims)?;
    s.conn.lock().execute(
        "UPDATE licenses SET token=?2, kid=?3, expires_at=?4, status='active' WHERE id=?1",
        params![id, token, kp.kid(), claims.expires_at.map(fmt_t)],
    )?;
    s.audit(
        "license.extend",
        id,
        &serde_json::json!({"days": extra_days}),
        "ok",
    )?;
    get_license(s, id)
}

/// Révoque (ré-authentification) ; la publication de la liste se fait ensuite.
pub fn revoke_license(s: &Session, id: &str, reason: &str) -> Result<()> {
    s.ensure_recent_reauth()?;
    get_license(s, id)?;
    let c = s.conn.lock();
    c.execute("UPDATE licenses SET status='revoked' WHERE id=?1", [id])?;
    c.execute(
        "INSERT INTO revocations(license_id, reason, revoked_at) VALUES (?1,?2,?3)
         ON CONFLICT(license_id) DO NOTHING",
        params![id, reason, now_rfc3339()],
    )?;
    drop(c);
    s.audit(
        "license.revoke",
        id,
        &serde_json::json!({"reason": reason}),
        "ok",
    )
}

/// Construit et signe la prochaine liste de révocation (numéro strictement croissant).
pub fn build_revocation_list(s: &Session, now: OffsetDateTime) -> Result<(u64, String)> {
    let kp = license_keys::active(s)?;
    let (seq, revoked) = {
        let c = s.conn.lock();
        let last: Option<i64> =
            c.query_row("SELECT max(seq) FROM revocation_lists", [], |r| r.get(0))?;
        let mut st = c.prepare("SELECT license_id FROM revocations ORDER BY license_id")?;
        let revoked: std::collections::BTreeSet<String> = st
            .query_map([], |r| r.get(0))?
            .collect::<std::result::Result<_, _>>()?;
        (u64::try_from(last.unwrap_or(0)).unwrap_or(0) + 1, revoked)
    };
    let token = sign_revocation_list(
        &kp,
        &RevocationList {
            seq,
            issued_at: now,
            revoked,
        },
    )?;
    let c = s.conn.lock();
    c.execute(
        "INSERT INTO revocation_lists(seq, token) VALUES (?1, ?2)",
        params![i64::try_from(seq).unwrap_or(i64::MAX), token],
    )?;
    c.execute(
        "UPDATE revocations SET published_seq=?1 WHERE published_seq IS NULL",
        [i64::try_from(seq).unwrap_or(i64::MAX)],
    )?;
    Ok((seq, token))
}

pub fn mark_list_published(s: &Session, seq: u64) -> Result<()> {
    s.conn.lock().execute(
        "UPDATE revocation_lists SET published_at=?2 WHERE seq=?1",
        params![i64::try_from(seq).unwrap_or(i64::MAX), now_rfc3339()],
    )?;
    s.audit(
        "license.revocations.publish",
        &seq.to_string(),
        &serde_json::json!({}),
        "ok",
    )
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RevocationStatus {
    pub last_seq: Option<i64>,
    pub last_published_at: Option<String>,
    pub unpublished: i64,
}

pub fn revocation_status(s: &Session) -> Result<RevocationStatus> {
    let c = s.conn.lock();
    let (last_seq, last_published_at) = c
        .query_row(
            "SELECT seq, published_at FROM revocation_lists ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or((None, None));
    let unpublished: i64 = c.query_row(
        "SELECT count(*) FROM revocations WHERE published_seq IS NULL OR published_seq NOT IN (SELECT seq FROM revocation_lists WHERE published_at IS NOT NULL)",
        [],
        |r| r.get(0),
    )?;
    Ok(RevocationStatus {
        last_seq,
        last_published_at,
        unpublished,
    })
}

/// Export CSV des licences (sans le jeton complet : colonne tronquée).
pub fn export_csv(s: &Session) -> Result<String> {
    let mut w = csv::Writer::from_writer(vec![]);
    w.write_record([
        "readable_key",
        "license_id",
        "product",
        "customer",
        "issued_at",
        "expires_at",
        "status",
        "kid",
    ])
    .map_err(|e| CoreError::Io(e.to_string()))?;
    for l in list_licenses(s)? {
        // Neutralise l'injection de formules dans les tableurs.
        let safe = |v: &str| {
            if v.starts_with(['=', '+', '-', '@']) {
                format!("'{v}")
            } else {
                v.to_owned()
            }
        };
        w.write_record([
            l.readable_key.as_str(),
            l.id.as_str(),
            &safe(&l.product_name),
            &safe(&l.customer_name),
            l.issued_at.as_str(),
            l.expires_at.as_deref().unwrap_or(""),
            l.status.as_str(),
            l.kid.as_str(),
        ])
        .map_err(|e| CoreError::Io(e.to_string()))?;
    }
    let bytes = w.into_inner().map_err(|e| CoreError::Io(e.to_string()))?;
    s.audit("license.export", "", &serde_json::json!({}), "ok")?;
    String::from_utf8(bytes).map_err(|_| CoreError::Io("CSV".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::tests::{new_vault, PASS};
    use cc_license::{LicenseChecker, PublicKey, Verifier};

    fn t0() -> OffsetDateTime {
        OffsetDateTime::parse("2026-06-01T00:00:00Z", &Rfc3339).unwrap()
    }

    #[test]
    fn full_license_lifecycle() {
        let d = tempfile::tempdir().unwrap();
        let mut v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        license_keys::generate(s).unwrap();
        let prod = create_product(
            s,
            &NewProduct {
                app_id: None,
                name: "Pro".into(),
                kind: LicenseKind::Subscription,
                duration_days: Some(30),
                price_cents: 500_000,
                currency: "XOF".into(),
                features: vec!["export".into()],
            },
        )
        .unwrap();
        assert!(create_product(
            s,
            &NewProduct {
                app_id: None,
                name: "Bad".into(),
                kind: LicenseKind::Trial,
                duration_days: None,
                price_cents: 0,
                currency: "XOF".into(),
                features: vec![]
            }
        )
        .is_err());
        assert!(create_product(
            s,
            &NewProduct {
                app_id: None,
                name: "Bad".into(),
                kind: LicenseKind::Perpetual,
                duration_days: None,
                price_cents: 0,
                currency: "xof".into(),
                features: vec![]
            }
        )
        .is_err());
        let cust = create_customer(
            s,
            "=Awa Diallo",
            Some("awa@example.com"),
            Some("+221 77 000 00 00"),
            "",
        )
        .unwrap();
        assert!(create_customer(s, "X", Some("pas-un-email"), None, "").is_err());
        assert!(create_customer(s, "X", None, Some("<script>"), "").is_err());
        let sale = record_sale(s, &prod.id, &cust.id, "manual", Some("OM-123")).unwrap();
        assert_eq!(sale.amount_cents, 500_000);
        assert!(
            record_sale(s, &prod.id, &cust.id, "mobile_money", None).is_err(),
            "prévu, pas actif"
        );
        assert!(record_sale(s, &prod.id, &cust.id, "bitcoin", None).is_err());
        let lic = create_license(
            s,
            &prod.id,
            &cust.id,
            Some(&sale.id),
            serde_json::Map::new(),
            t0(),
        )
        .unwrap();
        assert_eq!(lic.readable_key.len(), 19);
        assert_eq!(
            find_by_readable_key(s, &lic.readable_key.to_lowercase())
                .unwrap()
                .id,
            lic.id
        );
        // Vérification hors ligne avec la clé publique.
        let pks: Vec<PublicKey> = license_keys::known_public_keys(s)
            .unwrap()
            .iter()
            .map(|k| PublicKey::from_paserk(k).unwrap())
            .collect();
        let verifier = Verifier::new(pks);
        let claims = verifier
            .verify(&lic.token, t0() + Duration::days(1))
            .unwrap();
        assert_eq!(claims.features, vec!["export".to_string()]);
        assert!(verifier
            .verify(&lic.token, t0() + Duration::days(31))
            .is_err());
        // Prolongation : même identifiant, nouvelle échéance.
        let ext = extend_license(s, &lic.id, 30, t0()).unwrap();
        assert!(verifier
            .verify(&ext.token, t0() + Duration::days(45))
            .is_ok());
        assert_eq!(ext.readable_key, lic.readable_key);
        // Révocation → liste signée → refusée côté client.
        assert!(matches!(
            revoke_license(s, &lic.id, "fraude"),
            Err(CoreError::ReauthRequired)
        ));
        v.reauth(PASS, None).unwrap();
        let s = v.session().unwrap();
        let (seq0, list0) = build_revocation_list(s, t0()).unwrap();
        let mut checker = LicenseChecker::new(verifier.clone(), 14);
        checker.update_revocations(&list0, t0()).unwrap();
        assert!(checker.check(&ext.token, t0()).is_ok());
        revoke_license(s, &lic.id, "fraude").unwrap();
        assert_eq!(revocation_status(s).unwrap().unpublished, 1);
        let (seq, list) = build_revocation_list(s, t0()).unwrap();
        assert_eq!(seq, seq0 + 1);
        mark_list_published(s, seq).unwrap();
        assert_eq!(revocation_status(s).unwrap().unpublished, 0);
        checker.update_revocations(&list, t0()).unwrap();
        assert_eq!(
            checker.check(&ext.token, t0()).unwrap_err(),
            cc_license::LicenseError::Revoked
        );
        assert!(extend_license(s, &lic.id, 10, t0()).is_err());
        // Export CSV (anti-injection de formules).
        let csv = export_csv(s).unwrap();
        assert!(
            csv.contains("'=Awa Diallo")
                && csv.contains(&lic.readable_key)
                && !csv.contains(&lic.token)
        );
        assert_eq!(list_products(s).unwrap().len(), 1);
        assert_eq!(list_customers(s).unwrap().len(), 1);
        assert_eq!(list_sales(s).unwrap().len(), 1);
        assert_eq!(list_licenses(s).unwrap()[0].status, "revoked");
        assert_eq!(payment_providers().len(), 3);
        assert!(find_by_readable_key(s, "0000-0000-0000-0000").is_err());
        assert!(find_by_readable_key(s, "x").is_err());
    }

    #[test]
    fn licenses_right_enforced_for_app_products() {
        let d = tempfile::tempdir().unwrap();
        let v = new_vault(d.path(), false);
        let s = v.session().unwrap();
        license_keys::generate(s).unwrap();
        let app = crate::apps::create(
            s,
            &crate::apps::NewApp {
                name: "A".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let prod = create_product(
            s,
            &NewProduct {
                app_id: Some(app.id),
                name: "P".into(),
                kind: LicenseKind::Perpetual,
                duration_days: None,
                price_cents: 0,
                currency: "EUR".into(),
                features: vec![],
            },
        )
        .unwrap();
        let cust = create_customer(s, "C", None, None, "").unwrap();
        assert!(
            matches!(
                create_license(s, &prod.id, &cust.id, None, serde_json::Map::new(), t0()),
                Err(CoreError::Forbidden(_))
            ),
            "appli en lecture seule"
        );
    }
}

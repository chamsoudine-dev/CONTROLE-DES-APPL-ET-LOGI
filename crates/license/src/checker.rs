use crate::{LicenseClaims, LicenseError, Result, RevocationList, Verifier};
use time::{Duration, OffsetDateTime};

/// Liste de révocation en cache côté appli cliente.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedRevocationList {
    pub list: RevocationList,
    /// Dernière récupération réussie (horloge locale).
    pub fetched_at: OffsetDateTime,
}

/// Résultat d'une vérification complète.
#[derive(Clone, Debug, PartialEq)]
pub enum CheckOutcome {
    /// Licence valide ; `offline_days_left` = jours restants avant expiration du délai de grâce.
    Valid {
        claims: Box<LicenseClaims>,
        offline_days_left: i64,
    },
}

/// Logique de vérification côté appli cliente : signature, dates, révocation, délai de grâce.
#[derive(Clone, Debug)]
pub struct LicenseChecker {
    verifier: Verifier,
    grace: Duration,
    cache: Option<CachedRevocationList>,
}

impl LicenseChecker {
    /// `grace_days` : durée maximale sans liste de révocation fraîche (14 jours recommandé).
    pub fn new(verifier: Verifier, grace_days: i64) -> Self {
        Self {
            verifier,
            grace: Duration::days(grace_days),
            cache: None,
        }
    }

    pub fn cached(&self) -> Option<&CachedRevocationList> {
        self.cache.as_ref()
    }

    /// Restaure un cache persisté (déjà vérifié auparavant — il est revérifié ici).
    pub fn restore_cache(&mut self, token: &str, fetched_at: OffsetDateTime) -> Result<()> {
        let list = self.verifier.verify_revocation_list(token)?;
        self.cache = Some(CachedRevocationList { list, fetched_at });
        Ok(())
    }

    /// Intègre une liste fraîchement téléchargée. Refuse un `seq` inférieur (rollback).
    pub fn update_revocations(&mut self, token: &str, now: OffsetDateTime) -> Result<u64> {
        let list = self.verifier.verify_revocation_list(token)?;
        if let Some(c) = &self.cache {
            if list.seq < c.list.seq {
                return Err(LicenseError::Rollback);
            }
        }
        let seq = list.seq;
        self.cache = Some(CachedRevocationList {
            list,
            fetched_at: now,
        });
        Ok(seq)
    }

    /// Vérification complète d'une licence à l'instant `now`.
    ///
    /// Sans aucune liste en cache, la date d'émission de la licence sert de point de départ
    /// du délai de grâce (permet une première utilisation hors ligne).
    pub fn check(&self, token: &str, now: OffsetDateTime) -> Result<CheckOutcome> {
        let claims = self.verifier.verify(token, now)?;
        let reference = match &self.cache {
            Some(c) => {
                if c.list.is_revoked(&claims.id) {
                    return Err(LicenseError::Revoked);
                }
                c.fetched_at
            }
            None => claims.issued_at,
        };
        let deadline = reference + self.grace;
        if now > deadline {
            return Err(LicenseError::GraceExpired);
        }
        Ok(CheckOutcome::Valid {
            offline_days_left: (deadline - now).whole_days(),
            claims: Box::new(claims),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{issue, sign_revocation_list, LicenseKind, SigningKeyPair};

    fn t0() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap()
    }

    fn setup() -> (SigningKeyPair, LicenseChecker, String, String) {
        let kp = SigningKeyPair::generate();
        let c = LicenseClaims::new("p", "P", "c", "C", LicenseKind::Perpetual, t0(), None);
        let id = c.id.clone();
        let tok = issue(&kp, &c).unwrap();
        let checker = LicenseChecker::new(Verifier::new([kp.public_key().clone()]), 14);
        (kp, checker, tok, id)
    }

    fn list(kp: &SigningKeyPair, seq: u64, ids: &[&str]) -> String {
        sign_revocation_list(
            kp,
            &RevocationList {
                seq,
                issued_at: t0(),
                revoked: ids.iter().map(|s| (*s).to_string()).collect(),
            },
        )
        .unwrap()
    }

    #[test]
    fn valid_without_list_within_grace() {
        let (_, ch, tok, _) = setup();
        let CheckOutcome::Valid {
            offline_days_left, ..
        } = ch.check(&tok, t0() + Duration::days(4)).unwrap();
        assert_eq!(offline_days_left, 10);
        assert_eq!(
            ch.check(&tok, t0() + Duration::days(15)).unwrap_err(),
            LicenseError::GraceExpired
        );
    }

    #[test]
    fn revoked_rejected_after_list_update() {
        let (kp, mut ch, tok, id) = setup();
        ch.update_revocations(&list(&kp, 1, &[]), t0()).unwrap();
        assert!(ch.check(&tok, t0()).is_ok());
        ch.update_revocations(&list(&kp, 2, &[&id]), t0()).unwrap();
        assert_eq!(ch.check(&tok, t0()).unwrap_err(), LicenseError::Revoked);
    }

    #[test]
    fn revocation_rollback_rejected() {
        let (kp, mut ch, tok, id) = setup();
        ch.update_revocations(&list(&kp, 5, &[&id]), t0()).unwrap();
        assert_eq!(
            ch.update_revocations(&list(&kp, 4, &[]), t0()).unwrap_err(),
            LicenseError::Rollback
        );
        assert_eq!(ch.check(&tok, t0()).unwrap_err(), LicenseError::Revoked);
        assert_eq!(ch.cached().unwrap().list.seq, 5);
    }

    #[test]
    fn forged_list_rejected() {
        let (_, mut ch, _, _) = setup();
        let attacker = SigningKeyPair::generate();
        assert!(ch
            .update_revocations(&list(&attacker, 99, &[]), t0())
            .is_err());
        assert!(ch.cached().is_none());
    }

    #[test]
    fn grace_refreshes_with_fetch_and_restore() {
        let (kp, mut ch, tok, _) = setup();
        let l = list(&kp, 1, &[]);
        ch.update_revocations(&l, t0() + Duration::days(10))
            .unwrap();
        assert!(ch.check(&tok, t0() + Duration::days(20)).is_ok());
        assert_eq!(
            ch.check(&tok, t0() + Duration::days(25)).unwrap_err(),
            LicenseError::GraceExpired
        );
        let mut ch2 = LicenseChecker::new(Verifier::new([kp.public_key().clone()]), 14);
        ch2.restore_cache(&l, t0() + Duration::days(10)).unwrap();
        assert!(ch2.check(&tok, t0() + Duration::days(20)).is_ok());
    }
}

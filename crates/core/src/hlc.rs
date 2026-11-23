//! Horloge logique hybride (HLC) : ordre total, comparable lexicographiquement.
//!
//! Format : `<ms sur 13 chiffres>-<compteur sur 5 chiffres>-<id appareil>`.
use crate::{CoreError, Result};
use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hlc {
    pub wall_ms: u64,
    pub counter: u32,
    pub device: String,
}

impl Hlc {
    pub fn parse(s: &str) -> Result<Self> {
        let mut it = s.splitn(3, '-');
        let bad = || CoreError::Validation(format!("HLC invalide : {s}"));
        let wall = it.next().ok_or_else(bad)?;
        let ctr = it.next().ok_or_else(bad)?;
        let device = it.next().ok_or_else(bad)?;
        if wall.len() != 13 || ctr.len() != 5 || device.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            wall_ms: wall.parse().map_err(|_| bad())?,
            counter: ctr.parse().map_err(|_| bad())?,
            device: device.to_owned(),
        })
    }

    /// Nouvelle valeur locale, strictement supérieure à `last`.
    pub fn tick(last: Option<&Hlc>, now_ms: u64, device: &str) -> Hlc {
        match last {
            Some(l) if l.wall_ms >= now_ms => Hlc {
                wall_ms: l.wall_ms,
                counter: l.counter + 1,
                device: device.into(),
            },
            _ => Hlc {
                wall_ms: now_ms,
                counter: 0,
                device: device.into(),
            },
        }
    }

    /// Mise à jour à la réception d'une valeur distante (garantit la causalité).
    pub fn observe(last: Option<&Hlc>, remote: &Hlc, now_ms: u64, device: &str) -> Hlc {
        let l_wall = last.map_or(0, |l| l.wall_ms);
        let wall = now_ms.max(l_wall).max(remote.wall_ms);
        let counter = if wall == l_wall && wall == remote.wall_ms {
            last.map_or(0, |l| l.counter).max(remote.counter) + 1
        } else if wall == l_wall {
            last.map_or(0, |l| l.counter) + 1
        } else if wall == remote.wall_ms {
            remote.counter + 1
        } else {
            0
        };
        Hlc {
            wall_ms: wall,
            counter,
            device: device.into(),
        }
    }
}

impl std::fmt::Display for Hlc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:013}-{:05}-{}",
            self.wall_ms, self.counter, self.device
        )
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.wall_ms, self.counter, &self.device).cmp(&(
            other.wall_ms,
            other.counter,
            &other.device,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_order() {
        let a = Hlc {
            wall_ms: 1_700_000_000_000,
            counter: 2,
            device: "dev-a".into(),
        };
        let s = a.to_string();
        assert_eq!(s, "1700000000000-00002-dev-a");
        assert_eq!(Hlc::parse(&s).unwrap(), a);
        let b = Hlc {
            wall_ms: 1_700_000_000_000,
            counter: 2,
            device: "dev-b".into(),
        };
        assert!(
            a < b && a.to_string() < b.to_string(),
            "ordre total, cohérent avec l'ordre texte"
        );
        for bad in [
            "",
            "1-2-3",
            "abcdefghijklm-00001-x",
            "1700000000000-00001-",
            "1700000000000-0001-x",
        ] {
            assert!(Hlc::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tick_and_observe_monotonic() {
        let t1 = Hlc::tick(None, 100, "a");
        let t2 = Hlc::tick(Some(&t1), 50, "a"); // horloge qui recule
        assert!(t2 > t1);
        let t3 = Hlc::tick(Some(&t2), 200, "a");
        assert_eq!((t3.wall_ms, t3.counter), (200, 0));
        let remote = Hlc {
            wall_ms: 500,
            counter: 7,
            device: "b".into(),
        };
        let o = Hlc::observe(Some(&t3), &remote, 300, "a");
        assert!(o > remote && o > t3);
        let o2 = Hlc::observe(
            Some(&o),
            &Hlc {
                wall_ms: 500,
                counter: 9,
                device: "b".into(),
            },
            10,
            "a",
        );
        assert_eq!((o2.wall_ms, o2.counter), (500, 10));
        let o3 = Hlc::observe(
            None,
            &Hlc {
                wall_ms: 5,
                counter: 0,
                device: "b".into(),
            },
            10,
            "a",
        );
        assert_eq!((o3.wall_ms, o3.counter), (10, 0));
        let o4 = Hlc::observe(
            Some(&Hlc {
                wall_ms: 20,
                counter: 3,
                device: "a".into(),
            }),
            &Hlc {
                wall_ms: 5,
                counter: 0,
                device: "b".into(),
            },
            10,
            "a",
        );
        assert_eq!((o4.wall_ms, o4.counter), (20, 4));
    }
}

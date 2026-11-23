//! Intégrité de l'appareil : détection heuristique root (Android) / jailbreak (iOS).
//!
//! Avertissement seulement (pas de blocage) : ces contrôles sont contournables par un attaquant
//! déterminé ; ils servent à informer l'utilisateur que le trousseau et le bac à sable de l'OS
//! ne protègent plus correctement ses secrets.
use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct IntegrityReport {
    pub platform: &'static str,
    pub compromised: bool,
    pub indicators: Vec<String>,
}

/// Chemins typiques d'un Android rooté (su, Magisk, SuperSU).
pub const ANDROID_ROOT_PATHS: &[&str] = &[
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/su/bin/su",
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/system/sd/xbin/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/sbin/.magisk",
    "/data/adb/magisk",
    "/cache/.disable_magisk",
];

/// Chemins typiques d'un iOS jailbreaké.
pub const IOS_JAILBREAK_PATHS: &[&str] = &[
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/private/var/lib/apt/",
    "/var/jb",
    "/usr/lib/libjailbreak.dylib",
];

/// Évalue l'intégrité avec une fonction d'existence de chemin injectable (tests).
pub fn evaluate(platform: &'static str, exists: impl Fn(&str) -> bool) -> IntegrityReport {
    let paths: &[&str] = match platform {
        "android" => ANDROID_ROOT_PATHS,
        "ios" => IOS_JAILBREAK_PATHS,
        _ => &[],
    };
    let indicators: Vec<String> = paths
        .iter()
        .filter(|p| exists(p))
        .map(|p| (*p).to_owned())
        .collect();
    IntegrityReport {
        platform,
        compromised: !indicators.is_empty(),
        indicators,
    }
}

/// Contrôle de l'appareil courant.
pub fn device_integrity() -> IntegrityReport {
    evaluate(std::env::consts::OS, |p| std::path::Path::new(p).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_never_flagged() {
        let r = evaluate("linux", |_| true);
        assert!(!r.compromised && r.indicators.is_empty());
        let here = device_integrity();
        if !matches!(std::env::consts::OS, "android" | "ios") {
            assert!(!here.compromised);
        }
    }

    #[test]
    fn android_and_ios_indicators() {
        let r = evaluate("android", |p| {
            p == "/system/xbin/su" || p == "/data/adb/magisk"
        });
        assert!(r.compromised);
        assert_eq!(r.indicators.len(), 2);
        assert!(!evaluate("android", |_| false).compromised);
        let i = evaluate("ios", |p| p == "/Applications/Cydia.app");
        assert!(i.compromised && i.platform == "ios");
    }
}

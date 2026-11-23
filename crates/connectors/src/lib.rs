//! Connecteurs fournisseurs de Control Center.
//!
//! Chaque connecteur implémente [`Connector`] ; tous passent par le client [`http::HttpClient`]
//! durci (HTTPS, pas de redirection inter-hôte, réponses bornées).
#![forbid(unsafe_code)]

pub mod github;
pub mod http;
pub mod types;

pub use types::{
    Access, ActionSpec, Connector, DetectedPermission, Health, PermissionSpec, Provider, Resource,
    TestReport,
};

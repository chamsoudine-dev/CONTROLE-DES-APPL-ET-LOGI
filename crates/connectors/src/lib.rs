//! Connecteurs fournisseurs de Control Center.
//!
//! Chaque connecteur implémente [`Connector`] ; tous passent par le client [`http::HttpClient`]
//! durci (HTTPS, pas de redirection inter-hôte, réponses bornées). Les écritures passent par
//! [`exec`] (politique, confirmation, ré-authentification, audit).
#![forbid(unsafe_code)]

pub mod app_health;
pub mod cloudflare;
pub mod cloudinary;
mod common;
pub mod custom;
pub mod exec;
pub mod firebase;
pub mod github;
pub mod http;
pub mod media;
pub mod netlify;
pub mod registry;
pub mod supabase;
pub mod types;
pub mod vercel;

pub use types::{
    Access, ActionSpec, Connector, DetectedPermission, Health, PermissionSpec, Provider, Resource,
    TestReport,
};

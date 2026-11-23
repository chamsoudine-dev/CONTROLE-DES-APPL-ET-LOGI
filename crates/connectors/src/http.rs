//! Client HTTP durci : HTTPS obligatoire (sauf boucle locale), pas de redirection inter-hôte,
//! taille de réponse bornée, délai, identifiants envoyés uniquement à l'hôte déclaré.
use cc_core::secrets::SecretValue;
use cc_core::{CoreError, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};
use std::time::Duration;
use url::Url;

pub const MAX_BODY: usize = 10 * 1024 * 1024;
const USER_AGENT: &str = concat!("ControlCenter/", env!("CARGO_PKG_VERSION"));

/// Méthode d'authentification.
#[derive(Clone, Debug)]
pub enum Auth {
    None,
    Bearer(SecretValue),
    Header { name: String, value: SecretValue },
    Basic { user: String, pass: SecretValue },
}

/// Réponse lue intégralement (bornée à `MAX_BODY`).
#[derive(Clone, Debug)]
pub struct Response {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Response {
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| CoreError::External(format!("réponse JSON invalide : {e}")))
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// Échoue si le statut n'est pas 2xx, avec un message exploitable (jamais la clé).
    pub fn ok(self) -> Result<Self> {
        if self.status.is_success() {
            return Ok(self);
        }
        let snippet: String = String::from_utf8_lossy(&self.body)
            .chars()
            .take(200)
            .collect();
        Err(CoreError::External(match self.status.as_u16() {
            401 => "authentification refusée (clé invalide ou expirée)".into(),
            403 => format!("permission insuffisante : {snippet}"),
            404 => "ressource introuvable (ou clé sans accès)".into(),
            429 => "quota dépassé, réessayez plus tard".into(),
            s => format!("HTTP {s} : {snippet}"),
        }))
    }
}

fn is_loopback(u: &Url) -> bool {
    matches!(
        u.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    )
}

/// Valide une URL de base : HTTPS obligatoire, sauf boucle locale (serveurs de dev, tests).
pub fn validate_base_url(raw: &str) -> Result<Url> {
    let u = Url::parse(raw.trim()).map_err(|_| CoreError::Validation("URL invalide".into()))?;
    if !u.username().is_empty() || u.password().is_some() {
        return Err(CoreError::Validation(
            "identifiants interdits dans l'URL".into(),
        ));
    }
    match u.scheme() {
        "https" => Ok(u),
        "http" if is_loopback(&u) => Ok(u),
        _ => Err(CoreError::Validation("HTTPS obligatoire".into())),
    }
}

#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
    base: Url,
    auth: Auth,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl HttpClient {
    pub fn new(base_url: &str, auth: Auth) -> Result<Self> {
        let base = validate_base_url(base_url)?;
        let origin_host = base.host_str().unwrap_or_default().to_owned();
        let inner = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(10))
            .https_only(!is_loopback(&base))
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                // Jamais de redirection vers un autre hôte (fuite d'identifiants), max 5.
                if attempt.previous().len() >= 5 {
                    attempt.error("trop de redirections")
                } else if attempt.url().host_str() == Some(origin_host.as_str()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|e| CoreError::External(e.to_string()))?;
        Ok(Self { inner, base, auth })
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    /// Construit l'URL d'un chemin relatif ; refuse toute URL absolue vers un autre hôte.
    pub fn url(&self, path: &str) -> Result<Url> {
        if path.starts_with("http://") || path.starts_with("https://") {
            let u = Url::parse(path).map_err(|_| CoreError::Validation("URL invalide".into()))?;
            if u.host_str() != self.base.host_str() || u.scheme() != self.base.scheme() {
                return Err(CoreError::Forbidden(
                    "hôte différent de l'hôte déclaré".into(),
                ));
            }
            return Ok(u);
        }
        let mut base = self.base.clone();
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        base.join(path.trim_start_matches('/'))
            .map_err(|_| CoreError::Validation("chemin invalide".into()))
    }

    pub async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&serde_json::Value>,
        headers: &[(&str, &str)],
    ) -> Result<Response> {
        let url = self.url(path)?;
        self.send_url(method, url, body.map(|b| Body::Json(b.clone())), headers)
            .await
    }

    pub async fn send_url(
        &self,
        method: Method,
        url: Url,
        body: Option<Body>,
        headers: &[(&str, &str)],
    ) -> Result<Response> {
        let mut req = self.inner.request(method, url);
        req = match &self.auth {
            Auth::None => req,
            Auth::Bearer(t) => req.bearer_auth(t.expose()),
            Auth::Header { name, value } => {
                let n = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| CoreError::Validation("nom d'en-tête invalide".into()))?;
                let mut v = HeaderValue::from_str(value.expose())
                    .map_err(|_| CoreError::Validation("valeur d'en-tête invalide".into()))?;
                v.set_sensitive(true);
                req.header(n, v)
            }
            Auth::Basic { user, pass } => req.basic_auth(user, Some(pass.expose())),
        };
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req = match body {
            Some(Body::Json(j)) => req.json(&j),
            Some(Body::Form(f)) => req.form(&f),
            Some(Body::Bytes(b, ct)) => req.header("content-type", ct).body(b),
            None => req,
        };
        let mut resp = req.send().await.map_err(|e| {
            CoreError::External(if e.is_timeout() {
                "délai dépassé".into()
            } else if e.is_connect() {
                "connexion impossible (hors ligne ?)".into()
            } else {
                "erreur réseau".into()
            })
        })?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| CoreError::External("réponse interrompue".into()))?
        {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(CoreError::External("réponse trop volumineuse".into()));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    pub async fn get(&self, path: &str) -> Result<Response> {
        self.send(Method::GET, path, None, &[]).await
    }

    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.get(path).await?.ok()?.json()
    }
}

/// Corps de requête.
#[derive(Clone, Debug)]
pub enum Body {
    Json(serde_json::Value),
    Form(Vec<(String, String)>),
    Bytes(Vec<u8>, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn rejects_http_and_credentials_in_url() {
        assert!(validate_base_url("http://example.com").is_err());
        assert!(validate_base_url("ftp://example.com").is_err());
        assert!(validate_base_url("https://user:pw@example.com").is_err());
        assert!(validate_base_url("nope").is_err());
        assert!(validate_base_url("https://api.example.com").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_base_url("http://localhost:3000").is_ok());
    }

    #[test]
    fn url_join_and_cross_host_refused() {
        let c = HttpClient::new("https://api.example.com/v1", Auth::None).unwrap();
        assert_eq!(
            c.url("/users").unwrap().as_str(),
            "https://api.example.com/v1/users"
        );
        assert_eq!(
            c.url("users?a=1").unwrap().as_str(),
            "https://api.example.com/v1/users?a=1"
        );
        assert!(c.url("https://evil.example.org/x").is_err());
        assert!(c.url("https://api.example.com/other").is_ok());
        assert!(format!("{c:?}").contains("api.example.com"));
    }

    #[tokio::test]
    async fn auth_headers_sent() {
        let s = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/b"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/h"))
            .and(header("x-api-key", "k"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        Mock::given(method("GET"))
            .and(path("/basic"))
            .and(header("authorization", "Basic dTpw"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        let b = HttpClient::new(&s.uri(), Auth::Bearer(SecretValue::new("tok"))).unwrap();
        let v: serde_json::Value = b.get_json("/b").await.unwrap();
        assert_eq!(v["ok"], true);
        let h = HttpClient::new(
            &s.uri(),
            Auth::Header {
                name: "x-api-key".into(),
                value: SecretValue::new("k"),
            },
        )
        .unwrap();
        assert!(h.get("/h").await.unwrap().status.is_success());
        let ba = HttpClient::new(
            &s.uri(),
            Auth::Basic {
                user: "u".into(),
                pass: SecretValue::new("p"),
            },
        )
        .unwrap();
        assert!(ba.get("/basic").await.unwrap().status.is_success());
        let bad = HttpClient::new(
            &s.uri(),
            Auth::Header {
                name: "bad header".into(),
                value: SecretValue::new("k"),
            },
        )
        .unwrap();
        assert!(bad.get("/h").await.is_err());
    }

    #[tokio::test]
    async fn no_cross_host_redirect_and_errors() {
        let s = MockServer::start().await;
        Mock::given(path("/redir"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "https://evil.example.org/steal"),
            )
            .mount(&s)
            .await;
        for (p, code) in [
            ("/401", 401),
            ("/403", 403),
            ("/404", 404),
            ("/429", 429),
            ("/500", 500),
        ] {
            Mock::given(path(p))
                .respond_with(ResponseTemplate::new(code))
                .mount(&s)
                .await;
        }
        Mock::given(path("/big"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; MAX_BODY + 1]))
            .mount(&s)
            .await;
        Mock::given(path("/badjson"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{"))
            .mount(&s)
            .await;
        let c = HttpClient::new(&s.uri(), Auth::Bearer(SecretValue::new("tok"))).unwrap();
        let r = c.get("/redir").await.unwrap();
        assert_eq!(r.status.as_u16(), 302, "redirection non suivie");
        assert_eq!(r.header("location"), Some("https://evil.example.org/steal"));
        for p in ["/401", "/403", "/404", "/429", "/500"] {
            let e = c.get(p).await.unwrap().ok().unwrap_err();
            assert!(!e.to_string().contains("tok"));
        }
        assert!(c.get("/big").await.is_err());
        assert!(c.get_json::<serde_json::Value>("/badjson").await.is_err());
        let off = HttpClient::new("http://127.0.0.1:1", Auth::None).unwrap();
        assert!(off.get("/").await.is_err());
    }
}

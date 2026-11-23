//! Vérification de disponibilité d'une URL d'application (en ligne / hors ligne).
use crate::common::elapsed_ms;
use crate::http::{Auth, HttpClient};
use crate::types::Health;
use cc_core::Result;
use std::time::Instant;

pub async fn check(url: &str) -> Result<Health> {
    let c = HttpClient::new(url, Auth::None)?;
    let t = Instant::now();
    Ok(
        match c
            .send_url(reqwest::Method::GET, c.base().clone(), None, &[])
            .await
        {
            Ok(r) => Health {
                online: r.status.is_success() || r.status.is_redirection(),
                latency_ms: elapsed_ms(t),
                detail: format!("HTTP {}", r.status.as_u16()),
            },
            Err(e) => Health {
                online: false,
                latency_ms: elapsed_ms(t),
                detail: e.to_string(),
            },
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn online_offline() {
        let s = MockServer::start().await;
        Mock::given(wiremock::matchers::path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s)
            .await;
        Mock::given(wiremock::matchers::path("/down"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&s)
            .await;
        assert!(check(&s.uri()).await.unwrap().online);
        assert!(!check(&format!("{}/down", s.uri())).await.unwrap().online);
        assert!(!check("http://127.0.0.1:1").await.unwrap().online);
        assert!(
            check("http://example.com").await.is_err(),
            "HTTPS obligatoire"
        );
    }
}

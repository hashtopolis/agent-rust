use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

use crate::http::{BasicAuth, HttpSettings};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub trait Transport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError>;
}

/// Lets the tokenless startup client borrow the transport before the
/// authenticated client takes ownership of it.
impl<T: Transport + ?Sized> Transport for &T {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
        (**self).post_json(body).await
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("http error: {}", crate::http::with_causes(.0))]
    Http(#[from] reqwest::Error),
    #[error("unexpected status code from server: {0}")]
    Status(u16),
}

#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    url: String,
    auth: Option<BasicAuth>,
}

impl HttpTransport {
    pub fn new(url: impl Into<String>, settings: &HttpSettings) -> Result<Self, TransportError> {
        let client = settings.client_builder().timeout(DEFAULT_TIMEOUT).build()?;

        Ok(Self {
            client,
            url: url.into(),
            auth: settings.auth().cloned(),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn request(&self, body: &Value) -> reqwest::RequestBuilder {
        let request = self.client.post(&self.url).json(body);

        match &self.auth {
            Some(auth) => auth.apply(request),
            None => request,
        }
    }
}

impl Transport for HttpTransport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
        tracing::trace!(url = %self.url, request = %body, "api request");

        let response = self.request(body).send().await?;
        let status = response.status();

        if !status.is_success() {
            tracing::trace!(status = status.as_u16(), "api response (error status)");

            return Err(TransportError::Status(status.as_u16()));
        }

        let value: Value = response.json().await?;
        tracing::trace!(status = status.as_u16(), response = %value, "api response");

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use reqwest::header::AUTHORIZATION;
    use serde_json::json;

    use crate::config::{BasicAuthConfig, Server};

    fn authorization(settings: &HttpSettings) -> Option<String> {
        let transport =
            HttpTransport::new("https://server.example/api/server.php", settings).unwrap();
        let request = transport.request(&json!({})).build().unwrap();

        request
            .headers()
            .get(AUTHORIZATION)
            .map(|value| value.to_str().unwrap().to_string())
    }

    #[test]
    fn api_requests_carry_basic_auth() {
        let settings = HttpSettings::from_server(&Server {
            basic_auth: Some(BasicAuthConfig::new("agent", "secret")),
            ..Server::default()
        })
        .unwrap();

        // base64("agent:secret")
        assert_eq!(
            authorization(&settings).as_deref(),
            Some("Basic YWdlbnQ6c2VjcmV0")
        );
    }

    #[test]
    fn api_requests_without_auth_send_no_authorization_header() {
        assert_eq!(authorization(&HttpSettings::default()), None);
    }

    #[test]
    fn debug_output_hides_secrets() {
        let settings = HttpSettings::from_server(&Server {
            basic_auth: Some(BasicAuthConfig::new("agent", "secret")),
            proxy: Some("http://puser:hunter2@proxy.example:3128".to_string()),
            ..Server::default()
        })
        .unwrap();
        let transport =
            HttpTransport::new("https://server.example/api/server.php", &settings).unwrap();

        let debug = format!("{transport:?}");

        assert!(!debug.contains("secret"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
    }
}

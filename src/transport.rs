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
    #[error("http error: {0}")]
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
}

impl Transport for HttpTransport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
        tracing::trace!(url = %self.url, request = %body, "api request");

        let mut request = self.client.post(&self.url).json(body);
        if let Some(auth) = &self.auth {
            request = auth.apply(request);
        }

        let response = request.send().await?;
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

    use serde_json::json;

    use crate::config::{BasicAuthConfig, Server};
    use crate::http::test_server::OneShot;

    const OK_RESPONSE: &str = r#"{"action":"testConnection","response":"SUCCESS"}"#;

    async fn post_to(server: &OneShot, settings: &HttpSettings) {
        let transport =
            HttpTransport::new(format!("{}/api/server.php", server.url), settings).unwrap();

        transport
            .post_json(&json!({ "action": "testConnection" }))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn api_requests_carry_basic_auth() {
        let server = OneShot::start(OK_RESPONSE).await;
        let settings = HttpSettings::from_server(&Server {
            basic_auth: Some(BasicAuthConfig::new("agent", "secret")),
            ..Server::default()
        })
        .unwrap();

        post_to(&server, &settings).await;

        let head = server.request_head().await;
        // base64("agent:secret"), lowercased by `request_head`
        assert!(
            head.contains("authorization: basic ywdlbnq6c2vjcmv0"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn api_requests_without_auth_send_no_authorization_header() {
        let server = OneShot::start(OK_RESPONSE).await;

        post_to(&server, &HttpSettings::default()).await;

        let head = server.request_head().await;
        assert!(!head.contains("authorization"), "{head}");
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

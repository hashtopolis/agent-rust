use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

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
}

impl HttpTransport {
    pub fn new(url: impl Into<String>) -> Result<Self, TransportError> {
        Self::with_client(
            url,
            reqwest::Client::builder()
                .timeout(DEFAULT_TIMEOUT)
                .build()?,
        )
    }

    pub fn with_client(
        url: impl Into<String>,
        client: reqwest::Client,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            client,
            url: url.into(),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Transport for HttpTransport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
        let response = self.client.post(&self.url).json(body).send().await?;
        let status = response.status();

        if !status.is_success() {
            return Err(TransportError::Status(status.as_u16()));
        }

        Ok(response.json().await?)
    }
}

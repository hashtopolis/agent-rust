use std::fmt;
use std::time::Duration;

use serde_json::Value;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub trait Transport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError>;
}

#[derive(Debug)]
pub enum TransportError {
    Http(reqwest::Error),
    Status(u16),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Http(e) => write!(f, "http error: {e}"),
            TransportError::Status(code) => write!(f, "unexpected status code from server: {code}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransportError::Http(e) => Some(e),
            TransportError::Status(_) => None,
        }
    }
}

impl From<reqwest::Error> for TransportError {
    fn from(e: reqwest::Error) -> Self {
        TransportError::Http(e)
    }
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

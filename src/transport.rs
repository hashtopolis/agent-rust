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

#[derive(Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    url: String,
    basic_auth: Option<(String, String)>,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("client", &self.client)
            .field("url", &self.url)
            .field(
                "basic_auth",
                &self.basic_auth.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
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
            basic_auth: None,
        })
    }

    pub fn with_basic_auth(mut self, username: String, password: String) -> Self {
        self.basic_auth = Some((username, password));
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Transport for HttpTransport {
    async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
        let mut request = self.client.post(&self.url).json(body);

        if let Some((username, password)) = &self.basic_auth {
            request = request.basic_auth(username, Some(password));
        }

        let response = request.send().await?;
        let status = response.status();

        if !status.is_success() {
            return Err(TransportError::Status(status.as_u16()));
        }

        Ok(response.json().await?)
    }
}

//! HTTP client setup shared by the API transport and the downloader, so the
//! server connection settings (client certificate, proxy, basic auth) apply to
//! every request the agent makes.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::config::Server;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("failed to read client certificate {}: {source}", path.display())]
    ReadCert {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "invalid client certificate {}: expected one PEM file with an X.509 v3 certificate and its unencrypted private key: {source}",
        path.display()
    )]
    InvalidCert {
        path: PathBuf,
        #[source]
        source: reqwest::Error,
    },
    // The url is left out on purpose: it may carry proxy credentials.
    #[error("invalid server.proxy url: {source}")]
    InvalidProxy {
        #[source]
        source: reqwest::Error,
    },
    #[error("server.auth_user and server.auth_password must be set together")]
    PartialAuth,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuth {
    user: String,
    password: String,
}

impl BasicAuth {
    pub fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: password.into(),
        }
    }

    pub fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request.basic_auth(&self.user, Some(&self.password))
    }
}

impl fmt::Debug for BasicAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicAuth")
            .field("user", &self.user)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// The server connection settings, validated once at startup so a bad
/// certificate or proxy fails before the first request.
#[derive(Clone, Default)]
pub struct HttpSettings {
    identity: Option<reqwest::Identity>,
    proxy: Option<reqwest::Proxy>,
    auth: Option<BasicAuth>,
}

impl HttpSettings {
    pub fn from_server(server: &Server) -> Result<Self, HttpError> {
        let identity = server
            .cert
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty())
            .map(read_identity)
            .transpose()?;

        let proxy = non_empty(&server.proxy).map(read_proxy).transpose()?;

        let auth = match (
            non_empty(&server.auth_user),
            non_empty(&server.auth_password),
        ) {
            (Some(user), Some(password)) => Some(BasicAuth::new(user, password)),
            (None, None) => None,
            _ => return Err(HttpError::PartialAuth),
        };

        Ok(Self {
            identity,
            proxy,
            auth,
        })
    }

    /// Callers add their own timeouts: API calls are short, while downloads
    /// may stream for many minutes.
    pub fn client_builder(&self) -> reqwest::ClientBuilder {
        let mut builder = reqwest::Client::builder();

        if let Some(identity) = &self.identity {
            builder = builder.identity(identity.clone());
        }

        if let Some(proxy) = &self.proxy {
            builder = builder.proxy(proxy.clone());
        }

        builder
    }

    pub fn auth(&self) -> Option<&BasicAuth> {
        self.auth.as_ref()
    }
}

fn non_empty(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|value| !value.is_empty())
}

/// reqwest only parses the key and certificate when a client is built, so
/// build a throwaway one here to report a bad file by name at startup. It
/// loads no root certificates, so a broken OS trust store cannot be
/// misreported as a bad client certificate.
fn read_identity(path: &Path) -> Result<reqwest::Identity, HttpError> {
    let pem = fs::read(path).map_err(|source| HttpError::ReadCert {
        path: path.to_path_buf(),
        source,
    })?;

    let invalid = |source| HttpError::InvalidCert {
        path: path.to_path_buf(),
        source,
    };
    let identity = reqwest::Identity::from_pem(&pem).map_err(invalid)?;

    reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .identity(identity.clone())
        .build()
        .map_err(invalid)?;

    Ok(identity)
}

fn read_proxy(url: &str) -> Result<reqwest::Proxy, HttpError> {
    let proxy = reqwest::Proxy::all(url).map_err(|source| HttpError::InvalidProxy { source })?;

    Ok(proxy.no_proxy(reqwest::NoProxy::from_env()))
}

// reqwest's own `Proxy` Debug prints the proxy password, so only say what is set.
impl fmt::Debug for HttpSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpSettings")
            .field("identity", &self.identity.is_some())
            .field("proxy", &self.proxy.is_some())
            .field("auth", &self.auth)
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod test_server {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    /// Answers exactly one HTTP/1.1 request with `200` and a fixed body, and
    /// hands back the request head it received.
    pub(crate) struct OneShot {
        pub(crate) url: String,
        handle: JoinHandle<String>,
    }

    impl OneShot {
        pub(crate) async fn start(body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());

            let handle = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let head = read_request(&mut socket).await;

                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();

                head
            });

            Self { url, handle }
        }

        /// The request line and headers, lowercased so checks need not care
        /// about header case.
        pub(crate) async fn request_head(self) -> String {
            self.handle.await.unwrap().to_lowercase()
        }
    }

    /// Reads the head and drains a `content-length` body, so closing the
    /// socket afterwards cannot reset a client that is still sending.
    async fn read_request(socket: &mut TcpStream) -> String {
        let mut received = Vec::new();
        let mut buf = [0u8; 4096];

        let head_end = loop {
            if let Some(pos) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }

            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before the request head ended");
            received.extend_from_slice(&buf[..n]);
        };

        let head = String::from_utf8_lossy(&received[..head_end]).into_owned();
        let body_len = head
            .lines()
            .find_map(|line| {
                line.to_lowercase()
                    .strip_prefix("content-length:")
                    .map(|value| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);

        while received.len() < head_end + body_len {
            let n = socket.read(&mut buf).await.unwrap();
            assert!(n > 0, "connection closed before the request body ended");
            received.extend_from_slice(&buf[..n]);
        }

        head
    }
}

#[cfg(test)]
mod tests {
    use super::test_server::OneShot;
    use super::*;

    use tempfile::TempDir;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    fn server() -> Server {
        Server::default()
    }

    #[test]
    fn nothing_configured_yields_no_auth() {
        let settings = HttpSettings::from_server(&server()).unwrap();

        assert!(settings.auth().is_none());
        assert!(settings.client_builder().build().is_ok());
    }

    #[test]
    fn empty_strings_count_as_unset() {
        let settings = HttpSettings::from_server(&Server {
            cert: Some(PathBuf::new()),
            proxy: Some(String::new()),
            auth_user: Some(String::new()),
            auth_password: Some(String::new()),
            ..server()
        })
        .unwrap();

        assert!(settings.auth().is_none());
        assert!(!format!("{settings:?}").contains("true"), "{settings:?}");
    }

    #[test]
    fn auth_needs_both_user_and_password() {
        for (user, password) in [
            (Some("agent"), None),
            (None, Some("secret")),
            (Some("agent"), Some("")),
        ] {
            let result = HttpSettings::from_server(&Server {
                auth_user: user.map(str::to_string),
                auth_password: password.map(str::to_string),
                ..server()
            });

            assert!(
                matches!(result, Err(HttpError::PartialAuth)),
                "user {user:?}, password {password:?}: {result:?}"
            );
        }
    }

    #[test]
    fn user_and_password_become_basic_auth() {
        let settings = HttpSettings::from_server(&Server {
            auth_user: Some("agent".to_string()),
            auth_password: Some("secret".to_string()),
            ..server()
        })
        .unwrap();

        assert_eq!(settings.auth(), Some(&BasicAuth::new("agent", "secret")));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let settings = HttpSettings::from_server(&Server {
            auth_user: Some("agent".to_string()),
            auth_password: Some("secret".to_string()),
            proxy: Some("http://puser:hunter2@proxy.example:3128".to_string()),
            ..server()
        })
        .unwrap();

        let debug = format!("{settings:?}");

        assert!(debug.contains("agent"), "{debug}");
        assert!(!debug.contains("secret"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
    }

    #[test]
    fn missing_certificate_file_is_reported_with_its_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("missing.pem");

        let error = HttpSettings::from_server(&Server {
            cert: Some(path.clone()),
            ..server()
        })
        .unwrap_err();

        assert!(matches!(error, HttpError::ReadCert { .. }), "{error:?}");
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn certificate_without_key_is_rejected_with_its_path() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cert-only.pem");
        let identity = fs::read_to_string(fixture("client-identity.pem")).unwrap();
        let cert_end =
            identity.find("-----END CERTIFICATE-----").unwrap() + "-----END CERTIFICATE-----".len();
        fs::write(&path, &identity[..cert_end]).unwrap();

        let error = HttpSettings::from_server(&Server {
            cert: Some(path.clone()),
            ..server()
        })
        .unwrap_err();

        assert!(matches!(error, HttpError::InvalidCert { .. }), "{error:?}");
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn v1_certificate_is_rejected_with_its_path() {
        let path = fixture("client-v1.pem");

        let error = HttpSettings::from_server(&Server {
            cert: Some(path.clone()),
            ..server()
        })
        .unwrap_err();

        assert!(matches!(error, HttpError::InvalidCert { .. }), "{error:?}");
        assert!(
            error.to_string().contains(&path.display().to_string()),
            "{error}"
        );
    }

    #[test]
    fn valid_identity_is_accepted() {
        let settings = HttpSettings::from_server(&Server {
            cert: Some(fixture("client-identity.pem")),
            ..server()
        })
        .unwrap();

        assert!(
            format!("{settings:?}").contains("identity: true"),
            "{settings:?}"
        );
        assert!(settings.client_builder().build().is_ok());
    }

    #[test]
    fn invalid_proxy_error_does_not_echo_the_url() {
        let error = HttpSettings::from_server(&Server {
            proxy: Some("http://puser:hunter2@[::1".to_string()),
            ..server()
        })
        .unwrap_err();

        assert!(matches!(error, HttpError::InvalidProxy { .. }), "{error:?}");
        assert!(
            !format!("{error} {error:?}").contains("hunter2"),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn configured_proxy_receives_the_requests() {
        let proxy = OneShot::start("{}").await;
        let settings = HttpSettings::from_server(&Server {
            proxy: Some(proxy.url.clone()),
            ..server()
        })
        .unwrap();
        let client = settings.client_builder().build().unwrap();

        client
            .get("http://agent-test.invalid/ping")
            .send()
            .await
            .unwrap();

        let head = proxy.request_head().await;
        assert!(
            head.starts_with("get http://agent-test.invalid/ping "),
            "{head}"
        );
    }

    #[tokio::test]
    async fn proxy_credentials_go_in_the_proxy_authorization_header() {
        let proxy = OneShot::start("{}").await;
        let settings = HttpSettings::from_server(&Server {
            proxy: Some(proxy.url.replace("http://", "http://puser:hunter2@")),
            ..server()
        })
        .unwrap();
        let client = settings.client_builder().build().unwrap();

        client
            .get("http://agent-test.invalid/ping")
            .send()
            .await
            .unwrap();

        let head = proxy.request_head().await;
        // base64("puser:hunter2"), lowercased by `request_head`
        assert!(
            head.contains("proxy-authorization: basic chvzzxi6ahvudgvymg=="),
            "{head}"
        );
    }
}

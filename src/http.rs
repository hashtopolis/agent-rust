//! HTTP client setup shared by the API transport and the downloader, so the
//! server connection settings (client certificate, proxy, basic auth) apply to
//! every request the agent makes.

use std::error::Error as _;
use std::fmt::{self, Write as _};
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
    #[error(
        "server.basic_auth needs both user and password (the password may also come from HTP_AUTH_PASSWORD)"
    )]
    PartialAuth,
}

#[derive(Clone, PartialEq, Eq)]
pub struct BasicAuth {
    user: String,
    password: String,
}

impl BasicAuth {
    pub(crate) fn new(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            password: password.into(),
        }
    }

    pub(crate) fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
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
            .client_cert
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty())
            .map(read_identity)
            .transpose()?;

        let proxy = non_empty(&server.proxy).map(read_proxy).transpose()?;

        let (user, password) = match &server.basic_auth {
            Some(auth) => (non_empty(&auth.user), non_empty(&auth.password)),
            None => (None, None),
        };

        let auth = match (user, password) {
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

    /// Basic auth over plain http puts the password on the wire readable by
    /// anyone in between. It still works, since TLS may be terminated outside
    /// the agent, so callers only warn.
    pub fn sends_credentials_in_clear(&self, server_url: &str) -> bool {
        self.auth.is_some()
            && reqwest::Url::parse(server_url).is_ok_and(|url| url.scheme() == "http")
    }
}

/// reqwest's own message stops at "error sending request for url (...)"; the
/// actual cause (refused connection, untrusted certificate, TLS alert) is in
/// its source chain, so spell that out for log lines.
pub(crate) fn with_causes(error: &reqwest::Error) -> String {
    let mut message = error.to_string();
    let mut cause = error.source();

    while let Some(current) = cause {
        write!(message, ": {current}").expect("writing to a String cannot fail");
        cause = current.source();
    }

    message
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
mod tests {
    use super::*;

    use crate::config::BasicAuthConfig;

    use tempfile::TempDir;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn nothing_configured_yields_no_auth() {
        let settings = HttpSettings::from_server(&Server::default()).unwrap();

        assert!(settings.auth().is_none());
        assert!(settings.client_builder().build().is_ok());
    }

    #[test]
    fn empty_strings_count_as_unset() {
        let settings = HttpSettings::from_server(&Server {
            client_cert: Some(PathBuf::new()),
            proxy: Some(String::new()),
            basic_auth: Some(BasicAuthConfig::new("", "")),
            ..Server::default()
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
                basic_auth: Some(BasicAuthConfig {
                    user: user.map(str::to_string),
                    password: password.map(str::to_string),
                }),
                ..Server::default()
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
            basic_auth: Some(BasicAuthConfig::new("agent", "secret")),
            ..Server::default()
        })
        .unwrap();

        assert_eq!(settings.auth(), Some(&BasicAuth::new("agent", "secret")));
    }

    #[test]
    fn debug_output_hides_secrets() {
        let settings = HttpSettings::from_server(&Server {
            basic_auth: Some(BasicAuthConfig::new("agent", "secret")),
            proxy: Some("http://puser:hunter2@proxy.example:3128".to_string()),
            ..Server::default()
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
            client_cert: Some(path.clone()),
            ..Server::default()
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
            client_cert: Some(path.clone()),
            ..Server::default()
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
            client_cert: Some(path.clone()),
            ..Server::default()
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
            client_cert: Some(fixture("client-identity.pem")),
            ..Server::default()
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
            ..Server::default()
        })
        .unwrap_err();

        assert!(matches!(error, HttpError::InvalidProxy { .. }), "{error:?}");
        assert!(
            !format!("{error} {error:?}").contains("hunter2"),
            "{error:?}"
        );
    }

    #[test]
    fn basic_auth_over_plain_http_is_flagged() {
        let settings = HttpSettings::from_server(&Server {
            basic_auth: Some(BasicAuthConfig::new("agent", "secret")),
            ..Server::default()
        })
        .unwrap();

        assert!(settings.sends_credentials_in_clear("http://server.example/api/server.php"));
        assert!(settings.sends_credentials_in_clear("HTTP://server.example/api/server.php"));
        assert!(!settings.sends_credentials_in_clear("https://server.example/api/server.php"));
        assert!(
            !HttpSettings::default()
                .sends_credentials_in_clear("http://server.example/api/server.php")
        );
    }
}

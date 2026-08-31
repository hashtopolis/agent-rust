//! Fetching bytes onto disk. Separate from [`Transport`](crate::transport) because the
//! JSON API is one POST endpoint while assets are GETs against arbitrary URLs,
//! streamed to a path.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("http error for {url}: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("unexpected status code {status} for {url}")]
    Status { url: String, status: u16 },
    #[error("cannot resolve download url {url}")]
    Url { url: String },
    #[error("failed to write {}: {source}", path.display())]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

pub trait Downloader {
    async fn download(&self, url: &str, dest: &Path) -> Result<(), DownloadError>;
}

impl<D: Downloader + ?Sized> Downloader for &D {
    async fn download(&self, url: &str, dest: &Path) -> Result<(), DownloadError> {
        (**self).download(url, dest).await
    }
}

#[derive(Clone)]
pub struct HttpDownloader {
    server_client: reqwest::Client,
    external_client: reqwest::Client,
    base_url: String,
    basic_auth: Option<(String, String)>,
}

impl std::fmt::Debug for HttpDownloader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDownloader")
            .field("server_client", &self.server_client)
            .field("external_client", &self.external_client)
            .field("base_url", &self.base_url)
            .field(
                "basic_auth",
                &self.basic_auth.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl HttpDownloader {
    pub fn new(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self::with_clients(client.clone(), client, base_url)
    }

    pub fn with_clients(
        server_client: reqwest::Client,
        external_client: reqwest::Client,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            server_client,
            external_client,
            base_url: base_url.into(),
            basic_auth: None,
        }
    }

    pub fn with_basic_auth(mut self, username: String, password: String) -> Self {
        self.basic_auth = Some((username, password));
        self
    }

    /// Cracker and preprocessor downloads carry absolute URLs; hashlist, file and
    /// found downloads carry paths relative to the server root, which is the API
    /// url with its `api/server.php` endpoint stripped off.
    fn resolve(&self, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            return url.to_string();
        }

        let root = self.base_url.replace("api/server.php", "");

        format!("{root}{url}")
    }

    fn is_server_url(&self, url: &str) -> bool {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return true;
        }

        let (Ok(base), Ok(candidate)) = (
            reqwest::Url::parse(&self.base_url),
            reqwest::Url::parse(url),
        ) else {
            return false;
        };

        base.scheme() == candidate.scheme()
            && base.host_str() == candidate.host_str()
            && base.port_or_known_default() == candidate.port_or_known_default()
    }
}

impl Downloader for HttpDownloader {
    async fn download(&self, url: &str, dest: &Path) -> Result<(), DownloadError> {
        let server_url = self.is_server_url(url);
        let url = self.resolve(url);
        let client = if server_url {
            &self.server_client
        } else {
            &self.external_client
        };
        let mut request = client.get(&url);

        if server_url && let Some((username, password)) = &self.basic_auth {
            request = request.basic_auth(username, Some(password));
        }

        let mut response = request.send().await.map_err(|source| DownloadError::Http {
            url: url.clone(),
            source,
        })?;

        let status = response.status();

        if !status.is_success() {
            return Err(DownloadError::Status {
                url,
                status: status.as_u16(),
            });
        }

        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|source| DownloadError::Write {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }

        let mut file =
            tokio::fs::File::create(dest)
                .await
                .map_err(|source| DownloadError::Write {
                    path: dest.to_path_buf(),
                    source,
                })?;

        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|source| DownloadError::Http {
                url: url.clone(),
                source,
            })?
        {
            file.write_all(&chunk)
                .await
                .map_err(|source| DownloadError::Write {
                    path: dest.to_path_buf(),
                    source,
                })?;
        }

        file.flush().await.map_err(|source| DownloadError::Write {
            path: dest.to_path_buf(),
            source,
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn downloader(base_url: &str) -> HttpDownloader {
        HttpDownloader::new(reqwest::Client::new(), base_url)
    }

    #[test]
    fn absolute_urls_pass_through_unchanged() {
        let d = downloader("https://server.example/api/server.php");

        assert_eq!(
            d.resolve("https://hashcat.net/files/hashcat-6.2.6.7z"),
            "https://hashcat.net/files/hashcat-6.2.6.7z"
        );
    }

    #[test]
    fn relative_urls_join_the_server_root() {
        let d = downloader("https://server.example/api/server.php");

        assert_eq!(
            d.resolve("getFile/12/wordlist.txt"),
            "https://server.example/getFile/12/wordlist.txt"
        );
    }

    #[test]
    fn relative_and_same_origin_urls_use_the_server_client() {
        let d = downloader("https://server.example:443/api/server.php");

        assert!(d.is_server_url("getFile/12/wordlist.txt"));
        assert!(d.is_server_url("https://server.example/getFile/12/wordlist.txt"));
    }

    #[test]
    fn external_urls_do_not_receive_server_credentials() {
        let d = downloader("https://server.example/api/server.php");

        assert!(!d.is_server_url("https://downloads.example/hashcat.7z"));
        assert!(!d.is_server_url("http://server.example/hashcat.7z"));
    }
}

//! Fetching bytes onto disk. Separate from [`Transport`](crate::transport) because the
//! JSON API is one POST endpoint while assets are GETs against arbitrary URLs,
//! streamed to a path.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::io::AsyncWriteExt;

use crate::http::BasicAuth;

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

#[derive(Debug, Clone)]
pub struct HttpDownloader {
    client: reqwest::Client,
    base_url: String,
    auth: Option<BasicAuth>,
}

impl HttpDownloader {
    pub fn new(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into(),
            auth: None,
        }
    }

    /// Basic auth for the server. Sent only to the server's own origin, never
    /// to the absolute cracker and preprocessor urls on other hosts.
    pub fn with_auth(mut self, auth: Option<BasicAuth>) -> Self {
        self.auth = auth;
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

    fn auth_for(&self, url: &str) -> Option<&BasicAuth> {
        let auth = self.auth.as_ref()?;
        let target = reqwest::Url::parse(url).ok()?;
        let server = reqwest::Url::parse(&self.base_url).ok()?;

        (target.origin() == server.origin()).then_some(auth)
    }
}

impl Downloader for HttpDownloader {
    async fn download(&self, url: &str, dest: &Path) -> Result<(), DownloadError> {
        let url = self.resolve(url);

        let mut request = self.client.get(&url);
        if let Some(auth) = self.auth_for(&url) {
            request = auth.apply(request);
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

    use crate::http::BasicAuth;
    use crate::http::test_server::OneShot;

    use tempfile::TempDir;

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

    fn auth() -> BasicAuth {
        BasicAuth::new("agent", "secret")
    }

    #[test]
    fn auth_goes_only_to_the_server_origin() {
        let d = downloader("https://server.example/api/server.php").with_auth(Some(auth()));

        assert!(
            d.auth_for("https://server.example/getFile/1/words.txt")
                .is_some()
        );
        assert!(
            d.auth_for("https://SERVER.example:443/getFile/1/words.txt")
                .is_some()
        );
        assert!(
            d.auth_for("https://hashcat.net/files/hashcat-6.2.6.7z")
                .is_none()
        );
        assert!(
            d.auth_for("http://server.example/getFile/1/words.txt")
                .is_none()
        );
        assert!(
            d.auth_for("https://server.example:8443/getFile/1/words.txt")
                .is_none()
        );
        assert!(d.auth_for("https://server.example.evil.test/x").is_none());
    }

    #[test]
    fn no_auth_configured_sends_none() {
        let d = downloader("https://server.example/api/server.php");

        assert!(
            d.auth_for("https://server.example/getFile/1/words.txt")
                .is_none()
        );
    }

    #[tokio::test]
    async fn relative_downloads_carry_basic_auth_and_foreign_ones_do_not() {
        let server = OneShot::start("wordlist").await;
        let elsewhere = OneShot::start("cracker").await;
        let dir = TempDir::new().unwrap();
        let d = downloader(&format!("{}/api/server.php", server.url)).with_auth(Some(auth()));

        d.download("getFile/1/words.txt", &dir.path().join("words.txt"))
            .await
            .unwrap();
        d.download(
            &format!("{}/hashcat.7z", elsewhere.url),
            &dir.path().join("hashcat.7z"),
        )
        .await
        .unwrap();

        let server_head = server.request_head().await;
        let elsewhere_head = elsewhere.request_head().await;
        assert!(
            server_head.contains("authorization: basic ywdlbnq6c2vjcmv0"),
            "{server_head}"
        );
        assert!(
            !elsewhere_head.contains("authorization"),
            "{elsewhere_head}"
        );
    }
}

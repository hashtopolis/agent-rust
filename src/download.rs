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

#[derive(Debug, Clone)]
pub struct HttpDownloader {
    client: reqwest::Client,
    base_url: String,
}

impl HttpDownloader {
    pub fn new(client: reqwest::Client, base_url: impl Into<String>) -> Self {
        Self {
            client,
            base_url: base_url.into(),
        }
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
}

impl Downloader for HttpDownloader {
    async fn download(&self, url: &str, dest: &Path) -> Result<(), DownloadError> {
        let url = self.resolve(url);

        let mut response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|source| DownloadError::Http {
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
}

//! Fetching bytes onto disk. Separate from [`Transport`](crate::transport) because the
//! JSON API is one POST endpoint while assets are GETs against arbitrary URLs,
//! streamed to a path.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

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
}

impl Downloader for HttpDownloader {
    async fn download(&self, url: &str, dest: &Path) -> Result<(), DownloadError> {
        let _ = &self.client;
        let _ = &self.base_url;

        tracing::info!(url, dest = %dest.display(), "download; not yet implemented");

        Ok(())
    }
}

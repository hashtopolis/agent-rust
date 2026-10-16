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
    #[error("http error for {url}: {}", crate::http::with_causes(.source))]
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
    /// The credentials and the parsed server url whose origin they are for.
    auth: Option<(BasicAuth, reqwest::Url)>,
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
        self.auth = auth.zip(reqwest::Url::parse(&self.base_url).ok());
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
        let (auth, server) = self.auth.as_ref()?;
        let target = reqwest::Url::parse(url).ok()?;

        (target.origin() == server.origin()).then_some(auth)
    }

    /// Resolves `url` and builds the GET for it, with basic auth only when the
    /// resolved url is on the server's origin. Returns the resolved url too,
    /// for error messages.
    fn request(&self, url: &str) -> (String, reqwest::RequestBuilder) {
        let url = self.resolve(url);
        let request = self.client.get(&url);

        let request = match self.auth_for(&url) {
            Some(auth) => auth.apply(request),
            None => request,
        };

        (url, request)
    }
}

impl Downloader for HttpDownloader {
    async fn download(&self, url: &str, dest: &Path) -> Result<(), DownloadError> {
        let (url, request) = self.request(url);

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

    use reqwest::header::AUTHORIZATION;

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

    fn authorization(d: &HttpDownloader, url: &str) -> Option<String> {
        let (_, request) = d.request(url);
        let request = request.build().unwrap();

        request
            .headers()
            .get(AUTHORIZATION)
            .map(|value| value.to_str().unwrap().to_string())
    }

    #[test]
    fn basic_auth_goes_only_to_the_server_origin() {
        let d = downloader("https://server.example/api/server.php").with_auth(Some(auth()));

        for url in [
            "getFile/1/words.txt",
            "https://server.example/getFile/1/words.txt",
            "https://SERVER.example:443/getFile/1/words.txt",
        ] {
            // base64("agent:secret")
            assert_eq!(
                authorization(&d, url).as_deref(),
                Some("Basic YWdlbnQ6c2VjcmV0"),
                "{url}"
            );
        }

        for url in [
            "https://hashcat.net/files/hashcat-6.2.6.7z",
            "http://server.example/getFile/1/words.txt",
            "https://server.example:8443/getFile/1/words.txt",
            "https://server.example.evil.test/x",
        ] {
            assert_eq!(authorization(&d, url), None, "{url}");
        }
    }

    #[test]
    fn no_auth_configured_sends_none() {
        let d = downloader("https://server.example/api/server.php");

        assert_eq!(authorization(&d, "getFile/1/words.txt"), None);
    }
}

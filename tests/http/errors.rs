use serde_json::json;
use tempfile::TempDir;

use htp_agent::download::{Downloader, HttpDownloader};
use htp_agent::http::HttpSettings;
use htp_agent::transport::{HttpTransport, Transport};

use crate::support::one_shot::closed_url;

// reqwest's own message stops at "error sending request"; the cause must
// follow it, because that is what an operator debugging TLS or a proxy reads.
const CAUSE: &str = "tcp connect error";

#[tokio::test]
async fn transport_errors_name_the_cause() {
    let transport = HttpTransport::new(closed_url().await, &HttpSettings::default()).unwrap();

    let error = transport.post_json(&json!({})).await.unwrap_err();

    assert!(error.to_string().contains(CAUSE), "{error}");
}

#[tokio::test]
async fn download_errors_name_the_cause() {
    let dir = TempDir::new().unwrap();
    let downloader = HttpDownloader::new(reqwest::Client::new(), closed_url().await);

    let error = downloader
        .download("getFile/1/words.txt", &dir.path().join("words.txt"))
        .await
        .unwrap_err();

    assert!(error.to_string().contains(CAUSE), "{error}");
}

use serde_json::json;
use tempfile::TempDir;

use htp_agent::config::{BasicAuthConfig, Server};
use htp_agent::download::{Downloader, HttpDownloader};
use htp_agent::http::HttpSettings;
use htp_agent::transport::{HttpTransport, Transport};

use crate::support::one_shot::OneShot;

const OK_RESPONSE: &str = r#"{"action":"testConnection","response":"SUCCESS"}"#;

// base64("agent:secret"), lowercased by `request_head`
const AGENT_SECRET: &str = "authorization: basic ywdlbnq6c2vjcmv0";

fn with_basic_auth() -> HttpSettings {
    HttpSettings::from_server(&Server {
        basic_auth: Some(BasicAuthConfig {
            user: Some("agent".to_string()),
            password: Some("secret".to_string()),
        }),
        ..Server::default()
    })
    .unwrap()
}

async fn post_to(server: &OneShot, settings: &HttpSettings) {
    let transport = HttpTransport::new(format!("{}/api/server.php", server.url), settings).unwrap();

    transport
        .post_json(&json!({ "action": "testConnection" }))
        .await
        .unwrap();
}

#[tokio::test]
async fn api_requests_carry_basic_auth() {
    let server = OneShot::start(OK_RESPONSE).await;

    post_to(&server, &with_basic_auth()).await;

    let head = server.request_head().await;
    assert!(head.contains(AGENT_SECRET), "{head}");
}

#[tokio::test]
async fn api_requests_without_auth_send_no_authorization_header() {
    let server = OneShot::start(OK_RESPONSE).await;

    post_to(&server, &HttpSettings::default()).await;

    let head = server.request_head().await;
    assert!(!head.contains("authorization"), "{head}");
}

#[tokio::test]
async fn relative_downloads_carry_basic_auth_and_foreign_ones_do_not() {
    let server = OneShot::start("wordlist").await;
    let elsewhere = OneShot::start("cracker").await;
    let dir = TempDir::new().unwrap();
    let settings = with_basic_auth();
    let downloader = HttpDownloader::new(
        settings.client_builder().build().unwrap(),
        format!("{}/api/server.php", server.url),
    )
    .with_auth(settings.auth().cloned());

    downloader
        .download("getFile/1/words.txt", &dir.path().join("words.txt"))
        .await
        .unwrap();
    downloader
        .download(
            &format!("{}/hashcat.7z", elsewhere.url),
            &dir.path().join("hashcat.7z"),
        )
        .await
        .unwrap();

    let server_head = server.request_head().await;
    let elsewhere_head = elsewhere.request_head().await;
    assert!(server_head.contains(AGENT_SECRET), "{server_head}");
    assert!(
        !elsewhere_head.contains("authorization"),
        "{elsewhere_head}"
    );
}

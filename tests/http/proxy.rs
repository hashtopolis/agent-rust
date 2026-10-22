use htp_agent::config::Server;
use htp_agent::http::HttpSettings;

use crate::support::one_shot::OneShot;

/// Sends one plain-http GET with `proxy_url` as `server.proxy`.
async fn get_through(proxy_url: String) {
    let settings = HttpSettings::from_server(&Server {
        proxy: Some(proxy_url),
        ..Server::default()
    })
    .unwrap();
    let client = settings.client_builder().build().unwrap();

    client
        .get("http://agent-test.invalid/ping")
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn the_configured_proxy_receives_the_requests() {
    let proxy = OneShot::start("{}").await;

    get_through(proxy.url.clone()).await;

    let head = proxy.request_head().await;
    assert!(
        head.starts_with("get http://agent-test.invalid/ping "),
        "{head}"
    );
}

#[tokio::test]
async fn proxy_credentials_go_in_the_proxy_authorization_header() {
    let proxy = OneShot::start("{}").await;

    get_through(proxy.url.replace("http://", "http://puser:hunter2@")).await;

    let head = proxy.request_head().await;
    // base64("puser:hunter2"), lowercased by `request_head`
    assert!(
        head.contains("proxy-authorization: basic chvzzxi6ahvudgvymg=="),
        "{head}"
    );
}

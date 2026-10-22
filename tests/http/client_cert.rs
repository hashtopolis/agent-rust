use htp_agent::config::Server;
use htp_agent::http::HttpSettings;

use crate::support::fixture;
use crate::support::tls_server::{ClientAuth, TEST_CA, TlsServer};

/// Trusts the test CA directly, so these tests do not depend on the OS store.
fn client(settings: &HttpSettings) -> reqwest::Client {
    settings
        .client_builder()
        .add_root_certificate(reqwest::Certificate::from_pem(TEST_CA).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn the_configured_client_certificate_is_presented() {
    let server = TlsServer::start(ClientAuth::Required).await;
    let settings = HttpSettings::from_server(&Server {
        client_cert: Some(fixture("client-identity.pem")),
        ..Server::default()
    })
    .unwrap();

    let response = client(&settings).get(&server.url).send().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(server.finish().await.unwrap().client_cert_presented);
}

#[tokio::test]
async fn a_server_requiring_a_client_certificate_rejects_us_without_one() {
    let server = TlsServer::start(ClientAuth::Required).await;

    let result = client(&HttpSettings::default())
        .get(&server.url)
        .send()
        .await;

    assert!(result.is_err(), "{result:?}");
    let error = server.finish().await.unwrap_err();
    assert!(error.contains("no certificates"), "{error}");
}

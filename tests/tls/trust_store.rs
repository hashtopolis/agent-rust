use htp_agent::http::HttpSettings;

use crate::server::{ClientAuth, TlsServer};

// Gated on HTP_TRUST_STORE_TEST: the flag is a promise that the test CA from
// tests/fixtures is trusted, either through the OS store (CI installs it) or
// through SSL_CERT_FILE. Without that promise the CA is unknown and the test
// would fail for reasons unrelated to the agent.
#[tokio::test]
async fn a_server_signed_by_a_trusted_internal_ca_is_accepted() {
    if std::env::var_os("HTP_TRUST_STORE_TEST").is_none() {
        return;
    }

    let server = TlsServer::start(ClientAuth::None).await;
    let client = HttpSettings::default().client_builder().build().unwrap();

    let response = client.get(&server.url).send().await.unwrap();

    assert_eq!(response.status(), 200);
    assert!(server.finish().await.is_ok());
}

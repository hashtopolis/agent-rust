//! A one-shot HTTPS server on 127.0.0.1 whose certificate is signed by the
//! test CA in `tests/fixtures`, optionally demanding a client certificate.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

pub const TEST_CA: &[u8] = include_bytes!("../../fixtures/test-ca.pem");
const LOCALHOST: &[u8] = include_bytes!("../../fixtures/localhost.pem");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    None,
    Required,
}

/// What the server saw of the one connection it accepted.
#[derive(Debug)]
pub struct Connection {
    pub client_cert_presented: bool,
}

pub struct TlsServer {
    pub url: String,
    handle: JoinHandle<Result<Connection, String>>,
}

impl TlsServer {
    pub async fn start(client_auth: ClientAuth) -> Self {
        let acceptor = TlsAcceptor::from(Arc::new(server_config(client_auth)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "https://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        );

        let handle = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
            let client_cert_presented = tls
                .get_ref()
                .1
                .peer_certificates()
                .is_some_and(|certs| !certs.is_empty());

            let mut received = Vec::new();
            let mut buf = [0u8; 1024];

            while !received.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = tls.read(&mut buf).await.map_err(|e| e.to_string())?;

                if n == 0 {
                    return Err("connection closed before the request head ended".to_string());
                }

                received.extend_from_slice(&buf[..n]);
            }

            tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .map_err(|e| e.to_string())?;
            tls.shutdown().await.ok();

            Ok(Connection {
                client_cert_presented,
            })
        });

        Self { url, handle }
    }

    /// The accepted connection, or the handshake or IO error that ended it.
    pub async fn finish(self) -> Result<Connection, String> {
        self.handle.await.unwrap()
    }
}

fn server_config(client_auth: ClientAuth) -> ServerConfig {
    let provider = Arc::new(ring::default_provider());
    let certs = CertificateDer::pem_slice_iter(LOCALHOST)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(LOCALHOST).unwrap();

    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();

    let builder = match client_auth {
        ClientAuth::None => builder.with_no_client_auth(),
        ClientAuth::Required => {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from_pem_slice(TEST_CA).unwrap())
                .unwrap();
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .unwrap();

            builder.with_client_cert_verifier(verifier)
        }
    };

    builder.with_single_cert(certs, key).unwrap()
}

//! TLS against a local HTTPS server: the client certificate from
//! `server.cert`, and server certificates trusted through the OS store. CI
//! runs these on Linux, macOS and Windows, so every platform's certificate
//! handling is exercised.

mod server;

mod client_cert;
mod trust_store;

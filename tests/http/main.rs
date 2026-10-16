//! The HTTP layer against local servers: basic auth, the proxy, error messages,
//! the client certificate from `server.client_cert`, and server certificates
//! trusted through the OS store. CI runs these on Linux, macOS and Windows, so
//! every platform's certificate handling is exercised.

mod support;

mod basic_auth;
mod client_cert;
mod errors;
mod proxy;
mod trust_store;

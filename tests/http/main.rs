//! The HTTP layer against local servers: the proxy, error messages, the
//! client certificate from `server.client_cert`, and server certificates
//! trusted through the OS store. CI runs these on Linux, macOS and Windows; the
//! OS trust store test runs where CI can install the test CA (Linux, Windows).

mod support;

mod client_cert;
mod errors;
mod proxy;
mod trust_store;

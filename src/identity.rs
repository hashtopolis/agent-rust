const AGENT_TYPE: &str = "rust";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const AGENT_TARGET: &str = env!("TARGET_TRIPLE");

pub fn agent_type() -> &'static str {
    AGENT_TYPE
}

pub fn agent_version() -> &'static str {
    AGENT_VERSION
}

/// The target triple this binary was compiled for (e.g.
/// `x86_64-unknown-linux-musl`). Used to select the matching binary from a
/// bundled release on self-update.
pub fn agent_target() -> &'static str {
    AGENT_TARGET
}

pub fn client_signature() -> String {
    format!("s3-{AGENT_TYPE}-{AGENT_VERSION}")
}

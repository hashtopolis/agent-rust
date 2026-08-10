const AGENT_TYPE: &str = "rust";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn agent_type() -> &'static str {
    AGENT_TYPE
}

pub fn agent_version() -> &'static str {
    AGENT_VERSION
}

pub fn client_signature() -> String {
    format!("s3-{AGENT_TYPE}-{AGENT_VERSION}")
}

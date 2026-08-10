use std::fs;
use std::path::PathBuf;

use htp_agent::agent::Session;
use htp_agent::config::{Config, Overrides};
use serde_json::{Value, json};
use tempfile::TempDir;

/// A temporary working directory holding the two config files, so a test can
/// build a [`Config`] and inspect what the agent wrote to `state.json`.
pub struct Env {
    _dir: TempDir,
    pub settings_path: PathBuf,
    pub state_path: PathBuf,
}

impl Env {
    pub fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let settings_path = dir.path().join("config.json");
        let state_path = dir.path().join("state.json");

        fs::write(
            &settings_path,
            json!({
                "server": {
                    "url": "https://example.com/api/server.php",
                    "voucher": "89GD78tf"
                }
            })
            .to_string(),
        )
        .unwrap();

        Self {
            _dir: dir,
            settings_path,
            state_path,
        }
    }

    /// Seed `state.json` with a token, as if the agent had already registered.
    pub fn with_token(self, token: &str) -> Self {
        fs::write(&self.state_path, json!({ "token": token }).to_string()).unwrap();
        self
    }

    pub fn config(&self) -> Config {
        Config::load(&self.settings_path, &self.state_path, Overrides::default()).unwrap()
    }

    pub fn state_json(&self) -> Option<Value> {
        fs::read_to_string(&self.state_path)
            .ok()
            .map(|raw| serde_json::from_str(&raw).unwrap())
    }
}

/// A plausible in-memory session, for building an [`Agent`](htp_agent::agent::Agent)
/// directly without the login handshake.
pub fn test_session() -> Session {
    Session {
        timeout: 30,
        multicast_enabled: false,
        server_version: "test".to_string(),
    }
}

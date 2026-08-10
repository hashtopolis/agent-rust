use htp_agent::agent::{Agent, AgentError};
use htp_agent::config::Config;
use serde_json::json;

use crate::support::env::Env;
use crate::support::provisioner::FakeProvisioner;
use crate::support::transport::{ScriptedTransport, success};

fn login_reply() -> serde_json::Value {
    json!({
        "action": "login",
        "response": "SUCCESS",
        "timeout": 30,
        "multicastEnabled": false,
        "server-version": "0.14.0"
    })
}

#[tokio::test]
async fn fresh_start_registers_then_reports_and_logs_in() {
    let env = Env::new();

    let transport = ScriptedTransport::new([
        success("testConnection"),
        json!({"action": "register", "response": "SUCCESS", "token": "fresh-token"}),
        login_reply(),
        success("updateInformation"),
    ]);
    let probe = transport.clone();

    Agent::bootstrap(transport, env.config(), FakeProvisioner::default())
        .await
        .unwrap();

    assert_eq!(
        probe.actions(),
        ["testConnection", "register", "login", "updateInformation"]
    );

    // register carries no token; the reported and login requests carry the one
    // the server just issued.
    assert!(probe.request_for("register")["token"].is_null());
    assert_eq!(
        probe.request_for("updateInformation")["token"],
        "fresh-token"
    );
    assert_eq!(probe.request_for("login")["token"], "fresh-token");

    // The freshly issued token is persisted.
    assert_eq!(env.state_json().unwrap()["token"], "fresh-token");
}

#[tokio::test]
async fn existing_token_skips_registration() {
    let env = Env::new().with_token("stored-token");

    let transport = ScriptedTransport::new([
        success("testConnection"),
        login_reply(),
        success("updateInformation"),
    ]);
    let probe = transport.clone();

    Agent::bootstrap(transport, env.config(), FakeProvisioner::default())
        .await
        .unwrap();

    assert_eq!(
        probe.actions(),
        ["testConnection", "login", "updateInformation"]
    );
    assert_eq!(
        probe.request_for("updateInformation")["token"],
        "stored-token"
    );
}

#[tokio::test]
async fn register_uses_the_configured_agent_name() {
    let env = Env::new();

    // Rewrite settings to include an explicit agent name.
    std::fs::write(
        &env.settings_path,
        json!({
            "server": {
                "url": "https://example.com/api/server.php",
                "voucher": "89GD78tf"
            },
            "agent": { "name": "cruncher" }
        })
        .to_string(),
    )
    .unwrap();

    let transport = ScriptedTransport::new([
        success("testConnection"),
        json!({"action": "register", "response": "SUCCESS", "token": "t"}),
        login_reply(),
        success("updateInformation"),
    ]);
    let probe = transport.clone();

    Agent::bootstrap(transport, env.config(), FakeProvisioner::default())
        .await
        .unwrap();

    assert_eq!(probe.request_for("register")["name"], "cruncher");
}

#[tokio::test]
async fn invalid_token_on_update_information_is_fatal() {
    let env = Env::new().with_token("stale-token");

    let transport = ScriptedTransport::new([
        success("testConnection"),
        json!({"action": "updateInformation", "response": "ERROR", "message": "Invalid token!"}),
    ]);

    let result = Agent::bootstrap(transport, env.config(), FakeProvisioner::default()).await;

    assert!(
        matches!(result, Err(AgentError::TokenRejected)),
        "expected TokenRejected"
    );
}

#[tokio::test]
async fn missing_voucher_without_token_is_reported() {
    let env = Env::new();

    // Settings with a url but no voucher, and no token in state.
    std::fs::write(
        &env.settings_path,
        json!({ "server": { "url": "https://example.com/api/server.php" } }).to_string(),
    )
    .unwrap();
    let config = Config::load(&env.settings_path, &env.state_path, Default::default()).unwrap();

    let transport = ScriptedTransport::new([success("testConnection")]);

    let result = Agent::bootstrap(transport, config, FakeProvisioner::default()).await;

    assert!(
        matches!(result, Err(AgentError::Config(_))),
        "expected a config error naming the missing voucher"
    );
}

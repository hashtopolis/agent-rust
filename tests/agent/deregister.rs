use htp_agent::agent::{Agent, deregister};
use htp_agent::client::Client;

use crate::support::env::{Env, test_session};
use crate::support::provisioner::FakeProvisioner;
use crate::support::transport::{ScriptedTransport, success};

#[tokio::test]
async fn deregister_sends_request_and_removes_only_the_state_file() {
    let env = Env::new().with_token("stored-token");

    let transport = ScriptedTransport::new([success("deregister")]);
    let probe = transport.clone();

    let config = env.config();
    let client = Client::with_token(transport, "stored-token");

    deregister(&client, &config).await.unwrap();

    assert_eq!(probe.request_for("deregister")["token"], "stored-token");
    assert!(env.state_json().is_none(), "state.json must be gone");
    assert!(
        env.settings_path.exists(),
        "the user's settings file must be left in place"
    );
}

#[tokio::test]
async fn agent_deregister_consumes_the_agent_and_removes_state() {
    let env = Env::new().with_token("stored-token");

    let transport = ScriptedTransport::new([success("deregister")]);
    let probe = transport.clone();

    let client = Client::with_token(transport, "stored-token");
    let agent = Agent::new(
        client,
        env.config(),
        FakeProvisioner::default(),
        test_session(),
    );

    agent.deregister().await.unwrap();

    assert_eq!(probe.request_for("deregister")["token"], "stored-token");
    assert!(env.state_json().is_none(), "state.json must be gone");
    assert!(
        env.settings_path.exists(),
        "the user's settings file must be left in place"
    );
}

use htp_agent::client::{Client, ClientError};
use serde_json::{Value, json};

use crate::support::transport::MockTransport;

pub const TOKEN: &str = "GHhgdf(/&";

pub fn mock_client_returning(reply: Value) -> Client<MockTransport> {
    Client::with_token(MockTransport::new(reply), TOKEN)
}

pub fn error_reply(action: &str) -> Value {
    json!({"action": action, "response": "ERROR", "message": "boom"})
}

pub fn assert_server_error<T: std::fmt::Debug>(result: Result<T, ClientError>, action: &str) {
    match result {
        Err(ClientError::Server { action: a, message }) => {
            assert_eq!(a, action);
            assert_eq!(message.as_deref(), Some("boom"));
        }
        other => panic!("expected server error for '{action}', got {other:?}"),
    }
}

pub fn assert_client_sent_body(client: &Client<MockTransport>, expected: Value) {
    assert_eq!(client.transport().last_request_body(), expected);
}

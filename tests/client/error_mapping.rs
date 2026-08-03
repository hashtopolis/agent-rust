use htp_agent::client::{Client, ClientError};
use htp_agent::model::ProtocolError;
use htp_agent::transport::TransportError;
use serde_json::json;

use crate::common::{TOKEN, assert_client_sent_body, mock_client_returning};
use crate::support::transport::{FailingTransport, MockTransport};

#[tokio::test]
async fn unknown_response_status_is_rejected() {
    let client =
        mock_client_returning(json!({"action": "testConnection", "response": "SOMETHING_ELSE"}));

    match client.test_connection().await {
        Err(ClientError::Server { action, message }) => {
            assert_eq!(action, "testConnection");
            assert!(message.is_none());
        }
        other => panic!("expected server error, got {other:?}"),
    }
}

#[tokio::test]
async fn transport_failure_maps_to_transport_error() {
    let client = Client::with_token(FailingTransport, TOKEN);

    let err = client.get_task().await.unwrap_err();

    assert!(matches!(
        err,
        ClientError::Transport(TransportError::Status(500))
    ));
}

#[tokio::test]
async fn success_missing_required_field_maps_to_protocol_error() {
    let client = mock_client_returning(json!({"action": "register", "response": "SUCCESS"}));

    let err = client.register("v", "host", None).await.unwrap_err();

    assert!(matches!(
        err,
        ClientError::Protocol(ProtocolError::MissingField("token"))
    ));
}

#[tokio::test]
async fn undecodable_success_body_maps_to_codec_error() {
    let client = mock_client_returning(
        json!({"action": "getTask", "response": "SUCCESS", "taskId": "not-a-number"}),
    );

    let err = client.get_task().await.unwrap_err();

    assert!(matches!(err, ClientError::Codec(_)));
}

#[tokio::test]
async fn malformed_success_payload_maps_to_codec_error() {
    let client =
        mock_client_returning(json!({"action": "getChunk", "response": "SUCCESS", "status": 5}));

    let err = client.get_chunk(5).await.unwrap_err();

    assert!(matches!(err, ClientError::Codec(_)));
}

#[tokio::test]
async fn new_token_is_used_after_set_token() {
    let transport =
        MockTransport::new(json!({"action": "getTask", "response": "SUCCESS", "taskId": null}));
    let mut client = Client::new(transport);
    client.set_token("later-token");

    client.get_task().await.unwrap();

    assert_client_sent_body(
        &client,
        json!({"action": "getTask", "token": "later-token"}),
    );
}

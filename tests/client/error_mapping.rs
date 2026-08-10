use htp_agent::client::{Client, ClientError};
use htp_agent::model::ProtocolError;
use htp_agent::transport::TransportError;
use serde_json::json;

use crate::common::{TOKEN, assert_client_sent_body, error_reply, mock_client_returning};
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
        ClientError::Transport {
            action: "getTask",
            source: TransportError::Status(500)
        }
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
async fn tokenless_client_can_register() {
    let transport = MockTransport::new(
        json!({"action": "register", "response": "SUCCESS", "token": "fresh-token"}),
    );
    let client = Client::new(transport);

    let res = client
        .register("89GD78tf", "client name", None)
        .await
        .unwrap();

    assert_eq!(res.token, "fresh-token");
    assert_client_sent_body(
        &client,
        json!({"action": "register", "voucher": "89GD78tf", "name": "client name"}),
    );
}

#[tokio::test]
async fn invalid_token_error_is_recognised_by_its_message() {
    let client = mock_client_returning(
        json!({"action": "getTask", "response": "ERROR", "message": "Invalid token!"}),
    );

    let err = client.get_task().await.unwrap_err();

    assert!(err.is_invalid_token(), "got {err:?}");
}

#[tokio::test]
async fn other_server_errors_are_not_invalid_token() {
    let client = mock_client_returning(error_reply("getTask"));

    let err = client.get_task().await.unwrap_err();

    assert!(!err.is_invalid_token(), "got {err:?}");
}

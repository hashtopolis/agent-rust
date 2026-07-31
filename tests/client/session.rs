use htp_agent::model::{CheckClientVersionResponse, LoginResponse, Os, RegisterResponse};
use serde_json::json;

use crate::common::{
    TOKEN, assert_client_sent_body, assert_server_error, error_reply, mock_client_returning,
};

#[tokio::test]
async fn test_connection_succeeds() {
    let client = mock_client_returning(json!({"action": "testConnection", "response": "SUCCESS"}));

    client.test_connection().await.unwrap();

    assert_client_sent_body(&client, json!({"action": "testConnection"}));
}

#[tokio::test]
async fn test_connection_error() {
    let client = mock_client_returning(error_reply("testConnection"));

    assert_server_error(client.test_connection().await, "testConnection");
}

#[tokio::test]
async fn register_returns_token() {
    let client = mock_client_returning(
        json!({"action": "register", "response": "SUCCESS", "token": "GHhgdf(/&"}),
    );

    let res = client
        .register("89GD78tf", "client name", Some(true))
        .await
        .unwrap();

    assert_eq!(
        res,
        RegisterResponse {
            token: "GHhgdf(/&".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "register", "voucher": "89GD78tf", "name": "client name", "cpu-only": true}),
    );
}

#[tokio::test]
async fn register_error() {
    let client = mock_client_returning(error_reply("register"));

    assert_server_error(
        client.register("89GD78tf", "client name", None).await,
        "register",
    );
}

#[tokio::test]
async fn login_returns_session_details() {
    let client = mock_client_returning(json!({
        "action": "login",
        "response": "SUCCESS",
        "timeout": 30,
        "multicastEnabled": false,
        "server-version": "0.14.0"
    }));

    let res = client.login("generic-python").await.unwrap();

    assert_eq!(
        res,
        LoginResponse {
            timeout: 30,
            multicast_enabled: false,
            server_version: "0.14.0".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "login", "token": TOKEN, "clientSignature": "generic-python"}),
    );
}

#[tokio::test]
async fn login_error() {
    let client = mock_client_returning(error_reply("login"));

    assert_server_error(client.login("generic-python").await, "login");
}

#[tokio::test]
async fn update_information_succeeds() {
    let client =
        mock_client_returning(json!({"action": "updateInformation", "response": "SUCCESS"}));

    client
        .update_information("230-34-345-345", &["ATI HD7970", "ATI HD7970"])
        .await
        .unwrap();

    assert_client_sent_body(
        &client,
        json!({
            "action": "updateInformation",
            "token": TOKEN,
            "uid": "230-34-345-345",
            "os": u8::from(Os::detect()),
            "devices": ["ATI HD7970", "ATI HD7970"]
        }),
    );
}

#[tokio::test]
async fn update_information_error() {
    let client = mock_client_returning(error_reply("updateInformation"));

    assert_server_error(
        client
            .update_information("230-34-345-345", &[] as &[&str])
            .await,
        "updateInformation",
    );
}

#[tokio::test]
async fn check_client_version_returns_up_to_date() {
    let client = mock_client_returning(json!({
        "action": "checkClientVersion",
        "response": "SUCCESS",
        "version": "OK"
    }));

    let res = client
        .check_client_version("0.43.5", "csharp")
        .await
        .unwrap();

    assert_eq!(res, CheckClientVersionResponse::UpToDate);
    assert_client_sent_body(
        &client,
        json!({"action": "checkClientVersion", "token": TOKEN, "version": "0.43.5", "type": "csharp"}),
    );
}

#[tokio::test]
async fn check_client_version_returns_new_version() {
    let client = mock_client_returning(json!({
        "action": "checkClientVersion",
        "response": "SUCCESS",
        "version": "NEW",
        "url": "https://example.com/getclient.php"
    }));

    let res = client
        .check_client_version("0.43.5", "csharp")
        .await
        .unwrap();

    assert_eq!(
        res,
        CheckClientVersionResponse::NewVersion {
            url: "https://example.com/getclient.php".to_string()
        }
    );
}

#[tokio::test]
async fn check_client_version_error() {
    let client = mock_client_returning(error_reply("checkClientVersion"));

    assert_server_error(
        client.check_client_version("0.43.5", "csharp").await,
        "checkClientVersion",
    );
}

#[tokio::test]
async fn deregister_succeeds() {
    let client = mock_client_returning(json!({"action": "deregister", "response": "SUCCESS"}));

    client.deregister().await.unwrap();

    assert_client_sent_body(&client, json!({"action": "deregister", "token": TOKEN}));
}

#[tokio::test]
async fn deregister_error() {
    let client = mock_client_returning(error_reply("deregister"));

    assert_server_error(client.deregister().await, "deregister");
}

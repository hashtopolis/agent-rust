use htp_agent::model::GetHealthCheckResponse;
use serde_json::json;

use crate::common::{
    TOKEN, assert_client_sent_body, assert_server_error, error_reply, mock_client_returning,
};

#[tokio::test]
async fn get_health_check_returns_parameters() {
    let client = mock_client_returning(json!({
        "action": "getHealthCheck",
        "response": "SUCCESS",
        "attack": "#HL# -a 3 -1 ?l?u?d ?1?1?1?1?1",
        "crackerBinaryId": 1,
        "hashes": ["9f650d4ef70eead895e7a03ce0f83e88", "24a7bdfd14bca7f9d14154c0800a833d"],
        "checkId": 7,
        "hashlistAlias": "#HL#"
    }));

    let res = client.get_health_check().await.unwrap();

    assert_eq!(
        res,
        GetHealthCheckResponse {
            attack: "#HL# -a 3 -1 ?l?u?d ?1?1?1?1?1".to_string(),
            cracker_binary_id: 1,
            hashes: vec![
                "9f650d4ef70eead895e7a03ce0f83e88".to_string(),
                "24a7bdfd14bca7f9d14154c0800a833d".to_string()
            ],
            check_id: 7,
            hashlist_alias: "#HL#".to_string()
        }
    );
    assert_client_sent_body(&client, json!({"action": "getHealthCheck", "token": TOKEN}));
}

#[tokio::test]
async fn get_health_check_error() {
    let client = mock_client_returning(error_reply("getHealthCheck"));

    assert_server_error(client.get_health_check().await, "getHealthCheck");
}

#[tokio::test]
async fn send_health_check_succeeds() {
    let client = mock_client_returning(json!({"action": "sendHealthCheck", "response": "SUCCESS"}));

    client
        .send_health_check(
            7,
            23,
            1536306884,
            1536306902,
            1,
            &[
                "nvmlDeviceGetTemperatureThreshold(): Not Supported",
                "nvmlDeviceGetTemperatureThreshold(): Not Supported",
            ],
        )
        .await
        .unwrap();

    assert_client_sent_body(
        &client,
        json!({
            "action": "sendHealthCheck",
            "token": TOKEN,
            "checkId": 7,
            "numCracked": 23,
            "start": 1536306884,
            "end": 1536306902,
            "numGpus": 1,
            "errors": [
                "nvmlDeviceGetTemperatureThreshold(): Not Supported",
                "nvmlDeviceGetTemperatureThreshold(): Not Supported"
            ]
        }),
    );
}

#[tokio::test]
async fn send_health_check_error() {
    let client = mock_client_returning(error_reply("sendHealthCheck"));

    assert_server_error(
        client
            .send_health_check(7, 23, 1536306884, 1536306902, 1, &[] as &[&str])
            .await,
        "sendHealthCheck",
    );
}

use htp_agent::model::{BenchmarkType, ProgressReport, SendProgressResponse};
use serde_json::json;

use crate::common::{
    TOKEN, assert_client_sent_body, assert_server_error, error_reply, mock_client_returning,
};

#[tokio::test]
async fn send_keyspace_succeeds() {
    let client = mock_client_returning(
        json!({"action": "sendKeyspace", "response": "SUCCESS", "keyspace": "OK"}),
    );

    client.send_keyspace(35, 568000).await.unwrap();

    assert_client_sent_body(
        &client,
        json!({"action": "sendKeyspace", "token": TOKEN, "taskId": 35, "keyspace": 568000}),
    );
}

#[tokio::test]
async fn send_keyspace_error() {
    let client = mock_client_returning(error_reply("sendKeyspace"));

    assert_server_error(client.send_keyspace(35, 568000).await, "sendKeyspace");
}

#[tokio::test]
async fn send_benchmark_succeeds() {
    let client = mock_client_returning(
        json!({"action": "sendBenchmark", "response": "SUCCESS", "benchmark": "OK"}),
    );

    client
        .send_benchmark(35, BenchmarkType::Speed, "674:674.74")
        .await
        .unwrap();

    assert_client_sent_body(
        &client,
        json!({
            "action": "sendBenchmark",
            "token": TOKEN,
            "taskId": 35,
            "type": "speed",
            "result": "674:674.74"
        }),
    );
}

#[tokio::test]
async fn send_benchmark_error() {
    let client = mock_client_returning(error_reply("sendBenchmark"));

    assert_server_error(
        client
            .send_benchmark(35, BenchmarkType::Speed, "674:674.74")
            .await,
        "sendBenchmark",
    );
}

#[tokio::test]
async fn send_progress_returns_stop() {
    let client = mock_client_returning(json!({
        "action": "sendProgress",
        "response": "SUCCESS",
        "cracked": 2,
        "skipped": 0,
        "agent": "stop"
    }));
    let res = client
        .send_progress(ProgressReport {
            chunk_id: 35,
            keyspace_progress: 568000,
            relative_progress: 4545,
            speed: 570000,
            state: 3,
            cracks: vec![
                vec![
                    "7fde65673fd28736423f23423786f".to_string(),
                    "thisisplain".to_string(),
                    "746869736973706c61696e".to_string(),
                    "787523889".to_string(),
                ],
                vec![
                    "7fde65673f28987f7423f2342378f".to_string(),
                    "otherplain".to_string(),
                    "6f74686572706c61696e".to_string(),
                    "78652".to_string(),
                ],
            ],
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        res,
        SendProgressResponse::Stop {
            cracked: 2,
            skipped: 0
        }
    );
    assert_client_sent_body(
        &client,
        json!({
            "action": "sendProgress",
            "token": TOKEN,
            "chunkId": 35,
            "keyspaceProgress": 568000,
            "relativeProgress": 4545,
            "speed": 570000,
            "state": 3,
            "cracks": [
                ["7fde65673fd28736423f23423786f", "thisisplain", "746869736973706c61696e", "787523889"],
                ["7fde65673f28987f7423f2342378f", "otherplain", "6f74686572706c61696e", "78652"]
            ]
        }),
    );
}

#[tokio::test]
async fn send_progress_returns_continue() {
    let client = mock_client_returning(json!({
        "action": "sendProgress",
        "response": "SUCCESS",
        "cracked": 2,
        "skipped": 0,
        "zaps": ["87634876fe7f7df5e76f56a757", "7863487563874ffefe67575745"]
    }));

    let res = client
        .send_progress(ProgressReport::default())
        .await
        .unwrap();

    assert_eq!(
        res,
        SendProgressResponse::Continue {
            cracked: 2,
            skipped: 0,
            zaps: vec![
                "87634876fe7f7df5e76f56a757".to_string(),
                "7863487563874ffefe67575745".to_string()
            ]
        }
    );
}

#[tokio::test]
async fn send_progress_error_reply_is_a_rejection() {
    let client = mock_client_returning(error_reply("sendProgress"));

    let res = client
        .send_progress(ProgressReport::default())
        .await
        .unwrap();

    assert_eq!(
        res,
        SendProgressResponse::Rejected {
            reason: Some("boom".to_string())
        }
    );
}

#[tokio::test]
async fn client_error_succeeds() {
    let client = mock_client_returning(json!({"action": "clientError", "response": "SUCCESS"}));

    client
        .client_error(45, Some(1), "This is a sample error message!")
        .await
        .unwrap();

    assert_client_sent_body(
        &client,
        json!({
            "action": "clientError",
            "token": TOKEN,
            "taskId": 45,
            "chunkId": 1,
            "message": "This is a sample error message!"
        }),
    );
}

#[tokio::test]
async fn client_error_error() {
    let client = mock_client_returning(error_reply("clientError"));

    assert_server_error(
        client
            .client_error(45, None, "This is a sample error message!")
            .await,
        "clientError",
    );
}

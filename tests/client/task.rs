use htp_agent::model::{
    BenchmarkType, BrainConfig, Chunk, GetChunkResponse, GetTaskResponse, Preprocessor,
    TaskAssignment,
};
use serde_json::json;

use crate::common::{
    TOKEN, assert_client_sent_body, assert_server_error, error_reply, mock_client_returning,
};

#[tokio::test]
async fn get_task_returns_no_task_when_none_available() {
    let client = mock_client_returning(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": null,
        "reason": "No task available!"
    }));

    let res = client.get_task().await.unwrap();

    assert_eq!(
        res,
        GetTaskResponse::NoTask {
            reason: Some("No task available!".to_string())
        }
    );
    assert_client_sent_body(&client, json!({"action": "getTask", "token": TOKEN}));
}

#[tokio::test]
async fn get_task_returns_no_task_without_reason() {
    let client = mock_client_returning(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": null
    }));

    let res = client.get_task().await.unwrap();

    assert_eq!(res, GetTaskResponse::NoTask { reason: None });
}

#[tokio::test]
async fn get_task_returns_health_check() {
    let client = mock_client_returning(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": -1
    }));

    let res = client.get_task().await.unwrap();

    assert_eq!(res, GetTaskResponse::HealthCheck);
}

#[tokio::test]
async fn get_task_returns_task_assignment() {
    let client = mock_client_returning(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": 25,
        "crackerId": 45,
        "attackcmd": "#HL# -a 3 ?a?a?a?a --hash-type=0",
        "cmdpars": " --hash-type=0 ",
        "hashlistId": 13,
        "bench": 30,
        "statustimer": 5,
        "files": ["rockyou.txt", "wordlist.txt"],
        "benchType": "speed",
        "hashlistAlias": "#HL#",
        "keyspace": 0,
        "enforcePipe": false,
        "slowHash": false,
        "usePreprocessor": true,
        "preprocessor": 2,
        "preprocessorCommand": "wordlist.txt",
        "useBrain": true,
        "brainHost": "10.20.30.40",
        "brainPort": 1234,
        "brainPass": "password",
        "brainFeatures": 3
    }));

    let res = client.get_task().await.unwrap();

    assert_eq!(
        res,
        GetTaskResponse::Task(Box::new(TaskAssignment {
            task_id: 25,
            cracker_id: 45,
            attack_command: "#HL# -a 3 ?a?a?a?a --hash-type=0".to_string(),
            cmd_parameters: " --hash-type=0 ".to_string(),
            hashlist_id: 13,
            benchmark: 30,
            status_timer: 5,
            files: vec!["rockyou.txt".to_string(), "wordlist.txt".to_string()],
            bench_type: BenchmarkType::Speed,
            hashlist_alias: "#HL#".to_string(),
            keyspace: 0,
            enforce_pipe: false,
            slow_hash: false,
            preprocessor: Some(Preprocessor {
                id: 2,
                command: "wordlist.txt".to_string()
            }),
            brain: Some(BrainConfig {
                host: "10.20.30.40".to_string(),
                port: 1234,
                pass: "password".to_string(),
                features: 3
            })
        }))
    );
}

#[tokio::test]
async fn get_task_error() {
    let client = mock_client_returning(error_reply("getTask"));

    assert_server_error(client.get_task().await, "getTask");
}

#[tokio::test]
async fn get_chunk_returns_chunk() {
    let client = mock_client_returning(json!({
        "action": "getChunk",
        "response": "SUCCESS",
        "status": "OK",
        "chunkId": 13,
        "skip": 45000,
        "length": 10000
    }));

    let res = client.get_chunk(5).await.unwrap();

    assert_eq!(
        res,
        GetChunkResponse::Chunk(Chunk {
            id: 13,
            skip: 45000,
            length: 10000
        })
    );
    assert_client_sent_body(
        &client,
        json!({"action": "getChunk", "token": TOKEN, "taskId": 5}),
    );
}

#[tokio::test]
async fn get_chunk_decodes_status_only_variants() {
    let cases = [
        ("keyspace_required", GetChunkResponse::KeyspaceRequired),
        ("benchmark", GetChunkResponse::BenchmarkRequired),
        ("fully_dispatched", GetChunkResponse::FullyDispatched),
        ("cracker_update", GetChunkResponse::CrackerUpdate),
        ("health_check", GetChunkResponse::HealthCheck),
    ];

    for (status, expected) in cases {
        let client = mock_client_returning(
            json!({"action": "getChunk", "response": "SUCCESS", "status": status}),
        );

        let res = client.get_chunk(5).await.unwrap();

        assert_eq!(res, expected);
    }
}

#[tokio::test]
async fn get_chunk_error() {
    let client = mock_client_returning(error_reply("getChunk"));

    assert_server_error(client.get_chunk(5).await, "getChunk");
}

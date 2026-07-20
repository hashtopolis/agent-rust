mod support;

use htp_agent::client::{Client, ClientError, ProgressReport};
use htp_agent::model::{
    BenchmarkType, BinaryType, BrainConfig, CheckClientVersionResponse, Chunk,
    DownloadBinaryResponse, GetChunkResponse, GetFileResponse, GetFileStatusResponse,
    GetFoundResponse, GetHashlistResponse, GetHealthCheckResponse, GetTaskResponse, LoginResponse,
    Os, Preprocessor, RegisterResponse, SendProgressResponse, TaskAssignment,
};
use htp_agent::protocol::ProtocolError;
use htp_agent::transport::TransportError;
use serde_json::{Value, json};

use support::transport::{FailingTransport, MockTransport};

const TOKEN: &str = "tok";

fn mock_client_returning(reply: Value) -> Client<MockTransport> {
    Client::with_token(MockTransport::new(reply), TOKEN)
}

fn error_reply(action: &str) -> Value {
    json!({"action": action, "response": "ERROR", "message": "boom"})
}

fn assert_server_error<T: std::fmt::Debug>(result: Result<T, ClientError>, action: &str) {
    match result {
        Err(ClientError::Server { action: a, message }) => {
            assert_eq!(a, action);
            assert_eq!(message.as_deref(), Some("boom"));
        }
        other => panic!("expected server error for '{action}', got {other:?}"),
    }
}

fn assert_client_sent_body(client: &Client<MockTransport>, expected: Value) {
    assert_eq!(client.transport().last_request_body(), expected);
}

#[tokio::test]
async fn test_connection_returns_ack() {
    let client = mock_client_returning(json!({"action": "testConnection", "response": "SUCCESS"}));

    let res = client.test_connection().await.unwrap();

    assert!(res.envelope.is_success());
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
        json!({"action": "register", "response": "SUCCESS", "token": "newtok"}),
    );

    let res = client.register("v", "host", Some(true)).await.unwrap();

    assert_eq!(
        res,
        RegisterResponse {
            token: "newtok".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "register", "voucher": "v", "name": "host", "cpu-only": true}),
    );
}

#[tokio::test]
async fn register_error() {
    let client = mock_client_returning(error_reply("register"));

    assert_server_error(client.register("v", "host", None).await, "register");
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

    let res = client.login("sig").await.unwrap();

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
        json!({"action": "login", "token": TOKEN, "clientSignature": "sig"}),
    );
}

#[tokio::test]
async fn login_error() {
    let client = mock_client_returning(error_reply("login"));

    assert_server_error(client.login("sig").await, "login");
}

#[tokio::test]
async fn update_information_returns_ack() {
    let client =
        mock_client_returning(json!({"action": "updateInformation", "response": "SUCCESS"}));

    let res = client
        .update_information("uid", Os::Linux, vec!["GPU0".to_string()])
        .await
        .unwrap();

    assert!(res.envelope.is_success());
    assert_client_sent_body(
        &client,
        json!({
            "action": "updateInformation",
            "token": TOKEN,
            "uid": "uid",
            "os": 0,
            "devices": ["GPU0"]
        }),
    );
}

#[tokio::test]
async fn update_information_error() {
    let client = mock_client_returning(error_reply("updateInformation"));

    assert_server_error(
        client.update_information("uid", Os::Linux, vec![]).await,
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

    let res = client.check_client_version("1.0", "rust").await.unwrap();

    assert_eq!(res, CheckClientVersionResponse::UpToDate);
    assert_client_sent_body(
        &client,
        json!({"action": "checkClientVersion", "token": TOKEN, "version": "1.0", "type": "rust"}),
    );
}

#[tokio::test]
async fn check_client_version_returns_new_version() {
    let client = mock_client_returning(json!({
        "action": "checkClientVersion",
        "response": "SUCCESS",
        "version": "NEW",
        "url": "https://hashtopolis.example.com/agents/htp-agent-2.0"
    }));

    let res = client.check_client_version("1.0", "rust").await.unwrap();

    assert_eq!(
        res,
        CheckClientVersionResponse::NewVersion {
            url: "https://hashtopolis.example.com/agents/htp-agent-2.0".to_string()
        }
    );
}

#[tokio::test]
async fn check_client_version_error() {
    let client = mock_client_returning(error_reply("checkClientVersion"));

    assert_server_error(
        client.check_client_version("1.0", "rust").await,
        "checkClientVersion",
    );
}

#[tokio::test]
async fn download_binary_returns_archive() {
    let client = mock_client_returning(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://hashtopolis.example.com/files/hashcat-6.2.6.7z",
        "name": "hashcat",
        "executable": "hashcat.bin"
    }));

    let res = client
        .download_binary(BinaryType::Cracker, Some(3), None)
        .await
        .unwrap();

    assert_eq!(
        res,
        DownloadBinaryResponse::Archive {
            url: "https://hashtopolis.example.com/files/hashcat-6.2.6.7z".to_string(),
            name: "hashcat".to_string(),
            binary: "hashcat.bin".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "downloadBinary", "token": TOKEN, "type": "cracker", "binaryVersionId": 3}),
    );
}

#[tokio::test]
async fn download_binary_returns_utility() {
    let client = mock_client_returning(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "executable": "https://hashtopolis.example.com/files/7zr"
    }));

    let res = client
        .download_binary(BinaryType::Extractor, None, None)
        .await
        .unwrap();

    assert_eq!(
        res,
        DownloadBinaryResponse::Utility {
            url: "https://hashtopolis.example.com/files/7zr".to_string()
        }
    );
}

#[tokio::test]
async fn download_binary_returns_preprocessor() {
    let client = mock_client_returning(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://hashtopolis.example.com/files/prince.7z",
        "name": "princeprocessor",
        "executable": "pp64.bin",
        "keyspaceCommand": "--keyspace",
        "skipCommand": "--skip",
        "limitCommand": "--limit"
    }));

    let res = client
        .download_binary(BinaryType::Preprocessor, None, Some(1))
        .await
        .unwrap();

    assert_eq!(
        res,
        DownloadBinaryResponse::Preprocessor {
            url: "https://hashtopolis.example.com/files/prince.7z".to_string(),
            name: "princeprocessor".to_string(),
            binary: "pp64.bin".to_string(),
            keyspace_command: "--keyspace".to_string(),
            skip_command: "--skip".to_string(),
            limit_command: "--limit".to_string()
        }
    );
}

#[tokio::test]
async fn download_binary_error() {
    let client = mock_client_returning(error_reply("downloadBinary"));

    assert_server_error(
        client
            .download_binary(BinaryType::Cracker, None, None)
            .await,
        "downloadBinary",
    );
}

#[tokio::test]
async fn get_task_returns_no_task_when_none_available() {
    let client = mock_client_returning(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": null,
        "reason": "none available"
    }));

    let res = client.get_task().await.unwrap();

    assert_eq!(
        res,
        GetTaskResponse::NoTask {
            reason: Some("none available".to_string())
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
        "taskId": 42,
        "crackerId": 3,
        "attackcmd": "#HL# -a 0 -m 0 rockyou.txt",
        "cmdpars": "--force",
        "hashlistId": 7,
        "bench": 30,
        "statustimer": 5,
        "files": ["rockyou.txt"],
        "benchType": "speed",
        "hashlistAlias": "#HL#",
        "keyspace": 14344385,
        "enforcePipe": true,
        "slowHash": false,
        "usePreprocessor": true,
        "preprocessor": 1,
        "preprocessorCommand": "pp64",
        "useBrain": true,
        "brainHost": "10.0.0.1",
        "brainPort": 13000,
        "brainPass": "secret",
        "brainFeatures": 3
    }));

    let res = client.get_task().await.unwrap();

    assert_eq!(
        res,
        GetTaskResponse::Task(Box::new(TaskAssignment {
            task_id: 42,
            cracker_id: 3,
            attack_command: "#HL# -a 0 -m 0 rockyou.txt".to_string(),
            cmd_parameters: "--force".to_string(),
            hashlist_id: 7,
            benchmark: 30,
            status_timer: 5,
            files: vec!["rockyou.txt".to_string()],
            bench_type: BenchmarkType::Speed,
            hashlist_alias: "#HL#".to_string(),
            keyspace: 14344385,
            enforce_pipe: true,
            slow_hash: false,
            preprocessor: Some(Preprocessor {
                id: 1,
                command: "pp64".to_string()
            }),
            brain: Some(BrainConfig {
                host: "10.0.0.1".to_string(),
                port: 13000,
                pass: "secret".to_string(),
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
        "chunkId": 10,
        "skip": 0,
        "length": 100
    }));

    let res = client.get_chunk(5).await.unwrap();

    assert_eq!(
        res,
        GetChunkResponse::Chunk(Chunk {
            id: 10,
            skip: 0,
            length: 100
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

#[tokio::test]
async fn send_keyspace_returns_ack() {
    let client = mock_client_returning(
        json!({"action": "sendKeyspace", "response": "SUCCESS", "keyspace": "OK"}),
    );

    let res = client.send_keyspace(5, 1000).await.unwrap();

    assert!(res.envelope.is_success());
    assert_client_sent_body(
        &client,
        json!({"action": "sendKeyspace", "token": TOKEN, "taskId": 5, "keyspace": 1000}),
    );
}

#[tokio::test]
async fn send_keyspace_error() {
    let client = mock_client_returning(error_reply("sendKeyspace"));

    assert_server_error(client.send_keyspace(5, 1000).await, "sendKeyspace");
}

#[tokio::test]
async fn send_benchmark_returns_ack() {
    let client = mock_client_returning(
        json!({"action": "sendBenchmark", "response": "SUCCESS", "benchmark": "OK"}),
    );

    let res = client
        .send_benchmark(5, BenchmarkType::Speed, "0.5")
        .await
        .unwrap();

    assert!(res.envelope.is_success());
    assert_client_sent_body(
        &client,
        json!({
            "action": "sendBenchmark",
            "token": TOKEN,
            "taskId": 5,
            "type": "speed",
            "result": "0.5"
        }),
    );
}

#[tokio::test]
async fn send_benchmark_error() {
    let client = mock_client_returning(error_reply("sendBenchmark"));

    assert_server_error(
        client.send_benchmark(5, BenchmarkType::Speed, "0.5").await,
        "sendBenchmark",
    );
}

#[tokio::test]
async fn send_progress_returns_stop() {
    let client = mock_client_returning(json!({
        "action": "sendProgress",
        "response": "SUCCESS",
        "cracked": 1,
        "skipped": 0,
        "agent": "stop"
    }));
    let res = client
        .send_progress(ProgressReport {
            chunk_id: 1,
            keyspace_progress: 2,
            relative_progress: 3,
            speed: 4,
            state: 5,
            cracks: vec!["h".to_string()],
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(
        res,
        SendProgressResponse::Stop {
            cracked: 1,
            skipped: 0
        }
    );
    assert_client_sent_body(
        &client,
        json!({
            "action": "sendProgress",
            "token": TOKEN,
            "chunkId": 1,
            "keyspaceProgress": 2,
            "relativeProgress": 3,
            "speed": 4,
            "state": 5,
            "cracks": ["h"]
        }),
    );
}

#[tokio::test]
async fn send_progress_returns_continue() {
    let client = mock_client_returning(json!({
        "action": "sendProgress",
        "response": "SUCCESS",
        "cracked": 2,
        "skipped": 1,
        "zaps": ["hash1", "hash2"]
    }));

    let res = client
        .send_progress(ProgressReport::default())
        .await
        .unwrap();

    assert_eq!(
        res,
        SendProgressResponse::Continue {
            cracked: 2,
            skipped: 1,
            zaps: vec!["hash1".to_string(), "hash2".to_string()]
        }
    );
}

#[tokio::test]
async fn send_progress_error() {
    let client = mock_client_returning(error_reply("sendProgress"));

    assert_server_error(
        client.send_progress(ProgressReport::default()).await,
        "sendProgress",
    );
}

#[tokio::test]
async fn client_error_returns_ack() {
    let client = mock_client_returning(json!({"action": "clientError", "response": "SUCCESS"}));

    let res = client.client_error(5, Some(9), "boom").await.unwrap();

    assert!(res.envelope.is_success());
    assert_client_sent_body(
        &client,
        json!({
            "action": "clientError",
            "token": TOKEN,
            "taskId": 5,
            "chunkId": 9,
            "message": "boom"
        }),
    );
}

#[tokio::test]
async fn client_error_error() {
    let client = mock_client_returning(error_reply("clientError"));

    assert_server_error(client.client_error(5, None, "boom").await, "clientError");
}

#[tokio::test]
async fn get_hashlist_returns_url() {
    let client = mock_client_returning(
        json!({"action": "getHashlist", "response": "SUCCESS", "url": "https://hashtopolis.example.com/getHashlist/7"}),
    );

    let res = client.get_hashlist(7).await.unwrap();

    assert_eq!(
        res,
        GetHashlistResponse {
            url: "https://hashtopolis.example.com/getHashlist/7".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "getHashlist", "token": TOKEN, "hashlistId": 7}),
    );
}

#[tokio::test]
async fn get_hashlist_error() {
    let client = mock_client_returning(error_reply("getHashlist"));

    assert_server_error(client.get_hashlist(7).await, "getHashlist");
}

#[tokio::test]
async fn get_found_returns_url() {
    let client = mock_client_returning(
        json!({"action": "getFound", "response": "SUCCESS", "url": "https://hashtopolis.example.com/getFound/7"}),
    );

    let res = client.get_found(7).await.unwrap();

    assert_eq!(
        res,
        GetFoundResponse {
            url: "https://hashtopolis.example.com/getFound/7".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "getFound", "token": TOKEN, "hashlistId": 7}),
    );
}

#[tokio::test]
async fn get_found_error() {
    let client = mock_client_returning(error_reply("getFound"));

    assert_server_error(client.get_found(7).await, "getFound");
}

#[tokio::test]
async fn get_file_returns_file_metadata() {
    let client = mock_client_returning(json!({
        "action": "getFile",
        "response": "SUCCESS",
        "filename": "rockyou.txt",
        "extension": "txt",
        "url": "https://hashtopolis.example.com/files/rockyou.txt",
        "filesize": 100
    }));

    let res = client.get_file(5, "rockyou.txt").await.unwrap();

    assert_eq!(
        res,
        GetFileResponse {
            filename: "rockyou.txt".to_string(),
            extension: "txt".to_string(),
            url: "https://hashtopolis.example.com/files/rockyou.txt".to_string(),
            filesize: 100
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "getFile", "token": TOKEN, "taskId": 5, "file": "rockyou.txt"}),
    );
}

#[tokio::test]
async fn get_file_error() {
    let client = mock_client_returning(error_reply("getFile"));

    assert_server_error(client.get_file(5, "x").await, "getFile");
}

#[tokio::test]
async fn get_file_status_returns_filenames() {
    let client = mock_client_returning(json!({
        "action": "getFileStatus",
        "response": "SUCCESS",
        "filenames": ["a.txt"]
    }));

    let res = client.get_file_status().await.unwrap();

    assert_eq!(
        res,
        GetFileStatusResponse {
            filenames: vec!["a.txt".to_string()]
        }
    );
    assert_client_sent_body(&client, json!({"action": "getFileStatus", "token": TOKEN}));
}

#[tokio::test]
async fn get_file_status_error() {
    let client = mock_client_returning(error_reply("getFileStatus"));

    assert_server_error(client.get_file_status().await, "getFileStatus");
}

#[tokio::test]
async fn get_health_check_returns_parameters() {
    let client = mock_client_returning(json!({
        "action": "getHealthCheck",
        "response": "SUCCESS",
        "attack": "a",
        "crackerBinaryId": 3,
        "hashes": ["h"],
        "checkId": 9,
        "hashlistAlias": "#HL#"
    }));

    let res = client.get_health_check().await.unwrap();

    assert_eq!(
        res,
        GetHealthCheckResponse {
            attack: "a".to_string(),
            cracker_binary_id: 3,
            hashes: vec!["h".to_string()],
            check_id: 9,
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
async fn send_health_check_returns_ack() {
    let client = mock_client_returning(json!({"action": "sendHealthCheck", "response": "SUCCESS"}));

    let res = client
        .send_health_check(9, 5, 100, 200, 2, vec!["e".to_string()])
        .await
        .unwrap();

    assert!(res.envelope.is_success());
    assert_client_sent_body(
        &client,
        json!({
            "action": "sendHealthCheck",
            "token": TOKEN,
            "checkId": 9,
            "numCracked": 5,
            "start": 100,
            "end": 200,
            "numGpus": 2,
            "errors": ["e"]
        }),
    );
}

#[tokio::test]
async fn send_health_check_error() {
    let client = mock_client_returning(error_reply("sendHealthCheck"));

    assert_server_error(
        client.send_health_check(9, 5, 100, 200, 2, vec![]).await,
        "sendHealthCheck",
    );
}

#[tokio::test]
async fn deregister_returns_ack() {
    let client = mock_client_returning(json!({"action": "deregister", "response": "SUCCESS"}));

    let res = client.deregister().await.unwrap();

    assert!(res.envelope.is_success());
    assert_client_sent_body(&client, json!({"action": "deregister", "token": TOKEN}));
}

#[tokio::test]
async fn deregister_error() {
    let client = mock_client_returning(error_reply("deregister"));

    assert_server_error(client.deregister().await, "deregister");
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

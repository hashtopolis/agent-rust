mod support;

use htp_agent::client::{Client, ClientError};
use htp_agent::model::{
    BenchmarkType, BrainConfig, CheckClientVersionResponse, Chunk, DownloadCrackerResponse,
    DownloadPreprocessorResponse, DownloadUtilityResponse, GetChunkResponse, GetFileResponse,
    GetFileStatusResponse, GetFoundResponse, GetHashlistResponse, GetHealthCheckResponse,
    GetTaskResponse, LoginResponse, Os, Preprocessor, ProgressReport, RegisterResponse,
    SendProgressResponse, TaskAssignment,
};
use htp_agent::protocol::ProtocolError;
use htp_agent::transport::TransportError;
use serde_json::{Value, json};

use support::transport::{FailingTransport, MockTransport};

const TOKEN: &str = "GHhgdf(/&";

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
async fn update_information_returns_ack() {
    let client =
        mock_client_returning(json!({"action": "updateInformation", "response": "SUCCESS"}));

    let res = client
        .update_information("230-34-345-345", Os::Linux, &["ATI HD7970", "ATI HD7970"])
        .await
        .unwrap();

    assert!(res.envelope.is_success());
    assert_client_sent_body(
        &client,
        json!({
            "action": "updateInformation",
            "token": TOKEN,
            "uid": "230-34-345-345",
            "os": 0,
            "devices": ["ATI HD7970", "ATI HD7970"]
        }),
    );
}

#[tokio::test]
async fn update_information_error() {
    let client = mock_client_returning(error_reply("updateInformation"));

    assert_server_error(
        client
            .update_information("230-34-345-345", Os::Linux, &[] as &[&str])
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
async fn download_cracker_returns_archive() {
    let client = mock_client_returning(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://hashcat.net/files/hashcat-3.01.7z",
        "name": "Hashcat",
        "executable": "hashcat64.bin"
    }));

    let res = client.download_cracker(45).await.unwrap();

    assert_eq!(
        res,
        DownloadCrackerResponse {
            url: "https://hashcat.net/files/hashcat-3.01.7z".to_string(),
            name: "Hashcat".to_string(),
            binary: "hashcat64.bin".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "downloadBinary", "token": TOKEN, "type": "cracker", "binaryVersionId": 45}),
    );
}

#[tokio::test]
async fn download_extractor_returns_utility() {
    let client = mock_client_returning(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "executable": "https://example.com/getapp.php"
    }));

    let res = client.download_extractor().await.unwrap();

    assert_eq!(
        res,
        DownloadUtilityResponse {
            url: "https://example.com/getapp.php".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "downloadBinary", "token": TOKEN, "type": "7zr"}),
    );
}

#[tokio::test]
async fn download_preprocessor_returns_preprocessor() {
    let client = mock_client_returning(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z",
        "name": "Prince",
        "executable": "pp.bin",
        "keyspaceCommand": "--keyspace",
        "skipCommand": "--skip",
        "limitCommand": "--limit"
    }));

    let res = client.download_preprocessor(1).await.unwrap();

    assert_eq!(
        res,
        DownloadPreprocessorResponse {
            url: "https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z".to_string(),
            name: "Prince".to_string(),
            binary: "pp.bin".to_string(),
            keyspace_command: Some("--keyspace".to_string()),
            skip_command: Some("--skip".to_string()),
            limit_command: Some("--limit".to_string())
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "downloadBinary", "token": TOKEN, "type": "preprocessor", "preprocessorId": 1}),
    );
}

#[tokio::test]
async fn download_binary_error() {
    let client = mock_client_returning(error_reply("downloadBinary"));

    assert_server_error(client.download_cracker(45).await, "downloadBinary");
}

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

#[tokio::test]
async fn send_keyspace_returns_ack() {
    let client = mock_client_returning(
        json!({"action": "sendKeyspace", "response": "SUCCESS", "keyspace": "OK"}),
    );

    let res = client.send_keyspace(35, 568000).await.unwrap();

    assert!(res.envelope.is_success());
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
async fn send_benchmark_returns_ack() {
    let client = mock_client_returning(
        json!({"action": "sendBenchmark", "response": "SUCCESS", "benchmark": "OK"}),
    );

    let res = client
        .send_benchmark(35, BenchmarkType::Speed, "674:674.74")
        .await
        .unwrap();

    assert!(res.envelope.is_success());
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

    let res = client
        .client_error(45, Some(1), "This is a sample error message!")
        .await
        .unwrap();

    assert!(res.envelope.is_success());
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

#[tokio::test]
async fn get_hashlist_returns_url() {
    let client = mock_client_returning(
        json!({"action": "getHashlist", "response": "SUCCESS", "url": "get.php?hashlist=5&token=GHhgdf(/&"}),
    );

    let res = client.get_hashlist(23).await.unwrap();

    assert_eq!(
        res,
        GetHashlistResponse {
            url: "get.php?hashlist=5&token=GHhgdf(/&".to_string()
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "getHashlist", "token": TOKEN, "hashlistId": 23}),
    );
}

#[tokio::test]
async fn get_hashlist_error() {
    let client = mock_client_returning(error_reply("getHashlist"));

    assert_server_error(client.get_hashlist(23).await, "getHashlist");
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
        "extension": ".txt",
        "url": "get.php?file=5&token=GHhgdf(/&",
        "filesize": 267729
    }));

    let res = client.get_file(56, "rockyou.txt").await.unwrap();

    assert_eq!(
        res,
        GetFileResponse {
            filename: "rockyou.txt".to_string(),
            extension: ".txt".to_string(),
            url: "get.php?file=5&token=GHhgdf(/&".to_string(),
            filesize: 267729
        }
    );
    assert_client_sent_body(
        &client,
        json!({"action": "getFile", "token": TOKEN, "taskId": 56, "file": "rockyou.txt"}),
    );
}

#[tokio::test]
async fn get_file_error() {
    let client = mock_client_returning(error_reply("getFile"));

    assert_server_error(client.get_file(56, "rockyou.txt").await, "getFile");
}

#[tokio::test]
async fn get_file_status_returns_filenames() {
    let client = mock_client_returning(json!({
        "action": "getFileStatus",
        "response": "SUCCESS",
        "filenames": ["top10000.txt"]
    }));

    let res = client.get_file_status().await.unwrap();

    assert_eq!(
        res,
        GetFileStatusResponse {
            filenames: vec!["top10000.txt".to_string()]
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
async fn send_health_check_returns_ack() {
    let client = mock_client_returning(json!({"action": "sendHealthCheck", "response": "SUCCESS"}));

    let res = client
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

    assert!(res.envelope.is_success());
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

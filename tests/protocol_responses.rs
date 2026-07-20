use htp_agent::model::BenchmarkType;
use htp_agent::protocol::{
    AckResponse, BrainConfig, CheckClientVersionResponse, DownloadBinaryResponse, GetChunkResponse,
    GetFileResponse, GetFileStatusResponse, GetFoundResponse, GetHashlistResponse,
    GetHealthCheckResponse, GetTaskResponse, LoginResponse, Preprocessor, RegisterResponse,
    ResponseStatus, SendProgressResponse, raw,
};
use serde::de::DeserializeOwned;
use serde_json::json;

fn decode<Raw, Real>(value: serde_json::Value) -> Real
where
    Raw: DeserializeOwned,
    Real: TryFrom<Raw>,
    <Real as TryFrom<Raw>>::Error: std::fmt::Debug,
{
    let raw: Raw = serde_json::from_value(value).expect("raw wire decode failed");
    Real::try_from(raw).expect("raw -> real conversion failed")
}

#[test]
fn envelope_reports_success() {
    let res: AckResponse = serde_json::from_value(json!({
        "action": "register",
        "response": "SUCCESS"
    }))
    .unwrap();

    assert!(res.envelope.is_success());
    assert_eq!(res.envelope.action.as_deref(), Some("register"));
}

#[test]
fn register_returns_token() {
    let res: RegisterResponse = decode::<raw::RegisterResponse, _>(json!({
        "action": "register",
        "response": "SUCCESS",
        "token": "abc123"
    }));

    assert_eq!(res.token, "abc123");
}

#[test]
fn register_without_token_is_rejected() {
    let raw: raw::RegisterResponse =
        serde_json::from_value(json!({"action": "register", "response": "SUCCESS"})).unwrap();

    assert!(RegisterResponse::try_from(raw).is_err());
}

#[test]
fn envelope_carries_error_message() {
    let res: AckResponse = serde_json::from_value(json!({
        "action": "updateInformation",
        "response": "ERROR",
        "message": "Invalid token!"
    }))
    .unwrap();

    assert_eq!(res.envelope.response, ResponseStatus::Error);
    assert!(!res.envelope.is_success());
    assert_eq!(res.envelope.message.as_deref(), Some("Invalid token!"));
}

#[test]
fn unknown_response_status_falls_back_to_other() {
    let res: AckResponse = serde_json::from_value(json!({
        "action": "testConnection",
        "response": "SOMETHING_ELSE"
    }))
    .unwrap();

    assert_eq!(res.envelope.response, ResponseStatus::Other);
}

#[test]
fn simple_success_needs_only_the_status() {
    let res: AckResponse =
        serde_json::from_value(json!({"action": "deregister", "response": "SUCCESS"})).unwrap();

    assert!(res.envelope.is_success());
    assert!(res.envelope.message.is_none());
}

#[test]
fn login_fields() {
    let res: LoginResponse = decode::<raw::LoginResponse, _>(json!({
        "action": "login",
        "response": "SUCCESS",
        "server-version": "0.14.0 (abc)",
        "multicastEnabled": true,
        "timeout": 30
    }));

    assert_eq!(res.server_version, "0.14.0 (abc)");
    assert!(res.multicast_enabled);
    assert_eq!(res.timeout, 30);
}

#[test]
fn login_without_all_fields_is_rejected() {
    let raw: raw::LoginResponse =
        serde_json::from_value(json!({"action": "login", "response": "SUCCESS"})).unwrap();

    assert!(LoginResponse::try_from(raw).is_err());
}

#[test]
fn check_client_version_up_to_date() {
    let res: CheckClientVersionResponse = decode::<raw::CheckClientVersionResponse, _>(json!({
        "action": "checkClientVersion",
        "response": "SUCCESS",
        "version": "OK"
    }));

    assert_eq!(res, CheckClientVersionResponse::UpToDate);
}

#[test]
fn check_client_version_new() {
    let res: CheckClientVersionResponse = decode::<raw::CheckClientVersionResponse, _>(json!({
        "action": "checkClientVersion",
        "response": "SUCCESS",
        "version": "NEW",
        "url": "https://server/agents.php?download=3"
    }));

    assert_eq!(
        res,
        CheckClientVersionResponse::NewVersion {
            url: "https://server/agents.php?download=3".to_string()
        }
    );
}

#[test]
fn check_client_version_new_without_url_is_rejected() {
    let raw: raw::CheckClientVersionResponse = serde_json::from_value(json!({
        "action": "checkClientVersion",
        "response": "SUCCESS",
        "version": "NEW"
    }))
    .unwrap();

    assert!(CheckClientVersionResponse::try_from(raw).is_err());
}

#[test]
fn download_binary_utility_is_a_direct_url() {
    let res: DownloadBinaryResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "executable": "https://server/static/7zr"
    }));

    assert_eq!(
        res,
        DownloadBinaryResponse::Utility {
            url: "https://server/static/7zr".to_string()
        }
    );
}

#[test]
fn download_binary_cracker_is_an_archive() {
    let res: DownloadBinaryResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://server/files/hashcat.7z",
        "name": "hashcat",
        "executable": "hashcat.bin"
    }));

    assert_eq!(
        res,
        DownloadBinaryResponse::Archive {
            url: "https://server/files/hashcat.7z".to_string(),
            name: "hashcat".to_string(),
            binary: "hashcat.bin".to_string()
        }
    );
}

#[test]
fn download_binary_preprocessor_carries_commands() {
    let res: DownloadBinaryResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://server/files/princeprocessor.7z",
        "name": "princeprocessor",
        "executable": "pp64.bin",
        "keyspaceCommand": "--keyspace",
        "skipCommand": "--skip",
        "limitCommand": "--limit"
    }));

    assert_eq!(
        res,
        DownloadBinaryResponse::Preprocessor {
            url: "https://server/files/princeprocessor.7z".to_string(),
            name: "princeprocessor".to_string(),
            binary: "pp64.bin".to_string(),
            keyspace_command: "--keyspace".to_string(),
            skip_command: "--skip".to_string(),
            limit_command: "--limit".to_string()
        }
    );
}

#[test]
fn get_task_no_task_available() {
    let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": null,
        "reason": "No suitable task available!"
    }));

    assert_eq!(
        res,
        GetTaskResponse::NoTask {
            reason: Some("No suitable task available!".to_string())
        }
    );
}

#[test]
fn get_task_health_check() {
    let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": -1
    }));

    assert_eq!(res, GetTaskResponse::HealthCheck);
}

#[test]
fn get_task_full_assignment_without_conditional_groups() {
    let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": 42,
        "crackerId": 3,
        "attackcmd": "#HL# -a 0 wordlist",
        "cmdpars": " --hash-type=0 ",
        "hashlistId": 7,
        "bench": 30,
        "statustimer": 5,
        "files": ["wordlist"],
        "benchType": "speed",
        "hashlistAlias": "#HL#",
        "keyspace": 14344385,
        "usePreprocessor": false,
        "preprocessor": null,
        "preprocessorCommand": null,
        "enforcePipe": false,
        "slowHash": true,
        "useBrain": false
    }));

    let GetTaskResponse::Task(task) = res else {
        panic!("expected a task assignment, got {res:?}");
    };
    assert_eq!(task.task_id, 42);
    assert_eq!(task.cracker_id, 3);
    assert_eq!(task.attack_command, "#HL# -a 0 wordlist");
    assert_eq!(task.bench_type, BenchmarkType::Speed);
    assert_eq!(task.keyspace, 14344385);
    assert_eq!(task.files, vec!["wordlist".to_string()]);
    assert!(task.slow_hash);
    assert!(task.preprocessor.is_none());
    assert!(task.brain.is_none());
}

#[test]
fn get_task_with_brain_and_preprocessor() {
    let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": 1,
        "crackerId": 3,
        "attackcmd": "#HL#",
        "cmdpars": "",
        "hashlistId": 7,
        "bench": 30,
        "statustimer": 5,
        "files": [],
        "benchType": "run",
        "hashlistAlias": "#HL#",
        "keyspace": 100,
        "enforcePipe": false,
        "slowHash": false,
        "usePreprocessor": true,
        "preprocessor": 5,
        "preprocessorCommand": "-c",
        "useBrain": true,
        "brainHost": "10.0.0.1",
        "brainPort": 13743,
        "brainPass": "secret",
        "brainFeatures": 3
    }));

    let GetTaskResponse::Task(task) = res else {
        panic!("expected a task assignment, got {res:?}");
    };
    assert_eq!(
        task.preprocessor,
        Some(Preprocessor {
            id: 5,
            command: "-c".to_string()
        })
    );
    assert_eq!(
        task.brain,
        Some(BrainConfig {
            host: "10.0.0.1".to_string(),
            port: 13743,
            pass: "secret".to_string(),
            features: 3
        })
    );
}

#[test]
fn get_task_brain_flag_without_fields_is_rejected() {
    let raw: raw::GetTaskResponse = serde_json::from_value(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": 1,
        "crackerId": 3,
        "attackcmd": "#HL#",
        "cmdpars": "",
        "hashlistId": 7,
        "bench": 30,
        "statustimer": 5,
        "files": [],
        "benchType": "run",
        "hashlistAlias": "#HL#",
        "keyspace": 100,
        "enforcePipe": false,
        "slowHash": false,
        "usePreprocessor": false,
        "useBrain": true
    }))
    .unwrap();

    assert!(GetTaskResponse::try_from(raw).is_err());
}

#[test]
fn get_chunk_ok_variant() {
    let res: GetChunkResponse = decode::<raw::GetChunkResponse, _>(json!({
        "action": "getChunk",
        "response": "SUCCESS",
        "status": "OK",
        "chunkId": 100,
        "skip": 0,
        "length": 5000
    }));

    assert_eq!(
        res,
        GetChunkResponse::Chunk {
            id: 100,
            skip: 0,
            length: 5000
        }
    );
}

#[test]
fn get_chunk_ok_without_chunk_fields_is_rejected() {
    let raw: raw::GetChunkResponse = serde_json::from_value(json!({
        "action": "getChunk",
        "response": "SUCCESS",
        "status": "OK"
    }))
    .unwrap();

    assert!(GetChunkResponse::try_from(raw).is_err());
}

#[test]
fn get_chunk_status_only_variants() {
    for (status, expected) in [
        ("keyspace_required", GetChunkResponse::KeyspaceRequired),
        ("benchmark", GetChunkResponse::BenchmarkRequired),
        ("fully_dispatched", GetChunkResponse::FullyDispatched),
        ("cracker_update", GetChunkResponse::CrackerUpdate),
        ("health_check", GetChunkResponse::HealthCheck),
    ] {
        let res: GetChunkResponse = decode::<raw::GetChunkResponse, _>(json!({
            "action": "getChunk",
            "response": "SUCCESS",
            "status": status
        }));
        assert_eq!(res, expected, "status {status}");
    }
}

#[test]
fn ack_only_actions_decode_from_the_status_alone() {
    let res: AckResponse = serde_json::from_value(json!({
        "action": "sendKeyspace",
        "response": "SUCCESS",
        "keyspace": "OK"
    }))
    .unwrap();

    assert!(res.envelope.is_success());
}

#[test]
fn send_progress_stop_branch() {
    let raw: raw::SendProgressResponse = serde_json::from_value(json!({
        "action": "sendProgress",
        "response": "SUCCESS",
        "cracked": 2,
        "skipped": 1,
        "agent": "stop"
    }))
    .unwrap();

    assert_eq!(
        SendProgressResponse::from(raw),
        SendProgressResponse::Stop {
            cracked: 2,
            skipped: 1
        }
    );
}

#[test]
fn send_progress_continue_branch_carries_zaps() {
    let raw: raw::SendProgressResponse = serde_json::from_value(json!({
        "action": "sendProgress",
        "response": "SUCCESS",
        "cracked": 2,
        "skipped": 0,
        "zaps": ["hashA", "hashB"]
    }))
    .unwrap();

    assert_eq!(
        SendProgressResponse::from(raw),
        SendProgressResponse::Continue {
            cracked: 2,
            skipped: 0,
            zaps: vec!["hashA".to_string(), "hashB".to_string()]
        }
    );
}

#[test]
fn send_progress_defaults_to_continue_when_fields_absent() {
    let raw: raw::SendProgressResponse = serde_json::from_value(json!({
        "action": "sendProgress",
        "response": "SUCCESS"
    }))
    .unwrap();

    assert_eq!(
        SendProgressResponse::from(raw),
        SendProgressResponse::Continue {
            cracked: 0,
            skipped: 0,
            zaps: vec![]
        }
    );
}

#[test]
fn get_file() {
    let res: GetFileResponse = decode::<raw::GetFileResponse, _>(json!({
        "action": "getFile",
        "response": "SUCCESS",
        "filename": "rockyou.txt",
        "extension": "txt",
        "url": "getFile.php?file=1",
        "filesize": 139921497
    }));

    assert_eq!(res.filename, "rockyou.txt");
    assert_eq!(res.extension, "txt");
    assert_eq!(res.url, "getFile.php?file=1");
    assert_eq!(res.filesize, 139921497);
}

#[test]
fn get_file_without_all_fields_is_rejected() {
    let raw: raw::GetFileResponse = serde_json::from_value(json!({
        "action": "getFile",
        "response": "SUCCESS",
        "filename": "rockyou.txt"
    }))
    .unwrap();

    assert!(GetFileResponse::try_from(raw).is_err());
}

#[test]
fn get_file_status() {
    let res: GetFileStatusResponse = raw::GetFileStatusResponse {
        filenames: vec!["a.txt".to_string(), "b.7z".to_string()],
    }
    .into();

    assert_eq!(res.filenames, vec!["a.txt".to_string(), "b.7z".to_string()]);
}

#[test]
fn get_file_status_empty() {
    let raw: raw::GetFileStatusResponse = serde_json::from_value(json!({
        "action": "getFileStatus",
        "response": "SUCCESS"
    }))
    .unwrap();
    let res = GetFileStatusResponse::from(raw);
    assert!(res.filenames.is_empty());
}

#[test]
fn get_hashlist() {
    let res: GetHashlistResponse = decode::<raw::GetHashlistResponse, _>(json!({
        "action": "getHashlist",
        "response": "SUCCESS",
        "url": "getHashlist.php?hashlist=7"
    }));

    assert_eq!(res.url, "getHashlist.php?hashlist=7");
}

#[test]
fn get_found() {
    let res: GetFoundResponse = decode::<raw::GetFoundResponse, _>(json!({
        "action": "getFound",
        "response": "SUCCESS",
        "url": "getFound.php?hashlist=7"
    }));

    assert_eq!(res.url, "getFound.php?hashlist=7");
}

#[test]
fn get_health_check() {
    let res: GetHealthCheckResponse = decode::<raw::GetHealthCheckResponse, _>(json!({
        "action": "getHealthCheck",
        "response": "SUCCESS",
        "attack": " --hash-type=0 #HL# -a 3 ?a?a?a",
        "crackerBinaryId": 3,
        "hashes": ["hash1", "hash2"],
        "checkId": 9,
        "hashlistAlias": "#HL#"
    }));

    assert_eq!(res.attack, " --hash-type=0 #HL# -a 3 ?a?a?a");
    assert_eq!(res.cracker_binary_id, 3);
    assert_eq!(res.hashes, vec!["hash1".to_string(), "hash2".to_string()]);
    assert_eq!(res.check_id, 9);
    assert_eq!(res.hashlist_alias, "#HL#");
}

#[test]
fn get_health_check_without_all_fields_is_rejected() {
    let raw: raw::GetHealthCheckResponse = serde_json::from_value(json!({
        "action": "getHealthCheck",
        "response": "SUCCESS",
        "attack": " --hash-type=0 #HL# -a 3 ?a?a?a"
    }))
    .unwrap();

    assert!(GetHealthCheckResponse::try_from(raw).is_err());
}

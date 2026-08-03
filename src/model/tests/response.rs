use crate::model::convert::TaskId;
use crate::model::raw;
use crate::model::{
    BenchmarkType, BrainConfig, CheckClientVersionResponse, Chunk, DownloadCrackerResponse,
    DownloadPreprocessorResponse, DownloadUtilityResponse, GetChunkResponse, GetFileResponse,
    GetFileStatusResponse, GetFoundResponse, GetHashlistResponse, GetHealthCheckResponse,
    GetTaskResponse, LoginResponse, Preprocessor, RegisterResponse, SendProgressResponse,
};
use serde::de::DeserializeOwned;
use serde_json::json;

#[test]
fn task_id_classifies_the_overloaded_field() {
    assert_eq!(TaskId::from_raw(None), TaskId::None);
    assert_eq!(TaskId::from_raw(Some(-1)), TaskId::HealthCheck);
    assert_eq!(TaskId::from_raw(Some(0)), TaskId::Id(0));
    assert_eq!(TaskId::from_raw(Some(42)), TaskId::Id(42));
    assert_eq!(TaskId::from_raw(Some(-99)), TaskId::None);
}

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
fn register_returns_token() {
    let res: RegisterResponse = decode::<raw::RegisterResponse, _>(json!({
        "action": "register",
        "response": "SUCCESS",
        "token": "GHhgdf(/&"
    }));

    assert_eq!(res.token, "GHhgdf(/&");
}

#[test]
fn register_without_token_is_rejected() {
    let raw: raw::RegisterResponse =
        serde_json::from_value(json!({"action": "register", "response": "SUCCESS"})).unwrap();

    assert!(RegisterResponse::try_from(raw).is_err());
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
        "url": "https://example.com/getclient.php"
    }));

    assert_eq!(
        res,
        CheckClientVersionResponse::NewVersion {
            url: "https://example.com/getclient.php".to_string()
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
fn download_binary_utility() {
    let res: DownloadUtilityResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "executable": "https://example.com/getapp.php"
    }));

    assert_eq!(
        res,
        DownloadUtilityResponse {
            url: "https://example.com/getapp.php".to_string()
        }
    );
}

#[test]
fn download_binary_cracker() {
    let res: DownloadCrackerResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://hashcat.net/files/hashcat-3.01.7z",
        "name": "Hashcat",
        "executable": "hashcat64.bin"
    }));

    assert_eq!(
        res,
        DownloadCrackerResponse {
            url: "https://hashcat.net/files/hashcat-3.01.7z".to_string(),
            name: "Hashcat".to_string(),
            binary: "hashcat64.bin".to_string()
        }
    );
}

#[test]
fn download_binary_preprocessor_carries_commands() {
    let res: DownloadPreprocessorResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://github.com/hashcat/princeprocessor/releases/download/v0.22/princeprocessor-0.22.7z",
        "name": "Prince",
        "executable": "pp.bin",
        "keyspaceCommand": "--keyspace",
        "skipCommand": "--skip",
        "limitCommand": "--limit"
    }));

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
}

#[test]
fn download_binary_preprocessor_allows_absent_commands() {
    // A preprocessor without a keyspace/skip/limit flag reports them as null;
    // the agent falls back to head/tail, so the fields are optional.
    let res: DownloadPreprocessorResponse = decode::<raw::DownloadBinaryResponse, _>(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://example.com/pp.7z",
        "name": "Prince",
        "executable": "pp.bin",
        "keyspaceCommand": null,
        "skipCommand": null,
        "limitCommand": null
    }));

    assert_eq!(res.keyspace_command, None);
    assert_eq!(res.skip_command, None);
    assert_eq!(res.limit_command, None);
}

#[test]
fn download_binary_utility_without_executable_is_rejected() {
    let raw: raw::DownloadBinaryResponse =
        serde_json::from_value(json!({"action": "downloadBinary", "response": "SUCCESS"})).unwrap();

    assert!(DownloadUtilityResponse::try_from(raw).is_err());
}

#[test]
fn download_binary_cracker_without_name_is_rejected() {
    let raw: raw::DownloadBinaryResponse = serde_json::from_value(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "url": "https://hashcat.net/files/hashcat-3.01.7z",
        "executable": "hashcat64.bin"
    }))
    .unwrap();

    assert!(DownloadCrackerResponse::try_from(raw).is_err());
}

#[test]
fn download_binary_preprocessor_without_url_is_rejected() {
    let raw: raw::DownloadBinaryResponse = serde_json::from_value(json!({
        "action": "downloadBinary",
        "response": "SUCCESS",
        "name": "Prince",
        "executable": "pp.bin"
    }))
    .unwrap();

    assert!(DownloadPreprocessorResponse::try_from(raw).is_err());
}

#[test]
fn get_task_no_task_available() {
    let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
        "action": "getTask",
        "response": "SUCCESS",
        "taskId": null,
        "reason": "No task available!"
    }));

    assert_eq!(
        res,
        GetTaskResponse::NoTask {
            reason: Some("No task available!".to_string())
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
        "usePreprocessor": false,
        "preprocessor": null,
        "preprocessorCommand": null,
        "enforcePipe": false,
        "slowHash": false,
        "useBrain": false
    }));

    let GetTaskResponse::Task(task) = res else {
        panic!("expected a task assignment, got {res:?}");
    };
    assert_eq!(task.task_id, 25);
    assert_eq!(task.cracker_id, 45);
    assert_eq!(task.attack_command, "#HL# -a 3 ?a?a?a?a --hash-type=0");
    assert_eq!(task.bench_type, BenchmarkType::Speed);
    assert_eq!(task.keyspace, 0);
    assert_eq!(
        task.files,
        vec!["rockyou.txt".to_string(), "wordlist.txt".to_string()]
    );
    assert!(!task.slow_hash);
    assert!(task.preprocessor.is_none());
    assert!(task.brain.is_none());
}

#[test]
fn get_task_with_brain_and_preprocessor() {
    let res: GetTaskResponse = decode::<raw::GetTaskResponse, _>(json!({
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

    let GetTaskResponse::Task(task) = res else {
        panic!("expected a task assignment, got {res:?}");
    };
    assert_eq!(
        task.preprocessor,
        Some(Preprocessor {
            id: 2,
            command: "wordlist.txt".to_string()
        })
    );
    assert_eq!(
        task.brain,
        Some(BrainConfig {
            host: "10.20.30.40".to_string(),
            port: 1234,
            pass: "password".to_string(),
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
        "chunkId": 13,
        "skip": 45000,
        "length": 10000
    }));

    assert_eq!(
        res,
        GetChunkResponse::Chunk(Chunk {
            id: 13,
            skip: 45000,
            length: 10000
        })
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
        "zaps": ["87634876fe7f7df5e76f56a757", "7863487563874ffefe67575745"]
    }))
    .unwrap();

    assert_eq!(
        SendProgressResponse::from(raw),
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
        "extension": ".txt",
        "url": "get.php?file=5&token=GHhgdf(/&",
        "filesize": 267729
    }));

    assert_eq!(res.filename, "rockyou.txt");
    assert_eq!(res.extension, ".txt");
    assert_eq!(res.url, "get.php?file=5&token=GHhgdf(/&");
    assert_eq!(res.filesize, 267729);
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
        "url": "get.php?hashlist=5&token=GHhgdf(/&"
    }));

    assert_eq!(res.url, "get.php?hashlist=5&token=GHhgdf(/&");
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
        "attack": "#HL# -a 3 -1 ?l?u?d ?1?1?1?1?1",
        "crackerBinaryId": 1,
        "hashes": ["9f650d4ef70eead895e7a03ce0f83e88", "24a7bdfd14bca7f9d14154c0800a833d"],
        "checkId": 7,
        "hashlistAlias": "#HL#"
    }));

    assert_eq!(res.attack, "#HL# -a 3 -1 ?l?u?d ?1?1?1?1?1");
    assert_eq!(res.cracker_binary_id, 1);
    assert_eq!(
        res.hashes,
        vec![
            "9f650d4ef70eead895e7a03ce0f83e88".to_string(),
            "24a7bdfd14bca7f9d14154c0800a833d".to_string()
        ]
    );
    assert_eq!(res.check_id, 7);
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

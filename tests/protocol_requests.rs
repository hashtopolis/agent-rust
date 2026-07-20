use htp_agent::model::{BenchmarkType, Os};
use htp_agent::protocol::{BinaryType, Request};
use serde_json::json;

#[test]
fn register_full() {
    let req = Request::Register {
        voucher: "my-voucher".to_string(),
        name: "agent-host".to_string(),
        cpu_only: Some(true),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "register",
            "voucher": "my-voucher",
            "name": "agent-host",
            "cpu-only": true
        })
    );
}

#[test]
fn register_omits_cpu_only_when_none() {
    let req = Request::Register {
        voucher: "v".to_string(),
        name: "host".to_string(),
        cpu_only: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "register", "voucher": "v", "name": "host"})
    );
}

#[test]
fn login() {
    let req = Request::Login {
        token: "tok123".to_string(),
        client_signature: "s3-rust-0.1.0".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "login", "token": "tok123", "clientSignature": "s3-rust-0.1.0"})
    );
}

#[test]
fn test_connection_carries_only_the_action() {
    assert_eq!(
        serde_json::to_value(Request::TestConnection).unwrap(),
        json!({"action": "testConnection"})
    );
}

#[test]
fn update_information_serializes_os_as_numeric_code() {
    let req = Request::UpdateInformation {
        token: "tok123".to_string(),
        uid: "1b4e28ba-2fa1-11d2-883f-0016d3cca427".to_string(),
        os: Os::Linux,
        devices: vec![
            "GeForce RTX 3090".to_string(),
            "GeForce RTX 3090".to_string(),
        ],
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "updateInformation",
            "token": "tok123",
            "uid": "1b4e28ba-2fa1-11d2-883f-0016d3cca427",
            "os": 0,
            "devices": ["GeForce RTX 3090", "GeForce RTX 3090"]
        })
    );
}

#[test]
fn check_client_version() {
    let req = Request::CheckClientVersion {
        token: "tok123".to_string(),
        version: "0.1.0".to_string(),
        agent_type: "rust".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "checkClientVersion",
            "token": "tok123",
            "version": "0.1.0",
            "type": "rust"
        })
    );
}

#[test]
fn download_binary_cracker_includes_version_id() {
    let req = Request::DownloadBinary {
        token: "tok123".to_string(),
        binary_type: BinaryType::Cracker,
        binary_version_id: Some(12),
        preprocessor_id: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "downloadBinary",
            "token": "tok123",
            "type": "cracker",
            "binaryVersionId": 12
        })
    );
}

#[test]
fn download_binary_util_omits_optional_ids() {
    let req = Request::DownloadBinary {
        token: "tok123".to_string(),
        binary_type: BinaryType::Extractor,
        binary_version_id: None,
        preprocessor_id: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "downloadBinary", "token": "tok123", "type": "7zr"})
    );
}

#[test]
fn binary_type_wire_values() {
    assert_eq!(
        serde_json::to_value(BinaryType::Extractor).unwrap(),
        json!("7zr")
    );
    assert_eq!(
        serde_json::to_value(BinaryType::Cracker).unwrap(),
        json!("cracker")
    );
    assert_eq!(
        serde_json::to_value(BinaryType::Prince).unwrap(),
        json!("prince")
    );
    assert_eq!(
        serde_json::to_value(BinaryType::Uftpd).unwrap(),
        json!("uftpd")
    );
    assert_eq!(
        serde_json::to_value(BinaryType::Preprocessor).unwrap(),
        json!("preprocessor")
    );
}

#[test]
fn get_task() {
    let req = Request::GetTask {
        token: "tok123".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getTask", "token": "tok123"})
    );
}

#[test]
fn get_chunk() {
    let req = Request::GetChunk {
        token: "tok123".to_string(),
        task_id: 42,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getChunk", "token": "tok123", "taskId": 42})
    );
}

#[test]
fn send_keyspace() {
    let req = Request::SendKeyspace {
        token: "tok123".to_string(),
        task_id: 42,
        keyspace: 14344385,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendKeyspace",
            "token": "tok123",
            "taskId": 42,
            "keyspace": 14344385
        })
    );
}

#[test]
fn send_benchmark() {
    let req = Request::SendBenchmark {
        token: "tok123".to_string(),
        task_id: 42,
        bench_type: BenchmarkType::Speed,
        result: "3320.1".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendBenchmark",
            "token": "tok123",
            "taskId": 42,
            "type": "speed",
            "result": "3320.1"
        })
    );
    assert_eq!(
        serde_json::to_value(BenchmarkType::Run).unwrap(),
        json!("run")
    );
}

#[test]
fn send_progress_omits_optional_telemetry() {
    let req = Request::SendProgress {
        token: "tok123".to_string(),
        chunk_id: 100,
        keyspace_progress: 500,
        relative_progress: 5000,
        speed: 123456,
        state: 4,
        cracks: vec!["5f4dcc3b5aa765d61d8327deb882cf99:password".to_string()],
        debug_output: None,
        gpu_temp: None,
        gpu_util: None,
        cpu_util: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendProgress",
            "token": "tok123",
            "chunkId": 100,
            "keyspaceProgress": 500,
            "relativeProgress": 5000,
            "speed": 123456,
            "state": 4,
            "cracks": ["5f4dcc3b5aa765d61d8327deb882cf99:password"]
        })
    );
}

#[test]
fn send_progress_includes_telemetry_when_present() {
    let req = Request::SendProgress {
        token: "tok123".to_string(),
        chunk_id: 100,
        keyspace_progress: 500,
        relative_progress: 5000,
        speed: 123456,
        state: 4,
        cracks: vec![],
        debug_output: Some(vec!["oops".to_string()]),
        gpu_temp: Some(vec![55, 60]),
        gpu_util: Some(vec![98, 99]),
        cpu_util: Some(vec![12.5]),
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["debugOutput"], json!(["oops"]));
    assert_eq!(v["gpuTemp"], json!([55, 60]));
    assert_eq!(v["gpuUtil"], json!([98, 99]));
    assert_eq!(v["cpuUtil"], json!([12.5]));
}

#[test]
fn client_error_keeps_null_chunk_id() {
    let req = Request::ClientError {
        token: "tok123".to_string(),
        task_id: 42,
        chunk_id: None,
        message: "hashcat exited with code 1".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "clientError",
            "token": "tok123",
            "taskId": 42,
            "chunkId": null,
            "message": "hashcat exited with code 1"
        })
    );
}

#[test]
fn client_error_with_chunk_id() {
    let req = Request::ClientError {
        token: "tok123".to_string(),
        task_id: 42,
        chunk_id: Some(7),
        message: "boom".to_string(),
    };

    assert_eq!(serde_json::to_value(&req).unwrap()["chunkId"], json!(7));
}

#[test]
fn get_hashlist() {
    let req = Request::GetHashlist {
        token: "tok123".to_string(),
        hashlist_id: 7,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getHashlist", "token": "tok123", "hashlistId": 7})
    );
}

#[test]
fn get_found() {
    let req = Request::GetFound {
        token: "tok123".to_string(),
        hashlist_id: 7,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getFound", "token": "tok123", "hashlistId": 7})
    );
}

#[test]
fn get_file() {
    let req = Request::GetFile {
        token: "tok123".to_string(),
        task_id: 42,
        file: "rockyou.txt".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "getFile",
            "token": "tok123",
            "taskId": 42,
            "file": "rockyou.txt"
        })
    );
}

#[test]
fn get_file_status() {
    let req = Request::GetFileStatus {
        token: "tok123".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getFileStatus", "token": "tok123"})
    );
}

#[test]
fn get_health_check() {
    let req = Request::GetHealthCheck {
        token: "tok123".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getHealthCheck", "token": "tok123"})
    );
}

#[test]
fn send_health_check() {
    let req = Request::SendHealthCheck {
        token: "tok123".to_string(),
        check_id: 9,
        num_cracked: 2,
        start: 1700000000,
        end: 1700000123,
        num_gpus: 4,
        errors: vec![],
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendHealthCheck",
            "token": "tok123",
            "checkId": 9,
            "numCracked": 2,
            "start": 1700000000,
            "end": 1700000123,
            "numGpus": 4,
            "errors": []
        })
    );
}

#[test]
fn deregister() {
    let req = Request::Deregister {
        token: "tok123".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "deregister", "token": "tok123"})
    );
}

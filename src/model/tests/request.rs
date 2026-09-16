use crate::model::raw::{BinaryType, Request};
use crate::model::{BenchmarkType, Crack, Os};
use serde_json::json;

#[test]
fn register_full() {
    let req = Request::Register {
        voucher: "89GD78tf".to_string(),
        name: "client name".to_string(),
        cpu_only: Some(true),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "register",
            "voucher": "89GD78tf",
            "name": "client name",
            "cpu-only": true
        })
    );
}

#[test]
fn register_omits_cpu_only_when_none() {
    let req = Request::Register {
        voucher: "89GD78tf".to_string(),
        name: "client name".to_string(),
        cpu_only: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "register", "voucher": "89GD78tf", "name": "client name"})
    );
}

#[test]
fn login() {
    let req = Request::Login {
        token: "GHhgdf(/&".to_string(),
        client_signature: "generic-python".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "login", "token": "GHhgdf(/&", "clientSignature": "generic-python"})
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
        token: "GHhgdf(/&".to_string(),
        uid: "230-34-345-345".to_string(),
        os: Os::Linux.into(),
        devices: vec!["ATI HD7970".to_string(), "ATI HD7970".to_string()],
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "updateInformation",
            "token": "GHhgdf(/&",
            "uid": "230-34-345-345",
            "os": 0,
            "devices": ["ATI HD7970", "ATI HD7970"]
        })
    );
}

#[test]
fn check_client_version() {
    let req = Request::CheckClientVersion {
        token: "GHhgdf(/&".to_string(),
        version: "0.43.5".to_string(),
        agent_type: "csharp".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "checkClientVersion",
            "token": "GHhgdf(/&",
            "version": "0.43.5",
            "type": "csharp"
        })
    );
}

#[test]
fn download_binary_cracker_includes_version_id() {
    let req = Request::DownloadBinary {
        token: "GHhgdf(/&".to_string(),
        binary_type: BinaryType::Cracker,
        binary_version_id: Some(45),
        preprocessor_id: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "downloadBinary",
            "token": "GHhgdf(/&",
            "type": "cracker",
            "binaryVersionId": 45
        })
    );
}

#[test]
fn download_binary_util_omits_optional_ids() {
    let req = Request::DownloadBinary {
        token: "GHhgdf(/&".to_string(),
        binary_type: BinaryType::Extractor,
        binary_version_id: None,
        preprocessor_id: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "downloadBinary", "token": "GHhgdf(/&", "type": "7zr"})
    );
}

#[test]
fn get_task() {
    let req = Request::GetTask {
        token: "GHhgdf(/&".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getTask", "token": "GHhgdf(/&"})
    );
}

#[test]
fn get_chunk() {
    let req = Request::GetChunk {
        token: "GHhgdf(/&".to_string(),
        task_id: 5,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getChunk", "token": "GHhgdf(/&", "taskId": 5})
    );
}

#[test]
fn send_keyspace() {
    let req = Request::SendKeyspace {
        token: "GHhgdf(/&".to_string(),
        task_id: 35,
        keyspace: 568000,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendKeyspace",
            "token": "GHhgdf(/&",
            "taskId": 35,
            "keyspace": 568000
        })
    );
}

#[test]
fn send_benchmark() {
    let req = Request::SendBenchmark {
        token: "GHhgdf(/&".to_string(),
        task_id: 35,
        bench_type: BenchmarkType::Speed.into(),
        result: "674:674.74".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendBenchmark",
            "token": "GHhgdf(/&",
            "taskId": 35,
            "type": "speed",
            "result": "674:674.74"
        })
    );
}

#[test]
fn send_progress_omits_optional_telemetry() {
    let req = Request::SendProgress {
        token: "GHhgdf(/&".to_string(),
        chunk_id: 35,
        keyspace_progress: 568000,
        relative_progress: 4545,
        speed: 570000,
        state: 3,
        cracks: vec![
            Crack::Fields(vec![
                "7fde65673fd28736423f23423786f".to_string(),
                "thisisplain".to_string(),
                "746869736973706c61696e".to_string(),
                "787523889".to_string(),
            ]),
            Crack::Fields(vec![
                "7fde65673f28987f7423f2342378f".to_string(),
                "otherplain".to_string(),
                "6f74686572706c61696e".to_string(),
                "78652".to_string(),
            ]),
        ],
        debug_output: None,
        gpu_temp: None,
        gpu_util: None,
        cpu_util: None,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendProgress",
            "token": "GHhgdf(/&",
            "chunkId": 35,
            "keyspaceProgress": 568000,
            "relativeProgress": 4545,
            "speed": 570000,
            "state": 3,
            "cracks": [
                ["7fde65673fd28736423f23423786f", "thisisplain", "746869736973706c61696e", "787523889"],
                ["7fde65673f28987f7423f2342378f", "otherplain", "6f74686572706c61696e", "78652"]
            ]
        })
    );
}

#[test]
fn send_progress_mixes_field_and_raw_cracks() {
    // hashcat cracks are pre-split fields (JSON array); generic cracks are raw
    // lines (JSON string). Both must be able to travel in one request, each in
    // its own shape.
    let req = Request::SendProgress {
        token: "tok".to_string(),
        chunk_id: 1,
        keyspace_progress: 0,
        relative_progress: 0,
        speed: 0,
        state: 2,
        cracks: vec![
            Crack::Fields(vec!["hash".to_string(), "plain".to_string()]),
            Crack::Raw("otherhash:otherplain".to_string()),
        ],
        debug_output: None,
        gpu_temp: None,
        gpu_util: None,
        cpu_util: None,
    };

    let v = serde_json::to_value(&req).unwrap();

    assert_eq!(
        v["cracks"],
        json!([["hash", "plain"], "otherhash:otherplain"])
    );
}

#[test]
fn send_progress_includes_telemetry_when_present() {
    let req = Request::SendProgress {
        token: "GHhgdf(/&".to_string(),
        chunk_id: 35,
        keyspace_progress: 568000,
        relative_progress: 4545,
        speed: 570000,
        state: 3,
        cracks: vec![],
        debug_output: Some(vec!["oops".to_string()]),
        gpu_temp: Some(vec![67]),
        gpu_util: Some(vec![99]),
        cpu_util: Some(vec![12.5]),
    };
    let v = serde_json::to_value(&req).unwrap();
    assert_eq!(v["debugOutput"], json!(["oops"]));
    assert_eq!(v["gpuTemp"], json!([67]));
    assert_eq!(v["gpuUtil"], json!([99]));
    assert_eq!(v["cpuUtil"], json!([12.5]));
}

#[test]
fn client_error_keeps_null_chunk_id() {
    let req = Request::ClientError {
        token: "GHhgdf(/&".to_string(),
        task_id: 45,
        chunk_id: None,
        message: "This is a sample error message!".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "clientError",
            "token": "GHhgdf(/&",
            "taskId": 45,
            "chunkId": null,
            "message": "This is a sample error message!"
        })
    );
}

#[test]
fn client_error_with_chunk_id() {
    let req = Request::ClientError {
        token: "GHhgdf(/&".to_string(),
        task_id: 45,
        chunk_id: Some(1),
        message: "This is a sample error message!".to_string(),
    };

    assert_eq!(serde_json::to_value(&req).unwrap()["chunkId"], json!(1));
}

#[test]
fn get_hashlist() {
    let req = Request::GetHashlist {
        token: "GHhgdf(/&".to_string(),
        hashlist_id: 23,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getHashlist", "token": "GHhgdf(/&", "hashlistId": 23})
    );
}

#[test]
fn get_found() {
    let req = Request::GetFound {
        token: "GHhgdf(/&".to_string(),
        hashlist_id: 7,
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getFound", "token": "GHhgdf(/&", "hashlistId": 7})
    );
}

#[test]
fn get_file() {
    let req = Request::GetFile {
        token: "GHhgdf(/&".to_string(),
        task_id: 56,
        file: "rockyou.txt".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "getFile",
            "token": "GHhgdf(/&",
            "taskId": 56,
            "file": "rockyou.txt"
        })
    );
}

#[test]
fn get_file_status() {
    let req = Request::GetFileStatus {
        token: "GHhgdf(/&".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getFileStatus", "token": "GHhgdf(/&"})
    );
}

#[test]
fn get_health_check() {
    let req = Request::GetHealthCheck {
        token: "GHhgdf(/&".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "getHealthCheck", "token": "GHhgdf(/&"})
    );
}

#[test]
fn send_health_check() {
    let req = Request::SendHealthCheck {
        token: "GHhgdf(/&".to_string(),
        check_id: 7,
        num_cracked: 23,
        start: 1536306884,
        end: 1536306902,
        num_gpus: 1,
        errors: vec![
            "nvmlDeviceGetTemperatureThreshold(): Not Supported".to_string(),
            "nvmlDeviceGetTemperatureThreshold(): Not Supported".to_string(),
        ],
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({
            "action": "sendHealthCheck",
            "token": "GHhgdf(/&",
            "checkId": 7,
            "numCracked": 23,
            "start": 1536306884,
            "end": 1536306902,
            "numGpus": 1,
            "errors": [
                "nvmlDeviceGetTemperatureThreshold(): Not Supported",
                "nvmlDeviceGetTemperatureThreshold(): Not Supported"
            ]
        })
    );
}

#[test]
fn deregister() {
    let req = Request::Deregister {
        token: "GHhgdf(/&".to_string(),
    };

    assert_eq!(
        serde_json::to_value(&req).unwrap(),
        json!({"action": "deregister", "token": "GHhgdf(/&"})
    );
}

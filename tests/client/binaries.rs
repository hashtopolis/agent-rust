use htp_agent::model::{
    DownloadCrackerResponse, DownloadPreprocessorResponse, DownloadUtilityResponse,
};
use serde_json::json;

use crate::common::{
    TOKEN, assert_client_sent_body, assert_server_error, error_reply, mock_client_returning,
};

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

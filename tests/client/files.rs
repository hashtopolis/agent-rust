use htp_agent::model::{
    GetFileResponse, GetFileStatusResponse, GetFoundResponse, GetHashlistResponse,
};
use serde_json::json;

use crate::common::{
    TOKEN, assert_client_sent_body, assert_server_error, error_reply, mock_client_returning,
};

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

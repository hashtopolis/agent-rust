//! Downloads checked against the server's RFC 9530 `Repr-Digest` header.
//!
//! The encoding itself is pinned against the published BLAKE3 vectors in
//! `src/digest.rs`; these drive a real `HttpDownloader` against a real socket to
//! cover the plumbing: reading the header off the response, hashing the stream,
//! and what happens to the file when the digests disagree.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tempfile::TempDir;

use htp_agent::download::{DownloadError, Downloader, HttpDownloader};

use crate::support::one_shot::OneShot;

const BODY: &str = "a-short-wordlist\n";

/// `blake3=:<base64>:`, the single-member form the server sends.
fn repr_digest(bytes: &[u8]) -> String {
    format!(
        "blake3=:{}:",
        STANDARD.encode(blake3::hash(bytes).as_bytes())
    )
}

/// Downloads `BODY` from a server sending `repr-digest`, into a temp file.
/// Hands back the result and the path, so a test can assert on both.
async fn download_with(
    repr_digest: Option<&str>,
) -> (Result<(), DownloadError>, TempDir, std::path::PathBuf) {
    let headers: Vec<(&str, &str)> = repr_digest
        .map(|value| vec![("repr-digest", value)])
        .unwrap_or_default();

    let server = OneShot::start_with_headers(BODY, &headers).await;
    let downloader = HttpDownloader::new(reqwest::Client::new(), server.url.clone());

    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("words.txt");

    let result = downloader.download(&server.url, &dest).await;

    (result, dir, dest)
}

#[tokio::test]
async fn a_matching_digest_passes_and_keeps_the_bytes() {
    let digest = repr_digest(BODY.as_bytes());
    let (result, _dir, dest) = download_with(Some(&digest)).await;

    result.expect("a download whose digest matches should succeed");
    assert_eq!(tokio::fs::read_to_string(&dest).await.unwrap(), BODY);
}

#[tokio::test]
async fn a_mismatching_digest_fails_and_removes_the_file() {
    // A valid, well-formed digest — of something else.
    let digest = repr_digest(b"different bytes");
    let (result, _dir, dest) = download_with(Some(&digest)).await;

    let error = result.expect_err("a download whose digest disagrees should fail");

    assert!(
        matches!(error, DownloadError::DigestMismatch { .. }),
        "{error:?}"
    );

    // The announced and actual digests both belong in the message: that is what
    // an operator compares against `b3sum` on the server.
    let message = error.to_string();
    assert!(
        message.contains(&blake3::hash(b"different bytes").to_hex().to_string())
            && message.contains(&blake3::hash(BODY.as_bytes()).to_hex().to_string()),
        "{message}"
    );

    // Load-bearing: the provisioner only size-checks a file that is already
    // present, so rejected bytes must not be left behind.
    assert!(
        !dest.exists(),
        "the file that failed its digest check should be gone"
    );
}

#[tokio::test]
async fn no_header_downloads_as_before() {
    let (result, _dir, dest) = download_with(None).await;

    result.expect("a server that announces no digest should still be downloaded from");
    assert_eq!(tokio::fs::read_to_string(&dest).await.unwrap(), BODY);
}

#[tokio::test]
async fn an_unreadable_header_falls_back_instead_of_failing() {
    // Each of these is a blake3 member the agent cannot use. None of them may
    // stop the download: the size check stays the only check, as before.
    for value in [
        "blake3=:not base64!:",
        "blake3=::",
        "blake3=:AAEC:",
        "sha-256=:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=:",
    ] {
        let (result, _dir, dest) = download_with(Some(value)).await;

        result.unwrap_or_else(|error| panic!("{value} should not fail the download: {error}"));
        assert_eq!(
            tokio::fs::read_to_string(&dest).await.unwrap(),
            BODY,
            "{value}"
        );
    }
}

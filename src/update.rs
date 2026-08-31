//! Self-update: fetch the bundle, install the binary for this build's target,
//! and re-exec.
//!
//! The server serves one `rust-agent.zip` for the `rust` type, holding a binary
//! per target plus a `manifest.json` (see `scripts/bundle.sh`). Delivery is not
//! per-OS, so the agent picks its binary by matching [`agent_target`] against
//! each entry's `triples`.
//!
//! [`apply`] does not return on success; the process image is replaced. Any
//! failure leaves the running agent untouched.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use thiserror::Error;

use crate::download::{DownloadError, Downloader};
use crate::identity::{agent_target, agent_version};

/// Manifest file name, matched by suffix so the bundle may nest under a folder.
const MANIFEST_NAME: &str = "manifest.json";

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error(transparent)]
    Download(#[from] DownloadError),
    #[error("reading update bundle: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("parsing bundle manifest: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("update bundle has no {MANIFEST_NAME}")]
    MissingManifest,
    #[error("update bundle has no binary for target {0}")]
    NoMatchingBinary(String),
    #[error("update bundle is missing announced entry {0}")]
    MissingEntry(String),
    #[error("filesystem error at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("resolving the current executable: {0}")]
    CurrentExe(#[source] io::Error),
    #[error("replacing the running executable: {0}")]
    Replace(#[source] io::Error),
    #[error("re-executing the updated agent: {0}")]
    ReExec(#[source] io::Error),
}

#[derive(Debug, Deserialize)]
struct Manifest {
    version: String,
    binaries: Vec<BinaryEntry>,
}

#[derive(Debug, Deserialize)]
struct BinaryEntry {
    /// Path within the bundle, relative to the manifest's folder.
    path: String,
    #[serde(default)]
    triples: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Installed,
    AlreadyCurrent,
}

/// Download the bundle at `url`, install the binary matching this build's
/// target, and re-exec. Does not return on success.
pub async fn apply<D: Downloader>(downloader: &D, url: &str) -> Result<(), UpdateError> {
    let current_exe = std::env::current_exe().map_err(UpdateError::CurrentExe)?;

    let zip_path =
        std::env::temp_dir().join(format!("rust-agent-update-{}.zip", std::process::id()));

    tracing::info!(%url, "downloading update bundle");
    downloader.download(url, &zip_path).await?;

    // Zip extraction and the swap are blocking; run them off the async runtime.
    // Stage beside the current exe so the swap is a same-filesystem rename.
    let exe_dir = current_exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let zip_for_task = zip_path.clone();

    let outcome = tokio::task::spawn_blocking(move || {
        install_from_zip(&zip_for_task, &exe_dir, agent_target())
    })
    .await
    .map_err(|source| UpdateError::Io {
        path: zip_path.clone(),
        source: io::Error::other(source),
    })?;

    let _ = fs::remove_file(&zip_path);

    match outcome? {
        Outcome::AlreadyCurrent => {
            tracing::warn!("update bundle matches the running version; not restarting");
            Ok(())
        }
        Outcome::Installed => {
            tracing::info!("update installed; restarting");
            restart(&current_exe)
        }
    }
}

/// Result of staging the bundle.
#[derive(Debug)]
enum StageResult {
    AlreadyCurrent,
    /// Binary written here, awaiting the swap.
    ReadyForSwap {
        path: PathBuf,
        version: String,
    },
}

/// Pick the binary for `target` and replace the running executable. Blocking.
fn install_from_zip(zip_path: &Path, exe_dir: &Path, target: &str) -> Result<Outcome, UpdateError> {
    // Same filesystem as the exe, so the swap is a rename, not a cross-device copy.
    let staged = exe_dir.join(".htp-agent-update.tmp");

    match stage_from_zip(zip_path, &staged, target)? {
        StageResult::AlreadyCurrent => Ok(Outcome::AlreadyCurrent),
        StageResult::ReadyForSwap { path, version } => {
            set_executable(&path)?;

            tracing::info!(%version, "staged new binary");

            self_replace::self_replace(&path).map_err(UpdateError::Replace)?;
            let _ = fs::remove_file(&path);

            Ok(Outcome::Installed)
        }
    }
}

/// Read the manifest, pick the binary for `target`, and extract it to `dest`.
fn stage_from_zip(zip_path: &Path, dest: &Path, target: &str) -> Result<StageResult, UpdateError> {
    let file = fs::File::open(zip_path).map_err(io_at(zip_path))?;
    let mut archive = zip::ZipArchive::new(file)?;

    let manifest_name = find_manifest_name(&archive).ok_or(UpdateError::MissingManifest)?;
    let manifest = read_manifest(&mut archive, &manifest_name)?;

    if manifest.version == agent_version() {
        return Ok(StageResult::AlreadyCurrent);
    }

    let relative = select_binary(&manifest, target)?;
    // Entry paths are relative to the manifest's folder.
    let entry_name = format!("{}{relative}", manifest_prefix(&manifest_name));

    extract_entry(&mut archive, &entry_name, dest)?;

    Ok(StageResult::ReadyForSwap {
        path: dest.to_path_buf(),
        version: manifest.version,
    })
}

/// The manifest's full entry name, found by suffix so it may sit under a folder.
fn find_manifest_name<R: Read + io::Seek>(archive: &zip::ZipArchive<R>) -> Option<String> {
    archive
        .file_names()
        .find(|name| *name == MANIFEST_NAME || name.ends_with(&format!("/{MANIFEST_NAME}")))
        .map(str::to_owned)
}

/// The manifest's folder (trailing slash), or "" at the root; binary paths are
/// relative to it.
fn manifest_prefix(manifest_name: &str) -> &str {
    &manifest_name[..manifest_name.len() - MANIFEST_NAME.len()]
}

fn read_manifest<R: Read + io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    manifest_name: &str,
) -> Result<Manifest, UpdateError> {
    let mut entry = archive.by_name(manifest_name)?;
    let mut buf = String::new();
    entry
        .read_to_string(&mut buf)
        .map_err(io_at(Path::new(manifest_name)))?;

    Ok(serde_json::from_str(&buf)?)
}

fn select_binary(manifest: &Manifest, target: &str) -> Result<String, UpdateError> {
    manifest
        .binaries
        .iter()
        .find(|binary| binary.triples.iter().any(|triple| triple == target))
        .map(|binary| binary.path.clone())
        .ok_or_else(|| UpdateError::NoMatchingBinary(target.to_owned()))
}

fn extract_entry<R: Read + io::Seek>(
    archive: &mut zip::ZipArchive<R>,
    entry_name: &str,
    dest: &Path,
) -> Result<(), UpdateError> {
    let mut entry = archive
        .by_name(entry_name)
        .map_err(|_| UpdateError::MissingEntry(entry_name.to_owned()))?;

    // Destination is fixed by the agent, not the entry name, so a crafted path
    // cannot escape it.
    let mut out = fs::File::create(dest).map_err(io_at(dest))?;
    io::copy(&mut entry, &mut out).map_err(io_at(dest))?;

    Ok(())
}

/// Extraction drops the executable bit; restore it before the swap.
fn set_executable(path: &Path) -> Result<(), UpdateError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).map_err(io_at(path))?.permissions();
        permissions.set_mode(permissions.mode() | 0o755);
        fs::set_permissions(path, permissions).map_err(io_at(path))?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

/// Re-exec the updated binary with the original arguments. Does not return on
/// success.
fn restart(current_exe: &Path) -> Result<(), UpdateError> {
    let args = std::env::args_os().skip(1);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        // exec replaces the process image; it returns only on failure.
        Err(UpdateError::ReExec(
            Command::new(current_exe).args(args).exec(),
        ))
    }

    #[cfg(not(unix))]
    {
        // Windows cannot exec in place: spawn the new binary and exit.
        Command::new(current_exe)
            .args(args)
            .spawn()
            .map_err(UpdateError::ReExec)?;
        std::process::exit(0);
    }
}

fn io_at(path: &Path) -> impl FnOnce(io::Error) -> UpdateError {
    let path = path.to_path_buf();

    move |source| UpdateError::Io { path, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use tempfile::TempDir;

    /// Build a bundle zip nested under `rust-agent/`, as `scripts/bundle.sh`
    /// lays it out, with placeholder binaries.
    fn build_bundle(dir: &Path, version: &str) -> PathBuf {
        let zip_path = dir.join("rust-agent.zip");
        let file = fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        let manifest = format!(
            r#"{{
              "agent_type": "rust",
              "version": "{version}",
              "binaries": [
                {{"path": "x86_64-unknown-linux-musl/htp-agent", "os": "linux", "arch": "x86_64",
                  "triples": ["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"]}},
                {{"path": "x86_64-pc-windows-gnu/htp-agent.exe", "os": "windows", "arch": "x86_64",
                  "triples": ["x86_64-pc-windows-gnu", "x86_64-pc-windows-msvc"]}}
              ]
            }}"#
        );

        zip.start_file("rust-agent/manifest.json", opts).unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();
        zip.start_file("rust-agent/x86_64-unknown-linux-musl/htp-agent", opts)
            .unwrap();
        zip.write_all(b"linux-binary").unwrap();
        zip.start_file("rust-agent/x86_64-pc-windows-gnu/htp-agent.exe", opts)
            .unwrap();
        zip.write_all(b"windows-binary").unwrap();
        zip.finish().unwrap();

        zip_path
    }

    #[test]
    fn stages_the_matching_binary_from_a_nested_bundle() {
        let tmp = TempDir::new().unwrap();
        let zip = build_bundle(tmp.path(), "0.2.0");
        let dest = tmp.path().join("staged");

        let staged = stage_from_zip(&zip, &dest, "x86_64-pc-windows-gnu").unwrap();

        match staged {
            StageResult::ReadyForSwap { path, version } => {
                assert_eq!(path, dest);
                assert_eq!(version, "0.2.0");
                assert_eq!(fs::read(&dest).unwrap(), b"windows-binary");
            }
            StageResult::AlreadyCurrent => panic!("expected a staged binary"),
        }
    }

    #[test]
    fn staging_is_skipped_when_the_bundle_matches_the_running_version() {
        let tmp = TempDir::new().unwrap();
        let zip = build_bundle(tmp.path(), agent_version());
        let dest = tmp.path().join("staged");

        let staged = stage_from_zip(&zip, &dest, "x86_64-unknown-linux-musl").unwrap();

        assert!(matches!(staged, StageResult::AlreadyCurrent));
        assert!(
            !dest.exists(),
            "nothing should be extracted when up to date"
        );
    }

    #[test]
    fn staging_fails_without_a_binary_for_the_target() {
        let tmp = TempDir::new().unwrap();
        let zip = build_bundle(tmp.path(), "0.2.0");
        let dest = tmp.path().join("staged");

        let error = stage_from_zip(&zip, &dest, "aarch64-apple-darwin").unwrap_err();
        assert!(matches!(error, UpdateError::NoMatchingBinary(_)));
    }

    fn manifest() -> Manifest {
        Manifest {
            version: "0.2.0".to_owned(),
            binaries: vec![
                BinaryEntry {
                    path: "x86_64-unknown-linux-musl/htp-agent".to_owned(),
                    triples: vec![
                        "x86_64-unknown-linux-musl".to_owned(),
                        "x86_64-unknown-linux-gnu".to_owned(),
                    ],
                },
                BinaryEntry {
                    path: "x86_64-pc-windows-gnu/htp-agent.exe".to_owned(),
                    triples: vec![
                        "x86_64-pc-windows-gnu".to_owned(),
                        "x86_64-pc-windows-msvc".to_owned(),
                    ],
                },
            ],
        }
    }

    #[test]
    fn selects_the_binary_for_an_exact_triple() {
        assert_eq!(
            select_binary(&manifest(), "x86_64-unknown-linux-musl").unwrap(),
            "x86_64-unknown-linux-musl/htp-agent"
        );
    }

    #[test]
    fn selects_via_an_equivalent_triple() {
        // A gnu-built agent is served the musl binary; an msvc-built one the gnu.
        assert_eq!(
            select_binary(&manifest(), "x86_64-unknown-linux-gnu").unwrap(),
            "x86_64-unknown-linux-musl/htp-agent"
        );
        assert_eq!(
            select_binary(&manifest(), "x86_64-pc-windows-msvc").unwrap(),
            "x86_64-pc-windows-gnu/htp-agent.exe"
        );
    }

    #[test]
    fn errors_when_no_binary_matches_the_target() {
        let error = select_binary(&manifest(), "aarch64-apple-darwin").unwrap_err();
        assert!(matches!(error, UpdateError::NoMatchingBinary(t) if t == "aarch64-apple-darwin"));
    }

    #[test]
    fn manifest_prefix_handles_nested_and_root_manifests() {
        assert_eq!(manifest_prefix("rust-agent/manifest.json"), "rust-agent/");
        assert_eq!(manifest_prefix("manifest.json"), "");
    }
}

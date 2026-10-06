//! Self-update: fetch the bundle, install the binary for this build's target,
//! and re-exec.
//!
//! The server serves one `rust-agent.zip` for the `rust` type, holding a binary
//! per target plus a `manifest.json` (see `scripts/bundle.sh`). Delivery is not
//! per-OS, so the agent picks its binary by matching [`agent_target`] against
//! each entry's `triples`.
//!
//! After installation, [`apply`] replaces the process image.
//! A staged binary must pass a version probe before installation. Replacement or
//! restart failures restore the previous executable; rollback failures are reported
//! separately. Crashes after a successful restart require external supervision.

use std::fs;
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Deserialize;
use tempfile::TempDir;
use thiserror::Error;

use crate::download::{DownloadError, Downloader};
use crate::identity::{agent_target, agent_version};

/// Manifest file name, matched by suffix so the bundle may nest under a folder.
const MANIFEST_NAME: &str = "manifest.json";
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

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
    #[error("starting the staged agent version check: {0}")]
    Probe(#[source] io::Error),
    #[error("staged agent version check timed out")]
    ProbeTimeout,
    #[error("staged agent must report htp-agent {expected}; got {actual:?} ({status})")]
    InvalidVersion {
        expected: String,
        actual: String,
        status: std::process::ExitStatus,
    },
    #[error("{original}; restoring the previous executable also failed: {source}")]
    Rollback {
        original: Box<UpdateError>,
        #[source]
        source: io::Error,
    },
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

/// Download the bundle at `url`, validate and install this target's binary,
/// and re-exec. Returns without restarting when the version already matches.
pub async fn apply<D: Downloader>(downloader: &D, url: &str) -> Result<(), UpdateError> {
    let current_exe = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(UpdateError::CurrentExe)?;
    let exe_dir = current_exe
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    // The downloader opens a path, so reserve a private directory first. An
    // existing file or symlink in the system temp directory cannot redirect it.
    let download_dir = private_directory(&std::env::temp_dir(), "htp-agent-download-")?;
    let zip_path = download_dir.path().join("bundle.zip");

    tracing::info!(%url, "downloading update bundle");
    downloader.download(url, &zip_path).await?;

    // Move the directory guard into the worker: cancellation must not delete
    // the archive while blocking extraction is still using it.
    let prepared = tokio::task::spawn_blocking(move || {
        let _download_dir = download_dir;

        prepare_from_zip(&zip_path, &exe_dir, agent_target())
    })
    .await
    .map_err(|source| UpdateError::Io {
        path: current_exe.clone(),
        source: io::Error::other(source),
    })??;

    let Some(prepared) = prepared else {
        tracing::warn!("update bundle matches the running version; not restarting");

        return Ok(());
    };

    validate_binary(&prepared.path, &prepared.version, PROBE_TIMEOUT).await?;

    // Once replacement starts, finish the transaction even if shutdown cancels
    // the async caller. All filesystem guards live in this blocking worker.
    let error_path = current_exe.clone();

    tokio::task::spawn_blocking(move || {
        replace_and_restart(
            &current_exe,
            prepared,
            |path| self_replace::self_replace(path),
            restart,
        )
    })
    .await
    .map_err(|source| UpdateError::Io {
        path: error_path,
        source: io::Error::other(source),
    })?
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

struct PreparedUpdate {
    directory: TempDir,
    path: PathBuf,
    version: String,
}

fn private_directory(parent: &Path, prefix: &str) -> Result<TempDir, UpdateError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        builder.permissions(fs::Permissions::from_mode(0o700));
    }

    builder.tempdir_in(parent).map_err(io_at(parent))
}

/// Extract into a private directory beside the executable, on the same filesystem.
fn prepare_from_zip(
    zip_path: &Path,
    exe_dir: &Path,
    target: &str,
) -> Result<Option<PreparedUpdate>, UpdateError> {
    let directory = private_directory(exe_dir, ".htp-agent-update-")?;
    let staged = directory
        .path()
        .join(format!("htp-agent{}", std::env::consts::EXE_SUFFIX));

    match stage_from_zip(zip_path, &staged, target)? {
        StageResult::AlreadyCurrent => Ok(None),
        StageResult::ReadyForSwap { path, version } => {
            set_executable(&path)?;

            Ok(Some(PreparedUpdate {
                directory,
                path,
                version,
            }))
        }
    }
}

async fn validate_binary(path: &Path, version: &str, timeout: Duration) -> Result<(), UpdateError> {
    let output = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| UpdateError::ProbeTimeout)?
    .map_err(UpdateError::Probe)?;

    let actual = String::from_utf8_lossy(&output.stdout).trim().to_owned();

    if !output.status.success() || actual != format!("htp-agent {version}") {
        return Err(UpdateError::InvalidVersion {
            expected: version.to_owned(),
            actual,
            status: output.status,
        });
    }

    Ok(())
}

/// Back up before the swap, and restore to the recorded installation path on any
/// returned error. Windows self-replacement can relocate the running executable,
/// so resolving current_exe again (or calling self_replace for rollback) is unsafe.
fn replace_and_restart(
    current_exe: &Path,
    prepared: PreparedUpdate,
    replace: impl FnOnce(&Path) -> io::Result<()>,
    restart: impl FnOnce(&Path) -> Result<(), UpdateError>,
) -> Result<(), UpdateError> {
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));
    let mut original = fs::File::open(current_exe).map_err(io_at(current_exe))?;
    let permissions = original
        .metadata()
        .map_err(io_at(current_exe))?
        .permissions();

    // Anonymous files are cleaned by the OS on exec/exit, when Rust destructors
    // do not run. Keep the rollback bytes available through an open handle.
    let mut backup = tempfile::tempfile_in(exe_dir).map_err(io_at(exe_dir))?;
    io::copy(&mut original, &mut backup).map_err(io_at(current_exe))?;
    drop(original);

    tracing::info!(version = %prepared.version, "installing validated update");

    let installed = replace(&prepared.path).map_err(UpdateError::Replace);
    drop(prepared.directory);

    let result = installed.and_then(|()| restart(current_exe));

    if let Err(original) = result {
        if let Err(source) = restore_backup(current_exe, &mut backup, permissions) {
            return Err(UpdateError::Rollback {
                original: Box::new(original),
                source,
            });
        }

        tracing::warn!("restored the previous executable after failed update");

        return Err(original);
    }

    Ok(())
}

fn restore_backup(
    current_exe: &Path,
    backup: &mut fs::File,
    permissions: fs::Permissions,
) -> io::Result<()> {
    let exe_dir = current_exe.parent().unwrap_or_else(|| Path::new("."));
    let mut restored = tempfile::NamedTempFile::new_in(exe_dir)?;
    backup.rewind()?;
    io::copy(backup, &mut restored)?;
    restored.as_file().set_permissions(permissions)?;
    restored.persist(current_exe).map_err(|error| error.error)?;

    Ok(())
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
    let mut out = fs::File::create_new(dest).map_err(io_at(dest))?;
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
                {{"path": "x86_64-pc-windows-msvc/htp-agent.exe", "os": "windows", "arch": "x86_64",
                  "triples": ["x86_64-pc-windows-msvc", "x86_64-pc-windows-gnu"]}}
              ]
            }}"#
        );

        zip.start_file("rust-agent/manifest.json", opts).unwrap();
        zip.write_all(manifest.as_bytes()).unwrap();
        zip.start_file("rust-agent/x86_64-unknown-linux-musl/htp-agent", opts)
            .unwrap();
        zip.write_all(b"linux-binary").unwrap();
        zip.start_file("rust-agent/x86_64-pc-windows-msvc/htp-agent.exe", opts)
            .unwrap();
        zip.write_all(b"windows-binary").unwrap();
        zip.finish().unwrap();

        zip_path
    }

    /// A version one patch above the running agent, so a bundle labelled with it
    /// is treated as an upgrade rather than the current build. Deriving it from
    /// `agent_version()` keeps these fixtures correct across version bumps.
    fn newer_version() -> String {
        let mut parts: Vec<u32> = agent_version()
            .split('.')
            .map(|p| p.parse().expect("agent version is numeric semver"))
            .collect();
        *parts.last_mut().expect("agent version has components") += 1;
        parts
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    #[test]
    fn stages_the_matching_binary_from_a_nested_bundle() {
        let tmp = TempDir::new().unwrap();
        let zip = build_bundle(tmp.path(), &newer_version());
        let dest = tmp.path().join("staged");

        let staged = stage_from_zip(&zip, &dest, "x86_64-pc-windows-msvc").unwrap();

        match staged {
            StageResult::ReadyForSwap { path, version } => {
                assert_eq!(path, dest);
                assert_eq!(version, newer_version());
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
        let zip = build_bundle(tmp.path(), &newer_version());
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
                    path: "x86_64-pc-windows-msvc/htp-agent.exe".to_owned(),
                    triples: vec![
                        "x86_64-pc-windows-msvc".to_owned(),
                        "x86_64-pc-windows-gnu".to_owned(),
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
        // A gnu-built agent is served the musl binary on linux and the msvc one
        // on windows.
        assert_eq!(
            select_binary(&manifest(), "x86_64-unknown-linux-gnu").unwrap(),
            "x86_64-unknown-linux-musl/htp-agent"
        );
        assert_eq!(
            select_binary(&manifest(), "x86_64-pc-windows-gnu").unwrap(),
            "x86_64-pc-windows-msvc/htp-agent.exe"
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

    #[test]
    fn staging_uses_separate_private_directories() {
        let tmp = TempDir::new().unwrap();
        let zip = build_bundle(tmp.path(), &newer_version());

        let first = prepare_from_zip(&zip, tmp.path(), "x86_64-unknown-linux-musl")
            .unwrap()
            .unwrap();
        let second = prepare_from_zip(&zip, tmp.path(), "x86_64-unknown-linux-musl")
            .unwrap()
            .unwrap();

        assert_ne!(first.directory.path(), second.directory.path());
        assert_eq!(fs::read(&first.path).unwrap(), b"linux-binary");
        assert_eq!(fs::read(&second.path).unwrap(), b"linux-binary");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            assert_eq!(
                fs::metadata(first.directory.path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn extraction_does_not_follow_an_existing_symlink() {
        let tmp = TempDir::new().unwrap();
        let zip = build_bundle(tmp.path(), &newer_version());
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"original").unwrap();

        let dest = tmp.path().join("staged");
        std::os::unix::fs::symlink(&victim, &dest).unwrap();

        let error = stage_from_zip(&zip, &dest, "x86_64-unknown-linux-musl").unwrap_err();

        assert!(
            matches!(error, UpdateError::Io { source, .. } if source.kind() == io::ErrorKind::AlreadyExists)
        );
        assert_eq!(fs::read(victim).unwrap(), b"original");
    }

    struct FailedDownload {
        destination: std::sync::Mutex<Option<PathBuf>>,
        interrupted: bool,
    }

    impl Downloader for FailedDownload {
        async fn download(&self, _: &str, dest: &Path) -> Result<(), DownloadError> {
            *self.destination.lock().unwrap() = Some(dest.to_owned());
            fs::write(dest, b"incomplete zip").unwrap();

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                assert_eq!(
                    fs::metadata(dest.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
            }

            if self.interrupted {
                return Err(DownloadError::Write {
                    path: dest.to_owned(),
                    source: io::Error::other("interrupted download"),
                });
            }

            Ok(())
        }
    }

    #[tokio::test]
    async fn failed_downloads_and_invalid_archives_clean_up_the_private_directory() {
        for interrupted in [true, false] {
            let downloader = FailedDownload {
                destination: Default::default(),
                interrupted,
            };

            let result = apply(&downloader, "unused").await;

            assert!(if interrupted {
                matches!(result, Err(UpdateError::Download(_)))
            } else {
                matches!(result, Err(UpdateError::Zip(_)))
            });

            let destination = downloader.destination.lock().unwrap().clone().unwrap();

            assert_eq!(destination.file_name().unwrap(), "bundle.zip");
            assert!(!destination.parent().unwrap().exists());
        }
    }

    #[cfg(unix)]
    fn script(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("probe");
        fs::write(&path, body).unwrap();
        set_executable(&path).unwrap();

        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn version_probe_requires_a_successful_matching_version() {
        let tmp = TempDir::new().unwrap();
        let path = script(tmp.path(), "#!/bin/sh\necho 'htp-agent 0.2.0'\n");

        validate_binary(&path, "0.2.0", PROBE_TIMEOUT)
            .await
            .unwrap();

        let error = validate_binary(&path, "0.3.0", PROBE_TIMEOUT)
            .await
            .unwrap_err();

        assert!(matches!(error, UpdateError::InvalidVersion { .. }));

        let path = script(tmp.path(), "#!/bin/sh\necho 'htp-agent 0.2.0'\nexit 1\n");

        let error = validate_binary(&path, "0.2.0", PROBE_TIMEOUT)
            .await
            .unwrap_err();

        assert!(matches!(error, UpdateError::InvalidVersion { .. }));

        let path = script(tmp.path(), "#!/nonexistent/htp-test-interpreter\n");

        let error = validate_binary(&path, "0.2.0", PROBE_TIMEOUT)
            .await
            .unwrap_err();

        assert!(matches!(error, UpdateError::Probe(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn version_probe_times_out() {
        let tmp = TempDir::new().unwrap();
        // exec makes sleep the direct child, so kill_on_drop kills it too.
        let path = script(tmp.path(), "#!/bin/sh\nexec sleep 60\n");

        let error = validate_binary(&path, "0.2.0", Duration::from_millis(50))
            .await
            .unwrap_err();

        assert!(matches!(error, UpdateError::ProbeTimeout));
    }

    #[test]
    fn replacement_errors_restore_the_recorded_path() {
        for relocate_first in [false, true] {
            let tmp = TempDir::new().unwrap();
            let exe = tmp.path().join("agent");
            fs::write(&exe, b"previous executable").unwrap();

            let zip = build_bundle(tmp.path(), &newer_version());
            let prepared = prepare_from_zip(&zip, tmp.path(), "x86_64-unknown-linux-musl")
                .unwrap()
                .unwrap();
            let stage_dir = prepared.directory.path().to_owned();

            let error = replace_and_restart(
                &exe,
                prepared,
                |_| {
                    if relocate_first {
                        // self-replace can move the old Windows executable
                        // before a later copy or rename fails.
                        fs::rename(&exe, tmp.path().join("relocated"))?;
                    }

                    Err(io::Error::other("replacement failed"))
                },
                |_| panic!("must not restart after a failed replacement"),
            )
            .unwrap_err();

            assert!(matches!(error, UpdateError::Replace(_)));
            assert_eq!(fs::read(&exe).unwrap(), b"previous executable");
            assert!(!stage_dir.exists());
        }
    }

    #[cfg(unix)]
    fn executable_bundle(dir: &Path, binary: &[u8]) -> PathBuf {
        let path = dir.join("bundle.zip");
        let mut zip = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        let manifest = serde_json::json!({
            "version": newer_version(),
            "binaries": [{"path": "htp-agent", "triples": [agent_target()]}],
        });
        zip.start_file("manifest.json", options).unwrap();
        zip.write_all(manifest.to_string().as_bytes()).unwrap();
        zip.start_file("htp-agent", options).unwrap();
        zip.write_all(binary).unwrap();
        zip.finish().unwrap();

        path
    }

    #[cfg(unix)]
    struct CopyDownload(PathBuf);

    #[cfg(unix)]
    impl Downloader for CopyDownload {
        async fn download(&self, _: &str, dest: &Path) -> Result<(), DownloadError> {
            fs::copy(&self.0, dest).unwrap();

            Ok(())
        }
    }

    // This test only performs updates when invoked in a disposable copy of the
    // test executable. The parent below checks both its bytes and restart args.
    #[cfg(unix)]
    #[test]
    fn update_child() {
        let Some(root) = std::env::var_os("HTP_UPDATE_TEST_ROOT") else {
            return;
        };

        let root = PathBuf::from(root).canonicalize().unwrap();
        let exe = std::env::current_exe().unwrap().canonicalize().unwrap();

        assert_eq!(exe, root.join("agent"));

        let original = fs::read(&exe).unwrap();
        let scenario = std::env::var("HTP_UPDATE_TEST_SCENARIO").unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();

        let result = if scenario == "restart-error" {
            let prepared = prepare_from_zip(&root.join("bundle.zip"), &root, agent_target())
                .unwrap()
                .unwrap();

            runtime
                .block_on(validate_binary(
                    &prepared.path,
                    &prepared.version,
                    PROBE_TIMEOUT,
                ))
                .unwrap();

            replace_and_restart(
                &exe,
                prepared,
                |path| self_replace::self_replace(path),
                |path| {
                    // Force an actual exec failure after self-replace succeeded.
                    fs::remove_file(path).unwrap();

                    restart(path)
                },
            )
        } else {
            runtime.block_on(apply(&CopyDownload(root.join("bundle.zip")), "unused"))
        };

        match scenario.as_str() {
            "invalid" => assert!(matches!(result, Err(UpdateError::Probe(_)))),
            "wrong-version" => assert!(matches!(result, Err(UpdateError::InvalidVersion { .. }))),
            "restart-error" => assert!(matches!(result, Err(UpdateError::ReExec(_)))),
            _ => panic!("a successful update must exec without returning: {result:?}"),
        }

        assert_eq!(fs::read(exe).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn updates_and_failed_restarts_in_disposable_processes() {
        let original = std::env::current_exe().unwrap();
        // The staged binary must report the bundle's version for the probe to
        // pass, so echo the same upgrade version the manifest advertises.
        let new_binary = format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then\n  echo 'htp-agent {}'\nelse\n  printf '%s\\n' \"$@\" > \"$HTP_UPDATE_MARKER\"\nfi\n",
            newer_version()
        );
        let new_binary = new_binary.as_bytes();

        for scenario in ["success", "invalid", "wrong-version", "restart-error"] {
            let tmp = TempDir::new().unwrap();
            let exe = tmp.path().join("agent");
            fs::copy(&original, &exe).unwrap();

            let marker = tmp.path().join("restarted");
            let binary: &[u8] = match scenario {
                "invalid" => b"#!/nonexistent/htp-test-interpreter\n",
                "wrong-version" => b"#!/bin/sh\necho 'htp-agent 9.9.9'\n",
                _ => new_binary,
            };
            executable_bundle(tmp.path(), binary);

            let output = Command::new(&exe)
                .args(["--exact", "update::tests::update_child", "--nocapture"])
                .env("HTP_UPDATE_TEST_ROOT", tmp.path())
                .env("HTP_UPDATE_TEST_SCENARIO", scenario)
                .env("HTP_UPDATE_MARKER", &marker)
                .output()
                .unwrap();

            assert!(output.status.success(), "{scenario}: {output:?}");

            if scenario == "success" {
                assert_eq!(fs::read(&exe).unwrap(), new_binary);
                assert_eq!(
                    fs::read_to_string(marker).unwrap(),
                    "--exact\nupdate::tests::update_child\n--nocapture\n"
                );
            } else {
                assert_eq!(fs::read(&exe).unwrap(), fs::read(&original).unwrap());
                assert!(!marker.exists());
            }

            let expected_files = if scenario == "success" { 3 } else { 2 };

            assert_eq!(
                fs::read_dir(tmp.path()).unwrap().count(),
                expected_files,
                "temporary files left after {scenario}"
            );
        }
    }
}

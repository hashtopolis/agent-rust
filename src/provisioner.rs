//! Getting bytes onto disk which [`Client`] does not cover.

use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::archive::{self, ArchiveError};
use crate::client::{Client, ClientError};
use crate::config::Paths;
use crate::cracker::{AnyCracker, Cracker, CrackerKind, build_cracker};
use crate::download::{DownloadError, Downloader};
use crate::identity::{agent_type, agent_version};
use crate::model::{CheckClientVersionResponse, CrackerId, Preprocessor, ResolvedPreprocessor};
use crate::transport::Transport;
use crate::update;

#[derive(Debug, Error)]
pub enum ProvisionError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error(transparent)]
    Download(#[from] DownloadError),
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    #[error("filesystem error at {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("{file} is {actual} bytes, server announced {expected}")]
    SizeMismatch {
        file: String,
        expected: u64,
        actual: u64,
    },
    #[error("refusing task file name {file:?}: not a plain filename")]
    UnsafeFileName { file: String },
    #[error("no hashcat.osx in the cracker archive and cracker.hashcat_path is not set")]
    HashcatFallbackMissing,
    #[error("cracker.hashcat_path is not a usable hashcat binary or install: {}", path.display())]
    HashcatFallbackUnusable { path: PathBuf },
}

/// The agent lends its [`Client`] into each call so the auth token has a single
/// source of truth.
pub trait Provisioner<T: Transport> {
    /// Returning a built cracker rather than a path lets a fake provisioner hand
    /// the loop a fake cracker, keeping chunk dispatch testable.
    type Cracker: Cracker;

    async fn deletion_check(&self, client: &Client<T>) -> Result<(), ProvisionError>;

    async fn ensure_cracker(
        &self,
        client: &Client<T>,
        cracker_id: CrackerId,
    ) -> Result<Self::Cracker, ProvisionError>;

    async fn ensure_preprocessor(
        &self,
        client: &Client<T>,
        preprocessor: &Preprocessor,
    ) -> Result<ResolvedPreprocessor, ProvisionError>;

    async fn ensure_files(
        &self,
        client: &Client<T>,
        files: &[String],
        task_id: u64,
    ) -> Result<(), ProvisionError>;

    async fn ensure_hashlist(
        &self,
        client: &Client<T>,
        hashlist_id: u64,
    ) -> Result<(), ProvisionError>;

    async fn ensure_found(
        &self,
        client: &Client<T>,
        hashlist_id: u64,
        cracker_id: CrackerId,
    ) -> Result<(), ProvisionError>;

    async fn check_client_version(&self, client: &Client<T>) -> Result<(), ProvisionError>;
}

pub struct DiskProvisioner<D: Downloader> {
    paths: Paths,
    hashcat_fallback: Option<PathBuf>,
    downloader: D,
}

impl<D: Downloader> DiskProvisioner<D> {
    pub fn new(paths: Paths, hashcat_fallback: Option<PathBuf>, downloader: D) -> Self {
        Self {
            paths,
            hashcat_fallback,
            downloader,
        }
    }

    /// Resolve the configured fallback to a hashcat binary. Required since
    /// hashcat does not bundle an OSX binary in the official archive. `announced` is tried
    /// first when it points at a directory.
    async fn resolve_hashcat_fallback(&self, announced: &str) -> Result<PathBuf, ProvisionError> {
        let configured = self
            .hashcat_fallback
            .as_ref()
            .ok_or(ProvisionError::HashcatFallbackMissing)?;

        resolve_local_hashcat(configured, announced)
            .await
            .ok_or_else(|| ProvisionError::HashcatFallbackUnusable {
                path: configured.clone(),
            })
    }
}

/// Resolve a hashcat path: the file itself, or a known binary inside a directory.
async fn resolve_local_hashcat(path: &Path, announced: &str) -> Option<PathBuf> {
    let path = absolute(path.to_path_buf());
    let metadata = tokio::fs::metadata(&path).await.ok()?;

    if metadata.is_file() {
        return Some(path);
    }

    if metadata.is_dir() {
        for name in [announced, "hashcat", "hashcat.bin", "hashcat.osx"] {
            let candidate = path.join(name);
            if path_exists(&candidate).await {
                return Some(candidate);
            }
        }
    }

    None
}

impl<T: Transport, D: Downloader> Provisioner<T> for DiskProvisioner<D> {
    type Cracker = AnyCracker;

    async fn deletion_check(&self, client: &Client<T>) -> Result<(), ProvisionError> {
        let status = client.get_file_status().await?;

        for filename in &status.filenames {
            // Anything beyond a bare name could resolve outside the files
            // directory, so we refuse to act on it.
            if !is_plain_filename(filename) {
                tracing::warn!(file = %filename, "ignoring deletion request with a path in the file name");
                continue;
            }

            let path = self.paths.files.join(filename);

            if !path_exists(&path).await {
                continue;
            }

            tracing::info!(file = %filename, "deleting file as requested by server");

            // A wordlist archive leaves an extracted `.txt` behind, so the
            // sibling goes with the archive.
            if is_7z(&path) {
                let extracted = path.with_extension("txt");

                if path_exists(&extracted).await {
                    remove_file(&extracted).await;
                }
            }

            remove_file(&path).await;
        }

        Ok(())
    }

    /// Downloads and extracts the cracker on first use, then hands back a built
    /// backend pointing at the executable. The server names the backend
    /// (`hashcat` vs. a generic one) and the executable file within the archive.
    async fn ensure_cracker(
        &self,
        client: &Client<T>,
        cracker_id: CrackerId,
    ) -> Result<AnyCracker, ProvisionError> {
        let info = client.download_cracker(cracker_id).await?;

        // Absolute so the cracker still spawns once the run sets its cwd to this
        // directory: a relative program would otherwise be resolved a second time
        // against that cwd.
        let cracker_dir = absolute(self.paths.crackers.join(cracker_id.to_string()));

        if !cracker_dir.is_dir() {
            let archive = self.paths.crackers.join(format!("{cracker_id}.7z"));
            self.downloader.download(&info.url, &archive).await?;

            let extract_dir = cracker_dir.clone();
            let extract_archive = archive.clone();
            spawn_extract(&archive, move || {
                archive::extract_flattened(&extract_archive, &extract_dir)
            })
            .await?;

            let _ = tokio::fs::remove_file(&archive).await;
        }

        let is_hashcat = info.name.eq_ignore_ascii_case("hashcat");

        let mut binary_path = cracker_dir.join(&info.binary);

        // On macOS the archive ships no hashcat binary; fall back to a local one
        // when it is absent. The existence check still prefers an archived
        // `hashcat.osx` if present.
        if is_hashcat && cfg!(target_os = "macos") && !path_exists(&binary_path).await {
            binary_path = self.resolve_hashcat_fallback(&info.binary).await?;
        }

        make_executable(&binary_path).await?;

        let kind = if is_hashcat {
            CrackerKind::Hashcat
        } else {
            CrackerKind::Generic
        };

        Ok(build_cracker(
            kind,
            cracker_id,
            binary_path,
            self.paths.clone(),
        ))
    }

    /// Downloads and extracts the preprocessor on first use, then hands back the
    /// resolved binary path together with the skip/limit/keyspace flags the
    /// server announced. The command building and pipe execution live in the
    /// backend, which never sees the client that fetched this.
    async fn ensure_preprocessor(
        &self,
        client: &Client<T>,
        preprocessor: &Preprocessor,
    ) -> Result<ResolvedPreprocessor, ProvisionError> {
        let info = client.download_preprocessor(preprocessor.id).await?;

        // Absolute so the binary still spawns once the run sets its cwd to the
        // cracker (pipe) or preprocessor (keyspace) directory.
        let dir = absolute(self.paths.preprocessors.join(preprocessor.id.to_string()));

        if !dir.is_dir() {
            let archive = self
                .paths
                .preprocessors
                .join(format!("{}.7z", preprocessor.id));
            self.downloader.download(&info.url, &archive).await?;

            let extract_dir = dir.clone();
            let extract_archive = archive.clone();
            spawn_extract(&archive, move || {
                archive::extract_flattened(&extract_archive, &extract_dir)
            })
            .await?;

            let _ = tokio::fs::remove_file(&archive).await;
        }

        let binary_path = resolve_binary(&dir, &info.binary).await;
        make_executable(&binary_path).await?;

        Ok(ResolvedPreprocessor {
            command: preprocessor.command.clone(),
            binary_path,
            keyspace_command: info.keyspace_command,
            skip_command: info.skip_command,
            limit_command: info.limit_command,
        })
    }

    /// Fetches every task file that is not already present with the announced
    /// size, extracting `.7z` archives (wordlists) once downloaded.
    async fn ensure_files(
        &self,
        client: &Client<T>,
        files: &[String],
        task_id: u64,
    ) -> Result<(), ProvisionError> {
        for file in files {
            // The server names these files; a name carrying a path separator or
            // `..` would let `paths.files.join` land the download outside the
            // files directory (an absolute name replaces it outright), so refuse
            // anything that is not a bare filename before fetching it.
            if !is_plain_filename(file) {
                return Err(ProvisionError::UnsafeFileName { file: file.clone() });
            }

            let info = client.get_file(task_id, file).await?;

            let dest = self.paths.files.join(file);
            let extracted = dest.with_extension("txt");

            if file_has_size(&dest, info.filesize).await {
                tracing::debug!(file = %file, "already present with expected size; skipping");
                continue;
            }

            if path_exists(&extracted).await {
                tracing::debug!(file = %file, "extracted output already present; skipping");
                continue;
            }

            tracing::debug!(file = %file, url = %info.url, size = info.filesize, "downloading task file");
            self.downloader.download(&info.url, &dest).await?;

            let actual = file_size(&dest).await;

            if actual != info.filesize {
                return Err(ProvisionError::SizeMismatch {
                    file: file.clone(),
                    expected: info.filesize,
                    actual,
                });
            }

            if is_7z(&dest) && !path_exists(&extracted).await {
                let files_dir = self.paths.files.clone();
                let extract_archive = dest.clone();
                spawn_extract(&dest, move || {
                    archive::extract_into(&extract_archive, &files_dir)
                })
                .await?;
            }
        }

        Ok(())
    }

    /// The hashlist is re-fetched on every task change, so it is always written
    /// fresh rather than size-checked.
    async fn ensure_hashlist(
        &self,
        client: &Client<T>,
        hashlist_id: u64,
    ) -> Result<(), ProvisionError> {
        let info = client.get_hashlist(hashlist_id).await?;

        let dest = self.paths.hashlists.join(hashlist_id.to_string());
        self.downloader.download(&info.url, &dest).await?;

        Ok(())
    }

    /// The potfile lands in the cracker's own directory, which is where hashcat
    /// looks for it.
    async fn ensure_found(
        &self,
        _client: &Client<T>,
        _hashlist_id: u64,
        _cracker_id: CrackerId,
    ) -> Result<(), ProvisionError> {
        todo!("Not yet implemented")
    }

    async fn check_client_version(&self, client: &Client<T>) -> Result<(), ProvisionError> {
        match client
            .check_client_version(agent_version(), agent_type())
            .await?
        {
            CheckClientVersionResponse::UpToDate => {
                tracing::info!("client version is up to date")
            }
            CheckClientVersionResponse::NewVersion { url } => {
                tracing::info!(%url, "new client version available; updating");

                // On success the process re-execs and never returns here; a
                // failure must not stop the agent, so it is logged and swallowed.
                if let Err(error) = update::apply(&self.downloader, &url).await {
                    tracing::error!(%error, "self-update failed; staying on the current version");
                }
            }
        }

        Ok(())
    }
}

/// Run a blocking extraction off the async runtime. A panic in the extractor
/// surfaces as an [`io::Error`] against the archive rather than unwinding the
/// agent loop.
async fn spawn_extract(
    archive: &Path,
    extract: impl FnOnce() -> Result<(), ArchiveError> + Send + 'static,
) -> Result<(), ProvisionError> {
    let archive = archive.to_path_buf();

    tokio::task::spawn_blocking(extract)
        .await
        .map_err(|source| ProvisionError::Io {
            path: archive,
            source: io::Error::other(source),
        })??;

    Ok(())
}

/// Resolve the preprocessor executable inside its directory. The server sends a
/// base name (e.g. `pp.bin`); when that file is absent the archive ships a
/// bitness-suffixed variant instead (`pp64.bin`), so the agent inserts the host
/// bitness before the extension and falls back to that.
async fn resolve_binary(dir: &Path, executable: &str) -> PathBuf {
    let direct = dir.join(executable);

    if path_exists(&direct).await {
        return direct;
    }

    dir.join(with_bitness(executable))
}

/// Insert the host bitness before the file extension: `pp.bin` -> `pp64.bin`,
/// `pp` -> `pp64`.
fn with_bitness(name: &str) -> String {
    let bits = if cfg!(target_pointer_width = "64") {
        "64"
    } else {
        "32"
    };

    match name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}{bits}.{ext}"),
        None => format!("{name}{bits}"),
    }
}

/// Mark a freshly extracted cracker binary executable. Extraction does not
/// always preserve the archived mode bits, so the agent sets them itself.
async fn make_executable(path: &Path) -> Result<(), ProvisionError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = tokio::fs::metadata(path).await.map_err(io_at(path))?;

        let mode = metadata.permissions().mode();

        // Skip the chmod when the exec bits are already set. This keeps
        // symlinked binaries working: metadata() and set_permissions()
        // follow the link, so a link to a binary the agent does not own
        // (e.g. a Homebrew hashcat) would otherwise fail the
        // chmod with EPERM even though the target is already executable.
        if mode & 0o111 != 0o111 {
            let mut permissions = metadata.permissions();
            permissions.set_mode(mode | 0o111);

            tokio::fs::set_permissions(path, permissions)
                .await
                .map_err(io_at(path))?;
        }
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

async fn file_has_size(path: &Path, expected: u64) -> bool {
    matches!(tokio::fs::metadata(path).await, Ok(m) if m.len() == expected)
}

async fn file_size(path: &Path) -> u64 {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.len())
        .unwrap_or(0)
}

async fn path_exists(path: &Path) -> bool {
    tokio::fs::try_exists(path).await.unwrap_or(false)
}

/// A failed delete is logged rather than aborting the sweep: the next check
/// will retry, and one stuck file should not block the rest.
async fn remove_file(path: &Path) {
    if let Err(error) = tokio::fs::remove_file(path).await {
        tracing::warn!(path = %path.display(), %error, "failed to delete file");
    }
}

/// A bare file name with no separator or parent reference. This is what keeps a
/// server-supplied name from resolving outside the files directory. Both
/// separators are rejected regardless of platform, matching the reference agent.
fn is_plain_filename(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\']) && name != "." && name != ".."
}

fn is_7z(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("7z"))
}

/// Make `path` absolute without touching the filesystem, falling back to the
/// original on the (platform-specific) error paths.
fn absolute(path: PathBuf) -> PathBuf {
    std::path::absolute(&path).unwrap_or(path)
}

#[cfg(unix)]
fn io_at(path: &Path) -> impl FnOnce(io::Error) -> ProvisionError {
    let path = path.to_path_buf();

    move |source| ProvisionError::Io { path, source }
}

#[cfg(test)]
mod tests {
    use super::{
        DiskProvisioner, ProvisionError, Provisioner, absolute, is_plain_filename,
        resolve_local_hashcat, with_bitness,
    };
    use crate::client::Client;
    use crate::config::Paths;
    use crate::download::{DownloadError, Downloader};
    use crate::transport::{Transport, TransportError};

    use std::path::Path;

    use serde_json::Value;
    use tempfile::TempDir;

    #[test]
    fn bitness_is_inserted_before_the_extension() {
        let bits = if cfg!(target_pointer_width = "64") {
            "64"
        } else {
            "32"
        };

        assert_eq!(with_bitness("pp.bin"), format!("pp{bits}.bin"));
        assert_eq!(with_bitness("pp"), format!("pp{bits}"));
        assert_eq!(with_bitness("a.b.exe"), format!("a.b{bits}.exe"));
    }

    #[test]
    fn plain_names_are_accepted() {
        assert!(is_plain_filename("wordlist.7z"));
        assert!(is_plain_filename("rockyou.txt"));
    }

    #[test]
    fn names_that_could_escape_the_files_directory_are_rejected() {
        assert!(!is_plain_filename(""));
        assert!(!is_plain_filename("../secret"));
        assert!(!is_plain_filename("sub/dir.txt"));
        assert!(!is_plain_filename("sub\\dir.txt"));
        assert!(!is_plain_filename("/etc/passwd"));
        assert!(!is_plain_filename(".."));
    }

    #[tokio::test]
    async fn hashcat_fallback_resolves_a_file_path_directly() {
        let tmp = TempDir::new().unwrap();
        let bin = tmp.path().join("hashcat");
        tokio::fs::write(&bin, b"x").await.unwrap();

        let resolved = resolve_local_hashcat(&bin, "hashcat.osx").await.unwrap();

        assert_eq!(resolved, absolute(bin));
    }

    #[tokio::test]
    async fn hashcat_fallback_prefers_the_announced_name_inside_a_directory() {
        let tmp = TempDir::new().unwrap();
        tokio::fs::write(tmp.path().join("hashcat.osx"), b"x")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("hashcat.bin"), b"x")
            .await
            .unwrap();

        let resolved = resolve_local_hashcat(tmp.path(), "hashcat.osx")
            .await
            .unwrap();

        assert_eq!(resolved.file_name().unwrap(), "hashcat.osx");
    }

    #[tokio::test]
    async fn hashcat_fallback_falls_back_to_a_common_name_in_a_directory() {
        let tmp = TempDir::new().unwrap();
        tokio::fs::write(tmp.path().join("hashcat.bin"), b"x")
            .await
            .unwrap();

        let resolved = resolve_local_hashcat(tmp.path(), "hashcat.osx")
            .await
            .unwrap();

        assert_eq!(resolved.file_name().unwrap(), "hashcat.bin");
    }

    #[tokio::test]
    async fn hashcat_fallback_is_none_when_nothing_resolves() {
        let tmp = TempDir::new().unwrap();

        assert!(
            resolve_local_hashcat(tmp.path(), "hashcat.osx")
                .await
                .is_none()
        );
        assert!(
            resolve_local_hashcat(&tmp.path().join("nope"), "hashcat.osx")
                .await
                .is_none()
        );
    }

    /// A transport and downloader that fail the test if the guard ever lets a
    /// request or write through for a rejected name.
    struct PanicTransport;

    impl Transport for PanicTransport {
        async fn post_json(&self, _body: &Value) -> Result<Value, TransportError> {
            panic!("ensure_files must reject an unsafe name before contacting the server");
        }
    }

    struct PanicDownloader;

    impl Downloader for PanicDownloader {
        async fn download(&self, _url: &str, _dest: &Path) -> Result<(), DownloadError> {
            panic!("ensure_files must reject an unsafe name before downloading");
        }
    }

    fn paths_in(root: &Path) -> Paths {
        Paths {
            files: root.join("files"),
            crackers: root.join("crackers"),
            hashlists: root.join("hashlists"),
            preprocessors: root.join("preprocessors"),
            zaps: root.join("zaps"),
        }
    }

    #[tokio::test]
    async fn ensure_files_rejects_a_name_that_escapes_the_files_directory() {
        let tmp = TempDir::new().unwrap();
        let provisioner = DiskProvisioner::new(paths_in(tmp.path()), None, PanicDownloader);
        let client = Client::new(PanicTransport);

        for name in ["../evil", "/etc/cron.d/evil", "sub/evil", ".."] {
            let error = provisioner
                .ensure_files(&client, &[name.to_owned()], 1)
                .await
                .expect_err("an unsafe file name must be refused");

            assert!(
                matches!(&error, ProvisionError::UnsafeFileName { file } if file == name),
                "expected UnsafeFileName for {name:?}, got {error:?}"
            );
        }

        // Nothing should have been written to the files directory.
        assert!(!tmp.path().join("files").join("evil").exists());
    }
}

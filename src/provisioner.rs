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
use crate::model::{CheckClientVersionResponse, Preprocessor};
use crate::transport::Transport;

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
        cracker_id: u64,
    ) -> Result<Self::Cracker, ProvisionError>;

    async fn ensure_preprocessor(
        &self,
        client: &Client<T>,
        preprocessor: &Preprocessor,
    ) -> Result<(), ProvisionError>;

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
        cracker_id: u64,
    ) -> Result<(), ProvisionError>;

    async fn check_client_version(&self, client: &Client<T>) -> Result<(), ProvisionError>;
}

pub struct DiskProvisioner<D: Downloader> {
    paths: Paths,
    downloader: D,
}

impl<D: Downloader> DiskProvisioner<D> {
    pub fn new(paths: Paths, downloader: D) -> Self {
        Self { paths, downloader }
    }
}

impl<T: Transport, D: Downloader> Provisioner<T> for DiskProvisioner<D> {
    type Cracker = AnyCracker;

    async fn deletion_check(&self, client: &Client<T>) -> Result<(), ProvisionError> {
        let status = client.get_file_status().await?;

        tracing::info!(
            files = ?status.filenames,
            "server file status received; local pruning not yet implemented"
        );

        Ok(())
    }

    /// Downloads and extracts the cracker on first use, then hands back a built
    /// backend pointing at the executable. The server names the backend
    /// (`hashcat` vs. a generic one) and the executable file within the archive.
    async fn ensure_cracker(
        &self,
        client: &Client<T>,
        cracker_id: u64,
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

        let binary_path = cracker_dir.join(&info.binary);
        make_executable(&binary_path).await?;

        let kind = if info.name.eq_ignore_ascii_case("hashcat") {
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

    async fn ensure_preprocessor(
        &self,
        _client: &Client<T>,
        _preprocessor: &Preprocessor,
    ) -> Result<(), ProvisionError> {
        todo!("Not yet implemented")
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
        _cracker_id: u64,
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
                tracing::info!(%url, "new client version available; self-update not yet implemented")
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

/// Mark a freshly extracted cracker binary executable. Extraction does not
/// always preserve the archived mode bits, so the agent sets them itself.
async fn make_executable(path: &Path) -> Result<(), ProvisionError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let metadata = tokio::fs::metadata(path).await.map_err(io_at(path))?;

        let mut permissions = metadata.permissions();
        permissions.set_mode(permissions.mode() | 0o111);

        tokio::fs::set_permissions(path, permissions)
            .await
            .map_err(io_at(path))?;
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

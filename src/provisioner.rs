//! Getting bytes onto disk which [`Client`] does not cover.

use thiserror::Error;

use crate::client::{Client, ClientError};
use crate::config::Paths;
use crate::cracker::{AnyCracker, Cracker};
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

#[allow(dead_code)]
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

    async fn ensure_cracker(
        &self,
        _client: &Client<T>,
        _cracker_id: u64,
    ) -> Result<AnyCracker, ProvisionError> {
        todo!("Not yet implemented")
    }

    async fn ensure_preprocessor(
        &self,
        _client: &Client<T>,
        _preprocessor: &Preprocessor,
    ) -> Result<(), ProvisionError> {
        todo!("Not yet implemented")
    }

    async fn ensure_files(
        &self,
        _client: &Client<T>,
        _files: &[String],
        _task_id: u64,
    ) -> Result<(), ProvisionError> {
        todo!("Not yet implemented")
    }

    async fn ensure_hashlist(
        &self,
        _client: &Client<T>,
        _hashlist_id: u64,
    ) -> Result<(), ProvisionError> {
        todo!("Not yet implemented")
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

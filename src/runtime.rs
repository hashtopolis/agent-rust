//! Construction of one complete, immutable agent generation.
//!
//! A [`RuntimeFactory`] prepares services from a configuration snapshot without
//! touching the currently active agent. The supervisor publishes the returned
//! runtime only after construction, connection probing, login and information
//! reporting have all succeeded.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use thiserror::Error;

use crate::agent::{Agent, AgentError};
use crate::config::{Config, ConfigError, Paths, Server, Settings};
use crate::download::HttpDownloader;
use crate::provisioner::DiskProvisioner;
use crate::transport::{HttpTransport, Transport};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy)]
enum HttpClientPolicy {
    Api,
    ServerDownload,
    ExternalDownload,
}

impl HttpClientPolicy {
    fn timeout(self) -> Option<Duration> {
        match self {
            Self::Api => Some(REQUEST_TIMEOUT),
            Self::ServerDownload | Self::ExternalDownload => None,
        }
    }

    fn includes_client_identity(self) -> bool {
        matches!(self, Self::Api | Self::ServerDownload)
    }
}

/// A replacement runtime and the matching config, including any token or UUID
/// which bootstrap persisted while preparing it.
pub struct PreparedRuntime<T, P>
where
    T: Transport,
    P: crate::provisioner::Provisioner<T>,
{
    pub agent: Agent<T, P>,
    pub config: Config,
}

pub trait RuntimeFactory {
    type Transport: Transport;
    type Provisioner: crate::provisioner::Provisioner<Self::Transport>;

    /// Build only the provisioner (and its download clients) for a settings
    /// snapshot, ensuring the target directories exist. Purely local: no
    /// transport, no network. This is the `RebuildTask` reload path, where the
    /// live client and session are kept and only the provisioner is replaced.
    fn build_provisioner(
        &self,
        settings: &Settings,
        url: &str,
    ) -> Result<Self::Provisioner, RuntimeBuildError>;

    async fn prepare(
        &self,
        config: Config,
        mode: RuntimeBuildMode,
    ) -> Result<PreparedRuntime<Self::Transport, Self::Provisioner>, RuntimeBuildError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBuildMode {
    Initial,
    Replacement,
}

#[derive(Debug, Error)]
pub enum RuntimeBuildError {
    #[error(transparent)]
    Agent(#[from] AgentError),

    #[error("building the HTTP client: {0}")]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Transport(#[from] crate::transport::TransportError),

    #[error("runtime preparation failed: {0}")]
    Unavailable(String),

    #[error("reading client certificate {}: {source}", path.display())]
    ReadCertificate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HttpRuntimeFactory;

impl RuntimeFactory for HttpRuntimeFactory {
    type Transport = HttpTransport;
    type Provisioner = DiskProvisioner<HttpDownloader>;

    fn build_provisioner(
        &self,
        settings: &Settings,
        url: &str,
    ) -> Result<Self::Provisioner, RuntimeBuildError> {
        let server = settings.server.clone();
        let paths = settings.paths.clone();
        let hashcat_path = settings.cracker.hashcat_path.clone();

        if hashcat_path.is_some() && !cfg!(target_os = "macos") {
            tracing::warn!("hashcat_path is only used on macOS; ignoring it on this platform");
        }

        create_download_dirs(&paths)?;

        let server_download_client = build_http_client(&server, HttpClientPolicy::ServerDownload)?;
        let external_download_client =
            build_http_client(&server, HttpClientPolicy::ExternalDownload)?;
        let mut downloader =
            HttpDownloader::with_clients(server_download_client, external_download_client, url);

        if let (Some(username), Some(password)) = (server.auth_user, server.auth_password) {
            downloader = downloader.with_basic_auth(username, password);
        }

        Ok(DiskProvisioner::new(paths, hashcat_path, downloader))
    }

    async fn prepare(
        &self,
        config: Config,
        mode: RuntimeBuildMode,
    ) -> Result<PreparedRuntime<Self::Transport, Self::Provisioner>, RuntimeBuildError> {
        let url = config.require_url()?.to_owned();
        let transport = self.build_transport(&config)?;
        let provisioner = self.build_provisioner(config.settings(), &url)?;

        let agent = match mode {
            RuntimeBuildMode::Initial => Agent::bootstrap(transport, config, provisioner).await?,
            RuntimeBuildMode::Replacement => {
                Agent::bootstrap_once(transport, config, provisioner).await?
            }
        };
        let config = agent.config().clone();

        Ok(PreparedRuntime { agent, config })
    }
}

impl HttpRuntimeFactory {
    pub fn build_transport(&self, config: &Config) -> Result<HttpTransport, RuntimeBuildError> {
        let url = config.require_url()?;
        let server = &config.settings().server;
        let http = build_http_client(server, HttpClientPolicy::Api)?;
        let mut transport = HttpTransport::with_client(url, http)?;

        if let (Some(username), Some(password)) =
            (server.auth_user.clone(), server.auth_password.clone())
        {
            transport = transport.with_basic_auth(username, password);
        }

        Ok(transport)
    }
}

/// Create the on-disk layout the provisioner and backends write into. Runs
/// whenever a generation's provisioner is built, so a `paths` change creates the
/// new directories before the next task provisions into them.
fn create_download_dirs(paths: &Paths) -> Result<(), ConfigError> {
    // Old python agent did not create the zaps path
    for dir in [
        &paths.files,
        &paths.crackers,
        &paths.hashlists,
        &paths.preprocessors,
        &paths.zaps,
    ] {
        std::fs::create_dir_all(dir).map_err(|source| ConfigError::CreateDir {
            path: dir.clone(),
            source,
        })?;
    }

    Ok(())
}

fn build_http_client(
    server: &Server,
    policy: HttpClientPolicy,
) -> Result<reqwest::Client, RuntimeBuildError> {
    let mut builder = reqwest::Client::builder();

    if let Some(timeout) = policy.timeout() {
        builder = builder.timeout(timeout);
    }

    if let Some(proxy) = server.proxy.as_deref() {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }

    if policy.includes_client_identity()
        && let Some(path) = &server.cert
    {
        let pem = fs::read(path).map_err(|source| RuntimeBuildError::ReadCertificate {
            path: path.clone(),
            source,
        })?;
        let identity = reqwest::Identity::from_pem(&pem)?;
        builder = builder.identity(identity);
    }

    Ok(builder.build()?)
}

//! Startup handshake and the state the work loop runs on.

mod progress;
mod run;

pub use run::{LoopState, Step};

use thiserror::Error;
use tokio::time::sleep;

use crate::client::{Client, ClientError};
use crate::config::{Config, ConfigError};
use crate::identity::client_signature;
use crate::provisioner::Provisioner;
use crate::sysinfo;
use crate::transport::Transport;

use run::RETRY_DELAY;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("server error: {0}")]
    Client(ClientError),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Cracker(#[from] crate::cracker::CrackerError),

    #[error("token rejected by server; fix the token in state.json or re-register the agent")]
    TokenRejected,
}

impl AgentError {
    /// A rejected token is fatal: registration consumes the voucher, so the
    /// agent cannot silently obtain a new one.
    fn client(error: ClientError) -> Self {
        if error.is_invalid_token() {
            AgentError::TokenRejected
        } else {
            AgentError::Client(error)
        }
    }
}

/// Run a client call, optionally retrying transport failures. A rejected token
/// is always fatal and any other server error propagates. `call` manufactures a
/// fresh future for each attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapPolicy {
    RetryTransport,
    SingleAttempt,
}

impl BootstrapPolicy {
    fn retries_transport(self) -> bool {
        matches!(self, Self::RetryTransport)
    }
}

async fn call_with_retry_policy<T, Fut>(
    policy: BootstrapPolicy,
    mut call: impl FnMut() -> Fut,
) -> Result<T, AgentError>
where
    Fut: Future<Output = Result<T, ClientError>>,
{
    loop {
        match call().await {
            Ok(value) => return Ok(value),
            Err(error) if error.is_invalid_token() => return Err(AgentError::TokenRejected),
            Err(error @ ClientError::Transport { .. }) if policy.retries_transport() => {
                tracing::warn!(%error, "request failed; retrying");
                sleep(RETRY_DELAY).await;
            }
            Err(error) => return Err(AgentError::client(error)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub timeout: i64,
    pub multicast_enabled: bool,
    pub server_version: String,
}

pub struct Agent<T: Transport, P: Provisioner<T>> {
    client: Client<T>,
    config: Config,
    provisioner: P,
    #[allow(dead_code)]
    session: Session,
}

impl<T: Transport, P: Provisioner<T>> Agent<T, P> {
    pub fn new(client: Client<T>, config: Config, provisioner: P, session: Session) -> Self {
        Self {
            client,
            config,
            provisioner,
            session,
        }
    }

    /// The immutable configuration snapshot for this agent generation.
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub(crate) fn replace_config(&mut self, config: Config) {
        self.config = config;
    }

    /// Swap the provisioner for a rebuilt one while keeping the live client and
    /// session. Used to activate a `RebuildTask` reload without re-logging in.
    pub(crate) fn replace_provisioner(&mut self, provisioner: P) {
        self.provisioner = provisioner;
    }

    pub async fn bootstrap(
        transport: T,
        config: Config,
        provisioner: P,
    ) -> Result<Self, AgentError> {
        Self::bootstrap_with_policy(
            transport,
            config,
            provisioner,
            BootstrapPolicy::RetryTransport,
        )
        .await
    }

    /// Prepare a replacement generation with a single attempt per request. A
    /// supervisor must be able to retain the active generation when a candidate
    /// endpoint is unavailable instead of blocking forever in bootstrap retry.
    pub async fn bootstrap_once(
        transport: T,
        config: Config,
        provisioner: P,
    ) -> Result<Self, AgentError> {
        Self::bootstrap_with_policy(
            transport,
            config,
            provisioner,
            BootstrapPolicy::SingleAttempt,
        )
        .await
    }

    async fn bootstrap_with_policy(
        transport: T,
        mut config: Config,
        provisioner: P,
        policy: BootstrapPolicy,
    ) -> Result<Self, AgentError> {
        let token = resolve_token(&transport, &mut config, policy).await?;
        let client = Client::with_token(transport, token);

        let login_result =
            call_with_retry_policy(policy, || client.login(client_signature())).await?;
        tracing::info!(
            server_version = %login_result.server_version,
            timeout = login_result.timeout,
            "login successful"
        );

        // Shutdown on failure (exit process)

        let uuid = config.uuid_or_create()?.to_string();
        let settings = config.settings();

        let devices = sysinfo::collect_devices(
            settings.agent.devices.as_deref(),
            settings.behavior.cpu_only,
        );

        call_with_retry_policy(policy, || client.update_information(&uuid, &devices)).await?;

        let session = Session {
            timeout: login_result.timeout,
            multicast_enabled: login_result.multicast_enabled,
            server_version: login_result.server_version,
        };

        Ok(Self::new(client, config, provisioner, session))
    }

    pub async fn deregister(self) -> Result<(), AgentError> {
        deregister(&self.client, &self.config).await
    }
}

async fn resolve_token<T: Transport>(
    transport: &T,
    config: &mut Config,
    policy: BootstrapPolicy,
) -> Result<String, AgentError> {
    let probe = Client::new(transport);
    call_with_retry_policy(policy, || probe.test_connection()).await?;

    if let Some(token) = config.token() {
        tracing::info!("using stored token");

        return Ok(token.to_string());
    }

    let voucher = config.require_voucher()?.to_string();
    let name = config
        .settings()
        .agent
        .name
        .clone()
        .unwrap_or_else(sysinfo::hostname);
    let cpu_only = config.settings().behavior.cpu_only.then_some(true);

    let registered = call_with_retry_policy(policy, || {
        probe.register(voucher.as_str(), name.as_str(), cpu_only)
    })
    .await?;

    config.set_token(registered.token.as_str())?;
    tracing::info!("registered successfully");

    Ok(registered.token)
}

pub async fn deregister<T: Transport>(
    client: &Client<T>,
    config: &Config,
) -> Result<(), AgentError> {
    client.deregister().await.map_err(AgentError::client)?;
    config.remove_state_file()?;
    tracing::info!("deregistered; removed {}", config.state_path().display());

    Ok(())
}

//! Lifecycle supervision and transactional configuration handover.
//!
//! The active [`Agent`] owns one immutable configuration generation. Before
//! starting another loop iteration, the supervisor reads a candidate from disk
//! and activates it according to its [`ReloadImpact`]:
//!
//! - `Live` — settings-only; swap the config on the running agent, keeping its
//!   client, session, provisioner and in-flight loop state.
//! - `RebuildTask` — same server, changed paths/cracker; rebuild the provisioner
//!   locally and swap it in without re-authenticating, dropping the in-flight
//!   task so the next assignment re-provisions.
//! - `Reconnect` — server or agent identity changed; ask the [`RuntimeFactory`]
//!   to prepare and authenticate a complete replacement, published only on
//!   success.
//!
//! Since one agent tick includes a complete chunk run, the boundary between
//! ticks is the universal reload safe point.

use thiserror::Error;
use tokio::time::sleep;

use crate::agent::{Agent, AgentError, LoopState, Step};
use crate::config::{Config, ConfigCandidate, ConfigError, ReloadImpact};
use crate::runtime::{RuntimeBuildError, RuntimeBuildMode, RuntimeFactory};

pub struct Supervisor<F: RuntimeFactory> {
    factory: F,
    agent: Agent<F::Transport, F::Provisioner>,
    config: Config,
    loop_state: LoopState,
    generation: u64,
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error(transparent)]
    Runtime(#[from] RuntimeBuildError),

    #[error(transparent)]
    Agent(#[from] AgentError),
}

impl<F: RuntimeFactory> Supervisor<F> {
    pub async fn bootstrap(factory: F, config: Config) -> Result<Self, SupervisorError> {
        let prepared = factory.prepare(config, RuntimeBuildMode::Initial).await?;

        Ok(Self {
            factory,
            agent: prepared.agent,
            config: prepared.config,
            loop_state: LoopState::new(),
            generation: 1,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Poll for a candidate and activate it at the tick boundary. Live changes
    /// retain loop state; other changes prepare a complete replacement first.
    pub async fn tick(&mut self) -> Result<Step, SupervisorError> {
        self.try_reload().await;
        Ok(self.agent.tick(&mut self.loop_state).await?)
    }

    pub async fn run(&mut self) -> Result<(), SupervisorError> {
        tracing::debug!(
            generation = self.generation,
            "entering supervised agent loop"
        );

        let mut shutdown = Box::pin(shutdown_signal());

        loop {
            let step = tokio::select! {
                _ = &mut shutdown => Step::Shutdown,
                result = self.tick() => result?,
            };

            match step {
                Step::Continue => {}
                Step::Sleep(delay) => {
                    tokio::select! {
                        _ = &mut shutdown => return Ok(()),
                        _ = sleep(delay) => {}
                    }
                }
                Step::Shutdown => return Ok(()),
            }
        }
    }

    async fn try_reload(&mut self) {
        let candidate = match self.config.load_candidate() {
            Ok(Some(candidate)) => candidate,
            Ok(None) => return,
            Err(error) => {
                log_candidate_error(&error);
                return;
            }
        };

        let impact = candidate.impact();
        let next_generation = self.generation.saturating_add(1);

        match impact {
            // Settings-only: swap the config on the running agent, keeping its
            // client, session, provisioner and in-flight loop state.
            ReloadImpact::Live => {
                self.config.commit_candidate(candidate);
                self.agent.replace_config(self.config.clone());
                self.generation = next_generation;

                tracing::info!(
                    generation = self.generation,
                    ?impact,
                    "activated settings generation"
                );
            }

            // Same server, changed paths/cracker: rebuild the provisioner
            // locally and swap it in without re-authenticating. The in-flight
            // task is dropped so the next assignment re-provisions.
            ReloadImpact::RebuildTask => self.rebuild_task(candidate, next_generation),

            // Server/agent identity changed: prepare and authenticate a complete
            // replacement generation before publishing it.
            ReloadImpact::Reconnect => self.reconnect(candidate, next_generation).await,
        }
    }

    /// Rebuild the provisioner off to the side, then swap it onto the live
    /// agent. Building is fallible (proxy, cert, directory creation) and runs
    /// before any mutation, so a failure retains the active generation. Reuses
    /// the current url because a `RebuildTask` change leaves the server untouched.
    fn rebuild_task(&mut self, candidate: ConfigCandidate, next_generation: u64) {
        let impact = candidate.impact();

        let url = match self.config.require_url() {
            Ok(url) => url.to_owned(),
            Err(error) => {
                log_candidate_error(&error);
                return;
            }
        };

        let provisioner = match self.factory.build_provisioner(candidate.settings(), &url) {
            Ok(provisioner) => provisioner,
            Err(error) => {
                tracing::warn!(
                    generation = next_generation,
                    ?impact,
                    %error,
                    "rebuilt services rejected; retaining the active generation"
                );
                return;
            }
        };

        self.config.commit_candidate(candidate);
        self.agent.replace_provisioner(provisioner);
        self.agent.replace_config(self.config.clone());
        self.loop_state = LoopState::new();
        self.generation = next_generation;

        tracing::info!(
            generation = self.generation,
            ?impact,
            "activated rebuilt services generation"
        );
    }

    async fn reconnect(&mut self, candidate: ConfigCandidate, next_generation: u64) {
        let impact = candidate.impact();
        let server_url_changed =
            self.config.settings().server.url != candidate.settings().server.url;
        let mut candidate_config = self.config.with_candidate(&candidate);

        if server_url_changed {
            candidate_config.clear_token();
        }

        tracing::info!(
            generation = next_generation,
            ?impact,
            "preparing replacement agent generation"
        );

        let mut prepared = match self
            .factory
            .prepare(candidate_config, RuntimeBuildMode::Replacement)
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::warn!(
                    generation = next_generation,
                    ?impact,
                    %error,
                    "replacement runtime rejected; retaining the active generation"
                );
                return;
            }
        };

        if let Err(error) = prepared.config.persist_prepared_state() {
            tracing::warn!(
                generation = next_generation,
                ?impact,
                %error,
                "replacement state could not be committed; retaining the active generation"
            );
            return;
        }

        prepared.agent.replace_config(prepared.config.clone());

        self.agent = prepared.agent;
        self.config = prepared.config;
        self.loop_state = LoopState::new();
        self.generation = next_generation;

        tracing::info!(
            generation = self.generation,
            ?impact,
            "activated replacement agent generation"
        );
    }
}

fn log_candidate_error(error: &ConfigError) {
    tracing::warn!(%error, "settings candidate is invalid; retaining the active generation");
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!(%error, "cannot listen for SIGTERM; using Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }

    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::agent::Session;
    use crate::client::Client;
    use crate::config::Overrides;
    use crate::cracker::{ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressSink};
    use crate::model::{Chunk, Preprocessor, ResolvedPreprocessor, TaskAssignment};
    use crate::provisioner::{ProvisionError, Provisioner};
    use crate::runtime::{PreparedRuntime, RuntimeBuildMode};
    use crate::transport::{Transport, TransportError};

    #[derive(Clone)]
    struct IdleTransport;

    impl Transport for IdleTransport {
        async fn post_json(&self, body: &Value) -> Result<Value, TransportError> {
            assert_eq!(body["action"], "getTask");
            Ok(json!({
                "action": "getTask",
                "response": "SUCCESS",
                "taskId": null
            }))
        }
    }

    #[derive(Clone)]
    struct NoopCracker;

    impl Cracker for NoopCracker {
        async fn measure_keyspace(
            &self,
            _task: &TaskAssignment,
            _preprocessor: Option<&ResolvedPreprocessor>,
        ) -> Result<Option<u64>, CrackerError> {
            Ok(None)
        }

        async fn run_benchmark(
            &self,
            _task: &TaskAssignment,
            _preprocessor: Option<&ResolvedPreprocessor>,
        ) -> Result<Option<String>, CrackerError> {
            Ok(None)
        }

        async fn run_chunk<S: ProgressSink>(
            &self,
            _task: &TaskAssignment,
            _chunk: Chunk,
            _preprocessor: Option<&ResolvedPreprocessor>,
            _sink: &S,
        ) -> Result<ChunkOutcome, CrackerError> {
            Ok(ChunkOutcome::default())
        }

        async fn run_health_check(
            &self,
            _attack: &str,
            _hashlist_alias: &str,
            _hashes: &[String],
        ) -> Result<HealthCheckOutcome, CrackerError> {
            Ok(HealthCheckOutcome::default())
        }
    }

    #[derive(Clone)]
    struct NoopProvisioner;

    impl<T: Transport> Provisioner<T> for NoopProvisioner {
        type Cracker = NoopCracker;

        async fn deletion_check(&self, _client: &Client<T>) -> Result<(), ProvisionError> {
            Ok(())
        }

        async fn ensure_cracker(
            &self,
            _client: &Client<T>,
            _cracker_id: u64,
        ) -> Result<Self::Cracker, ProvisionError> {
            Ok(NoopCracker)
        }

        async fn ensure_preprocessor(
            &self,
            _client: &Client<T>,
            preprocessor: &Preprocessor,
        ) -> Result<ResolvedPreprocessor, ProvisionError> {
            Ok(ResolvedPreprocessor {
                command: preprocessor.command.clone(),
                binary_path: PathBuf::from("noop"),
                keyspace_command: None,
                skip_command: None,
                limit_command: None,
            })
        }

        async fn ensure_files(
            &self,
            _client: &Client<T>,
            _files: &[String],
            _task_id: u64,
        ) -> Result<(), ProvisionError> {
            Ok(())
        }

        async fn ensure_hashlist(
            &self,
            _client: &Client<T>,
            _hashlist_id: u64,
        ) -> Result<(), ProvisionError> {
            Ok(())
        }

        async fn ensure_found(
            &self,
            _client: &Client<T>,
            _hashlist_id: u64,
            _cracker_id: u64,
        ) -> Result<(), ProvisionError> {
            Ok(())
        }

        async fn check_client_version(&self, _client: &Client<T>) -> Result<(), ProvisionError> {
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeFactory {
        builds: Arc<Mutex<Vec<(RuntimeBuildMode, String)>>>,
        provisioner_builds: Arc<Mutex<Vec<String>>>,
    }

    impl FakeFactory {
        fn builds(&self) -> Vec<(RuntimeBuildMode, String)> {
            self.builds.lock().unwrap().clone()
        }

        fn provisioner_builds(&self) -> Vec<String> {
            self.provisioner_builds.lock().unwrap().clone()
        }
    }

    impl RuntimeFactory for FakeFactory {
        type Transport = IdleTransport;
        type Provisioner = NoopProvisioner;

        fn build_provisioner(
            &self,
            settings: &crate::config::Settings,
            url: &str,
        ) -> Result<Self::Provisioner, RuntimeBuildError> {
            self.provisioner_builds.lock().unwrap().push(url.to_owned());

            if settings
                .paths
                .files
                .to_string_lossy()
                .contains("unavailable")
            {
                return Err(RuntimeBuildError::Unavailable(url.to_owned()));
            }

            Ok(NoopProvisioner)
        }

        async fn prepare(
            &self,
            mut config: Config,
            mode: RuntimeBuildMode,
        ) -> Result<PreparedRuntime<Self::Transport, Self::Provisioner>, RuntimeBuildError>
        {
            let url = config.require_url()?.to_owned();
            self.builds.lock().unwrap().push((mode, url.clone()));

            if url.contains("unavailable") {
                return Err(RuntimeBuildError::Unavailable(url));
            }

            if config.token().is_none() {
                config.set_token("replacement-token")?;
            }

            let agent = Agent::new(
                Client::with_token(IdleTransport, "token"),
                config.clone(),
                NoopProvisioner,
                Session {
                    timeout: 30,
                    multicast_enabled: false,
                    server_version: "test".to_string(),
                },
            );

            Ok(PreparedRuntime { agent, config })
        }
    }

    struct Fixture {
        _dir: TempDir,
        settings: PathBuf,
        state: PathBuf,
    }

    impl Fixture {
        fn new(url: &str) -> Self {
            let dir = TempDir::new().unwrap();
            let settings = dir.path().join("config.json");
            let state = dir.path().join("state.json");
            std::fs::write(&state, json!({ "token": "token" }).to_string()).unwrap();

            let fixture = Self {
                _dir: dir,
                settings,
                state,
            };
            fixture.write_url(url);
            fixture
        }

        fn write_url(&self, url: &str) {
            std::fs::write(
                &self.settings,
                json!({ "server": { "url": url } }).to_string(),
            )
            .unwrap();
        }

        fn write_settings(&self, value: Value) {
            std::fs::write(&self.settings, value.to_string()).unwrap();
        }

        fn write_url_with_voucher(&self, url: &str) {
            std::fs::write(
                &self.settings,
                json!({ "server": { "url": url, "voucher": "voucher" } }).to_string(),
            )
            .unwrap();
        }

        fn write_live_settings(&self, url: &str) {
            std::fs::write(
                &self.settings,
                json!({
                    "server": { "url": url },
                    "behavior": { "disable_update": true }
                })
                .to_string(),
            )
            .unwrap();
        }

        fn config(&self) -> Config {
            Config::load(&self.settings, &self.state, Overrides::default()).unwrap()
        }
    }

    #[tokio::test]
    async fn activates_a_prepared_generation_before_the_next_tick() {
        let fixture = Fixture::new("https://old.example/api/server.php");
        let factory = FakeFactory::default();
        let mut supervisor = Supervisor::bootstrap(factory.clone(), fixture.config())
            .await
            .unwrap();

        fixture.write_url_with_voucher("https://new.example/api/server.php");
        let step = supervisor.tick().await.unwrap();

        assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
        assert_eq!(supervisor.generation(), 2);
        assert_eq!(
            supervisor.config().require_url().unwrap(),
            "https://new.example/api/server.php"
        );
        assert_eq!(
            factory.builds(),
            vec![
                (
                    RuntimeBuildMode::Initial,
                    "https://old.example/api/server.php".to_string()
                ),
                (
                    RuntimeBuildMode::Replacement,
                    "https://new.example/api/server.php".to_string()
                )
            ]
        );
        assert_eq!(
            Config::load(&fixture.settings, &fixture.state, Overrides::default())
                .unwrap()
                .token(),
            Some("replacement-token")
        );
    }

    #[tokio::test]
    async fn failed_preparation_retains_the_active_generation() {
        let fixture = Fixture::new("https://old.example/api/server.php");
        let factory = FakeFactory::default();
        let mut supervisor = Supervisor::bootstrap(factory.clone(), fixture.config())
            .await
            .unwrap();

        fixture.write_url_with_voucher("https://unavailable.example/api/server.php");
        let step = supervisor.tick().await.unwrap();

        assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
        assert_eq!(supervisor.generation(), 1);
        assert_eq!(
            supervisor.config().require_url().unwrap(),
            "https://old.example/api/server.php"
        );
        assert_eq!(factory.builds().len(), 2);
        assert_eq!(
            Config::load(&fixture.settings, &fixture.state, Overrides::default())
                .unwrap()
                .token(),
            Some("token"),
            "a rejected candidate must not overwrite active state"
        );
    }

    #[tokio::test]
    async fn invalid_candidate_never_reaches_the_factory() {
        let fixture = Fixture::new("https://old.example/api/server.php");
        let factory = FakeFactory::default();
        let mut supervisor = Supervisor::bootstrap(factory.clone(), fixture.config())
            .await
            .unwrap();

        std::fs::write(&fixture.settings, "{").unwrap();
        let step = supervisor.tick().await.unwrap();

        assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
        assert_eq!(supervisor.generation(), 1);
        assert_eq!(factory.builds().len(), 1);
    }

    #[tokio::test]
    async fn live_settings_keep_the_active_runtime_and_loop_state() {
        let url = "https://old.example/api/server.php";
        let fixture = Fixture::new(url);
        let factory = FakeFactory::default();
        let mut supervisor = Supervisor::bootstrap(factory.clone(), fixture.config())
            .await
            .unwrap();

        fixture.write_live_settings(url);
        let step = supervisor.tick().await.unwrap();

        assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
        assert_eq!(supervisor.generation(), 2);
        assert!(supervisor.config().settings().behavior.disable_update);
        assert_eq!(factory.builds().len(), 1);
        assert!(
            factory.provisioner_builds().is_empty(),
            "a live change must not rebuild services"
        );
    }

    #[tokio::test]
    async fn rebuild_task_swaps_services_without_relogin() {
        let url = "https://old.example/api/server.php";
        let fixture = Fixture::new(url);
        let factory = FakeFactory::default();
        let mut supervisor = Supervisor::bootstrap(factory.clone(), fixture.config())
            .await
            .unwrap();

        fixture.write_settings(json!({
            "server": { "url": url },
            "paths": { "files": "/new/files" }
        }));
        let step = supervisor.tick().await.unwrap();

        assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
        assert_eq!(supervisor.generation(), 2);
        assert_eq!(
            supervisor.config().settings().paths.files,
            PathBuf::from("/new/files")
        );
        assert_eq!(supervisor.config().require_url().unwrap(), url);
        // The provisioner was rebuilt once, against the unchanged server url.
        assert_eq!(factory.provisioner_builds(), vec![url.to_string()]);
        // Only the initial bootstrap logged in; a RebuildTask must not re-prepare.
        assert_eq!(factory.builds().len(), 1);
    }

    #[tokio::test]
    async fn rebuild_task_failure_retains_the_active_generation() {
        let url = "https://old.example/api/server.php";
        let fixture = Fixture::new(url);
        let factory = FakeFactory::default();
        let mut supervisor = Supervisor::bootstrap(factory.clone(), fixture.config())
            .await
            .unwrap();

        fixture.write_settings(json!({
            "server": { "url": url },
            "paths": { "files": "/unavailable/files" }
        }));
        let step = supervisor.tick().await.unwrap();

        assert_eq!(step, Step::Sleep(Duration::from_secs(5)));
        assert_eq!(supervisor.generation(), 1);
        assert_eq!(
            supervisor.config().settings().paths.files,
            PathBuf::from("files")
        );
        assert_eq!(factory.provisioner_builds().len(), 1);
        assert_eq!(factory.builds().len(), 1);
    }
}

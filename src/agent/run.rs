//! The agent work loop
//!
//! [`Agent::tick`] runs one iteration and returns a [`Step`] instead of
//! sleeping; [`Agent::run`] owns the timing and shutdown, which keeps the loop
//! testable without mocking time.

use std::time::{Duration, Instant};

use tokio::time::sleep;

use crate::client::ClientError;
use crate::cracker::Cracker;
use crate::model::{GetChunkResponse, GetTaskResponse, TaskAssignment};
use crate::provisioner::Provisioner;
use crate::transport::Transport;

use super::progress::ClientSink;
use super::{Agent, AgentError};

pub(super) const RETRY_DELAY: Duration = Duration::from_secs(5);
const IDLE_DELAY: Duration = Duration::from_secs(5);
const BENCH_FAIL_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Continue,
    Sleep(Duration),
    Shutdown,
}

pub struct LoopState {
    current_task: Option<TaskAssignment>,
    last_task_id: Option<u64>,
    task_change: bool,
    measured_keyspace: Option<u64>,
    last_deletion_check: Option<Instant>,
}

impl LoopState {
    pub fn new() -> Self {
        Self {
            current_task: None,
            last_task_id: None,
            task_change: true,
            measured_keyspace: None,
            last_deletion_check: None,
        }
    }

    pub fn current_task(&self) -> Option<&TaskAssignment> {
        self.current_task.as_ref()
    }

    fn reset_task(&mut self) {
        self.current_task = None;
        self.measured_keyspace = None;
    }
}

impl Default for LoopState {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Transport, P: Provisioner<T>> Agent<T, P> {
    pub async fn run(&mut self) -> Result<(), AgentError> {
        tracing::debug!("entering agent loop");

        let mut state = LoopState::new();
        let mut shutdown = Box::pin(shutdown_signal());

        loop {
            let step = tokio::select! {
                _ = &mut shutdown => Step::Shutdown,
                result = self.tick(&mut state) => result?,
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

    pub async fn tick(&mut self, state: &mut LoopState) -> Result<Step, AgentError> {
        if let Err(error) = self.config.reload_settings() {
            tracing::warn!(%error, "failed to reload settings; keeping the previous ones");
        }

        self.maybe_deletion_check(state).await;

        if state.current_task.is_none() {
            match self.client.get_task().await {
                Err(error) => return self.on_loop_error("getTask", error),
                Ok(GetTaskResponse::HealthCheck) => {
                    self.run_health_check().await?;
                    return Ok(Step::Continue);
                }
                Ok(GetTaskResponse::NoTask { reason }) => {
                    tracing::info!(?reason, "no task available");
                    state.task_change = true;
                    return Ok(Step::Sleep(IDLE_DELAY));
                }
                Ok(GetTaskResponse::Task(task)) => {
                    let task = *task;
                    if state.last_task_id != Some(task.task_id) {
                        state.task_change = true;
                    }
                    state.last_task_id = Some(task.task_id);
                    tracing::info!(task_id = task.task_id, "got task");
                    state.current_task = Some(task);
                }
            }
        }

        let task = state
            .current_task
            .clone()
            .expect("current task set immediately above");

        // Provisioning runs before getChunk so a miss does not strand an already
        // dispatched chunk.
        let cracker = match self
            .provisioner
            .ensure_cracker(&self.client, task.cracker_id)
            .await
        {
            Ok(cracker) => cracker,
            Err(error) => {
                tracing::warn!(%error, cracker_id = task.cracker_id, "cracker not ready");
                state.task_change = true;
                state.reset_task();

                return Ok(Step::Sleep(RETRY_DELAY));
            }
        };

        if let Some(preprocessor) = &task.preprocessor
            && let Err(error) = self
                .provisioner
                .ensure_preprocessor(&self.client, preprocessor)
                .await
        {
            tracing::warn!(%error, "preprocessor not ready");
            state.reset_task();

            return Ok(Step::Sleep(RETRY_DELAY));
        }

        if let Err(error) = self
            .provisioner
            .ensure_files(&self.client, &task.files, task.task_id)
            .await
        {
            tracing::warn!(%error, "required files missing");
            state.reset_task();

            return Ok(Step::Sleep(RETRY_DELAY));
        }

        if state.task_change {
            if let Err(error) = self
                .provisioner
                .ensure_hashlist(&self.client, task.hashlist_id)
                .await
            {
                tracing::warn!(%error, "failed to load hashlist");
                state.reset_task();

                return Ok(Step::Sleep(RETRY_DELAY));
            }

            self.maybe_check_version().await;

            if task.brain.is_some()
                && let Err(error) = self
                    .provisioner
                    .ensure_found(&self.client, task.hashlist_id, task.cracker_id)
                    .await
            {
                tracing::warn!(%error, "failed to load found hashes");
                state.reset_task();

                return Ok(Step::Sleep(RETRY_DELAY));
            }
        }

        state.task_change = false;

        let chunk = match self.client.get_chunk(task.task_id).await {
            Ok(chunk) => chunk,
            Err(error) => return self.on_loop_error("getChunk", error),
        };

        match chunk {
            GetChunkResponse::FullyDispatched => {
                state.reset_task();
                Ok(Step::Sleep(RETRY_DELAY))
            }
            GetChunkResponse::HealthCheck => {
                self.run_health_check().await?;
                state.reset_task();
                Ok(Step::Continue)
            }
            GetChunkResponse::CrackerUpdate => {
                tracing::info!("cracker update requested");
                state.task_change = true;
                state.reset_task();
                Ok(Step::Sleep(RETRY_DELAY))
            }
            GetChunkResponse::KeyspaceRequired => {
                if let Err(error) = self.measure_and_send_keyspace(state, &task, &cracker).await {
                    if matches!(error, AgentError::TokenRejected) {
                        return Err(error);
                    }
                    tracing::error!(%error, "keyspace measurement failed");
                    state.reset_task();
                }
                Ok(Step::Continue)
            }
            GetChunkResponse::BenchmarkRequired => {
                self.run_and_send_benchmark(state, &task, &cracker).await
            }
            GetChunkResponse::Chunk(chunk) => {
                if chunk.length == 0 {
                    tracing::error!("invalid chunk size (0) retrieved; retrying");
                    state.reset_task();
                    return Ok(Step::Sleep(RETRY_DELAY));
                }

                let sink = ClientSink {
                    client: &self.client,
                    task_id: task.task_id,
                    chunk_id: chunk.id,
                };

                match cracker.run_chunk(&task, chunk, &sink).await {
                    Ok(outcome) => {
                        if outcome.stopped {
                            state.reset_task();
                            state.task_change = true;
                        }
                        self.maybe_check_version().await;
                        Ok(Step::Continue)
                    }
                    Err(error) => {
                        tracing::error!(%error, "chunk run failed");
                        let _ = self
                            .client
                            .client_error(task.task_id, Some(chunk.id), error.to_string())
                            .await;
                        state.reset_task();
                        Ok(Step::Continue)
                    }
                }
            }
        }
    }

    async fn maybe_deletion_check(&self, state: &mut LoopState) {
        let behavior = &self.config.settings().behavior;

        if behavior.file_deletion_disable {
            return;
        }

        let due = state
            .last_deletion_check
            .is_none_or(|last| last.elapsed() >= behavior.file_deletion_interval());

        if due {
            if let Err(error) = self.provisioner.deletion_check(&self.client).await {
                tracing::warn!(%error, "deletion check failed");
            }

            state.last_deletion_check = Some(Instant::now());
        }
    }

    async fn maybe_check_version(&self) {
        if self.config.settings().behavior.disable_update {
            return;
        }

        if let Err(error) = self.provisioner.check_client_version(&self.client).await {
            tracing::warn!(%error, "client version check failed");
        }
    }

    async fn measure_and_send_keyspace(
        &self,
        state: &mut LoopState,
        task: &TaskAssignment,
        cracker: &impl Cracker,
    ) -> Result<(), AgentError> {
        let keyspace = match cracker.measure_keyspace(task).await {
            Ok(keyspace) => keyspace,
            Err(error) => {
                self.report_task_error(task.task_id, "Keyspace measure failed!")
                    .await;

                return Err(error.into());
            }
        };
        state.measured_keyspace = Some(keyspace);

        self.client
            .send_keyspace(task.task_id, keyspace)
            .await
            .map_err(AgentError::client)?;

        tracing::info!(keyspace, "keyspace accepted");

        Ok(())
    }

    async fn run_and_send_benchmark(
        &self,
        state: &mut LoopState,
        task: &TaskAssignment,
        cracker: &impl Cracker,
    ) -> Result<Step, AgentError> {
        tracing::info!("benchmark task");

        match cracker.run_benchmark(task, state.measured_keyspace).await {
            Ok(Some(result)) => {
                match self
                    .client
                    .send_benchmark(task.task_id, task.bench_type, result)
                    .await
                {
                    Ok(()) => {
                        tracing::info!("server accepted benchmark");
                        Ok(Step::Continue)
                    }
                    Err(error) if error.is_invalid_token() => Err(AgentError::TokenRejected),
                    Err(error) => {
                        tracing::error!(%error, "failed to send benchmark");
                        state.reset_task();
                        Ok(Step::Sleep(RETRY_DELAY))
                    }
                }
            }
            Ok(None) => {
                tracing::error!("benchmark produced no result");
                self.report_task_error(task.task_id, "Benchmark produced no result!")
                    .await;
                state.reset_task();
                Ok(Step::Sleep(BENCH_FAIL_DELAY))
            }
            Err(error) => {
                tracing::error!(%error, "benchmark failed");
                self.report_task_error(task.task_id, format!("Benchmark failed! {error}"))
                    .await;
                state.reset_task();
                Ok(Step::Sleep(BENCH_FAIL_DELAY))
            }
        }
    }

    async fn report_task_error(&self, task_id: u64, message: impl Into<String>) {
        let _ = self.client.client_error(task_id, None, message).await;
    }

    async fn run_health_check(&self) -> Result<(), AgentError> {
        tracing::info!("health check requested by server");

        let hc = match self.client.get_health_check().await {
            Ok(hc) => hc,
            Err(error) if error.is_invalid_token() => return Err(AgentError::TokenRejected),
            Err(error) => {
                tracing::error!(%error, "failed to get health check");
                return Ok(());
            }
        };

        let cracker = match self
            .provisioner
            .ensure_cracker(&self.client, hc.cracker_binary_id)
            .await
        {
            Ok(cracker) => cracker,
            Err(error) => {
                tracing::warn!(%error, "health-check cracker not ready");
                return Ok(());
            }
        };

        match cracker
            .run_health_check(&hc.attack, &hc.hashlist_alias, &hc.hashes)
            .await
        {
            Ok(outcome) => match self
                .client
                .send_health_check(
                    hc.check_id,
                    outcome.num_cracked,
                    outcome.start,
                    outcome.end,
                    outcome.num_gpus,
                    &outcome.errors,
                )
                .await
            {
                Ok(()) => tracing::info!("health check completed"),
                Err(error) if error.is_invalid_token() => return Err(AgentError::TokenRejected),
                Err(error) => tracing::error!(%error, "failed to send health check results"),
            },
            Err(error) => tracing::error!(%error, "health check run failed"),
        }

        Ok(())
    }

    fn on_loop_error(&self, action: &str, error: ClientError) -> Result<Step, AgentError> {
        if error.is_invalid_token() {
            return Err(AgentError::TokenRejected);
        }

        tracing::error!(action, %error, "request failed");

        Ok(Step::Sleep(RETRY_DELAY))
    }
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

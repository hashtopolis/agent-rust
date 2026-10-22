use std::sync::{Arc, Mutex};

use htp_agent::client::Client;
use htp_agent::cracker::{
    ChunkOutcome, Cracker, CrackerError, HealthCheckOutcome, ProgressCommand, ProgressSink,
};
use std::path::{Path, PathBuf};

use htp_agent::model::{Chunk, Preprocessor, ProgressReport, ResolvedPreprocessor, TaskAssignment};
use htp_agent::provisioner::{ProvisionError, Provisioner};
use htp_agent::transport::Transport;

/// `run_chunk` consumes one `sendProgress` reply and stops if it says to.
#[derive(Clone)]
pub struct FakeCracker {
    pub keyspace: u64,
    pub benchmark: Option<String>,
}

impl Default for FakeCracker {
    fn default() -> Self {
        Self {
            keyspace: 0,
            benchmark: Some("674:674.74".to_string()),
        }
    }
}

impl Cracker for FakeCracker {
    async fn measure_keyspace(
        &self,
        _task: &TaskAssignment,
        _preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<u64>, CrackerError> {
        Ok(Some(self.keyspace))
    }

    async fn run_benchmark(
        &self,
        _task: &TaskAssignment,
        _preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<String>, CrackerError> {
        Ok(self.benchmark.clone())
    }

    async fn run_chunk<S: ProgressSink>(
        &self,
        _task: &TaskAssignment,
        _chunk: Chunk,
        _preprocessor: Option<&ResolvedPreprocessor>,
        sink: &S,
    ) -> Result<ChunkOutcome, CrackerError> {
        let command = sink.send_progress(ProgressReport::default(), false).await;
        Ok(ChunkOutcome {
            stopped: matches!(command, Ok(ProgressCommand::Stop)),
        })
    }

    async fn run_health_check(
        &self,
        _attack: &str,
        _hashlist_alias: &str,
        _hashes: &[String],
    ) -> Result<HealthCheckOutcome, CrackerError> {
        Ok(HealthCheckOutcome {
            num_cracked: 1,
            ..HealthCheckOutcome::default()
        })
    }

    /// Return a path so a brain task still exercises `ensure_found`; the loop only
    /// asks for this when `task.brain` is set.
    fn found_hashes_path(&self) -> Option<PathBuf> {
        Some(PathBuf::from("found.potfile"))
    }
}

/// Every provisioning entry point the loop can call, recorded in the order the
/// loop invokes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    DeletionCheck,
    Cracker,
    Preprocessor,
    Files,
    Hashlist,
    CheckVersion,
    Found,
}

/// Stands in for an installed update the agent should restart into.
#[derive(Debug, PartialEq, Eq)]
pub struct FakeRestart;

/// Never touches the client, so a loop test only scripts the loop's own
/// requests. Records every provisioning call and, optionally, fails one stage
/// or installs an update on a given version check. Clones share the call log,
/// so a test keeps a probe after the provisioner is moved into the agent.
#[derive(Clone)]
pub struct FakeProvisioner {
    cracker: FakeCracker,
    fail_at: Option<Stage>,
    update_on_check: Option<usize>,
    calls: Arc<Mutex<Vec<Stage>>>,
}

impl Default for FakeProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeProvisioner {
    pub fn new() -> Self {
        Self {
            cracker: FakeCracker::default(),
            fail_at: None,
            update_on_check: None,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn with_cracker(mut self, cracker: FakeCracker) -> Self {
        self.cracker = cracker;
        self
    }

    pub fn failing_at(mut self, stage: Stage) -> Self {
        self.fail_at = Some(stage);
        self
    }

    /// Report an installed update on the `nth` version check (1-based).
    pub fn updating_on_check(mut self, nth: usize) -> Self {
        self.update_on_check = Some(nth);
        self
    }

    pub fn calls(&self) -> Vec<Stage> {
        self.calls.lock().unwrap().clone()
    }

    /// Record the call, then honour a scripted failure for this stage.
    fn enter(&self, stage: Stage) -> Result<(), ProvisionError> {
        self.calls.lock().unwrap().push(stage);

        if self.fail_at == Some(stage) {
            Err(not_ready())
        } else {
            Ok(())
        }
    }
}

/// Stands in for any provisioning failure; the loop never inspects the variant.
fn not_ready() -> ProvisionError {
    ProvisionError::SizeMismatch {
        file: "fake".to_string(),
        expected: 1,
        actual: 0,
    }
}

impl<T: Transport> Provisioner<T> for FakeProvisioner {
    type Cracker = FakeCracker;
    type Restart = FakeRestart;

    async fn deletion_check(&self, _client: &Client<T>) -> Result<(), ProvisionError> {
        self.enter(Stage::DeletionCheck)
    }

    async fn ensure_cracker(
        &self,
        _client: &Client<T>,
        _cracker_id: u64,
    ) -> Result<FakeCracker, ProvisionError> {
        self.enter(Stage::Cracker)?;

        Ok(self.cracker.clone())
    }

    async fn ensure_preprocessor(
        &self,
        _client: &Client<T>,
        preprocessor: &Preprocessor,
    ) -> Result<ResolvedPreprocessor, ProvisionError> {
        self.enter(Stage::Preprocessor)?;

        Ok(ResolvedPreprocessor {
            command: preprocessor.command.clone(),
            binary_path: PathBuf::from("pp"),
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
        self.enter(Stage::Files)
    }

    async fn ensure_hashlist(
        &self,
        _client: &Client<T>,
        _hashlist_id: u64,
    ) -> Result<(), ProvisionError> {
        self.enter(Stage::Hashlist)
    }

    async fn ensure_found(
        &self,
        _client: &Client<T>,
        _hashlist_id: u64,
        _dest: &Path,
    ) -> Result<(), ProvisionError> {
        self.enter(Stage::Found)
    }

    async fn check_client_version(
        &self,
        _client: &Client<T>,
    ) -> Result<Option<FakeRestart>, ProvisionError> {
        self.enter(Stage::CheckVersion)?;

        let checks = self
            .calls()
            .iter()
            .filter(|stage| **stage == Stage::CheckVersion)
            .count();

        Ok((self.update_on_check == Some(checks)).then_some(FakeRestart))
    }
}

//! A common interface over the hashcat and generic backends. The loop passes a
//! [`ProgressSink`] into [`Cracker::run_chunk`] so the backends report progress
//! without ever seeing `client` or `transport`.

use std::path::PathBuf;

use enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::backend::generic::GenericCracker;
use crate::backend::hashcat::HashcatCracker;
use crate::model::{Chunk, CrackerId, ProgressReport, ResolvedPreprocessor, TaskAssignment};

#[derive(Debug, Error)]
pub enum CrackerError {
    #[error("cracker process error: {0}")]
    Process(String),
    #[error("unparsable cracker status: {0}")]
    UnparsableStatus(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressCommand {
    /// `zaps` are hashes cracked elsewhere to remove from the pot.
    Continue {
        zaps: Vec<String>,
    },
    Stop,
}

/// The report never reached the server (unreachable, timed out, unparsable
/// reply). It is not a `CrackerError`: the backend must retain the unsent state
/// (cracks, progress) and resend it on the next update, not abort the run.
#[derive(Debug, Clone, Error)]
#[error("progress update could not be delivered: {0}")]
pub struct ProgressUpdateError(pub String);

pub trait ProgressSink {
    /// `Err` is a delivery failure, not a reason to stop: the cracker backend keeps the
    /// unsent state and retries on the next update. A chunk stops only on an
    /// explicit `Stop` or a genuine local process fault (`CrackerError`).
    async fn send_progress(
        &self,
        report: ProgressReport,
    ) -> Result<ProgressCommand, ProgressUpdateError>;

    /// Report a cracker error (e.g. a stderr line) without stopping the run.
    /// The server logs it and decides on a later tick whether
    /// to abort the chunk, so delivery failures are swallowed.
    async fn report_error(&self, message: impl Into<String>);
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkOutcome {
    pub stopped: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthCheckOutcome {
    pub start: i64,
    pub end: i64,
    pub num_gpus: u32,
    pub num_cracked: u64,
    pub errors: Vec<String>,
}

#[enum_dispatch]
pub trait Cracker {
    /// `Ok(None)` means the keyspace is unbounded or too large to represent: a
    /// preprocessor with no keyspace command, or a count that overflows the wire
    /// field. The client encodes that as `-1` for the server.
    async fn measure_keyspace(
        &self,
        task: &TaskAssignment,
        preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<u64>, CrackerError>;

    /// `Ok(None)` means the benchmark produced no usable result.
    async fn run_benchmark(
        &self,
        task: &TaskAssignment,
        preprocessor: Option<&ResolvedPreprocessor>,
    ) -> Result<Option<String>, CrackerError>;

    async fn run_chunk<S: ProgressSink>(
        &self,
        task: &TaskAssignment,
        chunk: Chunk,
        preprocessor: Option<&ResolvedPreprocessor>,
        sink: &S,
    ) -> Result<ChunkOutcome, CrackerError>;

    async fn run_health_check(
        &self,
        attack: &str,
        hashlist_alias: &str,
        hashes: &[String],
    ) -> Result<HealthCheckOutcome, CrackerError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrackerKind {
    Hashcat,
    Generic,
}

#[enum_dispatch(Cracker)]
pub enum AnyCracker {
    Hashcat(HashcatCracker),
    Generic(GenericCracker),
}

pub async fn build_cracker(
    kind: CrackerKind,
    cracker_id: CrackerId,
    binary_path: PathBuf,
    paths: crate::config::Paths,
) -> Result<AnyCracker, CrackerError> {
    let cracker = match kind {
        CrackerKind::Hashcat => HashcatCracker::new(cracker_id, binary_path, paths)
            .await?
            .into(),
        CrackerKind::Generic => GenericCracker::new(cracker_id, binary_path, paths).into(),
    };

    Ok(cracker)
}

//! A common interface over the hashcat and generic backends. The loop passes a
//! [`ProgressSink`] into [`Cracker::run_chunk`] so the backends report progress
//! without ever seeing `client` or `transport`.

use std::path::PathBuf;

use enum_dispatch::enum_dispatch;
use thiserror::Error;

use crate::backend::generic::GenericCracker;
use crate::backend::hashcat::HashcatCracker;
use crate::model::{Chunk, ProgressReport, TaskAssignment};

#[derive(Debug, Error)]
pub enum CrackerError {
    #[error("cracker process error: {0}")]
    Process(String),
    #[error("unparsable cracker status: {0}")]
    UnparsableStatus(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgressCommand {
    /// `zaps` are hashes cracked elsewhere to remove from the pot.
    Continue {
        zaps: Vec<String>,
    },
    Stop,
    /// The report could not be delivered; the backend should keep going.
    Failed,
}

pub trait ProgressSink {
    async fn send_progress(&self, report: ProgressReport) -> ProgressCommand;
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
    async fn measure_keyspace(&self, task: &TaskAssignment) -> Result<u64, CrackerError>;

    /// `Ok(None)` means the benchmark produced no usable result.
    async fn run_benchmark(
        &self,
        task: &TaskAssignment,
        measured_keyspace: Option<u64>,
    ) -> Result<Option<String>, CrackerError>;

    async fn run_chunk<S: ProgressSink>(
        &self,
        task: &TaskAssignment,
        chunk: Chunk,
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

pub fn build_cracker(kind: CrackerKind, cracker_id: u64, binary_path: PathBuf) -> AnyCracker {
    match kind {
        CrackerKind::Hashcat => HashcatCracker::new(cracker_id, binary_path).into(),
        CrackerKind::Generic => GenericCracker::new(cracker_id, binary_path).into(),
    }
}
